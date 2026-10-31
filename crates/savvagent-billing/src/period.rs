//! Billing periods: the UTC calendar [`Month`], and when one **closes**.
//!
//! A leaf module (no SQL, no Stripe) so that metering ([`crate::usage`]),
//! the Stripe meter outbox ([`crate::stripe_outbox`]) and Stripe invoicing
//! ([`crate::billing`]) share one definition of "this period is over".
//!
//! A period is open from 00:00 UTC on its first day until
//! [`PERIOD_CLOSE_GRACE`] after 00:00 UTC on the first day of the next month
//! ([`closes_at`]). The grace lets a resource server's outbox drain events
//! that happened just before midnight into the month they were earned in.
//! Once a period has closed ([`period_closed`]) nothing is billed into it any
//! more: ingest re-dates a late event to the moment it arrives, so the
//! platform's counters, budgets and Stripe all count it in the current period
//! (see [`crate::usage`]).
//!
//! ```
//! use chrono::{TimeZone, Utc};
//! use savvagent_billing::period::{closes_at, period_closed, Month};
//!
//! let october = Month::new(2026, 10).unwrap();
//! assert_eq!(closes_at(october), Some(Utc.with_ymd_and_hms(2026, 11, 1, 2, 0, 0).unwrap()));
//! assert!(!period_closed(october, Utc.with_ymd_and_hms(2026, 11, 1, 1, 59, 59).unwrap()));
//! assert!(period_closed(october, Utc.with_ymd_and_hms(2026, 11, 1, 2, 0, 0).unwrap()));
//! ```

use std::fmt;
use std::str::FromStr;

use chrono::{
    DateTime, Datelike, Days, Duration, DurationRound, Months, NaiveDate, NaiveTime, Utc,
};

/// A UTC calendar month: a billing period, and what the price book versions
/// by (the month a price takes effect, at 00:00 UTC on its first day).
/// Written `YYYY-MM`.
///
/// ```
/// use savvagent_billing::period::Month;
///
/// let m: Month = "2026-11".parse().unwrap();
/// assert_eq!(m.to_string(), "2026-11");
/// assert!("2026-1".parse::<Month>().is_err());
/// assert!("2026-13".parse::<Month>().is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Month(NaiveDate);

impl Month {
    /// The month `year`-`month`, if `month` is 1 to 12 and the year is one
    /// `chrono` can represent.
    pub fn new(year: i32, month: u32) -> Option<Self> {
        NaiveDate::from_ymd_opt(year, month, 1).map(Self)
    }

    /// The month `date` falls in.
    pub fn containing(date: NaiveDate) -> Self {
        // Subtracting at most 30 days from a valid date cannot leave chrono's
        // range: the first of the month is itself a valid date.
        Self(date - Days::new(u64::from(date.day0())))
    }

    /// The month (UTC) the instant `at` falls in.
    pub fn of(at: DateTime<Utc>) -> Self {
        Self::containing(at.date_naive())
    }

    /// The first day of the month.
    pub fn first_day(self) -> NaiveDate {
        self.0
    }

    /// The month `months` after this one (before it, if negative), if chrono
    /// can represent it.
    pub fn offset(self, months: i32) -> Option<Self> {
        let n = Months::new(months.unsigned_abs());
        if months >= 0 {
            self.0.checked_add_months(n)
        } else {
            self.0.checked_sub_months(n)
        }
        .map(Self)
    }
}

impl fmt::Display for Month {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.0.year(), self.0.month())
    }
}

/// Why a `YYYY-MM` string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a month as YYYY-MM, e.g. 2026-11, got {0:?}")]
pub struct ParseMonthError(String);

impl FromStr for Month {
    type Err = ParseMonthError;

    /// Exactly four digits, `-`, two digits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseMonthError(s.to_owned());
        let (y, m) = s.split_once('-').ok_or_else(err)?;
        let digits = |t: &str, n: usize| t.len() == n && t.bytes().all(|b| b.is_ascii_digit());
        if !digits(y, 4) || !digits(m, 2) {
            return Err(err());
        }
        let year = y.parse().map_err(|_| err())?;
        let month = m.parse().map_err(|_| err())?;
        Month::new(year, month).ok_or_else(err)
    }
}

/// How long after the end of a UTC month its period stays open for late
/// events: 2 hours after 00:00 UTC on the 1st of the next month.
pub const PERIOD_CLOSE_GRACE: Duration = Duration::hours(2);

/// The first instant of `month`, 00:00 UTC on its first day.
pub fn starts_at(month: Month) -> DateTime<Utc> {
    month.first_day().and_time(NaiveTime::MIN).and_utc()
}

/// The instant `month`'s period closes: [`PERIOD_CLOSE_GRACE`] after the
/// first instant of the next month. `None` only for a month whose successor
/// chrono cannot represent (it never closes).
pub fn closes_at(month: Month) -> Option<DateTime<Utc>> {
    month
        .offset(1)
        .map(|next| starts_at(next) + PERIOD_CLOSE_GRACE)
}

/// Whether `month`'s period has closed at `now`: nothing more may be billed
/// into it.
pub fn period_closed(month: Month, now: DateTime<Utc>) -> bool {
    closes_at(month).is_some_and(|close| now >= close)
}

/// The instant a usage event that happened at `occurred_at` and arrived at
/// `now` is billed at: `occurred_at` (never later than `now`), unless its
/// month's period has closed, in which case `now`.
///
/// ```
/// use chrono::{TimeZone, Utc};
/// use savvagent_billing::period::billed_at;
///
/// let now = Utc.with_ymd_and_hms(2026, 11, 1, 3, 0, 0).unwrap();
/// let late = Utc.with_ymd_and_hms(2026, 10, 31, 23, 59, 0).unwrap();
/// assert_eq!(billed_at(late, now), now, "October closed at 02:00");
/// let early = Utc.with_ymd_and_hms(2026, 11, 1, 0, 30, 0).unwrap();
/// assert_eq!(billed_at(early, now), early);
/// ```
pub fn billed_at(occurred_at: DateTime<Utc>, now: DateTime<Utc>) -> DateTime<Utc> {
    let at = occurred_at.min(now);
    if period_closed(Month::of(at), now) {
        now
    } else {
        at
    }
}

/// The start of the UTC hour holding `at`: the Stripe meter outbox's
/// aggregation bucket, and the timestamp its meter event carries. Always in
/// the same UTC month as `at`, since months start on the hour.
///
/// ```
/// use chrono::{TimeZone, Utc};
/// use savvagent_billing::period::hour_bucket;
///
/// let at = Utc.with_ymd_and_hms(2026, 10, 20, 13, 47, 12).unwrap();
/// assert_eq!(hour_bucket(at), Utc.with_ymd_and_hms(2026, 10, 20, 13, 0, 0).unwrap());
/// ```
pub fn hour_bucket(at: DateTime<Utc>) -> DateTime<Utc> {
    // Truncating to a whole hour cannot leave chrono's range for any instant
    // inside it; fall back to `at` itself rather than panic in the impossible
    // case.
    at.duration_trunc(Duration::hours(1)).unwrap_or(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    #[test]
    fn a_period_closes_two_hours_into_the_next_month() {
        let dec = Month::new(2026, 12).unwrap();
        assert_eq!(closes_at(dec), Some(utc(2027, 1, 1, 2, 0)));
        assert!(!period_closed(dec, utc(2026, 12, 31, 23, 59)));
        assert!(!period_closed(dec, utc(2027, 1, 1, 1, 59)));
        assert!(period_closed(dec, utc(2027, 1, 1, 2, 0)));
        let feb = Month::new(2028, 2).unwrap();
        assert_eq!(closes_at(feb), Some(utc(2028, 3, 1, 2, 0)));
    }

    #[test]
    fn late_events_are_billed_now_and_future_ones_no_later_than_now() {
        let now = utc(2026, 11, 1, 2, 0);
        assert_eq!(billed_at(utc(2026, 10, 31, 23, 0), now), now);
        assert_eq!(billed_at(utc(2026, 10, 2, 0, 0), now), now);
        let inside = utc(2026, 11, 1, 1, 0);
        assert_eq!(billed_at(inside, now), inside);
        assert_eq!(billed_at(now + Duration::minutes(3), now), now);
        // Within the grace, the old month still takes it.
        let grace = utc(2026, 11, 1, 1, 30);
        let last = utc(2026, 10, 31, 23, 59);
        assert_eq!(billed_at(last, grace), last);
    }

    #[test]
    fn buckets_are_whole_hours_in_the_same_month() {
        let at = utc(2026, 10, 31, 23, 59) + Duration::seconds(59);
        let b = hour_bucket(at);
        assert_eq!(b, utc(2026, 10, 31, 23, 0));
        assert_eq!(Month::of(b), Month::of(at));
        assert_eq!(b.timestamp() % 3600, 0);
        assert_eq!(hour_bucket(b), b);
    }
}
