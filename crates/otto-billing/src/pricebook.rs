//! The price book: what each value meter costs, as data (savvagent/otto-platform#60).
//!
//! A meter's price is a **version**: graduated tiers that take effect at
//! 00:00 UTC on the first day of a month ([`Month`]) and stay in effect until
//! the meter's next version. The tiers in effect for a billing period are
//! those of the latest version whose month is not after the period's month
//! ([`tiers_in_effect`]). A meter with no such version is **unpriced**: it
//! rates to 0 and says so ([`LineAmount::Unpriced`]), rather than looking free.
//!
//! **Graduated tiers.** Units `1..=up_to` of the first tier are charged at its
//! unit amount, the units above that up to the second tier's `up_to` at the
//! second's, and so on; the last tier is unbounded. A free allowance is a first
//! tier priced at 0. [`Tiers`] is the only way to hold a tier list, and it
//! cannot be built with bounds that are not strictly increasing or a last tier
//! that is bounded, so [`rate`] never meets one.
//!
//! **Money is exact.** Unit amounts are `i64` millionths of a US cent
//! (`ucents`), so sub-cent prices need no floats. See [`rate`] for the
//! arithmetic and the one rounding step.
//!
//! **Past prices never change.** [`set_version`] writes a version for the
//! current month or a later one, never an earlier one, and replaces an existing
//! version only while its month is still in the future, so a period that has
//! been (or is being) billed keeps the price it was billed at. A replacement is
//! a new version with a new id, never an edit: the id is what a Stripe Price is
//! recorded against, and Stripe prices are immutable.
//!
//! **Read by anyone, written by the operator.** `otto_app` may read the price
//! book but not write it (migration 0020), so the read functions take any
//! connection, pinned or not, and [`set_version`] takes an [`Unpinned`]
//! transaction, which runs as the connecting role.
//!
//! ```
//! use otto_billing::pricebook::{rate, LineAmount, Tier, Tiers};
//!
//! // The first 1,000 units free, then 0.15 cents (150,000 ucents) each.
//! let tiers = Tiers::new(vec![
//!     Tier { up_to: Some(1_000), unit_amount_ucents: 0 },
//!     Tier { up_to: None, unit_amount_ucents: 150_000 },
//! ])
//! .unwrap();
//!
//! assert_eq!(rate(1_000, Some(&tiers)).unwrap(), LineAmount::Priced { cents: 0 });
//! // 10 billable units: 1.5 cents, rounded half up to 2.
//! assert_eq!(rate(1_010, Some(&tiers)).unwrap(), LineAmount::Priced { cents: 2 });
//! // No price in effect: 0, and reported as unpriced.
//! assert_eq!(rate(1_010, None).unwrap(), LineAmount::Unpriced);
//! ```

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Datelike, Days, NaiveDate, Utc};
use otto_tenant::Unpinned;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::meters::Meter;

/// Millionths of a cent in one cent.
pub const UCENTS_PER_CENT: i64 = 1_000_000;

/// The most tiers one version may have. Far more than a price needs; it keeps
/// a tier's position inside the `smallint` column and a typo'd command short.
pub const MAX_TIERS: usize = 64;

// ---------------------------------------------------------------- months

/// A calendar month, as the price book versions by: the month a price takes
/// effect, at 00:00 UTC on its first day. Written `YYYY-MM`.
///
/// ```
/// use otto_billing::pricebook::Month;
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

// ----------------------------------------------------------------- tiers

/// One graduated tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    /// The last unit (cumulative, counted from 1) this tier prices; `None` on
    /// the last tier, which is unbounded.
    pub up_to: Option<i64>,
    /// Price per unit in this tier, in millionths of a US cent.
    pub unit_amount_ucents: i64,
}

/// Why a tier list was refused. Positions are 0-based.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TierError {
    #[error("a price needs at least one tier")]
    Empty,
    #[error("a price may have at most {MAX_TIERS} tiers")]
    TooMany,
    #[error("tier {position}: up_to must be at least 1")]
    NonPositiveBound { position: usize },
    #[error("tier {position}: up_to {up_to} must be greater than the previous tier's {previous}")]
    NotIncreasing {
        position: usize,
        up_to: i64,
        previous: i64,
    },
    #[error("tier {position}: only the last tier may be unbounded")]
    UnboundedNotLast { position: usize },
    #[error("the last tier must be unbounded")]
    LastBounded,
    #[error("tier {position}: the unit amount must not be negative")]
    NegativeAmount { position: usize },
}

/// A tier list [`rate`] can price: at least one tier, bounds strictly
/// increasing and at least 1, only the last tier unbounded, no negative
/// amounts.
///
/// ```
/// use otto_billing::pricebook::{Tier, TierError, Tiers};
///
/// let bounded_last = Tiers::new(vec![Tier { up_to: Some(10), unit_amount_ucents: 1 }]);
/// assert_eq!(bounded_last.unwrap_err(), TierError::LastBounded);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tiers(Vec<Tier>);

impl Tiers {
    /// Check `tiers` and hold them.
    pub fn new(tiers: Vec<Tier>) -> Result<Self, TierError> {
        if tiers.is_empty() {
            return Err(TierError::Empty);
        }
        if tiers.len() > MAX_TIERS {
            return Err(TierError::TooMany);
        }
        let last = tiers.len() - 1;
        let mut previous: Option<i64> = None;
        for (position, tier) in tiers.iter().enumerate() {
            if tier.unit_amount_ucents < 0 {
                return Err(TierError::NegativeAmount { position });
            }
            match tier.up_to {
                None if position != last => return Err(TierError::UnboundedNotLast { position }),
                None => {}
                Some(_) if position == last => return Err(TierError::LastBounded),
                Some(up_to) if up_to < 1 => return Err(TierError::NonPositiveBound { position }),
                Some(up_to) => {
                    if let Some(previous) = previous.filter(|&p| up_to <= p) {
                        return Err(TierError::NotIncreasing {
                            position,
                            up_to,
                            previous,
                        });
                    }
                    previous = Some(up_to);
                }
            }
        }
        Ok(Self(tiers))
    }

    /// The tiers, in order.
    pub fn as_slice(&self) -> &[Tier] {
        &self.0
    }
}

// ---------------------------------------------------------------- rating

/// What one meter line comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineAmount {
    /// Rated against the tiers in effect, in whole US cents.
    Priced { cents: i64 },
    /// No price was in effect. Charges nothing, and is reported so a missing
    /// price is visible rather than looking like a free meter.
    Unpriced,
}

impl LineAmount {
    /// Whole US cents: 0 when unpriced.
    pub fn cents(self) -> i64 {
        match self {
            Self::Priced { cents } => cents,
            Self::Unpriced => 0,
        }
    }

    /// Whether a price was in effect.
    pub fn is_priced(self) -> bool {
        matches!(self, Self::Priced { .. })
    }
}

/// Why a quantity could not be rated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RateError {
    #[error("quantity {0} is negative")]
    NegativeQuantity(i64),
    /// The amount does not fit in `i64` cents. Refused rather than wrapped or
    /// saturated: an invoice must be the right number or no number.
    #[error("the line amount overflows")]
    Overflow,
}

/// Rate `quantity` units of one meter against the tiers in effect.
///
/// The line amount is the sum, over the tiers, of the units falling in each
/// tier times that tier's unit amount, computed exactly in millionths of a cent
/// (in `i128`, which no `i64` quantity and `i64` unit amounts can overflow).
/// That total is then rounded to whole cents **once per meter line**, never per
/// tier, **half up** (ties away from zero; a line is never negative): Stripe
/// rounds a line item's amount to the nearest cent the same way, so this
/// matches the invoice it will produce. A result that does not fit in `i64`
/// cents is [`RateError::Overflow`].
///
/// `tiers` is `None` for a meter with no price in effect, which rates to
/// [`LineAmount::Unpriced`]. A zero quantity rates to 0 cents.
///
/// ```
/// use otto_billing::pricebook::{rate, LineAmount, Tier, Tiers};
///
/// // 0.5 cents per unit for the first 3 units, then 0.25.
/// let tiers = Tiers::new(vec![
///     Tier { up_to: Some(3), unit_amount_ucents: 500_000 },
///     Tier { up_to: None, unit_amount_ucents: 250_000 },
/// ])
/// .unwrap();
/// // 3 × 0.5 + 2 × 0.25 = 2.0 cents. Rounded per tier it would be 2 + 1 = 3.
/// assert_eq!(rate(5, Some(&tiers)).unwrap(), LineAmount::Priced { cents: 2 });
/// // 1 × 0.5 = 0.5 cents, rounded half up.
/// assert_eq!(rate(1, Some(&tiers)).unwrap().cents(), 1);
/// assert!(rate(-1, Some(&tiers)).is_err());
/// ```
pub fn rate(quantity: i64, tiers: Option<&Tiers>) -> Result<LineAmount, RateError> {
    if quantity < 0 {
        return Err(RateError::NegativeQuantity(quantity));
    }
    let Some(tiers) = tiers else {
        return Ok(LineAmount::Unpriced);
    };
    let ucents = line_ucents(quantity, tiers);
    // Non-negative (the quantity and every amount are), so adding half a cent
    // and truncating is round-half-up.
    let cents = (ucents + i128::from(UCENTS_PER_CENT / 2)) / i128::from(UCENTS_PER_CENT);
    let cents = i64::try_from(cents).map_err(|_| RateError::Overflow)?;
    Ok(LineAmount::Priced { cents })
}

/// The exact line amount in millionths of a cent. At most `quantity` units are
/// counted across all tiers, each at most `i64::MAX`, so the sum is below
/// `2^126` and cannot overflow `i128`.
fn line_ucents(quantity: i64, tiers: &Tiers) -> i128 {
    let mut priced: i64 = 0;
    let mut total: i128 = 0;
    for tier in tiers.as_slice() {
        let ceiling = tier.up_to.map_or(quantity, |up_to| up_to.min(quantity));
        if ceiling <= priced {
            break;
        }
        total += i128::from(ceiling - priced) * i128::from(tier.unit_amount_ucents);
        priced = ceiling;
    }
    total
}

// -------------------------------------------------------------- storage

/// A price-book failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "no meter {0:?}: a service declares its meters (PUT /internal/meters) before they can \
         be priced"
    )]
    UnknownMeter(String),
    #[error(
        "{month} is before the current month ({current}); a past month's price is never \
         changed, so past invoices never change"
    )]
    PastMonth { month: Month, current: Month },
    #[error(
        "{meter} already has a price for {month}, which is in effect; set one for a later \
         month instead"
    )]
    InEffect { meter: String, month: Month },
    #[error(transparent)]
    Tiers(#[from] TierError),
    /// A stored version the rater cannot price: its rows were edited by hand
    /// into a shape [`Tiers`] refuses.
    #[error("price version {version} is malformed: {reason}")]
    Corrupt { version: Uuid, reason: String },
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// A price-book result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// One version of one meter's price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceVersion {
    /// Stable for the life of the version; a replacement gets a new one.
    pub id: Uuid,
    /// The meter's key, `<service>/<meter>`.
    pub meter: String,
    pub effective_month: Month,
    pub created_at: DateTime<Utc>,
    pub tiers: Tiers,
}

/// A meter with the price version in effect for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedMeter {
    pub meter: Meter,
    pub version: PriceVersion,
}

/// What [`set_version`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetOutcome {
    pub version: PriceVersion,
    /// The id of the future version this one replaced, if any.
    pub replaced: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: Uuid,
    meter: String,
    effective_month: NaiveDate,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TierRow {
    version_id: Uuid,
    position: i16,
    up_to: Option<i64>,
    unit_amount_ucents: i64,
}

/// Attach each version's tiers, checking them as [`Tiers`] does.
async fn with_tiers(conn: &mut PgConnection, rows: Vec<VersionRow>) -> Result<Vec<PriceVersion>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let tier_rows: Vec<TierRow> = sqlx::query_as(
        "SELECT version_id, position, up_to, unit_amount_ucents FROM price_tiers \
         WHERE version_id = ANY($1) ORDER BY version_id, position",
    )
    .bind(&ids)
    .fetch_all(conn)
    .await?;

    rows.into_iter()
        .map(|row| {
            let corrupt = |reason: String| Error::Corrupt {
                version: row.id,
                reason,
            };
            let mine = tier_rows.iter().filter(|t| t.version_id == row.id);
            let mut tiers = Vec::new();
            for (expected, t) in mine.enumerate() {
                if usize::try_from(t.position).ok() != Some(expected) {
                    return Err(corrupt(format!(
                        "tier positions are not 0..n (at {expected})"
                    )));
                }
                tiers.push(Tier {
                    up_to: t.up_to,
                    unit_amount_ucents: t.unit_amount_ucents,
                });
            }
            let tiers = Tiers::new(tiers).map_err(|e| corrupt(e.to_string()))?;
            let effective_month = Month::containing(row.effective_month);
            if effective_month.first_day() != row.effective_month {
                return Err(corrupt("effective month is not a first of month".into()));
            }
            Ok(PriceVersion {
                id: row.id,
                meter: row.meter,
                effective_month,
                created_at: row.created_at,
                tiers,
            })
        })
        .collect()
}

/// The version of `meter`'s price in effect during `month`: the latest one
/// whose effective month is not after it. `None` means the meter is unpriced
/// for that month (which [`rate`] reports as [`LineAmount::Unpriced`]).
///
/// Takes any connection: `otto_app` may read the price book, so a pinned
/// transaction's `conn()` works as well as an unpinned one's.
pub async fn tiers_in_effect(
    conn: &mut PgConnection,
    meter: &str,
    month: Month,
) -> Result<Option<PriceVersion>> {
    let rows: Vec<VersionRow> = sqlx::query_as(
        "SELECT id, meter, effective_month, created_at FROM price_versions \
         WHERE meter = $1 AND effective_month <= $2 \
         ORDER BY effective_month DESC LIMIT 1",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_all(&mut *conn)
    .await?;
    Ok(with_tiers(conn, rows).await?.pop())
}

/// Every meter that has a price in effect during `month`, with that price, by
/// meter key. Meters with no price in effect are left out.
pub async fn book_in_effect(conn: &mut PgConnection, month: Month) -> Result<Vec<PricedMeter>> {
    let meters: Vec<Meter> = sqlx::query_as(
        "SELECT m.key, m.service, m.meter, m.display_name, m.unit, m.created_at, m.updated_at \
         FROM meters m \
         WHERE EXISTS (SELECT 1 FROM price_versions v \
                       WHERE v.meter = m.key AND v.effective_month <= $1) \
         ORDER BY m.key",
    )
    .bind(month.first_day())
    .fetch_all(&mut *conn)
    .await?;
    let rows: Vec<VersionRow> = sqlx::query_as(
        "SELECT DISTINCT ON (meter) id, meter, effective_month, created_at \
         FROM price_versions WHERE effective_month <= $1 \
         ORDER BY meter, effective_month DESC",
    )
    .bind(month.first_day())
    .fetch_all(&mut *conn)
    .await?;
    let mut versions = with_tiers(conn, rows).await?;

    let mut book = Vec::with_capacity(meters.len());
    for meter in meters {
        // Every version names an existing meter (a foreign key), and every
        // meter listed has a version in effect, so this always finds one.
        let Some(at) = versions.iter().position(|v| v.meter == meter.key) else {
            continue;
        };
        let version = versions.swap_remove(at);
        book.push(PricedMeter { meter, version });
    }
    Ok(book)
}

/// Every version of every meter's price, by meter key, oldest month first.
pub async fn list_versions(conn: &mut PgConnection) -> Result<Vec<PriceVersion>> {
    let rows: Vec<VersionRow> = sqlx::query_as(
        "SELECT id, meter, effective_month, created_at FROM price_versions \
         ORDER BY meter, effective_month",
    )
    .fetch_all(&mut *conn)
    .await?;
    with_tiers(conn, rows).await
}

/// Write `meter`'s price from `month` on.
///
/// `now` decides which months are past. A month before the current one is
/// refused ([`Error::PastMonth`]); so is replacing the current month's
/// existing version ([`Error::InEffect`]): either would change what an
/// already-billed (or being-billed) period costs. A version for a future month
/// is replaced if one exists: the old version and its tiers are deleted and a
/// new version, with a new id, is written. A version for the current month may
/// be created when the meter has none for it yet. The meter must exist
/// ([`Error::UnknownMeter`]).
///
/// Unpinned because `otto_app` cannot write the price book (migration 0020).
pub async fn set_version(
    tx: &mut Unpinned,
    meter: &str,
    month: Month,
    tiers: &Tiers,
    now: DateTime<Utc>,
) -> Result<SetOutcome> {
    let current = Month::of(now);
    if month < current {
        return Err(Error::PastMonth { month, current });
    }
    // FOR SHARE: the meter cannot be deleted while its price is written.
    let known: Option<String> =
        sqlx::query_scalar("SELECT key FROM meters WHERE key = $1 FOR SHARE")
            .bind(meter)
            .fetch_optional(tx.conn())
            .await?;
    if known.is_none() {
        return Err(Error::UnknownMeter(meter.to_owned()));
    }

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM price_versions WHERE meter = $1 AND effective_month = $2 FOR UPDATE",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_optional(tx.conn())
    .await?;
    if let Some(old) = existing {
        if month <= current {
            return Err(Error::InEffect {
                meter: meter.to_owned(),
                month,
            });
        }
        sqlx::query("DELETE FROM price_versions WHERE id = $1")
            .bind(old)
            .execute(tx.conn())
            .await?;
    }

    let (id, created_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO price_versions (meter, effective_month) VALUES ($1, $2) \
         RETURNING id, created_at",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_one(tx.conn())
    .await?;
    for (position, tier) in tiers.as_slice().iter().enumerate() {
        // MAX_TIERS keeps every position inside smallint.
        let position = i16::try_from(position).map_err(|_| TierError::TooMany)?;
        sqlx::query(
            "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(position)
        .bind(tier.up_to)
        .bind(tier.unit_amount_ucents)
        .execute(tx.conn())
        .await?;
    }

    Ok(SetOutcome {
        version: PriceVersion {
            id,
            meter: meter.to_owned(),
            effective_month: month,
            created_at,
            tiers: tiers.clone(),
        },
        replaced: existing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(up_to: Option<i64>, unit_amount_ucents: i64) -> Tier {
        Tier {
            up_to,
            unit_amount_ucents,
        }
    }

    fn tiers(list: &[(Option<i64>, i64)]) -> Tiers {
        Tiers::new(list.iter().map(|&(u, a)| tier(u, a)).collect()).unwrap()
    }

    fn cents(quantity: i64, t: &Tiers) -> i64 {
        match rate(quantity, Some(t)).unwrap() {
            LineAmount::Priced { cents } => cents,
            LineAmount::Unpriced => panic!("priced tiers rated as unpriced"),
        }
    }

    /// 100 free, then 1 cent each to 1,000, then 0.5 cents each.
    fn three_tiers() -> Tiers {
        tiers(&[
            (Some(100), 0),
            (Some(1_000), UCENTS_PER_CENT),
            (None, UCENTS_PER_CENT / 2),
        ])
    }

    #[test]
    fn rating_across_tier_edges() {
        let t = three_tiers();
        assert_eq!(cents(0, &t), 0);
        assert_eq!(cents(1, &t), 0);
        assert_eq!(cents(100, &t), 0, "the whole free allowance is free");
        assert_eq!(cents(101, &t), 1, "the first unit past the allowance");
        assert_eq!(cents(1_000, &t), 900, "the last unit of the second tier");
        assert_eq!(cents(1_001, &t), 901, "0.5 rounds half up");
        assert_eq!(cents(1_002, &t), 901);
        assert_eq!(cents(2_000, &t), 900 + 500);
    }

    #[test]
    fn a_single_unbounded_tier_is_a_flat_rate() {
        let t = tiers(&[(None, 2 * UCENTS_PER_CENT)]);
        assert_eq!(cents(0, &t), 0);
        assert_eq!(cents(7, &t), 14);
    }

    #[test]
    fn zero_quantity_is_zero_and_still_priced() {
        assert_eq!(
            rate(0, Some(&three_tiers())).unwrap(),
            LineAmount::Priced { cents: 0 }
        );
    }

    #[test]
    fn rounding_is_half_up_once_per_line() {
        // 0.4999995 cents per unit.
        let t = tiers(&[(None, 499_999)]);
        assert_eq!(cents(1, &t), 0, "0.499999 rounds down");
        // Exactly half a cent.
        let half = tiers(&[(None, 500_000)]);
        assert_eq!(cents(1, &half), 1, ".5 rounds up");
        assert_eq!(cents(3, &half), 2, "1.5 rounds up");
        assert_eq!(cents(2, &half), 1, "1.0 is exact");
        let just_under = tiers(&[(None, 1_499_999)]);
        assert_eq!(cents(1, &just_under), 1, "1.499999 rounds down");

        // Two tiers that each come to 0.4 cents: 0.8 in total, so 1 cent. Per
        // tier rounding would make it 0.
        let split = tiers(&[(Some(1), 400_000), (None, 400_000)]);
        assert_eq!(cents(2, &split), 1);
        // Two tiers that each come to 0.5: 1.0 in total, not 1 + 1.
        let halves = tiers(&[(Some(1), 500_000), (None, 500_000)]);
        assert_eq!(cents(2, &halves), 1);
    }

    #[test]
    fn huge_quantities_rate_exactly() {
        // i64::MAX units at 1 ucent: i64::MAX / 1e6 cents, rounded half up.
        let t = tiers(&[(None, 1)]);
        let expected = (i64::MAX / UCENTS_PER_CENT)
            + i64::from(i64::MAX % UCENTS_PER_CENT >= UCENTS_PER_CENT / 2);
        assert_eq!(cents(i64::MAX, &t), expected);

        // A bound at i64::MAX on a middle tier is still finite.
        let t = tiers(&[(Some(i64::MAX - 1), 0), (None, UCENTS_PER_CENT)]);
        assert_eq!(cents(i64::MAX, &t), 1);
    }

    #[test]
    fn an_amount_beyond_i64_cents_is_refused_not_wrapped() {
        let t = tiers(&[(None, i64::MAX)]);
        assert_eq!(rate(i64::MAX, Some(&t)), Err(RateError::Overflow));
        // Just inside: i64::MAX ucents per unit is ~9.2e12 cents; 1e6 units of
        // it is ~9.2e18 cents, which fits.
        assert_eq!(
            rate(1_000_000, Some(&t)).unwrap().cents(),
            i64::MAX,
            "1e6 units of i64::MAX ucents is exactly i64::MAX cents"
        );
        assert_eq!(rate(1_000_001, Some(&t)), Err(RateError::Overflow));
    }

    #[test]
    fn an_unpriced_meter_rates_zero_and_says_so() {
        let line = rate(5_000, None).unwrap();
        assert_eq!(line, LineAmount::Unpriced);
        assert_eq!(line.cents(), 0);
        assert!(!line.is_priced());
        assert!(rate(0, Some(&three_tiers())).unwrap().is_priced());
    }

    #[test]
    fn a_negative_quantity_is_refused() {
        assert_eq!(
            rate(-1, Some(&three_tiers())),
            Err(RateError::NegativeQuantity(-1))
        );
        assert_eq!(rate(-1, None), Err(RateError::NegativeQuantity(-1)));
    }

    #[test]
    fn malformed_tier_lists_are_refused() {
        let check = |list: &[(Option<i64>, i64)]| {
            Tiers::new(list.iter().map(|&(u, a)| tier(u, a)).collect()).unwrap_err()
        };
        assert_eq!(check(&[]), TierError::Empty);
        assert_eq!(check(&[(Some(10), 1)]), TierError::LastBounded);
        assert_eq!(
            check(&[(None, 1), (None, 2)]),
            TierError::UnboundedNotLast { position: 0 }
        );
        assert_eq!(
            check(&[(Some(10), 1), (Some(10), 1), (None, 1)]),
            TierError::NotIncreasing {
                position: 1,
                up_to: 10,
                previous: 10
            }
        );
        assert_eq!(
            check(&[(Some(10), 1), (Some(5), 1), (None, 1)]),
            TierError::NotIncreasing {
                position: 1,
                up_to: 5,
                previous: 10
            }
        );
        assert_eq!(
            check(&[(Some(0), 1), (None, 1)]),
            TierError::NonPositiveBound { position: 0 }
        );
        assert_eq!(
            check(&[(Some(-5), 1), (None, 1)]),
            TierError::NonPositiveBound { position: 0 }
        );
        assert_eq!(
            check(&[(Some(10), -1), (None, 1)]),
            TierError::NegativeAmount { position: 0 }
        );
        let many: Vec<(Option<i64>, i64)> = (1..=MAX_TIERS as i64)
            .map(Some)
            .chain([None])
            .map(|u| (u, 1))
            .collect();
        assert_eq!(check(&many), TierError::TooMany);
        assert!(Tiers::new(
            many[1..]
                .iter()
                .map(|&(u, a)| tier(u, a))
                .collect::<Vec<_>>()
        )
        .is_ok());
    }

    #[test]
    fn months_parse_strictly_and_round_trip() {
        let m: Month = "2026-02".parse().unwrap();
        assert_eq!(m.first_day(), NaiveDate::from_ymd_opt(2026, 2, 1).unwrap());
        assert_eq!(m.to_string(), "2026-02");
        for bad in [
            "",
            "2026",
            "2026-",
            "2026-00",
            "2026-13",
            "26-02",
            "2026-2",
            "2026/02",
            "2026-02-01",
            "+026-02",
            "2026-+2",
            " 2026-02",
        ] {
            assert!(bad.parse::<Month>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_month_contains_every_day_of_it() {
        let feb = Month::new(2028, 2).unwrap();
        for day in 1..=29 {
            let date = NaiveDate::from_ymd_opt(2028, 2, day).unwrap();
            assert_eq!(Month::containing(date), feb);
        }
        let at = DateTime::parse_from_rfc3339("2026-10-31T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(Month::of(at).to_string(), "2026-10");
        assert!(Month::new(2026, 13).is_none());
    }
}
