//! The pure half of the price book: months, tiers, and rating. No database.

/// Millionths of a cent in one cent.
pub const UCENTS_PER_CENT: i64 = 1_000_000;

/// The most tiers one version may have. Far more than a price needs; it keeps
/// a tier's position inside the `smallint` column and a typo'd command short.
pub const MAX_TIERS: usize = 64;

// ---------------------------------------------------------------- months

/// Defined in [`crate::period`], where every billing period is reckoned;
/// the price book versions by it too.
pub use crate::period::{Month, ParseMonthError};

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

// ------------------------------------------------------------- selection

/// The rule that decides which version is in effect: of the effective
/// `months` of one meter's versions, the latest that is not after `period`.
/// `None` means the meter is unpriced for `period`.
///
/// [`super::tiers_in_effect`] and [`super::book_in_effect`] apply the same
/// rule in SQL (`effective_month <= $period ORDER BY effective_month DESC`);
/// this is the form for callers already holding the versions.
///
/// ```
/// use otto_billing::pricebook::{month_in_effect, Month};
///
/// let m = |s: &str| s.parse::<Month>().unwrap();
/// let versions = [m("2026-01"), m("2026-04"), m("2026-07")];
/// assert_eq!(month_in_effect(versions, m("2026-05")), Some(m("2026-04")));
/// assert_eq!(month_in_effect(versions, m("2025-12")), None);
/// ```
pub fn month_in_effect(months: impl IntoIterator<Item = Month>, period: Month) -> Option<Month> {
    months.into_iter().filter(|&m| m <= period).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, NaiveDate, Utc};

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
    fn the_latest_month_not_after_the_period_is_in_effect() {
        let m = |s: &str| s.parse::<Month>().unwrap();
        let versions = [m("2026-07"), m("2026-01"), m("2026-04")];
        assert_eq!(month_in_effect(versions, m("2025-12")), None);
        assert_eq!(month_in_effect(versions, m("2026-01")), Some(m("2026-01")));
        assert_eq!(month_in_effect(versions, m("2026-03")), Some(m("2026-01")));
        assert_eq!(month_in_effect(versions, m("2026-04")), Some(m("2026-04")));
        assert_eq!(month_in_effect(versions, m("2031-01")), Some(m("2026-07")));
        assert_eq!(month_in_effect([], m("2026-01")), None);
    }

    #[test]
    fn months_offset_across_years() {
        let m = |s: &str| s.parse::<Month>().unwrap();
        assert_eq!(m("2026-11").offset(2), Some(m("2027-01")));
        assert_eq!(m("2026-01").offset(-1), Some(m("2025-12")));
        assert_eq!(m("2026-05").offset(0), Some(m("2026-05")));
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
