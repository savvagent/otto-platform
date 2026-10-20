//! The price book: what each value meter costs, as data (savvagent/otto-platform#60).
//!
//! A meter's price is a **version**: graduated tiers that take effect at
//! 00:00 UTC on the first day of a month ([`Month`]) and stay in effect until
//! the meter's next version. The tiers in effect for a billing period are
//! those of the latest version whose month is not after the period's month
//! ([`month_in_effect`], which [`tiers_in_effect`] and [`book_in_effect`]
//! apply in SQL). A meter with no such version is **unpriced**: it rates to 0
//! and says so ([`LineAmount::Unpriced`]), rather than looking free.
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
//! **Only the future is priced.** [`set_version`] writes a version only for a
//! month after the current one (by the database's clock), so a period that has
//! been, or is being, billed keeps the price it started with; a meter with no
//! price gets its first one from next month. A future version is replaced by a
//! new version with a new id, never edited: the id is what a Stripe Price is
//! recorded against, and Stripe prices are immutable.
//!
//! **Read by anyone, written by the operator.** `otto_app` may read the price
//! book but not write it (migration 0020), so the read functions take any
//! connection, pinned or not, and [`set_version`] takes an
//! [`otto_tenant::Unpinned`] transaction, which runs as the connecting role.
//!
//! Split in two: [`rate`](mod@rate) is the pure part (months, tiers, rating) and
//! [`store`] reads and writes the tables. Both are re-exported here.
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

pub mod rate;
pub mod store;

pub use rate::{
    month_in_effect, rate, LineAmount, Month, ParseMonthError, RateError, Tier, TierError, Tiers,
    MAX_TIERS, UCENTS_PER_CENT,
};
pub use store::{
    book_in_effect, current_month, list_versions, set_version, tiers_in_effect, Error,
    PriceVersion, PricedMeter, Result, SetOutcome, VersionRecord,
};
