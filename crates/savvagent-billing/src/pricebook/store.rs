//! The storage half of the price book: reading and writing `price_versions`
//! and `price_tiers` (migration 0020).

use chrono::{DateTime, Duration, NaiveDate, Utc};
use savvagent_tenant::Unpinned;
use sqlx::PgConnection;
use uuid::Uuid;

use super::rate::{Month, Tier, TierError, Tiers};
use crate::meters::Meter;

/// A price-book failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "no meter {0:?}: a service declares its meters (PUT /internal/meters) before they can \
         be priced"
    )]
    UnknownMeter(String),
    #[error(
        "{month} is not after the current month ({current}); a price takes effect from a \
         future month only, so a period being billed, or already billed, never changes price"
    )]
    NotFuture { month: Month, current: Month },
    #[error(
        "{month} starts in less than {} hours; a price must be set at least that long before \
         its month starts, so Stripe has its price switch scheduled in time. The earliest \
         month that can be priced now is {earliest}",
        MIN_LEAD.num_hours()
    )]
    TooSoon { month: Month, earliest: Month },
    #[error(
        "the price of {meter} for {month} was set concurrently by another run; re-run \
         `pricebook list` to see which one was kept"
    )]
    Concurrent { meter: String, month: Month },
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

/// One version of one meter's price, checked.
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

/// One stored version as [`list_versions`] reports it: its tiers, or why they
/// cannot be priced. Lets an operator listing the book find a malformed
/// version instead of being refused the whole list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRecord {
    pub id: Uuid,
    pub meter: String,
    pub effective_month: Month,
    pub created_at: DateTime<Utc>,
    pub tiers: std::result::Result<Tiers, String>,
}

impl TryFrom<VersionRecord> for PriceVersion {
    type Error = Error;

    fn try_from(r: VersionRecord) -> Result<Self> {
        match r.tiers {
            Ok(tiers) => Ok(Self {
                id: r.id,
                meter: r.meter,
                effective_month: r.effective_month,
                created_at: r.created_at,
                tiers,
            }),
            Err(reason) => Err(Error::Corrupt {
                version: r.id,
                reason,
            }),
        }
    }
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
    /// The version that was in effect for the month before this one was
    /// written (the replaced one, or an earlier month's), if any: what the
    /// month would have cost.
    pub before: Option<VersionRecord>,
}

/// How long before its month starts a price version must be set: long enough
/// for many runs of Stripe sync to schedule the switch before 00:00 UTC on
/// the first.
pub const MIN_LEAD: Duration = Duration::hours(24);

/// The earliest month whose price can be set at `now`: next month, unless it
/// starts within [`MIN_LEAD`], then the month after.
///
/// ```
/// use chrono::{TimeZone, Utc};
/// use savvagent_billing::pricebook::{store::earliest_month_at, Month};
///
/// let mid = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
/// assert_eq!(earliest_month_at(mid), Some(Month::new(2026, 11).unwrap()));
/// let last_day = Utc.with_ymd_and_hms(2026, 10, 31, 0, 0, 1).unwrap();
/// assert_eq!(earliest_month_at(last_day), Some(Month::new(2026, 12).unwrap()));
/// ```
pub fn earliest_month_at(now: DateTime<Utc>) -> Option<Month> {
    let next = Month::of(now).offset(1)?;
    if crate::period::starts_at(next) - now >= MIN_LEAD {
        Some(next)
    } else {
        next.offset(1)
    }
}

/// [`earliest_month_at`] by the database's clock.
pub async fn earliest_month(conn: &mut PgConnection) -> Result<Month> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()").fetch_one(conn).await?;
    earliest_month_at(now).ok_or(Error::NotFuture {
        month: Month::of(now),
        current: Month::of(now),
    })
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

/// A version row joined to its meter, for [`book_in_effect`].
#[derive(sqlx::FromRow)]
struct BookRow {
    #[sqlx(flatten)]
    version: VersionRow,
    meter_service: String,
    meter_name: String,
    meter_display_name: String,
    meter_unit: String,
    meter_created_at: DateTime<Utc>,
    meter_updated_at: DateTime<Utc>,
}

/// Attach each version's tiers, in the order given, checking them as
/// [`Tiers`] does. A version that fails the check is reported, not dropped.
async fn records(conn: &mut PgConnection, rows: Vec<VersionRow>) -> Result<Vec<VersionRecord>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let tier_rows: Vec<TierRow> = sqlx::query_as(
        "SELECT version_id, position, up_to, unit_amount_ucents FROM price_tiers \
         WHERE version_id = ANY($1) ORDER BY version_id, position",
    )
    .bind(&ids)
    .fetch_all(conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let mine = tier_rows.iter().filter(|t| t.version_id == row.id);
            let effective_month = Month::containing(row.effective_month);
            let tiers = check_tiers(mine).and_then(|tiers| {
                if effective_month.first_day() == row.effective_month {
                    Ok(tiers)
                } else {
                    Err("the effective month is not a first of month".into())
                }
            });
            VersionRecord {
                id: row.id,
                meter: row.meter,
                effective_month,
                created_at: row.created_at,
                tiers,
            }
        })
        .collect())
}

fn check_tiers<'a>(rows: impl Iterator<Item = &'a TierRow>) -> std::result::Result<Tiers, String> {
    let mut tiers = Vec::new();
    for (expected, t) in rows.enumerate() {
        if usize::try_from(t.position).ok() != Some(expected) {
            return Err(format!("tier positions are not 0..n (at {expected})"));
        }
        tiers.push(Tier {
            up_to: t.up_to,
            unit_amount_ucents: t.unit_amount_ucents,
        });
    }
    Tiers::new(tiers).map_err(|e| e.to_string())
}

/// The current month by the database's clock (UTC), which is the one clock
/// every instance and the operator CLI share.
pub async fn current_month(conn: &mut PgConnection) -> Result<Month> {
    let first: NaiveDate =
        sqlx::query_scalar("SELECT date_trunc('month', now() AT TIME ZONE 'UTC')::date")
            .fetch_one(conn)
            .await?;
    Ok(Month::containing(first))
}

/// The version of `meter`'s price in effect during `month`, by
/// [`super::month_in_effect`]'s rule. `None` means the meter is unpriced for
/// that month (which [`super::rate`] reports as
/// [`super::LineAmount::Unpriced`]).
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
    records(conn, rows)
        .await?
        .pop()
        .map(PriceVersion::try_from)
        .transpose()
}

/// Every meter that has a price in effect during `month`, with that price, by
/// meter key. Meters with no price in effect are left out.
pub async fn book_in_effect(conn: &mut PgConnection, month: Month) -> Result<Vec<PricedMeter>> {
    let rows: Vec<BookRow> = sqlx::query_as(
        "SELECT DISTINCT ON (v.meter) \
                v.id, v.meter, v.effective_month, v.created_at, \
                m.service AS meter_service, m.meter AS meter_name, \
                m.display_name AS meter_display_name, m.unit AS meter_unit, \
                m.created_at AS meter_created_at, m.updated_at AS meter_updated_at \
         FROM price_versions v JOIN meters m ON m.key = v.meter \
         WHERE v.effective_month <= $1 \
         ORDER BY v.meter, v.effective_month DESC",
    )
    .bind(month.first_day())
    .fetch_all(&mut *conn)
    .await?;

    let (versions, meters): (Vec<VersionRow>, Vec<Meter>) = rows
        .into_iter()
        .map(|r| {
            let meter = Meter {
                key: r.version.meter.clone(),
                service: r.meter_service,
                meter: r.meter_name,
                display_name: r.meter_display_name,
                unit: r.meter_unit,
                created_at: r.meter_created_at,
                updated_at: r.meter_updated_at,
            };
            (r.version, meter)
        })
        .unzip();
    // `records` keeps the order it is given, so the two lists stay paired.
    records(conn, versions)
        .await?
        .into_iter()
        .zip(meters)
        .map(|(record, meter)| {
            Ok(PricedMeter {
                meter,
                version: record.try_into()?,
            })
        })
        .collect()
}

/// Every stored version of every meter's price, by meter key, oldest month
/// first, each with its tiers or the reason they cannot be priced.
pub async fn list_versions(conn: &mut PgConnection) -> Result<Vec<VersionRecord>> {
    let rows: Vec<VersionRow> = sqlx::query_as(
        "SELECT id, meter, effective_month, created_at FROM price_versions \
         ORDER BY meter, effective_month",
    )
    .fetch_all(&mut *conn)
    .await?;
    records(conn, rows).await
}

/// Write `meter`'s price from `month` on.
///
/// `month` must be after the current month by the database's clock
/// ([`current_month`]), or this is [`Error::NotFuture`]: a version for the
/// current or an earlier month would change what a period being billed, or
/// already billed, costs. It must also start at least [`MIN_LEAD`] from now
/// ([`earliest_month`]), or this is [`Error::TooSoon`], so Stripe sync has
/// the switch scheduled well before the month begins. A meter with no price
/// therefore gets its first one from next month at the earliest. If `meter` already has a version for `month`, that
/// version and its tiers are deleted and a new version, with a new id, is
/// written. The meter must exist ([`Error::UnknownMeter`]). Two runs for the
/// same meter and month at once: one wins, the other is
/// [`Error::Concurrent`].
///
/// Unpinned because `otto_app` cannot write the price book (migration 0020).
pub async fn set_version(
    tx: &mut Unpinned,
    meter: &str,
    month: Month,
    tiers: &Tiers,
) -> Result<SetOutcome> {
    let current = current_month(tx.conn()).await?;
    if month <= current {
        return Err(Error::NotFuture { month, current });
    }
    let earliest = earliest_month(tx.conn()).await?;
    if month < earliest {
        return Err(Error::TooSoon { month, earliest });
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

    let before: Vec<VersionRow> = sqlx::query_as(
        "SELECT id, meter, effective_month, created_at FROM price_versions \
         WHERE meter = $1 AND effective_month <= $2 \
         ORDER BY effective_month DESC LIMIT 1",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_all(tx.conn())
    .await?;
    let before = records(tx.conn(), before).await?.pop();

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM price_versions WHERE meter = $1 AND effective_month = $2 FOR UPDATE",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_optional(tx.conn())
    .await?;
    if let Some(old) = existing {
        sqlx::query("DELETE FROM price_versions WHERE id = $1")
            .bind(old)
            .execute(tx.conn())
            .await?;
    }

    let inserted: std::result::Result<(Uuid, DateTime<Utc>), sqlx::Error> = sqlx::query_as(
        "INSERT INTO price_versions (meter, effective_month) VALUES ($1, $2) \
         RETURNING id, created_at",
    )
    .bind(meter)
    .bind(month.first_day())
    .fetch_one(tx.conn())
    .await;
    let (id, created_at) = match inserted {
        Ok(row) => row,
        // Another run inserted this (meter, month) after our FOR UPDATE found
        // nothing to lock, and committed first.
        Err(sqlx::Error::Database(e))
            if e.code().as_deref() == Some("23505")
                && e.constraint() == Some("price_versions_meter_month") =>
        {
            return Err(Error::Concurrent {
                meter: meter.to_owned(),
                month,
            });
        }
        Err(e) => return Err(e.into()),
    };
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
        before,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn a_month_must_start_a_full_day_after_now() {
        let nov = Month::new(2026, 11).unwrap();
        let dec = Month::new(2026, 12).unwrap();
        let start = crate::period::starts_at(nov);
        assert_eq!(earliest_month_at(start - MIN_LEAD), Some(nov));
        assert_eq!(
            earliest_month_at(start - MIN_LEAD + Duration::seconds(1)),
            Some(dec)
        );
        assert_eq!(
            earliest_month_at(Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap()),
            Some(nov)
        );
        // December 31st: next year's February.
        let new_year = Utc.with_ymd_and_hms(2026, 12, 31, 12, 0, 0).unwrap();
        assert_eq!(earliest_month_at(new_year), Month::new(2027, 2));
    }
}
