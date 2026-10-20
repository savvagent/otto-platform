//! One Stripe mode per database.
//!
//! A Stripe account has two separate worlds, live and test: a customer,
//! subscription, meter or price made with a test-mode key does not exist for
//! a live-mode key. Every Stripe id billing records belongs to the mode of
//! the key that made it. Booting with a key of the other mode would have sync
//! adopt nothing and create everything again (or fail on every recorded id),
//! and invoice nobody correctly. So the first boot with a key records its
//! mode in `stripe_account_mode` (global, one row, no `otto_app` access) and
//! every later one refuses to start on a mismatch ([`check_key_mode`]).

use otto_tenant::Db;

use super::{Error, Result};
use crate::stripe::{KeyMode, SecretKey};

/// The SQL an operator runs, unpinned as the owner role, to let the next
/// boot record a new mode. Only after clearing (or deliberately keeping) the
/// other mode's recorded Stripe ids; see docs/deploy/fly.md.
pub const RESET_MODE_SQL: &str = "DELETE FROM stripe_account_mode;";

/// The mode recorded for this database, if any.
pub async fn recorded_key_mode(db: &Db) -> Result<Option<KeyMode>> {
    let mut tx = db.begin_unpinned().await?;
    let mode: Option<String> = sqlx::query_scalar("SELECT mode FROM stripe_account_mode")
        .fetch_optional(tx.conn())
        .await?;
    tx.commit().await?;
    mode.map(|m| {
        KeyMode::parse(&m).ok_or_else(|| Error::Unexpected(format!("stored Stripe mode {m:?}")))
    })
    .transpose()
}

/// Record `key`'s mode if none is recorded yet, else check it matches.
///
/// # Errors
///
/// [`Error::UnknownKeyMode`] for a key whose prefix says neither live nor
/// test, [`Error::ModeMismatch`] for a key of the other mode (nothing is
/// written), or a database error. Never shows the key.
pub async fn check_key_mode(db: &Db, key: &SecretKey) -> Result<KeyMode> {
    let mode = key.mode().ok_or(Error::UnknownKeyMode)?;
    let mut tx = db.begin_unpinned().await?;
    sqlx::query(
        "INSERT INTO stripe_account_mode (mode) VALUES ($1) ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(mode.as_str())
    .execute(tx.conn())
    .await?;
    let recorded: String = sqlx::query_scalar("SELECT mode FROM stripe_account_mode")
        .fetch_one(tx.conn())
        .await?;
    tx.commit().await?;
    let recorded = KeyMode::parse(&recorded)
        .ok_or_else(|| Error::Unexpected(format!("stored Stripe mode {recorded:?}")))?;
    if recorded != mode {
        return Err(Error::ModeMismatch {
            recorded,
            key: mode,
        });
    }
    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn the_first_key_sets_the_mode_and_the_other_mode_is_refused(pool: sqlx::PgPool) {
        let db = Db::from_pool(pool.clone());
        let test = SecretKey::new("sk_test_supersecret").unwrap();
        let live = SecretKey::new("rk_live_supersecret").unwrap();
        assert_eq!(recorded_key_mode(&db).await.unwrap(), None);

        assert_eq!(check_key_mode(&db, &test).await.unwrap(), KeyMode::Test);
        // Again (every boot), and with another key of the same mode.
        assert_eq!(check_key_mode(&db, &test).await.unwrap(), KeyMode::Test);
        let other_test = SecretKey::new("rk_test_another").unwrap();
        assert_eq!(
            check_key_mode(&db, &other_test).await.unwrap(),
            KeyMode::Test
        );

        let err = check_key_mode(&db, &live).await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::ModeMismatch {
                    recorded: KeyMode::Test,
                    key: KeyMode::Live
                }
            ),
            "{err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("live-mode key"), "{msg}");
        assert!(msg.contains("docs/deploy/fly.md"), "{msg}");
        assert!(!msg.contains("supersecret"), "{msg}");
        assert_eq!(
            recorded_key_mode(&db).await.unwrap(),
            Some(KeyMode::Test),
            "a refused key changes nothing"
        );

        // The documented reset lets the next boot record the new mode.
        sqlx::query(RESET_MODE_SQL).execute(&pool).await.unwrap();
        assert_eq!(check_key_mode(&db, &live).await.unwrap(), KeyMode::Live);
        assert!(check_key_mode(&db, &test).await.is_err());
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn a_key_of_no_known_mode_is_refused_and_records_nothing(pool: sqlx::PgPool) {
        let db = Db::from_pool(pool);
        let odd = SecretKey::new("sk_supersecret").unwrap();
        let err = check_key_mode(&db, &odd).await.unwrap_err();
        assert!(matches!(err, Error::UnknownKeyMode), "{err}");
        assert!(!err.to_string().contains("supersecret"));
        assert_eq!(recorded_key_mode(&db).await.unwrap(), None);
    }
}
