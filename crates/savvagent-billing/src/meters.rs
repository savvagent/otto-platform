//! Value meters: what each otto-* service bills by, declared by the service
//! itself under its own service slug (epic savvagent/otto-platform#55).
//!
//! A meter's key is `<service>/<meter>`, e.g. `otto-flags/evaluations`. A
//! resource server declares its meters at startup (`PUT /internal/meters`),
//! and may declare only keys under the `service` an operator assigned it
//! (`resource_servers.service`). Declaring is an idempotent upsert: the same
//! declaration again changes nothing, and a changed display name or unit
//! replaces the old one. Nothing here removes a meter; one a service stops
//! declaring stays, because past usage was recorded against it.
//!
//! **Unpinned, not pinned.** `meters` is global reference data with no
//! `org_id` (migration 0017). `otto_app` may read it but not write it, the
//! plans rule, so declarations are written through
//! [`savvagent_tenant::Db::begin_unpinned`] as the connecting role.
//!
//! ```
//! use savvagent_billing::meters::{check_declaration, MeterSpec};
//!
//! let ok = MeterSpec { key: "otto-flags/evaluations", display_name: "Flag evaluations", unit: "evaluation" };
//! assert!(check_declaration("otto-flags", &ok).is_ok());
//!
//! // Another service's namespace is refused.
//! let theirs = MeterSpec { key: "otto-cxp/tickets", ..ok };
//! assert!(check_declaration("otto-flags", &theirs).is_err());
//! ```

use chrono::{DateTime, Utc};
use savvagent_core::error::Result;
use savvagent_tenant::Unpinned;
use sqlx::FromRow;

/// Longest meter name (the part after `/`), matching `meters_meter_slug`.
pub const MAX_METER_NAME_LEN: usize = 63;
/// Longest display name, in characters (`meters_display_name_len`).
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;
/// Longest unit, in characters (`meters_unit_len`).
pub const MAX_UNIT_CHARS: usize = 32;

/// One meter as a service declares it. Borrowed: the caller owns the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterSpec<'a> {
    /// `<service>/<meter>`.
    pub key: &'a str,
    pub display_name: &'a str,
    pub unit: &'a str,
}

/// A declaration that passed [`check_declaration`]: the key split into its
/// parts, and the display name and unit trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidMeter {
    pub key: String,
    pub service: String,
    pub meter: String,
    pub display_name: String,
    pub unit: String,
}

/// A declared meter, as the `meters` table holds it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Meter {
    pub key: String,
    pub service: String,
    pub meter: String,
    pub display_name: String,
    pub unit: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Whether `name` is a valid meter name: `^[a-z][a-z0-9_]{0,62}$`.
pub fn is_meter_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= MAX_METER_NAME_LEN
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Check one declaration from the resource server whose service slug is
/// `service`. The `Err` is a reason fit to return to that resource server: it
/// names the rule broken, never a database error.
pub fn check_declaration(
    service: &str,
    spec: &MeterSpec<'_>,
) -> std::result::Result<ValidMeter, String> {
    let Some((prefix, meter)) = spec.key.split_once('/') else {
        return Err(format!("`key` must be `{service}/<meter>`"));
    };
    if prefix != service {
        return Err(format!(
            "`key` must be under this resource server's service: `{service}/<meter>`"
        ));
    }
    if !is_meter_name(meter) {
        return Err(
            "the meter name must be a lower-case letter, then up to 62 lower-case letters, \
             digits or underscores"
                .into(),
        );
    }
    let display_name = check_text("display_name", spec.display_name, MAX_DISPLAY_NAME_CHARS)?;
    let unit = check_text("unit", spec.unit, MAX_UNIT_CHARS)?;
    Ok(ValidMeter {
        key: spec.key.to_owned(),
        service: service.to_owned(),
        meter: meter.to_owned(),
        display_name,
        unit,
    })
}

/// Bidi overrides and isolates, zero-width characters and the BOM. These names
/// end up on usage pages and invoices, where an invisible character can make
/// one meter read like another or reorder the text around it.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

fn check_text(field: &str, text: &str, max: usize) -> std::result::Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > max {
        return Err(format!("`{field}` must be 1 to {max} characters"));
    }
    if text
        .chars()
        .any(|c| c.is_control() || is_invisible_format(c))
    {
        return Err(format!(
            "`{field}` must not contain control or invisible formatting characters"
        ));
    }
    Ok(text.to_owned())
}

/// Upsert checked declarations. Idempotent: an unchanged meter is left alone
/// (its `updated_at` included), a changed display name or unit replaces the
/// stored one.
pub async fn upsert_meters(tx: &mut Unpinned, meters: &[ValidMeter]) -> Result<()> {
    for m in meters {
        sqlx::query(
            "INSERT INTO meters (key, service, meter, display_name, unit) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (key) DO UPDATE SET \
               display_name = EXCLUDED.display_name, \
               unit = EXCLUDED.unit, \
               updated_at = now() \
             WHERE (meters.display_name, meters.unit) \
                   IS DISTINCT FROM (EXCLUDED.display_name, EXCLUDED.unit)",
        )
        .bind(&m.key)
        .bind(&m.service)
        .bind(&m.meter)
        .bind(&m.display_name)
        .bind(&m.unit)
        .execute(tx.conn())
        .await?;
    }
    Ok(())
}

/// Every meter one service has declared, by key.
pub async fn list_meters(tx: &mut Unpinned, service: &str) -> Result<Vec<Meter>> {
    let rows = sqlx::query_as(
        "SELECT key, service, meter, display_name, unit, created_at, updated_at \
         FROM meters WHERE service = $1 ORDER BY key",
    )
    .bind(service)
    .fetch_all(tx.conn())
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(key: &'a str, display_name: &'a str, unit: &'a str) -> MeterSpec<'a> {
        MeterSpec {
            key,
            display_name,
            unit,
        }
    }

    #[test]
    fn a_good_declaration_is_split_and_trimmed() {
        let m = check_declaration(
            "otto-flags",
            &spec("otto-flags/evals_2", "  Evals ", " eval "),
        )
        .unwrap();
        assert_eq!(
            m,
            ValidMeter {
                key: "otto-flags/evals_2".into(),
                service: "otto-flags".into(),
                meter: "evals_2".into(),
                display_name: "Evals".into(),
                unit: "eval".into(),
            }
        );
    }

    #[test]
    fn keys_outside_the_callers_service_are_refused() {
        for key in [
            "otto-cxp/tickets",
            "otto-flag/evals",
            "otto-flagsx/evals",
            "evals",
            "/evals",
            "otto-flags/",
        ] {
            assert!(
                check_declaration("otto-flags", &spec(key, "X", "x")).is_err(),
                "{key:?}"
            );
        }
    }

    #[test]
    fn invisible_formatting_characters_are_refused() {
        for name in [
            "Jobs\u{202E}detelpmoc",
            "Jobs\u{200B}completed",
            "\u{FEFF}Jobs",
        ] {
            let refused =
                check_declaration("otto-flags", &spec("otto-flags/evaluations", name, "eval"));
            assert!(refused.is_err(), "{name:?} should be refused");
        }
    }

    #[test]
    fn malformed_fields_are_refused() {
        let long_meter = format!("otto-flags/a{}", "b".repeat(MAX_METER_NAME_LEN));
        let at_cap_meter = format!("otto-flags/a{}", "b".repeat(MAX_METER_NAME_LEN - 1));
        assert!(check_declaration("otto-flags", &spec(&at_cap_meter, "X", "x")).is_ok());
        let long_name = "é".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        let at_cap_name = "é".repeat(MAX_DISPLAY_NAME_CHARS);
        assert!(check_declaration("otto-flags", &spec("otto-flags/a", &at_cap_name, "x")).is_ok());
        let long_unit = "u".repeat(MAX_UNIT_CHARS + 1);
        for (key, name, unit) in [
            ("otto-flags/Evals", "X", "x"),
            ("otto-flags/1evals", "X", "x"),
            ("otto-flags/ev-als", "X", "x"),
            ("otto-flags/ev/als", "X", "x"),
            (long_meter.as_str(), "X", "x"),
            ("otto-flags/evals", "   ", "x"),
            ("otto-flags/evals", long_name.as_str(), "x"),
            ("otto-flags/evals", "two\nlines", "x"),
            ("otto-flags/evals", "X", ""),
            ("otto-flags/evals", "X", long_unit.as_str()),
            ("otto-flags/evals", "X", "a\tb"),
        ] {
            assert!(
                check_declaration("otto-flags", &spec(key, name, unit)).is_err(),
                "{key:?} {name:?} {unit:?}"
            );
        }
    }
}
