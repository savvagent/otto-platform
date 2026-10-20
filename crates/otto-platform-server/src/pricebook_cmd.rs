//! `otto-platform-server pricebook ...` — the operator's way to set what each
//! value meter costs (savvagent/otto-platform#60).
//!
//! ```text
//! otto-platform-server pricebook set <service>/<meter> --effective YYYY-MM \
//!     --tier <up_to|inf>:<ucents> [--tier <up_to|inf>:<ucents>]...
//! otto-platform-server pricebook list
//! ```
//!
//! `set` writes one version of a meter's price: graduated tiers, in order,
//! each `<up_to>:<ucents>` (units up to and including `up_to` this month, at
//! `ucents` millionths of a cent each) and the last `inf:<ucents>`. A free
//! allowance is a first tier at 0. The bounds must be strictly increasing and
//! only the last tier unbounded; the meter must already be declared by its
//! service. The version takes effect at 00:00 UTC on the first of the month.
//!
//! Past prices never change: a month before the current one is refused, and so
//! is replacing the current month's price once set. A future month's price is
//! replaced by running `set` again, which writes a new version (a new id) in
//! its place. See `otto_billing::pricebook::set_version`.
//!
//! `list` prints every version of every meter's price, marking the one in
//! effect now, and every declared meter that has no price.

use std::collections::BTreeSet;
use std::io::Write;

use chrono::{DateTime, Utc};
use otto_billing::meters::is_meter_name;
use otto_billing::pricebook::{self, Month, Tier, Tiers};
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server pricebook <command>

commands:
  set <service>/<meter> --effective YYYY-MM --tier <up_to|inf>:<ucents> [--tier ...]
                       set a meter's graduated price from the start of a month
                       (ucents = millionths of a US cent per unit; the last tier is inf)
  list                 print every price version and every unpriced meter
";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Set {
        meter: String,
        effective: Month,
        tiers: Tiers,
    },
    List,
}

/// Parse the arguments after `pricebook`.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let (cmd, rest) = args.split_first().ok_or("missing command")?;
    let mut positional: Vec<&str> = Vec::new();
    let mut effective: Option<&str> = None;
    let mut tiers: Vec<&str> = Vec::new();
    let mut it = rest.iter().map(String::as_str);
    while let Some(a) = it.next() {
        match a {
            "--effective" => {
                let v = it.next().ok_or("--effective needs a value")?;
                if effective.replace(v).is_some() {
                    return Err("--effective given more than once".into());
                }
            }
            "--tier" => tiers.push(it.next().ok_or("--tier needs a value")?),
            _ if a.starts_with("--") => return Err(format!("unknown flag {a}")),
            _ => positional.push(a),
        }
    }

    match cmd.as_str() {
        "set" => {
            let [meter] = positional.as_slice() else {
                return Err("expected exactly one <service>/<meter>".into());
            };
            let effective = effective
                .ok_or("--effective YYYY-MM is required")?
                .parse::<Month>()
                .map_err(|e| e.to_string())?;
            let tiers = tiers
                .iter()
                .map(|t| parse_tier(t))
                .collect::<Result<Vec<_>, _>>()?;
            if tiers.is_empty() {
                return Err("at least one --tier is required; the last is inf:<ucents>".into());
            }
            Ok(Command::Set {
                meter: meter_key(meter)?,
                effective,
                tiers: Tiers::new(tiers).map_err(|e| e.to_string())?,
            })
        }
        "list" if positional.is_empty() && effective.is_none() && tiers.is_empty() => {
            Ok(Command::List)
        }
        "list" => Err("list takes no arguments".into()),
        other => Err(format!("unknown command {other:?}")),
    }
}

/// `<service>/<meter>`, each part a slug. Whether the meter exists is checked
/// against the database when the command runs.
fn meter_key(key: &str) -> Result<String, String> {
    match key.split_once('/') {
        Some((service, meter))
            if otto_auth::resources::is_service_slug(service) && is_meter_name(meter) =>
        {
            Ok(key.to_owned())
        }
        _ => Err(format!(
            "`{key}` is not a meter key: expected <service>/<meter>, e.g. otto-flags/evaluations"
        )),
    }
}

/// Digits only: no sign, no separators, no exponent. A price is typed by hand,
/// so anything else is more likely a mistake than a number.
fn parse_count(field: &str, s: &str) -> Result<i64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{field} must be a whole number, got {s:?}"));
    }
    s.parse()
        .map_err(|_| format!("{field} {s} is too large (at most {})", i64::MAX))
}

/// `<up_to|inf>:<ucents>`.
fn parse_tier(s: &str) -> Result<Tier, String> {
    let (up_to, ucents) = s
        .split_once(':')
        .ok_or_else(|| format!("--tier expects <up_to|inf>:<ucents>, got {s:?}"))?;
    let up_to = match up_to {
        "inf" => None,
        n => Some(parse_count("a tier's up_to", n)?),
    };
    Ok(Tier {
        up_to,
        unit_amount_ucents: parse_count("a tier's ucents", ucents)?,
    })
}

/// `1000:0 inf:150000`: the form `set` takes.
fn format_tiers(tiers: &Tiers) -> String {
    tiers
        .as_slice()
        .iter()
        .map(|t| match t.up_to {
            Some(n) => format!("{n}:{}", t.unit_amount_ucents),
            None => format!("inf:{}", t.unit_amount_ucents),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run a parsed command, writing human-readable output to `out`. `now` decides
/// which months are past and which version is in effect.
pub async fn execute(
    db: &Db,
    cmd: Command,
    now: DateTime<Utc>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match cmd {
        Command::Set {
            meter,
            effective,
            tiers,
        } => {
            let mut tx = db.begin_unpinned().await?;
            let outcome = pricebook::set_version(&mut tx, &meter, effective, &tiers, now).await?;
            tx.commit().await?;
            writeln!(
                out,
                "{meter} from {effective}: {}",
                format_tiers(&outcome.version.tiers)
            )?;
            writeln!(out, "version {}", outcome.version.id)?;
            if let Some(old) = outcome.replaced {
                writeln!(out, "replaced version {old}")?;
            }
        }
        Command::List => {
            let mut tx = db.begin_unpinned().await?;
            let versions = pricebook::list_versions(tx.conn()).await?;
            let meters: Vec<String> = sqlx::query_scalar("SELECT key FROM meters ORDER BY key")
                .fetch_all(tx.conn())
                .await?;
            tx.commit().await?;

            let current = Month::of(now);
            for (i, v) in versions.iter().enumerate() {
                // Versions come by meter, oldest month first, so the one in
                // effect is the last of its meter's not after this month.
                let next = versions.get(i + 1).filter(|n| n.meter == v.meter);
                let status = if v.effective_month > current {
                    "scheduled"
                } else if next.is_some_and(|n| n.effective_month <= current) {
                    "superseded"
                } else {
                    "in-effect"
                };
                writeln!(
                    out,
                    "{}\t{}\t{status}\t{}\t{}",
                    v.meter,
                    v.effective_month,
                    format_tiers(&v.tiers),
                    v.id,
                )?;
            }
            let priced: BTreeSet<&str> = versions.iter().map(|v| v.meter.as_str()).collect();
            for meter in meters.iter().filter(|m| !priced.contains(m.as_str())) {
                writeln!(out, "{meter}\t-\tunpriced")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn tier(up_to: Option<i64>, unit_amount_ucents: i64) -> Tier {
        Tier {
            up_to,
            unit_amount_ucents,
        }
    }

    #[test]
    fn parses_set() {
        assert_eq!(
            parse(&args(
                "set otto-flags/evaluations --effective 2026-11 --tier 1000:0 --tier inf:150000"
            ))
            .unwrap(),
            Command::Set {
                meter: "otto-flags/evaluations".into(),
                effective: "2026-11".parse().unwrap(),
                tiers: Tiers::new(vec![tier(Some(1000), 0), tier(None, 150_000)]).unwrap(),
            }
        );
        // Flags in any order; a single unbounded tier is a flat rate.
        assert_eq!(
            parse(&args("set --tier inf:7 otto-x/calls --effective 2027-01")).unwrap(),
            Command::Set {
                meter: "otto-x/calls".into(),
                effective: "2027-01".parse().unwrap(),
                tiers: Tiers::new(vec![tier(None, 7)]).unwrap(),
            }
        );
        assert_eq!(parse(&args("list")).unwrap(), Command::List);
    }

    #[test]
    fn set_refuses_tiers_that_are_not_strictly_increasing_or_end_bounded() {
        for (line, why) in [
            (
                "set s/m --effective 2026-11 --tier 100:0 --tier 100:5 --tier inf:1",
                "a repeated bound",
            ),
            (
                "set s/m --effective 2026-11 --tier 100:0 --tier 50:5 --tier inf:1",
                "a decreasing bound",
            ),
            (
                "set s/m --effective 2026-11 --tier 100:0 --tier 200:5",
                "a bounded last tier",
            ),
            (
                "set s/m --effective 2026-11 --tier inf:0 --tier inf:5",
                "two unbounded tiers",
            ),
            (
                "set s/m --effective 2026-11 --tier inf:0 --tier 100:5",
                "an unbounded tier that is not last",
            ),
            (
                "set s/m --effective 2026-11 --tier 0:0 --tier inf:5",
                "a zero bound",
            ),
            ("set s/m --effective 2026-11", "no tiers"),
        ] {
            assert!(parse(&args(line)).is_err(), "{why}: {line}");
        }
    }

    #[test]
    fn set_refuses_malformed_input() {
        for line in [
            "set",
            "set s/m --tier inf:1",
            "set s/m --effective 2026-11 --effective 2026-12 --tier inf:1",
            "set s/m --effective 2026-1 --tier inf:1",
            "set s/m --effective 2026-13 --tier inf:1",
            "set s/m --effective --tier inf:1",
            "set s/m a/b --effective 2026-11 --tier inf:1",
            "set sm --effective 2026-11 --tier inf:1",
            "set S/m --effective 2026-11 --tier inf:1",
            "set s/M --effective 2026-11 --tier inf:1",
            "set s/m --effective 2026-11 --tier inf",
            "set s/m --effective 2026-11 --tier inf:-1",
            "set s/m --effective 2026-11 --tier inf:+1",
            "set s/m --effective 2026-11 --tier inf:1.5",
            "set s/m --effective 2026-11 --tier inf:1e6",
            "set s/m --effective 2026-11 --tier inf:1_000",
            "set s/m --effective 2026-11 --tier Inf:1",
            "set s/m --effective 2026-11 --tier -5:0 --tier inf:1",
            "set s/m --effective 2026-11 --tier inf:9223372036854775808",
            "set s/m --effective 2026-11 --tier inf:1 --bogus",
            "set s/m --effective 2026-11 --tier",
        ] {
            assert!(parse(&args(line)).is_err(), "{line}");
        }
        assert!(parse(&args(
            "set s/m --effective 2026-11 --tier inf:9223372036854775807"
        ))
        .is_ok());
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(parse(&[]).is_err());
        assert!(parse(&args("frobnicate")).is_err());
        assert!(parse(&args("list extra")).is_err());
        assert!(parse(&args("list --tier inf:1")).is_err());
    }

    async fn run(db: &Db, line: &str, now: &str) -> anyhow::Result<String> {
        let now = DateTime::parse_from_rfc3339(now)
            .unwrap()
            .with_timezone(&Utc);
        let mut out = Vec::new();
        execute(db, parse(&args(line)).unwrap(), now, &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Registers `svc` and declares `svc/calls` and `svc/bytes`. Fixtures, not
    /// real meters or rates.
    async fn seed_meters(pool: &PgPool) {
        sqlx::query(
            "INSERT INTO resource_servers (resource_uri, name, scopes, default_scopes, service) \
             VALUES ('https://svc.example/mcp', 'svc', '{a}', '{}', 'svc')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO meters (key, service, meter, display_name, unit) VALUES \
             ('svc/calls', 'svc', 'calls', 'Calls', 'call'), \
             ('svc/bytes', 'svc', 'bytes', 'Bytes', 'byte')",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn set_then_list_prints_the_book(pool: PgPool) {
        seed_meters(&pool).await;
        let db = Db::from_pool(pool);
        let now = "2026-10-20T12:00:00Z";

        let out = run(
            &db,
            "set svc/calls --effective 2026-10 --tier 100:0 --tier inf:2500",
            now,
        )
        .await
        .unwrap();
        assert!(
            out.starts_with("svc/calls from 2026-10: 100:0 inf:2500\n"),
            "{out}"
        );
        assert!(!out.contains("replaced"), "{out}");
        run(
            &db,
            "set svc/calls --effective 2026-12 --tier inf:2000",
            now,
        )
        .await
        .unwrap();
        let replaced = run(
            &db,
            "set svc/calls --effective 2026-12 --tier inf:1900",
            now,
        )
        .await
        .unwrap();
        assert!(replaced.contains("replaced version "), "{replaced}");

        let list = run(&db, "list", now).await.unwrap();
        let rows: Vec<Vec<&str>> = list
            .lines()
            .map(|l| l.split('\t').take(4).collect())
            .collect();
        assert_eq!(
            rows,
            [
                vec!["svc/calls", "2026-10", "in-effect", "100:0 inf:2500"],
                vec!["svc/calls", "2026-12", "scheduled", "inf:1900"],
                vec!["svc/bytes", "-", "unpriced"],
            ]
        );

        // Two months on, the December price is in effect and October's is not.
        let later = run(&db, "list", "2026-12-01T00:00:00Z").await.unwrap();
        assert!(
            later.contains("svc/calls\t2026-10\tsuperseded\t"),
            "{later}"
        );
        assert!(later.contains("svc/calls\t2026-12\tin-effect\t"), "{later}");
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn set_refuses_an_unknown_meter_and_a_past_month(pool: PgPool) {
        seed_meters(&pool).await;
        let db = Db::from_pool(pool);
        let now = "2026-10-20T12:00:00Z";

        let err = run(&db, "set svc/nope --effective 2026-11 --tier inf:1", now)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no meter \"svc/nope\""), "{err}");

        let err = run(&db, "set svc/calls --effective 2026-09 --tier inf:1", now)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("before the current month"),
            "{err}"
        );

        run(&db, "set svc/calls --effective 2026-10 --tier inf:1", now)
            .await
            .unwrap();
        let err = run(&db, "set svc/calls --effective 2026-10 --tier inf:2", now)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("in effect"), "{err}");

        assert_eq!(
            run(&db, "list", now).await.unwrap().lines().count(),
            2,
            "nothing refused was written"
        );
    }
}
