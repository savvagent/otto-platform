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
//! Only a future month can be priced, judged by the database's clock: the
//! current month and earlier ones are refused, so a period being billed, or
//! already billed, never changes price, and a meter with no price gets its
//! first one from next month. Running `set` again for the same future month
//! replaces that version with a new one (a new id). See
//! `otto_billing::pricebook::set_version`.
//!
//! `list` prints every version of every meter's price as
//! `meter  month  in-effect|scheduled|superseded  tiers  id`, and a line for
//! every declared meter with no price in effect: `unpriced`, or
//! `unpriced (scheduled YYYY-MM)` when its first price is coming. A stored
//! version that cannot be priced shows `corrupt: <reason>` in place of its
//! tiers, so it can be found and fixed.

use std::collections::BTreeSet;
use std::io::Write;

use otto_billing::meters::is_meter_name;
use otto_billing::pricebook::{self, month_in_effect, Month, Tier, Tiers, VersionRecord};
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server pricebook <command>

commands:
  set <service>/<meter> --effective YYYY-MM --tier <up_to|inf>:<ucents> [--tier ...]
                       set a meter's graduated price from the start of a future month
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

/// Run a parsed command, writing human-readable output to `out`. Which months
/// are past, current or future is the database's call
/// ([`pricebook::current_month`]), not this machine's clock.
pub async fn execute(db: &Db, cmd: Command, out: &mut impl Write) -> anyhow::Result<()> {
    match cmd {
        Command::Set {
            meter,
            effective,
            tiers,
        } => {
            let mut tx = db.begin_unpinned().await?;
            let outcome = pricebook::set_version(&mut tx, &meter, effective, &tiers).await?;
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
            let current = pricebook::current_month(tx.conn()).await?;
            let versions = pricebook::list_versions(tx.conn()).await?;
            let declared: Vec<String> = sqlx::query_scalar("SELECT key FROM meters")
                .fetch_all(tx.conn())
                .await?;
            tx.commit().await?;
            write_book(out, current, &declared, &versions)?;
        }
    }
    Ok(())
}

/// The `list` output. See the module docs for its shape.
fn write_book(
    out: &mut impl Write,
    current: Month,
    declared: &[String],
    versions: &[VersionRecord],
) -> std::io::Result<()> {
    let keys: BTreeSet<&str> = declared
        .iter()
        .map(String::as_str)
        .chain(versions.iter().map(|v| v.meter.as_str()))
        .collect();
    for key in keys {
        // `list_versions` orders a meter's versions oldest month first.
        let mine: Vec<&VersionRecord> = versions.iter().filter(|v| v.meter == key).collect();
        let in_effect = month_in_effect(mine.iter().map(|v| v.effective_month), current);
        if in_effect.is_none() {
            match mine.iter().find(|v| v.effective_month > current) {
                Some(first) => writeln!(
                    out,
                    "{key}\t-\tunpriced (scheduled {})",
                    first.effective_month
                )?,
                None => writeln!(out, "{key}\t-\tunpriced")?,
            }
        }
        for v in mine {
            let status = if v.effective_month > current {
                "scheduled"
            } else if Some(v.effective_month) == in_effect {
                "in-effect"
            } else {
                "superseded"
            };
            let tiers = match &v.tiers {
                Ok(tiers) => format_tiers(tiers),
                Err(reason) => format!("corrupt: {reason}"),
            };
            writeln!(
                out,
                "{key}\t{}\t{status}\t{tiers}\t{}",
                v.effective_month, v.id
            )?;
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

    async fn run(db: &Db, line: &str) -> anyhow::Result<String> {
        let mut out = Vec::new();
        execute(db, parse(&args(line)).unwrap(), &mut out).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    async fn now_month(db: &Db) -> Month {
        let mut tx = db.begin_unpinned().await.unwrap();
        pricebook::current_month(tx.conn()).await.unwrap()
    }

    /// Registers `svc` and declares `svc/calls`, `svc/bytes` and `svc/later`.
    /// Fixtures, not real meters or rates.
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
             ('svc/bytes', 'svc', 'bytes', 'Bytes', 'byte'), \
             ('svc/later', 'svc', 'later', 'Later', 'thing')",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    /// A version already in effect, which `set` cannot write.
    async fn insert_flat(pool: &PgPool, meter: &str, m: Month, ucents: i64) -> uuid::Uuid {
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO price_versions (meter, effective_month) VALUES ($1, $2) RETURNING id",
        )
        .bind(meter)
        .bind(m.first_day())
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO price_tiers (version_id, position, up_to, unit_amount_ucents) \
             VALUES ($1, 0, NULL, $2)",
        )
        .bind(id)
        .bind(ucents)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn set_then_list_prints_the_book(pool: PgPool) {
        seed_meters(&pool).await;
        let db = Db::from_pool(pool.clone());
        let current = now_month(&db).await;
        let (prev2, prev, next) = (
            current.offset(-2).unwrap(),
            current.offset(-1).unwrap(),
            current.offset(1).unwrap(),
        );
        insert_flat(&pool, "svc/calls", prev2, 3000).await;
        insert_flat(&pool, "svc/calls", prev, 2500).await;
        // A version that cannot be priced, listed rather than failing the list.
        let bad = insert_flat(&pool, "svc/bytes", prev, 1).await;
        sqlx::query("UPDATE price_tiers SET up_to = 5 WHERE version_id = $1")
            .bind(bad)
            .execute(&pool)
            .await
            .unwrap();

        let out = run(
            &db,
            &format!("set svc/calls --effective {next} --tier 100:0 --tier inf:2000"),
        )
        .await
        .unwrap();
        assert!(
            out.starts_with(&format!("svc/calls from {next}: 100:0 inf:2000\n")),
            "{out}"
        );
        assert!(!out.contains("replaced"), "{out}");
        let replaced = run(
            &db,
            &format!("set svc/calls --effective {next} --tier inf:1900"),
        )
        .await
        .unwrap();
        assert!(replaced.contains("replaced version "), "{replaced}");
        run(
            &db,
            &format!("set svc/later --effective {next} --tier inf:5"),
        )
        .await
        .unwrap();

        let list = run(&db, "list").await.unwrap();
        let rows: Vec<Vec<String>> = list
            .lines()
            .map(|l| l.split('\t').take(4).map(str::to_owned).collect())
            .collect();
        let row = |cells: &[&str]| cells.iter().map(|c| c.to_string()).collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                row(&[
                    "svc/bytes",
                    &prev.to_string(),
                    "in-effect",
                    "corrupt: the last tier must be unbounded"
                ]),
                row(&["svc/calls", &prev2.to_string(), "superseded", "inf:3000"]),
                row(&["svc/calls", &prev.to_string(), "in-effect", "inf:2500"]),
                row(&["svc/calls", &next.to_string(), "scheduled", "inf:1900"]),
                row(&["svc/later", "-", &format!("unpriced (scheduled {next})")]),
                row(&["svc/later", &next.to_string(), "scheduled", "inf:5"]),
            ],
            "{list}"
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn list_names_meters_with_no_price(pool: PgPool) {
        seed_meters(&pool).await;
        let db = Db::from_pool(pool);
        assert_eq!(
            run(&db, "list").await.unwrap(),
            "svc/bytes\t-\tunpriced\nsvc/calls\t-\tunpriced\nsvc/later\t-\tunpriced\n"
        );
    }

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn set_refuses_an_unknown_meter_and_any_month_not_in_the_future(pool: PgPool) {
        seed_meters(&pool).await;
        let db = Db::from_pool(pool.clone());
        let current = now_month(&db).await;
        let next = current.offset(1).unwrap();
        insert_flat(&pool, "svc/calls", current.offset(-1).unwrap(), 1).await;

        let err = run(
            &db,
            &format!("set svc/nope --effective {next} --tier inf:1"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no meter \"svc/nope\""), "{err}");

        for m in [current.offset(-1).unwrap(), current] {
            for meter in ["svc/calls", "svc/bytes"] {
                let err = run(&db, &format!("set {meter} --effective {m} --tier inf:2"))
                    .await
                    .unwrap_err();
                assert!(
                    err.to_string().contains("is not after the current month"),
                    "{meter} {m}: {err}"
                );
            }
        }

        assert_eq!(
            run(&db, "list").await.unwrap().lines().count(),
            3,
            "nothing refused was written: one version and two unpriced meters"
        );
    }
}
