//! `savvagent-platform-server usage ...`: the operator's view of usage ingest.
//!
//! ```text
//! savvagent-platform-server usage held
//! ```
//!
//! Lists the events usage ingest held instead of billing
//! (`SAVVAGENT_USAGE_HOLD_THRESHOLD`, savvagent/otto-platform#79), oldest first.
//! A held event is not counted, not billed and not queued for Stripe; it has
//! been acknowledged to its shipper, which will not resend it. It needs only
//! `DATABASE_URL`.

use std::io::Write;

use savvagent_tenant::Db;

pub const USAGE: &str = "\
usage: savvagent-platform-server usage <command>

commands:
  held  list usage events held for review instead of billed
";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Held,
}

/// Parse the arguments after `usage`.
pub fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [] => Err("missing command".into()),
        [cmd] if cmd == "held" => Ok(Command::Held),
        [cmd, ..] if cmd == "held" => Err("`held` takes no arguments".into()),
        [cmd, ..] => Err(format!("unknown command {cmd:?}")),
    }
}

pub async fn execute(db: &Db, cmd: Command, out: &mut impl Write) -> anyhow::Result<()> {
    match cmd {
        Command::Held => {
            let held = savvagent_billing::usage::list_held(db).await?;
            if held.is_empty() {
                writeln!(out, "no usage events are held")?;
                return Ok(());
            }
            for h in &held {
                writeln!(
                    out,
                    "{} org={} resource={} event={} meter={} quantity={} period={} \
                     occurred_at={} | {}",
                    h.created_at.to_rfc3339(),
                    h.org_id,
                    h.resource_uri,
                    h.event_id,
                    h.meter,
                    h.quantity,
                    h.period_start,
                    h.occurred_at.to_rfc3339(),
                    h.reason
                )?;
            }
            writeln!(
                out,
                "{} usage event(s) held: not counted and not billed",
                held.len()
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_held_only() {
        assert_eq!(parse(&args(&["held"])), Ok(Command::Held));
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["held", "x"])).is_err());
        assert!(parse(&args(&["nope"])).is_err());
    }
}
