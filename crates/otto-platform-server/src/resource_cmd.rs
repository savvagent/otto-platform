//! `otto-platform-server resource ...` — the operator's way to provision
//! resource servers: register one, issue or rotate its credentials, point its
//! lifecycle webhook somewhere.
//!
//! ```text
//! otto-platform-server resource register <resource-uri> --name <name> \
//!     --scopes a,b,c [--default-scopes a] [--scope-description a=text]... \
//!     [--service <slug>]
//! otto-platform-server resource set-service <resource-uri> <slug>
//! otto-platform-server resource rename-service <resource-uri> <new-slug>
//! otto-platform-server resource rename <old-uri> <new-uri> \
//!     --alias-until <RFC3339> [--name <name>]
//! otto-platform-server resource drop-alias <alias-uri>
//! otto-platform-server resource describe <resource-uri> \
//!     [--scope-description a=text]... [--clear]
//! otto-platform-server resource rotate-secret <resource-uri>
//! otto-platform-server resource set-webhook <resource-uri> <url>
//! otto-platform-server resource set-webhook <resource-uri> --clear
//! otto-platform-server resource enable|disable <resource-uri>
//! otto-platform-server resource list
//! ```
//!
//! `--scope-description scope=text` (repeatable) sets the human-readable text
//! the consent screen shows for a scope in place of its bare name. Text is
//! everything after the first `=`, so scope names must not contain one. On
//! `register` the flags, when given, replace the server's descriptions;
//! without them re-registering keeps what is there. `describe` always
//! replaces the whole set, so it is also how one is removed: repeat the
//! descriptions you want to keep, or pass `--clear` for none.
//!
//! `--service <slug>` on `register`, or `set-service`, assigns the service slug
//! the resource server's value meters are declared under (`<slug>/<meter>`).
//! Run it before a service that declares meters is released: until then its
//! declarations are refused (409 `service_not_set`) and its metered usage is
//! rejected as unknown. A slug is unique, and cannot be changed once the
//! service has declared meters under it. Re-registering without `--service`
//! leaves the slug alone.
//!
//! `rename-service` changes the slug after meters are declared, moving the
//! meters, their prices, and every org's usage pools and budgets to the new
//! name. It is refused, naming each blocker and its count, once anything under
//! the old meters records money: metered usage, a Stripe meter or price, or a
//! queued Stripe meter event. Pause the service's usage shipping first: a
//! batch in flight is refused (retriably) rather than stranded, and on retry a
//! metered event under an old meter key is rejected as unknown.
//!
//! `rename` moves a resource server to a new canonical URI in one
//! transaction: its tokens, authorization codes and usage dedupe ledger move
//! with it, and the old URI becomes an alias that still authenticates the
//! server at introspection until the `--alias-until` sunset (the server's
//! `aud` is then the old URI, so a server not yet reconfigured keeps working).
//! `--name` also changes the name on the consent screen. Renaming back onto a
//! live alias of the same server (`rename <new> <old>`) swaps the two URIs:
//! the rollback, keeping the alias's sunset unless `--alias-until` is given.
//! `drop-alias` ends an alias before its sunset. An alias row is never
//! deleted, and `register` and `rename` refuse any URI that is or was one, so
//! a retired URI is never handed to another server. `list` shows each alias
//! under its server with its sunset and state (`live`, `expired`, `dropped`).
//!
//! Secrets are printed once, on stdout, and cannot be read back: the
//! introspection secret is stored hashed, the webhook secret sealed. Losing
//! one means running the command again, which invalidates the old value.
//! `set-webhook` needs `OTTO_ENCRYPTION_KEY`, the same key the delivery task
//! opens secrets with.

use std::io::Write;

use chrono::{DateTime, Utc};
use otto_auth::resources::{self, ResourceAlias, ResourceServerSpec};
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server resource <command>

commands:
  register <resource-uri> --name <name> --scopes a,b [--default-scopes a]
           [--scope-description a=text]... [--service <slug>]
  set-service <resource-uri> <slug>   assign the service slug its value meters are keyed by
  rename-service <resource-uri> <new-slug>
                                      move its meters, prices, pools and budgets to a new slug,
                                      while none of its usage is metered or in Stripe;
                                      pause the service's usage shipping first
  rename <old-uri> <new-uri> --alias-until <RFC3339> [--name <name>]
                                      move it to a new canonical URI, keeping the old one as
                                      an alias until the sunset; renaming back onto a live
                                      alias swaps the two (--alias-until optional then)
  drop-alias <alias-uri>              end an alias before its sunset
  describe <resource-uri> [--scope-description a=text]... [--clear]
                                      replace the scope descriptions shown on the consent screen
  rotate-secret <resource-uri>        issue a new introspection credential
  set-webhook <resource-uri> <url>    set the lifecycle webhook, issue a new signing secret
  set-webhook <resource-uri> --clear  remove the webhook
  enable <resource-uri>
  disable <resource-uri>
  list
";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Register {
        resource_uri: String,
        name: String,
        scopes: Vec<String>,
        default_scopes: Vec<String>,
        /// `(scope, text)`; empty leaves existing descriptions alone.
        scope_descriptions: Vec<(String, String)>,
        /// `None` leaves the service slug alone.
        service: Option<String>,
    },
    SetService {
        resource_uri: String,
        service: String,
    },
    RenameService {
        resource_uri: String,
        service: String,
    },
    Rename {
        old_uri: String,
        new_uri: String,
        /// Required unless `new_uri` is a live alias (the swap); checked by
        /// `resources::rename`, which knows.
        alias_until: Option<DateTime<Utc>>,
        name: Option<String>,
    },
    DropAlias {
        alias_uri: String,
    },
    /// Replace all scope descriptions; empty clears them.
    Describe {
        resource_uri: String,
        scope_descriptions: Vec<(String, String)>,
    },
    RotateSecret {
        resource_uri: String,
    },
    SetWebhook {
        resource_uri: String,
        /// `None` clears it.
        url: Option<String>,
    },
    SetDisabled {
        resource_uri: String,
        disabled: bool,
    },
    List,
}

/// Parse the arguments after `resource`.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let (cmd, rest) = args.split_first().ok_or("missing command")?;
    let mut positional: Vec<&str> = Vec::new();
    let mut flags: Vec<(&str, Option<&str>)> = Vec::new();
    let mut it = rest.iter().map(String::as_str);
    while let Some(a) = it.next() {
        match a {
            "--name"
            | "--scopes"
            | "--default-scopes"
            | "--scope-description"
            | "--service"
            | "--alias-until" => {
                let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                flags.push((a, Some(v)));
            }
            "--clear" => flags.push((a, None)),
            _ if a.starts_with("--") => return Err(format!("unknown flag {a}")),
            _ => positional.push(a),
        }
    }
    let flag = |name: &str| flags.iter().find(|(f, _)| *f == name).map(|(_, v)| *v);
    let list = |v: &str| -> Vec<String> {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let descriptions = || -> Result<Vec<(String, String)>, String> {
        flags
            .iter()
            .filter(|(f, _)| *f == "--scope-description")
            .map(|(_, v)| {
                let v = v.unwrap_or_default();
                match v.split_once('=') {
                    Some((scope, text)) if !scope.trim().is_empty() => {
                        Ok((scope.trim().to_owned(), text.to_owned()))
                    }
                    _ => Err(format!("--scope-description expects scope=text, got {v:?}")),
                }
            })
            .collect()
    };
    let slug = |s: &str| -> Result<String, String> {
        if resources::is_service_slug(s) {
            Ok(s.to_owned())
        } else {
            Err(format!(
                "`{s}` is not a service slug: lower-case letters, digits and `-`, starting with a letter, at most 63 characters"
            ))
        }
    };
    let one_uri = |positional: &[&str]| match positional {
        [uri] => Ok((*uri).to_owned()),
        _ => Err("expected exactly one <resource-uri>".to_owned()),
    };

    match cmd.as_str() {
        "register" => Ok(Command::Register {
            resource_uri: one_uri(&positional)?,
            name: flag("--name")
                .flatten()
                .ok_or("--name is required")?
                .to_owned(),
            scopes: list(flag("--scopes").flatten().ok_or("--scopes is required")?),
            default_scopes: flag("--default-scopes")
                .flatten()
                .map(list)
                .unwrap_or_default(),
            scope_descriptions: descriptions()?,
            // Checked here so a bad slug is refused before `register` writes
            // anything, rather than after the registration has committed.
            service: flag("--service").flatten().map(slug).transpose()?,
        }),
        "set-service" => match positional.as_slice() {
            [uri, service] => Ok(Command::SetService {
                resource_uri: (*uri).to_owned(),
                service: slug(service)?,
            }),
            _ => Err("expected <resource-uri> <slug>".into()),
        },
        // No flags: it moves money-adjacent data, so a stray one is a mistake
        // to report rather than ignore.
        "rename-service" => match positional.as_slice() {
            [uri, service] if flags.is_empty() => Ok(Command::RenameService {
                resource_uri: (*uri).to_owned(),
                service: slug(service)?,
            }),
            _ => Err("expected <resource-uri> <new-slug>, and no flags".into()),
        },
        "rename" => {
            if let Some((stray, _)) = flags
                .iter()
                .find(|(f, _)| !matches!(*f, "--alias-until" | "--name"))
            {
                return Err(format!("rename takes no {stray}"));
            }
            let [old, new] = positional.as_slice() else {
                return Err("expected <old-uri> <new-uri>".into());
            };
            let alias_until = flag("--alias-until")
                .flatten()
                .map(|v| {
                    DateTime::parse_from_rfc3339(v)
                        .map(|t| t.with_timezone(&Utc))
                        .map_err(|_| {
                            format!("--alias-until {v:?} is not an RFC 3339 timestamp, e.g. 2027-01-31T00:00:00Z")
                        })
                })
                .transpose()?;
            Ok(Command::Rename {
                old_uri: (*old).to_owned(),
                new_uri: (*new).to_owned(),
                alias_until,
                name: flag("--name").flatten().map(str::to_owned),
            })
        }
        "drop-alias" => match positional.as_slice() {
            [uri] if flags.is_empty() => Ok(Command::DropAlias {
                alias_uri: (*uri).to_owned(),
            }),
            _ => Err("expected <alias-uri>, and no flags".into()),
        },
        "describe" => {
            let scope_descriptions = descriptions()?;
            let clear = flag("--clear").is_some();
            if clear != scope_descriptions.is_empty() {
                return Err(
                    "describe needs --scope-description scope=text (one or more), or --clear"
                        .into(),
                );
            }
            Ok(Command::Describe {
                resource_uri: one_uri(&positional)?,
                scope_descriptions,
            })
        }
        "rotate-secret" => Ok(Command::RotateSecret {
            resource_uri: one_uri(&positional)?,
        }),
        "set-webhook" => match (positional.as_slice(), flag("--clear").is_some()) {
            ([uri], true) => Ok(Command::SetWebhook {
                resource_uri: (*uri).to_owned(),
                url: None,
            }),
            ([uri, url], false) => Ok(Command::SetWebhook {
                resource_uri: (*uri).to_owned(),
                url: Some((*url).to_owned()),
            }),
            _ => Err("expected <resource-uri> <url>, or <resource-uri> --clear".into()),
        },
        "enable" | "disable" => Ok(Command::SetDisabled {
            resource_uri: one_uri(&positional)?,
            disabled: cmd == "disable",
        }),
        "list" if positional.is_empty() => Ok(Command::List),
        other => Err(format!("unknown command {other:?}")),
    }
}

/// Run a parsed command, writing human-readable output to `out`.
pub async fn execute(
    db: &Db,
    cipher: Option<&Cipher>,
    cmd: Command,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match cmd {
        Command::Register {
            resource_uri,
            name,
            scopes,
            default_scopes,
            scope_descriptions,
            service,
        } => {
            let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
            let defaults: Vec<&str> = default_scopes.iter().map(String::as_str).collect();
            let rs = resources::register(
                db,
                ResourceServerSpec {
                    resource_uri: &resource_uri,
                    name: &name,
                    scopes: &scopes,
                    default_scopes: &defaults,
                },
            )
            .await?;
            writeln!(out, "registered {} ({})", rs.resource_uri, rs.name)?;
            if !scope_descriptions.is_empty() {
                let rs = describe(db, &resource_uri, &scope_descriptions).await?;
                writeln!(
                    out,
                    "{} scope description(s) set",
                    rs.scope_descriptions.len()
                )?;
            }
            if let Some(service) = service {
                let rs = resources::set_service(db, &resource_uri, &service).await?;
                writeln!(out, "service={}", rs.service.as_deref().unwrap_or("-"))?;
            }
            writeln!(
                out,
                "next: `resource rotate-secret` for its credential, `resource set-webhook` for lifecycle events"
            )?;
        }
        Command::Describe {
            resource_uri,
            scope_descriptions,
        } => {
            let rs = describe(db, &resource_uri, &scope_descriptions).await?;
            writeln!(
                out,
                "{resource_uri} now has {} scope description(s)",
                rs.scope_descriptions.len()
            )?;
            writeln!(out, "service={}", rs.service.as_deref().unwrap_or("-"))?;
            for alias in resources::aliases_of(db, &resource_uri).await? {
                write_alias(out, &alias)?;
            }
        }
        Command::Rename {
            old_uri,
            new_uri,
            alias_until,
            name,
        } => {
            let r = resources::rename(db, &old_uri, &new_uri, alias_until, name.as_deref()).await?;
            let w = r.rewritten;
            writeln!(
                out,
                "{} {} -> {} ({})",
                if r.swapped { "swapped" } else { "renamed" },
                r.previous_uri,
                r.resource.resource_uri,
                r.resource.name
            )?;
            write_alias(out, &r.alias)?;
            writeln!(
                out,
                "rewritten: {} access token(s), {} refresh token(s), {} authorization code(s), \
                 {} usage dedupe record(s)",
                w.access_tokens, w.refresh_tokens, w.authorization_codes, w.usage_event_ids
            )?;
            writeln!(
                out,
                "the server may authenticate as either URI until the sunset; \
                 `resource drop-alias {}` ends the alias sooner",
                r.alias.alias_uri
            )?;
        }
        Command::DropAlias { alias_uri } => {
            let alias = resources::drop_alias(db, &alias_uri).await?;
            write_alias(out, &alias)?;
        }
        Command::SetService {
            resource_uri,
            service,
        } => {
            let rs = resources::set_service(db, &resource_uri, &service).await?;
            writeln!(
                out,
                "{resource_uri} service={}",
                rs.service.as_deref().unwrap_or("-")
            )?;
            writeln!(
                out,
                "its meters are declared as {service}/<meter> (PUT /internal/meters)"
            )?;
        }
        Command::RenameService {
            resource_uri,
            service,
        } => {
            let r = resources::rename_service(db, &resource_uri, &service).await?;
            let m = r.moved;
            writeln!(
                out,
                "{resource_uri} service={} (was {})",
                r.resource.service.as_deref().unwrap_or("-"),
                r.previous_service
            )?;
            writeln!(
                out,
                "moved: {} meter(s), {} price version(s), {} usage pool(s), {} budget(s), \
                 {} budget alert(s)",
                m.meters, m.price_versions, m.service_pools, m.service_budgets, m.budget_alerts
            )?;
            writeln!(
                out,
                "its meters are now declared as {service}/<meter> (PUT /internal/meters)"
            )?;
        }
        Command::RotateSecret { resource_uri } => {
            let secret = resources::rotate_introspection_secret(db, &resource_uri).await?;
            writeln!(out, "introspection secret for {resource_uri} (shown once):")?;
            writeln!(out, "{secret}")?;
            writeln!(
                out,
                "the resource server authenticates with HTTP Basic, client id = its resource uri, or Bearer <secret>"
            )?;
        }
        Command::SetWebhook { resource_uri, url } => {
            let cipher = cipher.ok_or_else(|| {
                anyhow::anyhow!("OTTO_ENCRYPTION_KEY must be set to store a webhook signing secret")
            })?;
            match resources::set_webhook(db, cipher, &resource_uri, url.as_deref()).await? {
                Some(secret) => {
                    writeln!(
                        out,
                        "webhook for {resource_uri} set to {}",
                        url.as_deref().unwrap_or_default()
                    )?;
                    writeln!(out, "signing secret (shown once):")?;
                    writeln!(out, "{secret}")?;
                }
                None => writeln!(out, "webhook for {resource_uri} cleared")?,
            }
        }
        Command::SetDisabled {
            resource_uri,
            disabled,
        } => {
            resources::set_disabled(db, &resource_uri, disabled).await?;
            writeln!(
                out,
                "{resource_uri} {}",
                if disabled { "disabled" } else { "enabled" }
            )?;
        }
        Command::List => {
            let aliases = resources::aliases(db).await?;
            for rs in resources::list(db).await? {
                writeln!(
                    out,
                    "{}\t{}\t{}\twebhook={}\tservice={}",
                    rs.resource_uri,
                    rs.name,
                    if rs.disabled { "disabled" } else { "enabled" },
                    rs.webhook_url.as_deref().unwrap_or("-"),
                    rs.service.as_deref().unwrap_or("-"),
                )?;
                for alias in aliases.iter().filter(|a| a.resource_uri == rs.resource_uri) {
                    write_alias(out, alias)?;
                }
            }
        }
    }
    Ok(())
}

/// One alias, indented under its server: `  alias <uri> sunset=<RFC3339> <state>`.
fn write_alias(out: &mut impl Write, alias: &ResourceAlias) -> std::io::Result<()> {
    writeln!(
        out,
        "  alias {}\tsunset={}\t{}",
        alias.alias_uri,
        alias
            .sunset_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        alias.state(Utc::now()).as_str()
    )
}

async fn describe(
    db: &Db,
    resource_uri: &str,
    descriptions: &[(String, String)],
) -> anyhow::Result<resources::ResourceServer> {
    let pairs: Vec<(&str, &str)> = descriptions
        .iter()
        .map(|(s, t)| (s.as_str(), t.as_str()))
        .collect();
    Ok(resources::set_scope_descriptions(db, resource_uri, &pairs).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_register() {
        assert_eq!(
            parse(&args(
                "register https://x.example/mcp --name X --scopes a,b --default-scopes a"
            ))
            .unwrap(),
            Command::Register {
                resource_uri: "https://x.example/mcp".into(),
                name: "X".into(),
                scopes: vec!["a".into(), "b".into()],
                default_scopes: vec!["a".into()],
                scope_descriptions: vec![],
                service: None,
            }
        );
        assert_eq!(
            parse(&args(
                "register https://x.example/mcp --name X --scopes a --scope-description a=x=y"
            ))
            .unwrap(),
            Command::Register {
                resource_uri: "https://x.example/mcp".into(),
                name: "X".into(),
                scopes: vec!["a".into()],
                default_scopes: vec![],
                scope_descriptions: vec![("a".into(), "x=y".into())],
                service: None,
            }
        );
        assert!(parse(&args("register https://x.example/mcp --name X")).is_err());
        assert_eq!(
            parse(&args(
                "register https://x.example/mcp --name X --scopes a --service otto-x"
            ))
            .unwrap(),
            Command::Register {
                resource_uri: "https://x.example/mcp".into(),
                name: "X".into(),
                scopes: vec!["a".into()],
                default_scopes: vec![],
                scope_descriptions: vec![],
                service: Some("otto-x".into()),
            }
        );
        assert!(parse(&args(
            "register https://x.example/mcp --name X --scopes a --service"
        ))
        .is_err());
        assert!(parse(&args(
            "register https://x.example/mcp --name X --scopes a --service Bad_Slug"
        ))
        .is_err());
    }

    #[test]
    fn parses_set_service() {
        assert_eq!(
            parse(&args("set-service https://x.example/mcp otto-x")).unwrap(),
            Command::SetService {
                resource_uri: "https://x.example/mcp".into(),
                service: "otto-x".into(),
            }
        );
        assert!(parse(&args("set-service https://x.example/mcp")).is_err());
        assert!(parse(&args("set-service https://x.example/mcp Otto-X")).is_err());
        assert!(parse(&args("set-service https://x.example/mcp a b")).is_err());
    }

    #[test]
    fn parses_rename_service() {
        assert_eq!(
            parse(&args("rename-service https://x.example/mcp otto-tower")).unwrap(),
            Command::RenameService {
                resource_uri: "https://x.example/mcp".into(),
                service: "otto-tower".into(),
            }
        );
        assert!(parse(&args("rename-service https://x.example/mcp")).is_err());
        assert!(parse(&args("rename-service")).is_err());
        assert!(parse(&args("rename-service https://x.example/mcp Otto-Tower")).is_err());
        assert!(parse(&args("rename-service https://x.example/mcp otto_tower")).is_err());
        assert!(parse(&args("rename-service https://x.example/mcp a b")).is_err());
        assert!(parse(&args(
            "rename-service https://x.example/mcp otto-tower --clear"
        ))
        .is_err());
    }

    #[test]
    fn parses_rename() {
        assert_eq!(
            parse(&args(
                "rename https://a.example/mcp https://b.example/mcp \
                 --alias-until 2027-01-31T00:00:00Z --name otto-tower"
            ))
            .unwrap(),
            Command::Rename {
                old_uri: "https://a.example/mcp".into(),
                new_uri: "https://b.example/mcp".into(),
                alias_until: Some("2027-01-31T00:00:00Z".parse().unwrap()),
                name: Some("otto-tower".into()),
            }
        );
        // An offset is normalized to UTC.
        assert_eq!(
            parse(&args(
                "rename https://a.example/mcp https://b.example/mcp --alias-until 2027-01-31T02:00:00+02:00"
            ))
            .unwrap(),
            Command::Rename {
                old_uri: "https://a.example/mcp".into(),
                new_uri: "https://b.example/mcp".into(),
                alias_until: Some("2027-01-31T00:00:00Z".parse().unwrap()),
                name: None,
            }
        );
        // The swap back names no sunset; `resources::rename` decides whether
        // it needs one.
        assert_eq!(
            parse(&args("rename https://b.example/mcp https://a.example/mcp")).unwrap(),
            Command::Rename {
                old_uri: "https://b.example/mcp".into(),
                new_uri: "https://a.example/mcp".into(),
                alias_until: None,
                name: None,
            }
        );
        for bad in [
            "rename https://a.example/mcp",
            "rename https://a.example/mcp https://b.example/mcp https://c.example/mcp",
            "rename https://a.example/mcp https://b.example/mcp --alias-until 2027-01-31",
            "rename https://a.example/mcp https://b.example/mcp --alias-until tomorrow",
            "rename https://a.example/mcp https://b.example/mcp --alias-until",
            "rename https://a.example/mcp https://b.example/mcp --clear",
            "rename https://a.example/mcp https://b.example/mcp --service x",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_drop_alias() {
        assert_eq!(
            parse(&args("drop-alias https://a.example/mcp")).unwrap(),
            Command::DropAlias {
                alias_uri: "https://a.example/mcp".into(),
            }
        );
        assert!(parse(&args("drop-alias")).is_err());
        assert!(parse(&args(
            "drop-alias https://a.example/mcp https://b.example/mcp"
        ))
        .is_err());
        assert!(parse(&args("drop-alias https://a.example/mcp --clear")).is_err());
    }

    #[test]
    fn parses_set_webhook_both_ways() {
        assert_eq!(
            parse(&args(
                "set-webhook https://x.example/mcp https://x.example/hook"
            ))
            .unwrap(),
            Command::SetWebhook {
                resource_uri: "https://x.example/mcp".into(),
                url: Some("https://x.example/hook".into())
            }
        );
        assert_eq!(
            parse(&args("set-webhook https://x.example/mcp --clear")).unwrap(),
            Command::SetWebhook {
                resource_uri: "https://x.example/mcp".into(),
                url: None
            }
        );
        assert!(parse(&args("set-webhook https://x.example/mcp")).is_err());
    }

    #[test]
    fn parses_describe() {
        let got = parse(&[
            "describe".into(),
            "https://x.example/mcp".into(),
            "--scope-description".into(),
            "a=Read things".into(),
            "--scope-description".into(),
            "b=Write things".into(),
        ])
        .unwrap();
        assert_eq!(
            got,
            Command::Describe {
                resource_uri: "https://x.example/mcp".into(),
                scope_descriptions: vec![
                    ("a".into(), "Read things".into()),
                    ("b".into(), "Write things".into())
                ],
            }
        );
        assert_eq!(
            parse(&args("describe https://x.example/mcp --clear")).unwrap(),
            Command::Describe {
                resource_uri: "https://x.example/mcp".into(),
                scope_descriptions: vec![],
            }
        );
        // Nothing to do, and contradictory, are both mistakes.
        assert!(parse(&args("describe https://x.example/mcp")).is_err());
        assert!(parse(&args(
            "describe https://x.example/mcp --clear --scope-description a=b"
        ))
        .is_err());
        assert!(parse(&args(
            "describe https://x.example/mcp --scope-description nope"
        ))
        .is_err());
        assert!(parse(&args(
            "describe https://x.example/mcp --scope-description =text"
        ))
        .is_err());
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(parse(&[]).is_err());
        assert!(parse(&args("frobnicate")).is_err());
        assert!(parse(&args("rotate-secret")).is_err());
        assert!(parse(&args("list --bogus")).is_err());
    }
}
