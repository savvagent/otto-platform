//! `otto-platform-server resource ...` — the operator's way to provision
//! resource servers: register one, issue or rotate its credentials, point its
//! lifecycle webhook somewhere.
//!
//! ```text
//! otto-platform-server resource register <resource-uri> --name <name> \
//!     --scopes a,b,c [--default-scopes a] [--scope-description a=text]...
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
//! Secrets are printed once, on stdout, and cannot be read back: the
//! introspection secret is stored hashed, the webhook secret sealed. Losing
//! one means running the command again, which invalidates the old value.
//! `set-webhook` needs `OTTO_ENCRYPTION_KEY`, the same key the delivery task
//! opens secrets with.

use std::io::Write;

use otto_auth::resources::{self, ResourceServerSpec};
use otto_tenant::crypto::Cipher;
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server resource <command>

commands:
  register <resource-uri> --name <name> --scopes a,b [--default-scopes a]
           [--scope-description a=text]...
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
            "--name" | "--scopes" | "--default-scopes" | "--scope-description" => {
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
        }),
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
            for rs in resources::list(db).await? {
                writeln!(
                    out,
                    "{}\t{}\t{}\twebhook={}",
                    rs.resource_uri,
                    rs.name,
                    if rs.disabled { "disabled" } else { "enabled" },
                    rs.webhook_url.as_deref().unwrap_or("-"),
                )?;
            }
        }
    }
    Ok(())
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
            }
        );
        assert!(parse(&args("register https://x.example/mcp --name X")).is_err());
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
