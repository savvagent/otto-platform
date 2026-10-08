//! `otto-platform-server client ...` — the operator's way to register OAuth
//! clients that dynamic registration cannot create.
//!
//! ```text
//! otto-platform-server client register --name <name> \
//!     --redirect-uri <uri> [--redirect-uri <uri> ...] [--first-party]
//! ```
//!
//! Prints the new `client_id` on stdout. The client is public (PKCE, no
//! secret), the same as every DCR client; what the operator adds is
//! `--first-party`, which makes the authorization server skip the consent
//! screen once the org a token is for is known. That flag exists nowhere else:
//! not in dynamic registration, not on any HTTP route.
//!
//! Redirect URIs go through the same screening as dynamic registration
//! (https, or http on loopback; no fragments, credentials, or wildcards).

use std::io::Write;

use otto_auth::oauth::{self, RegistrationRequest};
use otto_tenant::Db;

pub const USAGE: &str = "\
usage: otto-platform-server client <command>

commands:
  register --name <name> --redirect-uri <uri> [--redirect-uri <uri> ...] [--first-party]
";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Register {
        name: String,
        redirect_uris: Vec<String>,
        first_party: bool,
    },
}

/// Parse the arguments after `client`.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let (cmd, rest) = args.split_first().ok_or("missing command")?;
    match cmd.as_str() {
        "register" => {
            let mut name = None;
            let mut redirect_uris = Vec::new();
            let mut first_party = false;
            let mut it = rest.iter().map(String::as_str);
            while let Some(a) = it.next() {
                match a {
                    "--name" | "--redirect-uri" => {
                        let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                        if a == "--name" {
                            name = Some(v.to_owned());
                        } else {
                            redirect_uris.push(v.to_owned());
                        }
                    }
                    "--first-party" => first_party = true,
                    _ if a.starts_with("--") => return Err(format!("unknown flag {a}")),
                    _ => return Err(format!("unexpected argument {a:?}")),
                }
            }
            if redirect_uris.is_empty() {
                return Err("at least one --redirect-uri is required".into());
            }
            Ok(Command::Register {
                name: name.ok_or("--name is required")?,
                redirect_uris,
                first_party,
            })
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

/// Run a parsed command, writing human-readable output to `out`.
pub async fn execute(db: &Db, cmd: Command, out: &mut impl Write) -> anyhow::Result<()> {
    match cmd {
        Command::Register {
            name,
            redirect_uris,
            first_party,
        } => {
            let registered = oauth::register_operator_client(
                db,
                RegistrationRequest {
                    client_name: Some(name),
                    redirect_uris,
                    software_id: None,
                    grant_types: None,
                },
                first_party,
            )
            .await?;
            writeln!(out, "{}", registered.client_id)?;
        }
    }
    Ok(())
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
                "register --name Console --redirect-uri https://a.example/cb \
                 --redirect-uri https://b.example/cb --first-party"
            ))
            .unwrap(),
            Command::Register {
                name: "Console".into(),
                redirect_uris: vec!["https://a.example/cb".into(), "https://b.example/cb".into()],
                first_party: true,
            }
        );
        assert_eq!(
            parse(&args(
                "register --name X --redirect-uri https://a.example/cb"
            ))
            .unwrap(),
            Command::Register {
                name: "X".into(),
                redirect_uris: vec!["https://a.example/cb".into()],
                first_party: false,
            }
        );
    }

    #[test]
    fn rejects_unknown_or_incomplete_input() {
        assert!(parse(&[]).is_err());
        assert!(parse(&args("frobnicate")).is_err());
        assert!(parse(&args("register --redirect-uri https://a.example/cb")).is_err());
        assert!(parse(&args("register --name X")).is_err());
        assert!(parse(&args("register --name")).is_err());
        assert!(parse(&args(
            "register --name X --redirect-uri https://a.example/cb --bogus"
        ))
        .is_err());
        assert!(parse(&args(
            "register --name X --redirect-uri https://a.example/cb stray"
        ))
        .is_err());
    }
}
