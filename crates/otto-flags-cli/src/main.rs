//! `otto-flags`, run as `ottoctl flags`: issue an Otto Flags app's SDK keys from a
//! terminal.
//!
//! The server key (`srv_…`) is a secret the person stores in their app's
//! secret manager. Issued through an MCP client, it would land in a model's
//! context, its transcript and logs; issued here, it goes only to this
//! terminal or to a file the person names, created owner-only. otto-flags
//! issues it only to a token that carries `keys:issue`, a scope this binary
//! asks for at sign-in and agents are not meant to be granted.
//!
//! Where it goes is claimed before the request (see `Sink::reserve`): a
//! rotation revokes the old key at once, so a key that could not then be
//! delivered would leave the app with no working one.

use std::path::PathBuf;
use std::process::ExitCode;

use otto_client::{Client, Error, Sink, ToolOutput};
use serde_json::{json, Value};

const DEFAULT_RESOURCE: &str = "https://otto-flags.savvagent.com/mcp";
/// What issuing a key takes: `apps:admin` to manage apps, `keys:issue` to be
/// handed the server key.
const SCOPES: [&str; 2] = ["apps:admin", "keys:issue"];
const SERVER_KEY: &str = "/keys/serverKey";

const USAGE: &str = "\
usage:
  ottoctl flags app create <name> [--env <environment>]... [--out <file> [--overwrite]]
                                 register an app and issue its keys
  ottoctl flags keys rotate --app <name-or-id> [--which server|client|both]
                         [--out <file> [--overwrite]]
                                 replace an app's key (default: the server key);
                                 the old key stops working at once
  ottoctl flags help

The server key (srv_...) is printed only to a terminal, never to a pipe, or
written owner-only to the file given with --out (which must not exist unless
--overwrite). The public client key (sdk_...) is printed normally.

Both commands need an owner or admin of the organization, and sign in with
the apps:admin and keys:issue scopes. The service is $OTTO_FLAGS_RESOURCE,
else https://otto-flags.savvagent.com/mcp.";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(c) => c,
        Err(message) => {
            eprintln!("ottoctl flags: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let resource = std::env::var("OTTO_FLAGS_RESOURCE")
        .ok()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| DEFAULT_RESOURCE.to_owned());
    match run(command, &resource).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ottoctl flags: {message}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
enum Command {
    Help,
    Create {
        name: String,
        environments: Vec<String>,
        sink: Sink,
    },
    Rotate {
        app: String,
        which: String,
        sink: Sink,
    },
}

fn parse(args: &[String]) -> Result<Command, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (rest, create) = match words.as_slice() {
        [] | ["help" | "-h" | "--help", ..] => return Ok(Command::Help),
        ["app", "create", rest @ ..] => (rest, true),
        ["keys", "rotate", rest @ ..] => (rest, false),
        _ => return Err(format!("unknown command {:?}", args.join(" "))),
    };

    let (mut name, mut app, mut which) = (None, None, None);
    let (mut environments, mut out, mut overwrite) = (Vec::new(), None, false);
    let mut it = rest.iter();
    while let Some(&a) = it.next() {
        let mut value = || match it.next() {
            Some(v) if !v.is_empty() && !v.starts_with("--") => Ok(v.to_string()),
            _ => Err(format!("{a} needs a value")),
        };
        match a {
            "--overwrite" => overwrite = true,
            "--out" => out = Some(PathBuf::from(value()?)),
            "--env" if create => environments.push(value()?),
            "--app" if !create => app = Some(value()?),
            "--which" if !create => {
                let w = value()?;
                if !matches!(w.as_str(), "server" | "client" | "both") {
                    return Err(format!("--which is server, client or both, not {w:?}"));
                }
                which = Some(w);
            }
            positional
                if create
                    && name.is_none()
                    && !positional.is_empty()
                    && !positional.starts_with('-') =>
            {
                name = Some(positional.to_owned());
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    if which.as_deref() == Some("client") && (out.is_some() || overwrite) {
        return Err("--which client issues no server key, so there is nothing for --out".into());
    }
    let sink = match out {
        Some(path) => Sink::File { path, overwrite },
        None if overwrite => return Err("--overwrite goes with --out".into()),
        None => Sink::Terminal,
    };
    Ok(if create {
        Command::Create {
            name: name.ok_or("app create needs a name")?,
            environments,
            sink,
        }
    } else {
        Command::Rotate {
            app: app.ok_or("keys rotate needs --app")?,
            which: which.unwrap_or_else(|| "server".into()),
            sink,
        }
    })
}

async fn run(command: Command, resource: &str) -> Result<(), String> {
    let (tool, arguments, sink, app, issues_server_key) = match command {
        Command::Help => {
            println!("{USAGE}");
            return Ok(());
        }
        Command::Create {
            name,
            environments,
            sink,
        } => (
            "create_app",
            json!({ "name": name, "environments": environments }),
            sink,
            name,
            true,
        ),
        Command::Rotate { app, which, sink } => {
            let server = which != "client";
            (
                "rotate_app_keys",
                json!({ "app": app, "which": which }),
                sink,
                app,
                server,
            )
        }
    };
    let rotate_hint = format!("ottoctl flags keys rotate --app {}", shell_word(&app));
    // Claimed now, before anything is issued; dropped unused, it is removed.
    let reservation = if issues_server_key {
        Some(
            sink.reserve()
                .map_err(|e| format!("{e}. Nothing was changed."))?,
        )
    } else {
        None
    };

    let client = Client::with_defaults().map_err(|e| e.to_string())?;
    let scopes = SCOPES.map(String::from);
    let out = client
        .call_tool(resource, &scopes, tool, arguments, &[SERVER_KEY])
        .await
        .map_err(|e| explain(e, resource, issues_server_key, &rotate_hint))?;

    report(&out);
    match (out.secret(SERVER_KEY), reservation) {
        (Some(key), Some(reservation)) => {
            eprintln!(
                "Server key (secret, shown only now; store it in your app's secret manager):"
            );
            reservation.deliver(key).map_err(|e| {
                format!(
                    "the new server key was issued but could not be delivered: {e}. It is not \
                     stored anywhere: issue another with `{rotate_hint}`"
                )
            })
        }
        (None, Some(_)) => Err(format!(
            "otto-flags did not issue a server key. Issue one with `{rotate_hint}`"
        )),
        // `--which client`: a server key, if one came back anyway, is dropped.
        (_, None) => Ok(()),
    }
}

/// What the result says, minus the server key (already removed from it).
fn report(out: &ToolOutput) {
    eprintln!(
        "App {} ({}), environments: {}",
        text(out, "/app/name"),
        text(out, "/app/id"),
        out.value()
            .pointer("/app/environments")
            .and_then(Value::as_array)
            .map(|envs| {
                envs.iter()
                    .filter_map(Value::as_str)
                    .map(clean)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    );
    if let Some(key) = out
        .value()
        .pointer("/keys/clientKey")
        .and_then(Value::as_str)
    {
        eprintln!(
            "Client key (public, safe in browser or mobile code): {}",
            clean(key)
        );
    }
}

fn explain(e: Error, resource: &str, issues_server_key: bool, rotate_hint: &str) -> String {
    match e {
        Error::NoResponse { .. } if issues_server_key => format!(
            "{e}\nIf it did, the old server key no longer works and the new one was not \
             received. Issue another with `{rotate_hint}`."
        ),
        Error::InsufficientScope { message, .. } => format!(
            "{message}\nIssuing keys needs the apps:admin and keys:issue scopes. Sign in again \
             and grant them: ottoctl login --resource {resource} --scope apps:admin --scope \
             keys:issue --force"
        ),
        e => e.to_string(),
    }
}

/// A string field of the result, for a message.
fn text(out: &ToolOutput, pointer: &str) -> String {
    out.value()
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_else(|| "?".into())
}

/// `s` as one word for a POSIX shell, quoted when it needs to be, for a
/// command a message suggests.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.:/@".contains(c));
    if plain {
        s.to_owned()
    } else {
        format!("'{}'", clean(s).replace('\'', r"'\''"))
    }
}

/// Server text without control characters, which could drive the terminal.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_both_commands() {
        let Command::Create {
            name,
            environments,
            sink: Sink::File { path, overwrite },
        } = parse(&args(
            "app create web --env prod --env dev --out k --overwrite",
        ))
        .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (name.as_str(), path.to_str(), overwrite),
            ("web", Some("k"), true)
        );
        assert_eq!(environments, ["prod", "dev"]);

        let Command::Rotate { app, which, sink } = parse(&args("keys rotate --app web")).unwrap()
        else {
            panic!()
        };
        assert_eq!((app.as_str(), which.as_str()), ("web", "server"));
        assert!(matches!(sink, Sink::Terminal));
    }

    #[test]
    fn suggested_commands_quote_odd_names() {
        assert_eq!(shell_word("checkout-web"), "checkout-web");
        assert_eq!(shell_word("my app"), "'my app'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
    }

    #[test]
    fn refuses_what_it_does_not_understand() {
        for bad in [
            "app create",
            "app create a b",
            "app create web --app x",
            "keys rotate",
            "keys rotate --app web --which all",
            "keys rotate --app web --overwrite",
            "keys rotate --app",
            "keys rotate --app web --out --overwrite",
            "keys rotate --app web --which client --out k",
            "app create web --env",
            "flags list",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
