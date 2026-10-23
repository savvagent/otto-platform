//! `otto`: sign in to an otto deployment, and run `otto-<app>` subcommands.
//!
//! `otto <app> <args>` runs the `otto-<app>` binary found on PATH with the
//! same arguments and exits with its status, the way git and cargo dispatch.
//! Each app ships its own verbs without changing this binary; it links
//! `otto-client` to get a token for its own resource.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "\
usage:
  otto login --resource <uri> [--scope <scope>]...   sign in to a resource
  otto <app> [args...]                               run the `otto-<app>` binary on PATH
  otto help

`otto login` opens your browser to sign in. The token is cached per resource
in $OTTO_CONFIG_DIR, else $XDG_CONFIG_HOME/otto, else ~/.config/otto
(credentials.json, owner-only). Linux and macOS.";

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "login" => login(&rest).await,
        app => dispatch(app, &rest),
    }
}

async fn login(args: &[String]) -> ExitCode {
    let mut resource = None;
    let mut scopes = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--resource", Some(v)) => resource = Some(v.clone()),
            ("--scope", Some(v)) => scopes.push(v.clone()),
            _ => {
                eprintln!("otto login: unexpected argument {a:?}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(resource) = resource else {
        eprintln!("otto login: --resource <uri> is required\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let client = match otto_client::Client::with_defaults() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    match client.login(&resource, &scopes).await {
        Ok(()) => {
            eprintln!("Signed in to {resource}.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &otto_client::Error) -> ExitCode {
    eprintln!("otto: {e}");
    ExitCode::FAILURE
}

fn dispatch(app: &str, args: &[String]) -> ExitCode {
    // The name becomes part of a file name looked up on PATH; anything that
    // could change which file that is (a slash, `..`) is refused.
    let valid = !app.is_empty()
        && app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !valid {
        eprintln!("otto: {app:?} is not a command or an app name\n\n{USAGE}");
        return ExitCode::from(2);
    }
    let binary = format!("otto-{app}");
    let Some(path) = find_on_path(&binary, std::env::var_os("PATH").as_deref()) else {
        eprintln!("otto: no `{binary}` found on PATH, so `otto {app}` has nothing to run");
        return ExitCode::from(127);
    };
    match Command::new(&path).args(args).status() {
        Ok(status) => exit_code(status),
        Err(e) => {
            eprintln!("otto: could not run {}: {}", path.display(), e.kind());
            ExitCode::from(126)
        }
    }
}

#[cfg(unix)]
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => ExitCode::from(c as u8),
        // The shell convention for death by signal.
        (None, Some(s)) => ExitCode::from(128u8.wrapping_add(s as u8)),
        (None, None) => ExitCode::FAILURE,
    }
}

#[cfg(not(unix))]
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    ExitCode::from(status.code().unwrap_or(1) as u8)
}

fn find_on_path(binary: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path_var?)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}
