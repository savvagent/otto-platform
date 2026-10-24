//! `ottoctl`: sign in to an otto deployment, and run `otto-<app>` subcommands.
//!
//! `ottoctl <app> <args>` runs the `otto-<app>` binary found on PATH with the
//! same arguments, the way git and cargo dispatch. On Unix it replaces this
//! process (`exec`), so signals, Ctrl-C and the exit status are the app's own.
//! Windows has no `exec`: `ottoctl` waits for the app, leaves Ctrl-C to it, and
//! exits with its exit code.
//! Each app ships its own verbs without changing this binary; it links
//! `otto-client` to get a token for its own resource.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use otto_client::LoginOutcome;

const USAGE: &str = "\
usage:
  ottoctl login --resource <uri> [--scope <scope>]... [--force]
                                 sign in to a resource; --force signs in again
                                 even if a usable login is cached
  ottoctl <app> [args...]        run the `otto-<app>` binary on PATH, e.g.
                                 `ottoctl flags help` for Otto Flags keys
  ottoctl help

`ottoctl login` opens your browser to sign in. The token is cached per resource
in $OTTO_CONFIG_DIR, else $XDG_CONFIG_HOME/otto, else ~/.config/otto
(%LOCALAPPDATA%\\otto on Windows), in credentials.json, owner-only.";

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
    let mut force = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--force" => force = true,
            "--resource" | "--scope" => {
                let Some(v) = it.next() else {
                    eprintln!("ottoctl login: {a} needs a value\n\n{USAGE}");
                    return ExitCode::from(2);
                };
                if a == "--resource" {
                    resource = Some(v.clone());
                } else {
                    scopes.push(v.clone());
                }
            }
            _ => {
                eprintln!("ottoctl login: unexpected argument {a:?}\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(resource) = resource else {
        eprintln!("ottoctl login: --resource <uri> is required\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let client = match otto_client::Client::with_defaults() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    match client.login(&resource, &scopes, force).await {
        Ok(LoginOutcome::AlreadySignedIn) => {
            eprintln!("Already signed in to {resource}. Use --force to sign in again.");
            ExitCode::SUCCESS
        }
        Ok(LoginOutcome::SignedIn) => {
            eprintln!("Signed in to {resource}.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &otto_client::Error) -> ExitCode {
    eprintln!("ottoctl: {e}");
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
        eprintln!("ottoctl: {app:?} is not a command or an app name\n\n{USAGE}");
        return ExitCode::from(2);
    }
    let binary = format!("otto-{app}{}", std::env::consts::EXE_SUFFIX);
    let Some(path) = find_on_path(&binary, std::env::var_os("PATH").as_deref()) else {
        eprintln!("ottoctl: no `{binary}` found on PATH, so `ottoctl {app}` has nothing to run");
        return ExitCode::from(127);
    };
    // `path` is absolute (see `find_on_path`), so `Command` runs exactly the
    // file found rather than searching PATH again.
    let mut cmd = Command::new(&path);
    cmd.args(args);
    run(cmd, &path)
}

#[cfg(unix)]
fn run(mut cmd: Command, path: &Path) -> ExitCode {
    use std::os::unix::process::CommandExt;
    // Only returns on failure.
    let e = cmd.exec();
    eprintln!("ottoctl: could not run {}: {}", path.display(), e.kind());
    ExitCode::from(126)
}

#[cfg(windows)]
fn run(mut cmd: Command, path: &Path) -> ExitCode {
    use windows::core::BOOL;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    // Ctrl-C reaches every process attached to the console, the app and this
    // one alike. Handle it here by doing nothing, so the app decides what
    // Ctrl-C means and `ottoctl` exits when it does. A handler, unlike ignoring
    // the signal outright, is not inherited by the app.
    unsafe extern "system" fn let_the_app_handle_it(_ctrl_type: u32) -> BOOL {
        true.into()
    }
    let _ = unsafe { SetConsoleCtrlHandler(Some(let_the_app_handle_it), true) };

    match cmd.status() {
        // `process::exit` passes the full status, where `ExitCode` holds a u8.
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("ottoctl: could not run {}: {}", path.display(), e.kind());
            ExitCode::from(126)
        }
    }
}

/// The first executable `binary` in an absolute PATH entry. Empty and
/// relative entries are skipped: they resolve against whatever the current
/// directory happens to be.
fn find_on_path(binary: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path_var?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Windows has no execute bit; `binary` already ends in `.exe`. Batch files
/// are not looked for: `cmd.exe` would re-parse their arguments.
#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}
