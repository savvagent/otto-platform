//! `savctl <app>` runs `savctl-<app>` from PATH with its arguments and exit code.
//!
//! The portable tests use a copy of `savctl` itself as the app, since it is the
//! one executable every platform's test run has: `savctl-echo login "a b"` fails
//! with exit 2 and names the argument it was given.

use std::path::Path;
use std::process::Command;

const EXE: &str = std::env::consts::EXE_SUFFIX;

fn savctl(path: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_savctl"));
    c.env("PATH", path)
        .env("SAVVAGENT_CONFIG_DIR", path.join("cfg"));
    c
}

/// Install a copy of `savctl` as the app `savctl-<name>`.
fn install_copy(dir: &Path, name: &str) {
    std::fs::copy(
        env!("CARGO_BIN_EXE_savctl"),
        dir.join(format!("savctl-{name}{EXE}")),
    )
    .unwrap();
}

#[cfg(unix)]
fn install_script(dir: &Path, name: &str, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn runs_the_app_binary_with_arguments_and_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    install_copy(dir.path(), "echo");
    let out = savctl(dir.path())
        .args(["echo", "login", "a b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unexpected argument \"a b\""), "{stderr}");
}

#[cfg(unix)]
#[test]
fn passes_stdout_and_any_exit_code_through() {
    let dir = tempfile::tempdir().unwrap();
    install_script(
        dir.path(),
        "savctl-fake",
        "#!/bin/sh\necho \"args: $*\"\nexit 7\n",
    );
    let out = savctl(dir.path())
        .args(["fake", "keys", "rotate", "--app", "a b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "args: keys rotate --app a b\n"
    );
}

#[test]
fn a_missing_binary_is_named_in_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = savctl(dir.path()).arg("nope").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("`savctl-nope{EXE}`")));
}

#[test]
fn a_name_that_could_escape_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["../x", "a/b", "a\\b", "A", ""] {
        let out = savctl(dir.path()).arg(bad).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
}

/// Without the execute bit on Unix; without `.exe` on Windows.
#[test]
fn a_non_executable_file_is_not_a_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("savctl-plain"), "x").unwrap();
    let out = savctl(dir.path()).arg("plain").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
}

/// A bare `savctl login` signs in to every resource, so these tests only use
/// arguments that are refused before any sign-in starts.
#[test]
fn login_scopes_need_a_resource() {
    let dir = tempfile::tempdir().unwrap();
    let out = savctl(dir.path())
        .args(["login", "--scope", "flags:read"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--scope needs --resource"), "{stderr}");
    assert!(
        stderr.contains("https://otto-flags.savvagent.com/mcp"),
        "{stderr}"
    );
}

#[test]
fn login_refuses_an_unknown_argument() {
    let dir = tempfile::tempdir().unwrap();
    let out = savctl(dir.path())
        .args(["login", "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn a_relative_or_empty_path_entry_is_not_searched() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("bin")).unwrap();
    install_copy(&dir.path().join("bin"), "rel");
    install_copy(dir.path(), "rel");
    // A relative entry and an empty one (the current directory, to a shell).
    let path = if cfg!(windows) { "bin;;" } else { "bin::" };
    let out = Command::new(env!("CARGO_BIN_EXE_savctl"))
        .current_dir(dir.path())
        .env("PATH", path)
        .env("SAVVAGENT_CONFIG_DIR", dir.path().join("cfg"))
        .args(["rel", "help"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
}

#[cfg(unix)]
#[test]
fn the_app_replaces_savctl_so_a_signal_reaches_the_caller_as_the_apps() {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempfile::tempdir().unwrap();
    install_script(dir.path(), "savctl-sig", "#!/bin/sh\nkill -TERM $$\n");
    let out = savctl(dir.path()).arg("sig").output().unwrap();
    // exec'd, so the process the caller waits on is the one that was killed.
    assert_eq!(out.status.signal(), Some(15));
}

/// A reader that stops early (`savctl help | grep -q login`) is not a crash.
#[test]
fn help_survives_a_closed_pipe() {
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let mut child = savctl(dir.path())
        .arg("help")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

/// The pre-Savvagent `otto-<app>` name is not dispatched to.
#[test]
fn an_otto_prefixed_binary_is_not_an_app() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        env!("CARGO_BIN_EXE_savctl"),
        dir.path().join(format!("otto-old{EXE}")),
    )
    .unwrap();
    let out = savctl(dir.path()).arg("old").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("`savctl-old{EXE}`")), "{stderr}");
}

/// The help names the command, the config directory and its variable.
#[test]
fn help_names_savctl_and_the_savvagent_config_dir() {
    let dir = tempfile::tempdir().unwrap();
    let out = savctl(dir.path()).arg("help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for want in [
        "savctl login",
        "savctl-<app>",
        "$SAVVAGENT_CONFIG_DIR",
        "$XDG_CONFIG_HOME/savvagent",
        "~/.config/savvagent",
        "%LOCALAPPDATA%\\savvagent",
    ] {
        assert!(stdout.contains(want), "help lacks {want:?}:\n{stdout}");
    }
    assert!(!stdout.contains("savvagent-ctl"), "{stdout}");
    assert!(!stdout.contains("OTTO_CONFIG_DIR"), "{stdout}");
}
