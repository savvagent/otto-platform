//! `ottoctl <app>` runs `otto-<app>` from PATH with its arguments and exit code.
//!
//! The portable tests use a copy of `ottoctl` itself as the app, since it is the
//! one executable every platform's test run has: `otto-echo login "a b"` fails
//! with exit 2 and names the argument it was given.

use std::path::Path;
use std::process::Command;

const EXE: &str = std::env::consts::EXE_SUFFIX;

fn ottoctl(path: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ottoctl"));
    c.env("PATH", path).env("OTTO_CONFIG_DIR", path.join("cfg"));
    c
}

/// Install a copy of `ottoctl` as the app `otto-<name>`.
fn install_copy(dir: &Path, name: &str) {
    std::fs::copy(
        env!("CARGO_BIN_EXE_ottoctl"),
        dir.join(format!("otto-{name}{EXE}")),
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
    let out = ottoctl(dir.path())
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
        "otto-fake",
        "#!/bin/sh\necho \"args: $*\"\nexit 7\n",
    );
    let out = ottoctl(dir.path())
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
    let out = ottoctl(dir.path()).arg("nope").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("`otto-nope{EXE}`")));
}

#[test]
fn a_name_that_could_escape_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["../x", "a/b", "a\\b", "A", ""] {
        let out = ottoctl(dir.path()).arg(bad).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
}

/// Without the execute bit on Unix; without `.exe` on Windows.
#[test]
fn a_non_executable_file_is_not_a_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("otto-plain"), "x").unwrap();
    let out = ottoctl(dir.path()).arg("plain").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
}

/// A bare `ottoctl login` signs in to every resource, so these tests only use
/// arguments that are refused before any sign-in starts.
#[test]
fn login_scopes_need_a_resource() {
    let dir = tempfile::tempdir().unwrap();
    let out = ottoctl(dir.path())
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
    let out = ottoctl(dir.path())
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
    let out = Command::new(env!("CARGO_BIN_EXE_ottoctl"))
        .current_dir(dir.path())
        .env("PATH", path)
        .env("OTTO_CONFIG_DIR", dir.path().join("cfg"))
        .args(["rel", "help"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
}

#[cfg(unix)]
#[test]
fn the_app_replaces_otto_so_a_signal_reaches_the_caller_as_the_apps() {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempfile::tempdir().unwrap();
    install_script(dir.path(), "otto-sig", "#!/bin/sh\nkill -TERM $$\n");
    let out = ottoctl(dir.path()).arg("sig").output().unwrap();
    // exec'd, so the process the caller waits on is the one that was killed.
    assert_eq!(out.status.signal(), Some(15));
}
