//! `otto <app>` runs `otto-<app>` from PATH with its arguments and exit code.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn otto(path: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_otto"));
    c.env("PATH", path).env("OTTO_CONFIG_DIR", path.join("cfg"));
    c
}

fn install(dir: &Path, name: &str, script: &str) {
    let p = dir.join(name);
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn runs_the_app_binary_with_arguments_and_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    install(
        dir.path(),
        "otto-fake",
        "#!/bin/sh\necho \"args: $*\"\nexit 7\n",
    );
    let out = otto(dir.path())
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
    let out = otto(dir.path()).arg("nope").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&out.stderr).contains("`otto-nope`"));
}

#[test]
fn a_name_that_could_escape_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["../x", "a/b", "A", ""] {
        let out = otto(dir.path()).arg(bad).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
}

#[test]
fn a_non_executable_file_is_not_a_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("otto-plain"), "x").unwrap();
    let out = otto(dir.path()).arg("plain").output().unwrap();
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn login_requires_a_resource() {
    let dir = tempfile::tempdir().unwrap();
    let out = otto(dir.path()).arg("login").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--resource"));
}
