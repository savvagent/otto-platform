//! A secret an app returned, and the only places it may be written.
//!
//! [`Secret`] has no `Display` or `Debug` that shows its value, so it cannot
//! reach a log line or an error message by formatting. The one way out is
//! [`Secret::deliver`]: to the terminal (refused when stdout is a pipe or a
//! file, which is how secrets end up in CI logs), or to a file the user named,
//! created readable by its owner only.

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::pkce::random_token;

pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// The raw value. Use it to build a request header; do not format it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Hand the secret to a person. `Sink::Terminal` prints it on stdout only
    /// if stdout is a terminal; `Sink::File` writes it owner-only and says
    /// where on stderr.
    pub fn deliver(&self, sink: &Sink) -> Result<()> {
        let stdout = std::io::stdout();
        let is_terminal = stdout.is_terminal();
        self.deliver_to(
            sink,
            &mut stdout.lock(),
            is_terminal,
            &mut std::io::stderr(),
        )
    }

    fn deliver_to(
        &self,
        sink: &Sink,
        out: &mut dyn Write,
        out_is_terminal: bool,
        status: &mut dyn Write,
    ) -> Result<()> {
        match sink {
            Sink::Terminal if !out_is_terminal => Err(Error::Refused(
                "refusing to print a secret to a pipe or a file, where it could end up in a \
                 log; name a file to write it to instead"
                    .into(),
            )),
            Sink::Terminal => {
                writeln!(out, "{}", self.0).map_err(|e| Error::io("writing to terminal", &e))
            }
            Sink::File { path, overwrite } => {
                let bytes = format!("{}\n", self.0);
                if *overwrite {
                    replace_private(path, bytes.as_bytes())?;
                } else {
                    write_new_private(path, bytes.as_bytes())?;
                }
                writeln!(status, "secret written to {}", path.display())
                    .map_err(|e| Error::io("writing to terminal", &e))
            }
        }
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone)]
pub enum Sink {
    Terminal,
    /// `overwrite: false` refuses an existing path, including a symlink.
    /// `overwrite: true` replaces it by renaming a new file over it, which
    /// replaces a symlink itself rather than writing through it.
    File {
        path: PathBuf,
        overwrite: bool,
    },
}

/// Create `path` owner-only. `create_new` (`O_CREAT | O_EXCL`) refuses any
/// existing entry, a symlink or a FIFO included, so nothing planted at the
/// path is followed or written through.
fn create_private(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Write `bytes` to a new owner-only file at `path`. An existing entry is
/// refused; a write that fails part-way removes the file it created, so no
/// truncated copy of a secret is left behind.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_private(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Refused(format!(
                "{} already exists; choose another file or allow overwriting",
                path.display()
            ))
        } else {
            Error::io(&format!("creating {}", path.display()), &e)
        }
    })?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(Error::io(&format!("writing {}", path.display()), &e));
    }
    Ok(())
}

/// Replace `path` with `bytes`, owner-only: write a new file beside it, then
/// rename it into place. A crash never leaves a half-written file, and the
/// temporary file is removed if anything fails.
pub(crate) fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Refused(format!("{} is not a file path", path.display())))?;
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        random_token(6)
    ));
    let result = write_new_private(&tmp, bytes).and_then(|()| {
        std::fs::rename(&tmp, path)
            .map_err(|e| Error::io(&format!("replacing {}", path.display()), &e))
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const VALUE: &str = "srv_THE-SECRET";

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn cannot_be_formatted() {
        let s = Secret::new(VALUE);
        assert!(!format!("{s} {s:?}").contains("THE-SECRET"));
    }

    #[test]
    fn terminal_sink_refuses_a_pipe_and_writes_nothing() {
        let (mut out, mut status) = (Vec::new(), Vec::new());
        let err = Secret::new(VALUE)
            .deliver_to(&Sink::Terminal, &mut out, false, &mut status)
            .unwrap_err();
        assert!(matches!(err, Error::Refused(_)));
        assert!(out.is_empty() && status.is_empty());
        assert!(!err.to_string().contains("THE-SECRET"));
    }

    #[test]
    fn terminal_sink_prints_to_a_terminal() {
        let (mut out, mut status) = (Vec::new(), Vec::new());
        Secret::new(VALUE)
            .deliver_to(&Sink::Terminal, &mut out, true, &mut status)
            .unwrap();
        assert_eq!(out, format!("{VALUE}\n").as_bytes());
        assert!(status.is_empty());
    }

    #[test]
    fn file_sink_writes_owner_only_and_reports_only_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let (mut out, mut status) = (Vec::new(), Vec::new());
        let sink = Sink::File {
            path: path.clone(),
            overwrite: false,
        };
        Secret::new(VALUE)
            .deliver_to(&sink, &mut out, false, &mut status)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{VALUE}\n")
        );
        assert_eq!(mode(&path), 0o600);
        assert!(out.is_empty());
        let status = String::from_utf8(status).unwrap();
        assert!(status.contains("key") && !status.contains("THE-SECRET"));
    }

    #[test]
    fn file_sink_refuses_an_existing_file_or_symlink_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        for path in [victim.clone(), link.clone()] {
            let sink = Sink::File {
                path,
                overwrite: false,
            };
            let err = Secret::new(VALUE)
                .deliver_to(&sink, &mut Vec::new(), false, &mut Vec::new())
                .unwrap_err();
            assert!(matches!(err, Error::Refused(_)), "{err:?}");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    }

    #[test]
    fn overwrite_replaces_a_symlink_instead_of_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let sink = Sink::File {
            path: link.clone(),
            overwrite: true,
        };
        Secret::new(VALUE)
            .deliver_to(&sink, &mut Vec::new(), false, &mut Vec::new())
            .unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(!link.is_symlink());
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            format!("{VALUE}\n")
        );
        assert_eq!(mode(&link), 0o600);
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
