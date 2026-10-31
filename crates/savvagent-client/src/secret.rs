//! A secret an app returned, and the only places it may be written.
//!
//! [`Secret`] has no `Display` or `Debug` that shows its value, so it cannot
//! reach a log line or an error message by formatting. The one way out is
//! [`Secret::deliver`]: to the terminal (refused when stdout is a pipe or a
//! file, which is how secrets end up in CI logs), or to a file the user named,
//! created readable by its owner only.
//!
//! A secret the server shows only once, and whose request also revokes the
//! old one, must not be requested before its destination is secured. For that,
//! [`Sink::reserve`] claims the destination first, and [`Reservation::deliver`]
//! fills it once the secret arrives.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::pkce::random_token;
use crate::private_fs;

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
        sink.reserve()?.deliver(self)
    }

    #[cfg(test)]
    fn deliver_to(
        &self,
        sink: &Sink,
        out: &mut dyn Write,
        out_is_terminal: bool,
        status: &mut dyn Write,
    ) -> Result<()> {
        sink.reserve_with(out_is_terminal)?
            .deliver_to(self, out, status)
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

fn not_a_terminal() -> Error {
    Error::Refused(
        "refusing to print a secret to a pipe or a file, where it could end up in a log; name \
         a file to write it to instead"
            .into(),
    )
}

fn already_exists(path: &Path) -> Error {
    Error::Refused(format!(
        "{} already exists; choose another file or allow overwriting",
        path.display()
    ))
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

impl Sink {
    /// Claim this destination before the secret exists, so a request that
    /// issues it is made only once it can be delivered. For a file this
    /// creates it, empty and owner-only (with `overwrite`, a temporary file
    /// beside it), which proves the directory is writable and keeps anyone
    /// else from taking the name meanwhile. A reservation dropped without
    /// delivering removes what it created. Only a failure while writing (a
    /// full disk) can still lose the secret.
    pub fn reserve(&self) -> Result<Reservation> {
        self.reserve_with(std::io::stdout().is_terminal())
    }

    fn reserve_with(&self, out_is_terminal: bool) -> Result<Reservation> {
        let (path, overwrite) = match self {
            Sink::Terminal if !out_is_terminal => return Err(not_a_terminal()),
            Sink::Terminal => return Ok(Reservation::Terminal),
            Sink::File { path, overwrite } => (path.clone(), *overwrite),
        };
        let created = if overwrite {
            temp_beside(&path)?
        } else {
            path.clone()
        };
        let file = private_fs::create_new(&created).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                already_exists(&created)
            } else {
                Error::io(&format!("creating {}", created.display()), &e)
            }
        })?;
        Ok(Reservation::File {
            file: Some(file),
            created,
            path,
        })
    }
}

/// A destination claimed by [`Sink::reserve`].
#[derive(Debug)]
pub enum Reservation {
    Terminal,
    File {
        /// `None` once delivered.
        file: Option<File>,
        /// What was created: `path` itself, or a temporary file beside it.
        created: PathBuf,
        path: PathBuf,
    },
}

impl Reservation {
    /// Write the secret to the reserved destination.
    pub fn deliver(self, secret: &Secret) -> Result<()> {
        self.deliver_to(
            secret,
            &mut std::io::stdout().lock(),
            &mut std::io::stderr(),
        )
    }

    fn deliver_to(
        mut self,
        secret: &Secret,
        out: &mut dyn Write,
        status: &mut dyn Write,
    ) -> Result<()> {
        let Reservation::File {
            file,
            created,
            path,
        } = &mut self
        else {
            return writeln!(out, "{}", secret.0).map_err(|e| Error::io("writing to terminal", &e));
        };
        let mut f = file.take().expect("a reservation is delivered once");
        f.write_all(format!("{}\n", secret.0).as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| Error::io(&format!("writing {}", created.display()), &e))?;
        drop(f);
        if created != path {
            std::fs::rename(&*created, &*path)
                .map_err(|e| Error::io(&format!("replacing {}", path.display()), &e))?;
        }
        // Delivered: nothing for `drop` to clean up.
        *created = PathBuf::new();
        writeln!(status, "secret written to {}", path.display())
            .map_err(|e| Error::io("writing to terminal", &e))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Reservation::File { file, created, .. } = self {
            drop(file.take());
            if !created.as_os_str().is_empty() {
                let _ = std::fs::remove_file(&*created);
            }
        }
    }
}

/// A new temporary file name beside `path`, for replacing it by rename.
fn temp_beside(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Refused(format!("{} is not a file path", path.display())))?;
    Ok(path.with_file_name(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        random_token(6)
    )))
}

/// Write `bytes` to a new owner-only file at `path`. An existing entry is
/// refused; a write that fails part-way removes the file it created, so no
/// truncated copy of a secret is left behind.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = private_fs::create_new(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            already_exists(path)
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
    let tmp = temp_beside(path)?;
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

    const VALUE: &str = "srv_THE-SECRET";

    // Windows ACLs are checked in `private_fs`.
    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
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
    fn reserving_claims_the_file_and_dropping_releases_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let sink = Sink::File {
            path: path.clone(),
            overwrite: false,
        };
        let reserved = sink.reserve_with(false).unwrap();
        assert!(path.exists(), "the name is taken before the secret exists");
        assert!(matches!(sink.reserve_with(false), Err(Error::Refused(_))));
        drop(reserved);
        assert!(!path.exists(), "an undelivered reservation leaves nothing");

        assert!(Sink::Terminal.reserve_with(false).is_err());
        let missing = Sink::File {
            path: dir.path().join("no/such/dir/key"),
            overwrite: true,
        };
        assert!(missing.reserve_with(false).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
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
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        assert!(out.is_empty());
        let status = String::from_utf8(status).unwrap();
        assert!(status.contains("key") && !status.contains("THE-SECRET"));
    }

    // Creating a symlink on Windows needs a privilege CI runners may lack.
    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn overwrite_replaces_a_symlink_instead_of_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        use std::os::unix::fs::PermissionsExt;
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
