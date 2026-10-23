//! A secret an app returned, and the only places it may be written.
//!
//! [`Secret`] has no `Display` or `Debug` that shows its value, so it cannot
//! reach a log line or an error message by formatting. The one way out is
//! [`Secret::deliver`], which writes to the terminal or to a file the user
//! named, created readable by its owner only.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// The raw value. Use it to build a request header; do not format it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Hand the secret to a person: `Sink::Terminal` or `Sink::File`.
    pub fn deliver(&self, sink: &Sink, terminal: &mut dyn Write) -> Result<()> {
        match sink {
            Sink::Terminal => {
                writeln!(terminal, "{}", self.0).map_err(|e| Error::io("writing to terminal", &e))
            }
            Sink::File(path) => {
                write_private(path, format!("{}\n", self.0).as_bytes())?;
                writeln!(terminal, "secret written to {}", path.display())
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
    File(PathBuf),
}

/// Write `bytes` to `path`, readable and writable by the owner only. A file
/// that already exists is narrowed to `0600` *before* the new content goes in,
/// so a looser mode never briefly holds a secret.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    // No `truncate(true)`: truncating happens at open, before the mode is
    // narrowed. Narrow first, then truncate.
    let mut file = opts
        .open(path)
        .map_err(|e| Error::io(&format!("opening {}", path.display()), &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(&format!("securing {}", path.display()), &e))?;
    }
    file.set_len(0)
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.flush())
        .map_err(|e| Error::io(&format!("writing {}", path.display()), &e))
}
