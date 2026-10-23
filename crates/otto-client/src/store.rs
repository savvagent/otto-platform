//! The token cache: one JSON file, owner-only, holding the dynamically
//! registered client id per authorization server and one grant per resource
//! (a token has one audience, so each resource gets its own).
//!
//! Location: `$OTTO_CONFIG_DIR`, else `$XDG_CONFIG_HOME/otto`, else
//! `$HOME/.config/otto`, file `credentials.json`. Linux and macOS only.
//!
//! Every change happens under an exclusive lock on `credentials.lock`, held
//! across the whole read-modify-write, so two `otto` processes never lose each
//! other's writes. Refresh holds it across the token request too: otto-auth
//! treats a refresh token presented twice as a replay and revokes every token
//! the client holds, so two processes must never refresh the same grant.
//! Reads take no lock; the file is only ever replaced by an atomic rename.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret::replace_private;

/// How long to wait for another `otto` process to finish with the store.
const LOCK_WAIT: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize)]
pub struct Grant {
    pub issuer: String,
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: u64,
    pub scope: String,
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Doc {
    #[serde(default)]
    clients: BTreeMap<String, String>,
    #[serde(default)]
    grants: BTreeMap<String, Grant>,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    pub fn open_default() -> Result<Self> {
        let nonempty = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
        let dir = if let Some(d) = nonempty("OTTO_CONFIG_DIR") {
            PathBuf::from(d)
        } else if let Some(d) = nonempty("XDG_CONFIG_HOME") {
            PathBuf::from(d).join("otto")
        } else if let Some(h) = nonempty("HOME") {
            PathBuf::from(h).join(".config").join("otto")
        } else {
            return Err(Error::Store(
                "cannot find a config directory: set OTTO_CONFIG_DIR".into(),
            ));
        };
        Ok(Store { dir })
    }

    fn file(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    /// The grant for `resource`, if any. Takes no lock.
    pub fn grant(&self, resource: &str) -> Result<Option<Grant>> {
        Ok(self.load()?.grants.remove(resource))
    }

    fn load(&self) -> Result<Doc> {
        match std::fs::read(self.file()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| {
                Error::Store(format!(
                    "{} is not valid; delete it and run `otto login` again",
                    self.file().display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Doc::default()),
            Err(e) => Err(Error::io("reading credentials", &e)),
        }
    }

    /// Create the directory owner-only if it is missing. An existing directory
    /// is left as it is: it may be one the user chose, such as `$HOME`, and the
    /// files in it are owner-only either way.
    fn ensure_dir(&self) -> Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&self.dir)
            .map_err(|e| Error::io("creating config dir", &e))
    }

    fn lock_file(&self) -> Result<File> {
        self.ensure_dir()?;
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(self.dir.join("credentials.lock"))
            .map_err(|e| Error::io("opening the credentials lock", &e))
    }

    /// Take the store's lock without blocking the async runtime: poll with
    /// `try_lock`, so a second `otto` process (or a second client in this one)
    /// waits instead of stalling a worker thread.
    pub(crate) async fn lock(&self) -> Result<Locked<'_>> {
        let file = self.lock_file()?;
        let deadline = tokio::time::Instant::now() + LOCK_WAIT;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(Error::Store(
                        "another otto process is holding the credentials lock".into(),
                    ))
                }
                Err(TryLockError::Error(e)) => {
                    return Err(Error::io("locking credentials", &e));
                }
            }
        }
        Ok(Locked {
            store: self,
            doc: self.load()?,
            _lock: file,
        })
    }
}

/// The store, locked and loaded. Changes are made to the in-memory document
/// and written by [`Locked::save`]; the lock is released when this drops.
pub(crate) struct Locked<'a> {
    store: &'a Store,
    doc: Doc,
    _lock: File,
}

impl Locked<'_> {
    pub(crate) fn grant(&self, resource: &str) -> Option<&Grant> {
        self.doc.grants.get(resource)
    }

    pub(crate) fn put_grant(&mut self, resource: &str, grant: Grant) {
        self.doc.grants.insert(resource.to_owned(), grant);
    }

    pub(crate) fn remove_grant(&mut self, resource: &str) {
        self.doc.grants.remove(resource);
    }

    pub(crate) fn client_id(&self, issuer: &str) -> Option<&str> {
        self.doc.clients.get(issuer).map(String::as_str)
    }

    pub(crate) fn put_client(&mut self, issuer: &str, client_id: &str) {
        self.doc
            .clients
            .insert(issuer.to_owned(), client_id.to_owned());
    }

    pub(crate) fn remove_client(&mut self, issuer: &str) {
        self.doc.clients.remove(issuer);
    }

    pub(crate) fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.doc)
            .map_err(|_| Error::Store("could not encode credentials".into()))?;
        replace_private(&self.store.file(), &bytes)
    }
}
