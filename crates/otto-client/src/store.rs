//! The token cache: one JSON file, owner-only, holding the dynamically
//! registered client id per authorization server and one grant per resource
//! (a token has one audience, so each resource gets its own).
//!
//! Location: `$OTTO_CONFIG_DIR`, else `$XDG_CONFIG_HOME/otto`, else
//! `$HOME/.config/otto`, file `credentials.json`. Linux and macOS only.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret::write_private;

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

    fn save(&self, doc: &Doc) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| Error::io("creating config dir", &e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::io("securing config dir", &e))?;
        }
        let bytes = serde_json::to_vec_pretty(doc)
            .map_err(|_| Error::Store("could not encode credentials".into()))?;
        // Write beside the target and rename, so a crash never leaves a
        // half-written credentials file.
        let tmp = self
            .dir
            .join(format!("credentials.json.tmp{}", std::process::id()));
        write_private(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.file()).map_err(|e| Error::io("replacing credentials", &e))
    }

    pub fn grant(&self, resource: &str) -> Result<Option<Grant>> {
        Ok(self.load()?.grants.remove(resource))
    }

    pub fn put_grant(&self, resource: &str, grant: Grant) -> Result<()> {
        let mut doc = self.load()?;
        doc.grants.insert(resource.to_owned(), grant);
        self.save(&doc)
    }

    pub fn remove_grant(&self, resource: &str) -> Result<()> {
        let mut doc = self.load()?;
        if doc.grants.remove(resource).is_some() {
            self.save(&doc)?;
        }
        Ok(())
    }

    pub fn client_id(&self, issuer: &str) -> Result<Option<String>> {
        Ok(self.load()?.clients.remove(issuer))
    }

    pub fn put_client(&self, issuer: &str, client_id: &str) -> Result<()> {
        let mut doc = self.load()?;
        doc.clients.insert(issuer.to_owned(), client_id.to_owned());
        self.save(&doc)
    }

    pub fn remove_client(&self, issuer: &str) -> Result<()> {
        let mut doc = self.load()?;
        if doc.clients.remove(issuer).is_some() {
            self.save(&doc)?;
        }
        Ok(())
    }
}
