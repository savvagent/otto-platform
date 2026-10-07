//! The console's handlers, grouped by what they act on.
//!
//! Every handler here is named once in [`crate::catalog`], which is what mounts
//! it and what documents it. A handler that is not in the catalog is not
//! reachable — deliberately, so that adding a route and describing it are the
//! same act.

pub mod auth;
pub mod orgs;
pub mod sso;
pub mod teams;
pub mod tokens;
pub mod usage;

/// Distinguish "field absent" from "field present and null".
///
/// serde collapses both into `None` for an `Option<T>`; wrapping the whole
/// deserialization in `Some` recovers the difference — absent stays `None`
/// because of `#[serde(default)]`, while an explicit `null` arrives as
/// `Some(None)`.
///
/// A user's `locale` has to be clearable or "match my browser" is a choice
/// nobody can make twice, and a plain `Option` cannot tell "leave it alone"
/// from "clear it".
pub(crate) fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}
