//! DNS TXT record verification, for claiming an email domain into an org's
//! SSO configuration — see otto-factory's `docs/specs/2026-09-16-oidc-federation-design.md`
//! §4.
//!
//! Uses the system's configured resolver (`/etc/resolv.conf` on Unix) — no
//! new `OTTO_*` config, and no credential of otto-platform's own is needed to do
//! a TXT lookup, which is the same trust boundary as any other outbound
//! network call this server already makes.

use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::{rdata::TXT, RData};
use hickory_resolver::TokioResolver;

use crate::error::{AuthError, Result};

const VERIFY_SUBDOMAIN: &str = "_otto-verify";

/// Resolves `_otto-verify.{domain}` TXT records and reports whether
/// any of them equals `otto-verify={expected_token}`.
///
/// The `Ok`/`Err` split is deliberate and exact, per spec §4 — do not widen
/// either side of it:
///
/// - `Ok(false)` covers NXDOMAIN, a timeout, and "no records" alike. All
///   three mean the same thing to the admin who just clicked "Verify": *not
///   yet, try again after DNS propagates*. Conflating "not verified" with
///   "the resolver had a problem" would turn a routine, expected state (DNS
///   hasn't propagated yet) into noise the admin can't act on differently.
/// - `Err` is reserved for a genuine resolver/transport failure — the
///   resolver itself being unreachable — which *is* an operator-facing
///   problem, not the domain's.
pub async fn verify_txt_record(domain: &str, expected_token: &str) -> Result<bool> {
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(|source| AuthError::DnsResolverFailure(source.to_string()))?;

    // Fully-qualified (trailing dot) so the system resolver's search-domain
    // list is never consulted — this name is always meant absolutely.
    let name = format!("{VERIFY_SUBDOMAIN}.{}.", domain.trim_end_matches('.'));
    let expected = format!("otto-verify={expected_token}");

    match resolver.txt_lookup(name).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .any(|record| matches!(&record.data, RData::TXT(txt) if txt_equals(txt, &expected)))),
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) | Err(NetError::Timeout) => Ok(false),
        Err(source) => Err(AuthError::DnsResolverFailure(source.to_string())),
    }
}

/// A TXT record's value can arrive split across multiple `<character-string>`
/// chunks (RFC 1035 §3.3.14); the logical value is their concatenation, not
/// any single chunk.
fn txt_equals(txt: &TXT, expected: &str) -> bool {
    let joined: String = txt
        .txt_data
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect();
    joined == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt(chunks: &[&str]) -> TXT {
        TXT::new(chunks.iter().map(|c| c.to_string()).collect())
    }

    #[test]
    fn txt_equals_matches_a_single_chunk() {
        let record = txt(&["otto-verify=abc123"]);
        assert!(txt_equals(&record, "otto-verify=abc123"));
    }

    #[test]
    fn txt_equals_rejects_a_mismatched_single_chunk() {
        let record = txt(&["otto-verify=wrong"]);
        assert!(!txt_equals(&record, "otto-verify=abc123"));
    }

    #[test]
    fn txt_equals_joins_multiple_chunks_before_comparing() {
        // RFC 1035 §3.3.14: a single logical value can arrive split across
        // several <character-string> chunks. Only their concatenation is
        // meaningful — neither chunk alone should match, and the joined
        // value must.
        let record = txt(&["otto-verify=abc", "123"]);
        assert!(txt_equals(&record, "otto-verify=abc123"));
        assert!(!txt_equals(&record, "otto-verify=abc"));
    }

    #[test]
    fn txt_equals_rejects_an_empty_record() {
        let record = txt(&[]);
        assert!(!txt_equals(&record, "otto-verify=abc123"));
    }
}
