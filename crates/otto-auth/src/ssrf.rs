//! SSRF guard primitives for outbound fetches of admin- or IdP-controlled URLs.
//!
//! Two pieces:
//!
//! - [`is_publicly_routable`], the address classifier.
//! - [`PinnedResolver`], a [`reqwest::dns::Resolve`] that resolves a host
//!   exactly once, classifies **every** resulting address, and hands the
//!   connector only addresses that passed. Because the connector dials what
//!   the resolver returned (there is no second lookup), the connection is
//!   pinned to the addresses that were checked, which closes DNS rebinding:
//!   an authoritative server answering public-then-private never gets a
//!   private answer past the check, since there is only ever one answer per
//!   connect.
//!
//! reqwest does not consult the resolver for a URL whose host is an IP
//! literal, so callers must still classify literal hosts themselves (see
//! `oidc::require_safe_url`).

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Why a host was refused by [`resolve_public`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The underlying lookup failed.
    #[error("host does not resolve: {0}")]
    Lookup(#[source] io::Error),
    /// The lookup succeeded but returned no addresses.
    #[error("host does not resolve to any address")]
    NoAddresses,
    /// At least one resolved address is not publicly routable. The whole
    /// answer is refused, not filtered: a mixed answer is a rebinding signal.
    #[error("host resolves to a non-public address ({0})")]
    NonPublic(IpAddr),
}

/// The inner DNS lookup, injectable so tests can script answers.
pub trait Lookup: Send + Sync + 'static {
    /// Resolves `host` to IP addresses (ports are not meaningful here).
    fn lookup<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;
}

/// The operating system's resolver, via `tokio::net::lookup_host`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// Resolves `host` once through `lookup` and returns the validated,
/// de-duplicated addresses (port 0; the connector substitutes the URL's port).
///
/// Fails if the lookup fails, returns nothing, or returns *any* address that
/// is not publicly routable.
pub async fn resolve_public<L: Lookup + ?Sized>(
    lookup: &L,
    host: &str,
) -> Result<Vec<SocketAddr>, ResolveError> {
    let ips = lookup.lookup(host).await.map_err(ResolveError::Lookup)?;
    if ips.is_empty() {
        return Err(ResolveError::NoAddresses);
    }
    if let Some(blocked) = ips.iter().find(|ip| !is_publicly_routable(ip)) {
        return Err(ResolveError::NonPublic(*blocked));
    }
    let mut seen = HashSet::new();
    Ok(ips
        .into_iter()
        .filter(|ip| seen.insert(*ip))
        .map(|ip| SocketAddr::new(ip, 0))
        .collect())
}

/// A [`Resolve`] that only ever yields publicly routable addresses.
///
/// ```
/// use std::sync::Arc;
/// use otto_auth::ssrf::PinnedResolver;
///
/// let client = reqwest::Client::builder()
///     .dns_resolver(Arc::new(PinnedResolver::system()))
///     .build()
///     .unwrap();
/// # drop(client);
/// ```
#[derive(Debug)]
pub struct PinnedResolver<L = SystemLookup> {
    lookup: Arc<L>,
}

impl PinnedResolver<SystemLookup> {
    /// A resolver backed by the operating system's DNS.
    pub fn system() -> Self {
        Self::new(SystemLookup)
    }
}

impl<L: Lookup> PinnedResolver<L> {
    /// A resolver backed by `lookup`.
    pub fn new(lookup: L) -> Self {
        Self {
            lookup: Arc::new(lookup),
        }
    }
}

impl<L: Lookup> Resolve for PinnedResolver<L> {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = Arc::clone(&self.lookup);
        Box::pin(async move {
            let addrs = resolve_public(&*lookup, name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is a global, publicly routable unicast address this server may
/// dial on behalf of an untrusted URL.
///
/// Deliberately conservative: anything reserved, special-purpose, or that can
/// embed or translate to an IPv4 address is refused outright rather than
/// unwrapped, since a translation prefix (NAT64, 6to4, Teredo) may be
/// routable on the host's network to an internal v4 target. Errs toward
/// rejecting an edge case over accepting one.
pub fn is_publicly_routable(ip: &IpAddr) -> bool {
    // `test-support` only: the crate's own mock server binds to 127.0.0.1.
    // Never enabled by a normal consumer of this crate (see Cargo.toml).
    if cfg!(feature = "test-support") && ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => is_v4_publicly_routable(v4),
        IpAddr::V6(v6) => is_v6_publicly_routable(v6),
    }
}

fn is_v4_publicly_routable(v4: &Ipv4Addr) -> bool {
    if v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
    {
        return false;
    }
    let [a, b, c, _] = v4.octets();
    !(a == 0 // 0.0.0.0/8 "this network"
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 192 && b == 88 && c == 99) // 192.88.99.0/24 deprecated 6to4 relay
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking
        || a >= 240) // 240.0.0.0/4 reserved (incl. broadcast)
}

fn is_v6_publicly_routable(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    // ::ffff:0:0/96 IPv4-mapped: judged by the embedded IPv4.
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_v4_publicly_routable(&mapped);
    }
    let s = v6.segments();
    // ::/96 IPv4-compatible (deprecated, covers ::a.b.c.d): refused whole.
    if s[..6] == [0; 6] {
        return false;
    }
    !(s[0] & 0xfe00 == 0xfc00 // fc00::/7 unique local
        || s[0] & 0xffc0 == 0xfe80 // fe80::/10 link-local
        || s[0] & 0xffc0 == 0xfec0 // fec0::/10 deprecated site-local
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4]) // 64:ff9b::/96 NAT64
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1) // 64:ff9b:1::/48 local-use NAT64
        || s[0] == 0x2002 // 2002::/16 6to4
        || (s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23 IETF assignments (incl. Teredo 2001::/32)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || (s[0] == 0x0100 && s[1..4] == [0; 3])) // 100::/64 discard-only
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // Deliberately never 127.0.0.1/::1: `test-support` exempts loopback only.
    fn blocked(ips: &[&str]) {
        for ip in ips {
            assert!(
                !is_publicly_routable(&ip.parse().unwrap()),
                "{ip} must be rejected"
            );
        }
    }
    fn allowed(ips: &[&str]) {
        for ip in ips {
            assert!(
                is_publicly_routable(&ip.parse().unwrap()),
                "{ip} must be accepted"
            );
        }
    }

    #[test]
    fn rejects_rfc1918_and_link_local_v4() {
        blocked(&["10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254"]);
    }

    #[test]
    fn cgnat_range_and_boundaries() {
        blocked(&["100.64.0.1", "100.127.255.255"]);
        allowed(&["100.63.255.255", "100.128.0.1"]);
    }

    #[test]
    fn rejects_benchmarking_198_18_15() {
        blocked(&["198.18.0.1", "198.19.255.255"]);
        allowed(&["198.17.255.255", "198.20.0.1"]);
    }

    #[test]
    fn rejects_reserved_240_4_and_broadcast() {
        blocked(&["240.0.0.1", "250.1.2.3", "255.255.255.255"]);
    }

    #[test]
    fn rejects_this_network_and_special_purpose_v4() {
        blocked(&["0.0.0.0", "0.1.2.3", "192.0.0.8", "192.88.99.1"]);
    }

    #[test]
    fn rejects_ipv6_unique_local_link_local_and_site_local() {
        blocked(&["fc00::1", "fd12:3456::1", "fe80::1", "fec0::1"]);
    }

    #[test]
    fn rejects_fly_private_network() {
        // Fly's private 6PN, the original motivating target.
        blocked(&["fdaa::1", "fdaa:0:1234::3"]);
    }

    #[test]
    fn rejects_nat64() {
        blocked(&[
            "64:ff9b::8.8.8.8",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::1",
        ]);
        allowed(&["64:ff9a::1"]);
    }

    #[test]
    fn rejects_6to4() {
        blocked(&["2002::1", "2002:a9fe:a9fe::1", "2002:0808:0808::1"]);
    }

    #[test]
    fn rejects_ipv4_mapped_non_public_but_not_public() {
        blocked(&[
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:198.18.0.1",
            "::ffff:240.0.0.1",
        ]);
        allowed(&["::ffff:8.8.8.8"]);
    }

    #[test]
    fn rejects_ipv4_compatible() {
        blocked(&["::10.0.0.1", "::169.254.169.254", "::8.8.8.8"]);
    }

    #[test]
    fn rejects_teredo_documentation_and_discard_v6() {
        blocked(&["2001::1", "2001:db8::1", "100::1", "::", "ff02::1"]);
    }

    #[test]
    fn accepts_ordinary_public_addresses() {
        allowed(&[
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700::1111",
        ]);
    }

    /// Scripted lookup: each call pops the next answer, recording call count.
    struct Script {
        answers: Mutex<VecDeque<io::Result<Vec<IpAddr>>>>,
        calls: Mutex<usize>,
    }
    impl Script {
        fn new(answers: Vec<io::Result<Vec<IpAddr>>>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.into()),
                calls: Mutex::new(0),
            })
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }
    impl Lookup for Arc<Script> {
        fn lookup<'a>(
            &'a self,
            _host: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
            *self.calls.lock().unwrap() += 1;
            let next = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::other("script exhausted")));
            Box::pin(async move { next })
        }
    }

    fn ips(list: &[&str]) -> io::Result<Vec<IpAddr>> {
        Ok(list.iter().map(|s| s.parse().unwrap()).collect())
    }

    #[tokio::test]
    async fn returns_only_validated_deduplicated_addresses() {
        let script = Script::new(vec![ips(&["8.8.8.8", "8.8.8.8", "2001:4860:4860::8888"])]);
        let got = resolve_public(&script, "ok.test").await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|a| a.port() == 0));
    }

    #[tokio::test]
    async fn one_private_address_poisons_the_whole_answer() {
        let script = Script::new(vec![ips(&["8.8.8.8", "10.0.0.5"])]);
        let err = resolve_public(&script, "mixed.test").await.unwrap_err();
        assert!(matches!(err, ResolveError::NonPublic(ip) if ip.to_string() == "10.0.0.5"));
    }

    #[tokio::test]
    async fn empty_answer_and_lookup_failure_fail_closed() {
        let script = Script::new(vec![ips(&[]), Err(io::Error::other("nxdomain"))]);
        assert!(matches!(
            resolve_public(&script, "a.test").await,
            Err(ResolveError::NoAddresses)
        ));
        assert!(matches!(
            resolve_public(&script, "a.test").await,
            Err(ResolveError::Lookup(_))
        ));
    }

    #[tokio::test]
    async fn rebinding_public_then_private_is_refused_at_connect_time() {
        // A prior lookup (e.g. a pre-flight check) saw a public address; the
        // lookup performed for the connection sees a private one. Every
        // lookup is validated independently, so the second must fail.
        let script = Script::new(vec![ips(&["8.8.8.8"]), ips(&["169.254.169.254"])]);
        assert!(resolve_public(&script, "rebind.test").await.is_ok());
        let err = resolve_public(&script, "rebind.test").await.unwrap_err();
        assert!(matches!(err, ResolveError::NonPublic(_)), "{err:?}");
    }

    #[tokio::test]
    async fn client_with_pinned_resolver_refuses_to_connect_to_a_private_answer() {
        // End to end through reqwest: the connect-time lookup answers private
        // (after a notional earlier public answer), so the request must fail
        // in the resolver without any connection attempt.
        let script = Script::new(vec![ips(&["10.255.255.1"])]);
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PinnedResolver::new(Arc::clone(&script))))
            .build()
            .unwrap();
        let err = client
            .get("https://rebind.test/")
            .send()
            .await
            .expect_err("a private answer must fail the request");
        assert!(err.is_connect(), "{err:?}");
        let mut chain = String::new();
        let mut src: Option<&dyn std::error::Error> = Some(&err);
        while let Some(e) = src {
            chain.push_str(&e.to_string());
            src = e.source();
        }
        assert!(
            chain.contains("non-public address (10.255.255.1)"),
            "{chain}"
        );
        assert_eq!(script.calls(), 1);
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn client_connects_only_to_the_resolver_supplied_address() {
        // Positive control: the name resolves (via the stub) to the loopback
        // test server, proving the connection uses the resolver's answer.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await;
        });
        let script = Script::new(vec![ips(&["127.0.0.1"])]);
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PinnedResolver::new(Arc::clone(&script))))
            .build()
            .unwrap();
        let body = client
            .get(format!("http://pinned.test:{port}/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
        assert_eq!(script.calls(), 1);
    }
}
