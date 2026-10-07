//! Bounded caches with per-entry expiry.
//!
//! Backed by `moka`, which evicts by frequency and recency when full. The
//! earlier hand-rolled map cleared itself when full, so a stream of garbage
//! keys could flush every live entry; here a full cache sheds its coldest
//! entries instead, and callers keep positive and negative results in separate
//! caches so junk can only ever displace other junk.

use std::hash::Hash;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use moka::Expiry;

struct PerEntry;

impl<K, V> Expiry<K, (V, Duration)> for PerEntry {
    fn expire_after_create(
        &self,
        _key: &K,
        value: &(V, Duration),
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.1)
    }
}

pub(crate) struct TtlCache<K, V> {
    inner: Cache<K, (V, Duration)>,
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(max_entries: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_entries)
                .expire_after(PerEntry)
                .build(),
        }
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key).map(|(v, _)| v)
    }

    pub(crate) fn insert(&self, key: K, value: V, ttl: Duration) {
        if !ttl.is_zero() {
            self.inner.insert(key, (value, ttl));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire_at_their_own_ttl() {
        let c = TtlCache::new(10);
        c.insert("short", 1, Duration::from_millis(80));
        c.insert("long", 2, Duration::from_secs(60));
        assert_eq!(c.get(&"short"), Some(1));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(c.get(&"short"), None);
        assert_eq!(c.get(&"long"), Some(2));
    }

    #[test]
    fn zero_ttl_is_not_stored() {
        let c = TtlCache::new(10);
        c.insert("a", 1, Duration::ZERO);
        assert_eq!(c.get(&"a"), None);
    }

    #[test]
    fn a_flood_of_new_keys_stays_bounded() {
        let c = TtlCache::new(100);
        for i in 0..5_000u32 {
            c.insert(i, i, Duration::from_secs(60));
        }
        c.inner.run_pending_tasks();
        assert!(c.inner.entry_count() <= 100);
    }
}
