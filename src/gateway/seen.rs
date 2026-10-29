//! Bounded, time-limited record of webhook event ids already processed.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// 10 minutes: longer than twice the 300s signature window, so a replayed
/// delivery can never outlive its dedupe entry while still being validly signed.
pub const TTL: Duration = Duration::from_secs(10 * 60);
pub const CAPACITY: usize = 10_000;

pub struct SeenCache {
    ttl: Duration,
    capacity: usize,
    seen: HashMap<String, Instant>,
    /// Insertion order, oldest first.
    order: VecDeque<(String, Instant)>,
}

impl SeenCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Returns `true` if `id` is new (and records it), `false` for a duplicate
    /// seen within the TTL. When full, the oldest entries are evicted first.
    pub fn check_and_insert(&mut self, id: &str, now: Instant) -> bool {
        self.evict_expired(now);
        if self.seen.contains_key(id) {
            return false;
        }
        self.seen.insert(id.to_string(), now);
        self.order.push_back((id.to_string(), now));
        while self.seen.len() > self.capacity {
            if let Some((old, _)) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    fn evict_expired(&mut self, now: Instant) {
        while let Some((id, at)) = self.order.front() {
            if now.saturating_duration_since(*at) < self.ttl {
                break;
            }
            self.seen.remove(id);
            self.order.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_within_ttl_are_detected() {
        let mut c = SeenCache::new(TTL, 100);
        let t0 = Instant::now();
        assert!(c.check_and_insert("a", t0));
        assert!(!c.check_and_insert("a", t0 + Duration::from_secs(1)));
        assert!(!c.check_and_insert("a", t0 + TTL - Duration::from_millis(1)));
        assert!(c.check_and_insert("b", t0));
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let mut c = SeenCache::new(TTL, 100);
        let t0 = Instant::now();
        assert!(c.check_and_insert("a", t0));
        assert!(
            c.check_and_insert("a", t0 + TTL),
            "expired entry may be seen again"
        );
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn a_duplicate_hit_does_not_extend_the_entry() {
        let mut c = SeenCache::new(TTL, 100);
        let t0 = Instant::now();
        c.check_and_insert("a", t0);
        assert!(!c.check_and_insert("a", t0 + TTL / 2));
        assert!(c.check_and_insert("a", t0 + TTL + Duration::from_secs(1)));
    }

    #[test]
    fn capacity_evicts_the_oldest_first() {
        let mut c = SeenCache::new(TTL, 3);
        let t = Instant::now();
        for id in ["a", "b", "c", "d"] {
            assert!(c.check_and_insert(id, t));
        }
        assert_eq!(c.len(), 3);
        assert!(c.check_and_insert("a", t), "oldest was evicted");
        assert!(!c.check_and_insert("d", t), "newest is retained");
    }

    #[test]
    fn memory_stays_bounded_under_a_flood() {
        let mut c = SeenCache::new(TTL, 50);
        let t = Instant::now();
        for i in 0..10_000 {
            c.check_and_insert(&format!("id-{i}"), t);
        }
        assert_eq!(c.len(), 50);
        assert_eq!(c.order.len(), 50);
    }
}
