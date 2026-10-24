//! Optional local transport leases. Absent from codec-free firmware.
#[cfg(feature = "discovery")]
use crate::{TelemetryError, TelemetryResult};
#[cfg(feature = "discovery")]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "discovery")]
#[derive(Clone, Debug)]
struct Peer {
    // Full authoritative identity, not its potentially colliding wire hash.
    sender: Arc<str>,
    address: u32,
    alias: u32,
    owner: u64,
    birth: u64,
    last_seen: u64,
    supported: bool,
    confirmed: bool,
}
#[cfg(feature = "discovery")]
#[derive(Clone, Copy, Debug, Default)]
struct Pending {
    address: u32,
    until: u64,
}

/// Fixed unknown-source scratch never allocates on refused ingress. Overflow
/// conservatively disables the optional codec for one existing liveness lease.
#[cfg(feature = "discovery")]
#[derive(Clone, Debug, Default)]
pub(crate) struct Ledger {
    peers: Vec<Peer>,
    names_bytes: usize,
    pending: [Pending; 4],
    overflow_until: u64,
    allowed: bool,
    ambiguous: bool,
    recheck_collisions: bool,
    next_expiry: u64,
    generation: u64,
}
#[cfg(feature = "discovery")]
impl Ledger {
    pub(crate) fn allowed(&self, now: u64) -> bool {
        self.allowed && now <= self.next_expiry
    }
    // Retaining opaque bytes does not dispatch them. The live lease is checked
    // again at send time; this snapshot only avoids speculative decoder work
    // while a capable-side owner is first admitted to its queue.
    pub(crate) fn retention_can_stay_compressed(&self) -> bool {
        self.allowed
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.peers.capacity() * core::mem::size_of::<Peer>() + self.names_bytes
    }
    fn name_bytes(name: &str) -> usize {
        name.len()
            .saturating_add(2 * core::mem::size_of::<usize>())
            .next_multiple_of(core::mem::size_of::<usize>())
    }
    fn changed(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
    fn pending(&mut self, address: u32, now: u64, ttl: u64) {
        let until = now.saturating_add(ttl);
        if let Some(slot) = self
            .pending
            .iter_mut()
            .find(|p| p.until != 0 && p.address == address)
        {
            slot.until = until;
        } else if let Some(slot) = self
            .pending
            .iter_mut()
            .find(|p| p.until < now || p.until == 0)
        {
            *slot = Pending { address, until };
            self.changed();
        } else {
            let newly_blocked = self.overflow_until == 0 || self.overflow_until < now;
            self.overflow_until = self.overflow_until.max(until);
            if newly_blocked {
                self.changed();
            }
        }
        if self.allowed {
            self.changed();
        }
        self.allowed = false;
        self.next_expiry = self.next_expiry.min(until);
    }
    // Incoming numeric identities are only used when they resolve uniquely.
    // Distinct full names with the same address/hash never overwrite one another.
    fn unique_address(&self, address: u32, now: u64, ttl: u64) -> Option<usize> {
        let mut found = None;
        for (index, peer) in self.peers.iter().enumerate() {
            if (peer.address == address || peer.alias == address)
                && now.saturating_sub(peer.last_seen) <= ttl
            {
                if found.is_some() {
                    return None;
                }
                found = Some(index);
            }
        }
        found
    }
    pub(crate) fn observe(&mut self, address: u32, now: u64, ttl: u64) {
        let Some(index) = self.unique_address(address, now, ttl) else {
            self.pending(address, now, ttl);
            return;
        };
        self.peers[index].last_seen = now;
        // Only renew a conservative cached minimum at its deadline. TX is O(1).
        if now >= self.next_expiry {
            self.recompute(now, ttl);
        }
    }
    pub(crate) fn revoke_if_unsupported(
        &mut self,
        address: u32,
        supported: bool,
        now: u64,
        ttl: u64,
    ) {
        self.observe(address, now, ttl);
        if supported {
            return;
        }
        if let Some(index) = self.unique_address(address, now, ttl) {
            if self.peers[index].supported {
                self.peers[index].supported = false;
                self.changed();
            }
            self.recompute(now, ttl);
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn learn(
        &mut self,
        address: u32,
        sender: &str,
        owner: u64,
        birth: u64,
        supported: bool,
        now: u64,
        ttl: u64,
    ) -> TelemetryResult<()> {
        let alias = crate::packet::sender_address_u32(sender);
        if sender.is_empty() {
            self.pending(address, now, ttl);
            return Ok(());
        }
        let position = self
            .peers
            .binary_search_by(|p| p.sender.as_ref().cmp(sender));
        let mut changed;
        match position {
            Ok(index) => {
                let peer = &mut self.peers[index];
                let same = peer.owner == owner && peer.birth == birth;
                let support = if same && peer.confirmed {
                    peer.supported && supported
                } else {
                    supported
                };
                changed = !same
                    || !peer.confirmed
                    || support != peer.supported
                    || peer.address != address;
                self.recheck_collisions |= peer.address != address;
                peer.address = address;
                peer.alias = alias;
                peer.owner = owner;
                peer.birth = birth;
                peer.supported = support;
                peer.confirmed = true;
                peer.last_seen = now;
            }
            Err(index) => {
                let grow = self.peers.len() == self.peers.capacity();
                let target = self
                    .peers
                    .len()
                    .saturating_add(1)
                    .checked_next_power_of_two()
                    .ok_or(TelemetryError::Io("memory pressure"))?
                    .max(4);
                let vector = if grow {
                    target.saturating_mul(core::mem::size_of::<Peer>())
                } else {
                    0
                };
                let name_bytes = Self::name_bytes(sender);
                let largest = vector.max(name_bytes).saturating_add(32);
                if let Err(error) = crate::memory_admission::check(
                    vector.saturating_add(name_bytes).saturating_add(32),
                    largest,
                ) {
                    self.pending(address, now, ttl);
                    return Err(error);
                }
                if grow
                    && self
                        .peers
                        .try_reserve_exact(target - self.peers.len())
                        .is_err()
                {
                    self.pending(address, now, ttl);
                    return Err(TelemetryError::Io("memory pressure"));
                }
                self.ambiguous |= self.peers.iter().any(|peer| {
                    [address, alias]
                        .iter()
                        .any(|value| [peer.address, peer.alias].contains(value))
                });
                self.peers.insert(
                    index,
                    Peer {
                        sender: Arc::from(sender),
                        address,
                        alias,
                        owner,
                        birth,
                        last_seen: now,
                        supported,
                        confirmed: true,
                    },
                );
                self.names_bytes = self.names_bytes.saturating_add(name_bytes);
                changed = true;
            }
        }
        for pending in &mut self.pending {
            if pending.until != 0 && [address, alias].contains(&pending.address) {
                *pending = Pending::default();
                changed = true;
            }
        }
        if changed {
            self.changed();
        }
        if changed || now >= self.next_expiry {
            self.recompute(now, ttl);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hint_address(
        &mut self,
        address: u32,
        sender: &str,
        owner: u64,
        birth: u64,
        supported: bool,
        now: u64,
        ttl: u64,
    ) {
        let alias = crate::packet::sender_address_u32(sender);
        let Ok(index) = self
            .peers
            .binary_search_by(|p| p.sender.as_ref().cmp(sender))
        else {
            self.pending(address, now, ttl);
            self.pending(alias, now, ttl);
            return;
        };
        let peer = &mut self.peers[index];
        let different = peer.owner != owner || peer.birth != birth || peer.address != address;
        if (different && peer.confirmed) || (!supported && peer.supported) {
            peer.supported = false;
            if different {
                peer.confirmed = false;
            }
            self.allowed = false;
            self.changed();
        }
    }
    pub(crate) fn address_payload(
        &mut self,
        payload: &[u8],
        accepted: bool,
        now: u64,
        ttl: u64,
    ) -> TelemetryResult<()> {
        let ad = crate::discovery::decode_address_view(payload)?;
        let supported =
            ad.link_capabilities.flags & crate::discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION != 0;
        if accepted {
            self.learn(
                ad.address,
                ad.hostname,
                ad.owner_hash,
                ad.birth_ms,
                supported,
                now,
                ttl,
            )
        } else {
            self.hint_address(
                ad.address,
                ad.hostname,
                ad.owner_hash,
                ad.birth_ms,
                supported,
                now,
                ttl,
            );
            Ok(())
        }
    }
    pub(crate) fn discovery_packet(
        &mut self,
        pkt: &crate::packet::Packet,
        accepted: bool,
        now: u64,
        ttl: u64,
    ) -> TelemetryResult<()> {
        use crate::config::DataType;
        match pkt.data_type() {
            DataType::DiscoveryAddress => self.address_payload(pkt.payload(), accepted, now, ttl),
            DataType::DiscoveryLinkCapabilities => {
                let caps = crate::discovery::decode_discovery_link_capabilities(pkt)?;
                // Unscoped legacy packets may revoke, never enable, incarnation trust.
                self.revoke_if_unsupported(
                    crate::packet::sender_address_u32(pkt.sender()),
                    caps.flags & crate::discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION != 0,
                    now,
                    ttl,
                );
                Ok(())
            }
            DataType::DiscoveryLeave if accepted => {
                self.remove_address(crate::packet::sender_address_u32(pkt.sender()), now, ttl);
                Ok(())
            }
            _ => Ok(()),
        }
    }
    pub(crate) fn remove_address(&mut self, address: u32, now: u64, ttl: u64) {
        if let Some(index) = self.unique_address(address, now, ttl) {
            let peer = self.peers.remove(index);
            self.recheck_collisions = true;
            self.names_bytes = self
                .names_bytes
                .saturating_sub(Self::name_bytes(&peer.sender));
            self.changed();
        }
        for pending in &mut self.pending {
            if pending.address == address {
                *pending = Pending::default();
            }
        }
        self.recompute(now, ttl);
    }
    /// Reclaim only optional codec metadata before refusing required routing
    /// or schema growth. Keep a fixed, allocation-free raw hold until every
    /// forgotten peer's existing lease has expired, so forgetting a legacy
    /// receiver cannot turn a later capable announcement into permission.
    pub(crate) fn evict_for_budget(&mut self, ttl: u64) -> bool {
        if self.heap_bytes() == 0 {
            return false;
        }
        let until = self
            .peers
            .iter()
            .map(|peer| peer.last_seen.saturating_add(ttl))
            .chain(self.pending.iter().map(|pending| pending.until))
            .chain(core::iter::once(self.overflow_until))
            .max()
            .unwrap_or(0);
        self.peers = Vec::new();
        self.names_bytes = 0;
        self.allowed = false;
        self.ambiguous = false;
        self.recheck_collisions = false;
        self.overflow_until = until;
        self.next_expiry = until;
        self.changed();
        true
    }

    pub(crate) fn evict(&mut self, now: u64, ttl: u64) {
        self.peers = Vec::new();
        self.names_bytes = 0;
        self.allowed = false;
        self.ambiguous = false;
        self.recheck_collisions = false;
        self.overflow_until = now.saturating_add(ttl);
        self.next_expiry = self.overflow_until;
        self.changed();
    }
    pub(crate) fn expire(&mut self, now: u64, ttl: u64) {
        if now > self.next_expiry {
            self.recompute(now, ttl);
        }
    }
    fn recompute(&mut self, now: u64, ttl: u64) {
        let before = self.peers.len();
        let mut removed = 0;
        self.peers.retain(|p| {
            let keep = now.saturating_sub(p.last_seen) <= ttl;
            if !keep {
                removed += Self::name_bytes(&p.sender);
            }
            keep
        });
        self.names_bytes = self.names_bytes.saturating_sub(removed);
        if self.peers.is_empty() {
            self.peers = Vec::new();
        }
        for pending in &mut self.pending {
            if pending.until < now {
                *pending = Pending::default();
            }
        }
        let mut allowed =
            !self.peers.is_empty() && (self.overflow_until == 0 || self.overflow_until < now);
        let mut expiry = u64::MAX;
        if before != self.peers.len() || self.recheck_collisions {
            self.ambiguous = self.peers.iter().enumerate().any(|(index, peer)| {
                self.peers[..index].iter().any(|other| {
                    [peer.address, peer.alias]
                        .iter()
                        .any(|value| [other.address, other.alias].contains(value))
                })
            });
            self.recheck_collisions = false;
        }
        allowed &= !self.ambiguous;
        for peer in &self.peers {
            allowed &= peer.confirmed && peer.supported && peer.address != 0;
            expiry = expiry.min(peer.last_seen.saturating_add(ttl));
        }
        for pending in &self.pending {
            if pending.until != 0 {
                allowed = false;
                expiry = expiry.min(pending.until);
            }
        }
        if self.overflow_until >= now && self.overflow_until != 0 {
            allowed = false;
            expiry = expiry.min(self.overflow_until);
        }
        if allowed != self.allowed || before != self.peers.len() {
            self.changed();
        }
        self.allowed = allowed;
        self.next_expiry = expiry;
    }
}
#[cfg(all(test, feature = "discovery"))]
mod tests {
    use super::*;
    #[test]
    fn all_peers_unknown_and_incarnation_leases() {
        let mut l = Ledger::default();
        assert!(!l.allowed(1));
        l.observe(1, 1, 100);
        l.learn(1, "ONE", 10, 1, true, 2, 100).unwrap();
        assert!(l.allowed(2));
        l.learn(2, "TWO", 20, 1, false, 3, 100).unwrap();
        assert!(!l.allowed(3));
        l.learn(2, "TWO", 20, 1, true, 4, 100).unwrap();
        assert!(!l.allowed(4));
        l.learn(2, "TWO", 20, 2, true, 5, 100).unwrap();
        assert!(l.allowed(5));
        assert!(!l.allowed(106));
        l.observe(1, 107, 100);
        assert!(!l.allowed(107));
    }
    #[test]
    fn unknown_ingress_revokes_without_allocating() {
        let mut l = Ledger::default();
        l.learn(1, "ONE", 1, 1, true, 1, 100).unwrap();
        let capacity = l.heap_bytes();
        l.observe(9, 2, 100);
        assert!(!l.allowed(2));
        assert_eq!(l.heap_bytes(), capacity);
        l.learn(9, "NINE", 9, 1, true, 3, 100).unwrap();
        assert!(l.allowed(3));
        l.revoke_if_unsupported(9, false, 4, 100);
        assert!(!l.allowed(4));
    }
    #[test]
    fn live_data_renews_trust_without_schema_refresh() {
        let mut l = Ledger::default();
        l.learn(10, "TEN", 99, 1, true, 1, 100).unwrap();
        let generation = l.generation();
        for now in 2..500 {
            l.observe(10, now, 100);
            assert!(l.allowed(now));
            assert_eq!(l.generation(), generation);
        }
        l.expire(600, 100);
        assert!(!l.allowed(600));
    }
    #[test]
    fn colliding_numeric_ids_never_alias_distinct_names() {
        let mut l = Ledger::default();
        l.learn(7, "FIRST", 1, 1, false, 1, 100).unwrap();
        l.learn(7, "SECOND", 2, 1, true, 2, 100).unwrap();
        assert_eq!(l.peers.len(), 2);
        assert!(!l.allowed(2));
        l.observe(7, 3, 100);
        assert!(!l.allowed(3));
    }
    #[test]
    fn repeated_unchanged_summary_does_not_invalidate_tx() {
        let mut l = Ledger::default();
        l.learn(1, "ONE", 1, 1, true, 0, 100).unwrap();
        let generation = l.generation();
        for now in 1..500 {
            l.learn(1, "ONE", 1, 1, true, now, 100).unwrap();
            assert_eq!(l.generation(), generation);
            assert!(l.allowed(now));
        }
    }
    #[test]
    fn budget_eviction_cannot_forget_a_live_legacy_receiver_into_codec_permission() {
        let mut ledger = Ledger::default();
        ledger.learn(1, "LEGACY", 1, 1, false, 50, 100).unwrap();
        ledger.learn(2, "CAPABLE", 2, 1, true, 1, 100).unwrap();
        assert!(ledger.evict_for_budget(100));
        assert_eq!(ledger.heap_bytes(), 0);
        ledger.learn(3, "NEW_CAPABLE", 3, 1, true, 80, 100).unwrap();
        assert!(!ledger.allowed(149));
        ledger.expire(151, 100);
        assert!(ledger.allowed(151));
        // If a forgotten old peer is actually still talking, its allocation-free
        // unknown-source lease blocks compression without another schema flood.
        ledger.observe(1, 152, 100);
        assert!(!ledger.allowed(152));
        assert!(!ledger.allowed(200));
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "explicit bounded microbenchmark"]
    fn codec_ledger_profile() {
        use std::time::Instant;
        for count in [16, 64, 256] {
            let mut ledger = Ledger::default();
            let began = Instant::now();
            let mut peak = 0;
            for index in 1..=count {
                let before = ledger.heap_bytes();
                ledger
                    .learn(
                        index,
                        &alloc::format!("PEER_{index:04}"),
                        index as u64,
                        1,
                        true,
                        1,
                        100_000,
                    )
                    .unwrap();
                // Conservative allocator peak bound includes overlapping old/new Vec.
                peak = peak.max(before + ledger.heap_bytes());
            }
            let insert = began.elapsed().as_nanos();
            let began = Instant::now();
            let generation = ledger.generation();
            for index in 0..10_000 {
                ledger.observe(index % count + 1, 2, 100_000);
            }
            let observe = began.elapsed().as_nanos();
            assert_eq!(generation, ledger.generation());
            let began = Instant::now();
            for _ in 0..100_000 {
                assert!(std::hint::black_box(&ledger).allowed(2));
            }
            let tx = began.elapsed().as_nanos();
            std::println!(
                "codec_ledger peers={count} heap_bytes={} peak_upper_bytes={peak} insert_ns={insert} observe_10k_ns={observe} tx_100k_ns={tx}",
                ledger.heap_bytes()
            );
        }
    }
}

/// Queue credit held while an expanded item is outside its queue. This is
/// separate from allocator admission: a callback may enqueue new work while
/// the current owner is still waiting to be retried.
pub(crate) trait QueueBudget {
    fn codec_reserved(&mut self) -> &mut usize;
    fn codec_used(&self) -> usize;
    fn codec_limit(&self) -> usize;
}
pub(crate) struct QueueReservation<'a, T: QueueBudget> {
    state: &'a crate::lock::RouterMutex<T>,
    bytes: usize,
}
impl<'a, T: QueueBudget> QueueReservation<'a, T> {
    pub(crate) fn acquire(
        state: &'a crate::lock::RouterMutex<T>,
        bytes: usize,
    ) -> crate::TelemetryResult<Self> {
        let mut locked = state.lock();
        if locked
            .codec_used()
            .checked_add(bytes)
            .is_none_or(|used| used > locked.codec_limit())
        {
            return Err(crate::TelemetryError::Io("memory pressure"));
        }
        *locked.codec_reserved() += bytes;
        Ok(Self { state, bytes })
    }
    /// Call under the same lock that immediately admits the retained queue
    /// owner, so callback/reentrant producers cannot steal its expansion credit.
    pub(crate) fn release_locked(&mut self, state: &mut T) {
        *state.codec_reserved() = state.codec_reserved().saturating_sub(self.bytes);
        self.bytes = 0;
    }
}
impl<T: QueueBudget> Drop for QueueReservation<'_, T> {
    fn drop(&mut self) {
        if self.bytes != 0 {
            let mut state = self.state.lock();
            self.release_locked(&mut state);
        }
    }
}
