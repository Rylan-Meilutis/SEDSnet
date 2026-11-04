//! STD-only caller-owned preparation. Commit is a try-lock-only cache/queue
//! transaction. Retire the preparation only after releasing application guards.
//!
//! Packet IDs and source timestamps are immutable. The initial cache age anchor
//! survives preparation/rebase/commit; later ordinary dispatch or duplicate
//! receipt retains legacy local-observation age semantics and may refresh cache
//! `cached_at_ms`. Cache observation age is not source freshness, application
//! authorization or a renewed caller deadline. Caller deadlines are external;
//! this SDK operation does not inspect or extend them.
use super::*;

#[derive(Clone, Copy, Debug)]
pub struct ManagedBatchPreparationLimits {
    pub max_batch_packets: usize,
    pub max_snapshot_types: usize,
    pub max_snapshot_entries: usize,
    pub max_original_payload_bytes: usize,
    pub max_snapshot_logical_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryManagedBatchError {
    CoreBusy,
    SchemaBusy,
    BlockedPendingReliableType,
    Capacity,
    RegistrationChanged,
    CacheSnapshotChanged,
    SchemaChanged,
    OriginalValueObsolete,
    AlreadyAdmitted,
    WrongRouter,
    OriginNotAllowed,
    EpochExhausted,
    EmptyBatch,
    DuplicateType,
    PreparationLimit,
    InvalidPacket,
}
#[derive(Debug)]
pub struct PrepareManagedBatchFailure {
    pub error: TryManagedBatchError,
    pub originals: Vec<Packet>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedBatchAccepted {
    pub queued_packets: usize,
}
struct ManagedItem {
    packet: Option<Packet>,
    meta: crate::MessageMeta,
    endpoints: Vec<crate::config::OwnedEndpointDefinition>,
    sender_address: u32,
    cost: usize,
    priority: u8,
    untracked_disposable: bool,
}
pub struct PreparedManagedBatch<'a> {
    router: &'a Router,
    items: Vec<ManagedItem>,
    costs: Vec<usize>,
    total_cost: usize,
    limits: ManagedBatchPreparationLimits,
    age_anchor_ms: u64,
    registration_epoch: u64,
    cache_epoch: u64,
    // After success these hold OLD live maps, never dropped during commit.
    replacement_types: BTreeSet<u32>,
    replacement_latest: BTreeMap<u32, Box<ManagedVariableCacheEntry>>,
    adds_registration: bool,
    admitted: bool,
}
impl PreparedManagedBatch<'_> {
    pub fn into_packets(self) -> Option<Vec<Packet>> {
        if self.admitted {
            return None;
        }
        Some(
            self.items
                .into_iter()
                .map(|item| item.packet.expect("unadmitted original"))
                .collect(),
        )
    }
}
impl Router {
    #[allow(clippy::result_large_err)]
    pub fn prepare_network_variable_batch(
        &self,
        mut originals: Vec<Packet>,
        limits: ManagedBatchPreparationLimits,
    ) -> Result<PreparedManagedBatch<'_>, PrepareManagedBatchFailure> {
        let fail = |error, originals| Err(PrepareManagedBatchFailure { error, originals });
        if !self.cfg.role.local_services() {
            return fail(TryManagedBatchError::OriginNotAllowed, originals);
        }
        if originals.is_empty() {
            return fail(TryManagedBatchError::EmptyBatch, originals);
        }
        if originals.len() > limits.max_batch_packets
            || originals
                .iter()
                .try_fold(0usize, |n, p| n.checked_add(p.payload().len()))
                .is_none_or(|n| n > limits.max_original_payload_bytes)
        {
            return fail(TryManagedBatchError::PreparationLimit, originals);
        }
        for (i, packet) in originals.iter().enumerate() {
            if is_internal_control_type(packet.data_type()) || packet.validate().is_err() {
                return fail(TryManagedBatchError::InvalidPacket, originals);
            }
            if originals[..i]
                .iter()
                .any(|old| old.data_type() == packet.data_type())
            {
                return fail(TryManagedBatchError::DuplicateType, originals);
            }
        }
        let mut descriptors = Vec::with_capacity(originals.len());
        for packet in &mut originals {
            let Some(meta) = crate::config::try_get_message_meta(packet.data_type()) else {
                return fail(TryManagedBatchError::InvalidPacket, originals);
            };
            if packet.endpoints().is_empty()
                || packet.payload().len() != packet.data_size()
                || Packet::validate_payload_against_element(
                    packet.wire_shape().unwrap_or(meta.element),
                    packet.payload(),
                )
                .is_err()
            {
                return fail(TryManagedBatchError::InvalidPacket, originals);
            }
            let endpoints = packet
                .endpoints()
                .iter()
                .map(|ep| crate::config::endpoint_definition(*ep))
                .collect::<Option<Vec<_>>>();
            let Some(endpoints) = endpoints else {
                return fail(TryManagedBatchError::InvalidPacket, originals);
            };
            #[cfg(feature = "compact-packet-store")]
            if packet.park_for_queue().is_err() {
                return fail(TryManagedBatchError::Capacity, originals);
            }
            let sender_address = packet
                .sender()
                .strip_prefix("@addr:")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| sender_address_u32(packet.sender()));
            let cost = packet
                .queue_byte_cost_saturated()
                .saturating_add(size_of::<bool>())
                .saturating_add(size_of::<u8>())
                .saturating_add(2usize.saturating_mul(size_of::<u64>()));
            descriptors.push((meta, endpoints, sender_address, cost));
        }
        // Provider invocation is outside Core and all application guards.
        let age_anchor_ms = self.clock.now_ms();
        let items = originals
            .into_iter()
            .zip(descriptors)
            .map(|(packet, (meta, endpoints, sender_address, cost))| {
                let untracked_disposable = packet.wire_target_senders().is_empty();
                ManagedItem {
                    packet: Some(packet),
                    meta,
                    endpoints,
                    sender_address,
                    cost,
                    priority: 254,
                    untracked_disposable,
                }
            })
            .collect::<Vec<_>>();
        let costs = items.iter().map(|i| i.cost).collect::<Vec<_>>();
        let total_cost = costs.iter().copied().fold(0usize, usize::saturating_add);
        let mut prepared = PreparedManagedBatch {
            router: self,
            items,
            costs,
            total_cost,
            limits,
            age_anchor_ms,
            registration_epoch: 0,
            cache_epoch: 0,
            replacement_types: BTreeSet::new(),
            replacement_latest: BTreeMap::new(),
            adds_registration: false,
            admitted: false,
        };
        if let Err(error) = self.refresh_managed_snapshot(&mut prepared, true) {
            return Err(PrepareManagedBatchFailure {
                error,
                originals: prepared.into_packets().expect("unadmitted"),
            });
        }
        Ok(prepared)
    }

    /// May allocate/wait; caller must run OUTSIDE every application guard.
    /// Preserves original packets, source time, initial age anchor and registry
    /// authority through commit. Ordinary dispatch/receipt may subsequently
    /// refresh local cache observation age; original source time is unchanged.
    /// It cannot rebind a revoked/restored registration or a caller deadline.
    pub fn refresh_network_variable_batch_cache_snapshot(
        &self,
        prepared: &mut PreparedManagedBatch<'_>,
    ) -> Result<(), TryManagedBatchError> {
        self.refresh_managed_snapshot(prepared, false)
    }

    fn refresh_managed_snapshot(
        &self,
        prepared: &mut PreparedManagedBatch<'_>,
        initial: bool,
    ) -> Result<(), TryManagedBatchError> {
        if prepared.admitted {
            return Err(TryManagedBatchError::AlreadyAdmitted);
        }
        if !core::ptr::eq(self, prepared.router) {
            return Err(TryManagedBatchError::WrongRouter);
        }
        let (registration_epoch, cache_epoch, mut types, mut latest) = {
            let st = self.state.lock();
            let local = st
                .local_services
                .as_ref()
                .ok_or(TryManagedBatchError::OriginNotAllowed)?;
            if local.managed_registration_epoch == u64::MAX || local.managed_cache_epoch == u64::MAX
            {
                return Err(TryManagedBatchError::EpochExhausted);
            }
            if !initial && local.managed_registration_epoch != prepared.registration_epoch {
                return Err(TryManagedBatchError::RegistrationChanged);
            }
            if local
                .managed_variable_types
                .len()
                .saturating_add(prepared.items.len())
                > prepared.limits.max_snapshot_types
                || local
                    .managed_variable_latest
                    .len()
                    .saturating_add(prepared.items.len())
                    > prepared.limits.max_snapshot_entries
            {
                return Err(TryManagedBatchError::PreparationLimit);
            }
            let existing_bytes = local
                .managed_variable_latest
                .values()
                .map(|e| e.packet.queue_byte_cost_saturated())
                .fold(0usize, usize::saturating_add);
            if existing_bytes.saturating_add(prepared.total_cost)
                > prepared.limits.max_snapshot_logical_bytes
            {
                return Err(TryManagedBatchError::PreparationLimit);
            }
            if prepared.items.iter().any(|i| {
                !Self::managed_variable_permissions_locked(
                    &st,
                    i.packet.as_ref().unwrap().data_type(),
                )
                .write
            }) {
                return Err(TryManagedBatchError::OriginNotAllowed);
            }
            (
                local.managed_registration_epoch,
                local.managed_cache_epoch,
                local.managed_variable_types.clone(),
                local.managed_variable_latest.clone(),
            )
        };
        #[cfg(not(feature = "discovery"))]
        let _ = prepared.age_anchor_ms;
        let mut adds_registration = false;
        for item in &prepared.items {
            let packet = item.packet.as_ref().expect("unadmitted");
            let key = packet.data_type().as_u32();
            let old = latest.get(&key);
            if old.is_some_and(|e| {
                e.sender_address == item.sender_address && packet.timestamp() < e.packet.timestamp()
            }) {
                return Err(TryManagedBatchError::OriginalValueObsolete);
            }
            #[cfg(feature = "discovery")]
            let upstream = old
                .filter(|e| e.packet.packet_id() == packet.packet_id())
                .and_then(|e| e.upstream);
            latest.insert(
                key,
                Box::new(ManagedVariableCacheEntry {
                    packet: packet.clone(),
                    sender_address: item.sender_address,
                    #[cfg(feature = "discovery")]
                    cached_at_ms: prepared.age_anchor_ms,
                    #[cfg(feature = "discovery")]
                    upstream,
                }),
            );
            adds_registration |= types.insert(key);
        }
        prepared.replacement_types = types;
        prepared.replacement_latest = latest;
        prepared.registration_epoch = registration_epoch;
        prepared.cache_epoch = cache_epoch;
        prepared.adds_registration = adds_registration;
        Ok(())
    }

    /// Tries only Core/Schema. Atomic all-cache + all-queued ownership, no
    /// first-value allocation, callbacks, providers, clock reads or old drops.
    /// Refusal has no effects; all originals remain caller-owned. Drop/retire
    /// `prepared` only AFTER releasing application admission guards.
    pub fn try_commit_network_variable_batch_unless_pending_type(
        &self,
        prepared: &mut PreparedManagedBatch<'_>,
        blocked: DataType,
    ) -> Result<ManagedBatchAccepted, TryManagedBatchError> {
        if prepared.admitted {
            return Err(TryManagedBatchError::AlreadyAdmitted);
        }
        if !core::ptr::eq(self, prepared.router) {
            return Err(TryManagedBatchError::WrongRouter);
        }
        if !self.cfg.role.local_services() {
            return Err(TryManagedBatchError::OriginNotAllowed);
        }
        let mut st = self
            .state
            .try_lock()
            .ok_or(TryManagedBatchError::CoreBusy)?;
        if self.pending_reliable_tx_type_locked(&st, blocked) {
            return Err(TryManagedBatchError::BlockedPendingReliableType);
        }
        let schema =
            crate::config::try_prepared_schema_guard().ok_or(TryManagedBatchError::SchemaBusy)?;
        let local = st
            .local_services
            .as_ref()
            .ok_or(TryManagedBatchError::OriginNotAllowed)?;
        if local.managed_registration_epoch == u64::MAX || local.managed_cache_epoch == u64::MAX {
            return Err(TryManagedBatchError::EpochExhausted);
        }
        if local.managed_registration_epoch != prepared.registration_epoch {
            return Err(TryManagedBatchError::RegistrationChanged);
        }
        if local.managed_cache_epoch != prepared.cache_epoch {
            return Err(TryManagedBatchError::CacheSnapshotChanged);
        }
        let next_cache = local
            .managed_cache_epoch
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(TryManagedBatchError::EpochExhausted)?;
        let next_registration = if prepared.adds_registration {
            local
                .managed_registration_epoch
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .ok_or(TryManagedBatchError::EpochExhausted)?
        } else {
            local.managed_registration_epoch
        };
        #[cfg(feature = "discovery")]
        let next_p2p = if prepared.adds_registration {
            st.p2p_revision
                .checked_add(2)
                .filter(|n| *n < u64::MAX)
                .ok_or(TryManagedBatchError::EpochExhausted)?
                - 1
        } else {
            st.p2p_revision
        };
        for item in &prepared.items {
            let packet = item.packet.as_ref().expect("unadmitted");
            if !schema.matches(packet.data_type(), &item.meta)
                || !item
                    .endpoints
                    .iter()
                    .all(|ep| schema.matches_managed_endpoint(ep))
            {
                return Err(TryManagedBatchError::SchemaChanged);
            }
            if !Self::managed_variable_permissions_locked(&st, packet.data_type()).write {
                return Err(TryManagedBatchError::RegistrationChanged);
            }
        }
        let used = st.queued_packet_budget_used(&schema);
        if used == usize::MAX
            || prepared.total_cost == usize::MAX
            || used
                .checked_add(prepared.total_cost)
                .is_none_or(|n| n > st.memory.max_queue_budget)
            || !st.transmit_queue.fits_prepared_batch(&prepared.costs)
        {
            return Err(TryManagedBatchError::Capacity);
        }
        // No fallible work after this boundary. Priority inheritance observes
        // the current queue under the same owner; batch types are distinct.
        for item in &mut prepared.items {
            let ty = item.packet.as_ref().unwrap().data_type();
            item.priority = if item.meta.reliable == crate::ReliableMode::Ordered {
                st.transmit_queue
                    .iter()
                    .find_map(|q| {
                        (RouterInner::ordered_original_type(q).is_some()
                            && q.accepted_type == ty.as_u32())
                        .then_some(q.priority)
                    })
                    .unwrap_or(254)
            } else {
                254
            };
        }
        let local = st.local_services.as_mut().expect("checked local services");
        core::mem::swap(
            &mut local.managed_variable_types,
            &mut prepared.replacement_types,
        );
        core::mem::swap(
            &mut local.managed_variable_latest,
            &mut prepared.replacement_latest,
        );
        local.managed_cache_epoch = next_cache;
        local.managed_registration_epoch = next_registration;
        #[cfg(feature = "discovery")]
        if prepared.adds_registration {
            local.managed_registration_dirty = true;
            st.p2p_revision = next_p2p;
        }
        for item in &mut prepared.items {
            let packet = item.packet.take().expect("checked original owner");
            let ty = packet.data_type();
            let mut delivery = match item.meta.reliable {
                crate::ReliableMode::Ordered => QueuedDelivery::Ordered,
                crate::ReliableMode::Unordered => QueuedDelivery::Unordered,
                crate::ReliableMode::None => QueuedDelivery::Untracked,
            };
            if delivery == QueuedDelivery::Ordered
                && st.transmit_queue.iter().any(|q| {
                    RouterInner::ordered_original_type(q).is_some()
                        && q.accepted_type == ty.as_u32()
                })
            {
                delivery = QueuedDelivery::OrderedTail;
            }
            let queued = TxQueued {
                disposable: u8::from(
                    delivery == QueuedDelivery::Untracked && item.untracked_disposable,
                ),
                item: RouterTxItem::Broadcast(RouterItem::Packet(packet)),
                ignore_local: false,
                priority: item.priority,
                delivery_state: delivery,
                accepted_type: ty.as_u32(),
                deferred_since_ms: 0,
                retry_after_ms: 0,
            };
            st.transmit_queue
                .push_prepared_batch_item(queued, item.cost, item.priority, |q| q.priority);
        }
        prepared.admitted = true;
        Ok(ManagedBatchAccepted {
            queued_packets: prepared.items.len(),
        })
    }
}

#[cfg(test)]
#[path = "router_prepared_managed_tests.rs"]
mod tests;
