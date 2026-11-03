//! Caller-owned queued Packet preparation with atomic pending-type admission.
//! Preparation may wait/allocate. Commit only tries SDK locks; no clock,
//! provider or application/transport callback runs here. This is not realtime.
use super::*;
use crate::MessageDataType;

#[path = "router_queue_accounting.rs"]
mod accounting;

#[derive(Debug)]
pub struct PrepareQueuedPacketFailure {
    pub error: TelemetryError,
    pub packet: Packet,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryPendingTypeError {
    CoreBusy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryQueuedPacketError {
    CoreBusy,
    SchemaBusy,
    BlockedPendingReliableType,
    Capacity,
    StalePreparation,
    AlreadyAdmitted,
    OriginNotAllowed,
}
/// Unadmitted packets remain caller-owned, including after every refusal.
/// `AlreadyAdmitted` does not undo the earlier successful SDK ownership.
pub struct PreparedQueuedPacket<'a> {
    router: &'a Router,
    packet: Option<Packet>,
    meta: crate::MessageMeta,
    ty: DataType,
    priority: u8,
    cost: usize,
    untracked_disposable: bool,
}
impl PreparedQueuedPacket<'_> {
    /// Recover the exact original Packet if it has not been admitted.
    pub fn into_packet(self) -> Option<Packet> {
        self.packet
    }
}
impl Router {
    /// Nonwaiting conservative ownership inspection. Busy is not clear.
    /// A momentary proof only: use the atomic queue API for queue admission.
    pub fn try_has_pending_reliable_tx_type(
        &self,
        ty: DataType,
    ) -> Result<bool, TryPendingTypeError> {
        let st = self.state.try_lock().ok_or(TryPendingTypeError::CoreBusy)?;
        Ok(self.pending_reliable_tx_type_locked(&st, ty))
    }

    /// Prepare outside application admission guards. No queue, transport,
    /// reliable sequence, clock or P2P session effects. Errors return the Packet.
    // Returning the original Packet inline is the ownership contract. Boxing
    // an error would allocate merely to report a refused preparation.
    #[allow(clippy::result_large_err)]
    #[allow(unused_mut)]
    pub fn prepare_tx_queue(
        &self,
        mut packet: Packet,
    ) -> Result<PreparedQueuedPacket<'_>, PrepareQueuedPacketFailure> {
        if let Err(error) = self.ensure_application_origin_allowed() {
            return Err(PrepareQueuedPacketFailure { error, packet });
        }
        let ty = packet.data_type();
        let Some(meta) = crate::config::try_get_message_meta(ty) else {
            return Err(PrepareQueuedPacketFailure {
                error: TelemetryError::BadArg,
                packet,
            });
        };
        // Derive priority directly from the captured schema. Calling the
        // public schema helpers here could mix snapshots during schema change.
        let priority = match ty {
            DataType::ReliableAck
            | DataType::ReliablePartialAck
            | DataType::ReliablePacketRequest
            | DataType::DiscoveryAnnounce
            | DataType::DiscoveryTimeSyncSources
            | DataType::DiscoveryTopology
            | DataType::DiscoveryTopologyRequest
            | DataType::DiscoveryLeave
            | DataType::DiscoveryLinkCapabilities
            | DataType::DiscoveryAddress => 255,
            DataType::DiscoverySchema
            | DataType::DiscoverySchemaRequest
            | DataType::ManagedVariableRequest
            | DataType::ManagedVariableValue
            | DataType::TimeSyncAnnounce
            | DataType::TimeSyncRequest
            | DataType::TimeSyncResponse => 254,
            _ => meta.priority.min(253),
        };
        let small_control = packet.payload().len() <= 16
            && packet.endpoints().len() <= 3
            && (1..=3).contains(&packet.wire_target_senders().len())
            && matches!(
                meta.element,
                MessageElement::Static(0..=16, MessageDataType::UInt8, _)
            )
            && matches!(
                packet.wire_shape(),
                None | Some(MessageElement::Static(0..=16, MessageDataType::UInt8, _))
            );
        let priority = if small_control {
            priority.max(254)
        } else {
            priority
        };
        let untracked_disposable = is_internal_control_type(ty)
            || (meta.reliable == crate::ReliableMode::None
                && packet.wire_target_senders().is_empty());
        #[cfg(feature = "compact-packet-store")]
        if let Err(error) = packet.park_for_queue() {
            return Err(PrepareQueuedPacketFailure { error, packet });
        }
        // Match TxQueued::byte_cost, saturating every component conservatively.
        let cost = packet
            .queue_byte_cost_saturated()
            .saturating_add(size_of::<bool>())
            .saturating_add(size_of::<u8>())
            .saturating_add(2usize.saturating_mul(size_of::<u64>()));
        Ok(PreparedQueuedPacket {
            router: self,
            packet: Some(packet),
            meta,
            ty,
            priority,
            cost,
            untracked_disposable,
        })
    }

    /// Atomically inspect existing reliable-type ownership and queue one Packet.
    /// No SDK mutex waits, clock/provider calls or callbacks. No growth/eviction.
    /// Refusals preserve the unadmitted original Packet and every existing owner.
    /// Ok transfers local SDK ownership once; it is not peer delivery/completion.
    pub fn try_tx_queue_unless_pending_reliable_type(
        &self,
        prepared: &mut PreparedQueuedPacket<'_>,
        blocked: DataType,
    ) -> Result<(), TryQueuedPacketError> {
        if prepared.packet.is_none() {
            return Err(TryQueuedPacketError::AlreadyAdmitted);
        }
        if !self.cfg.role.local_services() {
            return Err(TryQueuedPacketError::OriginNotAllowed);
        }
        if !core::ptr::eq(self, prepared.router) {
            return Err(TryQueuedPacketError::StalePreparation);
        }
        let mut st = self
            .state
            .try_lock()
            .ok_or(TryQueuedPacketError::CoreBusy)?;
        if self.pending_reliable_tx_type_locked(&st, blocked) {
            return Err(TryQueuedPacketError::BlockedPendingReliableType);
        }
        let schema =
            crate::config::try_prepared_schema_guard().ok_or(TryQueuedPacketError::SchemaBusy)?;
        if !schema.matches(prepared.ty, &prepared.meta) {
            return Err(TryQueuedPacketError::StalePreparation);
        }
        let used = st.queued_packet_budget_used(&schema);
        if used == usize::MAX
            || prepared.cost == usize::MAX
            || used
                .checked_add(prepared.cost)
                .is_none_or(|n| n > st.memory.max_queue_budget)
            || !st.transmit_queue.fits_prepared_batch(&[prepared.cost])
        {
            return Err(TryQueuedPacketError::Capacity);
        }
        let mut priority = if st.is_managed_variable(prepared.ty.as_u32()) {
            254
        } else {
            prepared.priority
        };
        let mut delivery = match prepared.meta.reliable {
            crate::ReliableMode::Ordered => QueuedDelivery::Ordered,
            crate::ReliableMode::Unordered => QueuedDelivery::Unordered,
            crate::ReliableMode::None => QueuedDelivery::Untracked,
        };
        if delivery == QueuedDelivery::Ordered
            && let Some(old_priority) = st.transmit_queue.iter().find_map(|q| {
                (RouterInner::ordered_original_type(q).is_some()
                    && q.accepted_type == prepared.ty.as_u32())
                .then_some(q.priority)
            })
        {
            priority = old_priority;
            delivery = QueuedDelivery::OrderedTail;
        }
        let item = TxQueued {
            disposable: if delivery != QueuedDelivery::Untracked {
                0
            } else {
                u8::from(prepared.untracked_disposable)
            },
            item: RouterTxItem::Broadcast(RouterItem::Packet(
                prepared.packet.take().expect("checked unadmitted Packet"),
            )),
            ignore_local: false,
            priority,
            delivery_state: delivery,
            accepted_type: prepared.ty.as_u32(),
            deferred_since_ms: 0,
            retry_after_ms: 0,
        };
        st.transmit_queue
            .push_prepared_batch_item(item, prepared.cost, priority, |q| q.priority);
        Ok(())
    }
}

#[cfg(test)]
#[path = "router_prepared_queue_tests.rs"]
mod tests;
