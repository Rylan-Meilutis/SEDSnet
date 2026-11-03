//! Hosted two-phase P2P admission. Preparation may block/allocate; admission
//! never waits for SDK mutexes and never calls a clock/provider/transport/user
//! handler. Allocator/deallocator latency (notably opening a BTreeMap session)
//! is not bounded: this is neither a realtime nor a lock-free API.
use super::*;

#[derive(Clone, Copy, Debug)]
pub enum P2pTarget<'a> {
    Hostname(&'a str),
    Address(NodeAddress),
}
#[derive(Clone, Copy, Debug)]
pub enum P2pStreamOperation<'a> {
    Data(&'a [u8]),
    Close,
    Reset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryP2pError {
    Busy,
    Stale,
    Capacity,
    AlreadyAdmitted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P2pAdmission {
    pub stream_id: P2pStreamId,
    pub sequence: u32,
    pub frames_queued: u8,
}

enum Action {
    Open(Option<P2pStreamSession>),
    Control { flags: u8, expected_sequence: u32 },
}
/// Opaque caller-owned preparation. No active protocol session, stream cursor,
/// sequence, queue, transport or handler is affected until successful admission.
/// Busy/Stale/Capacity leave all prepared buffers owned by this value. Drop it
/// outside the application's short guard. Never retry a revoked application
/// intent merely because this generic SDK plan can be prepared again.
pub struct PreparedP2p<'a> {
    router: &'a Router,
    local: AddressBookEntry,
    peer: AddressBookEntry,
    meta: crate::MessageMeta,
    revision: u64,
    stream_id: P2pStreamId,
    sequence: u32,
    action: Action,
    frames: [Option<RouterItem>; 2],
    costs: [usize; 2],
    count: usize,
    local_delivery: bool,
    admitted: bool,
    // Delay removed-session deallocation until caller drops outside its guard.
    retired: Option<P2pStreamSession>,
}
impl RouterInner {
    fn prepared_shared_queue_bytes_used(
        &self,
        schema: &crate::config::PreparedSchemaGuard,
    ) -> usize {
        self.queued_packet_budget_used(schema)
    }

    pub(super) fn invalidate_prepared_p2p(&mut self) {
        self.p2p_revision = self.p2p_revision.saturating_add(1);
    }
}
impl Router {
    fn prepared_p2p_target(st: &RouterInner, target: P2pTarget<'_>) -> Option<AddressBookEntry> {
        match target {
            P2pTarget::Hostname(name) => {
                if let Some(entry) = st.address_book.get(name) {
                    return Some(entry.as_ref().clone());
                }
                let address = sender_address_u32(name);
                if Self::hostname_for_address_locked(st, address).as_deref() != Some(name) {
                    return None;
                }
                Some(AddressBookEntry {
                    hostname: Arc::from(name),
                    address,
                    requested_address: 0,
                    mode: AddressAssignmentMode::Dynamic,
                    birth_ms: 0,
                    owner_hash: Self::sender_hash(name),
                    last_seen_ms: 0,
                })
            }
            P2pTarget::Address(address) => {
                if let Some(entry) = st
                    .address_by_value
                    .get(&address)
                    .and_then(|name| st.address_book.get(name))
                {
                    return Some(entry.as_ref().clone());
                }
                let name = Self::hostname_for_address_locked(st, address)?;
                Self::prepared_p2p_target(st, P2pTarget::Hostname(&name))
            }
        }
    }
    // Build only from the captured schema, including encryption policy. A
    // concurrent schema ABA cannot make packing silently use another policy.
    // Keep the captured wire inputs explicit; this private helper is not a policy callback.
    #[allow(clippy::too_many_arguments)]
    fn prepared_p2p_frame(
        &self,
        local: &AddressBookEntry,
        peer: &AddressBookEntry,
        meta: &crate::MessageMeta,
        ports: (P2pPort, P2pPort),
        timestamp: u64,
        stream: crate::SharedBytes,
        budget: usize,
    ) -> TelemetryResult<RouterItem> {
        let outer = Self::encode_p2p_payload(
            &local.hostname,
            local.address,
            ports.0,
            ports.1,
            stream.as_ref(),
        )?;
        let target = Self::sender_hash(&peer.hostname);
        let packet = Packet::new_with_owned_wire_contract(
            DataType::P2pMessage,
            Arc::from([DataEndpoint::Discovery]),
            local.hostname.clone(),
            timestamp,
            crate::packet::next_packet_nonce(),
            crate::config::StandardSmallPayload::from_arc(crate::shared_bytes::convert(outer)),
            Some(meta.element),
            Some(Arc::from([target])),
        )?;
        let reliable = (!matches!(meta.reliable, crate::ReliableMode::None)).then_some(
            wire_format::ReliableHeader {
                flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
                seq: 0,
                ack: 0,
            },
        );
        let require_crypto = match self.cfg.e2e_encryption() {
            RouterE2eEncryptionMode::Disabled | RouterE2eEncryptionMode::RequiredOnly => {
                meta.e2e_encryption == E2eEncryptionPolicy::RequireOn
            }
            RouterE2eEncryptionMode::Preferred => matches!(
                meta.e2e_encryption,
                E2eEncryptionPolicy::PreferOn | E2eEncryptionPolicy::RequireOn
            ),
            RouterE2eEncryptionMode::ForceAll => true,
        };
        if require_crypto && !self.e2e_crypto_supported() {
            return Err(TelemetryError::BadArg);
        }
        #[cfg(feature = "cryptography")]
        let seal = require_crypto.then_some(wire_format::E2eSealConfig {
            key_id: self.cfg.e2e_key_id(),
        });
        #[cfg(not(feature = "cryptography"))]
        let seal: Option<wire_format::E2eSealConfig> = None;
        #[cfg(feature = "compression")]
        let bytes = wire_format::pack_routed_packet(
            &packet,
            reliable,
            Some(meta.element),
            &[target],
            seal,
        )?;
        #[cfg(not(feature = "compression"))]
        let bytes = {
            #[cfg(feature = "cryptography")]
            if let Some(seal) = seal {
                wire_format::pack_packet_with_wire_contract_e2e(
                    &packet,
                    reliable,
                    Some(meta.element),
                    &[target],
                    seal,
                )?
            } else {
                wire_format::pack_packet_with_wire_contract(
                    &packet,
                    reliable,
                    Some(meta.element),
                    &[target],
                )?
            }
            #[cfg(not(feature = "cryptography"))]
            {
                let _ = seal;
                wire_format::pack_packet_with_wire_contract(
                    &packet,
                    reliable,
                    Some(meta.element),
                    &[target],
                )?
            }
        };
        let bytes: crate::SharedBytes = crate::shared_bytes::convert(bytes);
        #[cfg(feature = "compression")]
        let bytes = match wire_format::payload_encoding_for_retention(bytes.as_ref(), budget)? {
            Some(raw) => crate::shared_bytes::convert(raw),
            None => bytes,
        };
        #[cfg(not(feature = "compression"))]
        let _ = budget;
        let item = RouterItem::Packed(bytes);
        #[cfg(feature = "compact-packet-store")]
        let item = {
            let mut item = item;
            item.park_for_queue()?;
            item
        };
        Ok(item)
    }
    // Captured protocol/identity inputs remain explicit through preparation.
    #[allow(clippy::too_many_arguments)]
    fn finish_p2p_preparation<'a>(
        &'a self,
        local: AddressBookEntry,
        peer: AddressBookEntry,
        meta: crate::MessageMeta,
        revision: u64,
        stream_id: u32,
        sequence: u32,
        action: Action,
        ports: (u16, u16),
        payloads: [Option<crate::SharedBytes>; 2],
        timestamp: u64,
        budget: usize,
    ) -> TelemetryResult<PreparedP2p<'a>> {
        let local_delivery = local.hostname == peer.hostname;
        let priority = meta.priority.min(253);
        let mut frames = [None, None];
        let mut costs = [0, 0];
        let mut count = 0;
        for payload in payloads.into_iter().flatten() {
            let frame =
                self.prepared_p2p_frame(&local, &peer, &meta, ports, timestamp, payload, budget)?;
            costs[count] = if local_delivery {
                RouterRxItem {
                    src: None,
                    data: frame.clone(),
                    priority,
                }
                .byte_cost()
            } else {
                TxQueued {
                    disposable: 0,
                    item: RouterTxItem::Broadcast(frame.clone()),
                    ignore_local: true,
                    priority,
                    delivery_state: QueuedDelivery::Untracked,
                    accepted_type: DataType::P2pMessage.as_u32(),
                    deferred_since_ms: 0,
                    retry_after_ms: 0,
                }
                .byte_cost()
            };
            frames[count] = Some(frame);
            count += 1;
        }
        Ok(PreparedP2p {
            router: self,
            local,
            peer,
            meta,
            revision,
            stream_id,
            sequence,
            action,
            frames,
            costs,
            count,
            local_delivery,
            admitted: false,
            retired: None,
        })
    }
    /// Preparation may wait, allocate and call a clock/crypto provider. It does
    /// not open an active session or publish anything. Explicit timestamps,
    /// including zero, are frozen exactly; no timestamp is sampled on admission.
    pub fn prepare_p2p_stream_open(
        &self,
        target: P2pTarget<'_>,
        peer_port: u16,
        local_port: u16,
        timestamp: Option<u64>,
    ) -> TelemetryResult<PreparedP2p<'_>> {
        self.ensure_application_origin_allowed()?;
        if peer_port == 0 || local_port == 0 {
            return Err(TelemetryError::BadArg);
        }
        let timestamp = timestamp.unwrap_or_else(|| self.packet_timestamp_ms());
        let meta = message_meta(DataType::P2pMessage);
        let (local, peer, revision, id, budget, peer_address_bound) = {
            let st = self.state.lock();
            if st.p2p_revision == u64::MAX {
                return Err(TelemetryError::Io("p2p revision exhausted"));
            }
            let peer = Self::prepared_p2p_target(&st, target).ok_or(TelemetryError::BadArg)?;
            let peer_address_bound = Self::p2p_target_address_bound_locked(&st, &peer)
                .ok_or(TelemetryError::Io("p2p target identity changed"))?;
            let services = st
                .local_services
                .as_ref()
                .ok_or(TelemetryError::PermissionDenied)?;
            let mut id = services.next_p2p_stream_id.max(1);
            let first = id;
            while services.p2p_stream_sessions.contains_key(&id) {
                id = id.wrapping_add(1).max(1);
                if id == first {
                    return Err(TelemetryError::Io("p2p stream id exhausted"));
                }
            }
            (
                st.local_address.clone(),
                peer,
                st.p2p_revision,
                id,
                st.memory.max_queue_budget,
                peer_address_bound,
            )
        };
        let session = P2pStreamSession {
            peer_hostname: peer.hostname.clone(),
            peer_address: peer.address,
            local_port,
            peer_port,
            peer_stream_id: 0,
            next_sequence: 1,
            connected: false,
            peer_address_bound,
        };
        let syn = Self::encode_p2p_stream_payload(P2P_STREAM_SYN, id, 0, 0, &[])?;
        self.finish_p2p_preparation(
            local,
            peer,
            meta,
            revision,
            id,
            0,
            Action::Open(Some(session)),
            (local_port, peer_port),
            [Some(syn), None],
            timestamp,
            budget,
        )
    }
    /// Prepare DATA/FIN/RST. A required refresh SYN and control/data frame form
    /// one atomic local admission batch; network delivery remains asynchronous.
    pub fn prepare_p2p_stream_control(
        &self,
        id: u32,
        operation: P2pStreamOperation<'_>,
        timestamp: Option<u64>,
    ) -> TelemetryResult<PreparedP2p<'_>> {
        self.ensure_application_origin_allowed()?;
        let timestamp = timestamp.unwrap_or_else(|| self.packet_timestamp_ms());
        let meta = message_meta(DataType::P2pMessage);
        let (local, peer, session, revision, budget) = {
            let st = self.state.lock();
            if st.p2p_revision == u64::MAX {
                return Err(TelemetryError::Io("p2p revision exhausted"));
            }
            let session = st
                .local_services
                .as_ref()
                .and_then(|s| s.p2p_stream_sessions.get(&id))
                .ok_or(TelemetryError::BadArg)?
                .clone();
            let peer = Self::prepared_p2p_target(&st, P2pTarget::Hostname(&session.peer_hostname))
                .ok_or(TelemetryError::BadArg)?;
            // Topology-only routing entries carry a compact hostname hash,
            // not the assigned source address learned from the handshake.
            if session.peer_address_bound
                && st
                    .address_book
                    .get(session.peer_hostname.as_ref())
                    .is_some_and(|assigned| assigned.address != session.peer_address)
            {
                return Err(TelemetryError::Io("p2p peer identity changed"));
            }
            (
                st.local_address.clone(),
                peer,
                session,
                st.p2p_revision,
                st.memory.max_queue_budget,
            )
        };
        let (flags, payload) = match operation {
            P2pStreamOperation::Data(data) => (P2P_STREAM_DATA, data),
            P2pStreamOperation::Close => (P2P_STREAM_FIN, &[][..]),
            P2pStreamOperation::Reset => (P2P_STREAM_RST, &[][..]),
        };
        let frame = Self::encode_p2p_stream_payload(
            flags,
            id,
            session.peer_stream_id,
            session.next_sequence,
            payload,
        )?;
        let syn = if session.peer_stream_id == 0 {
            Some(Self::encode_p2p_stream_payload(
                P2P_STREAM_SYN,
                id,
                0,
                0,
                &[],
            )?)
        } else {
            None
        };
        let payloads = if let Some(syn) = syn {
            [Some(syn), Some(frame)]
        } else {
            [Some(frame), None]
        };
        self.finish_p2p_preparation(
            local,
            peer,
            meta,
            revision,
            id,
            session.next_sequence,
            Action::Control {
                flags,
                expected_sequence: session.next_sequence,
            },
            (session.local_port, session.peer_port),
            payloads,
            timestamp,
            budget,
        )
    }
    /// No SDK mutex wait or callback/clock/provider. Busy/Stale/Capacity have
    /// zero protocol effects and keep caller buffers. Successful queue ownership
    /// is not peer delivery/completion. BTreeMap allocation may occur on open;
    /// allocator latency is NOT bounded. Drop preparation outside caller guards.
    pub fn try_queue_prepared_p2p(
        &self,
        prepared: &mut PreparedP2p<'_>,
    ) -> Result<P2pAdmission, TryP2pError> {
        if prepared.admitted {
            return Err(TryP2pError::AlreadyAdmitted);
        }
        if !core::ptr::eq(self, prepared.router) || !self.cfg.role.local_services() {
            return Err(TryP2pError::Stale);
        }
        let mut st = self.state.try_lock().ok_or(TryP2pError::Busy)?;
        let schema = crate::config::try_prepared_schema_guard().ok_or(TryP2pError::Busy)?;
        if st.p2p_revision == u64::MAX
            || st.p2p_revision != prepared.revision
            || st.local_address != prepared.local
            || !schema.matches(DataType::P2pMessage, &prepared.meta)
        {
            return Err(TryP2pError::Stale);
        }
        // The revision covers address ingests; compare direct identity without
        // invoking resolution, allocating a hostname or sampling a clock here.
        if let Some(peer) = st.address_book.get(prepared.peer.hostname.as_ref())
            && peer.as_ref() != &prepared.peer
        {
            return Err(TryP2pError::Stale);
        }
        let services = st.local_services.as_ref().ok_or(TryP2pError::Stale)?;
        match &prepared.action {
            Action::Open(session) => {
                if session.is_none()
                    || services
                        .p2p_stream_sessions
                        .contains_key(&prepared.stream_id)
                {
                    return Err(TryP2pError::Stale);
                }
            }
            Action::Control {
                expected_sequence, ..
            } => {
                if services
                    .p2p_stream_sessions
                    .get(&prepared.stream_id)
                    .is_none_or(|s| s.next_sequence != *expected_sequence)
                {
                    return Err(TryP2pError::Stale);
                }
            }
        }
        let costs = &prepared.costs[..prepared.count];
        let total = costs
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(*c))
            .ok_or(TryP2pError::Capacity)?;
        if st
            .prepared_shared_queue_bytes_used(&schema)
            .checked_add(total)
            .is_none_or(|n| n > st.memory.max_queue_budget)
            || !(if prepared.local_delivery {
                st.received_queue.fits_prepared_batch(costs)
            } else {
                st.transmit_queue.fits_prepared_batch(costs)
            })
        {
            return Err(TryP2pError::Capacity);
        }
        let mut priority = prepared.meta.priority.min(253);
        let mut delivery = match prepared.meta.reliable {
            crate::ReliableMode::Ordered => QueuedDelivery::Ordered,
            crate::ReliableMode::Unordered => QueuedDelivery::Unordered,
            crate::ReliableMode::None => QueuedDelivery::Untracked,
        };
        if !prepared.local_delivery
            && delivery == QueuedDelivery::Ordered
            && let Some(old) = st.transmit_queue.iter().find_map(|q| {
                (RouterInner::ordered_original_type(q) == Some(DataType::P2pMessage))
                    .then_some(q.priority)
            })
        {
            priority = old;
            delivery = QueuedDelivery::OrderedTail;
        }
        // All fallible checks end above. Same core+schema guards span map,
        // sequence/cursor and complete queue batch commit. No eviction/growth.
        let services = st.local_services.as_mut().expect("validated services");
        match &mut prepared.action {
            Action::Open(session) => {
                services
                    .p2p_stream_sessions
                    .insert(prepared.stream_id, session.take().expect("unadmitted open"));
                services.next_p2p_stream_id = prepared.stream_id.wrapping_add(1).max(1);
            }
            Action::Control { flags, .. } => {
                if *flags & (P2P_STREAM_FIN | P2P_STREAM_RST) != 0 {
                    prepared.retired = services.p2p_stream_sessions.remove(&prepared.stream_id);
                } else {
                    let session = services
                        .p2p_stream_sessions
                        .get_mut(&prepared.stream_id)
                        .expect("validated session");
                    session.next_sequence = session.next_sequence.wrapping_add(1).max(1);
                }
            }
        }
        for n in 0..prepared.count {
            let data = prepared.frames[n].take().expect("prepared frame");
            if prepared.local_delivery {
                st.received_queue.push_prepared_batch_item(
                    RouterRxItem {
                        src: None,
                        data,
                        priority,
                    },
                    prepared.costs[n],
                    priority,
                    |q| q.priority,
                );
            } else {
                st.transmit_queue.push_prepared_batch_item(
                    TxQueued {
                        disposable: if delivery == QueuedDelivery::Untracked {
                            TX_DISPOSABLE
                        } else {
                            0
                        },
                        item: RouterTxItem::Broadcast(data),
                        ignore_local: true,
                        priority,
                        delivery_state: delivery,
                        accepted_type: DataType::P2pMessage.as_u32(),
                        deferred_since_ms: 0,
                        retry_after_ms: 0,
                    },
                    prepared.costs[n],
                    priority,
                    |q| q.priority,
                );
            }
        }
        st.invalidate_prepared_p2p();
        prepared.admitted = true;
        Ok(P2pAdmission {
            stream_id: prepared.stream_id,
            sequence: prepared.sequence,
            frames_queued: prepared.count as u8,
        })
    }
}

#[cfg(test)]
#[path = "router_prepared_p2p_tests.rs"]
mod tests;
