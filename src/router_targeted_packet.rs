//! Read-only preparation of an existing wire-format recipient contract.
use super::*;

/// Maximum recipient count accepted by [`Router::prepare_targeted_packet`].
/// This preparation-only bound changes neither router capacities nor wire format.
pub const MAX_PREPARED_TARGET_RECIPIENTS: usize = u16::MAX as usize;

/// A retained logical hostname and its existing wire-target symbol.
///
/// This snapshot is not freshness, authentication, physical incarnation, or
/// delivery evidence. Topology-only names have no assigned-address identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenRecipient {
    hostname: Arc<str>,
    wire_target_symbol: u64,
    assigned_address: Option<u32>,
    birth_ms: Option<u64>,
    owner_hash: Option<u64>,
}
impl FrozenRecipient {
    /// Exact retained canonical hostname, never an unresolved numeric alias.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    /// Existing 64-bit wire-contract symbol. This is neither the compact
    /// 32-bit source address nor an assigned node address or authentication ID.
    pub fn wire_target_symbol(&self) -> u64 {
        self.wire_target_symbol
    }
    /// Assigned node address, only when a real address-book record was present.
    pub fn assigned_address(&self) -> Option<u32> {
        self.assigned_address
    }
    /// Address-book birth metadata; absent for topology-only names.
    pub fn birth_ms(&self) -> Option<u64> {
        self.birth_ms
    }
    /// Address-book owner metadata; absent for topology-only names. Not authority.
    pub fn owner_hash(&self) -> Option<u64> {
        self.owner_hash
    }
}

/// Caller-owned, unadmitted packet with immutable logical recipient metadata.
///
/// No Router/Session authority is granted or retained. A caller requiring an
/// original router or physical receiver must retain and validate that context.
#[derive(Debug)]
pub struct FrozenTargetPacket {
    packet: Packet,
    recipients: Arc<[FrozenRecipient]>,
}
impl FrozenTargetPacket {
    /// Borrow the exact packet carrying the frozen wire contract.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }
    /// Recipient snapshots in the caller's requested order.
    pub fn recipients(&self) -> &[FrozenRecipient] {
        &self.recipients
    }
    /// Recover the packet and immutable recipient snapshot without admission.
    pub fn into_parts(self) -> (Packet, Arc<[FrozenRecipient]>) {
        (self.packet, self.recipients)
    }
    /// Recover the packet without enqueueing or sending it.
    pub fn into_packet(self) -> Packet {
        self.packet
    }
}

/// Preparation refusal; every refusal retains the original, unmodified packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareTargetedPacketErrorKind {
    /// Empty cohort or empty/noncanonical name (including numeric aliases).
    InvalidRecipients,
    /// The preparation-only recipient bound or allocation-size bound was exceeded.
    TooManyRecipients,
    /// A requested name or wire symbol was repeated.
    DuplicateRecipient,
    /// No retained address-book/topology evidence names this recipient.
    UnknownRecipient,
    /// Different retained names collide in the wire-target namespace.
    AmbiguousRecipient,
    /// Existing frozen contract differs; it is never replaced, widened or narrowed.
    ConflictingContract,
    /// Unknown schema, malformed payload/endpoints, or unavailable payload storage.
    InvalidPacket,
    /// Router role does not permit application-origin packets, or type is internal.
    OriginNotAllowed,
    /// A fallible temporary-vector reservation failed.
    Capacity,
}
/// Typed refusal retaining ownership of the exact original packet.
#[derive(Debug)]
pub struct PrepareTargetedPacketError {
    kind: PrepareTargetedPacketErrorKind,
    packet: Packet,
}
impl PrepareTargetedPacketError {
    /// Typed refusal reason; it never implies delivery or physical identity.
    pub fn reason(&self) -> PrepareTargetedPacketErrorKind {
        self.kind
    }
    /// Recover the exact original packet after refusal.
    pub fn into_packet(self) -> Packet {
        self.packet
    }
}

impl Router {
    /// Freeze a caller-selected cohort of retained canonical logical hostnames.
    ///
    /// Preparation may wait for the router mutex and allocate; call it outside
    /// admission/IO guards. It reads one router-state snapshot without reading a
    /// clock, pruning discovery, learning names, packing, encrypting, invoking
    /// providers/callbacks, assigning sequence numbers, queueing or sending.
    /// Retained records may be stale. No freshness/authentication claim is made.
    ///
    /// Names must be known through the address book or retained topology. Numeric
    /// `@addr:` aliases are rejected rather than guessed across address namespaces.
    /// Empty/duplicate/unknown/ambiguous/oversized cohorts fail with the original
    /// packet. An existing frozen cohort is accepted only if its set is identical;
    /// its wire order and shape remain unchanged. New contracts preserve packet
    /// ID, nonce, source UTC, payload, sender and endpoints, and use the existing
    /// inline shape/target wire format understood by earlier SDK receivers.
    ///
    /// Membership binds logical hostname symbols, not receiver incarnation. A new
    /// device reusing a hostname is indistinguishable in this existing contract.
    /// Preparation is not SDK admission, an ACK, or proof of receiver readiness.
    #[allow(clippy::result_large_err)]
    pub fn prepare_targeted_packet(
        &self,
        mut packet: Packet,
        original_hostnames: &[&str],
    ) -> Result<FrozenTargetPacket, PrepareTargetedPacketError> {
        let fail = |kind, packet| PrepareTargetedPacketError { kind, packet };
        use PrepareTargetedPacketErrorKind as Kind;
        if original_hostnames.is_empty() {
            return Err(fail(Kind::InvalidRecipients, packet));
        }
        if original_hostnames.len() > MAX_PREPARED_TARGET_RECIPIENTS
            || original_hostnames
                .len()
                .checked_mul(size_of::<FrozenRecipient>())
                .is_none()
        {
            return Err(fail(Kind::TooManyRecipients, packet));
        }
        if self.ensure_application_origin_allowed().is_err()
            || is_internal_control_type(packet.data_type())
        {
            return Err(fail(Kind::OriginNotAllowed, packet));
        }
        let mut recipients = Vec::new();
        let mut symbols = Vec::new();
        if recipients
            .try_reserve_exact(original_hostnames.len())
            .is_err()
            || symbols.try_reserve_exact(original_hostnames.len()).is_err()
        {
            return Err(fail(Kind::Capacity, packet));
        }
        for (index, name) in original_hostnames.iter().copied().enumerate() {
            if name.is_empty() || name.starts_with("@addr:") {
                return Err(fail(Kind::InvalidRecipients, packet));
            }
            let symbol = Self::sender_hash(name);
            symbols.push((symbol, index));
            recipients.push(FrozenRecipient {
                hostname: Arc::from(name),
                wire_target_symbol: symbol,
                assigned_address: None,
                birth_ms: None,
                owner_hash: None,
            });
        }
        symbols.sort_unstable();
        if symbols.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(fail(Kind::DuplicateRecipient, packet));
        }
        // Capture recipient existence and collisions from exactly one immutable
        // state guard. Do not use resolve_hostname: it reads time and prunes.
        {
            let state = self.state.lock();
            let mut found = Vec::new();
            if found.try_reserve_exact(recipients.len()).is_err() {
                return Err(fail(Kind::Capacity, packet));
            }
            found.resize(recipients.len(), false);
            let mut ambiguous = false;
            let mut consider = |candidate: &str| {
                let symbol = Self::sender_hash(candidate);
                if let Ok(position) = symbols.binary_search_by_key(&symbol, |pair| pair.0) {
                    let index = symbols[position].1;
                    if candidate == recipients[index].hostname.as_ref() {
                        found[index] = true;
                    } else {
                        ambiguous = true;
                    }
                }
            };
            for entry in state.address_book.values() {
                consider(entry.hostname.as_ref());
            }
            #[cfg(feature = "discovery")]
            for route in state.discovery_routes.values() {
                for (announcer, remote) in &route.announcers {
                    consider(announcer);
                    for board in remote.topology_boards.iter() {
                        consider(&board.sender_id);
                        for connection in &board.connections {
                            consider(connection);
                        }
                    }
                }
            }
            if ambiguous {
                return Err(fail(Kind::AmbiguousRecipient, packet));
            }
            if found.iter().any(|found| !found) {
                return Err(fail(Kind::UnknownRecipient, packet));
            }
            for recipient in &mut recipients {
                if let Some(entry) = state.address_book.get(recipient.hostname.as_ref()) {
                    if entry.hostname.as_ref() != recipient.hostname.as_ref() {
                        return Err(fail(Kind::AmbiguousRecipient, packet));
                    }
                    recipient.assigned_address = Some(entry.address);
                    recipient.birth_ms = Some(entry.birth_ms);
                    recipient.owner_hash = Some(entry.owner_hash);
                }
            }
        }
        let original_targets = packet.wire_target_senders();
        if !original_targets.is_empty() {
            if original_targets.len() != symbols.len() {
                return Err(fail(Kind::ConflictingContract, packet));
            }
            let mut original_sorted = Vec::new();
            if original_sorted
                .try_reserve_exact(original_targets.len())
                .is_err()
            {
                return Err(fail(Kind::Capacity, packet));
            }
            original_sorted.extend_from_slice(original_targets);
            original_sorted.sort_unstable();
            if original_sorted
                .iter()
                .zip(&symbols)
                .any(|(old, (new, _))| old != new)
            {
                return Err(fail(Kind::ConflictingContract, packet));
            }
            // Validate even an idempotent contract, preserving its original shape.
            let shape = match packet.wire_shape() {
                Some(shape) => shape,
                None => match crate::config::try_get_message_meta(packet.data_type()) {
                    Some(meta) => meta.element,
                    None => return Err(fail(Kind::InvalidPacket, packet)),
                },
            };
            if packet.validate_target_contract_shape(shape).is_err() {
                return Err(fail(Kind::InvalidPacket, packet));
            }
        } else {
            let shape = match packet.wire_shape() {
                Some(shape) => shape,
                None => match crate::config::try_get_message_meta(packet.data_type()) {
                    Some(meta) => meta.element,
                    None => return Err(fail(Kind::InvalidPacket, packet)),
                },
            };
            if packet.validate_target_contract_shape(shape).is_err() {
                return Err(fail(Kind::InvalidPacket, packet));
            }
            // Freeze sorted wire symbols; no pack/cache/provider operation.
            let targets: Arc<[u64]> = symbols.iter().map(|pair| pair.0).collect();
            packet.set_prepared_target_contract(shape, targets);
        }
        Ok(FrozenTargetPacket {
            packet,
            recipients: recipients.into(),
        })
    }
}

#[cfg(all(test, feature = "std", feature = "discovery"))]
mod tests {
    use super::*;

    #[test]
    fn identical_existing_targets_without_inline_shape_remain_unchanged() {
        crate::tests::ensure_common_test_schema();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("unshaped-origin"),
            Box::new(|| 1000),
        );
        let side = router.add_side_packed("known-peer", |_| Ok(()));
        let endpoint = DataEndpoint::named("RADIO");
        router
            .rx_from_side(
                &discovery::build_discovery_announce("unshaped-target", 1000, &[endpoint]).unwrap(),
                side,
            )
            .unwrap();
        router.process_all_queues().unwrap();
        let original = Packet::new_with_wire_contract(
            DataType::named("GPS_DATA"),
            &[endpoint],
            "unshaped-origin",
            1000,
            9,
            Arc::<[u8]>::from([0u8; 12]),
            None,
            Arc::from([Router::sender_hash("unshaped-target")]),
        )
        .unwrap();
        assert_eq!(original.wire_shape(), None);
        let original_wire = wire_format::pack_packet(&original);
        let prepared = router
            .prepare_targeted_packet(original.clone(), &["unshaped-target"])
            .unwrap();
        assert_eq!(prepared.packet(), &original);
        assert_eq!(wire_format::pack_packet(prepared.packet()), original_wire);
    }
}
