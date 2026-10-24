//! Telemetry Router
//!
//! Router with internal named sides (like Relay), plus local processing.
//!
//! Design:
//! - Sides are registered with per-side TX handlers (packed or packet).
//! - RX is tagged by source side; route rules decide whether it is forwarded.
//! - Local endpoint handlers process packets as before (no side parameter).
//! - De-duplication remains packet-id based and side-agnostic.

#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "tests/accepted_route_ownership.rs"]
mod accepted_route_ownership;

#[cfg(all(test, feature = "std"))]
#[path = "tests/independent_side_tx_router.rs"]
mod independent_side_tx;
#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "tests/ingress_target_filter.rs"]
mod ingress_target_filter_tests;
#[cfg(all(test, feature = "std", feature = "discovery", feature = "compression"))]
#[path = "tests/payload_codec_negotiation.rs"]
mod payload_codec_negotiation;
#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "tests/reliable_tx_window_backpressure.rs"]
mod reliable_tx_window_backpressure_tests;
#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "tests/shared_chunk_budget_router.rs"]
mod shared_chunk_budget_tests;
// Apply the same cache contract independently to router and relay state.
#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "tests/side_template_index.rs"]
mod side_template_index_tests;
#[cfg(feature = "discovery")]
use crate::config::runtime_reliable_max_end_to_end_pending;
#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "tests/replay_ownership_router.rs"]
mod replay_ownership_tests;
use crate::side_transport::{
    SIDE_TRANSPORT_FLAG_PACKET_NONCE, SIDE_TRANSPORT_KIND_CHUNK, SIDE_TRANSPORT_KIND_COMPACT,
    SIDE_TRANSPORT_KIND_COMPACT_DELTA, SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP,
    SIDE_TRANSPORT_KIND_FULL, SideChunkAssembly, SideCompactTimestampMode, SideHeaderTemplate,
    SideTransportFrames, extract_side_header_template, extract_side_header_template_view,
    parse_side_transport_wrapper, read_uleb128_local, reconstruct_side_compact_frame,
    wrap_side_transport_frame, write_uleb128_local,
};
#[cfg(all(test, feature = "discovery"))]
#[path = "tests/ack_return_identity.rs"]
mod ack_return_identity;
#[cfg(all(test, feature = "discovery"))]
#[path = "tests/ack_split_horizon.rs"]
mod ack_split_horizon;

#[cfg(all(test, feature = "discovery"))]
#[path = "tests/discovery_liveness.rs"]
mod discovery_liveness;

#[cfg(all(test, feature = "discovery"))]
mod compact_summary_tests {
    use super::*;

    #[test]
    fn ordered_pending_window_is_bounded_and_exhaustion_cancels_the_tail() {
        crate::tests::ensure_common_test_schema();
        let ep = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type_with_description(
            "ORDERED_WINDOW_REGRESSION",
            "bounded ordered window",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::Ordered,
            200,
        )
        .unwrap();
        let now = Arc::new(core::sync::atomic::AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let capacity = runtime_reliable_max_end_to_end_pending().max(1);
        for index in 0..capacity {
            let item = RouterItem::Packet(
                Packet::new(
                    ty,
                    &[ep],
                    "SOURCE",
                    index as u64 + 1,
                    Arc::<[u8]>::from([index as u8]),
                )
                .unwrap(),
            );
            assert_eq!(
                router.register_end_to_end_reliable_tx(&item, None).unwrap(),
                index == 0
            );
        }
        let rejected = RouterItem::Packet(
            Packet::new(
                ty,
                &[ep],
                "SOURCE",
                capacity as u64 + 1,
                Arc::<[u8]>::from([0]),
            )
            .unwrap(),
        );
        assert!(
            router
                .register_end_to_end_reliable_tx(&rejected, None)
                .is_err()
        );
        {
            let mut state = router.state.lock();
            assert_eq!(state.end_to_end_reliable_tx.len(), capacity);
            let first = state.end_to_end_reliable_tx_order[0];
            state
                .end_to_end_reliable_tx
                .get_mut(&first)
                .unwrap()
                .retries = runtime_reliable_max_retries();
        }
        now.store(runtime_reliable_retransmit_ms(), Ordering::Relaxed);
        assert!(router.process_end_to_end_reliable_timeouts().is_err());
        assert!(router.state.lock().end_to_end_reliable_tx.is_empty());
    }
    #[test]
    fn compact_reachability_survives_incomplete_detailed_topology() {
        crate::tests::ensure_common_test_schema();
        let router = Router::new(RouterConfig::new([]).with_sender("GB"));
        let endpoint = DataEndpoint::try_named("GROUND_STATION")
            .or_else(|| DataEndpoint::try_named("RADIO"))
            .unwrap();
        router.compact_summary_fixture(endpoint);
        let state = router.state.lock();
        let now = router.clock.now_ms();
        let advertised =
            router.advertised_discovery_endpoints_for_link_locked(&state, now, true, Some(1));
        assert!(
            advertised.contains(&endpoint),
            "compact subscriber route was lost at the bridge"
        );
        let reflected =
            router.advertised_discovery_endpoints_for_link_locked(&state, now, true, Some(0));
        assert!(
            !reflected.contains(&endpoint),
            "split horizon must still exclude ingress"
        );
        assert_eq!(
            router.advertised_discovery_timesync_sources_for_link_locked(&state, now, Some(1)),
            vec!["clock-behind-bridge".to_string()]
        );
        assert!(
            router
                .advertised_discovery_timesync_sources_for_link_locked(&state, now, Some(0))
                .is_empty()
        );
        assert!(
            !router
                .advertised_discovery_endpoints_for_link_locked(
                    &state,
                    now + DISCOVERY_ROUTE_TTL_MS + 1,
                    true,
                    Some(1)
                )
                .contains(&endpoint)
        );
        assert!(
            router
                .advertised_discovery_timesync_sources_for_link_locked(
                    &state,
                    now + DISCOVERY_ROUTE_TTL_MS + 1,
                    Some(1)
                )
                .is_empty()
        );
    }
}

use crate::config::RuntimeMemoryConfig;
use crate::diagnostics::{
    AdaptiveLinkStats, DiscoveryRuntimeStats, QueueRuntimeStats, ReliableRuntimeStats,
    RouteModeStats, RouteOverrideStats, RoutePriorityStats, RouteWeightStats, RuntimeSideStats,
    RuntimeStatsSnapshot, RuntimeTypeStats, TypedRouteOverrideStats,
};
#[cfg(feature = "discovery")]
use crate::discovery::{
    self, ClientStatsSnapshot, DISCOVERY_INCREMENTAL_RETRY_COUNT, DISCOVERY_ROUTE_TTL_MS,
    DISCOVERY_SLOW_LINK_PING_INTERVAL_MS, DiscoveryCadenceState,
    TIMESYNC_SLOW_LINK_MIN_INTERVAL_MS, TopologyAnnouncerRoute, TopologyBoardNode,
    TopologySideRoute, TopologySnapshot,
};
use crate::packet::{hash_bytes_u64, sender_address_u32};
use crate::queue::{BoundedDeque, ByteCost};
#[cfg(all(not(feature = "std"), target_os = "none"))]
use crate::seds_error_msg;
#[cfg(feature = "timesync")]
use crate::timesync::{
    INTERNAL_TIMESYNC_SOURCE_ID, LOCAL_TIMESYNC_DATE_SOURCE_ID, LOCAL_TIMESYNC_FULL_SOURCE_ID,
    LOCAL_TIMESYNC_SUBSEC_SOURCE_ID, LOCAL_TIMESYNC_TOD_SOURCE_ID, NetworkClock,
    NetworkTimeReading, PartialNetworkTime, SlewedNetworkClock, TimeSyncConfig, TimeSyncLeader,
    TimeSyncTracker, advance_network_time, compute_network_time_sample, decode_timesync_announce,
    decode_timesync_request, decode_timesync_response,
};
use crate::{
    E2eEncryptionPolicy, MessageElement, RouteSelectionMode, TelemetryError, TelemetryResult,
    config::{
        DataEndpoint, DataType, runtime_device_identifier, runtime_max_handler_retries,
        runtime_reliable_max_pending, runtime_reliable_max_retries,
        runtime_reliable_max_return_routes, runtime_reliable_retransmit_ms,
    },
    get_needed_message_size, impl_letype_num, is_reliable_type,
    lock::{ReentryGate, RouterMutex},
    message_e2e_encryption_policy, message_meta, message_priority,
    packet::Packet,
    reliable_mode, wire_format,
};
use alloc::string::{String, ToString};

#[cfg(any(test, all(feature = "embedded", not(feature = "std"))))]
use crate::small_map::SmallMap as RouterMap;
#[cfg(not(any(test, all(feature = "embedded", not(feature = "std")))))]
use alloc::collections::BTreeMap as RouterMap;

use alloc::collections::BTreeMap;

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{BTreeSet, VecDeque},
    format,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::cell::UnsafeCell;
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[cfg(feature = "std")]
use std::time::Instant;

/// Logical side index (CAN, UART, RADIO, etc.)
pub type RouterSideId = usize;

const CONTROL_SLOW_LINK_CAPACITY_BPS: u64 = 512;
pub const IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES: usize = 20;
pub const IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES: usize = 40;
pub const DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT: usize = 64;
static ROUTER_INSTANCE_SEQ: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideTransportProfile {
    Canonical,
    Template,
    Ipv6Like,
    Ipv4Like,
}

impl SideTransportProfile {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Template => "template",
            Self::Ipv6Like => "ipv6_like",
            Self::Ipv4Like => "ipv4_like",
        }
    }

    #[cfg(feature = "discovery")]
    #[inline]
    pub const fn discovery_code(self) -> u8 {
        match self {
            Self::Canonical => discovery::LINK_PROFILE_CANONICAL,
            Self::Template => discovery::LINK_PROFILE_TEMPLATE,
            Self::Ipv6Like => discovery::LINK_PROFILE_IPV6_LIKE,
            Self::Ipv4Like => discovery::LINK_PROFILE_IPV4_LIKE,
        }
    }
}

#[cfg(test)]
mod chunk_assembly_memory_tests {
    use super::*;
    #[test]
    fn full_chunk_budget_reclaims_other_partial_transfers_before_active_schema() {
        let mut state = SideTransportState::default();
        for id in 1..=4 {
            let mut assembly = SideChunkAssembly {
                total: 28,
                last_seen_ms: id as u64,
                ..Default::default()
            };
            for index in 0..23 {
                assembly.insert(
                    index,
                    crate::shared_bytes::convert(Arc::<[u8]>::from([id as u8; 112])),
                );
            }
            state.rx_chunks.insert(id, assembly);
        }
        state.rx_chunks.get_mut(&1).unwrap().insert(
            23,
            crate::shared_bytes::convert(Arc::<[u8]>::from([1u8; 56])),
        );
        // 16192 + (56 + 64) = 16312 bytes, as in the Gateway capture.
        state.refresh_rx_chunk_bytes();
        SideChunkAssembly::make_room(
            &mut state.rx_chunks,
            &mut state.rx_chunk_bytes,
            4,
            23,
            28,
            112,
            16384,
        )
        .unwrap();
        assert!(!state.rx_chunks.contains_key(&1));
        assert_eq!(state.rx_chunks[&4].received_len(), 23);
        for index in 23..28 {
            state.refresh_rx_chunk_bytes();
            SideChunkAssembly::make_room(
                &mut state.rx_chunks,
                &mut state.rx_chunk_bytes,
                4,
                index,
                28,
                112,
                16384,
            )
            .unwrap();
            state.rx_chunks.get_mut(&4).unwrap().insert(
                index,
                crate::shared_bytes::convert(Arc::<[u8]>::from([4u8; 112])),
            );
        }
        assert_eq!(
            state.rx_chunks.remove(&4).unwrap().assemble().unwrap(),
            vec![4u8; 28 * 112]
        );
        assert!(
            state
                .rx_chunks
                .values()
                .flat_map(|a| a.received.iter().flatten())
                .map(|p| p.len() + 64)
                .sum::<usize>()
                <= 16384
        );
    }

    #[test]
    fn duplicate_chunk_keeps_partial_transfers_but_oversize_transfer_is_rejected() {
        let mut state = SideTransportState::default();
        let mut assembly = SideChunkAssembly {
            total: 2,
            ..Default::default()
        };
        assembly.insert(
            0,
            crate::shared_bytes::convert(Arc::<[u8]>::from([1u8; 112])),
        );
        state.rx_chunks.insert(1, assembly.clone());
        state.rx_chunks.insert(2, assembly);
        state.refresh_rx_chunk_bytes();
        SideChunkAssembly::make_room(
            &mut state.rx_chunks,
            &mut state.rx_chunk_bytes,
            1,
            0,
            2,
            112,
            352,
        )
        .unwrap();
        assert_eq!(state.rx_chunks.len(), 2);
        state.refresh_rx_chunk_bytes();
        assert!(
            SideChunkAssembly::make_room(
                &mut state.rx_chunks,
                &mut state.rx_chunk_bytes,
                1,
                1,
                2,
                400,
                352
            )
            .is_err()
        );
        assert!(!state.rx_chunks.contains_key(&1));
        assert!(state.rx_chunks.contains_key(&2));
    }

    #[test]
    fn schema_sized_reassembly_allocates_exactly_and_preserves_order() {
        let payload: Vec<u8> = (0..3652).map(|i| (i % 251) as u8).collect();
        let mut assembly = SideChunkAssembly {
            total: payload.len().div_ceil(56) as u16,
            ..Default::default()
        };
        for (index, chunk) in payload.chunks(56).enumerate().rev() {
            assembly.insert(
                index as u16,
                crate::shared_bytes::convert(Arc::<[u8]>::from(chunk)),
            );
        }
        assert_eq!(assembly.received_len(), usize::from(assembly.total));
        let out = assembly.assemble().unwrap();
        assert_eq!(out, payload);
        assert_eq!(
            out.capacity(),
            payload.len(),
            "do not double discovery reassembly capacity"
        );
    }
    #[test]
    fn incomplete_or_noncontiguous_chunks_are_rejected() {
        let mut assembly = SideChunkAssembly {
            total: 2,
            ..Default::default()
        };
        assembly.insert(0, crate::shared_bytes::convert(Arc::<[u8]>::from([1u8])));
        assert!(assembly.clone().assemble().is_err());
        assert!(
            assembly
                .insert_with(2, 0, || Arc::<[u8]>::from([2u8]))
                .is_err()
        );
        assert!(assembly.assemble().is_err());
    }
}

#[derive(Clone, Debug, Default)]
struct SideTransportState {
    #[cfg(feature = "std")]
    tx_callback_gate: Arc<ReentryGate>,
    tx_chunk_progress: Option<Box<crate::side_transport::SideTxProgress>>,
    #[cfg(all(feature = "compression", feature = "discovery"))]
    payload_codec: crate::payload_codec::Ledger,
    #[cfg(all(feature = "compression", feature = "discovery"))]
    payload_codec_choice: u64,
    tx_template_ids: RouterMap<u64, u32>,
    tx_templates: BTreeMap<u64, SideHeaderTemplate>,
    tx_last_timestamps: RouterMap<u32, u64>,
    tx_compact_uses: RouterMap<u32, u8>,
    rx_templates: RouterMap<u64, u32>,
    rx_templates_by_id: BTreeMap<u32, SideHeaderTemplate>,
    rx_last_timestamps: RouterMap<u32, u64>,
    rx_chunks: BTreeMap<u32, SideChunkAssembly>,
    rx_chunk_reclaims: u32,
    rx_chunk_bytes: usize,
}

impl SideTransportState {
    #[inline(never)]
    fn take_chunk(&mut self, id: u32, reclaimed: bool) -> Option<SideChunkAssembly> {
        let value = SideChunkAssembly::remove(&mut self.rx_chunks, &mut self.rx_chunk_bytes, id)?;
        if reclaimed {
            self.rx_chunk_reclaims = self.rx_chunk_reclaims.saturating_add(1);
        }
        Some(value)
    }
    /// Seed fixtures that construct raw maps directly.
    #[cfg(test)]
    #[inline(never)]
    fn refresh_rx_chunk_bytes(&mut self) {
        self.rx_chunk_bytes = self
            .rx_chunks
            .values()
            .map(SideChunkAssembly::byte_cost)
            .sum();
    }
    fn refresh_transmit_header_templates(&mut self) {
        // Refresh on the wire, not by forgetting the eviction history. RX
        // retains its dictionary; clearing only TX makes bounded caches evict
        // different entries after the next insertion/capacity negotiation.
        for uses in self.tx_compact_uses.values_mut() {
            *uses = u8::MAX;
        }
        // Local topology changes do not invalidate dictionaries received from
        // peers. Dropping RX state here loses already-in-flight compact ACKs.
    }

    fn tx_template_count(&self) -> usize {
        self.tx_template_ids.len()
    }

    fn rx_template_count(&self) -> usize {
        self.rx_templates_by_id.len()
    }

    fn trim_tx_templates_to(&mut self, limit: usize) -> usize {
        let mut removed = 0usize;
        while self.tx_template_ids.len() > limit {
            let Some(old_hash) = self.tx_template_ids.keys().next().copied() else {
                break;
            };
            if let Some(old_id) = self.tx_template_ids.remove(&old_hash) {
                self.tx_last_timestamps.remove(&old_id);
                self.tx_compact_uses.remove(&old_id);
            }
            self.tx_templates.remove(&old_hash);
            removed += 1;
        }
        removed
    }

    fn insert_tx_template(
        &mut self,
        template: SideHeaderTemplate,
        template_id: u32,
        max_templates: usize,
    ) -> bool {
        if max_templates == 0 {
            return false;
        }
        let evicted = !self.tx_template_ids.contains_key(&template.hash)
            && self.trim_tx_templates_to(max_templates.saturating_sub(1)) > 0;
        self.tx_template_ids.insert(template.hash, template_id);
        self.tx_templates.insert(template.hash, template);
        self.tx_compact_uses.insert(template_id, 0);
        evicted
    }

    fn insert_rx_template(
        &mut self,
        template_id: u32,
        template: SideHeaderTemplate,
        max_templates: usize,
    ) -> bool {
        if max_templates == 0 {
            return false;
        }
        // Keep one owned header. The hash index needs only its wire ID, not
        // another copy of the header and its shared-buffer owners.
        if let Some(old_id) = self.rx_templates.get(&template.hash).copied()
            && old_id != template_id
        {
            self.rx_templates_by_id.remove(&old_id);
            self.rx_last_timestamps.remove(&old_id);
            self.rx_templates.remove(&template.hash);
        }
        if let Some(previous) = self.rx_templates_by_id.get(&template_id)
            && previous.hash != template.hash
        {
            self.rx_templates.remove(&previous.hash);
            self.rx_last_timestamps.remove(&template_id);
        }
        let mut evicted = false;
        if self.rx_templates_by_id.len() >= max_templates
            && !self.rx_templates_by_id.contains_key(&template_id)
            // Match TX's deterministic lowest-hash eviction on both routers
            // and relays; lowest wire ID can select a different live header.
            && let Some((&old_hash, &old_id)) = self.rx_templates.first_key_value()
        {
            self.rx_templates.remove(&old_hash);
            self.rx_templates_by_id.remove(&old_id);
            self.rx_last_timestamps.remove(&old_id);
            evicted = true;
        }
        self.rx_templates.insert(template.hash, template_id);
        self.rx_templates_by_id.insert(template_id, template);
        evicted
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactTimestampOmissionPolicy {
    all: bool,
    types: Option<Arc<[DataType]>>,
}
impl CompactTimestampOmissionPolicy {
    pub const fn none() -> Self {
        Self {
            all: false,
            types: None,
        }
    }
    pub const fn all() -> Self {
        Self {
            all: true,
            types: None,
        }
    }
    pub fn with_data_type(mut self, ty: DataType) -> Self {
        self.insert(ty);
        self
    }
    pub fn insert(&mut self, ty: DataType) {
        if self.contains(ty) {
            return;
        }
        let current = self.types.as_deref().unwrap_or(&[]);
        let mut types = Vec::with_capacity(current.len() + 1);
        types.extend_from_slice(current);
        let index = types.binary_search(&ty).unwrap_err();
        types.insert(index, ty);
        self.types = Some(Arc::from(types));
    }
    pub fn contains(&self, ty: DataType) -> bool {
        self.all
            || self
                .types
                .as_deref()
                .is_some_and(|types| types.binary_search(&ty).is_ok())
    }
    pub fn is_empty(&self) -> bool {
        !self.all && self.types.is_none()
    }
}

impl Default for CompactTimestampOmissionPolicy {
    #[inline]
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouterItem {
    Packet(Packet),
    Packed(crate::SharedBytes),
}

#[cfg(feature = "compact-packet-store")]
impl RouterItem {
    fn park_for_queue(&mut self) -> TelemetryResult<()> {
        match self {
            Self::Packet(packet) => packet.park_for_queue()?,
            Self::Packed(bytes) => bytes.park_for_queue()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouterRxItem {
    src: Option<RouterSideId>,
    data: RouterItem,
    priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RouterTxItem {
    Broadcast(RouterItem),
    EndToEndReplay {
        packet_id: u64,
    },
    ToSide {
        src: Option<RouterSideId>,
        dst: RouterSideId,
        data: RouterItem,
    },
    ReliableReplay {
        dst: RouterSideId,
        ty: DataType,
        seq: u32,
        bytes: crate::SharedBytes,
    },
}

impl ByteCost for RouterRxItem {
    #[cfg(feature = "compact-packet-store")]
    fn park_for_queue(&mut self) -> TelemetryResult<()> {
        self.data.park_for_queue()
    }
    #[inline]
    fn byte_cost(&self) -> usize {
        match &self.data {
            RouterItem::Packet(pkt) => pkt.byte_cost(),
            RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
        }
    }
}

impl ByteCost for RouterTxItem {
    #[cfg(feature = "compact-packet-store")]
    fn park_for_queue(&mut self) -> TelemetryResult<()> {
        match self {
            Self::Broadcast(item) | Self::ToSide { data: item, .. } => item.park_for_queue(),
            Self::ReliableReplay { bytes, .. } => bytes.park_for_queue(),
            _ => Ok(()),
        }
    }
    #[inline]
    fn byte_cost(&self) -> usize {
        match self {
            RouterTxItem::Broadcast(data) => match data {
                RouterItem::Packet(pkt) => pkt.byte_cost(),
                RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
            },
            RouterTxItem::EndToEndReplay { .. } => size_of::<u64>(),
            RouterTxItem::ToSide { data, .. } => match data {
                RouterItem::Packet(pkt) => pkt.byte_cost(),
                RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
            },
            RouterTxItem::ReliableReplay { bytes, .. } => {
                size_of::<crate::SharedBytes>() + bytes.len()
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ReplayMarkerKey {
    EndToEnd(u64),
    Hop(RouterSideId, DataType, u32),
}
impl RouterTxItem {
    fn replay_marker_key(&self) -> Option<ReplayMarkerKey> {
        match self {
            Self::EndToEndReplay { packet_id } => Some(ReplayMarkerKey::EndToEnd(*packet_id)),
            Self::ReliableReplay { dst, ty, seq, .. } => {
                Some(ReplayMarkerKey::Hop(*dst, *ty, *seq))
            }
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueuedDelivery {
    Untracked,
    OrderedTail,
    Ordered,
    DeferredOrdered,
    DeferredUnordered,
    Unordered,
    ClaimedOrdered,
    ClaimedUnordered,
}

/// Transmit queue item with flags.
/// Holds a RouterTxItem and a flag to ignore local dispatch.
/// Used internally by the Router transmit queue.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TxQueued {
    // Cached before queue parking; padding keeps the metadata footprint stable.
    disposable: bool,
    item: RouterTxItem,
    ignore_local: bool,
    priority: u8,
    delivery_state: QueuedDelivery,
    accepted_type: u32,
    deferred_since_ms: u64,
    retry_after_ms: u64,
}

#[derive(Clone, Copy)]
struct TxClaim {
    token: u32,
    ordered: bool,
}
#[derive(Default)]
struct DispatchContext {
    claim: Option<TxClaim>,
    since: Option<u64>,
    terminal: bool,
    owner_transferred: bool,
}
struct TxWork {
    queued: TxQueued,
    claim: Option<TxClaim>,
}

/// Do not allow a continuously replenished stream of control traffic to keep
/// an already-queued application packet from ever reaching a transport.
/// Priorities still determine normal ordering; this only services the oldest
/// lowest-priority item after a bounded high-priority burst.
const MAX_PRIORITY_BURST: u8 = 8;

/// ByteCost implementation for TxQueued.
// The cached bit must fit the old metadata padding on host and MCU targets.
const _: () = assert!(size_of::<TxQueued>() == size_of::<(RouterTxItem, bool, u8, u64)>() + 8);

impl ByteCost for TxQueued {
    #[cfg(feature = "compact-packet-store")]
    fn park_for_queue(&mut self) -> TelemetryResult<()> {
        self.item.park_for_queue()
    }
    /// Byte cost is the cost of the inner item plus one bool.
    #[inline]
    fn byte_cost(&self) -> usize {
        self.item.byte_cost() + size_of::<bool>() + size_of::<u8>() + 2 * size_of::<u64>()
    }
}

/// ByteCost implementation for `u64` (used by `recent_rx`).
impl ByteCost for u64 {
    /// Byte cost is size of u64.
    #[inline]
    fn byte_cost(&self) -> usize {
        size_of::<u64>()
    }
}

// -------------------- Reliable delivery state --------------------

#[derive(Debug, Clone)]
struct ReliableTxState {
    next_seq: u32,
    sent_order: VecDeque<u32>,
    sent: BTreeMap<u32, ReliableSent>,
}

#[derive(Debug, Clone)]
struct ReliableSent {
    bytes: crate::SharedBytes,
    last_send_ms: u64,
    retries: u32,
    queued: bool,
    partial_acked: bool,
}

#[derive(Debug, Clone)]
struct EndToEndReliableSent {
    ordered_type: Option<u32>,
    waiting_for_predecessor: bool,
    data: RouterItem,
    pending_destinations: BTreeMap<u64, RouterSideId>,
    tracked_destinations: bool,
    last_send_ms: u64,
    retries: u32,
    queued: bool,
}

#[derive(Debug, Clone)]
struct ReliableRxState {
    expected_seq: u32,
    buffered: RouterMap<u32, crate::SharedBytes>,
}

#[derive(Debug, Clone)]
struct ReliableReturnRouteState {
    side: RouterSideId,
    // A final receipt can be lost after the application has acted. Ordinary
    // RX traffic must not evict this delivery record before its return route.
    locally_delivered: bool,
    last_replay_ms: u64,
    // A legacy contract names this router, not its downstream owner.
    // Translate the child receipt back to the router identity and original
    // packet ID that the upstream publisher is awaiting.
    upstream_contract: Option<(u64, u64)>,
}

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DiscoverySenderState {
    /// Numeric identity advertised for this hostname. Compact frames may carry
    /// this address instead of the hostname, so routing must accept either.
    advertised_address: Option<u32>,
    reachable: Vec<DataEndpoint>,
    advertised_reachable: Vec<DataEndpoint>,
    reachable_network_variables: Vec<DataType>,
    reachable_timesync_sources: Vec<String>,
    advertised_reachable_timesync_sources: Vec<String>,
    link_capabilities: Option<discovery::LinkCapabilities>,
    topology_boards: Arc<Vec<TopologyBoardNode>>,
    has_full_topology: bool,
    has_schema: bool,
    last_seen_ms: u64,
}

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DiscoverySideState {
    reachable: Vec<DataEndpoint>,
    reachable_network_variables: Vec<DataType>,
    requested_network_variables: Vec<(DataType, u64)>,
    reachable_timesync_sources: Vec<String>,
    last_seen_ms: u64,
    announcers: BTreeMap<String, DiscoverySenderState>,
}

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default)]
struct DiscoverySideThrottleState {
    next_topology_request_ms: u64,
    next_schema_request_ms: u64,
    next_ping_ms: u64,
    // Scheduled and accepted sends differ when a constrained link is backed up.
    last_liveness_tx_ms: u64,
    pending_incremental: bool,
    incremental_retries_remaining: u8,
    has_sent_full: bool,
    last_topology: Vec<TopologyBoardNode>,
}

#[cfg(feature = "discovery")]
impl DiscoverySideThrottleState {
    fn liveness_due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_ping_ms
            && now_ms.saturating_sub(self.last_liveness_tx_ms)
                >= DISCOVERY_SLOW_LINK_PING_INTERVAL_MS
    }
}

#[cfg(all(feature = "discovery", feature = "timesync"))]
#[derive(Debug, Clone, Default)]
struct TimeSyncSideThrottleState {
    next_allowed_ms: u64,
}

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryAdvertiseLevel {
    MinimalPing,
    Incremental,
    Full,
}

#[derive(Debug, Clone, Default)]
struct AdaptiveRouteStats {
    estimated_bandwidth_bps: u64,
    peak_bandwidth_bps: u64,
    last_observed_ms: u64,
    last_slow_observed_ms: u64,
    sample_count: u64,
    window_started_ms: u64,
    window_bytes: u64,
    peak_usage_bps: u64,
}

impl AdaptiveRouteStats {
    #[inline]
    fn observe(&mut self, bytes: usize, sample_bps: u64, now_ms: u64) {
        self.estimated_bandwidth_bps = if self.estimated_bandwidth_bps == 0 {
            sample_bps
        } else if sample_bps >= self.estimated_bandwidth_bps {
            self.estimated_bandwidth_bps
                .saturating_mul(3)
                .saturating_add(sample_bps.saturating_mul(5))
                / 8
        } else {
            self.estimated_bandwidth_bps
                .saturating_mul(7)
                .saturating_add(sample_bps)
                / 8
        };
        self.peak_bandwidth_bps = self.peak_bandwidth_bps.max(sample_bps);
        self.last_observed_ms = now_ms;
        if sample_bps > 0 && sample_bps <= CONTROL_SLOW_LINK_CAPACITY_BPS {
            self.last_slow_observed_ms = now_ms;
        }
        self.sample_count = self.sample_count.saturating_add(1);
        if self.window_started_ms == 0 || now_ms.saturating_sub(self.window_started_ms) > 1_000 {
            self.window_started_ms = now_ms;
            self.window_bytes = 0;
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes as u64);
        self.peak_usage_bps = self.peak_usage_bps.max(self.current_usage_bps(now_ms));
    }

    #[inline]
    fn current_usage_bps(&self, now_ms: u64) -> u64 {
        if self.window_started_ms == 0 {
            return 0;
        }
        let elapsed_ms = now_ms.saturating_sub(self.window_started_ms).max(1);
        (u128::from(self.window_bytes).saturating_mul(1000) / u128::from(elapsed_ms))
            .min(u128::from(u64::MAX)) as u64
    }

    #[inline]
    fn available_headroom_bps(&self, now_ms: u64) -> u64 {
        let capacity = self
            .estimated_bandwidth_bps
            .max(self.peak_bandwidth_bps)
            .max(1);
        capacity.saturating_sub(self.current_usage_bps(now_ms))
    }

    #[inline]
    fn weight(&self, now_ms: u64) -> u64 {
        self.available_headroom_bps(now_ms).max(1)
    }

    #[inline]
    fn snapshot(&self, now_ms: u64, auto_balancing_enabled: bool) -> AdaptiveLinkStats {
        let current_usage_bps = self.current_usage_bps(now_ms);
        let estimated_capacity_bps = self.estimated_bandwidth_bps.max(1);
        let peak_capacity_bps = self.peak_bandwidth_bps.max(estimated_capacity_bps);
        let available_headroom_bps = peak_capacity_bps.saturating_sub(current_usage_bps);
        AdaptiveLinkStats {
            auto_balancing_enabled,
            estimated_capacity_bps,
            peak_capacity_bps,
            current_usage_bps,
            peak_usage_bps: self.peak_usage_bps.max(current_usage_bps),
            available_headroom_bps,
            effective_weight: available_headroom_bps.max(1),
            last_observed_ms: self.last_observed_ms,
            sample_count: self.sample_count,
        }
    }
}

use crate::type_stats::TypeRuntimeStatsInner;

#[derive(Debug, Clone, Default)]
struct SideRuntimeStatsInner {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    relayed_tx_packets: u64,
    relayed_tx_bytes: u64,
    relayed_rx_packets: u64,
    relayed_rx_bytes: u64,
    local_delivery_packets: u64,
    tx_retries: u64,
    tx_handler_failures: u64,
    local_handler_failures: u64,
    total_handler_retries: u64,
    side_transport_full_frames: u64,
    side_transport_compact_frames: u64,
    side_transport_compact_delta_frames: u64,
    side_transport_compact_omitted_timestamp_frames: u64,
    side_transport_chunk_frames: u64,
    side_transport_raw_bytes: u64,
    side_transport_wire_bytes: u64,
    side_transport_bytes_saved: u64,
    side_transport_min_compact_overhead_bytes: Option<usize>,
    side_transport_max_compact_overhead_bytes: Option<usize>,
    side_transport_compact_target_misses: u64,
    side_transport_template_evictions: u64,
    data_types: BTreeMap<u32, TypeRuntimeStatsInner>,
}

impl SideRuntimeStatsInner {
    fn type_stats_mut(&mut self, ty: DataType) -> &mut TypeRuntimeStatsInner {
        self.data_types.entry(ty.as_u32()).or_default()
    }

    fn note_tx(&mut self, ty: DataType, bytes: usize, relayed: bool, retries: usize) {
        self.tx_packets = self.tx_packets.saturating_add(1);
        self.tx_bytes = self.tx_bytes.saturating_add(bytes as u64);
        self.tx_retries = self.tx_retries.saturating_add(retries as u64);
        self.total_handler_retries = self.total_handler_retries.saturating_add(retries as u64);
        if relayed {
            self.relayed_tx_packets = self.relayed_tx_packets.saturating_add(1);
            self.relayed_tx_bytes = self.relayed_tx_bytes.saturating_add(bytes as u64);
        }
        self.type_stats_mut(ty)
            .tx(bytes as u64, relayed, retries as u64);
    }

    fn note_rx(&mut self, ty: DataType, bytes: usize, relayed: bool) {
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.rx_bytes = self.rx_bytes.saturating_add(bytes as u64);
        if relayed {
            self.relayed_rx_packets = self.relayed_rx_packets.saturating_add(1);
            self.relayed_rx_bytes = self.relayed_rx_bytes.saturating_add(bytes as u64);
        }
        self.type_stats_mut(ty).rx(bytes as u64, relayed);
    }

    fn note_local_delivery(&mut self, ty: DataType) {
        self.local_delivery_packets = self.local_delivery_packets.saturating_add(1);
        self.type_stats_mut(ty).rx(0, false);
    }

    fn note_local_handler_failure(&mut self, ty: DataType, retries: usize) {
        self.local_handler_failures = self.local_handler_failures.saturating_add(1);
        self.total_handler_retries = self.total_handler_retries.saturating_add(retries as u64);
        self.type_stats_mut(ty).failure(0);
    }

    fn note_tx_failure(&mut self, ty: DataType, retries: usize) {
        self.tx_handler_failures = self.tx_handler_failures.saturating_add(1);
        self.total_handler_retries = self.total_handler_retries.saturating_add(retries as u64);
        self.tx_retries = self.tx_retries.saturating_add(retries as u64);
        self.type_stats_mut(ty).failure(retries as u64);
    }

    fn note_side_transport_full(&mut self, raw_bytes: usize, wire_bytes: usize) {
        self.side_transport_full_frames = self.side_transport_full_frames.saturating_add(1);
        self.note_side_transport_bytes(raw_bytes, wire_bytes);
    }

    fn note_side_transport_compact(
        &mut self,
        raw_bytes: usize,
        wire_bytes: usize,
        compact_overhead_bytes: usize,
        used_timestamp_delta: bool,
        omitted_timestamp: bool,
    ) {
        self.side_transport_compact_frames = self.side_transport_compact_frames.saturating_add(1);
        if used_timestamp_delta {
            self.side_transport_compact_delta_frames =
                self.side_transport_compact_delta_frames.saturating_add(1);
        }
        if omitted_timestamp {
            self.side_transport_compact_omitted_timestamp_frames = self
                .side_transport_compact_omitted_timestamp_frames
                .saturating_add(1);
        }
        self.note_side_transport_bytes(raw_bytes, wire_bytes);
        self.side_transport_min_compact_overhead_bytes = Some(
            self.side_transport_min_compact_overhead_bytes
                .map_or(compact_overhead_bytes, |v| v.min(compact_overhead_bytes)),
        );
        self.side_transport_max_compact_overhead_bytes = Some(
            self.side_transport_max_compact_overhead_bytes
                .map_or(compact_overhead_bytes, |v| v.max(compact_overhead_bytes)),
        );
    }

    fn note_side_transport_chunks(&mut self, chunks: usize) {
        self.side_transport_chunk_frames = self
            .side_transport_chunk_frames
            .saturating_add(chunks as u64);
    }

    fn note_side_transport_bytes(&mut self, raw_bytes: usize, wire_bytes: usize) {
        self.side_transport_raw_bytes = self
            .side_transport_raw_bytes
            .saturating_add(raw_bytes as u64);
        self.side_transport_wire_bytes = self
            .side_transport_wire_bytes
            .saturating_add(wire_bytes as u64);
        if raw_bytes > wire_bytes {
            self.side_transport_bytes_saved = self
                .side_transport_bytes_saved
                .saturating_add((raw_bytes - wire_bytes) as u64);
        }
    }

    fn note_side_transport_compact_target_miss(&mut self) {
        self.side_transport_compact_target_misses =
            self.side_transport_compact_target_misses.saturating_add(1);
    }

    fn note_side_transport_template_eviction(&mut self) {
        self.side_transport_template_evictions =
            self.side_transport_template_evictions.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteSelectionOrigin {
    Flood,
    Discovered,
}

// -------------------- endpoint + board config --------------------
/// Packet Handler function type
type PacketHandlerFn = dyn Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static;

/// Packed Handler function type
type PackedHandlerFn = dyn Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static;
type PrioritizedPackedHandlerFn = dyn Fn(&[u8], u8) -> TelemetryResult<()> + Send + Sync + 'static;

// Make handlers usable across tasks
/// Endpoint handler function enum.
/// Holds either a `Packet` handler or a packed byte-slice handler.
/// /// - Packet handler signature: `Fn(&Packet) -> TelemetryResult<()>`
/// /// - Packed handler signature: `Fn(&[u8]) -> TelemetryResult<()>`
#[derive(Clone)]
pub enum EndpointHandlerFn {
    Packet(Arc<PacketHandlerFn>),
    Packed(Arc<PackedHandlerFn>),
}

/// Endpoint handler for a specific data endpoint.
pub struct EndpointHandler {
    endpoint: DataEndpoint,
    handler: EndpointHandlerFn,
}

/// Debug implementation for EndpointHandlerFn.
impl Debug for EndpointHandlerFn {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EndpointHandlerFn::Packet(_) => f.write_str("EndpointHandlerFn::Packet(<handler>)"),
            EndpointHandlerFn::Packed(_) => f.write_str("EndpointHandlerFn::Packed(<handler>)"),
        }
    }
}

/// TX handler for a router side: either packed or packet-based.
#[derive(Clone)]
pub enum RouterTxHandlerFn {
    Packed(Arc<PackedHandlerFn>),
    PackedWithPriority(Arc<PrioritizedPackedHandlerFn>),
    Packet(Arc<PacketHandlerFn>),
}

impl Debug for RouterTxHandlerFn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RouterTxHandlerFn::Packed(_) => f.debug_tuple("Packed").field(&"<handler>").finish(),
            RouterTxHandlerFn::PackedWithPriority(_) => f
                .debug_tuple("PackedWithPriority")
                .field(&"<handler>")
                .finish(),
            RouterTxHandlerFn::Packet(_) => f.debug_tuple("Packet").field(&"<handler>").finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RouterSideOptions {
    /// Enables the router's per-link reliable transport layer on this side.
    ///
    /// When `true` and the side uses a packed TX handler, reliable schema types gain
    /// sequence numbers, ACKs, packet requests, and retransmits on this specific hop.
    /// When `false`, the router strips the reliable framing for that side and sends only the
    /// application packet payload once.
    ///
    /// This setting only affects the hop between this router and the side's TX callback. It does
    /// not change whether a schema `DataType` is defined as reliable, and it does not disable the
    /// router's end-to-end reliable tracking for packets originated elsewhere in the network.
    pub reliable_enabled: bool,
    /// Marks the side as eligible for link-local-only endpoints and discovery routes.
    pub link_local_enabled: bool,
    /// Enables a side-local header-template dictionary for packed transport.
    ///
    /// The first frame for a stable header shape is sent in full. Later frames
    /// on the same side can replace the repeated static header bytes with a
    /// compact template hash plus only the fields that still vary packet to
    /// packet.
    pub header_template_enabled: bool,
    /// Maximum number of bytes to emit per packed TX callback.
    ///
    /// When non-zero and a wrapped packed frame would exceed this size, the
    /// router splits it into ordered chunks and reassembles those chunks on RX
    /// before normal packet processing.
    pub max_frame_bytes: usize,
    /// Target total side-transport overhead for compact follow-up frames.
    ///
    /// This is a profiling/negotiation target rather than a hard limit. The
    /// canonical packet is still reconstructed before normal router handling,
    /// so constrained links should watch runtime stats to confirm compact
    /// frames are meeting their IPv4/IPv6-like overhead budget.
    pub compact_header_target_bytes: usize,
    /// Maximum side-local header templates retained for TX and RX dictionaries.
    ///
    /// This keeps compact-link state bounded. When the dictionary is full, the
    /// oldest deterministic entry is evicted and a later packet with that
    /// shape will refresh the receiver with a full template frame.
    pub max_side_transport_templates: usize,
    /// Omits the timestamp field from compact follow-up frames when it is unchanged.
    ///
    /// The receiver reconstructs the canonical packet from the previous timestamp for that
    /// side-local template. This is only used after a full or compact frame has established
    /// timestamp context.
    pub omit_unchanged_compact_timestamps: bool,
    /// Optional per-data-type timestamp omission policy for compact follow-up frames.
    ///
    /// This allows a side to omit unchanged timestamps only for selected traffic while keeping
    /// absolute/delta timestamps for other data types on the same link.
    pub compact_timestamp_omission_types: CompactTimestampOmissionPolicy,
    /// Declared compact-link profile for stats and future negotiation.
    pub side_transport_profile: SideTransportProfile,
    /// Allows packets received from this side to enter router processing.
    pub ingress_enabled: bool,
    /// Allows the router to transmit packets toward this side.
    pub egress_enabled: bool,
}

impl Default for RouterSideOptions {
    fn default() -> Self {
        Self {
            reliable_enabled: false,
            link_local_enabled: false,
            header_template_enabled: false,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT,
            omit_unchanged_compact_timestamps: false,
            compact_timestamp_omission_types: CompactTimestampOmissionPolicy::none(),
            side_transport_profile: SideTransportProfile::Canonical,
            ingress_enabled: true,
            egress_enabled: true,
        }
    }
}

impl RouterSideOptions {
    /// Convenience preset for compact packed-side transport.
    ///
    /// This enables header-template reuse and, when `max_frame_bytes > 0`,
    /// router-managed chunking/reassembly for fixed-size transports.
    #[inline]
    pub fn with_small_packet_transport(mut self, max_frame_bytes: usize) -> Self {
        self.header_template_enabled = true;
        self.max_frame_bytes = max_frame_bytes;
        self.compact_header_target_bytes = IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES;
        self.side_transport_profile = SideTransportProfile::Ipv6Like;
        self
    }

    #[inline]
    pub fn with_ipv4_like_compact_header_target(mut self) -> Self {
        self.header_template_enabled = true;
        self.compact_header_target_bytes = IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES;
        self.omit_unchanged_compact_timestamps = true;
        self.side_transport_profile = SideTransportProfile::Ipv4Like;
        self
    }

    #[inline]
    pub fn with_ipv6_like_compact_header_target(mut self) -> Self {
        self.header_template_enabled = true;
        self.compact_header_target_bytes = IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES;
        self.side_transport_profile = SideTransportProfile::Ipv6Like;
        self
    }

    #[inline]
    pub fn with_template_transport(mut self) -> Self {
        self.header_template_enabled = true;
        self.side_transport_profile = SideTransportProfile::Template;
        self
    }

    #[inline]
    pub fn with_omitted_unchanged_compact_timestamps(mut self) -> Self {
        self.header_template_enabled = true;
        self.omit_unchanged_compact_timestamps = true;
        self
    }

    #[inline]
    pub fn with_omitted_unchanged_compact_timestamps_for_type(mut self, ty: DataType) -> Self {
        self.header_template_enabled = true;
        self.compact_timestamp_omission_types.insert(ty);
        self
    }

    #[inline]
    pub fn effective_transport_profile(&self) -> SideTransportProfile {
        if !self.header_template_enabled && self.max_frame_bytes == 0 {
            SideTransportProfile::Canonical
        } else if self.side_transport_profile == SideTransportProfile::Canonical {
            SideTransportProfile::Template
        } else {
            self.side_transport_profile
        }
    }

    #[cfg(feature = "discovery")]
    #[inline]
    pub fn link_capabilities(&self) -> discovery::LinkCapabilities {
        let mut flags = discovery::LINK_CAPABILITY_END_TO_END_RELIABILITY;
        if self.header_template_enabled {
            flags |= discovery::LINK_CAPABILITY_HEADER_TEMPLATES;
        }
        if self.max_frame_bytes != 0 {
            flags |= discovery::LINK_CAPABILITY_CHUNKING;
        }
        if self.reliable_enabled {
            flags |= discovery::LINK_CAPABILITY_RELIABILITY;
        }
        if self.omit_unchanged_compact_timestamps
            || !self.compact_timestamp_omission_types.is_empty()
        {
            flags |= discovery::LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS;
        }
        #[cfg(feature = "cryptography")]
        {
            flags |= discovery::LINK_CAPABILITY_CRYPTO;
        }
        #[cfg(feature = "compression")]
        {
            flags |= discovery::LINK_CAPABILITY_PAYLOAD_COMPRESSION;
        }
        discovery::LinkCapabilities {
            version: 1,
            flags,
            profile: self.effective_transport_profile().discovery_code(),
            max_frame_bytes: self.max_frame_bytes.min(u32::MAX as usize) as u32,
            compact_header_target_bytes: self.compact_header_target_bytes.min(u32::MAX as usize)
                as u32,
            max_side_transport_templates: self.max_side_transport_templates.min(u32::MAX as usize)
                as u32,
        }
    }
}

/// One side of the router – a name + TX handler.
#[derive(Clone, Debug)]
pub struct RouterSide {
    pub name: Arc<str>,
    pub tx_handler: RouterTxHandlerFn,
    pub opts: RouterSideOptions,
}

/// Debug implementation for EndpointHandler.
impl Debug for EndpointHandler {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointHandler")
            .field("endpoint", &self.endpoint)
            .field("handler", &self.handler)
            .finish()
    }
}

#[inline]
pub(crate) const fn endpoint_is_router_internal(endpoint: DataEndpoint) -> bool {
    #[cfg(feature = "timesync")]
    if matches!(endpoint, DataEndpoint::TimeSync) {
        return true;
    }
    #[cfg(feature = "discovery")]
    {
        discovery::is_discovery_endpoint(endpoint)
    }
    #[cfg(not(feature = "discovery"))]
    {
        let _ = endpoint;
        false
    }
}

impl EndpointHandler {
    /// Create a new endpoint handler for `Packet` callbacks.
    ///
    /// Handler signature is `Fn(&Packet) -> TelemetryResult<()>`.
    #[inline]
    pub fn new_packet_handler<F>(endpoint: DataEndpoint, f: F) -> Self
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        assert!(
            !endpoint_is_router_internal(endpoint),
            "reserved internal endpoint handlers must not be user-registered"
        );
        #[cfg(feature = "std")]
        crate::config::ensure_endpoint_id(endpoint, false)
            .expect("endpoint handler endpoint registration failed");
        Self {
            endpoint,
            handler: EndpointHandlerFn::Packet(Arc::new(f)),
        }
    }

    /// Create a new packet handler from a runtime endpoint definition.
    #[inline]
    #[cfg(feature = "std")]
    pub fn new_packet_handler_for<F>(endpoint: crate::config::OwnedEndpointDefinition, f: F) -> Self
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        Self::new_packet_handler(endpoint.id, f)
    }

    /// Create a new packet handler from a static endpoint definition.
    #[cfg(not(feature = "std"))]
    #[inline]
    pub fn new_packet_handler_for<F>(endpoint: crate::config::EndpointDefinition, f: F) -> Self
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        Self::new_packet_handler(endpoint.id, f)
    }

    /// Create a new packet handler by endpoint name.
    #[cfg(feature = "std")]
    #[inline]
    pub fn new_packet_handler_by_name<F>(endpoint_name: &str, f: F) -> TelemetryResult<Self>
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let endpoint = crate::config::endpoint_definition_by_name(endpoint_name)
            .ok_or(TelemetryError::BadArg)?;
        Ok(Self::new_packet_handler(endpoint.id, f))
    }

    /// Create a new endpoint handler for packed byte-slice callbacks.
    ///
    /// Handler signature is `Fn(&[u8]) -> TelemetryResult<()>`.
    #[inline]
    pub fn new_packed_handler<F>(endpoint: DataEndpoint, f: F) -> Self
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        assert!(
            !endpoint_is_router_internal(endpoint),
            "reserved internal endpoint handlers must not be user-registered"
        );
        #[cfg(feature = "std")]
        crate::config::ensure_endpoint_id(endpoint, false)
            .expect("endpoint handler endpoint registration failed");
        Self {
            endpoint,
            handler: EndpointHandlerFn::Packed(Arc::new(f)),
        }
    }

    /// Create a new packed handler from a runtime endpoint definition.
    #[inline]
    pub fn new_packed_handler_for<F>(endpoint: crate::config::EndpointDefinition, f: F) -> Self
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        Self::new_packed_handler(endpoint.id, f)
    }

    /// Create a new packed handler by endpoint name.
    #[cfg(feature = "std")]
    #[inline]
    pub fn new_packed_handler_by_name<F>(endpoint_name: &str, f: F) -> TelemetryResult<Self>
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let endpoint = crate::config::endpoint_definition_by_name(endpoint_name)
            .ok_or(TelemetryError::BadArg)?;
        Ok(Self::new_packed_handler(endpoint.id, f))
    }

    /// Return the endpoint that the handler is registered for.
    #[inline]
    pub fn get_endpoint(&self) -> DataEndpoint {
        self.endpoint
    }

    /// Return a reference to the handler function.
    #[inline]
    pub fn get_handler(&self) -> &EndpointHandlerFn {
        &self.handler
    }
}

pub trait Clock {
    /// Return the current time in milliseconds.
    fn now_ms(&self) -> u64;

    /// Return the current time in nanoseconds.
    ///
    /// The default implementation derives this from [`Clock::now_ms`].
    fn now_ns(&self) -> u64 {
        self.now_ms().saturating_mul(1_000_000)
    }
}

impl<T: Fn() -> u64> Clock for T {
    #[inline]
    fn now_ms(&self) -> u64 {
        self()
    }
}

#[cfg(feature = "std")]
#[derive(Debug)]
struct StdMonotonicClock {
    start: Instant,
}

#[cfg(feature = "std")]
impl Default for StdMonotonicClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

#[cfg(feature = "std")]
impl Clock for StdMonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn now_ns(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Router-level E2E cryptography behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterE2eEncryptionMode {
    /// Do not use E2E cryptography. Data types marked `RequireOn` are rejected.
    Disabled,
    /// Use E2E cryptography only for data types that require it.
    RequiredOnly,
    /// Use E2E cryptography for required and preferred data types.
    Preferred,
    /// Require E2E cryptography for every non-control data type.
    ForceAll,
}

pub type NodeAddress = u32;
pub type P2pPort = u16;
pub type P2pStreamId = u32;

const P2P_STREAM_MAGIC: [u8; 4] = *b"SDSP";
const P2P_STREAM_VERSION: u8 = 1;
const P2P_STREAM_SYN: u8 = 0x01;
const P2P_STREAM_ACK: u8 = 0x02;
const P2P_STREAM_FIN: u8 = 0x04;
const P2P_STREAM_RST: u8 = 0x08;
const P2P_STREAM_DATA: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressAssignmentMode {
    Dynamic,
    Requested(NodeAddress),
    Static(NodeAddress),
}

impl AddressAssignmentMode {
    #[inline]
    #[cfg(feature = "discovery")]
    fn mode_code(self) -> u8 {
        match self {
            Self::Dynamic => 0,
            Self::Requested(_) => 1,
            Self::Static(_) => 2,
        }
    }

    #[inline]
    fn requested_address(self) -> NodeAddress {
        match self {
            Self::Dynamic => 0,
            Self::Requested(addr) | Self::Static(addr) => addr,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressChangeReason {
    Configured,
    DynamicConflict,
    RequestedConflict,
    StaticConflict,
    HostnameConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressChange {
    pub old_hostname: Arc<str>,
    pub new_hostname: Arc<str>,
    pub old_address: NodeAddress,
    pub new_address: NodeAddress,
    pub reason: AddressChangeReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBookEntry {
    pub hostname: Arc<str>,
    pub address: NodeAddress,
    pub requested_address: NodeAddress,
    pub mode: AddressAssignmentMode,
    pub birth_ms: u64,
    pub owner_hash: u64,
    pub last_seen_ms: u64,
}

pub struct P2pMessage<'a> {
    pub source_hostname: &'a str,
    pub source_address: NodeAddress,
    pub source_port: P2pPort,
    pub destination_port: P2pPort,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pStreamEventKind {
    Accepted,
    Connected,
    Data,
    Closed,
    Reset,
}

pub struct P2pStreamEvent<'a> {
    pub kind: P2pStreamEventKind,
    pub stream_id: P2pStreamId,
    pub peer_stream_id: P2pStreamId,
    pub sequence: u32,
    pub peer_hostname: &'a str,
    pub peer_address: NodeAddress,
    pub local_port: P2pPort,
    pub peer_port: P2pPort,
    pub payload: &'a [u8],
}

struct P2pDecoded<'a> {
    source_hostname: &'a str,
    source_address: NodeAddress,
    source_port: P2pPort,
    destination_port: P2pPort,
    payload: &'a [u8],
}

#[derive(Debug, Clone)]
struct P2pStreamDecoded<'a> {
    flags: u8,
    source_stream_id: P2pStreamId,
    destination_stream_id: P2pStreamId,
    sequence: u32,
    payload: &'a [u8],
}

type AddressChangeFn = dyn Fn(AddressChange) -> TelemetryResult<()> + Send + Sync + 'static;

#[derive(Clone)]
struct AddressChangeHandler {
    handler: Arc<AddressChangeFn>,
}

impl Debug for AddressChangeHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("AddressChangeHandler(<handler>)")
    }
}

type P2pPortHandlerFn = dyn Fn(P2pMessage<'_>) -> TelemetryResult<()> + Send + Sync + 'static;

#[derive(Clone)]
struct P2pPortHandler {
    handler: Arc<P2pPortHandlerFn>,
}

impl Debug for P2pPortHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("P2pPortHandler(<handler>)")
    }
}

type P2pStreamHandlerFn = dyn Fn(P2pStreamEvent<'_>) -> TelemetryResult<()> + Send + Sync + 'static;

#[derive(Clone)]
struct P2pStreamHandler {
    handler: Arc<P2pStreamHandlerFn>,
}

impl Debug for P2pStreamHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("P2pStreamHandler(<handler>)")
    }
}

#[derive(Debug, Clone)]
struct P2pStreamSession {
    peer_hostname: Arc<str>,
    peer_address: NodeAddress,
    local_port: P2pPort,
    peer_port: P2pPort,
    peer_stream_id: P2pStreamId,
    next_sequence: u32,
    connected: bool,
}

#[derive(Debug, Clone)]
struct PendingP2pStreamEvent {
    handlers: Vec<P2pStreamHandler>,
    kind: P2pStreamEventKind,
    stream_id: P2pStreamId,
    peer_stream_id: P2pStreamId,
    peer_hostname: Arc<str>,
    peer_address: NodeAddress,
    local_port: P2pPort,
    peer_port: P2pPort,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Handlers for local endpoints.
    handlers: Arc<[EndpointHandler]>,
    /// Whether to enable reliable ordering/ACKs for reliable data types.
    reliable_enabled: bool,
    /// Optional per-router sender override.
    sender: Option<Arc<str>>,
    /// Address assignment policy used for P2P routing.
    address_mode: AddressAssignmentMode,
    /// Callbacks invoked when conflict resolution changes this router's identity.
    address_change_handlers: Arc<[AddressChangeHandler]>,
    /// End-to-end cryptography behavior for user data.
    e2e_encryption: RouterE2eEncryptionMode,
    /// Application-defined key id passed to the cryptography provider.
    #[cfg_attr(not(feature = "cryptography"), allow(dead_code))]
    e2e_key_id: u32,
    memory: RuntimeMemoryConfig,
    #[cfg(feature = "discovery")]
    preferred_discovery_master: Option<Arc<str>>,
    #[cfg(feature = "timesync")]
    timesync: Option<TimeSyncConfig>,
}

impl RouterConfig {
    /// Default router E2E mode for this build.
    ///
    /// Builds with cryptography prefer encrypted payloads automatically for data types that request
    /// it. Minimal builds without cryptography stay disabled and reject `RequireOn` traffic.
    pub fn default_e2e_encryption_mode() -> RouterE2eEncryptionMode {
        #[cfg(feature = "cryptography")]
        {
            RouterE2eEncryptionMode::Preferred
        }
        #[cfg(not(feature = "cryptography"))]
        {
            RouterE2eEncryptionMode::Disabled
        }
    }

    /// Create a new router configuration with the specified local endpoint handlers.
    pub fn new<H>(handlers: H) -> Self
    where
        H: Into<Arc<[EndpointHandler]>>,
    {
        let handlers: Arc<[EndpointHandler]> = handlers.into();
        assert!(
            handlers
                .iter()
                .all(|handler| !endpoint_is_router_internal(handler.endpoint)),
            "reserved internal endpoint handlers must not be user-registered"
        );
        Self {
            handlers,
            reliable_enabled: true,
            sender: None,
            address_mode: AddressAssignmentMode::Dynamic,
            address_change_handlers: Arc::from([]),
            e2e_encryption: Self::default_e2e_encryption_mode(),
            e2e_key_id: 0,
            memory: RuntimeMemoryConfig::default(),
            #[cfg(feature = "discovery")]
            preferred_discovery_master: None,
            #[cfg(feature = "timesync")]
            timesync: None,
        }
    }

    /// Enable or disable reliable delivery for this router instance.
    pub fn with_reliable_enabled(mut self, enabled: bool) -> Self {
        self.reliable_enabled = enabled;
        self
    }

    /// Override the sender identifier for this router instance.
    pub fn with_sender<S: AsRef<str>>(mut self, sender: S) -> Self {
        self.sender = Some(Arc::from(sender.as_ref()));
        self
    }

    /// Alias for `with_sender`; discovery uses this name for P2P service resolution.
    pub fn with_hostname<S: AsRef<str>>(self, hostname: S) -> Self {
        self.with_sender(hostname)
    }

    /// Request a dynamic address assigned by the discovered network authority.
    pub fn with_dynamic_address(mut self) -> Self {
        self.address_mode = AddressAssignmentMode::Dynamic;
        self
    }

    /// Request a preferred address. It is kept when unique and reassigned on conflict.
    pub fn with_requested_address(mut self, address: NodeAddress) -> Self {
        self.address_mode = AddressAssignmentMode::Requested(address);
        self
    }

    /// Require a static address. If two static nodes conflict, the oldest keeps it.
    pub fn with_static_address(mut self, address: NodeAddress) -> Self {
        self.address_mode = AddressAssignmentMode::Static(address);
        self
    }

    /// Register a callback for local address or hostname changes after conflict resolution.
    pub fn on_address_change<F>(mut self, f: F) -> Self
    where
        F: Fn(AddressChange) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut handlers = self.address_change_handlers.to_vec();
        handlers.push(AddressChangeHandler {
            handler: Arc::new(f),
        });
        self.address_change_handlers = Arc::from(handlers);
        self
    }

    /// Configure this router's end-to-end cryptography policy.
    pub fn with_e2e_encryption(mut self, mode: RouterE2eEncryptionMode) -> Self {
        self.e2e_encryption = mode;
        self
    }

    /// Configure the application-defined key id used for E2E encrypted payloads.
    pub fn with_e2e_key_id(mut self, key_id: u32) -> Self {
        self.e2e_key_id = key_id;
        self
    }

    /// Override per-router queue and dedupe memory limits.
    pub fn with_memory_config(mut self, memory: RuntimeMemoryConfig) -> TelemetryResult<Self> {
        memory.validate()?;
        self.memory = memory;
        Ok(self)
    }

    /// Prefer a named router as discovery master whenever it is visible.
    ///
    /// All routers in a deployment should use the same preference. If that
    /// router is absent, normal topology-based election is used. Discovery
    /// leadership remains independent from time-sync source priority.
    #[cfg(feature = "discovery")]
    pub fn with_preferred_discovery_master<S: AsRef<str>>(mut self, hostname: S) -> Self {
        let hostname = hostname.as_ref();
        self.preferred_discovery_master = if hostname.is_empty() {
            None
        } else {
            Some(Arc::from(hostname))
        };
        self
    }

    #[cfg(feature = "timesync")]
    /// Enables and configures built-in time synchronization for this router.
    pub fn with_timesync(mut self, cfg: TimeSyncConfig) -> Self {
        self.timesync = Some(cfg);
        self
    }

    #[inline]
    /// Check if the specified endpoint is local to this router.
    fn is_local_endpoint(&self, ep: DataEndpoint) -> bool {
        if endpoint_is_router_internal(ep) {
            return false;
        }
        self.handlers.iter().any(|h| h.endpoint == ep)
    }

    #[inline]
    fn reliable_enabled(&self) -> bool {
        self.reliable_enabled
    }

    #[inline]
    fn sender(&self) -> String {
        self.sender
            .as_deref()
            .map(ToString::to_string)
            .unwrap_or_else(runtime_device_identifier)
    }

    #[inline]
    fn address_mode(&self) -> AddressAssignmentMode {
        self.address_mode
    }

    #[inline]
    fn e2e_encryption(&self) -> RouterE2eEncryptionMode {
        self.e2e_encryption
    }

    #[cfg(feature = "cryptography")]
    #[inline]
    fn e2e_key_id(&self) -> u32 {
        self.e2e_key_id
    }

    #[cfg(feature = "timesync")]
    #[inline]
    fn timesync_config(&self) -> Option<TimeSyncConfig> {
        self.timesync
    }

    #[inline]
    fn memory_config(&self) -> RuntimeMemoryConfig {
        self.memory
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            handlers: Arc::from([]),
            reliable_enabled: true,
            sender: None,
            address_mode: AddressAssignmentMode::Dynamic,
            address_change_handlers: Arc::from([]),
            e2e_encryption: Self::default_e2e_encryption_mode(),
            e2e_key_id: 0,
            memory: RuntimeMemoryConfig::default(),
            #[cfg(feature = "discovery")]
            preferred_discovery_master: None,
            #[cfg(feature = "timesync")]
            timesync: None,
        }
    }
}

// -------------------- generic little-endian serialization --------------------

pub trait LeBytes: Copy + Sized {
    const WIDTH: usize;
    fn write_le(self, out: &mut [u8]);
    fn from_le_slice(bytes: &[u8]) -> Self;
}

impl_letype_num!(u8, 1);
impl_letype_num!(u16, 2);
impl_letype_num!(u32, 4);
impl_letype_num!(u64, 8);
impl_letype_num!(u128, 16);
impl_letype_num!(i8, 1);
impl_letype_num!(i16, 2);
impl_letype_num!(i32, 4);
impl_letype_num!(i64, 8);
impl_letype_num!(i128, 16);
impl_letype_num!(f32, 4);
impl_letype_num!(f64, 8);

/// Encode a slice of `LeBytes` into a contiguous little-endian byte array.
pub(crate) fn encode_slice_le<T: LeBytes>(data: &[T]) -> Arc<[u8]> {
    let total = data.len() * T::WIDTH;
    let mut buf = vec![0u8; total];

    for (i, v) in data.iter().copied().enumerate() {
        let start = i * T::WIDTH;
        v.write_le(&mut buf[start..start + T::WIDTH]);
    }

    Arc::from(buf)
}

/// Build an error payload for `TelemetryError` packets, respecting the
/// static/dynamic sizing rules from `message_meta`.
fn make_error_payload(msg: &str) -> crate::SharedBytes {
    let meta = message_meta(DataType::TelemetryError);
    match meta.element {
        MessageElement::Static(_, _, _) => {
            let max = get_needed_message_size(DataType::TelemetryError);
            let bytes = msg.as_bytes();
            let n = core::cmp::min(max, bytes.len());
            let mut buf = vec![0u8; max];
            if n > 0 {
                buf[..n].copy_from_slice(&bytes[..n]);
            }
            crate::shared_bytes::convert(Arc::<[u8]>::from(buf))
        }
        MessageElement::Dynamic(_, _) => {
            crate::shared_bytes::convert(Arc::<[u8]>::from(msg.as_bytes()))
        }
    }
}

/// Generic raw logger function used by Router::log and Router::log_queue.
/// Builds a Packet from the provided data slice and passes it to the
/// provided transmission function.
fn log_raw<T, F>(
    sender: Arc<str>,
    ty: DataType,
    data: &[T],
    timestamp: u64,
    mut tx_function: F,
) -> TelemetryResult<()>
where
    T: LeBytes,
    F: FnMut(Packet) -> TelemetryResult<()>,
{
    let meta = message_meta(ty);
    let got = data
        .len()
        .checked_mul(T::WIDTH)
        .ok_or(TelemetryError::PacketTooLarge(
            "typed payload size overflow",
        ))?;
    if T::WIDTH == 0 {
        return Err(TelemetryError::BadArg);
    }

    match meta.element {
        MessageElement::Static(_, _, _) => {
            let expected = crate::data_type_size(meta.element.data_type()) * meta.element;
            if got != expected {
                return Err(TelemetryError::SizeMismatch { expected, got });
            }
        }
        MessageElement::Dynamic(_, _) => {
            // checked_mul above already formed a whole number of typed values.
            // Packet construction still validates the actual schema encoding.
        }
    }

    const INLINE_ENCODE_BYTES: usize = if crate::config::STACK_PAYLOAD_SIZE < u8::MAX as usize {
        crate::config::STACK_PAYLOAD_SIZE
    } else {
        u8::MAX as usize
    };
    let payload = if got <= INLINE_ENCODE_BYTES {
        // Bounded by the same configured inline capacity as Packet. Tiny C/Rust
        // publications need neither a temporary Vec nor a payload Arc.
        let mut bytes = [0u8; INLINE_ENCODE_BYTES];
        for (value, destination) in data
            .iter()
            .copied()
            .zip(bytes[..got].chunks_exact_mut(T::WIDTH))
        {
            value.write_le(destination);
        }
        crate::config::StandardSmallPayload::new(&bytes[..got])
    } else {
        crate::config::StandardSmallPayload::from_arc(encode_slice_le(data))
    };
    let pkt = Packet::new_local(ty, meta.endpoints_owned(), sender, timestamp, payload)?;
    tx_function(pkt)
}

// Hosted diagnostics only: no trace branches, formatting or storage on MCUs.
#[cfg(feature = "std")]
fn reliable_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("SEDSNET_TRACE_RELIABLE").as_deref(),
            Ok("1" | "true")
        )
    })
}

/// Fallback printing for error messages when no local endpoints exist.
/// - With `std`: prints to stderr.
/// - Without `std`: forwards to `seds_error_msg` (platform-provided).
fn fallback_stdout(_msg: &str) {
    #[cfg(feature = "std")]
    {
        eprintln!("{}", _msg);
    }
    #[cfg(all(not(feature = "std"), target_os = "none"))]
    {
        // The length-delimited platform callback owns presentation. Forward
        // the existing message without allocating while reporting an error.
        unsafe {
            seds_error_msg(_msg.as_ptr(), _msg.len());
        }
    }
}

// -------------------- Router --------------------

/// Internal mutable state of the Router, protected by `RouterMutex`.
/// Holds the RX/TX queues and the recent-RX de-duplication set.
#[derive(Debug, Clone)]
struct RouterInner {
    #[cfg(feature = "compression")]
    codec_reserved_bytes: usize,
    memory: RuntimeMemoryConfig,
    sides: Vec<Option<RouterSide>>,
    route_overrides: RouterMap<(Option<RouterSideId>, RouterSideId), bool>,
    typed_route_overrides: RouterMap<(Option<RouterSideId>, u32, RouterSideId), bool>,
    route_weights: RouterMap<(Option<RouterSideId>, RouterSideId), u32>,
    route_priorities: RouterMap<(Option<RouterSideId>, RouterSideId), u32>,
    source_route_modes: RouterMap<Option<RouterSideId>, RouteSelectionMode>,
    route_selection_cursors: RouterMap<Option<RouterSideId>, u64>,
    adaptive_route_stats: RouterMap<RouterSideId, AdaptiveRouteStats>,
    // Own each large side value once and keep sparse index entries pointer-sized.
    // Embedded side indexes use compact sorted vectors; desktop indexes use B-trees.
    side_runtime_stats: RouterMap<RouterSideId, Box<SideRuntimeStatsInner>>,
    side_transport: RouterMap<RouterSideId, Box<SideTransportState>>,
    managed_variable_types: BTreeSet<u32>,
    managed_variable_permissions: BTreeMap<u32, NetworkVariablePermissions>,
    managed_variable_latest: BTreeMap<u32, Box<ManagedVariableCacheEntry>>,
    network_variable_update_handlers: BTreeMap<u32, Vec<NetworkVariableUpdateHandler>>,
    local_address: AddressBookEntry,
    address_book: BTreeMap<String, AddressBookEntry>,
    address_by_value: BTreeMap<NodeAddress, String>,
    p2p_port_handlers: BTreeMap<P2pPort, Vec<P2pPortHandler>>,
    p2p_stream_handlers: BTreeMap<P2pPort, Vec<P2pStreamHandler>>,
    p2p_stream_sessions: BTreeMap<P2pStreamId, P2pStreamSession>,
    next_p2p_stream_id: P2pStreamId,
    received_queue: BoundedDeque<RouterRxItem>,
    transmit_queue: BoundedDeque<TxQueued>,
    tx_priority_burst: u8,
    has_ordered_retry: bool,
    ordered_claim_seq: u32,
    rx_priority_burst: u8,
    recent_rx: BoundedDeque<u64>,
    reliable_tx: BTreeMap<(RouterSideId, u32), ReliableTxState>,
    reliable_rx: BTreeMap<(RouterSideId, u32), ReliableRxState>,
    reliable_return_routes: BTreeMap<u64, ReliableReturnRouteState>,
    reliable_return_route_order: VecDeque<u64>,
    end_to_end_reliable_tx: BTreeMap<u64, EndToEndReliableSent>,
    end_to_end_reliable_tx_order: VecDeque<u64>,
    total_handler_failures: u64,
    total_handler_retries: u64,
    #[cfg(feature = "discovery")]
    discovery_routes: RouterMap<RouterSideId, DiscoverySideState>,
    #[cfg(feature = "discovery")]
    discovery_cadence: DiscoveryCadenceState,
    #[cfg(feature = "discovery")]
    discovery_side_throttle: RouterMap<RouterSideId, DiscoverySideThrottleState>,
    #[cfg(feature = "discovery")]
    preferred_discovery_master: Option<Arc<str>>,
    #[cfg(all(feature = "discovery", feature = "timesync"))]
    timesync_side_throttle: RouterMap<RouterSideId, TimeSyncSideThrottleState>,
}

#[derive(Debug, Clone)]
struct ManagedVariableCacheEntry {
    packet: Packet,
    sender_address: u32,
    #[cfg(feature = "discovery")]
    cached_at_ms: u64,
}

type NetworkVariableUpdateFn = dyn Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static;

#[derive(Clone)]
struct NetworkVariableUpdateHandler {
    handler: Arc<NetworkVariableUpdateFn>,
}

impl Debug for NetworkVariableUpdateHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkVariableUpdateHandler(<handler>)")
    }
}

/// Local permission policy for a network-managed variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkVariablePermissions {
    pub read: bool,
    pub write: bool,
}

impl NetworkVariablePermissions {
    pub const NONE: Self = Self {
        read: false,
        write: false,
    };
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
    };
    pub const WRITE_ONLY: Self = Self {
        read: false,
        write: true,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouterQueueKind {
    Received,
    Transmit,
}

#[cfg(feature = "compression")]
impl crate::payload_codec::QueueBudget for RouterInner {
    fn codec_reserved(&mut self) -> &mut usize {
        &mut self.codec_reserved_bytes
    }
    fn codec_used(&self) -> usize {
        self.shared_queue_bytes_used()
    }
    fn codec_limit(&self) -> usize {
        self.memory.max_queue_budget
    }
}

impl RouterInner {
    #[cfg(all(feature = "compression", feature = "discovery"))]
    fn reclaim_codec_metadata(&mut self) -> bool {
        self.side_transport.values_mut().any(|transport| {
            transport
                .payload_codec
                .evict_for_budget(DISCOVERY_ROUTE_TTL_MS)
        })
    }

    /// Prepare required plaintext before publishing its queue owner. The state
    /// lock prevents another producer taking the checked expanded byte credit.
    /// A refused optional preparation leaves the original accepted work owned;
    /// dispatch will backpressure it until the required decoder scratch fits.
    #[cfg(feature = "compression")]
    fn prepare_codec_queue_owner(&mut self, side: Option<usize>, data: &mut RouterItem) {
        let RouterItem::Packed(bytes) = data else {
            return;
        };
        if !bytes.first().is_some_and(|flags| flags & 0x11 == 1) {
            return;
        }
        let capable = {
            #[cfg(feature = "discovery")]
            {
                side.and_then(|side| self.side_transport.get(&side))
                    .is_some_and(|transport| {
                        transport.payload_codec.retention_can_stay_compressed()
                    })
            }
            #[cfg(not(feature = "discovery"))]
            {
                let _ = side;
                false
            }
        };
        if capable {
            return;
        }
        let Ok(required) = wire_format::decoded_frame_upper_bound(bytes.as_ref()) else {
            return;
        };
        if self
            .shared_queue_bytes_used()
            .checked_add(required)
            .and_then(|used| {
                used.checked_add(
                    size_of::<crate::SharedBytes>()
                        + size_of::<bool>()
                        + size_of::<u8>()
                        + size_of::<u64>(),
                )
            })
            .is_none_or(|used| used > self.memory.max_queue_budget)
        {
            return;
        }
        if let Ok(Some(raw)) = wire_format::payload_encoding_for_retention(
            bytes.as_ref(),
            self.memory.max_queue_budget,
        ) {
            *bytes = crate::shared_bytes::convert(raw);
        }
    }

    fn retain_transmit<F>(&mut self, keep: F)
    where
        F: FnMut(&TxQueued) -> bool,
    {
        let hop = &mut self.reliable_tx;
        let end = &mut self.end_to_end_reliable_tx;
        self.transmit_queue.retain_observed(keep, |evicted| {
            if let Some(key) = evicted.item.replay_marker_key() {
                Self::set_replay_queued(hop, end, key, false);
            }
        });
    }

    #[inline(never)]
    fn claim_index(&self, token: u32) -> Option<usize> {
        self.transmit_queue.iter().position(|item| {
            matches!(
                item.delivery_state,
                QueuedDelivery::ClaimedOrdered | QueuedDelivery::ClaimedUnordered
            ) && item.deferred_since_ms == u64::from(token)
        })
    }

    #[inline(never)]
    fn refresh_retry_hint(&mut self) {
        self.has_ordered_retry = self.transmit_queue.iter().any(|item| {
            matches!(
                item.delivery_state,
                QueuedDelivery::ClaimedOrdered
                    | QueuedDelivery::ClaimedUnordered
                    | QueuedDelivery::DeferredOrdered
            )
        });
    }

    fn cancel_accepted_type(&mut self, ty: u32) {
        self.retain_transmit(|item| {
            !matches!(&item.item,
            RouterTxItem::Broadcast(_) if item.accepted_type == ty)
        });
    }

    fn replay_is_queued(&self, key: ReplayMarkerKey) -> Option<bool> {
        match key {
            ReplayMarkerKey::EndToEnd(id) => self.end_to_end_reliable_tx.get(&id).map(|s| s.queued),
            ReplayMarkerKey::Hop(side, ty, seq) => self
                .reliable_tx
                .get(&(side, ty.as_u32()))
                .and_then(|tx| tx.sent.get(&seq))
                .map(|s| s.queued),
        }
    }
    fn set_replay_queued(
        hop: &mut BTreeMap<(RouterSideId, u32), ReliableTxState>,
        end: &mut BTreeMap<u64, EndToEndReliableSent>,
        key: ReplayMarkerKey,
        queued: bool,
    ) {
        let flag = match key {
            ReplayMarkerKey::EndToEnd(id) => end.get_mut(&id).map(|s| &mut s.queued),
            ReplayMarkerKey::Hop(side, ty, seq) => hop
                .get_mut(&(side, ty.as_u32()))
                .and_then(|tx| tx.sent.get_mut(&seq))
                .map(|s| &mut s.queued),
        };
        if let Some(flag) = flag {
            *flag = queued;
        }
    }

    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn fair_bulk_owner(data: &RouterItem, priority: u8) -> Option<u32> {
        match data {
            RouterItem::Packet(packet) => crate::admission_fairness::packet_owner(packet, priority),
            RouterItem::Packed(bytes) => crate::shared_bytes::with_slice(bytes, |view| {
                crate::admission_fairness::packed_owner(view, priority)
            })
            .ok()
            .flatten(),
        }
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn tx_bulk_owner(item: &TxQueued) -> Option<u32> {
        match &item.item {
            RouterTxItem::Broadcast(data) | RouterTxItem::ToSide { data, .. } => {
                Self::fair_bulk_owner(data, item.priority)
            }
            _ => None,
        }
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn bulk_stream(data: &RouterItem) -> Option<u32> {
        match data {
            RouterItem::Packet(packet) => Some(packet.data_type().as_u32()),
            RouterItem::Packed(bytes) => crate::shared_bytes::with_slice(bytes, |view| {
                wire_format::scheduling_type(view).map(|ty| ty.as_u32())
            })
            .ok()
            .flatten(),
        }
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn tx_bulk_stream(item: &TxQueued) -> Option<u32> {
        match &item.item {
            RouterTxItem::Broadcast(data) | RouterTxItem::ToSide { data, .. } => {
                Self::bulk_stream(data)
            }
            _ => None,
        }
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn bulk_loads(&self, priority: u8) -> crate::admission_fairness::Loads {
        let mut loads = crate::admission_fairness::Loads::new();
        for item in self.received_queue.iter() {
            if item.priority <= priority
                && let Some(owner) = Self::fair_bulk_owner(&item.data, item.priority)
            {
                loads.record(owner, item.byte_cost());
            }
        }
        for item in self.transmit_queue.iter() {
            if item.priority <= priority
                && let Some(owner) = Self::tx_bulk_owner(item)
            {
                loads.record(owner, item.byte_cost());
            }
        }
        loads
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn competing_bulk_owner(&self, incoming: u32, priority: u8) -> Option<u32> {
        self.bulk_loads(priority).dominant_other(incoming)
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn reclaim_bulk_from(
        &mut self,
        owner: u32,
        priority: u8,
        incoming_stream: Option<u32>,
    ) -> bool {
        let mut streams = crate::admission_fairness::Loads::new();
        for item in self.received_queue.iter() {
            if item.priority <= priority
                && Self::fair_bulk_owner(&item.data, item.priority) == Some(owner)
                && let Some(ty) = Self::bulk_stream(&item.data)
            {
                streams.record(ty, item.byte_cost());
            }
        }
        for item in self.transmit_queue.iter() {
            if item.priority <= priority
                && Self::tx_bulk_owner(item) == Some(owner)
                && let Some(ty) = Self::tx_bulk_stream(item)
            {
                streams.record(ty, item.byte_cost());
            }
        }
        let stream = streams.queue_victim(incoming_stream);
        let rx = self
            .received_queue
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.priority <= priority
                    && Self::fair_bulk_owner(&item.data, item.priority) == Some(owner)
                    && stream.is_none_or(|ty| Self::bulk_stream(&item.data) == Some(ty))
            })
            .min_by_key(|(index, item)| (item.priority, *index))
            .map(|(index, item)| (index, item.priority));
        let tx = self
            .transmit_queue
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.priority <= priority
                    && Self::tx_bulk_owner(item) == Some(owner)
                    && stream.is_none_or(|ty| Self::tx_bulk_stream(item) == Some(ty))
            })
            .min_by_key(|(index, item)| (item.priority, *index))
            .map(|(index, item)| (index, item.priority));
        match (rx, tx) {
            (Some((index, rp)), Some((_, tp))) if rp <= tp => {
                self.received_queue.remove_pos(index).is_some()
            }
            (Some((index, _)), None) => self.received_queue.remove_pos(index).is_some(),
            (_, Some((index, _))) => self.transmit_queue.remove_pos(index).is_some(),
            _ => false,
        }
    }

    #[cfg(feature = "discovery")]
    fn topology_board_byte_cost(board: &TopologyBoardNode) -> usize {
        board
            .sender_id
            .len()
            .saturating_add(board.reachable_endpoints.len() * size_of::<DataEndpoint>())
            .saturating_add(
                board
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .sum::<usize>(),
            )
            .saturating_add(board.connections.iter().map(|s| s.len()).sum::<usize>())
    }

    #[cfg(feature = "discovery")]
    fn discovery_sender_byte_cost(sender: &str, state: &DiscoverySenderState) -> usize {
        sender
            .len()
            .saturating_add(state.reachable.len() * size_of::<DataEndpoint>())
            .saturating_add(state.advertised_reachable.len() * size_of::<DataEndpoint>())
            .saturating_add(state.reachable_network_variables.len() * size_of::<DataType>())
            .saturating_add(
                state
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                state
                    .advertised_reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                state
                    .topology_boards
                    .iter()
                    .map(Self::topology_board_byte_cost)
                    .sum::<usize>(),
            )
            .saturating_add(size_of::<DiscoverySenderState>())
    }

    #[cfg(feature = "discovery")]
    fn discovery_route_byte_cost(side: RouterSideId, route: &DiscoverySideState) -> usize {
        size_of::<RouterSideId>()
            .saturating_add(size_of::<DiscoverySideState>())
            .saturating_add(route.reachable.len() * size_of::<DataEndpoint>())
            .saturating_add(route.reachable_network_variables.len() * size_of::<DataType>())
            .saturating_add(
                route.requested_network_variables.len()
                    * (size_of::<DataType>() + size_of::<u64>()),
            )
            .saturating_add(
                route
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                route
                    .announcers
                    .iter()
                    .map(|(sender, state)| Self::discovery_sender_byte_cost(sender, state))
                    .sum::<usize>(),
            )
            .saturating_add(side.saturating_sub(side))
    }

    #[cfg(feature = "discovery")]
    fn discovery_bytes_used(&self) -> usize {
        self.discovery_routes
            .iter()
            .map(|(side, route)| Self::discovery_route_byte_cost(*side, route))
            .sum()
    }

    #[inline]
    fn reliable_rx_buffered_bytes(&self) -> usize {
        self.reliable_rx
            .values()
            .flat_map(|state| state.buffered.values())
            .map(|bytes| size_of::<crate::SharedBytes>() + bytes.len())
            .sum()
    }

    fn reliable_rx_buffer_len(&self) -> usize {
        self.reliable_rx
            .values()
            .map(|state| state.buffered.len())
            .sum()
    }

    #[inline(never)]
    fn side_chunk_bytes_used(&self) -> usize {
        self.side_transport
            .values()
            .map(|side| side.rx_chunk_bytes)
            .sum()
    }
    fn discard_side_chunk(&mut self, side: RouterSideId, id: u32) -> bool {
        self.side_transport
            .get_mut(&side)
            .is_some_and(|state| state.take_chunk(id, true).is_some())
    }
    fn reclaim_oldest_side_chunk(&mut self, keep: Option<(RouterSideId, u32)>) -> bool {
        let mut victim = None;
        let mut time = u64::MAX;
        for (&side, state) in &self.side_transport {
            let preserved = match keep {
                Some((owner, id)) if owner == side => Some(id),
                _ => None,
            };
            if let Some((id, seen)) = SideChunkAssembly::oldest(&state.rx_chunks, preserved)
                && (victim.is_none() || seen < time)
            {
                time = seen;
                victim = Some((side, id));
            }
        }
        match victim {
            Some((side, id)) => self.discard_side_chunk(side, id),
            None => false,
        }
    }
    fn make_side_chunk_room(
        &mut self,
        side: RouterSideId,
        id: u32,
        index: u16,
        total: u16,
        payload_len: usize,
    ) -> TelemetryResult<()> {
        let budget = self
            .memory
            .max_queue_budget
            .saturating_sub(self.protected_metadata_bytes_used());
        let state = self
            .side_transport
            .get_mut(&side)
            .ok_or(TelemetryError::BadArg)?;
        let existing = state.rx_chunks.get(&id).map(|a| a.total);
        if existing.is_some_and(|old| old != 0 && old != total) {
            state.take_chunk(id, true);
            return Err(TelemetryError::Unpack("side chunk total mismatch"));
        }
        let before = state.rx_chunks.len();
        let room = SideChunkAssembly::make_room(
            &mut state.rx_chunks,
            &mut state.rx_chunk_bytes,
            id,
            index,
            total,
            payload_len,
            budget,
        );
        if before != state.rx_chunks.len() {
            state.rx_chunk_reclaims = state
                .rx_chunk_reclaims
                .saturating_add((before - state.rx_chunks.len()) as u32);
        }
        let cost = room?;
        if cost == 0 {
            return Ok(());
        }
        if existing.is_none()
            && state.rx_chunks.len() >= 4
            && let Some((oldest, _)) = SideChunkAssembly::oldest(&state.rx_chunks, None)
        {
            state.take_chunk(oldest, true);
        }
        while self.shared_queue_bytes_used().saturating_add(cost) > self.memory.max_queue_budget {
            #[cfg(any(feature = "std", feature = "fair-admission"))]
            if let Some(owner) = self.bulk_loads(199).queue_victim(None)
                && self.reclaim_bulk_from(owner, 199, None)
            {
                continue;
            }
            if self.reclaim_oldest_side_chunk(Some((side, id))) {
                continue;
            }
            // The sender retries this fragment, not the earlier accepted ones.
            // Keep the bounded partial assembly while protected queues drain.
            return Err(TelemetryError::Io("memory pressure"));
        }
        Ok(())
    }

    #[inline(never)]
    fn protected_metadata_bytes_used(&self) -> usize {
        let codec_bytes = {
            #[cfg(all(feature = "compression", feature = "discovery"))]
            {
                self.side_transport
                    .values()
                    .map(|side| side.payload_codec.heap_bytes())
                    .sum::<usize>()
            }
            #[cfg(not(all(feature = "compression", feature = "discovery")))]
            {
                0usize
            }
        };
        codec_bytes.saturating_add(
            self.recent_rx
                .max_bytes()
                .saturating_add(self.reliable_rx_buffered_bytes())
                .saturating_add(crate::config::schema_bytes_used())
                .saturating_add({
                    #[cfg(feature = "discovery")]
                    {
                        self.discovery_bytes_used()
                    }
                    #[cfg(not(feature = "discovery"))]
                    {
                        0
                    }
                }),
        )
    }
    #[inline]
    fn shared_queue_bytes_used(&self) -> usize {
        self.received_queue
            .bytes_used()
            .saturating_add(self.transmit_queue.bytes_used())
            .saturating_add(self.side_chunk_bytes_used())
            .saturating_add(self.protected_metadata_bytes_used())
            .saturating_add({
                #[cfg(feature = "compression")]
                {
                    self.codec_reserved_bytes
                }
                #[cfg(not(feature = "compression"))]
                {
                    0
                }
            })
    }

    // A reliable original can be its payload's only owner before its first
    // dispatch. Only replay markers have a separately retained retry record.
    // Refuse new admission rather than silently discard an accepted original.
    fn classify_transmit_disposable(item: &TxQueued) -> bool {
        let data = match &item.item {
            RouterTxItem::Broadcast(data) | RouterTxItem::ToSide { data, .. } => data,
            _ => return true,
        };
        match data {
            RouterItem::Packet(pkt) => {
                is_internal_control_type(pkt.data_type())
                    || (!is_reliable_type(pkt.data_type()) && pkt.wire_target_senders().is_empty())
            }
            RouterItem::Packed(bytes) => crate::shared_bytes::with_slice(bytes, |view| {
                wire_format::peek_routing_frame_info(view).map_or(true, |frame| {
                    is_internal_control_type(frame.envelope.ty)
                        || (!is_reliable_type(frame.envelope.ty)
                            && frame.reliable.is_none()
                            && frame.envelope.target_senders().len() == 0)
                })
            })
            .unwrap_or(false),
        }
    }

    fn transmit_eviction_candidate(queue: &BoundedDeque<TxQueued>) -> Option<usize> {
        queue
            .iter()
            .enumerate()
            .filter(|(_, queued)| queued.disposable)
            .min_by_key(|(index, queued)| (queued.priority, core::cmp::Reverse(*index)))
            .map(|(index, _)| index)
    }

    fn pop_shared_queue_item(&mut self, preferred: RouterQueueKind) -> bool {
        match preferred {
            // RX and TX queues are stored in descending priority order.  When
            // the shared byte budget is exhausted, evict from the tail so a
            // low-priority telemetry packet cannot displace discovery or a
            // managed-variable update at the head of the queue.
            RouterQueueKind::Received => self.received_queue.pop_lowest_priority().is_some(),
            RouterQueueKind::Transmit => {
                let Some(index) = Self::transmit_eviction_candidate(&self.transmit_queue) else {
                    return false;
                };
                let Some(item) = self.transmit_queue.remove_pos(index) else {
                    return false;
                };
                if let Some(key) = item.item.replay_marker_key() {
                    Self::set_replay_queued(
                        &mut self.reliable_tx,
                        &mut self.end_to_end_reliable_tx,
                        key,
                        false,
                    );
                }
                true
            }
        }
    }

    fn lower_priority_shared_queue(&self, incoming_priority: u8) -> Option<RouterQueueKind> {
        let received = self
            .received_queue
            .lowest_priority(|queued| queued.priority)
            .map(|priority| (RouterQueueKind::Received, priority));
        let transmit = self
            .transmit_queue
            .iter()
            .filter(|queued| queued.disposable)
            .map(|queued| queued.priority)
            .min()
            .map(|priority| (RouterQueueKind::Transmit, priority));
        [received, transmit]
            .into_iter()
            .flatten()
            .filter(|(_, priority)| {
                *priority < incoming_priority
                    || (incoming_priority != 254 && *priority == incoming_priority)
            })
            .min_by_key(|(kind, priority)| {
                (
                    *priority,
                    if *kind == RouterQueueKind::Received {
                        0
                    } else {
                        1
                    },
                )
            })
            .map(|(kind, _)| kind)
    }

    fn make_shared_queue_room(
        &mut self,
        incoming_cost: usize,
        incoming_priority: u8,
        _incoming: Option<&RouterItem>,
    ) -> TelemetryResult<()> {
        if incoming_cost > self.memory.max_queue_budget {
            return Err(TelemetryError::PacketTooLarge(
                "Item exceeds maximum shared queue budget",
            ));
        }

        #[cfg(any(feature = "std", feature = "fair-admission"))]
        let mut fair_victim = None;
        while self.shared_queue_bytes_used().saturating_add(incoming_cost)
            > self.memory.max_queue_budget
        {
            #[cfg(all(feature = "compression", feature = "discovery"))]
            if self.reclaim_codec_metadata() {
                continue;
            }

            #[cfg(any(feature = "std", feature = "fair-admission"))]
            {
                let incoming =
                    _incoming.and_then(|data| Self::fair_bulk_owner(data, incoming_priority));
                let victim = *fair_victim.get_or_insert_with(|| {
                    self.bulk_loads(incoming_priority.min(199))
                        .queue_victim(incoming)
                });
                if let Some(victim) = victim
                    && self.reclaim_bulk_from(
                        victim,
                        incoming_priority.min(199),
                        (incoming == Some(victim))
                            .then(|| _incoming.and_then(Self::bulk_stream))
                            .flatten(),
                    )
                {
                    continue;
                }
                if incoming.is_some() {
                    return Err(TelemetryError::Io("shared fair queue saturated"));
                }
            }
            let Some(victim) = self.lower_priority_shared_queue(incoming_priority) else {
                if incoming_priority >= 200 && self.reclaim_oldest_side_chunk(None) {
                    continue;
                }
                return Err(TelemetryError::Io("shared priority queue saturated"));
            };
            if !self.pop_shared_queue_item(victim) {
                return Err(TelemetryError::PacketTooLarge(
                    "Item exceeds maximum shared queue budget",
                ));
            }
        }

        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn schema_growth_budget(&self) -> usize {
        // Queued packets are reclaimable. Existing reachability and active
        // reliable reassembly remain protected when admitting a new schema.
        let protected = self
            .recent_rx
            .max_bytes()
            .saturating_add(self.discovery_bytes_used())
            .saturating_add(self.reliable_rx_buffered_bytes())
            .saturating_add({
                #[cfg(feature = "compression")]
                {
                    self.codec_reserved_bytes
                }
                #[cfg(not(feature = "compression"))]
                {
                    0
                }
            });
        self.memory.max_queue_budget.saturating_sub(protected)
    }

    #[cfg(feature = "discovery")]
    fn commit_discovery_route(
        &mut self,
        side: RouterSideId,
        route: DiscoverySideState,
    ) -> TelemetryResult<()> {
        let previous = self
            .discovery_routes
            .get(&side)
            .map_or(0, |route| Self::discovery_route_byte_cost(side, route));
        let incoming = Self::discovery_route_byte_cost(side, &route);
        let growth = incoming.saturating_sub(previous);
        self.make_shared_queue_room(growth, 255, None)?;
        self.discovery_routes.insert(side, route);
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn fit_discovery_budget(&mut self) {
        while self.shared_queue_bytes_used() > self.memory.max_queue_budget {
            #[cfg(all(feature = "compression", feature = "discovery"))]
            if self.reclaim_codec_metadata() {
                continue;
            }

            // Discovery growth must discard queued work before reachability.
            // Evicting a whole side here forgets every downstream command route.
            if let Some(victim) = self.lower_priority_shared_queue(255)
                && self.pop_shared_queue_item(victim)
            {
                continue;
            }
            // Live routes are protected. Growth is admitted transactionally;
            // external registry/config changes cannot justify erasing routes.
            break;
        }
    }

    fn reliable_original_type(item: &TxQueued) -> Option<DataType> {
        let RouterTxItem::Broadcast(data) = &item.item else {
            return None;
        };
        let _ = data;
        let ty = DataType(item.accepted_type);
        (item.delivery_state != QueuedDelivery::Untracked).then_some(ty)
    }

    fn ordered_original_type(item: &TxQueued) -> Option<DataType> {
        let RouterTxItem::Broadcast(data) = &item.item else {
            return None;
        };
        let _ = data;
        let ty = DataType(item.accepted_type);
        matches!(
            item.delivery_state,
            QueuedDelivery::Ordered
                | QueuedDelivery::OrderedTail
                | QueuedDelivery::DeferredOrdered
                | QueuedDelivery::ClaimedOrdered
        )
        .then_some(ty)
    }

    fn pop_received_fair(&mut self) -> Option<RouterRxItem> {
        self.received_queue.pop_front_bulk_fair(
            &mut self.rx_priority_burst,
            MAX_PRIORITY_BURST,
            |item| item.priority,
        )
    }

    fn push_received(&mut self, item: RouterRxItem) -> TelemetryResult<()> {
        self.make_shared_queue_room(item.byte_cost(), item.priority, Some(&item.data))?;
        #[cfg(any(feature = "std", feature = "fair-admission"))]
        {
            #[cfg(any(feature = "std", feature = "fair-admission"))]
            let mut fair_victim = None;
            self.received_queue.push_back_prioritized_select(
                item,
                |queued| queued.priority,
                |queue, _incoming| {
                    #[cfg(any(feature = "std", feature = "fair-admission"))]
                    {
                        crate::admission_fairness::queue_victim(
                            queue,
                            _incoming,
                            |item| Self::fair_bulk_owner(&item.data, item.priority),
                            |item| item.priority,
                            |item| Self::bulk_stream(&item.data),
                            &mut fair_victim,
                        )
                    }
                },
                core::mem::drop,
            )
        }
        #[cfg(not(any(feature = "std", feature = "fair-admission")))]
        {
            self.received_queue
                .push_back_prioritized(item, |queued| queued.priority)
        }
    }

    fn push_transmit(&mut self, mut item: TxQueued) -> TelemetryResult<()> {
        #[cfg(feature = "compression")]
        match &mut item.item {
            RouterTxItem::Broadcast(data) => self.prepare_codec_queue_owner(None, data),
            RouterTxItem::ToSide { dst, data, .. } => {
                self.prepare_codec_queue_owner(Some(*dst), data)
            }
            _ => {}
        }
        if let RouterTxItem::Broadcast(data) = &item.item {
            item.accepted_type = match data {
                RouterItem::Packet(packet) => packet.data_type().as_u32(),
                RouterItem::Packed(bytes) => crate::shared_bytes::with_slice(bytes, |view| {
                    wire_format::scheduling_type(view)
                })
                .ok()
                .flatten()
                .map_or(0, |ty| ty.as_u32()),
            };
        }
        if item.delivery_state == QueuedDelivery::Untracked
            && matches!(&item.item, RouterTxItem::Broadcast(_))
        {
            item.delivery_state = match reliable_mode(DataType(item.accepted_type)) {
                crate::ReliableMode::Ordered => QueuedDelivery::Ordered,
                crate::ReliableMode::Unordered => QueuedDelivery::Unordered,
                crate::ReliableMode::None => QueuedDelivery::Untracked,
            };
        }
        // A partial schema merge may raise priority while an Ordered stream
        // is queued. Preserve its original service band until its tail drains.
        if matches!(
            item.delivery_state,
            QueuedDelivery::Ordered | QueuedDelivery::DeferredOrdered
        ) && let Some(priority) = self.transmit_queue.iter().find_map(|queued| {
            (Self::ordered_original_type(queued).is_some()
                && queued.accepted_type == item.accepted_type)
                .then_some(queued.priority)
        }) {
            item.priority = priority;
            item.delivery_state = QueuedDelivery::OrderedTail;
        }
        item.disposable = if item.delivery_state != QueuedDelivery::Untracked {
            false
        } else {
            Self::classify_transmit_disposable(&item)
        };
        let ordered_retry = Self::ordered_original_type(&item).is_some()
            && item.delivery_state == QueuedDelivery::DeferredOrdered;
        let replay = item.item.replay_marker_key();
        // Admission, eviction and the reservation change share this state lock.
        // An acknowledged/orphan marker has no payload left to retransmit.
        if replay.is_some_and(|key| self.replay_is_queued(key).is_none_or(|queued| queued)) {
            return Ok(());
        }
        #[cfg(feature = "discovery")]
        if let RouterTxItem::ToSide { dst, data, .. } = &item.item {
            // A new timestamp for the same catalog must not replace the
            // queued packet: a chunked side may already have sent its prefix.
            if let RouterItem::Packet(incoming) = data
                && self.transmit_queue.iter().any(|queued| {
                    matches!(&queued.item,
                        RouterTxItem::ToSide { dst: queued_dst, data: RouterItem::Packet(existing), .. }
                        if queued_dst == dst && discovery::same_schema_snapshot(existing, incoming))
                })
            {
                return Ok(());
            }
            let incoming = match data {
                RouterItem::Packet(pkt) if discovery::is_discovery_type(pkt.data_type()) => {
                    Some((pkt.data_type(), pkt.sender().to_owned()))
                }
                RouterItem::Packet(_) | RouterItem::Packed(_) => None,
            };
            if let Some((incoming_ty, incoming_sender)) = incoming {
                self.transmit_queue.retain(|queued| {
                    let RouterTxItem::ToSide {
                        dst: queued_dst,
                        data: queued_data,
                        ..
                    } = &queued.item
                    else {
                        return true;
                    };
                    let same_snapshot = match queued_data {
                        RouterItem::Packet(pkt) => {
                            pkt.data_type() == incoming_ty && pkt.sender() == incoming_sender
                        }
                        RouterItem::Packed(_) => false,
                    };
                    *queued_dst != *dst || !same_snapshot
                });
            }
        }
        self.make_shared_queue_room(
            item.byte_cost(),
            item.priority,
            match &item.item {
                RouterTxItem::Broadcast(data) | RouterTxItem::ToSide { data, .. } => Some(data),
                _ => None,
            },
        )?;
        let reliable_tx = &mut self.reliable_tx;
        let end_to_end = &mut self.end_to_end_reliable_tx;
        let result = {
            #[cfg(any(feature = "std", feature = "fair-admission"))]
            {
                #[cfg(any(feature = "std", feature = "fair-admission"))]
                let mut fair_victim = None;
                self.transmit_queue.push_back_prioritized_select(
                    item,
                    |queued| queued.priority,
                    |queue, _incoming| {
                        #[cfg(any(feature = "std", feature = "fair-admission"))]
                        {
                            if Self::tx_bulk_owner(_incoming).is_some() {
                                crate::admission_fairness::queue_victim(
                                    queue,
                                    _incoming,
                                    Self::tx_bulk_owner,
                                    |item| item.priority,
                                    Self::tx_bulk_stream,
                                    &mut fair_victim,
                                )
                            } else {
                                Self::transmit_eviction_candidate(queue)
                            }
                        }
                    },
                    |evicted: TxQueued| {
                        if let Some(key) = evicted.item.replay_marker_key() {
                            Self::set_replay_queued(reliable_tx, end_to_end, key, false);
                        }
                    },
                )
            }
            #[cfg(not(any(feature = "std", feature = "fair-admission")))]
            {
                self.transmit_queue.push_back_prioritized_select(
                    item,
                    |queued| queued.priority,
                    |queue, _| Self::transmit_eviction_candidate(queue),
                    |evicted: TxQueued| {
                        if let Some(key) = evicted.item.replay_marker_key() {
                            Self::set_replay_queued(reliable_tx, end_to_end, key, false);
                        }
                    },
                )
            }
        };
        if result.is_ok() && ordered_retry {
            self.has_ordered_retry = true;
        }
        if result.is_ok()
            && let Some(key) = replay
        {
            Self::set_replay_queued(reliable_tx, end_to_end, key, true);
        }
        result
    }

    fn push_recent_rx(&mut self, id: u64) -> TelemetryResult<()> {
        while self.recent_rx.len() >= self.memory.max_recent_rx_ids {
            let _ = self.recent_rx.pop_front();
        }
        self.make_shared_queue_room(0, 0, None)?;
        self.recent_rx.push_back(id)
    }

    #[allow(unused_mut)]
    fn buffer_reliable_rx(
        &mut self,
        side: RouterSideId,
        ty: DataType,
        seq: u32,
        mut bytes: crate::SharedBytes,
    ) -> TelemetryResult<()> {
        let key = Router::reliable_key(side, ty);
        if self
            .reliable_rx
            .get(&key)
            .is_some_and(|state| state.buffered.contains_key(&seq))
        {
            return Ok(());
        }
        let cost = size_of::<crate::SharedBytes>() + bytes.len();
        self.make_shared_queue_room(cost, crate::transport_priority(ty), None)?;
        #[cfg(feature = "compact-packet-store")]
        bytes.park_for_queue()?;
        let rx_state = self
            .reliable_rx
            .entry(key)
            .or_insert_with(|| ReliableRxState {
                expected_seq: 1,
                buffered: Default::default(),
            });
        if rx_state.buffered.len() >= runtime_reliable_max_pending() {
            let _ = rx_state.buffered.pop_first();
        }
        rx_state.buffered.insert(seq, bytes);
        Ok(())
    }
}

/// Non-blocking RX queue used by ISR-safe `rx_queue*` APIs.
///
/// Uses a tiny atomic try-lock so enqueue never blocks. If contended, push/pop
/// operations return `TelemetryError::Io("rx queue busy")`.
struct IsrRxQueue {
    busy: AtomicBool,
    q: UnsafeCell<BoundedDeque<RouterRxItem>>,
}

unsafe impl Send for IsrRxQueue {}
unsafe impl Sync for IsrRxQueue {}

struct IsrRxQueueGuard<'a> {
    owner: &'a IsrRxQueue,
}

impl Deref for IsrRxQueueGuard<'_> {
    type Target = BoundedDeque<RouterRxItem>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.owner.q.get() }
    }
}

impl DerefMut for IsrRxQueueGuard<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.owner.q.get() }
    }
}

impl Drop for IsrRxQueueGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.owner.busy.store(false, Ordering::Release);
    }
}

impl IsrRxQueue {
    #[inline]
    fn new(max_bytes: usize, starting_bytes: usize, grow_mult: f64) -> Self {
        Self {
            busy: AtomicBool::new(false),
            q: UnsafeCell::new(BoundedDeque::new(max_bytes, starting_bytes, grow_mult)),
        }
    }

    #[inline]
    fn try_lock(&self) -> TelemetryResult<IsrRxQueueGuard<'_>> {
        match self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Ok(IsrRxQueueGuard { owner: self }),
            Err(_) => Err(TelemetryError::Io("rx queue busy")),
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn push_back(&self, item: RouterRxItem) -> TelemetryResult<()> {
        let mut g = self.try_lock()?;
        g.push_back(item)
    }

    #[inline]
    fn push_back_prioritized(&self, item: RouterRxItem) -> TelemetryResult<()> {
        let mut g = self.try_lock()?;
        g.push_back_prioritized(item, |queued| queued.priority)
    }

    #[inline]
    fn pop_front(&self) -> TelemetryResult<Option<RouterRxItem>> {
        let mut g = self.try_lock()?;
        Ok(g.pop_front())
    }

    #[inline]
    fn clear(&self) -> TelemetryResult<()> {
        let mut g = self.try_lock()?;
        g.clear();
        Ok(())
    }

    #[inline]
    fn snapshot(&self) -> Option<(usize, usize)> {
        let g = self.try_lock().ok()?;
        Some((g.len(), g.bytes_used()))
    }
}

/// Telemetry Router for handling incoming and outgoing telemetry packets.
/// Supports queuing, processing, and dispatching to local endpoint handlers.
/// Thread-safe via internal locking.
pub struct Router {
    sender: RouterMutex<Arc<str>>,
    cfg: RouterConfig,
    state: RouterMutex<RouterInner>,
    isr_rx_queue: IsrRxQueue,
    #[cfg(not(feature = "std"))]
    side_tx_gate: ReentryGate,
    #[cfg(feature = "std")]
    side_tx_activity: crate::lock::SideTxActivity,
    clock: Box<dyn Clock + Send + Sync>,
    #[cfg(feature = "timesync")]
    timesync: RouterMutex<TimeSyncRuntime>,
}

#[cfg(feature = "timesync")]
#[derive(Debug, Clone)]
struct PendingTimeSyncRequest {
    seq: u64,
    t1_mono_ms: u64,
    source: String,
}

#[cfg(feature = "timesync")]
#[derive(Debug, Clone)]
struct RemoteTimeSyncSource {
    priority: u64,
    last_sample_mono_ms: u64,
    sample_unix_ms: u64,
}

#[cfg(feature = "timesync")]
#[derive(Debug, Clone)]
struct TimeSyncRuntime {
    cfg: Option<TimeSyncConfig>,
    tracker: Option<TimeSyncTracker>,
    clock: NetworkClock,
    disciplined_clock: SlewedNetworkClock,
    remote_sources: BTreeMap<String, RemoteTimeSyncSource>,
    next_seq: u64,
    next_announce_mono_ms: u64,
    next_request_mono_ms: u64,
    pending_request: Option<PendingTimeSyncRequest>,
}

#[cfg(feature = "timesync")]
impl TimeSyncRuntime {
    fn new(cfg: Option<TimeSyncConfig>) -> Self {
        Self {
            tracker: cfg.map(TimeSyncTracker::new),
            cfg,
            clock: NetworkClock::default(),
            disciplined_clock: SlewedNetworkClock::new(
                cfg.map(|c| c.max_slew_ppm)
                    .unwrap_or(TimeSyncConfig::default().max_slew_ppm),
            ),
            remote_sources: Default::default(),
            next_seq: 1,
            next_announce_mono_ms: 0,
            next_request_mono_ms: 0,
            pending_request: None,
        }
    }
}

enum RemoteSidePlan {
    Target(Vec<RouterSideId>),
}

#[cfg(feature = "discovery")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DiscoveryCandidateMatch {
    side: RouterSideId,
    overlap: usize,
}

#[cfg(feature = "discovery")]
#[inline]
const fn discovery_is_hop_local_advertisement(ty: DataType) -> bool {
    matches!(
        ty,
        DataType::DiscoveryAnnounce
            | DataType::DiscoveryTimeSyncSources
            | DataType::DiscoveryTopology
            | DataType::DiscoveryAddress
            | DataType::DiscoveryLinkCapabilities
    )
}

#[cfg(not(feature = "discovery"))]
const fn discovery_is_hop_local_advertisement(_ty: DataType) -> bool {
    false
}

impl Debug for Router {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let sender = self.sender();
        f.debug_struct("Router")
            .field("sender", &sender)
            .field("cfg", &self.cfg)
            .field("state", &"<mutex>")
            .field("clock", &"Clock")
            .finish()
    }
}

/// Check if any of the provided endpoints require remote forwarding when
/// discovery is unavailable and routing falls back to local-vs-remote schema.
#[inline]
fn has_nonlocal_endpoint(eps: &[DataEndpoint], cfg: &RouterConfig) -> bool {
    eps.iter().copied().any(|ep| !cfg.is_local_endpoint(ep))
}

#[inline]
fn force_remote_for_type(ty: DataType) -> bool {
    matches!(
        ty,
        DataType::ReliableAck
            | DataType::ReliablePartialAck
            | DataType::ReliablePacketRequest
            | DataType::P2pMessage
    ) || {
        #[cfg(feature = "timesync")]
        {
            matches!(
                ty,
                DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
            )
        }
        #[cfg(not(feature = "timesync"))]
        {
            false
        }
    }
}

#[inline]
fn is_internal_control_type(ty: DataType) -> bool {
    if matches!(
        ty,
        DataType::ReliableAck
            | DataType::ReliablePartialAck
            | DataType::ReliablePacketRequest
            | DataType::P2pMessage
    ) {
        return true;
    }

    #[cfg(feature = "timesync")]
    if matches!(
        ty,
        DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
    ) {
        return true;
    }

    #[cfg(feature = "discovery")]
    if discovery::is_discovery_type(ty) {
        return true;
    }

    let _ = ty;
    false
}

/// Helper function to call a handler with retries and error handling.
fn with_retries<F>(
    this: &Router,
    dest: DataEndpoint,
    data: &RouterItem,
    pkt_for_ctx: Option<&Packet>,
    env_for_ctx: Option<&wire_format::TelemetryEnvelope>,
    called_from_queue: bool,
    run: F,
) -> TelemetryResult<()>
where
    F: Fn() -> TelemetryResult<()>,
{
    match this.retry_with_attempts(runtime_max_handler_retries(), run) {
        Ok(((), attempts)) => {
            if attempts > 1 {
                let mut st = this.state.lock();
                st.total_handler_retries = st
                    .total_handler_retries
                    .saturating_add(attempts.saturating_sub(1) as u64);
            }
            Ok(())
        }
        Err((e, attempts)) => {
            {
                let mut st = this.state.lock();
                st.total_handler_failures = st.total_handler_failures.saturating_add(1);
                st.total_handler_retries = st.total_handler_retries.saturating_add(attempts as u64);
            }

            // If handler fails, remove from dedupe so it can be retried later if resent.
            this.remove_pkt_id(data);

            // Emit error packet (to local endpoints).
            if let Some(pkt) = pkt_for_ctx {
                let _ = this.handle_callback_error(pkt, Some(dest), e, called_from_queue);
            } else if let Some(env) = env_for_ctx {
                let _ = this.handle_callback_error_from_env(env, Some(dest), e, called_from_queue);
            }

            Err(TelemetryError::HandlerError("local handler failed"))
        }
    }
}
/// Router implementation
impl Router {
    #[cfg(feature = "discovery")]
    const END_TO_END_ACK_SENDER: &'static str = "E2EACK";
    const END_TO_END_ACK_PREFIX: &'static str = "E2EACK:";

    #[inline]
    fn side_ref(st: &RouterInner, side: RouterSideId) -> TelemetryResult<&RouterSide> {
        st.sides
            .get(side)
            .and_then(|side| side.as_ref())
            .ok_or(TelemetryError::HandlerError("router: invalid side id"))
    }

    fn note_side_tx_success(
        &self,
        side: RouterSideId,
        ty: DataType,
        bytes: usize,
        relayed: bool,
        attempts: usize,
    ) {
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        if ty == crate::DataType::DiscoveryAnnounce
            && !relayed
            && let Some(throttle) = st.discovery_side_throttle.get_mut(&side)
        {
            throttle.last_liveness_tx_ms = self.clock.now_ms();
        }
        #[cfg(all(feature = "discovery", feature = "timesync"))]
        if Self::is_timesync_type(ty) {
            let now = self.clock.now_ms();
            if Self::side_is_slow_control_link_locked(&st, side, now) {
                st.timesync_side_throttle
                    .entry(side)
                    .or_default()
                    .next_allowed_ms = now.saturating_add(TIMESYNC_SLOW_LINK_MIN_INTERVAL_MS);
            } else {
                st.timesync_side_throttle.remove(&side);
            }
        }
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_tx(ty, bytes, relayed, attempts.saturating_sub(1));
    }

    fn note_side_tx_failure(&self, side: RouterSideId, ty: DataType, attempts: usize) {
        let mut st = self.state.lock();
        st.total_handler_failures = st.total_handler_failures.saturating_add(1);
        st.total_handler_retries = st.total_handler_retries.saturating_add(attempts as u64);
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_tx_failure(ty, attempts);
    }

    fn note_side_rx(&self, side: RouterSideId, ty: DataType, bytes: usize, relayed: bool) {
        let mut st = self.state.lock();
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_rx(ty, bytes, relayed);
    }

    fn note_side_local_delivery(&self, side: RouterSideId, ty: DataType) {
        let mut st = self.state.lock();
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_local_delivery(ty);
    }

    fn note_side_local_handler_failure(&self, side: RouterSideId, ty: DataType, retries: usize) {
        let mut st = self.state.lock();
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_local_handler_failure(ty, retries);
    }

    fn cache_managed_variable_packet(
        &self,
        pkt: &Packet,
        notify_handlers: bool,
    ) -> TelemetryResult<()> {
        let sender_address = pkt
            .sender()
            .strip_prefix("@addr:")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| sender_address_u32(pkt.sender()));
        let handlers = {
            let mut st = self.state.lock();
            if !st
                .managed_variable_types
                .contains(&pkt.data_type().as_u32())
            {
                return Ok(());
            }
            let existing = st.managed_variable_latest.get(&pkt.data_type().as_u32());
            // Sender-local timestamps can order updates from one authoritative
            // writer even before network time is available. They cannot order
            // a restored local seed against a remote writer, and packet nonces
            // are deliberately pseudo-random deduplication keys rather than
            // revisions. Accept equal-timestamp updates in arrival order so
            // rapid toggles made during one clock tick are not discarded.
            if existing.is_some_and(|entry| {
                let current = &entry.packet;
                sender_address == entry.sender_address && pkt.timestamp() < current.timestamp()
            }) {
                return Ok(());
            }
            let changed = existing.is_none_or(|entry| entry.packet != *pkt);
            // A B-tree leaf reserves eleven values, even for one variable.
            // Keep that sparse root small; reuse each box on later updates so
            // frequent state changes introduce no allocator churn.
            let updated = ManagedVariableCacheEntry {
                packet: pkt.clone(),
                sender_address,
                #[cfg(feature = "discovery")]
                cached_at_ms: self.clock.now_ms(),
            };
            if let Some(entry) = st
                .managed_variable_latest
                .get_mut(&pkt.data_type().as_u32())
            {
                **entry = updated;
            } else {
                st.managed_variable_latest
                    .insert(pkt.data_type().as_u32(), Box::new(updated));
            }
            if notify_handlers && changed {
                st.network_variable_update_handlers
                    .get(&pkt.data_type().as_u32())
                    .cloned()
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        for handler in handlers {
            (handler.handler)(pkt)?;
        }
        Ok(())
    }

    fn remember_managed_variable_packet(&self, pkt: &Packet) -> TelemetryResult<()> {
        self.cache_managed_variable_packet(pkt, true)
    }

    fn managed_variable_latest(&self, ty: DataType) -> Option<Packet> {
        let st = self.state.lock();
        st.managed_variable_latest
            .get(&ty.as_u32())
            .map(|entry| entry.packet.clone())
    }

    #[cfg(feature = "discovery")]
    fn managed_variable_latest_with_age(&self, ty: DataType) -> Option<(Packet, u64)> {
        let now_ms = self.clock.now_ms();
        let st = self.state.lock();
        st.managed_variable_latest.get(&ty.as_u32()).map(|entry| {
            (
                entry.packet.clone(),
                now_ms.saturating_sub(entry.cached_at_ms),
            )
        })
    }

    fn is_managed_variable_type(&self, ty: DataType) -> bool {
        let st = self.state.lock();
        st.managed_variable_types.contains(&ty.as_u32())
    }

    fn managed_variable_permissions_locked(
        st: &RouterInner,
        ty: DataType,
    ) -> NetworkVariablePermissions {
        st.managed_variable_permissions
            .get(&ty.as_u32())
            .copied()
            .unwrap_or(NetworkVariablePermissions::READ_WRITE)
    }

    fn can_read_managed_variable(&self, ty: DataType) -> bool {
        let st = self.state.lock();
        Self::managed_variable_permissions_locked(&st, ty).read
    }

    #[cfg(feature = "discovery")]
    fn can_write_managed_variable(&self, ty: DataType) -> bool {
        let st = self.state.lock();
        Self::managed_variable_permissions_locked(&st, ty).write
    }

    #[inline]
    fn ensure_side_ingress_enabled(&self, side: RouterSideId) -> TelemetryResult<()> {
        let st = self.state.lock();
        let side_ref = Self::side_ref(&st, side)?;
        if side_ref.opts.ingress_enabled {
            Ok(())
        } else {
            Err(TelemetryError::HandlerError(
                "router: ingress disabled for side id",
            ))
        }
    }

    #[inline]
    fn default_route_enabled(&self, src: Option<RouterSideId>, dst: RouterSideId) -> bool {
        src != Some(dst)
    }

    #[inline]
    fn route_allowed_locked(
        &self,
        st: &RouterInner,
        src: Option<RouterSideId>,
        ty: Option<DataType>,
        dst: RouterSideId,
    ) -> bool {
        let Some(dst_side) = st.sides.get(dst).and_then(|side| side.as_ref()) else {
            return false;
        };
        if !dst_side.opts.egress_enabled {
            return false;
        }
        if let Some(src_id) = src {
            let Some(src_side) = st.sides.get(src_id).and_then(|side| side.as_ref()) else {
                return false;
            };
            if !src_side.opts.ingress_enabled {
                return false;
            }
        }
        let base_allowed = st
            .route_overrides
            .get(&(src, dst))
            .copied()
            .unwrap_or_else(|| self.default_route_enabled(src, dst));
        if !base_allowed {
            return false;
        }

        let Some(ty) = ty else {
            return true;
        };
        if st
            .typed_route_overrides
            .keys()
            .any(|(typed_src, typed_ty, _)| *typed_src == src && *typed_ty == ty.as_u32())
        {
            return st
                .typed_route_overrides
                .get(&(src, ty.as_u32(), dst))
                .copied()
                .unwrap_or(false);
        }
        true
    }

    #[cfg(feature = "discovery")]
    fn has_typed_route_overrides_locked(
        st: &RouterInner,
        src: Option<RouterSideId>,
        ty: DataType,
    ) -> bool {
        st.typed_route_overrides
            .keys()
            .any(|(typed_src, typed_ty, _)| *typed_src == src && *typed_ty == ty.as_u32())
    }

    #[cfg(feature = "discovery")]
    fn endpoint_overlap_count<I>(reachable: I, eps: &[DataEndpoint]) -> usize
    where
        I: IntoIterator<Item = DataEndpoint>,
    {
        let mut overlap = 0usize;
        for ep in reachable {
            if eps.contains(&ep) {
                overlap = overlap.saturating_add(1);
            }
        }
        overlap
    }

    #[inline]
    #[cfg(feature = "discovery")]
    fn preferred_scoring_endpoints<'a>(
        &self,
        eps: &'a [DataEndpoint],
        prefer_nonlocal: bool,
    ) -> alloc::borrow::Cow<'a, [DataEndpoint]> {
        if !prefer_nonlocal || eps.iter().all(|&ep| !self.cfg.is_local_endpoint(ep)) {
            return alloc::borrow::Cow::Borrowed(eps);
        }
        let nonlocal: Vec<DataEndpoint> = eps
            .iter()
            .copied()
            .filter(|&ep| !self.cfg.is_local_endpoint(ep))
            .collect();
        if nonlocal.is_empty() {
            alloc::borrow::Cow::Borrowed(eps)
        } else {
            alloc::borrow::Cow::Owned(nonlocal)
        }
    }

    fn pop_next_queued_control_rx_item(&self) -> TelemetryResult<Option<RouterRxItem>> {
        {
            let mut isr_rx = self.isr_rx_queue.try_lock()?;
            let idx = isr_rx.iter().position(Self::queued_rx_item_is_control);
            if let Some(idx) = idx {
                return Ok(isr_rx.remove_pos(idx));
            }
        }

        let mut st = self.state.lock();
        let idx = st
            .received_queue
            .iter()
            .position(Self::queued_rx_item_is_control);
        if let Some(idx) = idx {
            return Ok(st.received_queue.remove_pos(idx));
        }
        Ok(None)
    }

    fn queued_rx_item_is_control(item: &RouterRxItem) -> bool {
        // Admission computes and retains the reserved service band once.
        // Bulk queues can contain hundreds of entries: do not reparse every
        // packed header just to rediscover that none is a control packet.
        if item.priority < crate::transport_priority(DataType::ManagedVariableValue) {
            return false;
        }
        // Registered managed values keep their application type on the wire,
        // but their queued service class must match their transmission class.
        if item.priority == crate::transport_priority(DataType::ManagedVariableValue) {
            return true;
        }
        let ty = match &item.data {
            RouterItem::Packet(pkt) => Some(pkt.data_type()),
            RouterItem::Packed(bytes) => {
                if bytes.len() <= 128
                    && wire_format::peek_routing_frame_info(bytes)
                        .is_ok_and(|frame| frame.ack_only())
                {
                    return true;
                }
                wire_format::scheduling_type(bytes.as_ref())
            }
        };
        match ty {
            Some(
                DataType::ReliableAck
                | DataType::ReliablePartialAck
                | DataType::ReliablePacketRequest,
            ) => true,
            #[cfg(feature = "discovery")]
            Some(ty) => discovery::is_discovery_type(ty),
            _ => false,
        }
    }

    fn drain_queued_control_rx_before_tx(
        &self,
        start: u64,
        timeout_ms: u32,
    ) -> TelemetryResult<bool> {
        let mut did_any = false;
        while let Some(item) = self.pop_next_queued_control_rx_item()? {
            self.process_rx_queue_item(item)?;
            did_any = true;
            // Receipts precede retry exhaustion; discovery precedes routing.
            // A control burst still shares the caller's bounded deadline.
            if timeout_ms != 0 && self.clock.now_ms().wrapping_sub(start) >= u64::from(timeout_ms) {
                break;
            }
        }
        Ok(did_any)
    }

    fn eligible_side_ids_locked(
        &self,
        st: &RouterInner,
        src: Option<RouterSideId>,
        ty: Option<DataType>,
        restrict_link_local: bool,
    ) -> Vec<RouterSideId> {
        st.sides
            .iter()
            .enumerate()
            .filter_map(|(side_id, side)| {
                let side = side.as_ref()?;
                if restrict_link_local && !side.opts.link_local_enabled {
                    return None;
                }
                if self.route_allowed_locked(st, src, ty, side_id) {
                    Some(side_id)
                } else {
                    None
                }
            })
            .collect()
    }

    fn apply_route_selection_locked(
        &self,
        st: &mut RouterInner,
        src: Option<RouterSideId>,
        mut sides: Vec<RouterSideId>,
        origin: RouteSelectionOrigin,
    ) -> Vec<RouterSideId> {
        if sides.len() <= 1 {
            return sides;
        }

        let selection_mode = st.source_route_modes.get(&src).copied();
        if selection_mode.is_none() && origin == RouteSelectionOrigin::Discovered {
            return self.apply_adaptive_discovery_selection_locked(st, src, sides);
        }

        match selection_mode.unwrap_or(RouteSelectionMode::Fanout) {
            RouteSelectionMode::Fanout => sides,
            RouteSelectionMode::Weighted => {
                crate::small_sort::sort(&mut sides);
                let total_weight = sides.iter().fold(0_u64, |acc, side| {
                    acc + u64::from(st.route_weights.get(&(src, *side)).copied().unwrap_or(1))
                });
                if total_weight == 0 {
                    return Vec::new();
                }
                let cursor = st.route_selection_cursors.entry(src).or_insert(0);
                let pick = *cursor % total_weight;
                *cursor = cursor.wrapping_add(1);
                let mut remaining = pick;
                for side in sides {
                    let weight =
                        u64::from(st.route_weights.get(&(src, side)).copied().unwrap_or(1));
                    if remaining < weight {
                        return vec![side];
                    }
                    remaining -= weight;
                }
                Vec::new()
            }
            RouteSelectionMode::Failover => {
                sides.sort_by_key(|side| {
                    (
                        st.route_priorities.get(&(src, *side)).copied().unwrap_or(0),
                        *side,
                    )
                });
                sides.truncate(1);
                sides
            }
        }
    }

    fn apply_adaptive_discovery_selection_locked(
        &self,
        st: &mut RouterInner,
        src: Option<RouterSideId>,
        mut sides: Vec<RouterSideId>,
    ) -> Vec<RouterSideId> {
        crate::small_sort::sort(&mut sides);
        let mut unmeasured: Vec<_> = sides
            .iter()
            .copied()
            .filter(|side| !st.adaptive_route_stats.contains_key(side))
            .collect();
        if !unmeasured.is_empty() {
            let cursor = st.route_selection_cursors.entry(src).or_insert(0);
            let pick = (*cursor as usize) % unmeasured.len();
            *cursor = cursor.wrapping_add(1);
            return vec![unmeasured.swap_remove(pick)];
        }

        let now_ms = self.clock.now_ms();
        let total_weight = sides.iter().fold(0_u64, |acc, side| {
            acc + st
                .adaptive_route_stats
                .get(side)
                .map(|stats| stats.weight(now_ms))
                .unwrap_or(1)
        });
        if total_weight == 0 {
            sides.truncate(1);
            return sides;
        }

        let cursor = st.route_selection_cursors.entry(src).or_insert(0);
        let pick = *cursor % total_weight;
        *cursor = cursor.wrapping_add(1);
        let mut remaining = pick;
        for side in sides {
            let weight = st
                .adaptive_route_stats
                .get(&side)
                .map(|stats| stats.weight(now_ms))
                .unwrap_or(1);
            if remaining < weight {
                return vec![side];
            }
            remaining -= weight;
        }
        Vec::new()
    }

    fn record_side_tx_sample(
        &self,
        side: RouterSideId,
        bytes: usize,
        started_ms: u64,
        ended_ms: u64,
    ) {
        let sample_ms = ended_ms.saturating_sub(started_ms).max(1);
        let sample_bps = ((bytes as u128).saturating_mul(1000) / u128::from(sample_ms))
            .min(u128::from(u64::MAX)) as u64;
        let mut st = self.state.lock();
        st.adaptive_route_stats
            .entry(side)
            .or_default()
            .observe(bytes, sample_bps, ended_ms);
    }

    /// Seed adaptive route selection with a transport-measured link probe.
    ///
    /// Call this after a side-specific bring-up probe, or whenever the transport already knows the
    /// duration for a frame. The router does not emit synthetic probe frames by itself.
    pub fn note_side_link_probe_sample(
        &self,
        side: RouterSideId,
        bytes: usize,
        duration_ms: u64,
    ) -> TelemetryResult<()> {
        {
            let st = self.state.lock();
            let _ = Self::side_ref(&st, side).map_err(|_| TelemetryError::BadArg)?;
        }
        let ended_ms = self.clock.now_ms();
        self.record_side_tx_sample(side, bytes, ended_ms.saturating_sub(duration_ms), ended_ms);
        Ok(())
    }

    fn router_item_wire_len(data: &RouterItem) -> TelemetryResult<usize> {
        match data {
            RouterItem::Packet(pkt) => Ok(wire_format::packet_wire_size(pkt)),
            RouterItem::Packed(bytes) => Ok(bytes.len()),
        }
    }

    /// Extract the logical packet ID targeted by an end-to-end reliable ACK item.
    ///
    /// Router TX and replay queues can carry either decoded `Packet` values or
    /// packed frames. This helper normalizes both forms so ACK-routing code
    /// can reason about them uniformly.
    ///
    /// Only router-generated end-to-end `ReliableAck` packets qualify here.
    /// Ordinary application traffic and hop-level reliable control frames return
    /// `Ok(None)`.
    #[inline]
    fn reliable_control_target_packet_id(data: &RouterItem) -> TelemetryResult<Option<u64>> {
        match data {
            RouterItem::Packet(pkt) => {
                if !Self::is_end_to_end_ack_packet(pkt) {
                    return Ok(None);
                }
                Self::decode_end_to_end_reliable_ack(pkt.payload()).map(Some)
            }
            RouterItem::Packed(bytes) => {
                if wire_format::peek_routing_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| {
                        frame.envelope.ty != DataType::ReliableAck || frame.ack_only()
                    })
                {
                    return Ok(None);
                }
                let pkt = wire_format::unpack_packet(bytes.as_ref())?;
                if !Self::is_end_to_end_ack_packet(&pkt) {
                    return Ok(None);
                }
                Self::decode_end_to_end_reliable_ack(pkt.payload()).map(Some)
            }
        }
    }

    fn decode_end_to_end_reliable_ack(payload: &[u8]) -> TelemetryResult<u64> {
        if payload.len() != 8 {
            return Err(TelemetryError::Unpack("bad reliable e2e ack payload"));
        }
        Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
    }

    #[inline]
    fn sender_hash(sender: &str) -> u64 {
        if let Some(address) = sender
            .strip_prefix("@addr:")
            .and_then(|v| v.parse::<u32>().ok())
        {
            return u64::from(address);
        }
        hash_bytes_u64(0x517C_C1B7_2722_0A95, sender.as_bytes())
    }

    #[inline]
    fn fallback_address_for_hostname(hostname: &str) -> NodeAddress {
        let hash = Self::sender_hash(hostname);
        let mut address = (hash as u32) ^ ((hash >> 32) as u32);
        if address == 0 {
            address = 1;
        }
        address
    }

    /// Resolve the compact wire header's numeric source back to the stable
    /// hostname learned by address discovery. The DHCP-style assigned address
    /// and the wire address intentionally occupy separate namespaces, so both
    /// forms must be considered here.
    fn canonical_sender_locked(st: &RouterInner, sender: &str) -> String {
        let Some(address) = sender
            .strip_prefix("@addr:")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return sender.to_string();
        };
        Self::hostname_for_address_locked(st, address).unwrap_or_else(|| sender.to_string())
    }

    /// Resolve both assigned node addresses and stable compact wire hashes.
    ///
    /// Remote boards behind a router appear in incremental topology summaries,
    /// but do not send their link-local address advertisement across that
    /// router. Include those retained topology names so application packets
    /// can still be attributed at the far edge of a multi-hop network.
    fn hostname_for_address_locked(st: &RouterInner, address: NodeAddress) -> Option<String> {
        Self::hostname_for_address_borrowed_locked(st, address).map(str::to_string)
    }

    fn hostname_for_address_borrowed_locked<'a>(
        st: &'a RouterInner,
        address: NodeAddress,
    ) -> Option<&'a str> {
        if let Some(hostname) = st.address_by_value.get(&address) {
            return Some(hostname.as_str());
        }

        let mut found: Option<&'a str> = None;
        let mut collision = false;
        let mut consider = |candidate: &'a str| {
            if sender_address_u32(candidate) != address {
                return;
            }
            match found {
                None => found = Some(candidate),
                Some(existing) if existing == candidate => {}
                // Do not guess if two discovered names have the same compact
                // 32-bit wire address. Address discovery must resolve that
                // conflict before callers can safely attribute the packet.
                Some(_) => collision = true,
            }
        };

        for entry in st.address_book.values() {
            consider(entry.hostname.as_ref());
        }
        #[cfg(feature = "discovery")]
        for route in st.discovery_routes.values() {
            for (announcer, state) in &route.announcers {
                consider(announcer);
                for board in state.topology_boards.iter() {
                    consider(&board.sender_id);
                    // A constrained bridge can retain a remote only as a
                    // named connection on its own topology node.  That name
                    // is still authoritative discovery identity and is
                    // sufficient to resolve the deterministic compact sender
                    // address used by application and ACK packets.
                    for peer in &board.connections {
                        consider(peer);
                    }
                }
            }
        }
        if collision { None } else { found }
    }

    #[cfg(feature = "discovery")]
    fn address_mode_from_code(mode: u8, requested: NodeAddress) -> AddressAssignmentMode {
        match mode {
            2 => AddressAssignmentMode::Static(if requested == 0 { 1 } else { requested }),
            1 => AddressAssignmentMode::Requested(if requested == 0 { 1 } else { requested }),
            _ => AddressAssignmentMode::Dynamic,
        }
    }

    #[cfg(feature = "discovery")]
    fn address_winner_pref(entry: &AddressBookEntry) -> (u8, core::cmp::Reverse<u64>, u64) {
        let rank = match entry.mode {
            AddressAssignmentMode::Static(_) => 2,
            AddressAssignmentMode::Requested(_) => 1,
            AddressAssignmentMode::Dynamic => 0,
        };
        (
            rank,
            core::cmp::Reverse(entry.birth_ms),
            u64::MAX - entry.owner_hash,
        )
    }

    #[cfg(feature = "discovery")]
    fn identity_winner_pref(entry: &AddressBookEntry) -> (core::cmp::Reverse<u64>, u64) {
        (
            core::cmp::Reverse(entry.birth_ms),
            u64::MAX - entry.owner_hash,
        )
    }

    #[cfg(feature = "discovery")]
    fn allocate_free_address_locked(st: &RouterInner, seed: NodeAddress) -> NodeAddress {
        let mut candidate = if seed == 0 { 1 } else { seed };
        for _ in 0..u32::MAX {
            if candidate != 0 && !st.address_by_value.contains_key(&candidate) {
                return candidate;
            }
            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                candidate = 1;
            }
        }
        1
    }

    #[cfg(feature = "discovery")]
    fn unique_hostname_locked(st: &RouterInner, base: &str, owner_hash: u64) -> String {
        if !st.address_book.contains_key(base) {
            return base.to_string();
        }
        let stem = if base.is_empty() { "node" } else { base };
        let mut candidate = format!("{stem}-{owner_hash:08x}");
        let mut suffix = 1u32;
        while st.address_book.contains_key(&candidate) {
            candidate = format!("{stem}-{owner_hash:08x}-{suffix}");
            suffix = suffix.saturating_add(1);
        }
        candidate
    }

    fn update_local_identity_locked(
        &self,
        st: &mut RouterInner,
        mut local: AddressBookEntry,
        reason: AddressChangeReason,
    ) -> AddressChange {
        let old = st.local_address.clone();
        st.address_book.remove(old.hostname.as_ref());
        st.address_by_value.remove(&old.address);
        local.last_seen_ms = self.clock.now_ms();
        st.address_by_value
            .insert(local.address, local.hostname.to_string());
        st.address_book
            .insert(local.hostname.to_string(), local.clone());
        st.local_address = local.clone();
        *self.sender.lock() = local.hostname.clone();
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(st, self.clock.now_ms());
        AddressChange {
            old_hostname: old.hostname,
            new_hostname: local.hostname,
            old_address: old.address,
            new_address: local.address,
            reason,
        }
    }

    fn notify_address_change(&self, change: AddressChange) -> TelemetryResult<()> {
        for handler in self.cfg.address_change_handlers.iter() {
            (handler.handler)(change.clone())?;
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn local_address_advertisement(
        &self,
        reachable_endpoints: Vec<DataEndpoint>,
        reachable_network_variables: Vec<DataType>,
        reachable_timesync_sources: Vec<String>,
        link_capabilities: discovery::LinkCapabilities,
        state: u8,
    ) -> discovery::AddressAdvertisement {
        let st = self.state.lock();
        discovery::AddressAdvertisement {
            hostname: st.local_address.hostname.to_string(),
            address: st.local_address.address,
            requested_address: st.local_address.requested_address,
            mode: st.local_address.mode.mode_code(),
            state,
            birth_ms: st.local_address.birth_ms,
            owner_hash: st.local_address.owner_hash,
            reachable_endpoints,
            reachable_network_variables,
            reachable_timesync_sources,
            link_capabilities,
        }
    }

    #[cfg(feature = "discovery")]
    fn ingest_address_advertisement(
        &self,
        ad: discovery::AddressAdvertisement,
    ) -> TelemetryResult<bool> {
        let now_ms = self.clock.now_ms();
        let mut remote = AddressBookEntry {
            hostname: Arc::from(ad.hostname.as_str()),
            address: ad.address,
            requested_address: ad.requested_address,
            mode: Self::address_mode_from_code(ad.mode, ad.requested_address),
            birth_ms: ad.birth_ms,
            owner_hash: ad.owner_hash,
            last_seen_ms: now_ms,
        };
        let mut change = None;
        let mut changed = false;
        {
            let mut st = self.state.lock();
            let local = st.local_address.clone();
            let hostname_conflict =
                remote.hostname == local.hostname && remote.owner_hash != local.owner_hash;
            let address_conflict =
                remote.address == local.address && remote.owner_hash != local.owner_hash;

            if hostname_conflict
                && Self::identity_winner_pref(&remote) > Self::identity_winner_pref(&local)
            {
                let mut next = local.clone();
                next.hostname = Arc::from(Self::unique_hostname_locked(
                    &st,
                    local.hostname.as_ref(),
                    local.owner_hash,
                ));
                change = Some(self.update_local_identity_locked(
                    &mut st,
                    next,
                    AddressChangeReason::HostnameConflict,
                ));
                changed = true;
            } else if address_conflict
                && Self::address_winner_pref(&remote) > Self::address_winner_pref(&local)
            {
                let mut next = local.clone();
                let seed = next
                    .requested_address
                    .max(Self::fallback_address_for_hostname(next.hostname.as_ref()));
                next.address = Self::allocate_free_address_locked(&st, seed);
                let reason = match next.mode {
                    AddressAssignmentMode::Static(_) => AddressChangeReason::StaticConflict,
                    AddressAssignmentMode::Requested(_) => AddressChangeReason::RequestedConflict,
                    AddressAssignmentMode::Dynamic => AddressChangeReason::DynamicConflict,
                };
                change = Some(self.update_local_identity_locked(&mut st, next, reason));
                changed = true;
            } else if hostname_conflict {
                remote.hostname = Arc::from(Self::unique_hostname_locked(
                    &st,
                    remote.hostname.as_ref(),
                    remote.owner_hash,
                ));
                changed = true;
            } else if address_conflict {
                let seed = remote
                    .requested_address
                    .max(Self::fallback_address_for_hostname(
                        remote.hostname.as_ref(),
                    ));
                remote.address = Self::allocate_free_address_locked(&st, seed);
                changed = true;
            }

            st.address_book.remove(remote.hostname.as_ref());
            st.address_by_value.remove(&remote.address);
            st.address_by_value
                .insert(remote.address, remote.hostname.to_string());
            st.address_book
                .insert(remote.hostname.to_string(), remote.clone());
        }
        if let Some(change) = change {
            self.notify_address_change(change)?;
        }
        Ok(changed)
    }

    #[inline]
    #[cfg(feature = "discovery")]
    fn is_end_to_end_ack_sender(sender: &str) -> bool {
        sender == Self::END_TO_END_ACK_SENDER || sender.starts_with(Self::END_TO_END_ACK_PREFIX)
    }

    fn decode_end_to_end_ack_sender_hash(sender: &str) -> Option<u64> {
        if let Some(ack_sender) = sender.strip_prefix(Self::END_TO_END_ACK_PREFIX)
            && !ack_sender.is_empty()
        {
            return Some(Self::sender_hash(ack_sender));
        }
        None
    }

    /// Return the stable destination key carried by an end-to-end ACK.
    ///
    /// Compact embedded headers encode senders as numeric addresses, so the legacy
    /// `E2EACK:<hostname>` marker cannot survive a firmware hop. New ACKs carry the acknowledging
    /// owner's hash in their frozen target contract; marker decoding remains for older peers.
    fn end_to_end_ack_sender_hash(pkt: &Packet) -> Option<u64> {
        if pkt.data_type() != DataType::ReliableAck {
            return None;
        }
        pkt.wire_target_senders()
            .first()
            .copied()
            .or_else(|| Self::decode_end_to_end_ack_sender_hash(pkt.sender()))
    }

    fn is_end_to_end_ack_packet(pkt: &Packet) -> bool {
        Self::end_to_end_ack_sender_hash(pkt).is_some()
            && Self::decode_end_to_end_reliable_ack(pkt.payload()).is_ok()
    }

    fn encode_end_to_end_ack_sender(&self) -> String {
        let sender = self.sender_arc();
        format!("{}{}", Self::END_TO_END_ACK_PREFIX, sender)
    }

    #[cfg(feature = "discovery")]
    fn is_end_to_end_destination_sender(sender: &str) -> bool {
        sender != "RELAY" && !Self::is_end_to_end_ack_sender(sender)
    }

    fn encode_p2p_payload(
        src_hostname: &str,
        src_address: NodeAddress,
        src_port: P2pPort,
        dst_port: P2pPort,
        payload: &[u8],
    ) -> TelemetryResult<crate::SharedBytes> {
        let host_len = u16::try_from(src_hostname.len())
            .map_err(|_| TelemetryError::Pack("p2p hostname too long"))?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| TelemetryError::Pack("p2p payload too long"))?;
        let mut out = Vec::with_capacity(
            15usize
                .saturating_add(src_hostname.len())
                .saturating_add(payload.len()),
        );
        out.push(1);
        out.extend_from_slice(&dst_port.to_le_bytes());
        out.extend_from_slice(&src_port.to_le_bytes());
        out.extend_from_slice(&src_address.to_le_bytes());
        out.extend_from_slice(&host_len.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(src_hostname.as_bytes());
        out.extend_from_slice(payload);
        Ok(out.into())
    }

    fn decode_p2p_payload(payload: &[u8]) -> TelemetryResult<P2pDecoded<'_>> {
        if payload.len() < 15 {
            return Err(TelemetryError::Unpack("p2p frame short"));
        }
        if payload[0] != 1 {
            return Err(TelemetryError::Unpack("p2p frame version"));
        }
        let destination_port =
            u16::from_le_bytes(payload[1..3].try_into().expect("2-byte dst port"));
        let source_port = u16::from_le_bytes(payload[3..5].try_into().expect("2-byte src port"));
        let source_address = u32::from_le_bytes(payload[5..9].try_into().expect("4-byte address"));
        let host_len =
            u16::from_le_bytes(payload[9..11].try_into().expect("2-byte host len")) as usize;
        let body_len =
            u32::from_le_bytes(payload[11..15].try_into().expect("4-byte body len")) as usize;
        let host_start = 15usize;
        let host_end = host_start.saturating_add(host_len);
        let body_end = host_end.saturating_add(body_len);
        if host_end > payload.len() || body_end != payload.len() {
            return Err(TelemetryError::Unpack("p2p frame length"));
        }
        let source_hostname = core::str::from_utf8(&payload[host_start..host_end])
            .map_err(|_| TelemetryError::Unpack("p2p hostname utf8"))?;
        Ok(P2pDecoded {
            source_hostname,
            source_address,
            source_port,
            destination_port,
            payload: &payload[host_end..body_end],
        })
    }

    fn encode_p2p_stream_payload(
        flags: u8,
        source_stream_id: P2pStreamId,
        destination_stream_id: P2pStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> TelemetryResult<crate::SharedBytes> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| TelemetryError::Pack("p2p stream payload too long"))?;
        let mut out = Vec::with_capacity(22usize.saturating_add(payload.len()));
        out.extend_from_slice(&P2P_STREAM_MAGIC);
        out.push(P2P_STREAM_VERSION);
        out.push(flags);
        out.extend_from_slice(&source_stream_id.to_le_bytes());
        out.extend_from_slice(&destination_stream_id.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(payload);
        Ok(out.into())
    }

    fn decode_p2p_stream_payload(payload: &[u8]) -> TelemetryResult<Option<P2pStreamDecoded<'_>>> {
        if !payload.starts_with(&P2P_STREAM_MAGIC) {
            return Ok(None);
        }
        if payload.len() < 22 {
            return Err(TelemetryError::Unpack("p2p stream frame short"));
        }
        if payload[4] != P2P_STREAM_VERSION {
            return Err(TelemetryError::Unpack("p2p stream frame version"));
        }
        let flags = payload[5];
        let source_stream_id =
            u32::from_le_bytes(payload[6..10].try_into().expect("stream source id"));
        let destination_stream_id =
            u32::from_le_bytes(payload[10..14].try_into().expect("stream destination id"));
        let sequence = u32::from_le_bytes(payload[14..18].try_into().expect("stream sequence"));
        let body_len =
            u32::from_le_bytes(payload[18..22].try_into().expect("stream body len")) as usize;
        let body_end = 22usize.saturating_add(body_len);
        if body_end != payload.len() {
            return Err(TelemetryError::Unpack("p2p stream frame length"));
        }
        Ok(Some(P2pStreamDecoded {
            flags,
            source_stream_id,
            destination_stream_id,
            sequence,
            payload: &payload[22..],
        }))
    }

    fn allocate_p2p_stream_id_locked(st: &mut RouterInner) -> P2pStreamId {
        for _ in 0..u32::MAX {
            let id = st.next_p2p_stream_id.max(1);
            st.next_p2p_stream_id = st.next_p2p_stream_id.wrapping_add(1).max(1);
            if !st.p2p_stream_sessions.contains_key(&id) {
                return id;
            }
        }
        0
    }

    fn dispatch_p2p_packet(&self, pkt: &Packet) -> TelemetryResult<()> {
        if pkt.data_type() != DataType::P2pMessage {
            return Ok(());
        }
        let decoded = Self::decode_p2p_payload(pkt.payload())?;
        if let Some(stream) = Self::decode_p2p_stream_payload(decoded.payload)? {
            return self.dispatch_p2p_stream_frame(&decoded, &stream);
        }
        let handlers = {
            let st = self.state.lock();
            st.p2p_port_handlers
                .get(&decoded.destination_port)
                .cloned()
                .unwrap_or_default()
        };
        for handler in handlers {
            (handler.handler)(P2pMessage {
                source_hostname: decoded.source_hostname,
                source_address: decoded.source_address,
                source_port: decoded.source_port,
                destination_port: decoded.destination_port,
                payload: decoded.payload,
            })?;
        }
        Ok(())
    }

    fn dispatch_p2p_stream_frame(
        &self,
        msg: &P2pDecoded<'_>,
        frame: &P2pStreamDecoded<'_>,
    ) -> TelemetryResult<()> {
        let mut events: Vec<PendingP2pStreamEvent> = Vec::new();
        let mut reply: Option<(AddressBookEntry, P2pPort, P2pPort, crate::SharedBytes)> = None;
        {
            let mut st = self.state.lock();
            if frame.flags & P2P_STREAM_SYN != 0 && frame.flags & P2P_STREAM_ACK == 0 {
                let peer_hostname: Arc<str> = Arc::from(msg.source_hostname);
                let existing_id = st.p2p_stream_sessions.iter().find_map(|(id, session)| {
                    (session.peer_stream_id == frame.source_stream_id
                        && session.local_port == msg.destination_port
                        && session.peer_port == msg.source_port
                        && session.peer_address == msg.source_address
                        && session.peer_hostname.as_ref() == msg.source_hostname)
                        .then_some(*id)
                });
                let local_id = if let Some(local_id) = existing_id {
                    local_id
                } else {
                    let local_id = Self::allocate_p2p_stream_id_locked(&mut st);
                    if local_id == 0 {
                        return Err(TelemetryError::Io("p2p stream id exhausted"));
                    }
                    st.p2p_stream_sessions.insert(
                        local_id,
                        P2pStreamSession {
                            peer_hostname: peer_hostname.clone(),
                            peer_address: msg.source_address,
                            local_port: msg.destination_port,
                            peer_port: msg.source_port,
                            peer_stream_id: frame.source_stream_id,
                            next_sequence: 1,
                            connected: true,
                        },
                    );
                    let handlers = st
                        .p2p_stream_handlers
                        .get(&msg.destination_port)
                        .cloned()
                        .unwrap_or_default();
                    events.push(PendingP2pStreamEvent {
                        handlers,
                        kind: P2pStreamEventKind::Accepted,
                        stream_id: local_id,
                        peer_stream_id: frame.source_stream_id,
                        peer_hostname: peer_hostname.clone(),
                        peer_address: msg.source_address,
                        local_port: msg.destination_port,
                        peer_port: msg.source_port,
                    });
                    local_id
                };
                let dst =
                    st.address_book
                        .get(msg.source_hostname)
                        .cloned()
                        .unwrap_or(AddressBookEntry {
                            hostname: peer_hostname,
                            address: msg.source_address,
                            requested_address: msg.source_address,
                            mode: AddressAssignmentMode::Dynamic,
                            birth_ms: self.clock.now_ms(),
                            owner_hash: Self::sender_hash(msg.source_hostname),
                            last_seen_ms: self.clock.now_ms(),
                        });
                let payload = Self::encode_p2p_stream_payload(
                    P2P_STREAM_SYN | P2P_STREAM_ACK,
                    local_id,
                    frame.source_stream_id,
                    0,
                    &[],
                )?;
                reply = Some((dst, msg.source_port, msg.destination_port, payload));
            } else if frame.flags & P2P_STREAM_SYN != 0 && frame.flags & P2P_STREAM_ACK != 0 {
                if let Some(session) = st.p2p_stream_sessions.get_mut(&frame.destination_stream_id)
                {
                    session.peer_stream_id = frame.source_stream_id;
                    session.connected = true;
                    let peer_hostname = session.peer_hostname.clone();
                    let peer_address = session.peer_address;
                    let local_port = session.local_port;
                    let peer_port = session.peer_port;
                    let handlers = st
                        .p2p_stream_handlers
                        .get(&local_port)
                        .cloned()
                        .unwrap_or_default();
                    events.push(PendingP2pStreamEvent {
                        handlers,
                        kind: P2pStreamEventKind::Connected,
                        stream_id: frame.destination_stream_id,
                        peer_stream_id: frame.source_stream_id,
                        peer_hostname,
                        peer_address,
                        local_port,
                        peer_port,
                    });
                }
            } else if frame.flags & (P2P_STREAM_FIN | P2P_STREAM_RST | P2P_STREAM_DATA) != 0 {
                let kind = if frame.flags & P2P_STREAM_RST != 0 {
                    P2pStreamEventKind::Reset
                } else if frame.flags & P2P_STREAM_FIN != 0 {
                    P2pStreamEventKind::Closed
                } else {
                    P2pStreamEventKind::Data
                };
                let session_id = if frame.destination_stream_id != 0 {
                    Some(frame.destination_stream_id)
                } else {
                    st.p2p_stream_sessions.iter().find_map(|(id, session)| {
                        (session.peer_stream_id == frame.source_stream_id
                            && session.local_port == msg.destination_port
                            && session.peer_port == msg.source_port
                            && session.peer_address == msg.source_address
                            && session.peer_hostname.as_ref() == msg.source_hostname)
                            .then_some(*id)
                    })
                };
                if let Some(session_id) = session_id
                    && let Some(session) = st.p2p_stream_sessions.get(&session_id)
                {
                    let handlers = st
                        .p2p_stream_handlers
                        .get(&session.local_port)
                        .cloned()
                        .unwrap_or_default();
                    events.push(PendingP2pStreamEvent {
                        handlers,
                        kind,
                        stream_id: session_id,
                        peer_stream_id: frame.source_stream_id,
                        peer_hostname: session.peer_hostname.clone(),
                        peer_address: session.peer_address,
                        local_port: session.local_port,
                        peer_port: session.peer_port,
                    });
                    if matches!(kind, P2pStreamEventKind::Closed | P2pStreamEventKind::Reset) {
                        st.p2p_stream_sessions.remove(&session_id);
                    }
                }
            }
        }
        if let Some((dst, dst_port, src_port, payload)) = reply {
            self.send_p2p_to_entry(dst, dst_port, src_port, &payload)?;
        }
        for pending in events {
            for handler in pending.handlers {
                (handler.handler)(P2pStreamEvent {
                    kind: pending.kind,
                    stream_id: pending.stream_id,
                    peer_stream_id: pending.peer_stream_id,
                    sequence: frame.sequence,
                    peer_hostname: pending.peer_hostname.as_ref(),
                    peer_address: pending.peer_address,
                    local_port: pending.local_port,
                    peer_port: pending.peer_port,
                    payload: frame.payload,
                })?;
            }
        }
        Ok(())
    }

    /// Record the original live ingress for `packet_id`, preserving it across echoes.
    ///
    /// End-to-end reliable acknowledgements should return only toward the
    /// source-side that originated the data flow, not be flooded everywhere.
    /// This helper stores that learned return path in a bounded LRU-like cache.
    fn note_reliable_return_route(&self, side: RouterSideId, packet_id: u64) -> bool {
        let mut st = self.state.lock();
        // The retained proxy record owns retries until its child cohort
        // completes. Neither CAN reflections nor repeated upstream copies may
        // replace its return route or reapply the managed value meanwhile.
        if st.end_to_end_reliable_tx.contains_key(&packet_id)
            && st
                .reliable_return_routes
                .get(&packet_id)
                .is_some_and(|route| route.upstream_contract.is_some())
        {
            return false;
        }
        // A retry can remain in RX dedupe after its smaller return-path cache
        // entry was evicted. Relearning that path must not restart the replay
        // delay on every retry, or sustained cache churn suppresses it forever.
        let now = self.clock.now_ms();
        let retry_ms = runtime_reliable_retransmit_ms();
        let duplicate = st.recent_rx.contains(&packet_id)
            || st
                .reliable_return_routes
                .get(&packet_id)
                .is_some_and(|route| route.locally_delivered);
        let last_replay_ms = if duplicate {
            now.saturating_sub(retry_ms)
        } else {
            now
        };
        // A reflected copy is not evidence that the original publisher
        // moved. Keep the first live ingress during the current retry
        // window, otherwise an echo can redirect an already queued ACK into
        // the downstream bus. A retry-window expiry or disabled/removed side
        // still permits alternate-path recovery without explicit operator action.
        let replace_side = !duplicate
            || st
                .reliable_return_routes
                .get(&packet_id)
                .is_none_or(|route| {
                    now.saturating_sub(route.last_replay_ms) >= retry_ms
                        || !Self::side_ref(&st, route.side)
                            .is_ok_and(|side| side.opts.egress_enabled)
                });
        if !Self::remember_reliable_return_route_locked(&mut st, packet_id) {
            return true;
        }
        st.reliable_return_routes
            .entry(packet_id)
            .and_modify(|route| {
                if replace_side {
                    route.side = side;
                }
            })
            .or_insert(ReliableReturnRouteState {
                side,
                locally_delivered: false,
                last_replay_ms,
                upstream_contract: None,
            });
        true
    }

    /// Ensure `packet_id` is retained in the bounded reliable return-route cache.
    ///
    /// Existing entries are refreshed to the back of the order list. When the
    /// cache is full, evict the oldest route not pinned by active delivery.
    /// Refuse a new entry if every retained route is still active.
    fn remember_reliable_return_route_locked(st: &mut RouterInner, packet_id: u64) -> bool {
        let cap = runtime_reliable_max_return_routes().max(1);
        st.reliable_return_route_order
            .retain(|id| st.reliable_return_routes.contains_key(id) && *id != packet_id);
        while st.reliable_return_route_order.len() >= cap {
            let Some(index) = st
                .reliable_return_route_order
                .iter()
                .position(|id| !st.end_to_end_reliable_tx.contains_key(id))
            else {
                return false;
            };
            if let Some(oldest) = st.reliable_return_route_order.remove(index) {
                st.reliable_return_routes.remove(&oldest);
            }
        }
        st.reliable_return_route_order.push_back(packet_id);
        true
    }

    #[cfg(feature = "discovery")]
    fn remember_end_to_end_reliable_tx_locked(st: &mut RouterInner, packet_id: u64) {
        let cap = runtime_reliable_max_end_to_end_pending().max(1);
        st.end_to_end_reliable_tx_order
            .retain(|id| st.end_to_end_reliable_tx.contains_key(id) && *id != packet_id);
        while st.end_to_end_reliable_tx_order.len() >= cap {
            if let Some(oldest) = st.end_to_end_reliable_tx_order.pop_front() {
                st.end_to_end_reliable_tx.remove(&oldest);
            } else {
                break;
            }
        }
        st.end_to_end_reliable_tx_order.push_back(packet_id);
    }

    #[cfg(feature = "discovery")]
    fn expected_end_to_end_destinations_locked(
        &self,
        st: &RouterInner,
        data: &RouterItem,
        exclude: Option<RouterSideId>,
        managed: bool,
        resolve_proxy_segment: bool,
    ) -> TelemetryResult<BTreeMap<u64, RouterSideId>> {
        let (eps, ty) = self.item_route_info(data)?;
        // A targeted proxy creates a separate downstream contract. All other
        // dispatch/retry planning must retain the existing frozen owner set.
        let frozen_targets = if resolve_proxy_segment {
            wire_format::TargetSenderSet::Hashes(&[])
        } else {
            match data {
                RouterItem::Packet(packet) => {
                    wire_format::TargetSenderSet::Hashes(packet.wire_target_senders())
                }
                RouterItem::Packed(bytes) => {
                    wire_format::peek_routing_envelope(bytes)?.target_sender_set()
                }
            }
        };
        let now_ms = self.clock.now_ms();
        let restrict_link_local = Self::endpoints_are_link_local_only(&eps);
        /* Managed-variable ownership is advertised independently from normal
         * endpoint handlers.  Using topology-board endpoint overlap here can
         * silently narrow a variable update to one segment once detailed
         * topology arrives (for example FLIGHT_STATE is a conventional
         * endpoint on the fill side but only a managed variable on avionics).
         * Freeze one destination contract per advertising segment instead;
         * its announcer is the segment router that can ACK and replicate the
         * value to the owners behind it. */
        if managed || st.managed_variable_types.contains(&ty.as_u32()) {
            let mut out = BTreeMap::new();
            for (&side, route) in st.discovery_routes.iter() {
                if Some(side) == exclude {
                    continue;
                }
                if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                let Some(side_ref) = st.sides.get(side).and_then(Option::as_ref) else {
                    continue;
                };
                if restrict_link_local && !side_ref.opts.link_local_enabled {
                    continue;
                }
                if !self.route_allowed_locked(st, exclude, Some(ty), side) {
                    continue;
                }
                for (sender_id, sender_state) in route.announcers.iter() {
                    if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
                        || !sender_state.reachable_network_variables.contains(&ty)
                        || !Self::is_end_to_end_destination_sender(sender_id)
                    {
                        continue;
                    }
                    let owner = Self::sender_hash(sender_id);
                    if !frozen_targets.is_empty() && !frozen_targets.contains(owner) {
                        continue;
                    }
                    out.insert(owner, side);
                    if out.len() >= runtime_reliable_max_end_to_end_pending().max(1) {
                        return Ok(out);
                    }
                }
            }
            return Ok(out);
        }
        let prefer_best_overlap =
            is_reliable_type(ty) && Self::reliable_control_target_packet_id(data)?.is_none();
        let scoring_eps = self.preferred_scoring_endpoints(&eps, prefer_best_overlap);
        let mut best_overlap = 0usize;
        let limit = runtime_reliable_max_end_to_end_pending().max(1);
        let mut out = BTreeMap::new();
        for (&side, route) in st.discovery_routes.iter() {
            if Some(side) == exclude {
                continue;
            }
            if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                continue;
            }
            let Some(side_ref) = st.sides.get(side).and_then(Option::as_ref) else {
                continue;
            };
            if restrict_link_local && !side_ref.opts.link_local_enabled {
                continue;
            }
            if !self.route_allowed_locked(st, exclude, Some(ty), side) {
                continue;
            }
            for sender_state in route.announcers.values() {
                if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                for board in sender_state.topology_boards.iter() {
                    if !Self::is_end_to_end_destination_sender(&board.sender_id) {
                        continue;
                    }
                    let owner = Self::sender_hash(&board.sender_id);
                    if !frozen_targets.is_empty() && !frozen_targets.contains(owner) {
                        continue;
                    }
                    let overlap = Self::endpoint_overlap_count(
                        board.reachable_endpoints.iter().copied(),
                        &scoring_eps,
                    );
                    if overlap > 0 {
                        if prefer_best_overlap {
                            if overlap < best_overlap {
                                continue;
                            }
                            if overlap > best_overlap {
                                out.clear();
                                best_overlap = overlap;
                            }
                            // Keep only the first bounded cohort at the best
                            // score. Later higher scores replace it; no second
                            // candidate vector or allocation pass is needed.
                            if out.len() >= limit {
                                continue;
                            }
                        }
                        out.insert(owner, side);
                        if !prefer_best_overlap && out.len() >= limit {
                            return Ok(out);
                        }
                    }
                }
            }
        }

        Ok(out)
    }

    #[cfg(feature = "discovery")]
    #[allow(clippy::too_many_arguments)]
    fn discovered_route_candidates_locked(
        &self,
        st: &RouterInner,
        exclude: Option<RouterSideId>,
        ty: DataType,
        eps: &[DataEndpoint],
        target_senders: wire_format::TargetSenderSet<'_>,
        prefer_nonlocal: bool,
        preferred_timesync_source: Option<&str>,
    ) -> Vec<DiscoveryCandidateMatch> {
        let restrict_link_local = Self::endpoints_are_link_local_only(eps);
        let now_ms = self.clock.now_ms();
        let scoring_eps = self.preferred_scoring_endpoints(eps, prefer_nonlocal);
        let has_variable_owner = st.discovery_routes.iter().any(|(&side, route)| {
            exclude != Some(side)
                && now_ms.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                && route.reachable_network_variables.contains(&ty)
        });
        let mut out = Vec::new();
        let mut unique_endpoint_fallbacks = Vec::new();

        for (&side, route) in st.discovery_routes.iter() {
            if exclude == Some(side)
                || now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
            {
                continue;
            }
            if restrict_link_local
                && st
                    .sides
                    .get(side)
                    .and_then(|s| s.as_ref())
                    .map(|s| !s.opts.link_local_enabled)
                    .unwrap_or(true)
            {
                continue;
            }
            if !self.route_allowed_locked(st, exclude, Some(ty), side) {
                continue;
            }
            if !target_senders.is_empty()
                && !Self::side_matches_target_senders_locked(st, side, target_senders, now_ms)
            {
                if scoring_eps
                    .iter()
                    .copied()
                    .any(|ep| route.reachable.contains(&ep))
                {
                    unique_endpoint_fallbacks.push(side);
                }
                continue;
            }
            if !target_senders.is_empty() {
                out.push(DiscoveryCandidateMatch {
                    side,
                    overlap: usize::MAX,
                });
                continue;
            }
            if has_variable_owner {
                if route.reachable_network_variables.contains(&ty) {
                    out.push(DiscoveryCandidateMatch {
                        side,
                        overlap: usize::MAX,
                    });
                }
                continue;
            }
            if preferred_timesync_source
                .is_some_and(|source| route.reachable_timesync_sources.iter().any(|s| s == source))
            {
                out.push(DiscoveryCandidateMatch {
                    side,
                    overlap: usize::MAX,
                });
                continue;
            }
            let overlap =
                Self::endpoint_overlap_count(route.reachable.iter().copied(), &scoring_eps);
            if overlap > 0 {
                out.push(DiscoveryCandidateMatch { side, overlap });
            }
        }
        if !target_senders.is_empty() && out.is_empty() && unique_endpoint_fallbacks.len() == 1 {
            out.push(DiscoveryCandidateMatch {
                side: unique_endpoint_fallbacks[0],
                overlap: usize::MAX,
            });
        }
        out
    }

    /// Remove reflected discovery routes when another side advertises a
    /// shorter topology path to the destination endpoint. A multi-side Router
    /// must make this choice before adaptive weighting; otherwise an endpoint
    /// learned directly and through a remote bridge can be sent down either
    /// side with equal probability.
    #[cfg(feature = "discovery")]
    fn retain_shortest_discovery_candidates_locked(
        st: &RouterInner,
        matches: &mut Vec<DiscoveryCandidateMatch>,
        endpoints: &[DataEndpoint],
        target_senders: wire_format::TargetSenderSet<'_>,
        now_ms: u64,
    ) {
        if matches.len() <= 1 || endpoints.is_empty() {
            return;
        }

        let route_distance = |side: RouterSideId, target_sender: Option<u64>| -> Option<usize> {
            let route = st.discovery_routes.get(&side)?;
            route
                .announcers
                .iter()
                .filter(|(_, state)| {
                    now_ms.saturating_sub(state.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                })
                .filter_map(|(announcer, state)| {
                    let is_target = |board: &TopologyBoardNode| {
                        target_sender
                            .map(|target| Self::sender_hash(&board.sender_id) == target)
                            .unwrap_or_else(|| {
                                endpoints
                                    .iter()
                                    .any(|endpoint| board.reachable_endpoints.contains(endpoint))
                            })
                    };
                    // Targets are already owned by the topology snapshot. Avoid
                    // allocating a second set of their borrowed names.
                    if !state.topology_boards.iter().any(is_target) {
                        return if let Some(target) = target_sender {
                            state
                                .topology_boards
                                .iter()
                                .any(|board| Self::sender_hash(&board.sender_id) == target)
                                .then_some(usize::MAX / 2)
                        } else {
                            state
                                .reachable
                                .iter()
                                .any(|endpoint| endpoints.contains(endpoint))
                                .then_some(usize::MAX / 2)
                        };
                    }

                    let mut visited: BTreeSet<&str> = BTreeSet::new();
                    let mut pending = VecDeque::from([(announcer.as_str(), 0usize)]);
                    while let Some((sender, distance)) = pending.pop_front() {
                        if !visited.insert(sender) {
                            continue;
                        }
                        for board in state.topology_boards.iter() {
                            if board.sender_id == sender {
                                if is_target(board) {
                                    return Some(distance);
                                }
                                for peer in &board.connections {
                                    if !visited.contains(peer.as_str()) {
                                        pending.push_back((peer.as_str(), distance + 1));
                                    }
                                }
                            } else if board.connections.iter().any(|peer| peer == sender)
                                && !visited.contains(board.sender_id.as_str())
                            {
                                pending.push_back((board.sender_id.as_str(), distance + 1));
                            }
                        }
                    }
                    None
                })
                .min()
        };

        let route_targets = target_senders
            .iter()
            .map(Some)
            .chain(core::iter::once(None).filter(|_| target_senders.is_empty()));
        let mut selected = BTreeSet::new();
        for target in route_targets {
            let distances: Vec<(RouterSideId, usize)> = matches
                .iter()
                .filter_map(|candidate| {
                    route_distance(candidate.side, target)
                        .map(|distance| (candidate.side, distance))
                })
                .collect();
            let Some(best) = distances.iter().map(|(_, distance)| *distance).min() else {
                continue;
            };
            selected.extend(
                distances
                    .into_iter()
                    .filter(|(_, distance)| *distance == best)
                    .map(|(side, _)| side),
            );
        }
        if !selected.is_empty() {
            matches.retain(|candidate| selected.contains(&candidate.side));
        }
    }

    #[cfg(feature = "discovery")]
    fn select_discovered_candidate_sides_locked(
        &self,
        st: &mut RouterInner,
        exclude: Option<RouterSideId>,
        ty: DataType,
        target_senders: wire_format::TargetSenderSet<'_>,
        prefer_best_overlap: bool,
        matches: Vec<DiscoveryCandidateMatch>,
    ) -> Vec<RouterSideId> {
        let discovered_origin = if Self::has_typed_route_overrides_locked(st, exclude, ty)
            || !target_senders.is_empty()
        {
            RouteSelectionOrigin::Flood
        } else {
            RouteSelectionOrigin::Discovered
        };

        let mut matches = matches;
        if matches.iter().any(|m| m.overlap == usize::MAX) {
            matches.retain(|m| m.overlap == usize::MAX);
        }

        let selected: Vec<RouterSideId> = if prefer_best_overlap {
            let best_overlap = matches.iter().map(|m| m.overlap).max().unwrap_or(0);
            matches
                .into_iter()
                .filter(|m| m.overlap == best_overlap)
                .map(|m| m.side)
                .collect()
        } else {
            matches.into_iter().map(|m| m.side).collect()
        };

        /* Heartbeats represent network-wide liveness rather than a request for
         * one interchangeable endpoint owner.  When discovery finds the
         * heartbeat endpoint on multiple independent shortest-path sides,
         * every segment must receive it.  Ordinary data continues through the
         * adaptive single-path selector so a multi-homed router does not
         * duplicate application traffic. */
        let has_distributed_variable_owners = selected.iter().any(|side| {
            st.discovery_routes
                .get(side)
                .is_some_and(|route| route.reachable_network_variables.contains(&ty))
        });
        if DataType::try_named("HEARTBEAT") == Some(ty) || has_distributed_variable_owners {
            selected
        } else {
            self.apply_route_selection_locked(st, exclude, selected, discovered_origin)
        }
    }

    #[cfg(feature = "discovery")]
    fn register_end_to_end_reliable_tx(
        &self,
        data: &RouterItem,
        destinations: Option<BTreeMap<u64, RouterSideId>>,
    ) -> TelemetryResult<bool> {
        let packet_id = Self::get_hash(data);
        let now_ms = self.clock.now_ms();
        let ty = match data {
            RouterItem::Packet(pkt) => pkt.data_type(),
            RouterItem::Packed(bytes) => wire_format::peek_routing_envelope(bytes.as_ref())?.ty,
        };
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        let mut pending_destinations = match destinations {
            Some(destinations) => destinations,
            None => self.expected_end_to_end_destinations_locked(&st, data, None, false, false)?,
        };
        #[cfg(not(feature = "discovery"))]
        let mut pending_destinations = destinations.unwrap_or_default();
        // Callers pass the destination map used to construct this frozen
        // contract. Re-filtering the same map allocates owner scratch and
        // instantiates a second tree-extraction path on small MCUs.
        let frozen = match data {
            RouterItem::Packet(pkt) => !pkt.wire_target_senders().is_empty(),
            RouterItem::Packed(bytes) => {
                wire_format::peek_routing_envelope(bytes)?
                    .target_senders()
                    .len()
                    != 0
            }
        };
        self.filter_trackable_end_to_end_destinations_locked(
            &st,
            ty,
            &mut pending_destinations,
            frozen,
        );
        let tracked_destinations = !pending_destinations.is_empty();
        if let Some(existing) = st.end_to_end_reliable_tx.get(&packet_id) {
            return Ok(!existing.waiting_for_predecessor);
        }
        // Never evict an unacknowledged predecessor to admit a newer message.
        if st.end_to_end_reliable_tx.len() >= runtime_reliable_max_end_to_end_pending().max(1) {
            return Err(TelemetryError::Io("reliable window full"));
        }
        let ordered_type =
            matches!(reliable_mode(ty), crate::ReliableMode::Ordered).then_some(ty.as_u32());
        let waiting_for_predecessor = ordered_type.is_some()
            && st
                .end_to_end_reliable_tx
                .values()
                .any(|sent| sent.ordered_type == ordered_type);
        #[cfg(feature = "std")]
        if reliable_trace_enabled() {
            eprintln!(
                "[sedsnet-reliable] register time={now_ms} type={} id={packet_id:#x} waiting={waiting_for_predecessor} targets={pending_destinations:?}",
                ty.as_u32()
            );
        }
        #[cfg(feature = "compression")]
        let retained = match data {
            RouterItem::Packed(bytes) => RouterItem::Packed(
                wire_format::payload_encoding_for_retention(
                    bytes.as_ref(),
                    st.memory.max_queue_budget,
                )?
                .map(crate::shared_bytes::convert)
                .unwrap_or_else(|| bytes.clone()),
            ),
            packet => packet.clone(),
        };
        #[cfg(not(feature = "compression"))]
        let retained = data.clone();
        #[cfg(feature = "compact-packet-store")]
        let mut retained = retained;
        #[cfg(feature = "compact-packet-store")]
        retained.park_for_queue()?;
        Self::remember_end_to_end_reliable_tx_locked(&mut st, packet_id);
        st.end_to_end_reliable_tx.insert(
            packet_id,
            EndToEndReliableSent {
                ordered_type,
                waiting_for_predecessor,
                data: retained,
                pending_destinations,
                tracked_destinations,
                last_send_ms: now_ms,
                retries: 0,
                queued: false,
            },
        );
        Ok(!waiting_for_predecessor)
    }

    // Select at most one in-flight packet per ordered type. Waiting messages
    // share the existing bounded pending window, not an unbounded extra queue.
    fn release_ordered_successors(&self) -> TelemetryResult<()> {
        let ready = {
            let mut st = self.state.lock();
            let RouterInner {
                end_to_end_reliable_tx_order: order,
                end_to_end_reliable_tx: pending,
                ..
            } = &mut *st;
            let mut ready = Vec::new();
            for (index, id) in order.iter().copied().enumerate() {
                let Some(sent) = pending.get(&id) else {
                    continue;
                };
                if !sent.waiting_for_predecessor {
                    continue;
                }
                let Some(ty) = sent.ordered_type else {
                    continue;
                };
                // The retained window is bounded. Inspect earlier entries
                // instead of rebuilding an allocated active-type set on every
                // idle service pass. Only an actual release needs ready storage.
                if order.iter().take(index).any(|earlier| {
                    pending
                        .get(earlier)
                        .is_some_and(|sent| sent.ordered_type == Some(ty))
                }) {
                    continue;
                }
                let sent = pending.get_mut(&id).expect("retained ordered entry");
                sent.waiting_for_predecessor = false;
                sent.last_send_ms = self.clock.now_ms();
                ready.push(id);
            }
            ready
        };
        for id in ready {
            self.queue_end_to_end_reliable_retransmit(id)?;
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn reconcile_end_to_end_reliable_destinations_locked(
        &self,
        st: &mut RouterInner,
    ) -> TelemetryResult<()> {
        if st.end_to_end_reliable_tx.is_empty() {
            return Ok(());
        }
        let active_destinations = self.active_end_to_end_destinations_locked(st);
        let packet_ids: Vec<u64> = st.end_to_end_reliable_tx.keys().copied().collect();
        let mut completed = Vec::new();

        for packet_id in packet_ids {
            let Some(data) = st
                .end_to_end_reliable_tx
                .get(&packet_id)
                .map(|sent| sent.data.clone())
            else {
                continue;
            };
            let excluded = st
                .reliable_return_routes
                .get(&packet_id)
                .filter(|route| route.upstream_contract.is_some())
                .map(|route| route.side);
            let expected =
                self.expected_end_to_end_destinations_locked(st, &data, excluded, false, false)?;
            let Some(sent) = st.end_to_end_reliable_tx.get_mut(&packet_id) else {
                continue;
            };
            if !sent.tracked_destinations {
                continue;
            }
            // Route churn is not a delivery acknowledgement for ordered data.
            if sent.ordered_type.is_some() {
                for (sender, side) in &mut sent.pending_destinations {
                    if let Some(next_side) = expected.get(sender).or_else(|| {
                        active_destinations
                            .get(sender)
                            .filter(|side| Some(**side) != excluded)
                    }) {
                        *side = *next_side;
                    }
                }
                continue;
            }
            sent.pending_destinations.retain(|sender_hash, side| {
                match (
                    expected.get(sender_hash),
                    active_destinations
                        .get(sender_hash)
                        .filter(|side| Some(**side) != excluded),
                ) {
                    (Some(next_side), _) | (None, Some(next_side)) => {
                        *side = *next_side;
                        true
                    }
                    (None, None) => false,
                }
            });
            if sent.pending_destinations.is_empty() {
                completed.push(packet_id);
            }
        }

        for packet_id in completed {
            st.end_to_end_reliable_tx.remove(&packet_id);
        }

        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn active_end_to_end_destinations_locked(
        &self,
        st: &RouterInner,
    ) -> BTreeMap<u64, RouterSideId> {
        let now_ms = self.clock.now_ms();
        let mut out = BTreeMap::new();
        for (&side, route) in st.discovery_routes.iter() {
            if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                continue;
            }
            for (sender_name, sender_state) in &route.announcers {
                if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                if Self::is_end_to_end_destination_sender(sender_name) {
                    out.insert(Self::sender_hash(sender_name), side);
                }
                for board in sender_state.topology_boards.iter() {
                    if !Self::is_end_to_end_destination_sender(&board.sender_id) {
                        continue;
                    }
                    out.insert(Self::sender_hash(&board.sender_id), side);
                    if out.len() >= runtime_reliable_max_end_to_end_pending().max(1) {
                        return out;
                    }
                }
            }
        }
        out
    }

    #[cfg(feature = "discovery")]
    fn side_supports_end_to_end_tracking_locked(st: &RouterInner, side: RouterSideId) -> bool {
        matches!(
            st.sides
                .get(side)
                .and_then(Option::as_ref)
                .map(|side| &side.tx_handler),
            Some(RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_))
        )
    }

    #[cfg(feature = "discovery")]
    fn filter_trackable_end_to_end_destinations_locked(
        &self,
        st: &RouterInner,
        ty: DataType,
        pending: &mut BTreeMap<u64, RouterSideId>,
        frozen: bool,
    ) {
        // A heartbeat describes current liveness. Retrying an old heartbeat
        // until every discovered endpoint acknowledges it turns temporary
        // congestion into an ACK/retransmit storm and can starve fresh
        // heartbeats. Per-link reliability still applies where configured;
        // the next periodic heartbeat is the end-to-end freshness retry.
        if DataType::try_named("HEARTBEAT") == Some(ty) {
            pending.clear();
            return;
        }
        if frozen {
            return;
        }
        let now_ms = self.clock.now_ms();
        pending.retain(|_, side| {
            Self::side_supports_end_to_end_tracking_locked(st, *side)
                && (st.managed_variable_types.contains(&ty.as_u32())
                    || is_reliable_type(ty)
                    || !self.side_has_multiple_announcers_locked(st, *side, now_ms))
        });
    }

    #[cfg(feature = "discovery")]
    fn side_has_multiple_announcers_locked(
        &self,
        st: &RouterInner,
        side: RouterSideId,
        now_ms: u64,
    ) -> bool {
        st.discovery_routes
            .get(&side)
            .map(|route| {
                route
                    .announcers
                    .values()
                    .filter(|sender| {
                        now_ms.saturating_sub(sender.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                    })
                    .take(2)
                    .count()
                    > 1
            })
            .unwrap_or(false)
    }

    #[cfg(not(feature = "discovery"))]
    fn side_has_multiple_announcers_locked(
        &self,
        _st: &RouterInner,
        _side: RouterSideId,
        _now_ms: u64,
    ) -> bool {
        false
    }

    fn queue_end_to_end_reliable_ack(
        &self,
        pkt: &Packet,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        self.queue_end_to_end_reliable_ack_for_packet_id(
            pkt.packet_id(),
            pkt.sender(),
            called_from_queue,
        )
    }

    fn queue_end_to_end_reliable_ack_for_packet_id(
        &self,
        packet_id: u64,
        original_sender: &str,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if !self.cfg.reliable_enabled() {
            return Ok(());
        }
        let original_sender_hash = {
            let mut st = self.state.lock();
            // This helper is reached after local delivery succeeds, before
            // attempting its final receipt. Keep that fact in the existing
            // bounded reliable return-route cache: best-effort telemetry can
            // churn recent_rx thousands of times while this receipt retries.
            if let Some(route) = st.reliable_return_routes.get_mut(&packet_id) {
                route.locally_delivered = true;
            }
            Self::sender_hash(&Self::canonical_sender_locked(&st, original_sender))
        };
        self.queue_end_to_end_reliable_ack_for_sender_hash(
            packet_id,
            original_sender_hash,
            called_from_queue,
        )
    }

    fn queue_end_to_end_reliable_ack_for_sender_hash(
        &self,
        packet_id: u64,
        original_sender_hash: u64,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if !self.cfg.reliable_enabled() {
            return Ok(());
        }
        let ack_sender = self.encode_end_to_end_ack_sender();
        let ack = Packet::new_local(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_owned(),
            Arc::from(ack_sender),
            self.packet_timestamp_ms(),
            crate::config::StandardSmallPayload::new(&packet_id.to_le_bytes()),
        )?;
        let local_sender = self.sender_arc();
        // Keep the acknowledging owner first for compatibility. The second
        // identity is the original publisher: it lets a busy relay recover the
        // ACK route from discovery after its bounded packet-id cache expires.
        let ack = self.attach_wire_contract_to_item(
            RouterItem::Packet(ack),
            &[
                Self::sender_hash(local_sender.as_ref()),
                original_sender_hash,
            ],
        )?;
        // Freeze a known return side in the queued receipt itself. Its bounded
        // packet-id cache can churn before dispatch; an echoed data frame must
        // not redirect an ACK which already has a valid destination.
        let return_side = {
            let st = self.state.lock();
            st.reliable_return_routes
                .get(&packet_id)
                .map(|route| route.side)
        };
        let item = match return_side {
            Some(dst) => RouterTxItem::ToSide {
                src: None,
                dst,
                data: ack,
            },
            None => RouterTxItem::Broadcast(ack),
        };
        self.emit_internal_tx(item, true, called_from_queue)
    }

    fn emit_internal_tx(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if called_from_queue {
            self.tx_queue_item_with_flags(item, ignore_local)
        } else {
            self.tx_item_impl(item, ignore_local, false)
        }
    }

    fn emit_internal_tx_with_priority(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        priority: u8,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if called_from_queue {
            self.tx_queue_item_with_priority(item, ignore_local, priority)
        } else {
            self.tx_item_impl(item, ignore_local, false)
        }
    }

    fn queue_end_to_end_reliable_retransmit(&self, packet_id: u64) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let result = self.tx_queue_item_with_priority(
            RouterTxItem::EndToEndReplay { packet_id },
            true,
            Self::router_item_priority_bumped(DataType::ReliableAck),
        );
        // A reservation is one retry attempt. If control admission later evicts
        // its marker, wait a full interval instead of exhausting the budget in
        // successive maintenance polls before any transport can run.
        if result.is_ok()
            && let Some(sent) = self.state.lock().end_to_end_reliable_tx.get_mut(&packet_id)
        {
            sent.last_send_ms = sent.last_send_ms.max(now);
        }
        result
    }

    fn end_to_end_retransmit_sides(
        &self,
        packet_id: u64,
    ) -> Option<(RouterItem, Vec<RouterSideId>)> {
        let mut st = self.state.lock();
        let (data, tracked_destinations, mut sides) = {
            let sent = st.end_to_end_reliable_tx.get_mut(&packet_id)?;
            #[cfg(feature = "std")]
            if reliable_trace_enabled() {
                eprintln!(
                    "[sedsnet-reliable] replay time={} id={packet_id:#x} retries={} targets={:?}",
                    self.clock.now_ms(),
                    sent.retries,
                    sent.pending_destinations
                );
            }
            sent.queued = false;
            sent.last_send_ms = self.clock.now_ms();
            let data = sent.data.clone();
            let tracked_destinations = sent.tracked_destinations;
            let sides: Vec<RouterSideId> = sent.pending_destinations.values().copied().collect();
            (data, tracked_destinations, sides)
        };
        if tracked_destinations && sides.is_empty() {
            st.end_to_end_reliable_tx.remove(&packet_id);
            return None;
        }
        crate::small_sort::sort(&mut sides);
        sides.dedup();
        Some((data, sides))
    }

    fn item_type_priority(data: &RouterItem) -> TelemetryResult<(DataType, u8)> {
        let (ty, control) = match data {
            RouterItem::Packet(pkt) => (
                pkt.data_type(),
                pkt.payload().len() <= 16
                    && pkt.endpoints().len() <= 3
                    && crate::small_frozen_control(
                        pkt.data_type(),
                        pkt.wire_target_senders().len(),
                        pkt.wire_shape(),
                    ),
            ),
            RouterItem::Packed(bytes) => {
                let frame = wire_format::peek_routing_frame_info(bytes.as_ref())?;
                let env = &frame.envelope;
                // Hop ACKs carry the original data type. Their validated
                // control header, not that type's bulk priority, releases credit.
                if bytes.len() <= 128 && frame.ack_only() {
                    return Ok((
                        env.ty,
                        crate::transport_priority(crate::DataType::ReliableAck),
                    ));
                }
                let control = bytes.len() <= 128
                    && bytes.first().is_some_and(|flags| flags & 0x11 == 0)
                    && env.endpoints().take(4).count() <= 3
                    && crate::small_frozen_control(
                        env.ty,
                        env.target_senders().len(),
                        env.wire_shape,
                    );
                (env.ty, control)
            }
        };
        let priority = crate::scheduler_priority(ty);
        Ok((ty, if control { priority.max(254) } else { priority }))
    }

    fn router_item_priority(data: &RouterItem) -> TelemetryResult<u8> {
        Self::item_type_priority(data).map(|(_, priority)| priority)
    }

    fn item_service_type_priority(&self, data: &RouterItem) -> TelemetryResult<(DataType, u8)> {
        let (ty, priority) = Self::item_type_priority(data)?;
        let priority = if self.is_managed_variable_type(ty) {
            crate::transport_priority(DataType::ManagedVariableValue)
        } else {
            priority
        };
        Ok((ty, priority))
    }

    fn item_service_priority(&self, data: &RouterItem) -> TelemetryResult<u8> {
        self.item_service_type_priority(data)
            .map(|(_, priority)| priority)
    }

    #[inline]
    fn router_item_priority_bumped(ty: DataType) -> u8 {
        crate::scheduler_priority(ty).saturating_add(16)
    }

    #[inline]
    fn is_transient_tx_error(err: &TelemetryError) -> bool {
        matches!(
            err,
            TelemetryError::Io("side tx busy" | "memory pressure" | "reliable window full")
        )
    }

    #[cfg(feature = "timesync")]
    fn timesync_has_usable_time_locked(st: &TimeSyncRuntime, now_mono_ns: u64) -> bool {
        st.disciplined_clock.read_unix_ms(now_mono_ns).is_some()
            || st
                .clock
                .current_time(now_mono_ns)
                .and_then(|reading| reading.unix_time_ms)
                .is_some()
    }

    #[cfg(feature = "timesync")]
    fn reconcile_pending_timesync_request_locked(
        st: &mut TimeSyncRuntime,
        leader: &Option<TimeSyncLeader>,
        now_ms: u64,
    ) {
        let active_remote = match leader {
            Some(TimeSyncLeader::Remote(remote)) => Some(remote.sender.as_str()),
            _ => None,
        };
        let should_clear = st
            .pending_request
            .as_ref()
            .is_some_and(|pending| Some(pending.source.as_str()) != active_remote);
        if should_clear {
            st.pending_request = None;
            st.next_request_mono_ms = now_ms;
        }
    }

    ///Helper function for relay_send
    #[inline]
    fn enqueue_to_sides(
        &self,
        data: RouterItem,
        exclude: Option<RouterSideId>,
        ignore_local: bool,
    ) -> TelemetryResult<()> {
        let Some(data) = self.clear_intermediate_hop_targets(data, true)? else {
            return Ok(());
        };
        let plan = self.remote_side_plan(&data, exclude)?;
        let mut st = self.state.lock();
        let ty = Self::item_data_type(&data)?;
        let priority = if st.managed_variable_types.contains(&ty.as_u32()) {
            crate::transport_priority(DataType::ManagedVariableValue)
        } else {
            Self::router_item_priority(&data)?
        };

        let RemoteSidePlan::Target(sides) = plan;
        for idx in sides {
            st.push_transmit(TxQueued {
                disposable: true,
                item: RouterTxItem::ToSide {
                    src: exclude,
                    dst: idx,
                    data: data.clone(),
                },
                ignore_local,
                priority,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })?;
        }

        Ok(())
    }

    fn relay_send(
        &self,
        data: RouterItem,
        src: Option<RouterSideId>,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        if called_from_queue {
            return self.enqueue_to_sides(data, src, true);
        }

        let Some(data) = self.clear_intermediate_hop_targets(data, false)? else {
            return Ok(());
        };
        let RemoteSidePlan::Target(sides) = self.remote_side_plan(&data, src)?;
        for side in sides {
            self.tx_item_impl(
                RouterTxItem::ToSide {
                    src,
                    dst: side,
                    data: data.clone(),
                },
                true,
                false,
            )?;
        }

        Ok(())
    }

    fn item_route_info(&self, data: &RouterItem) -> TelemetryResult<(Vec<DataEndpoint>, DataType)> {
        match data {
            RouterItem::Packet(pkt) => {
                pkt.validate()?;
                let mut eps = pkt.endpoints().to_vec();
                crate::small_sort::sort(&mut eps);
                eps.dedup();
                Ok((eps, pkt.data_type()))
            }
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_routing_envelope(bytes.as_ref())?;
                let mut eps: Vec<DataEndpoint> = env.endpoints().collect();
                crate::small_sort::sort(&mut eps);
                eps.dedup();
                Ok((eps, env.ty))
            }
        }
    }

    fn unpack_packet_for_role(&self, bytes: &[u8]) -> TelemetryResult<Packet> {
        let managed = crate::memory_admission::supports_work_kinds()
            && wire_format::scheduling_type(bytes).is_some_and(|ty| {
                !is_internal_control_type(ty) && self.is_managed_variable_type(ty)
            });
        wire_format::unpack_packet_with_role(bytes, managed)
    }

    fn item_data_type(data: &RouterItem) -> TelemetryResult<DataType> {
        match data {
            RouterItem::Packet(pkt) => Ok(pkt.data_type()),
            RouterItem::Packed(bytes) => Ok(wire_format::peek_routing_envelope(bytes.as_ref())?.ty),
        }
    }

    fn e2e_crypto_supported(&self) -> bool {
        #[cfg(feature = "cryptography")]
        {
            self.cfg.e2e_encryption() != RouterE2eEncryptionMode::Disabled
                && crate::crypto::registered_crypto_available()
        }
        #[cfg(not(feature = "cryptography"))]
        {
            false
        }
    }

    fn should_require_e2e_for_type(&self, ty: DataType) -> bool {
        if is_internal_control_type(ty) {
            return false;
        }
        match self.cfg.e2e_encryption() {
            RouterE2eEncryptionMode::Disabled => {
                message_e2e_encryption_policy(ty) == E2eEncryptionPolicy::RequireOn
            }
            RouterE2eEncryptionMode::RequiredOnly => {
                message_e2e_encryption_policy(ty) == E2eEncryptionPolicy::RequireOn
            }
            RouterE2eEncryptionMode::Preferred => matches!(
                message_e2e_encryption_policy(ty),
                E2eEncryptionPolicy::PreferOn | E2eEncryptionPolicy::RequireOn
            ),
            RouterE2eEncryptionMode::ForceAll => true,
        }
    }

    fn ensure_e2e_policy_supported_for_type(&self, ty: DataType) -> TelemetryResult<()> {
        if self.should_require_e2e_for_type(ty) && !self.e2e_crypto_supported() {
            return Err(TelemetryError::BadArg);
        }
        Ok(())
    }

    #[cfg(feature = "cryptography")]
    fn e2e_seal_config_for_type(&self, ty: DataType) -> Option<wire_format::E2eSealConfig> {
        if self.should_require_e2e_for_type(ty) && self.e2e_crypto_supported() {
            Some(wire_format::E2eSealConfig {
                key_id: self.cfg.e2e_key_id(),
            })
        } else {
            None
        }
    }

    #[inline]
    fn pack_packet_for_router(
        &self,
        pkt: &Packet,
        reliable: Option<wire_format::ReliableHeader>,
    ) -> TelemetryResult<crate::SharedBytes> {
        #[cfg(feature = "compression")]
        {
            #[cfg(feature = "cryptography")]
            let e2e = self.e2e_seal_config_for_type(pkt.data_type());
            #[cfg(not(feature = "cryptography"))]
            let e2e = None;
            let reliable = reliable.or_else(|| {
                is_reliable_type(pkt.data_type()).then_some(wire_format::ReliableHeader {
                    flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
                    seq: 0,
                    ack: 0,
                })
            });
            wire_format::pack_routed_packet(
                pkt,
                reliable,
                pkt.wire_shape(),
                pkt.wire_target_senders(),
                e2e,
            )
            .map(crate::shared_bytes::convert)
        }
        #[cfg(not(feature = "compression"))]
        {
            #[cfg(feature = "cryptography")]
            if let Some(e2e) = self.e2e_seal_config_for_type(pkt.data_type()) {
                return (wire_format::pack_packet_with_wire_contract_e2e(
                    pkt,
                    reliable,
                    pkt.wire_shape(),
                    pkt.wire_target_senders(),
                    e2e,
                ))
                .map(crate::shared_bytes::convert);
            }
            Ok(match reliable {
                Some(hdr) => {
                    crate::shared_bytes::convert(wire_format::pack_packet_with_reliable(pkt, hdr))
                }
                None => crate::shared_bytes::convert(wire_format::pack_packet(pkt)),
            })
        }
    }

    #[inline]
    fn pack_packet_for_contract(
        &self,
        pkt: &Packet,
        reliable: Option<wire_format::ReliableHeader>,
        shape: Option<MessageElement>,
        target_senders: &[u64],
    ) -> TelemetryResult<crate::SharedBytes> {
        #[cfg(feature = "compression")]
        {
            #[cfg(feature = "cryptography")]
            let e2e = self.e2e_seal_config_for_type(pkt.data_type());
            #[cfg(not(feature = "cryptography"))]
            let e2e = None;
            wire_format::pack_routed_packet(pkt, reliable, shape, target_senders, e2e)
                .map(crate::shared_bytes::convert)
        }
        #[cfg(not(feature = "compression"))]
        {
            #[cfg(feature = "cryptography")]
            if let Some(e2e) = self.e2e_seal_config_for_type(pkt.data_type()) {
                return (wire_format::pack_packet_with_wire_contract_e2e(
                    pkt,
                    reliable,
                    shape,
                    target_senders,
                    e2e,
                ))
                .map(crate::shared_bytes::convert);
            }
            wire_format::pack_packet_with_wire_contract(pkt, reliable, shape, target_senders)
                .map(crate::shared_bytes::convert)
        }
    }

    #[cfg(feature = "cryptography")]
    #[inline]
    fn prepare_packed_for_remote(
        &self,
        bytes: crate::SharedBytes,
        reliable_override: Option<Option<wire_format::ReliableHeader>>,
    ) -> TelemetryResult<crate::SharedBytes> {
        let frame = wire_format::peek_frame_info(bytes.as_ref())?;
        if frame.ack_only() || self.e2e_seal_config_for_type(frame.envelope.ty).is_none() {
            return Ok(bytes);
        }
        let reliable = reliable_override.unwrap_or(frame.reliable);
        let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
        self.pack_packet_for_contract(
            &pkt,
            reliable,
            frame.envelope.wire_shape,
            &frame.envelope.target_senders,
        )
    }

    // Best-effort telemetry does not become reliable merely because discovery
    // currently sees one peer. Preserve explicit frozen receipt contracts and
    // managed-variable delivery even when the current schema is best effort.
    fn item_requires_end_to_end_tracking(
        &self,
        data: &RouterItem,
        ty: DataType,
    ) -> TelemetryResult<bool> {
        if is_reliable_type(ty) || self.is_managed_variable_type(ty) {
            return Ok(true);
        }
        match data {
            RouterItem::Packet(packet) => Ok(!packet.wire_target_senders().is_empty()),
            RouterItem::Packed(bytes) => {
                let frame = wire_format::peek_routing_frame_info(bytes.as_ref())?;
                Ok(frame.reliable.is_some() || frame.envelope.target_senders().len() != 0)
            }
        }
    }

    #[cfg(feature = "discovery")]
    fn item_target_senders<'a>(
        &self,
        data: &'a RouterItem,
    ) -> TelemetryResult<wire_format::TargetSenderSet<'a>> {
        match data {
            RouterItem::Packet(pkt) => Ok(wire_format::TargetSenderSet::Hashes(
                pkt.wire_target_senders(),
            )),
            RouterItem::Packed(bytes) => {
                Ok(wire_format::peek_routing_envelope(bytes.as_ref())?.target_sender_set())
            }
        }
    }

    fn item_targets_another_sender(&self, data: &RouterItem) -> TelemetryResult<bool> {
        let local_hash = Self::sender_hash(self.sender_arc().as_ref());
        match data {
            RouterItem::Packet(pkt) => {
                Ok(pkt.wire_target_senders().iter().any(|v| *v != local_hash))
            }
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_routing_envelope(bytes.as_ref())?;
                Ok(env.target_senders().any(|target| target != local_hash))
            }
        }
    }

    fn item_targets_local_sender(&self, data: &RouterItem) -> TelemetryResult<bool> {
        let local_hash = Self::sender_hash(self.sender_arc().as_ref());
        match data {
            RouterItem::Packet(pkt) => Ok(pkt.wire_target_senders().is_empty()
                || pkt.wire_target_senders().contains(&local_hash)),
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_routing_envelope(bytes.as_ref())?;
                Ok(env.target_senders().len() == 0
                    || env.target_senders().any(|target| target == local_hash))
            }
        }
    }

    fn item_targets_router_as_intermediate_hop(
        &self,
        data: &RouterItem,
        endpoints: &[DataEndpoint],
    ) -> TelemetryResult<bool> {
        // Inspect borrowed owners once. ACK contracts identify receipt owners,
        // not managed-value proxies; unaddressed transit remains byte-identical.
        let local_target = match data {
            RouterItem::Packet(pkt) => {
                if pkt.wire_target_senders().is_empty() || is_internal_control_type(pkt.data_type())
                {
                    return Ok(false);
                }
                pkt.wire_target_senders()
                    .contains(&Self::sender_hash(self.sender_arc().as_ref()))
            }
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_routing_envelope(bytes)?;
                if env.target_senders().len() == 0 || is_internal_control_type(env.ty) {
                    return Ok(false);
                }
                let local = Self::sender_hash(self.sender_arc().as_ref());
                env.target_senders().any(|owner| owner == local)
            }
        };
        Ok(local_target
            && !endpoints.iter().copied().any(|endpoint| {
                self.endpoint_has_packet_handler(endpoint)
                    || self.endpoint_has_packed_handler(endpoint)
            }))
    }

    fn clear_intermediate_hop_targets(
        &self,
        data: RouterItem,
        called_from_queue: bool,
    ) -> TelemetryResult<Option<RouterItem>> {
        // Every explicitly targeted proxy resolves its own downstream segment,
        // including a publisher contract naming several independent bridges.
        // Ordinary broadcasts need no owned endpoint or target scratch.
        let has_targets = match &data {
            RouterItem::Packet(pkt) => !pkt.wire_target_senders().is_empty(),
            RouterItem::Packed(bytes) => {
                wire_format::peek_routing_envelope(bytes)?
                    .target_senders()
                    .len()
                    != 0
            }
        };
        if !has_targets {
            return Ok(Some(data));
        }
        let (endpoints, _) = self.item_route_info(&data)?;
        if !self.item_targets_router_as_intermediate_hop(&data, &endpoints)? {
            return Ok(Some(data));
        }
        let pkt = match &data {
            RouterItem::Packet(pkt) => pkt.clone(),
            RouterItem::Packed(bytes) => self.unpack_packet_for_role(bytes.as_ref())?,
        };
        let reliable = match &data {
            RouterItem::Packet(_) => None,
            RouterItem::Packed(bytes) => wire_format::peek_frame_info(bytes.as_ref())?.reliable,
        };
        let shape = match &data {
            RouterItem::Packet(pkt) => pkt.wire_shape(),
            RouterItem::Packed(bytes) => {
                wire_format::peek_routing_envelope(bytes.as_ref())?.wire_shape
            }
        };
        let upstream_id = Self::get_hash(&data);
        #[cfg(feature = "discovery")]
        let destinations = {
            let st = self.state.lock();
            let upstream = st
                .reliable_return_routes
                .get(&upstream_id)
                .map(|route| route.side);
            let mut pending =
                self.expected_end_to_end_destinations_locked(&st, &data, upstream, true, true)?;
            if pending.is_empty() {
                pending = self
                    .expected_end_to_end_destinations_locked(&st, &data, upstream, false, true)?;
            }
            pending
        };
        #[cfg(feature = "discovery")]
        let targets: Vec<u64> = destinations.keys().copied().collect();
        #[cfg(not(feature = "discovery"))]
        let targets: Vec<u64> = Vec::new();
        #[cfg(feature = "discovery")]
        if targets.is_empty() {
            if self.packet_has_local_delivery(&pkt) {
                self.queue_end_to_end_reliable_ack_for_packet_id(
                    upstream_id,
                    pkt.sender(),
                    called_from_queue,
                )?;
                return Ok(Some(data));
            }
            if !is_reliable_type(pkt.data_type()) && reliable.is_none() {
                return Err(TelemetryError::Io("no discovered route"));
            }
        }
        // Preserve the publisher's packet identity across proxy hops. The
        // alias and frozen reader cohort distinguish downstream receipts;
        // changing the nonce here would defeat deduplication around cycles.
        let forwarded = self.pack_packet_for_contract(&pkt, reliable, shape, &targets)?;
        let downstream_id = wire_format::packet_id_from_wire(forwarded.as_ref())?;
        let forwarded = RouterItem::Packed(forwarded);
        #[cfg(feature = "discovery")]
        let already_pending = self
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&downstream_id);
        #[cfg(feature = "discovery")]
        let ready = self.register_end_to_end_reliable_tx(&forwarded, Some(destinations))?;
        #[cfg(not(feature = "discovery"))]
        let (ready, already_pending) = {
            let _ = called_from_queue;
            (true, false)
        };
        #[cfg(feature = "std")]
        if reliable_trace_enabled() {
            eprintln!(
                "[sedsnet-reliable] proxy retain upstream={upstream_id:#x} downstream={downstream_id:#x} existing={already_pending} ready={ready}"
            );
        }
        {
            let mut st = self.state.lock();
            let Some(mut route) = st.reliable_return_routes.get(&upstream_id).cloned() else {
                st.end_to_end_reliable_tx.remove(&downstream_id);
                return Err(TelemetryError::Io("no reliable return route"));
            };
            route.upstream_contract = Some((
                upstream_id,
                Self::sender_hash(&Self::canonical_sender_locked(&st, pkt.sender())),
            ));
            if !Self::remember_reliable_return_route_locked(&mut st, downstream_id) {
                st.end_to_end_reliable_tx.remove(&downstream_id);
                return Err(TelemetryError::Io("reliable return route window full"));
            }
            st.reliable_return_routes.insert(downstream_id, route);
        }
        Ok((ready && !already_pending).then_some(forwarded))
    }

    #[cfg(feature = "discovery")]
    fn side_matches_target_senders_locked(
        st: &RouterInner,
        side: RouterSideId,
        target_senders: wire_format::TargetSenderSet<'_>,
        now_ms: u64,
    ) -> bool {
        st.discovery_routes
            .get(&side)
            .map(|route| {
                if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    return false;
                }
                route.announcers.iter().any(|(announcer, sender_state)| {
                    if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                        return false;
                    }
                    target_senders.contains(Self::sender_hash(announcer))
                        || sender_state
                            .advertised_address
                            .is_some_and(|address| target_senders.contains(u64::from(address)))
                        || sender_state.topology_boards.iter().any(|board| {
                            target_senders.contains(Self::sender_hash(&board.sender_id))
                        })
                })
            })
            .unwrap_or(false)
    }

    fn attach_wire_contract_to_item(
        &self,
        data: RouterItem,
        target_senders: &[u64],
    ) -> TelemetryResult<RouterItem> {
        let pkt = match data {
            RouterItem::Packet(packet) => packet,
            RouterItem::Packed(bytes) => {
                // Preserve an existing frozen cohort. A locally queued plain
                // packed frame needs the same contract as a Packet source.
                if wire_format::peek_routing_envelope(&bytes)?
                    .target_senders()
                    .len()
                    != 0
                {
                    return Ok(RouterItem::Packed(bytes));
                }
                self.unpack_packet_for_role(&bytes)?
            }
        };
        let reliable = if is_reliable_type(pkt.data_type()) {
            Some(wire_format::ReliableHeader {
                flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
                seq: 0,
                ack: 0,
            })
        } else {
            None
        };
        // A previously frozen Packet has the same immutable cohort as packed
        // input. New discovery may change routes, never its receipt owners.
        let targets = if pkt.wire_target_senders().is_empty() {
            target_senders
        } else {
            pkt.wire_target_senders()
        };
        let bytes = self.pack_packet_for_contract(
            &pkt,
            reliable,
            pkt.wire_shape()
                .or_else(|| Some(message_meta(pkt.data_type()).element)),
            targets,
        )?;
        Ok(RouterItem::Packed(bytes))
    }

    fn endpoints_are_link_local_only(eps: &[DataEndpoint]) -> bool {
        !eps.is_empty() && eps.iter().all(|ep| ep.is_link_local_only())
    }

    fn should_route_remote(
        &self,
        data: &RouterItem,
        exclude: Option<RouterSideId>,
    ) -> TelemetryResult<bool> {
        #[cfg(feature = "discovery")]
        {
            let RemoteSidePlan::Target(sides) =
                self.remote_side_plan_with_selection(data, exclude, false)?;
            Ok(!sides.is_empty())
        }

        #[cfg(not(feature = "discovery"))]
        {
            let (eps, ty) = self.item_route_info(data)?;
            if !(has_nonlocal_endpoint(&eps, &self.cfg) || force_remote_for_type(ty)) {
                return Ok(false);
            }
            let st = self.state.lock();
            Ok(!self
                .eligible_side_ids_locked(
                    &st,
                    exclude,
                    Some(ty),
                    Self::endpoints_are_link_local_only(&eps),
                )
                .is_empty())
        }
    }

    #[cfg(feature = "discovery")]
    fn has_explicit_route_policy_locked(
        st: &RouterInner,
        src: Option<RouterSideId>,
        ty: DataType,
    ) -> bool {
        st.route_overrides
            .keys()
            .any(|(route_src, _)| *route_src == src)
            || Self::has_typed_route_overrides_locked(st, src, ty)
    }

    fn remote_side_plan(
        &self,
        data: &RouterItem,
        exclude: Option<RouterSideId>,
    ) -> TelemetryResult<RemoteSidePlan> {
        self.remote_side_plan_with_selection(data, exclude, true)
    }

    // Reachability is a query, not a transmission: it must not spend clock
    // allowances or advance weighted/adaptive cursors before actual dispatch.
    #[inline(never)]
    fn remote_side_plan_with_selection(
        &self,
        data: &RouterItem,
        exclude: Option<RouterSideId>,
        select_routes: bool,
    ) -> TelemetryResult<RemoteSidePlan> {
        let select_sides = |state: &mut RouterInner, sides: Vec<RouterSideId>, origin| {
            if select_routes {
                self.apply_route_selection_locked(state, exclude, sides, origin)
            } else {
                sides
            }
        };
        #[cfg(feature = "discovery")]
        {
            let (eps, ty) = self.item_route_info(data)?;
            let target_senders = self.item_target_senders(data)?;
            let resolve_beyond_local_hop =
                self.item_targets_router_as_intermediate_hop(data, &eps)?;
            let preferred_packet_id = Self::reliable_control_target_packet_id(data)?;
            let routing_target_senders = if preferred_packet_id.is_some() {
                // ACK target[0] identifies the acknowledging owner, not the
                // destination. Never route an ACK back toward that owner.
                target_senders.skip(1)
            } else if resolve_beyond_local_hop {
                wire_format::TargetSenderSet::Hashes(&[])
            } else {
                target_senders
            };
            if discovery::is_discovery_type(ty) {
                let mut st = self.state.lock();
                let sides = self.eligible_side_ids_locked(&st, exclude, Some(ty), false);
                return Ok(RemoteSidePlan::Target(select_sides(
                    &mut st,
                    sides,
                    RouteSelectionOrigin::Flood,
                )));
            }
            #[cfg(feature = "timesync")]
            if ty == DataType::TimeSyncAnnounce {
                // A source announcement describes the source carried in the
                // packet; routing it *toward* that discovered source sends it
                // back where it came from and leaves downstream clocks blind.
                // Propagate it once away from the ingress side, like topology
                // discovery. Dedupe and split-horizon exclusion prevent echoes,
                // while requests still use the exact discovered source route.
                let mut st = self.state.lock();
                let sides = self.eligible_side_ids_locked(&st, exclude, Some(ty), false);
                let sides = if select_routes {
                    Self::filter_timesync_sides_locked(&st, ty, self.clock.now_ms(), sides)
                } else {
                    sides
                };
                return Ok(RemoteSidePlan::Target(select_sides(
                    &mut st,
                    sides,
                    RouteSelectionOrigin::Flood,
                )));
            }
            let mut st = self.state.lock();
            // Preserve the local-only traffic optimization unless discovery
            // has positively identified a remote owner of this network
            // variable. A router may own the same schema endpoint locally and
            // still need to replicate the value across an IPC/network boundary.
            let now_ms = self.clock.now_ms();
            let has_remote_variable_owner = st.managed_variable_types.contains(&ty.as_u32())
                && st.discovery_routes.iter().any(|(&side, route)| {
                    exclude != Some(side)
                        && now_ms.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                        && route.reachable_network_variables.contains(&ty)
                });
            if !(has_nonlocal_endpoint(&eps, &self.cfg)
                || force_remote_for_type(ty)
                || !target_senders.is_empty()
                || has_remote_variable_owner)
            {
                return Ok(RemoteSidePlan::Target(Vec::new()));
            }

            #[cfg(feature = "timesync")]
            let preferred_timesync_source = self.preferred_timesync_route_source(data, ty)?;
            #[cfg(not(feature = "timesync"))]
            let preferred_timesync_source: Option<String> = None;

            if let Some(packet_id) = preferred_packet_id {
                let target_side = st
                    .reliable_return_routes
                    .get(&packet_id)
                    .map(|route| route.side);
                if let Some(side) = target_side
                    .filter(|side| self.route_allowed_locked(&st, exclude, Some(ty), *side))
                {
                    #[cfg(feature = "timesync")]
                    if select_routes
                        && !Self::timesync_allowed_for_side_locked(
                            &st,
                            side,
                            ty,
                            self.clock.now_ms(),
                        )
                    {
                        return Ok(RemoteSidePlan::Target(Vec::new()));
                    }
                    return Ok(RemoteSidePlan::Target(vec![side]));
                }
                // A receipt names its original publisher. Its internal
                // endpoint metadata does not restrict that return path.
                let eligible = self.eligible_side_ids_locked(&st, exclude, Some(ty), false);
                let exact: Vec<_> = eligible
                    .iter()
                    .copied()
                    .filter(|&side| {
                        !routing_target_senders.is_empty()
                            && Self::side_matches_target_senders_locked(
                                &st,
                                side,
                                routing_target_senders,
                                now_ms,
                            )
                    })
                    .collect();
                if !exact.is_empty() {
                    return Ok(RemoteSidePlan::Target(select_sides(
                        &mut st,
                        exact,
                        RouteSelectionOrigin::Discovered,
                    )));
                }
                // Known publisher routes which are excluded or denied remain
                // excluded. Sending same-segment CAN receipts onto the other
                // link creates an ACK flood. Reserve one-link recovery for
                // unknown/legacy publisher identities.
                let publisher_known = !routing_target_senders.is_empty()
                    && st.discovery_routes.keys().any(|&side| {
                        Self::side_matches_target_senders_locked(
                            &st,
                            side,
                            routing_target_senders,
                            now_ms,
                        )
                    });
                return Ok(RemoteSidePlan::Target(
                    if !publisher_known && exclude.is_some() && eligible.len() == 1 {
                        eligible
                    } else {
                        Vec::new()
                    },
                ));
            }
            let restrict_link_local = Self::endpoints_are_link_local_only(&eps);
            let prefer_best_overlap = is_reliable_type(ty)
                && routing_target_senders.is_empty()
                && preferred_packet_id.is_none();
            if st.discovery_routes.is_empty() {
                let mut fallback =
                    self.eligible_side_ids_locked(&st, exclude, Some(ty), restrict_link_local);
                #[cfg(feature = "timesync")]
                {
                    if select_routes {
                        fallback = Self::filter_timesync_sides_locked(
                            &st,
                            ty,
                            self.clock.now_ms(),
                            fallback,
                        );
                    }
                }
                return Ok(RemoteSidePlan::Target(if fallback.len() == 1 {
                    fallback
                } else {
                    Vec::new()
                }));
            }
            let mut matches = self.discovered_route_candidates_locked(
                &st,
                exclude,
                ty,
                &eps,
                routing_target_senders,
                prefer_best_overlap,
                preferred_timesync_source.as_deref(),
            );
            #[cfg(feature = "timesync")]
            {
                if select_routes {
                    matches =
                        Self::filter_timesync_matches_locked(&st, ty, self.clock.now_ms(), matches);
                }
            }
            /* Heartbeats and replicated network variables are network-segment
             * state, so a nearer owner on one side must not hide a farther
             * independent segment. Discovery's split horizon prevents the
             * advertisement from being reflected back onto its ingress side.
             * Ordinary application data retains shortest-path suppression. */
            let has_distributed_variable_owners = matches.iter().any(|candidate| {
                st.discovery_routes
                    .get(&candidate.side)
                    .is_some_and(|route| route.reachable_network_variables.contains(&ty))
            });
            if DataType::try_named("HEARTBEAT") != Some(ty) && !has_distributed_variable_owners {
                Self::retain_shortest_discovery_candidates_locked(
                    &st,
                    &mut matches,
                    &eps,
                    routing_target_senders,
                    self.clock.now_ms(),
                );
            }

            if !matches.is_empty() {
                if !select_routes {
                    // Only existence is queried. Shortest-path and side-policy
                    // validation already ran; do not select a weighted path.
                    return Ok(RemoteSidePlan::Target(vec![matches[0].side]));
                }
                Ok(RemoteSidePlan::Target(
                    self.select_discovered_candidate_sides_locked(
                        &mut st,
                        exclude,
                        ty,
                        routing_target_senders,
                        prefer_best_overlap,
                        matches,
                    ),
                ))
            } else if prefer_best_overlap {
                Ok(RemoteSidePlan::Target(Vec::new()))
            } else {
                if Self::has_explicit_route_policy_locked(&st, exclude, ty) {
                    let mut sides =
                        self.eligible_side_ids_locked(&st, exclude, Some(ty), restrict_link_local);
                    #[cfg(feature = "timesync")]
                    {
                        if select_routes {
                            sides = Self::filter_timesync_sides_locked(
                                &st,
                                ty,
                                self.clock.now_ms(),
                                sides,
                            );
                        }
                    }
                    Ok(RemoteSidePlan::Target(select_sides(
                        &mut st,
                        sides,
                        RouteSelectionOrigin::Flood,
                    )))
                } else {
                    Ok(RemoteSidePlan::Target(Vec::new()))
                }
            }
        }
        #[cfg(not(feature = "discovery"))]
        {
            let ty = Self::item_data_type(data)?;
            let mut st = self.state.lock();
            if let Some(packet_id) = Self::reliable_control_target_packet_id(data)? {
                let target_side = st
                    .reliable_return_routes
                    .get(&packet_id)
                    .map(|route| route.side);
                if let Some(side) = target_side
                    .filter(|side| self.route_allowed_locked(&st, exclude, Some(ty), *side))
                {
                    return Ok(RemoteSidePlan::Target(vec![side]));
                }
                let sides = self.eligible_side_ids_locked(&st, exclude, Some(ty), false);
                return Ok(RemoteSidePlan::Target(
                    if exclude.is_some() && sides.len() == 1 {
                        sides
                    } else {
                        Vec::new()
                    },
                ));
            }
            let sides = self.eligible_side_ids_locked(&st, exclude, Some(ty), false);
            Ok(RemoteSidePlan::Target(select_sides(
                &mut st,
                sides,
                RouteSelectionOrigin::Flood,
            )))
        }
    }

    #[cfg(feature = "discovery")]
    fn local_discovery_endpoints(&self, st: &RouterInner) -> Vec<DataEndpoint> {
        let mut eps: Vec<DataEndpoint> = self.cfg.handlers.iter().map(|h| h.endpoint).collect();
        // Managed-variable ownership has its own discovery field. Its message
        // endpoints describe delivery sinks, not ownership: treating them as
        // local endpoints makes every flight-state replica claim that it is
        // GroundStation and prevents ordinary telemetry from reaching the
        // real GroundStation route.
        let _ = st;
        #[cfg(feature = "timesync")]
        if self.cfg.timesync_config().is_some() {
            eps.push(DataEndpoint::TimeSync);
        }
        eps.retain(|ep| !discovery::is_discovery_endpoint(*ep));
        crate::small_sort::sort(&mut eps);
        eps.dedup();
        eps
    }

    #[cfg(feature = "discovery")]
    fn local_discovery_timesync_sources(&self, now_ms: u64) -> Vec<String> {
        #[cfg(feature = "timesync")]
        {
            let st = self.timesync.lock();
            if let Some(tracker) = st.tracker.as_ref()
                && tracker.should_serve(
                    now_ms,
                    Self::timesync_has_usable_time_locked(&st, self.monotonic_now_ns()),
                )
            {
                return vec![self.sender_arc().to_string()];
            }
        }
        Vec::new()
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    fn preferred_timesync_route_source(
        &self,
        data: &RouterItem,
        ty: DataType,
    ) -> TelemetryResult<Option<String>> {
        if !matches!(
            ty,
            DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
        ) {
            return Ok(None);
        }

        match data {
            RouterItem::Packet(pkt) => match ty {
                DataType::TimeSyncRequest => {
                    let local_sender = self.sender_arc();
                    if pkt.sender() == local_sender.as_ref() {
                        Ok(self.timesync.lock().tracker.as_ref().and_then(|tracker| {
                            tracker.current_source().map(|src| src.sender.clone())
                        }))
                    } else {
                        Ok(None)
                    }
                }
                DataType::TimeSyncAnnounce | DataType::TimeSyncResponse => {
                    Ok(Some(pkt.sender().to_owned()))
                }
                _ => Ok(None),
            },
            RouterItem::Packed(bytes) => {
                let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                self.preferred_timesync_route_source(&RouterItem::Packet(pkt), ty)
            }
        }
    }

    #[cfg(feature = "discovery")]
    fn note_discovery_topology_change_locked(st: &mut RouterInner, now_ms: u64) {
        st.discovery_cadence.on_topology_change(now_ms);
        // Propagate route changes immediately without restarting discovery or
        // resending the complete topology graph. DiscoveryAddress replaces the
        // prior compact route summary, so additions and removals converge while
        // explicit baseline requests remain available as loss recovery.
        for side_id in st
            .sides
            .iter()
            .enumerate()
            .filter_map(|(side_id, side)| side.as_ref().map(|_| side_id))
        {
            let throttle = st.discovery_side_throttle.entry(side_id).or_default();
            throttle.pending_incremental = true;
            throttle.incremental_retries_remaining = DISCOVERY_INCREMENTAL_RETRY_COUNT;
        }
        // Make the first incremental control frame self-describing. This is a
        // small header refresh, not a topology reset, and prevents a restarted
        // peer from missing the route delta because it lost its RX dictionary.
        for transport in st.side_transport.values_mut() {
            transport.refresh_transmit_header_templates();
        }
    }

    #[cfg(feature = "discovery")]
    fn sender_topology_board_mut<'a>(
        sender_state: &'a mut DiscoverySenderState,
        sender_id: &str,
    ) -> &'a mut TopologyBoardNode {
        let boards = Arc::make_mut(&mut sender_state.topology_boards);
        if let Some(idx) = boards.iter().position(|board| board.sender_id == sender_id) {
            return &mut boards[idx];
        }
        boards.push(TopologyBoardNode {
            sender_id: sender_id.to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: Vec::new(),
        });
        boards.last_mut().expect("inserted above")
    }

    #[cfg(feature = "discovery")]
    fn refresh_sender_topology_state(sender_state: &mut DiscoverySenderState) {
        if let Some(boards) = Arc::get_mut(&mut sender_state.topology_boards) {
            discovery::normalize_topology_boards(boards);
        }
        let (mut reachable, mut reachable_timesync_sources) =
            discovery::summarize_topology_boards(&sender_state.topology_boards);
        reachable.extend(sender_state.advertised_reachable.iter().copied());
        crate::small_sort::sort(&mut reachable);
        reachable.dedup();
        reachable_timesync_sources.extend(
            sender_state
                .advertised_reachable_timesync_sources
                .iter()
                .cloned(),
        );
        reachable_timesync_sources.sort_unstable();
        reachable_timesync_sources.dedup();
        sender_state.reachable = reachable;
        sender_state.reachable_timesync_sources = reachable_timesync_sources;
    }

    #[cfg(feature = "discovery")]
    fn recompute_discovery_side_state(route: &mut DiscoverySideState) {
        let mut reachable = Vec::new();
        let mut reachable_network_variables = Vec::new();
        let mut reachable_timesync_sources = Vec::new();
        let mut last_seen_ms = 0u64;
        for sender in route.announcers.values() {
            reachable.extend(sender.reachable.iter().copied());
            reachable_network_variables.extend(sender.reachable_network_variables.iter().copied());
            reachable_timesync_sources.extend(sender.reachable_timesync_sources.iter().cloned());
            last_seen_ms = last_seen_ms.max(sender.last_seen_ms);
        }
        reachable_network_variables
            .extend(route.requested_network_variables.iter().map(|(ty, _)| *ty));
        last_seen_ms = last_seen_ms.max(
            route
                .requested_network_variables
                .iter()
                .map(|(_, last_seen_ms)| *last_seen_ms)
                .max()
                .unwrap_or(0),
        );
        crate::small_sort::sort(&mut reachable);
        reachable.dedup();
        crate::small_sort::sort(&mut reachable_network_variables);
        reachable_network_variables.dedup();
        reachable_timesync_sources.sort_unstable();
        reachable_timesync_sources.dedup();
        route.reachable = reachable;
        route.reachable_network_variables = reachable_network_variables;
        route.reachable_timesync_sources = reachable_timesync_sources;
        route.last_seen_ms = last_seen_ms;
    }

    #[cfg(feature = "discovery")]
    fn local_discovery_topology_board(
        &self,
        st: &RouterInner,
        now_ms: u64,
        link_local_enabled: bool,
    ) -> TopologyBoardNode {
        let mut reachable_endpoints = self.local_discovery_endpoints(st);
        if !link_local_enabled {
            reachable_endpoints.retain(|ep| !ep.is_link_local_only());
        }
        let mut connections = Vec::new();
        for route in st.discovery_routes.values() {
            if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                continue;
            }
            for (sender, sender_state) in route.announcers.iter() {
                if now_ms.saturating_sub(sender_state.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS {
                    connections.push(sender.clone());
                }
            }
        }
        connections.sort_unstable();
        connections.dedup();
        let sender = self.sender_arc();
        TopologyBoardNode {
            sender_id: sender.to_string(),
            reachable_endpoints,
            reachable_timesync_sources: self.local_discovery_timesync_sources(now_ms),
            connections,
        }
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_topology_for_link_locked(
        &self,
        st: &RouterInner,
        now_ms: u64,
        link_local_enabled: bool,
        exclude_side: Option<RouterSideId>,
    ) -> Vec<TopologyBoardNode> {
        let mut boards = vec![self.local_discovery_topology_board(st, now_ms, link_local_enabled)];
        for (&route_side, route) in st.discovery_routes.iter() {
            if exclude_side == Some(route_side) {
                continue;
            }
            if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                continue;
            }
            for (announcer, sender_state) in route.announcers.iter() {
                if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                if sender_state.topology_boards.is_empty() {
                    let sender = self.sender_arc();
                    let fallback = TopologyBoardNode {
                        sender_id: announcer.clone(),
                        reachable_endpoints: sender_state.reachable.clone(),
                        reachable_timesync_sources: sender_state.reachable_timesync_sources.clone(),
                        connections: vec![sender.to_string()],
                    };
                    discovery::merge_topology_boards(&mut boards, core::slice::from_ref(&fallback));
                } else {
                    // Merge the retained view directly. Cloning it first and
                    // cloning again into the output doubled temporary strings.
                    discovery::merge_topology_boards(&mut boards, &sender_state.topology_boards);
                    if let Some(board) = boards
                        .iter_mut()
                        .find(|board| board.sender_id == *announcer)
                    {
                        let sender = self.sender_arc();
                        if !board.connections.iter().any(|peer| peer == sender.as_ref()) {
                            board.connections.push(sender.to_string());
                        }
                    }
                }
            }
        }
        if !link_local_enabled {
            for board in &mut boards {
                board
                    .reachable_endpoints
                    .retain(|ep| !ep.is_link_local_only());
            }
        }
        discovery::normalize_topology_boards(&mut boards);
        boards
    }

    #[cfg(feature = "discovery")]
    fn prune_discovery_routes_locked(st: &mut RouterInner, now_ms: u64) -> bool {
        // Polling runs at the firmware service rate, not the advertisement
        // rate. Never clone the topology just to discover nothing expired.
        let mut changed = false;
        st.discovery_routes.retain(|_, route| {
            let before_peers = route.announcers.len();
            let before_requests = route.requested_network_variables.len();
            route.announcers.retain(|_, sender| {
                now_ms.saturating_sub(sender.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
            });
            route
                .requested_network_variables
                .retain(|(_, last_seen_ms)| {
                    now_ms.saturating_sub(*last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                });
            if before_peers != route.announcers.len()
                || before_requests != route.requested_network_variables.len()
            {
                Self::recompute_discovery_side_state(route);
                changed = true;
            }
            let keep =
                !route.announcers.is_empty() || !route.requested_network_variables.is_empty();
            changed |= !keep;
            keep
        });
        changed
    }

    #[cfg(feature = "discovery")]
    fn advertised_summaries_from_topology_locked(
        &self,
        st: &RouterInner,
        now_ms: u64,
        link_local_enabled: bool,
        exclude_side: Option<RouterSideId>,
        topology: &[TopologyBoardNode],
    ) -> (Vec<crate::DataEndpoint>, Vec<String>) {
        let (mut endpoints, mut sources) = discovery::summarize_topology_boards(topology);
        for (&side, route) in &st.discovery_routes {
            if exclude_side == Some(side)
                || now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
            {
                continue;
            }
            for peer in route.announcers.values() {
                if now_ms.saturating_sub(peer.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                for endpoint in &peer.advertised_reachable {
                    if !discovery::is_discovery_endpoint(*endpoint)
                        && (link_local_enabled || !endpoint.is_link_local_only())
                        && !endpoints.contains(endpoint)
                    {
                        endpoints.push(*endpoint);
                    }
                }
                for source in &peer.advertised_reachable_timesync_sources {
                    if !sources.contains(source) {
                        sources.push(source.clone());
                    }
                }
            }
        }
        endpoints.retain(|endpoint| {
            !discovery::is_discovery_endpoint(*endpoint)
                && (link_local_enabled || !endpoint.is_link_local_only())
        });
        crate::small_sort::sort(&mut endpoints);
        sources.sort_unstable();
        (endpoints, sources)
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_endpoints_for_link_locked(
        &self,
        st: &RouterInner,
        now_ms: u64,
        link_local_enabled: bool,
        exclude_side: Option<RouterSideId>,
    ) -> Vec<DataEndpoint> {
        let (mut reachable_endpoints, _) = discovery::summarize_topology_boards(
            &self.advertised_discovery_topology_for_link_locked(
                st,
                now_ms,
                link_local_enabled,
                exclude_side,
            ),
        );
        // Compact advertisements can know routes before detailed topology arrives.
        // Preserve that reachability without assigning downstream endpoints to the bridge.
        for (&side, route) in &st.discovery_routes {
            if exclude_side == Some(side)
                || now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
            {
                continue;
            }
            for sender in route.announcers.values() {
                if now_ms.saturating_sub(sender.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS {
                    reachable_endpoints.extend(sender.advertised_reachable.iter().copied());
                }
            }
        }
        crate::small_sort::sort(&mut reachable_endpoints);
        reachable_endpoints.dedup();
        reachable_endpoints
            .into_iter()
            .filter(|ep| {
                !discovery::is_discovery_endpoint(*ep)
                    && (link_local_enabled || !ep.is_link_local_only())
            })
            .collect()
    }

    #[cfg(all(test, feature = "discovery"))]
    fn compact_summary_fixture(&self, endpoint: DataEndpoint) {
        let mut sender = DiscoverySenderState {
            advertised_reachable: vec![endpoint],
            advertised_reachable_timesync_sources: vec!["clock-behind-bridge".to_string()],
            last_seen_ms: self.clock.now_ms(),
            topology_boards: Arc::new(vec![TopologyBoardNode {
                sender_id: "bridge".to_string(),
                reachable_endpoints: Vec::new(),
                reachable_timesync_sources: Vec::new(),
                connections: Vec::new(),
            }]),
            ..Default::default()
        };
        Self::refresh_sender_topology_state(&mut sender);
        let mut route = DiscoverySideState::default();
        route.announcers.insert("bridge".to_string(), sender);
        Self::recompute_discovery_side_state(&mut route);
        self.state.lock().discovery_routes.insert(0, route);
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_timesync_sources_for_link_locked(
        &self,
        st: &RouterInner,
        now_ms: u64,
        exclude_side: Option<RouterSideId>,
    ) -> Vec<String> {
        let (_, mut sources) = discovery::summarize_topology_boards(
            &self.advertised_discovery_topology_for_link_locked(st, now_ms, true, exclude_side),
        );
        for (&side, route) in &st.discovery_routes {
            if exclude_side == Some(side)
                || now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
            {
                continue;
            }
            for sender in route.announcers.values() {
                if now_ms.saturating_sub(sender.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS {
                    sources.extend(sender.advertised_reachable_timesync_sources.iter().cloned());
                }
            }
        }
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    #[cfg(feature = "discovery")]
    fn advertised_network_variables_for_link_locked(
        &self,
        st: &RouterInner,
        now_ms: u64,
        exclude_side: Option<RouterSideId>,
    ) -> Vec<DataType> {
        let mut types: Vec<DataType> = st
            .managed_variable_types
            .iter()
            .copied()
            .map(DataType)
            .collect();
        for (&route_side, route) in st.discovery_routes.iter() {
            if exclude_side == Some(route_side) {
                continue;
            }
            if now_ms.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS {
                types.extend(route.reachable_network_variables.iter().copied());
            }
        }
        crate::small_sort::sort(&mut types);
        types.dedup();
        types
    }

    #[cfg(feature = "discovery")]
    fn preferred_discovery_master_present_locked<'a>(
        &self,
        st: &'a RouterInner,
        now_ms: u64,
    ) -> Option<&'a str> {
        if let Some(preferred) = st.preferred_discovery_master.as_deref()
            && (preferred == self.sender_arc().as_ref()
                || st
                    .discovery_routes
                    .values()
                    .filter(|route| {
                        now_ms.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                    })
                    .any(|route| {
                        route
                            .announcers
                            .iter()
                            .filter(|(_, peer)| {
                                now_ms.saturating_sub(peer.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                            })
                            .any(|(name, peer)| {
                                name == preferred
                                    || peer.topology_boards.iter().any(|board| {
                                        board.sender_id == preferred
                                            || board
                                                .connections
                                                .iter()
                                                .any(|name| name == preferred)
                                    })
                            })
                    }))
        {
            // Presence of the preferred master needs a name scan, not a
            // cloned topology and a graph election on each advertisement.
            return Some(preferred);
        }
        None
    }

    #[cfg(feature = "discovery")]
    fn discovery_master_sender_locked(&self, st: &RouterInner, now_ms: u64) -> String {
        if let Some(preferred) = self.preferred_discovery_master_present_locked(st, now_ms) {
            return preferred.to_string();
        }
        let boards = self.advertised_discovery_topology_for_link_locked(st, now_ms, true, None);
        discovery::elect_discovery_master(self.sender_arc().as_ref(), &boards)
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    #[inline]
    fn side_is_slow_control_link_locked(
        st: &RouterInner,
        side_id: RouterSideId,
        now_ms: u64,
    ) -> bool {
        st.adaptive_route_stats.get(&side_id).is_some_and(|stats| {
            let recent_slow = stats.last_slow_observed_ms > 0
                && now_ms.saturating_sub(stats.last_slow_observed_ms)
                    <= discovery::DISCOVERY_SLOW_LINK_FULL_INTERVAL_MS;
            stats.sample_count > 0
                && ((stats.estimated_bandwidth_bps > 0
                    && stats.estimated_bandwidth_bps <= CONTROL_SLOW_LINK_CAPACITY_BPS)
                    || recent_slow)
        })
    }

    #[cfg(feature = "discovery")]
    fn discovery_level_for_side_locked(
        st: &mut RouterInner,
        side_id: RouterSideId,
        now_ms: u64,
    ) -> Option<DiscoveryAdvertiseLevel> {
        let throttle = st.discovery_side_throttle.entry(side_id).or_default();
        if !throttle.has_sent_full {
            throttle.has_sent_full = true;
            throttle.pending_incremental = false;
            throttle.incremental_retries_remaining = 0;
            throttle.next_ping_ms = now_ms.saturating_add(DISCOVERY_SLOW_LINK_PING_INTERVAL_MS);
            return Some(DiscoveryAdvertiseLevel::Full);
        }
        if throttle.pending_incremental {
            throttle.incremental_retries_remaining =
                throttle.incremental_retries_remaining.saturating_sub(1);
            throttle.pending_incremental = throttle.incremental_retries_remaining > 0;
            return Some(DiscoveryAdvertiseLevel::Incremental);
        }
        // Stable links carry only a small liveness announcement. Route and
        // schema snapshots are emitted on changes or explicit recovery requests.
        if throttle.liveness_due(now_ms) {
            throttle.next_ping_ms = now_ms.saturating_add(DISCOVERY_SLOW_LINK_PING_INTERVAL_MS);
            return Some(DiscoveryAdvertiseLevel::MinimalPing);
        }
        None
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    #[inline]
    fn is_timesync_type(ty: DataType) -> bool {
        matches!(
            ty,
            DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
        )
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    #[inline(never)]
    fn timesync_allowed_for_side_locked(
        st: &RouterInner,
        side_id: RouterSideId,
        ty: DataType,
        now_ms: u64,
    ) -> bool {
        if !Self::is_timesync_type(ty) {
            return true;
        }
        if !Self::side_is_slow_control_link_locked(st, side_id, now_ms) {
            return true;
        }
        // A routing/availability check is not a successful transmission. Keep
        // the allowance available across retries and commit only on acceptance.
        st.timesync_side_throttle
            .get(&side_id)
            .is_none_or(|throttle| now_ms >= throttle.next_allowed_ms)
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    fn filter_timesync_sides_locked(
        st: &RouterInner,
        ty: DataType,
        now_ms: u64,
        sides: Vec<RouterSideId>,
    ) -> Vec<RouterSideId> {
        sides
            .into_iter()
            .filter(|side| Self::timesync_allowed_for_side_locked(st, *side, ty, now_ms))
            .collect()
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    fn filter_timesync_matches_locked(
        st: &RouterInner,
        ty: DataType,
        now_ms: u64,
        matches: Vec<DiscoveryCandidateMatch>,
    ) -> Vec<DiscoveryCandidateMatch> {
        matches
            .into_iter()
            .filter(|m| Self::timesync_allowed_for_side_locked(st, m.side, ty, now_ms))
            .collect()
    }

    #[cfg(feature = "discovery")]
    fn refresh_known_discovery_liveness(
        &self,
        pkt: &Packet,
        side: RouterSideId,
    ) -> TelemetryResult<bool> {
        if pkt.data_type() == crate::DataType::DiscoveryAddress {
            return self.refresh_known_address_payload(pkt.payload(), side);
        }
        if pkt.data_type() == crate::DataType::DiscoveryTopology {
            // No decoded graph or retained-side clone is needed for a retry
            // whose payload already describes precisely the retained state.
            // Keep changed topology behind the full admission guard.
            crate::memory_admission::check(512, 128)?;
            let now = self.clock.now_ms();
            let mut st = self.state.lock();
            let canonical = Self::canonical_sender_locked(&st, pkt.sender());
            let Some(route) = st.discovery_routes.get_mut(&side) else {
                return Ok(false);
            };
            let Some(peer) = route.announcers.get_mut(canonical.as_str()) else {
                return Ok(false);
            };
            let Some(full) =
                discovery::topology_payload_matches_retained(pkt.payload(), &peer.topology_boards)
            else {
                return Ok(false);
            };
            peer.has_full_topology |= full;
            peer.last_seen_ms = now;
            route.last_seen_ms = route.last_seen_ms.max(now);
            return Ok(true);
        }
        if pkt.data_type() != crate::DataType::DiscoveryAnnounce || !pkt.payload().is_empty() {
            return Ok(false);
        }
        crate::memory_admission::check(512, 128)?;
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        let canonical = Self::canonical_sender_locked(&st, pkt.sender());
        let Some(route) = st.discovery_routes.get_mut(&side) else {
            return Ok(false);
        };
        let Some(peer) = route.announcers.get_mut(canonical.as_str()) else {
            return Ok(false);
        };
        peer.last_seen_ms = now;
        route.last_seen_ms = route.last_seen_ms.max(now);
        Ok(true)
    }

    #[cfg(feature = "discovery")]
    fn refresh_known_address_payload(
        &self,
        payload: &[u8],
        side: RouterSideId,
    ) -> TelemetryResult<bool> {
        let ad = discovery::decode_address_view(payload)?;
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        let link_local = st
            .sides
            .get(side)
            .and_then(|entry| entry.as_ref())
            .is_some_and(|entry| entry.opts.link_local_enabled);
        {
            let Some(entry) = st.address_book.get(ad.hostname) else {
                return Ok(false);
            };
            if entry.address != ad.address
                || entry.requested_address != ad.requested_address
                || entry.mode != Self::address_mode_from_code(ad.mode, ad.requested_address)
                || entry.owner_hash != ad.owner_hash
            {
                return Ok(false);
            }
            if entry.birth_ms != ad.birth_ms
                && st.address_book.iter().any(|(hostname, other)| {
                    hostname.as_str() != ad.hostname
                        && [ad.address, ad.requested_address].iter().any(|candidate| {
                            *candidate != 0
                                && (other.address == *candidate
                                    || other.requested_address == *candidate)
                        })
                })
            {
                // Birth time participates in collision arbitration. Reuse an
                // incarnation only when the unchanged owner has no contender;
                // contested addresses retain the transactional admission path.
                return Ok(false);
            }
        }
        let sender = ad.hostname;
        let Some(route) = st.discovery_routes.get_mut(&side) else {
            return Ok(false);
        };
        let Some(peer) = route.announcers.get_mut(sender) else {
            return Ok(false);
        };
        if peer.advertised_address != Some(ad.address)
            || !ad
                .endpoints()
                .filter(|ep| link_local || !ep.is_link_local_only())
                .eq(peer.advertised_reachable.iter().copied())
            || !ad.sources().eq(peer
                .advertised_reachable_timesync_sources
                .iter()
                .map(String::as_str))
            || !ad
                .variables()
                .eq(peer.reachable_network_variables.iter().copied())
            || peer.link_capabilities != Some(ad.link_capabilities)
        {
            return Ok(false);
        }
        // A liveness update cannot add ownership, change identity, or enlarge
        // discovery state. Leave new/changed summaries behind the full guard.
        peer.last_seen_ms = now;
        route.last_seen_ms = route.last_seen_ms.max(now);
        if let Some(entry) = st.address_book.get_mut(ad.hostname) {
            // A known, uncontested owner can restart without cloning its
            // unchanged route/schema snapshot. Record the new incarnation.
            entry.birth_ms = ad.birth_ms;
            entry.last_seen_ms = now;
        }
        #[cfg(feature = "compression")]
        {
            drop(st);
            self.note_payload_codec_address(side, payload, true);
        }
        Ok(true)
    }

    #[cfg(feature = "discovery")]
    fn queue_pressure_keepalives(
        &self,
        requested_side: Option<RouterSideId>,
    ) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let sender = self.sender_arc();
        crate::memory_admission::check(
            256 + sender.len().saturating_mul(4),
            sender.len().max(256),
        )?;
        let side_count = self.state.lock().sides.len();
        for side in 0..side_count {
            let due = {
                let st = self.state.lock();
                requested_side.is_none_or(|wanted| wanted == side)
                    && st.sides[side].is_some()
                    && self.route_allowed_locked(
                        &st,
                        None,
                        Some(crate::DataType::DiscoveryAnnounce),
                        side,
                    )
                    && st
                        .discovery_side_throttle
                        .get(&side)
                        .is_none_or(|throttle| now >= throttle.next_ping_ms)
            };
            if !due {
                continue;
            }
            // Propagate newly learned reachability even when the full topology
            // cannot fit. Build only a split-horizon summary, never a graph.
            let summary = {
                let st = self.state.lock();
                let extra = st
                    .discovery_routes
                    .iter()
                    .filter(|(id, _)| **id != side)
                    .fold(0usize, |total, (_, route)| {
                        total
                            .saturating_add(route.reachable.len().saturating_mul(32))
                            .saturating_add(
                                route.reachable_network_variables.len().saturating_mul(32),
                            )
                            .saturating_add(
                                route
                                    .reachable_timesync_sources
                                    .iter()
                                    .map(|source| source.len().saturating_add(32).saturating_mul(4))
                                    .sum::<usize>(),
                            )
                    });
                if crate::memory_admission::check(4096usize.saturating_add(extra), 2048).is_ok() {
                    let opts = st.sides[side].as_ref().expect("checked above").opts.clone();
                    let mut endpoints = self.local_discovery_endpoints(&st);
                    let mut variables =
                        self.advertised_network_variables_for_link_locked(&st, now, Some(side));
                    let mut sources = self.local_discovery_timesync_sources(now);
                    for (&route_side, route) in &st.discovery_routes {
                        if route_side == side {
                            continue;
                        }
                        for peer in route.announcers.values() {
                            if now.saturating_sub(peer.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS {
                                endpoints.extend(peer.reachable.iter().copied());
                                sources.extend(peer.reachable_timesync_sources.iter().cloned());
                            }
                        }
                    }
                    endpoints.retain(|ep| {
                        !discovery::is_discovery_endpoint(*ep)
                            && (opts.link_local_enabled || !ep.is_link_local_only())
                    });
                    crate::small_sort::sort(&mut endpoints);
                    endpoints.dedup();
                    crate::small_sort::sort(&mut variables);
                    variables.dedup();
                    sources.sort_unstable();
                    sources.dedup();
                    Some((endpoints, variables, sources, opts.link_capabilities()))
                } else {
                    None
                }
            };
            let pkt = if let Some((endpoints, variables, sources, capabilities)) = summary {
                let address = self.local_address_advertisement(
                    endpoints,
                    variables,
                    sources,
                    capabilities,
                    discovery::ADDRESS_STATE_REQUEST,
                );
                discovery::build_discovery_address(sender.as_ref(), now, &address)?
            } else {
                discovery::build_discovery_announce(sender.as_ref(), now, &[])?
            };
            self.emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(pkt),
                },
                true,
                true,
            )?;
            self.state
                .lock()
                .discovery_side_throttle
                .entry(side)
                .or_default()
                .next_ping_ms = now.saturating_add(discovery::DISCOVERY_SLOW_INTERVAL_MS);
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn emit_discovery_snapshot(
        &self,
        called_from_queue: bool,
        include_schema: bool,
        include_topology: bool,
        skip_in_flight_sides: bool,
    ) -> TelemetryResult<()> {
        self.emit_discovery_snapshot_on_side(
            called_from_queue,
            include_schema,
            include_topology,
            skip_in_flight_sides,
            None,
        )
    }

    #[cfg(feature = "discovery")]
    fn emit_discovery_snapshot_on_side(
        &self,
        called_from_queue: bool,
        include_schema: bool,
        include_topology: bool,
        skip_in_flight_sides: bool,
        requested_side: Option<RouterSideId>,
    ) -> TelemetryResult<()> {
        if requested_side.is_none() {
            let count = self.state.lock().sides.len();
            for side in 0..count {
                if self.state.lock().sides[side].is_some() {
                    self.emit_discovery_snapshot_on_side(
                        called_from_queue,
                        include_schema,
                        include_topology,
                        skip_in_flight_sides,
                        Some(side),
                    )?;
                }
            }
            return Ok(());
        }
        let (scratch, largest) = {
            let now = self.clock.now_ms();
            let sender = self.sender_arc();
            let st = self.state.lock();
            let election_required = self
                .preferred_discovery_master_present_locked(&st, now)
                .is_none();
            let snapshot = discovery::topology_snapshot_scratch(
                sender.as_ref(),
                self.cfg.handlers.len(),
                st.managed_variable_types.len().saturating_add(
                    st.discovery_routes
                        .iter()
                        .filter(|(side, _)| Some(**side) != requested_side)
                        .map(|(_, r)| r.reachable_network_variables.len())
                        .sum::<usize>(),
                ),
                4,
                true,
                st.discovery_routes
                    .iter()
                    .filter(|(side, route)| {
                        (Some(**side) != requested_side)
                            && now.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                    })
                    .flat_map(|(_, route)| route.announcers.iter())
                    .filter(|(_, peer)| {
                        now.saturating_sub(peer.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                    })
                    .map(|(name, peer)| {
                        (
                            name.as_str(),
                            peer.reachable.as_slice(),
                            peer.reachable_timesync_sources.as_slice(),
                            peer.topology_boards.as_slice(),
                        )
                    }),
            );
            if !election_required {
                snapshot
            } else {
                let election = discovery::topology_snapshot_scratch(
                    sender.as_ref(),
                    self.cfg.handlers.len(),
                    0,
                    2,
                    false,
                    st.discovery_routes
                        .values()
                        .filter(|route| {
                            now.saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                        })
                        .flat_map(|route| route.announcers.iter())
                        .filter(|(_, peer)| {
                            now.saturating_sub(peer.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                        })
                        .map(|(name, peer)| {
                            (
                                name.as_str(),
                                peer.reachable.as_slice(),
                                peer.reachable_timesync_sources.as_slice(),
                                peer.topology_boards.as_slice(),
                            )
                        }),
                );
                (snapshot.0.max(election.0), snapshot.1.max(election.1))
            }
        };
        // Full metadata also carries the learned topology. Its working set
        // must never bypass the graph estimate merely because schema is due.
        let (scratch, largest) = if include_schema {
            (scratch.max(8192), largest.max(2048))
        } else {
            (scratch, largest)
        };
        // Snapshot construction may clone several route/schema summaries.
        // Reclaim ordinary queued telemetry before refusing discovery scratch.
        // Priority >= 200 commands, ACKs and metadata stay protected; do not
        // evict routes or reliable receive/reassembly state.
        while let Err(err) = crate::memory_admission::check(scratch, largest) {
            if matches!(err, TelemetryError::Io("memory pressure"))
                && crate::memory_admission::check(512, 256).is_ok()
            {
                let mut st = self.state.lock();
                if let Some(victim) = st.lower_priority_shared_queue(199)
                    && st.pop_shared_queue_item(victim)
                {
                    continue;
                }
            }
            if !include_schema && matches!(err, TelemetryError::Io("memory pressure")) {
                return self.queue_pressure_keepalives(requested_side);
            }
            return Err(err);
        }
        let now_ms = self.clock.now_ms();
        let per_side = {
            let mut st = self.state.lock();
            if Self::prune_discovery_routes_locked(&mut st, now_ms) {
                self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            st.fit_discovery_budget();
            let local_is_master =
                self.discovery_master_sender_locked(&st, now_ms) == self.sender_arc().as_ref();
            // The caller selects one side; keep its plan on the stack.
            let mut per_side = None;
            for side_id in 0..st.sides.len() {
                let Some(side) = st.sides[side_id].as_ref() else {
                    continue;
                };
                let opts = side.opts.clone();
                let link_local_enabled = opts.link_local_enabled;
                if requested_side.is_some_and(|requested| requested != side_id) {
                    continue;
                }
                let discovery_in_flight = skip_in_flight_sides
                    && st.reliable_tx.iter().any(|((pending_side, ty), tx_state)| {
                        *pending_side == side_id
                            && !tx_state.sent.is_empty()
                            && DataType::try_from_u32(*ty).is_some_and(discovery::is_discovery_type)
                    });
                if !self.route_allowed_locked(&st, None, Some(DataType::DiscoveryAnnounce), side_id)
                {
                    continue;
                }
                // A lost hop ACK must not make a live bridge disappear from
                // its neighbors. Keep the baseline pending, but permit a
                // bounded, unreliable keepalive independently of its ACK.
                let level = if discovery_in_flight {
                    let throttle = st.discovery_side_throttle.entry(side_id).or_default();
                    if !throttle.liveness_due(now_ms) {
                        None
                    } else {
                        throttle.next_ping_ms =
                            now_ms.saturating_add(DISCOVERY_SLOW_LINK_PING_INTERVAL_MS);
                        Some(DiscoveryAdvertiseLevel::MinimalPing)
                    }
                } else {
                    Self::discovery_level_for_side_locked(&mut st, side_id, now_ms)
                };
                let Some(level) = level else {
                    continue;
                };
                let include_side_topology = include_topology
                    && self.route_allowed_locked(
                        &st,
                        None,
                        Some(DataType::DiscoveryTopology),
                        side_id,
                    );
                let capabilities = opts.link_capabilities();
                if level == DiscoveryAdvertiseLevel::MinimalPing {
                    per_side = Some((
                        side_id,
                        level,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        capabilities,
                        local_is_master,
                    ));
                    continue;
                }
                let current_topology = if include_side_topology {
                    self.advertised_discovery_topology_for_link_locked(
                        &st,
                        now_ms,
                        link_local_enabled,
                        Some(side_id),
                    )
                } else {
                    Vec::new()
                };
                let (endpoints, timesync_sources) = if include_side_topology {
                    self.advertised_summaries_from_topology_locked(
                        &st,
                        now_ms,
                        link_local_enabled,
                        Some(side_id),
                        &current_topology,
                    )
                } else {
                    (
                        self.advertised_discovery_endpoints_for_link_locked(
                            &st,
                            now_ms,
                            link_local_enabled,
                            Some(side_id),
                        ),
                        self.advertised_discovery_timesync_sources_for_link_locked(
                            &st,
                            now_ms,
                            Some(side_id),
                        ),
                    )
                };
                let (topology, removed_topology) = match level {
                    DiscoveryAdvertiseLevel::Full => (current_topology.clone(), Vec::new()),
                    DiscoveryAdvertiseLevel::Incremental => {
                        let previous = &st
                            .discovery_side_throttle
                            .get(&side_id)
                            .expect("discovery throttle exists")
                            .last_topology;
                        discovery::topology_delta(previous, &current_topology)
                    }
                    DiscoveryAdvertiseLevel::MinimalPing => (Vec::new(), Vec::new()),
                };
                let throttle = st
                    .discovery_side_throttle
                    .get_mut(&side_id)
                    .expect("discovery throttle exists");
                if level == DiscoveryAdvertiseLevel::Full
                    || (level == DiscoveryAdvertiseLevel::Incremental
                        && throttle.incremental_retries_remaining == 0)
                {
                    throttle.last_topology = current_topology;
                }
                per_side = Some((
                    side_id,
                    level,
                    endpoints,
                    self.advertised_network_variables_for_link_locked(&st, now_ms, Some(side_id)),
                    timesync_sources,
                    topology,
                    removed_topology,
                    capabilities,
                    local_is_master,
                ));
            }
            per_side
        };
        if let Some((
            side_id,
            level,
            endpoints,
            network_variables,
            timesync_sources,
            topology,
            removed_topology,
            capabilities,
            local_is_master,
        )) = per_side
        {
            let sender = self.sender_arc();
            if matches!(
                level,
                DiscoveryAdvertiseLevel::Full | DiscoveryAdvertiseLevel::Incremental
            ) {
                let address = self.local_address_advertisement(
                    endpoints.clone(),
                    network_variables.clone(),
                    timesync_sources.clone(),
                    capabilities,
                    if local_is_master {
                        discovery::ADDRESS_STATE_APPROVED
                    } else {
                        discovery::ADDRESS_STATE_REQUEST
                    },
                );
                let pkt = discovery::build_discovery_address(sender.as_ref(), now_ms, &address)?;
                self.emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side_id,
                        data: RouterItem::Packet(pkt),
                    },
                    true,
                    called_from_queue,
                )?;
            }
            if level == DiscoveryAdvertiseLevel::MinimalPing {
                let pkt = discovery::build_discovery_announce(
                    sender.as_ref(),
                    now_ms,
                    endpoints.as_slice(),
                )?;
                self.emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side_id,
                        data: RouterItem::Packet(pkt),
                    },
                    true,
                    called_from_queue,
                )?;
            }
            if include_topology
                && (!topology.is_empty() || !removed_topology.is_empty())
                && level != DiscoveryAdvertiseLevel::MinimalPing
            {
                let pkt = if level == DiscoveryAdvertiseLevel::Full {
                    discovery::build_discovery_topology(sender.as_ref(), now_ms, &topology)?
                } else {
                    discovery::build_discovery_topology_delta(
                        sender.as_ref(),
                        now_ms,
                        &topology,
                        &removed_topology,
                    )?
                };
                self.emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side_id,
                        data: RouterItem::Packet(pkt),
                    },
                    true,
                    called_from_queue,
                )?;
            }
            // Release the temporary topology snapshot before constructing and
            // packing the larger schema. These buffers are no longer needed.
            drop((
                endpoints,
                network_variables,
                timesync_sources,
                topology,
                removed_topology,
            ));
            // Schema snapshots can be substantially larger than address and
            // topology advertisements. Send them after the route has been
            // established so a slow link can discover the network before it
            // begins transferring the merged metadata catalog.
            if include_schema && level == DiscoveryAdvertiseLevel::Full {
                let pkt = discovery::build_discovery_schema(sender.as_ref(), now_ms)?;
                self.emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side_id,
                        data: RouterItem::Packet(pkt),
                    },
                    true,
                    called_from_queue,
                )?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn queue_discovery_announce(
        &self,
        include_schema: bool,
        skip_in_flight_sides: bool,
    ) -> TelemetryResult<()> {
        let now_ms = self.clock.now_ms();
        {
            let mut st = self.state.lock();
            if Self::prune_discovery_routes_locked(&mut st, now_ms) {
                self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            st.fit_discovery_budget();
            if st.sides.iter().all(|side| side.is_none()) {
                return Ok(());
            }
            // An explicit announce is the bootstrap/recovery operation. Keep
            // it full; cadence-triggered topology changes use Incremental.
            if include_schema {
                for throttle in st.discovery_side_throttle.values_mut() {
                    throttle.has_sent_full = false;
                }
            }
            st.discovery_cadence.on_announce_sent(now_ms);
        }
        self.emit_discovery_snapshot(true, include_schema, true, skip_in_flight_sides)
    }

    #[cfg(feature = "discovery")]
    fn note_schema_received(&self, side: RouterSideId, sender: &str) {
        let mut st = self.state.lock();
        // Schema snapshots can be forwarded. They must never introduce a new
        // link-local announcer or change shared-bus reliability semantics.
        // If schema precedes topology, bounded recovery will request it again.
        let address = sender
            .strip_prefix("@addr:")
            .and_then(|value| value.parse::<u32>().ok());
        if let Some(route) = st.discovery_routes.get_mut(&side) {
            for (name, peer) in &mut route.announcers {
                if name == sender
                    || address.is_some_and(|address| {
                        peer.advertised_address == Some(address)
                            || sender_address_u32(name) == address
                    })
                {
                    peer.has_schema = true;
                    break;
                }
            }
        }
    }

    #[cfg(feature = "discovery")]
    fn poll_discovery_announce(&self) -> TelemetryResult<bool> {
        let now_ms = self.clock.now_ms();
        // An address/keepalive proves liveness, not receipt of the detailed
        // baseline. Recover a lost bootstrap without waiting 120 seconds or
        // discarding existing routes. Coalesce all missing peers on one side.
        let recovery_sides = {
            let mut st = self.state.lock();
            let mut due = Vec::new();
            for side in 0..st.sides.len() {
                let missing = st.discovery_routes.get(&side).is_some_and(|route| {
                    route.announcers.iter().any(|(name, peer)| {
                        !peer.has_full_topology
                            && now_ms.saturating_sub(peer.last_seen_ms) < DISCOVERY_ROUTE_TTL_MS
                            && !route.announcers.values().any(|bridge| {
                                bridge.has_full_topology
                                    && now_ms.saturating_sub(bridge.last_seen_ms)
                                        < DISCOVERY_ROUTE_TTL_MS
                                    && bridge
                                        .topology_boards
                                        .iter()
                                        .any(|board| board.sender_id == *name)
                            })
                    })
                });
                if !missing {
                    continue;
                }
                let throttle = st.discovery_side_throttle.entry(side).or_default();
                if throttle.next_topology_request_ms == 0 {
                    throttle.next_topology_request_ms =
                        now_ms.saturating_add(discovery::DISCOVERY_BASELINE_GRACE_MS);
                } else if now_ms >= throttle.next_topology_request_ms {
                    throttle.next_topology_request_ms =
                        now_ms.saturating_add(discovery::DISCOVERY_BASELINE_RETRY_MS);
                    due.push(side);
                }
            }
            due
        };
        let recovering = !recovery_sides.is_empty();
        for side in recovery_sides {
            let pkt =
                discovery::build_discovery_topology_request(self.sender_arc().as_ref(), now_ms)?;
            self.emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(pkt),
                },
                true,
                true,
            )?;
        }
        let schema_recovery_sides = {
            let mut st = self.state.lock();
            let mut due = Vec::new();
            for side in 0..st.sides.len() {
                let missing = st.discovery_routes.get(&side).is_some_and(|route| {
                    route.announcers.values().any(|peer| {
                        peer.has_full_topology
                            && !peer.has_schema
                            && now_ms.saturating_sub(peer.last_seen_ms) < DISCOVERY_ROUTE_TTL_MS
                    })
                });
                if !missing {
                    continue;
                }
                let throttle = st.discovery_side_throttle.entry(side).or_default();
                if throttle.next_schema_request_ms == 0 {
                    throttle.next_schema_request_ms =
                        now_ms.saturating_add(discovery::DISCOVERY_BASELINE_GRACE_MS);
                } else if now_ms >= throttle.next_schema_request_ms {
                    throttle.next_schema_request_ms =
                        now_ms.saturating_add(discovery::DISCOVERY_BASELINE_RETRY_MS);
                    due.push(side);
                }
            }
            due
        };
        let recovering = recovering || !schema_recovery_sides.is_empty();
        for side in schema_recovery_sides {
            let pkt =
                discovery::build_discovery_schema_request(self.sender_arc().as_ref(), now_ms)?;
            self.emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(pkt),
                },
                true,
                true,
            )?;
        }
        let due = {
            let mut st = self.state.lock();
            let removed = Self::prune_discovery_routes_locked(&mut st, now_ms);
            if removed {
                self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            st.fit_discovery_budget();
            let has_any = st.sides.iter().enumerate().any(|(side_id, side)| {
                let Some(side) = side.as_ref() else {
                    return false;
                };
                if !self.route_allowed_locked(&st, None, Some(DataType::DiscoveryAnnounce), side_id)
                {
                    return false;
                }
                let _ = side;
                let in_flight = st.reliable_tx.iter().any(|((pending_side, ty), tx_state)| {
                    *pending_side == side_id
                        && !tx_state.sent.is_empty()
                        && DataType::try_from_u32(*ty).is_some_and(discovery::is_discovery_type)
                });
                st.discovery_side_throttle
                    .get(&side_id)
                    .is_none_or(|throttle| {
                        (!in_flight && (!throttle.has_sent_full || throttle.pending_incremental))
                            || throttle.liveness_due(now_ms)
                    })
            });
            if st.sides.is_empty() || !has_any {
                return Ok(recovering);
            }
            st.discovery_cadence.due(now_ms)
        };
        if !due {
            return Ok(recovering);
        }
        // Runtime liveness/topology refreshes must stay small. A full schema
        // is sent by the initial explicit announce and in response to
        // DiscoverySchemaRequest; repeating it at every cadence can starve
        // commands on constrained serial and radio links.
        // A stalled reliable link must not prevent freshly learned routes
        // from propagating across another healthy side. Only omit the side
        // that already has discovery awaiting its hop ACK, except for bounded
        // liveness pings that must not depend on that ACK arriving.
        self.queue_discovery_announce(false, true)?;
        Ok(true)
    }

    #[cfg(feature = "discovery")]
    fn learn_discovery_packet(
        &self,
        pkt: &Packet,
        src: Option<RouterSideId>,
        called_from_queue: bool,
    ) -> TelemetryResult<bool> {
        if !discovery::is_discovery_type(pkt.data_type()) {
            return Ok(false);
        }
        let Some(side) = src else {
            return Ok(true);
        };
        #[cfg(feature = "compression")]
        self.note_payload_codec_packet(side, pkt, false);
        if self.refresh_known_discovery_liveness(pkt, side)? {
            return Ok(true);
        }
        #[cfg(not(feature = "std"))]
        if pkt.data_type() == crate::DataType::DiscoverySchema {
            self.merge_schema_changes(pkt.payload())?;
            self.note_schema_received(side, pkt.sender());
            return Ok(true);
        }
        // A compact address summary does not clone the complete topology or
        // schema. Account for its ingress-side aggregates instead; charging
        // every new peer for a full snapshot can prevent restart recovery.
        if matches!(
            pkt.data_type(),
            DataType::DiscoveryTopologyRequest | DataType::DiscoverySchemaRequest
        ) {
            crate::memory_admission::check(1024, 256)?;
            // A requesting peer may have restarted with an empty RX dictionary.
            // Its identity and routes need not change. Refresh only this link
            // so the next data/state report is immediately self-describing;
            // retain RX dictionaries and all learned topology.
            if let Some(transport) = self.state.lock().side_transport.get_mut(&side) {
                transport.refresh_transmit_header_templates();
            }
        }
        if matches!(
            pkt.data_type(),
            DataType::DiscoveryTopologyRequest | DataType::DiscoverySchemaRequest
        ) {
            let now_ms = self.clock.now_ms();
            {
                let mut st = self.state.lock();
                if Self::prune_discovery_routes_locked(&mut st, now_ms) {
                    self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                    Self::note_discovery_topology_change_locked(&mut st, now_ms);
                }
                let throttle = st.discovery_side_throttle.entry(side).or_default();
                throttle.has_sent_full = false;
                // A full reply cannot use the old incremental baseline. Drop
                // that derived copy before admitting its replacement scratch;
                // keep all learned routes, schemas and other links intact.
                throttle.last_topology = Vec::new();
            }
            // Do not depend on the elected master answering a forwarded request.
            // A recovering neighbor must get our retained downstream baseline
            // even before its identity is known. Reply only on its ingress link;
            // do not reset other links or broadcast application traffic.
            self.emit_discovery_snapshot_on_side(
                called_from_queue,
                pkt.data_type() == DataType::DiscoverySchemaRequest,
                true,
                false,
                Some(side),
            )?;
            return Ok(true);
        }
        let small_topology_scratch =
            if pkt.data_type() == DataType::DiscoveryTopology && pkt.payload().len() <= 128 {
                let st = self.state.lock();
                let sender = pkt
                    .sender()
                    .strip_prefix("@addr:")
                    .and_then(|value| value.parse::<u32>().ok())
                    .and_then(|address| Self::hostname_for_address_borrowed_locked(&st, address))
                    .unwrap_or(pkt.sender());
                st.discovery_routes.get(&side).and_then(|route| {
                    let peer = route.announcers.get(sender)?;
                    let mut shallow = discovery::CloneScratch::default();
                    shallow.buffer(route.reachable.len().saturating_mul(4));
                    shallow.buffer(route.reachable_network_variables.len().saturating_mul(4));
                    shallow.buffer(
                        route
                            .requested_network_variables
                            .len()
                            .saturating_mul(core::mem::size_of::<(DataType, u64)>()),
                    );
                    shallow.strings(&route.reachable_timesync_sources);
                    for (name, value) in &route.announcers {
                        shallow.buffer(name.len());
                        shallow.buffer(value.reachable.len().saturating_mul(4));
                        shallow.buffer(value.advertised_reachable.len().saturating_mul(4));
                        shallow.strings(&value.reachable_timesync_sources);
                        shallow.strings(&value.advertised_reachable_timesync_sources);
                        shallow.buffer(value.reachable_network_variables.len().saturating_mul(4));
                    }
                    let entry = core::mem::size_of::<String>()
                        + core::mem::size_of::<DiscoverySenderState>();
                    shallow.bytes = shallow
                        .bytes
                        .saturating_add(route.announcers.len().saturating_mul(entry));
                    shallow.largest = shallow
                        .largest
                        .max(entry.saturating_mul(11).saturating_add(128));
                    let mut deep = discovery::CloneScratch::default();
                    if discovery::topology_payload_is_incremental(pkt.payload()) {
                        deep.graph(&peer.topology_boards, pkt.payload().len() / 16);
                    }
                    Some((
                        2048usize
                            .saturating_add(shallow.bytes.saturating_mul(3))
                            .saturating_add(deep.bytes)
                            .saturating_add(pkt.payload().len().saturating_mul(4)),
                        shallow.largest.max(deep.largest).max(2048),
                    ))
                })
            } else {
                None
            };
        let retained_summary = if small_topology_scratch.is_none()
            && matches!(
                pkt.data_type(),
                DataType::DiscoveryAddress
                    | DataType::DiscoveryTopology
                    | DataType::DiscoveryAnnounce
                    | DataType::DiscoveryTimeSyncSources
                    | DataType::ManagedVariableRequest
            ) {
            self.state
                .lock()
                .discovery_routes
                .get(&side)
                .map_or(0, |route| {
                    RouterInner::discovery_route_byte_cost(side, route)
                })
        } else {
            0
        };
        let (decode_bytes, largest_block) = if let Some(scratch) = small_topology_scratch {
            scratch
        } else if pkt.data_type() == DataType::ManagedVariableRequest {
            let ty = discovery::decode_managed_variable_request(pkt)?;
            let existing = self
                .state
                .lock()
                .discovery_routes
                .get(&side)
                .is_some_and(|route| {
                    route
                        .requested_network_variables
                        .iter()
                        .any(|(id, _)| *id == ty)
                });
            if existing {
                (1024, 256)
            } else {
                // New subscriptions clone only this ingress summary; refreshing
                // an existing lease constructs no graph or schema definitions.
                (
                    2048usize.saturating_add(retained_summary.saturating_mul(2)),
                    retained_summary
                        .checked_next_power_of_two()
                        .unwrap_or(usize::MAX)
                        .max(1024),
                )
            }
        } else {
            let scratch = if pkt.data_type() == DataType::DiscoveryAddress {
                4096usize.saturating_add(retained_summary)
            } else {
                8192usize.saturating_add(retained_summary)
            };
            let decode_bytes = pkt
                .payload()
                .len()
                .saturating_mul(4)
                .saturating_add(scratch);
            let largest_block = pkt.payload().len().saturating_mul(2).max(2048);
            (decode_bytes, largest_block)
        };
        while let Err(err) = crate::memory_admission::check(decode_bytes, largest_block) {
            if !matches!(err, TelemetryError::Io("memory pressure")) {
                return Err(err);
            }
            let mut st = self.state.lock();
            #[cfg(feature = "compression")]
            if st.reclaim_codec_metadata() {
                continue;
            }

            let Some(victim) = st.lower_priority_shared_queue(255) else {
                return Err(err);
            };
            if !st.pop_shared_queue_item(victim) {
                return Err(err);
            }
        }
        if pkt.data_type() == DataType::DiscoveryAddress {
            let mut ad = discovery::decode_discovery_address(pkt)?;
            let identity = ad.clone();
            let mut changed = false;
            /* Packed no_std frames represent their source as @addr:N until
             * discovery resolves the address. DiscoveryAddress carries the
             * authoritative hostname in its payload, so key reachability by
             * that name immediately instead of permanently treating the
             * placeholder as a distinct router. */
            let sender_id = if ad.hostname.is_empty() {
                pkt.sender()
            } else {
                ad.hostname.as_str()
            };
            let now_ms = self.clock.now_ms();
            let mut st = self.state.lock();
            let side_link_local_enabled = st
                .sides
                .get(side)
                .and_then(|entry| entry.as_ref())
                .map(|side_ref| side_ref.opts.link_local_enabled)
                .unwrap_or(false);
            if !side_link_local_enabled {
                ad.reachable_endpoints.retain(|ep| !ep.is_link_local_only());
            }
            let mut route = st.discovery_routes.get(&side).cloned().unwrap_or_default();
            let previously_reachable_network_variables = route.reachable_network_variables.clone();
            if pkt.sender() != sender_id {
                route.announcers.remove(pkt.sender());
            }
            let mut sender_state =
                core::mem::take(route.announcers.entry(sender_id.to_string()).or_default());
            // DiscoveryAddress is a compact route summary. A multi-sided
            // router advertises endpoints reachable *through* it, so these
            // entries must not be attached to the announcer's topology node:
            // that would falsely claim ownership and freeze reliable packets
            // to the bridge before detailed topology arrives.
            if sender_state.advertised_address != Some(ad.address) {
                sender_state.advertised_address = Some(ad.address);
                changed = true;
            }
            if sender_state.advertised_reachable != ad.reachable_endpoints {
                sender_state.advertised_reachable = ad.reachable_endpoints;
                changed = true;
            }
            if sender_state.advertised_reachable_timesync_sources != ad.reachable_timesync_sources {
                sender_state.advertised_reachable_timesync_sources = ad.reachable_timesync_sources;
                changed = true;
            }
            if sender_state.reachable_network_variables != ad.reachable_network_variables {
                sender_state.reachable_network_variables = ad.reachable_network_variables;
                changed = true;
            }
            if sender_state.link_capabilities != Some(ad.link_capabilities) {
                sender_state.link_capabilities = Some(ad.link_capabilities);
                changed = true;
            }
            Self::refresh_sender_topology_state(&mut sender_state);
            sender_state.last_seen_ms = now_ms;
            route.announcers.insert(sender_id.to_string(), sender_state);
            Self::recompute_discovery_side_state(&mut route);
            let newly_reachable_network_variables: Vec<DataType> = route
                .reachable_network_variables
                .iter()
                .copied()
                .filter(|ty| !previously_reachable_network_variables.contains(ty))
                .collect();
            st.commit_discovery_route(side, route)?;
            self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
            if changed {
                Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
            }
            // A writer may have changed a managed variable while no remote
            // owner route was present. Local-only suppression correctly kept
            // that update off unrelated links, but the new owner still needs
            // the latest value. Replay only newly reachable variable types to
            // this advertising side; do not fan out or restart discovery.
            let replay: Vec<Packet> = newly_reachable_network_variables
                .iter()
                .filter(|ty| Self::managed_variable_permissions_locked(&st, **ty).write)
                .filter_map(|ty| {
                    st.managed_variable_latest
                        .get(&ty.as_u32())
                        .map(|entry| entry.packet.clone())
                })
                .collect();
            drop(st);
            self.ingest_address_advertisement(identity)?;
            #[cfg(feature = "compression")]
            self.note_payload_codec_packet(side, pkt, true);
            for value in replay {
                self.emit_internal_tx_with_priority(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side,
                        data: RouterItem::Packet(value),
                    },
                    true,
                    crate::transport_priority(DataType::ManagedVariableValue),
                    called_from_queue,
                )?;
            }
            return Ok(true);
        }
        let mut decoded_topology = if pkt.data_type() == DataType::DiscoveryTopology {
            Some(discovery::decode_discovery_topology_update(pkt)?)
        } else {
            None
        };
        let packet_sender = {
            let st = self.state.lock();
            let canonical = Self::canonical_sender_locked(&st, pkt.sender());
            if canonical != pkt.sender() {
                canonical
            } else if let Some(address) = pkt
                .sender()
                .strip_prefix("@addr:")
                .and_then(|value| value.parse::<u32>().ok())
            {
                // A compact topology frame may arrive before its reliable
                // DiscoveryAddress frame. Topology still carries stable board
                // names, so use the entry whose wire hash matches the compact
                // source address. This keeps autonomous routers keyed by name
                // even when the header omits that hostname.
                decoded_topology
                    .as_ref()
                    .and_then(|update| {
                        update
                            .boards
                            .iter()
                            .find(|board| sender_address_u32(&board.sender_id) == address)
                    })
                    .map(|board| board.sender_id.clone())
                    .unwrap_or(canonical)
            } else {
                canonical
            }
        };
        let local_sender = self.sender_arc();
        if packet_sender == local_sender.as_ref() {
            return Ok(true);
        }

        if pkt.data_type() == DataType::ManagedVariableRequest {
            let ty = discovery::decode_managed_variable_request(pkt)?;
            // A refresh request is direct evidence that this ingress segment
            // contains a subscriber for the variable. Track one bounded entry
            // per type and side rather than manufacturing a full discovery
            // announcer for every requester. This keeps later writes selective
            // without growing the topology graph or fragmenting embedded pools.
            {
                let now_ms = self.clock.now_ms();
                let mut st = self.state.lock();
                // Refreshing an existing subscription changes only its lease.
                // Do not clone the complete learned topology or rebuild route
                // summaries on every retry from a slow/disconnected subscriber.
                let existing = st.discovery_routes.get_mut(&side).and_then(|route| {
                    let (_, last_seen_ms) = route
                        .requested_network_variables
                        .iter_mut()
                        .find(|(requested, _)| *requested == ty)?;
                    *last_seen_ms = now_ms;
                    route.last_seen_ms = route.last_seen_ms.max(now_ms);
                    Some(())
                });
                let newly_reachable = existing.is_none();
                if newly_reachable {
                    let mut route = st.discovery_routes.get(&side).cloned().unwrap_or_default();
                    route.requested_network_variables.push((ty, now_ms));
                    Self::recompute_discovery_side_state(&mut route);
                    st.commit_discovery_route(side, route)?;
                }
                if newly_reachable {
                    self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                    Self::note_discovery_topology_change_locked(&mut st, now_ms);
                }
            }
            if !self.can_write_managed_variable(ty) {
                // Read-only caches are replicas, not authoritative owners.
                // Leave the request unhandled so normal discovery routing can
                // carry it toward a writer on another segment even when this
                // subscriber restored an older persisted value at boot.
                return Ok(false);
            }
            if let Some(value) = self.managed_variable_latest(ty) {
                self.emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side,
                        data: RouterItem::Packet(value),
                    },
                    true,
                    called_from_queue,
                )?;
                return Ok(true);
            }
            // A writer may not have produced its first value yet. Keep the
            // request moving in case another authoritative writer has one.
            return Ok(false);
        }
        #[cfg(feature = "std")]
        if pkt.data_type() == DataType::DiscoverySchema {
            #[cfg(feature = "compression")]
            let snapshot =
                self.decode_required_schema(|| discovery::decode_discovery_schema(pkt))?;
            #[cfg(not(feature = "compression"))]
            let snapshot = discovery::decode_discovery_schema(pkt)?;
            // The decoded snapshot contains the sender's complete schema, but
            // embedded targets retain only definitions that are not already
            // compiled into their local schema. Charging the complete wire
            // snapshot here made heterogeneous boards reject small schema
            // deltas whenever the sender's full snapshot exceeded the shared
            // queue budget. The merge performs an atomic projected-retained-
            // bytes check; afterwards, reclaim queue/topology space using the
            // actual retained schema size included by shared_queue_bytes_used.
            let mut st = self.state.lock();
            let budget = st.schema_growth_budget();
            let report = crate::config::merge_owned_schema_snapshot_with_budget(snapshot, budget)?;
            if report.changed() {
                st.fit_discovery_budget();
            }
            drop(st);
            self.note_schema_received(side, &packet_sender);
            return Ok(true);
        }
        if pkt.data_type() == DataType::DiscoveryLinkCapabilities {
            let _ = discovery::decode_discovery_link_capabilities(pkt)?;
            #[cfg(feature = "compression")]
            self.note_payload_codec_packet(side, pkt, true);
            return Ok(true);
        }
        let mut announce = if pkt.data_type() == DataType::DiscoveryAnnounce {
            Some(discovery::decode_discovery_announce(pkt)?)
        } else {
            None
        };
        let mut time_sources = if pkt.data_type() == DataType::DiscoveryTimeSyncSources {
            Some(discovery::decode_discovery_timesync_sources(pkt)?)
        } else {
            None
        };
        let mut st = self.state.lock();
        let now_ms = self.clock.now_ms();
        if pkt.data_type() == DataType::DiscoveryLeave {
            let leaving = packet_sender.as_str();
            let before = st.discovery_routes.clone();
            for route in st.discovery_routes.values_mut() {
                route.announcers.remove(leaving);
                for sender_state in route.announcers.values_mut() {
                    Arc::make_mut(&mut sender_state.topology_boards)
                        .retain(|board| board.sender_id != leaving);
                    for board in Arc::make_mut(&mut sender_state.topology_boards).iter_mut() {
                        board.connections.retain(|peer| peer != leaving);
                    }
                    Self::refresh_sender_topology_state(sender_state);
                }
                Self::recompute_discovery_side_state(route);
            }
            st.discovery_routes
                .retain(|_, route| !route.announcers.is_empty());
            if st.discovery_routes != before {
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
                self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
            }
            #[cfg(feature = "compression")]
            {
                drop(st);
                self.note_payload_codec_packet(side, pkt, true);
            }
            return Ok(true);
        }
        // Resolve aliases while every retained route is still visible.
        if let Some(update) = decoded_topology.as_mut() {
            for board in update.boards.iter_mut() {
                board.sender_id = Self::canonical_sender_locked(&st, &board.sender_id);
                for peer in board.connections.iter_mut() {
                    *peer = Self::canonical_sender_locked(&st, peer);
                }
            }
        }
        let mut route = st.discovery_routes.get(&side).cloned().unwrap_or_default();
        let alias_state = if packet_sender != pkt.sender() {
            route.announcers.remove(pkt.sender())
        } else {
            None
        };
        let side_link_local_enabled = st
            .sides
            .get(side)
            .and_then(|entry| entry.as_ref())
            .map(|side_ref| side_ref.opts.link_local_enabled)
            .unwrap_or(false);
        let mut sender_state = route
            .announcers
            .get_mut(&packet_sender)
            .map(core::mem::take)
            .or(alias_state)
            .unwrap_or_default();
        let changed = match pkt.data_type() {
            DataType::DiscoveryAnnounce => {
                let mut reachable = announce.take().expect("decoded above");
                // Empty announcements are slow-link keepalives, not endpoint
                // withdrawals. Preserve ownership until an explicit topology
                // update, leave, or expiry removes it. The common receive tail
                // still refreshes last_seen_ms without scheduling rediscovery.
                if reachable.is_empty() {
                    false
                } else {
                    if !side_link_local_enabled {
                        reachable.retain(|ep| !ep.is_link_local_only());
                    }
                    let board = Self::sender_topology_board_mut(&mut sender_state, &packet_sender);
                    let changed = board.reachable_endpoints != reachable;
                    board.reachable_endpoints = reachable;
                    Self::refresh_sender_topology_state(&mut sender_state);
                    changed
                }
            }
            DataType::DiscoveryTimeSyncSources => {
                let sources = time_sources.take().expect("decoded above");
                let board = Self::sender_topology_board_mut(&mut sender_state, &packet_sender);
                let changed = board.reachable_timesync_sources != sources;
                board.reachable_timesync_sources = sources;
                Self::refresh_sender_topology_state(&mut sender_state);
                changed
            }
            DataType::DiscoveryTopology => {
                let mut update = decoded_topology
                    .take()
                    .expect("topology packet was decoded before route selection");
                if !side_link_local_enabled {
                    for board in update.boards.iter_mut() {
                        board
                            .reachable_endpoints
                            .retain(|ep| !ep.is_link_local_only());
                    }
                }
                if !update.incremental {
                    sender_state.has_full_topology = true;
                }
                let changed = discovery::apply_shared_topology_update(
                    &mut sender_state.topology_boards,
                    update,
                );
                Self::refresh_sender_topology_state(&mut sender_state);
                changed
            }
            DataType::DiscoverySchema => false,
            _ => false,
        };
        sender_state.last_seen_ms = now_ms;
        route.announcers.insert(packet_sender, sender_state);
        Self::recompute_discovery_side_state(&mut route);
        st.commit_discovery_route(side, route)?;
        self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
        if changed {
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        Ok(true)
    }

    #[cfg(not(feature = "discovery"))]
    fn learn_discovery_packet(
        &self,
        _pkt: &Packet,
        _src: Option<RouterSideId>,
        _called_from_queue: bool,
    ) -> TelemetryResult<bool> {
        Ok(false)
    }

    #[inline]
    fn reliable_key(side: RouterSideId, ty: DataType) -> (RouterSideId, u32) {
        (side, ty.as_u32())
    }

    fn reliable_tx_state_mut<'a>(
        &'a self,
        st: &'a mut RouterInner,
        side: RouterSideId,
        ty: DataType,
    ) -> &'a mut ReliableTxState {
        let key = Self::reliable_key(side, ty);
        st.reliable_tx
            .entry(key)
            .or_insert_with(|| ReliableTxState {
                next_seq: 1,
                sent_order: VecDeque::new(),
                sent: Default::default(),
            })
    }

    fn reliable_rx_state_mut<'a>(
        &'a self,
        st: &'a mut RouterInner,
        side: RouterSideId,
        ty: DataType,
    ) -> &'a mut ReliableRxState {
        let key = Self::reliable_key(side, ty);
        st.reliable_rx
            .entry(key)
            .or_insert_with(|| ReliableRxState {
                expected_seq: 1,
                buffered: Default::default(),
            })
    }

    fn reliable_control_packet(
        &self,
        control_ty: DataType,
        ty: DataType,
        seq: u32,
    ) -> TelemetryResult<Packet> {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&ty.as_u32().to_le_bytes());
        bytes[4..].copy_from_slice(&seq.to_le_bytes());
        Packet::new_local(
            control_ty,
            message_meta(control_ty).endpoints_owned(),
            self.sender_arc(),
            self.packet_timestamp_ms(),
            crate::config::StandardSmallPayload::new(&bytes),
        )
    }

    fn queue_reliable_ack(
        &self,
        side: RouterSideId,
        ty: DataType,
        seq: u32,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(DataType::ReliableAck, ty, seq)?;
        self.emit_internal_tx_with_priority(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(pkt),
            },
            true,
            message_priority(DataType::ReliableAck),
            called_from_queue,
        )
    }

    fn queue_reliable_packet_request(
        &self,
        side: RouterSideId,
        ty: DataType,
        seq: u32,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(DataType::ReliablePacketRequest, ty, seq)?;
        self.emit_internal_tx_with_priority(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(pkt),
            },
            true,
            message_priority(DataType::ReliablePacketRequest),
            called_from_queue,
        )
    }

    fn queue_reliable_partial_ack(
        &self,
        side: RouterSideId,
        ty: DataType,
        seq: u32,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(DataType::ReliablePartialAck, ty, seq)?;
        self.emit_internal_tx_with_priority(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(pkt),
            },
            true,
            message_priority(DataType::ReliablePartialAck),
            called_from_queue,
        )
    }

    fn handle_reliable_ack(&self, side: RouterSideId, ty: DataType, ack: u32) {
        let mut st = self.state.lock();
        let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
        if matches!(reliable_mode(ty), crate::ReliableMode::Unordered) {
            tx_state.sent.remove(&ack);
            tx_state.sent_order.retain(|seq| *seq != ack);
            return;
        }

        while let Some(seq) = tx_state.sent_order.front().copied() {
            if seq > ack {
                break;
            }
            tx_state.sent_order.pop_front();
            tx_state.sent.remove(&seq);
        }
    }

    fn handle_reliable_partial_ack(&self, side: RouterSideId, ty: DataType, seq: u32) {
        let mut st = self.state.lock();
        let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
        if let Some(sent) = tx_state.sent.get_mut(&seq) {
            sent.partial_acked = true;
        }
    }

    fn queue_reliable_retransmit(
        &self,
        side: RouterSideId,
        ty: DataType,
        seq: u32,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let mut queued = None;
        {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
            if let Some(sent) = tx_state.sent.get_mut(&seq)
                && !sent.queued
            {
                sent.partial_acked = false;
                queued = Some(sent.bytes.clone());
            }
        }

        if let Some(bytes) = queued {
            let now = self.clock.now_ms();
            if called_from_queue {
                self.tx_queue_item_with_priority(
                    RouterTxItem::ReliableReplay {
                        dst: side,
                        ty,
                        seq,
                        bytes,
                    },
                    true,
                    Self::router_item_priority_bumped(ty),
                )?;
            } else {
                self.tx_item_impl(
                    RouterTxItem::ReliableReplay {
                        dst: side,
                        ty,
                        seq,
                        bytes,
                    },
                    true,
                    false,
                )?;
            }
            let mut st = self.state.lock();
            if let Some(sent) = st
                .reliable_tx
                .get_mut(&Self::reliable_key(side, ty))
                .and_then(|tx| tx.sent.get_mut(&seq))
            {
                sent.last_send_ms = sent.last_send_ms.max(now);
            }
        }

        Ok(())
    }

    fn send_reliable_raw_to_side(
        &self,
        side: RouterSideId,
        bytes: crate::SharedBytes,
        relayed: bool,
    ) -> TelemetryResult<()> {
        let handler = {
            let st = self.state.lock();
            let side_ref = Self::side_ref(&st, side)?;
            if !side_ref.opts.egress_enabled {
                return Ok(());
            }
            (side_ref.tx_handler.clone(), side_ref.opts.clone())
        };

        let (handler, opts) = handler;

        let Some(_side_tx_guard) = self.try_enter_side_tx(side) else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        let (ty, priority) = Self::item_type_priority(&RouterItem::Packed(bytes.clone()))?;
        let priority = priority.max(self.effective_transport_priority(ty));
        let result = match handler {
            packed @ (RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)) => {
                let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
                let mut attempts_total = 0usize;
                let mut sent_bytes = 0usize;
                self.send_side_frames_resumable(side, frames, |frame| {
                    match self.retry_with_attempts(runtime_max_handler_retries(), || {
                        Self::packed_handler_call(&packed, frame, priority)
                    }) {
                        Ok((_, attempts)) => {
                            attempts_total = attempts_total.saturating_add(attempts);
                            sent_bytes = sent_bytes.saturating_add(frame.len());
                        }
                        Err((err, attempts)) => {
                            self.note_side_tx_failure(
                                side,
                                ty,
                                attempts_total.saturating_add(attempts),
                            );
                            return Err(err);
                        }
                    }

                    Ok(())
                })?;
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                return Ok(());
            }
            RouterTxHandlerFn::Packet(f) => {
                let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                self.retry_with_attempts(runtime_max_handler_retries(), || f(&pkt))
            }
        };
        match result {
            Ok((_, attempts)) => {
                self.record_side_tx_sample(side, bytes.len(), started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, bytes.len(), relayed, attempts);
                Ok(())
            }
            Err((err, attempts)) => {
                self.note_side_tx_failure(side, ty, attempts);
                Err(err)
            }
        }
    }

    #[allow(unused_mut)]
    #[cfg(feature = "compression")]
    fn send_queued_to_side(
        &self,
        side: RouterSideId,
        data: &mut RouterItem,
        relayed: bool,
    ) -> (
        TelemetryResult<()>,
        Option<crate::payload_codec::QueueReservation<'_, RouterInner>>,
    ) {
        let reservation = match self.prepare_queued_payload(side, data) {
            Ok(reservation) => reservation,
            Err(error) => return (Err(error), None),
        };
        (
            self.send_reliable_to_side(side, data.clone(), relayed),
            reservation,
        )
    }

    fn send_reliable_to_side(
        &self,
        side: RouterSideId,
        data: RouterItem,
        relayed: bool,
    ) -> TelemetryResult<()> {
        // Reliability needs only the type and frozen-owner presence; endpoint
        // normalization and an owned wire-owner array are unnecessary here.
        let (ty, addressed) = match &data {
            RouterItem::Packet(pkt) => (pkt.data_type(), !pkt.wire_target_senders().is_empty()),
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_routing_envelope(bytes.as_ref())?;
                (env.ty, env.target_senders().len() != 0)
            }
        };
        let end_to_end_ordered =
            addressed && matches!(reliable_mode(ty), crate::ReliableMode::Ordered);
        let (handler, opts, hop_reliable_enabled) = {
            let st = self.state.lock();
            let side_ref = Self::side_ref(&st, side)?;
            let opts = side_ref.opts.clone();
            let hop_reliable_enabled = opts.reliable_enabled
                && !end_to_end_ordered
                && self.cfg.reliable_enabled()
                && !self.side_has_multiple_announcers_locked(&st, side, self.clock.now_ms());
            (side_ref.tx_handler.clone(), opts, hop_reliable_enabled)
        };

        if !matches!(
            &handler,
            RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
        ) {
            return self.call_side_tx_handler(side, &handler, &data, relayed);
        }

        if !hop_reliable_enabled {
            let mut adjusted_opts = opts;
            adjusted_opts.reliable_enabled = false;
            // End-to-end ACKs are ordinary routed control packets and must cross best-effort
            // segments. `reliable_enabled` controls only this side's hop sequencing/replay; using
            // it to discard an ACK prevents a reliable origin from ever confirming destinations
            // behind Pico-Fi, UDP, radio, or another transport with its own reliability layer.
            let preserve_end_to_end_ack = true;
            if let Some(adjusted) =
                self.adjust_reliable_for_side(adjusted_opts, data, preserve_end_to_end_ack)?
            {
                return self.call_side_tx_handler(side, &handler, &adjusted, relayed);
            }
            return Ok(());
        }

        if let RouterItem::Packed(bytes) = &data {
            wire_format::peek_routing_frame_info(bytes.as_ref())?;
        }
        let priority = self.item_service_priority(&data)?;

        if !is_reliable_type(ty) {
            if let Some(adjusted) = self.adjust_reliable_for_side(opts, data, true)? {
                self.call_side_tx_handler(side, &handler, &adjusted, relayed)?;
            }
            return Ok(());
        }

        #[cfg(feature = "compression")]
        let data = match data {
            RouterItem::Packed(bytes) => {
                let budget = self.state.lock().memory.max_queue_budget;
                let normalized =
                    wire_format::payload_encoding_for_retention(bytes.as_ref(), budget)?;
                RouterItem::Packed(
                    normalized
                        .map(crate::shared_bytes::convert)
                        .unwrap_or(bytes),
                )
            }
            packet => packet,
        };
        let (seq, flags) = {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
            if tx_state.sent.len() >= runtime_reliable_max_pending() {
                return Err(TelemetryError::Io("reliable window full"));
            }
            let seq = tx_state.next_seq;
            let next = tx_state.next_seq.wrapping_add(1);
            tx_state.next_seq = if next == 0 { 1 } else { next };
            let flags = match reliable_mode(ty) {
                crate::ReliableMode::Unordered => wire_format::RELIABLE_FLAG_UNORDERED,
                _ => 0,
            };
            (seq, flags)
        };

        let bytes: crate::SharedBytes = match data {
            RouterItem::Packet(pkt) => self.pack_packet_for_router(
                &pkt,
                Some(wire_format::ReliableHeader { flags, seq, ack: 0 }),
            )?,
            RouterItem::Packed(bytes) => {
                #[cfg(feature = "cryptography")]
                if self.e2e_seal_config_for_type(ty).is_some() {
                    self.prepare_packed_for_remote(
                        bytes,
                        Some(Some(wire_format::ReliableHeader { flags, seq, ack: 0 })),
                    )?
                } else {
                    let Some(rewritten) =
                        wire_format::rewrite_reliable_header_owned(bytes.as_ref(), flags, seq, 0)?
                    else {
                        let Some(_side_tx_guard) = self.try_enter_side_tx(side) else {
                            return Err(TelemetryError::Io("side tx busy"));
                        };
                        let started_ms = self.clock.now_ms();
                        let frames =
                            self.encode_side_transport_frames(side, opts, bytes.clone())?;
                        let mut attempts_total = 0usize;
                        let mut sent_bytes = 0usize;
                        self.send_side_frames_resumable(side, frames, |frame| {
                            match self.retry_with_attempts(runtime_max_handler_retries(), || {
                                Self::packed_handler_call(&handler, frame, priority)
                            }) {
                                Ok((_, attempts)) => {
                                    attempts_total = attempts_total.saturating_add(attempts);
                                    sent_bytes = sent_bytes.saturating_add(frame.len());
                                }
                                Err((err, attempts)) => {
                                    self.note_side_tx_failure(
                                        side,
                                        ty,
                                        attempts_total.saturating_add(attempts),
                                    );
                                    return Err(err);
                                }
                            }

                            Ok(())
                        })?;
                        self.record_side_tx_sample(
                            side,
                            sent_bytes,
                            started_ms,
                            self.clock.now_ms(),
                        );
                        self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                        return Ok(());
                    };
                    crate::shared_bytes::convert(rewritten)
                }
                #[cfg(not(feature = "cryptography"))]
                {
                    let Some(rewritten) =
                        wire_format::rewrite_reliable_header_owned(bytes.as_ref(), flags, seq, 0)?
                    else {
                        let Some(_side_tx_guard) = self.try_enter_side_tx(side) else {
                            return Err(TelemetryError::Io("side tx busy"));
                        };
                        let started_ms = self.clock.now_ms();
                        let frames =
                            self.encode_side_transport_frames(side, opts, bytes.clone())?;
                        let mut attempts_total = 0usize;
                        let mut sent_bytes = 0usize;
                        self.send_side_frames_resumable(side, frames, |frame| {
                            match self.retry_with_attempts(runtime_max_handler_retries(), || {
                                Self::packed_handler_call(&handler, frame, priority)
                            }) {
                                Ok((_, attempts)) => {
                                    attempts_total = attempts_total.saturating_add(attempts);
                                    sent_bytes = sent_bytes.saturating_add(frame.len());
                                }
                                Err((err, attempts)) => {
                                    self.note_side_tx_failure(
                                        side,
                                        ty,
                                        attempts_total.saturating_add(attempts),
                                    );
                                    return Err(err);
                                }
                            }

                            Ok(())
                        })?;
                        self.record_side_tx_sample(
                            side,
                            sent_bytes,
                            started_ms,
                            self.clock.now_ms(),
                        );
                        self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                        return Ok(());
                    };
                    crate::shared_bytes::convert(rewritten)
                }
            }
        };

        #[cfg(feature = "compact-packet-store")]
        let mut bytes = bytes;

        let Some(_side_tx_guard) = self.try_enter_side_tx(side) else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
        let mut attempts_total = 0usize;
        let mut sent_bytes = 0usize;
        self.send_side_frames_resumable(side, frames, |frame| {
            match self.retry_with_attempts(runtime_max_handler_retries(), || {
                Self::packed_handler_call(&handler, frame, priority)
            }) {
                Ok((_, attempts)) => {
                    attempts_total = attempts_total.saturating_add(attempts);
                    sent_bytes = sent_bytes.saturating_add(frame.len());
                }
                Err((err, attempts)) => {
                    self.note_side_tx_failure(side, ty, attempts_total.saturating_add(attempts));
                    return Err(err);
                }
            }

            Ok(())
        })?;
        self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
        self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);

        #[cfg(feature = "compact-packet-store")]
        {
            let _ = bytes.park_for_queue();
        }

        {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
            tx_state.sent_order.push_back(seq);
            tx_state.sent.insert(
                seq,
                ReliableSent {
                    bytes: bytes.clone(),
                    last_send_ms: self.clock.now_ms(),
                    retries: 0,
                    queued: false,
                    partial_acked: false,
                },
            );
        }

        Ok(())
    }

    fn run_side_chunk_transfer<T>(
        &self,
        side: RouterSideId,
        key: u64,
        send: impl FnOnce(&mut usize) -> TelemetryResult<T>,
    ) -> TelemetryResult<T> {
        let mut next = {
            let mut st = self.state.lock();
            let transport = st
                .side_transport
                .get_mut(&side)
                .ok_or(TelemetryError::BadArg)?;
            if transport.tx_chunk_progress.is_none() {
                crate::memory_admission::check(
                    512,
                    core::mem::size_of::<crate::side_transport::SideTxProgress>(),
                )?;
                transport.tx_chunk_progress =
                    Some(Box::new(crate::side_transport::SideTxProgress::default()));
            }
            transport
                .tx_chunk_progress
                .as_mut()
                .expect("initialized")
                .begin(key, self.clock.now_ms())?
        };
        let result = send(&mut next);
        if let Some(progress) = self
            .state
            .lock()
            .side_transport
            .get_mut(&side)
            .and_then(|transport| transport.tx_chunk_progress.as_mut())
        {
            progress.finish(key, next, self.clock.now_ms(), &result);
        }
        result
    }

    fn send_side_frames_resumable(
        &self,
        side: RouterSideId,
        mut frames: SideTransportFrames,
        mut send: impl FnMut(&[u8]) -> TelemetryResult<()>,
    ) -> TelemetryResult<()> {
        let bootstraps_template = frames.bootstraps_template();
        let result = if frames.len() == 1 {
            frames.send_resuming(&mut 0, send)
        } else {
            let key = frames.progress_key();
            self.run_side_chunk_transfer(side, key, |next| frames.send_resuming(next, &mut send))
        };
        if result.is_err() && bootstraps_template {
            // Encoding has already inserted the TX template, but a busy or
            // failed handler did not accept its bootstrap. Keep dictionary
            // eviction history and force a full refresh on the next attempt.
            // Never clear RX templates or allocate during this recovery.
            if let Some(state) = self.state.lock().side_transport.get_mut(&side) {
                state.refresh_transmit_header_templates();
            }
        }
        result
    }

    fn split_side_transport_frame(
        &self,
        _side: RouterSideId,
        frame: crate::SharedBytes,
        max_frame_bytes: usize,
    ) -> TelemetryResult<SideTransportFrames> {
        SideTransportFrames::split(frame, max_frame_bytes, self.sender_arc().as_bytes())
    }

    #[cfg(all(feature = "compression", feature = "discovery"))]
    fn note_payload_codec_packet(&self, side: RouterSideId, pkt: &Packet, accepted: bool) {
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        if !st
            .sides
            .get(side)
            .and_then(|entry| entry.as_ref())
            .is_some_and(|entry| {
                matches!(
                    entry.tx_handler,
                    RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
                )
            })
        {
            return;
        }
        if accepted && pkt.data_type() == crate::DataType::DiscoveryLeave {
            for transport in st.side_transport.values_mut() {
                let _ = transport.payload_codec.discovery_packet(
                    pkt,
                    true,
                    now,
                    DISCOVERY_ROUTE_TTL_MS,
                );
            }
        } else if let Some(transport) = st.side_transport.get_mut(&side) {
            let _ = transport.payload_codec.discovery_packet(
                pkt,
                accepted,
                now,
                DISCOVERY_ROUTE_TTL_MS,
            );
        }
        if st.shared_queue_bytes_used() > st.memory.max_queue_budget
            && let Some(transport) = st.side_transport.get_mut(&side)
        {
            transport.payload_codec.evict(now, DISCOVERY_ROUTE_TTL_MS);
        }
    }
    #[cfg(all(feature = "compression", feature = "discovery"))]
    fn note_payload_codec_address(&self, side: RouterSideId, payload: &[u8], accepted: bool) {
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        if !st
            .sides
            .get(side)
            .and_then(|entry| entry.as_ref())
            .is_some_and(|entry| {
                matches!(
                    entry.tx_handler,
                    RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
                )
            })
        {
            return;
        }
        if let Some(transport) = st.side_transport.get_mut(&side) {
            let _ = transport.payload_codec.address_payload(
                payload,
                accepted,
                now,
                DISCOVERY_ROUTE_TTL_MS,
            );
        }
        if st.shared_queue_bytes_used() > st.memory.max_queue_budget
            && let Some(transport) = st.side_transport.get_mut(&side)
        {
            transport.payload_codec.evict(now, DISCOVERY_ROUTE_TTL_MS);
        }
    }

    #[cfg(feature = "compression")]
    fn payload_for_transport_side(
        &self,
        side: RouterSideId,
        raw: crate::SharedBytes,
    ) -> TelemetryResult<crate::SharedBytes> {
        #[cfg(not(feature = "discovery"))]
        let _ = side;
        let (allowed, budget) = {
            #[cfg(feature = "discovery")]
            let mut st = self.state.lock();
            #[cfg(not(feature = "discovery"))]
            let st = self.state.lock();
            let budget = st.memory.max_queue_budget;
            #[cfg(feature = "discovery")]
            let allowed = {
                let transport = st
                    .side_transport
                    .get_mut(&side)
                    .ok_or(TelemetryError::BadArg)?;
                let generation = transport.payload_codec.generation();
                if transport.payload_codec_choice != generation {
                    transport.payload_codec_choice = generation;
                    transport.tx_chunk_progress = None;
                    transport.refresh_transmit_header_templates();
                }
                transport.payload_codec.allowed(self.clock.now_ms())
            };
            #[cfg(not(feature = "discovery"))]
            let allowed = false;
            (allowed, budget)
        };
        Ok(
            match wire_format::payload_encoding_for_side(raw.as_ref(), allowed, budget)? {
                Some(frame) => crate::shared_bytes::convert(frame),
                None => raw,
            },
        )
    }

    /// Persist an admitted downgrade in the queue owner before a handler can
    /// backpressure it. Retrying retained traffic must not need fresh decoder
    /// scratch merely to reproduce the same already-admitted plaintext frame.
    #[cfg(feature = "compression")]
    fn prepare_queued_payload(
        &self,
        side: RouterSideId,
        data: &mut RouterItem,
    ) -> TelemetryResult<Option<crate::payload_codec::QueueReservation<'_, RouterInner>>> {
        let RouterItem::Packed(bytes) = data else {
            return Ok(None);
        };
        if !bytes.first().is_some_and(|flags| flags & 0x11 == 1) {
            return Ok(None);
        }
        let capable = {
            #[cfg(feature = "discovery")]
            {
                self.state
                    .lock()
                    .side_transport
                    .get(&side)
                    .is_some_and(|transport| transport.payload_codec.allowed(self.clock.now_ms()))
            }
            #[cfg(not(feature = "discovery"))]
            {
                false
            }
        };
        if capable {
            return Ok(None);
        }
        let required = wire_format::decoded_frame_upper_bound(bytes.as_ref())?
            .checked_add(
                size_of::<crate::SharedBytes>()
                    + size_of::<bool>()
                    + size_of::<u8>()
                    + size_of::<u64>(),
            )
            .ok_or(TelemetryError::Io("memory pressure"))?;
        let reservation = crate::payload_codec::QueueReservation::acquire(&self.state, required)?;
        *bytes = self.payload_for_transport_side(side, bytes.clone())?;
        Ok(Some(reservation))
    }

    fn encode_side_transport_frames(
        &self,
        side: RouterSideId,
        opts: RouterSideOptions,
        raw: crate::SharedBytes,
    ) -> TelemetryResult<SideTransportFrames> {
        #[cfg(feature = "compression")]
        let raw = self.payload_for_transport_side(side, raw)?;
        if !opts.header_template_enabled && opts.max_frame_bytes == 0 {
            return Ok(SideTransportFrames::single(raw));
        }

        let raw_len = raw.len();
        if opts.max_frame_bytes != 0 && raw_len > opts.max_frame_bytes {
            // Canonical bytes keep a partially accepted transfer independent
            // of dictionary churn while other traffic is serviced.
            let frames = self.split_side_transport_frame(side, raw, opts.max_frame_bytes)?;
            let mut st = self.state.lock();
            let stats = st.side_runtime_stats.entry(side).or_default();
            stats.note_side_transport_full(raw_len, frames.wire_len());
            stats.note_side_transport_chunks(frames.len());
            return Ok(frames);
        }

        if opts.header_template_enabled {
            // Shared buses cannot retain one coherent dictionary across
            // independent producers. Do not build owned templates or wrap
            // canonical bytes when no dictionary can be used.
            let frame = wire_format::peek_routing_frame_info(raw.as_ref())?;
            let without_dictionary = opts.max_side_transport_templates == 0 || {
                let st = self.state.lock();
                self.side_has_multiple_announcers_locked(&st, side, self.clock.now_ms())
            };
            let reliable = is_reliable_type(frame.envelope.ty)
                || frame.reliable.is_some()
                // Managed-variable delivery freezes destination owners even
                // when the application schema itself is best effort. Its
                // end-to-end receipt must not depend on a lossy dictionary
                // bootstrap, and transports must be able to prioritize it
                // independently of queued schema/template frames.
                || frame.envelope.target_senders().len() != 0
                || matches!(
                    frame.envelope.ty,
                    crate::DataType::ReliableAck
                        | crate::DataType::ReliablePartialAck
                        | crate::DataType::ReliablePacketRequest
                );
            if without_dictionary || reliable {
                let mut st = self.state.lock();
                if without_dictionary {
                    let removed = st
                        .side_transport
                        .get_mut(&side)
                        .ok_or(TelemetryError::BadArg)?
                        .trim_tx_templates_to(0);
                    for _ in 0..removed {
                        st.side_runtime_stats
                            .entry(side)
                            .or_default()
                            .note_side_transport_template_eviction();
                    }
                }
                st.side_runtime_stats
                    .entry(side)
                    .or_default()
                    .note_side_transport_full(raw_len, raw_len);
                return Ok(SideTransportFrames::single(raw));
            }
        }

        if opts.header_template_enabled && crate::memory_admission::supports_work_kinds() {
            let (template, ..) = extract_side_header_template_view(raw.as_ref())?;
            let cached = self
                .state
                .lock()
                .side_transport
                .get(&side)
                .is_some_and(|transport| {
                    transport.tx_template_ids.contains_key(&template.hash)
                        && transport.tx_templates.contains_key(&template.hash)
                });
            if !cached
                && matches!(
                    crate::memory_admission::check_receive(raw.as_ref()),
                    Err(TelemetryError::Io("memory pressure"))
                )
            {
                // Compression is optional. Retain the canonical shared frame
                // instead of allocating a dictionary entry under pressure.
                // Oversized frames returned through the normal chunker above.
                self.state
                    .lock()
                    .side_runtime_stats
                    .entry(side)
                    .or_default()
                    .note_side_transport_full(raw_len, raw_len);
                return Ok(SideTransportFrames::single(raw));
            }
        }

        let mut compact_payload_len = None;
        let mut used_compact = false;
        let used_timestamp_delta = false;
        let omitted_timestamp = false;
        let wrapped = if opts.header_template_enabled {
            let (template, _ty, flags, data_size, timestamp, nonce, reliable_seq_ack, payload) =
                extract_side_header_template_view(raw.as_ref())?;
            // Reliable and frozen-owner packets already returned above.
            // Classify once per encode rather than repeating a schema lookup.
            let (template_id, use_compact, _previous_timestamp) = {
                let mut st = self.state.lock();
                /* Keep the sender's compact dictionary within the smallest
                 * capacity advertised by a live peer on this side. Template
                 * IDs otherwise outlive entries on a smaller receiver and
                 * later compact values are silently undecodable. */
                #[cfg(feature = "discovery")]
                let mut effective_template_limit = opts.max_side_transport_templates;
                #[cfg(not(feature = "discovery"))]
                let effective_template_limit = opts.max_side_transport_templates;
                #[cfg(feature = "discovery")]
                {
                    if let Some(route) = st.discovery_routes.get(&side) {
                        let active_peers = route
                            .announcers
                            .values()
                            .filter(|sender| {
                                self.clock.now_ms().saturating_sub(sender.last_seen_ms)
                                    <= DISCOVERY_ROUTE_TTL_MS
                            })
                            .count();
                        /* Compact template state is intentionally side-local.
                         * On a shared bus, independent producers cannot divide
                         * a receiver's bounded dictionary between themselves,
                         * so their compact frames can evict one another. Keep
                         * compression for point-to-point links and
                         * automatically use self-describing full frames once
                         * discovery proves a side is multi-producer. */
                        if active_peers > 1 {
                            effective_template_limit = 0;
                        } else {
                            effective_template_limit = route
                                .announcers
                                .values()
                                .filter_map(|sender| sender.link_capabilities)
                                .filter(|caps| {
                                    caps.flags & discovery::LINK_CAPABILITY_HEADER_TEMPLATES != 0
                                        && caps.max_side_transport_templates > 0
                                })
                                .map(|caps| caps.max_side_transport_templates as usize)
                                .fold(effective_template_limit, core::cmp::min);
                        }
                    }
                }
                let trimmed = st
                    .side_transport
                    .get_mut(&side)
                    .ok_or(TelemetryError::BadArg)?
                    .trim_tx_templates_to(effective_template_limit);
                for _ in 0..trimmed {
                    st.side_runtime_stats
                        .entry(side)
                        .or_default()
                        .note_side_transport_template_eviction();
                }
                let side_state = st
                    .side_transport
                    .get_mut(&side)
                    .ok_or(TelemetryError::BadArg)?;
                if let Some(id) = side_state.tx_template_ids.get(&template.hash).copied() {
                    let previous = side_state.tx_last_timestamps.get(&id).copied();
                    /* A full refresh makes compact transport self-healing when
                     * the receiver missed the original template frame. */
                    const FULL_REFRESH_AFTER_COMPACT_FRAMES: u8 = 8;
                    let compact_uses = side_state.tx_compact_uses.entry(id).or_default();
                    // Discovery must bootstrap even when a receiver lost its dictionary.
                    #[cfg(feature = "discovery")]
                    let discovery_refresh = discovery::is_discovery_type(_ty);
                    #[cfg(not(feature = "discovery"))]
                    let discovery_refresh = false;
                    let use_compact =
                        *compact_uses < FULL_REFRESH_AFTER_COMPACT_FRAMES && !discovery_refresh;
                    if use_compact {
                        *compact_uses = compact_uses.saturating_add(1);
                    } else {
                        *compact_uses = 0;
                    }
                    (id, use_compact, previous)
                } else {
                    /* Sequential template IDs collide when multiple routers
                     * transmit on one physical bus. The template hash covers
                     * the source address and immutable header fields, making
                     * this ID producer-stable without adding bytes to compact
                     * frames. */
                    let template_id = ((template.hash >> 32) as u32 ^ template.hash as u32).max(1);
                    let evicted = side_state.insert_tx_template(
                        template.into_owned(),
                        template_id,
                        effective_template_limit,
                    );
                    if evicted {
                        st.side_runtime_stats
                            .entry(side)
                            .or_default()
                            .note_side_transport_template_eviction();
                    }
                    if let Some(side_state) = st.side_transport.get_mut(&side)
                        && effective_template_limit > 0
                    {
                        side_state.tx_last_timestamps.insert(template_id, timestamp);
                    }
                    (template_id, false, None)
                }
            };
            if use_compact {
                used_compact = true;
                compact_payload_len = Some(payload.len());
                // A previous transmitted frame is not a confirmed receive base.
                // Absolute timestamps preserve identity after loss or reordering.
                let timestamp_field = Some(timestamp);
                let mut body = Vec::with_capacity(payload.len() + 32);
                body.push(flags);
                write_uleb128_local(u64::from(template_id), &mut body);
                write_uleb128_local(data_size, &mut body);
                if let Some(timestamp_field) = timestamp_field {
                    write_uleb128_local(timestamp_field, &mut body);
                }
                if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
                    write_uleb128_local(u64::from(nonce), &mut body);
                }
                if let Some((seq, ack)) = reliable_seq_ack {
                    write_uleb128_local(u64::from(seq), &mut body);
                    write_uleb128_local(u64::from(ack), &mut body);
                }
                body.extend_from_slice(payload);
                {
                    let mut st = self.state.lock();
                    if let Some(side_state) = st.side_transport.get_mut(&side) {
                        side_state.tx_last_timestamps.insert(template_id, timestamp);
                    }
                }
                let kind = if omitted_timestamp {
                    SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP
                } else if used_timestamp_delta {
                    SIDE_TRANSPORT_KIND_COMPACT_DELTA
                } else {
                    SIDE_TRANSPORT_KIND_COMPACT
                };
                wrap_side_transport_frame(kind, &body)
            } else {
                let mut body = Vec::with_capacity(raw.len() + 4);
                write_uleb128_local(u64::from(template_id), &mut body);
                body.extend_from_slice(raw.as_ref());
                wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &body)
            }
        } else {
            wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, raw.as_ref())
        };

        let frames = if opts.max_frame_bytes != 0 && wrapped.len() > opts.max_frame_bytes {
            self.split_side_transport_frame(side, wrapped, opts.max_frame_bytes)
        } else {
            Ok(SideTransportFrames::single(wrapped))
        }?;
        let wire_len = frames.wire_len();
        let mut st = self.state.lock();
        let stats = st.side_runtime_stats.entry(side).or_default();
        if used_compact {
            let overhead = compact_payload_len
                .map(|payload_len| wire_len.saturating_sub(payload_len))
                .unwrap_or(wire_len);
            stats.note_side_transport_compact(
                raw_len,
                wire_len,
                overhead,
                used_timestamp_delta,
                omitted_timestamp,
            );
            if opts.compact_header_target_bytes != 0 && overhead > opts.compact_header_target_bytes
            {
                stats.note_side_transport_compact_target_miss();
            }
        } else {
            stats.note_side_transport_full(raw_len, wire_len);
        }
        if frames.len() > 1 {
            stats.note_side_transport_chunks(frames.len());
        }
        Ok(frames)
    }

    fn expire_side_chunks(&self) {
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        for side in st.side_transport.values_mut() {
            let side = side.as_mut();
            #[cfg(all(feature = "compression", feature = "discovery"))]
            side.payload_codec.expire(now, DISCOVERY_ROUTE_TTL_MS);
            let reclaimed =
                SideChunkAssembly::expire(&mut side.rx_chunks, &mut side.rx_chunk_bytes, now);
            side.rx_chunk_reclaims = side.rx_chunk_reclaims.saturating_add(reclaimed);
        }
    }

    // A validated frame from a previously discovered direct peer proves that
    // its link is alive, even when allocation admission refuses its payload.
    // Update existing timestamps only: no allocation, schema merge or new route.
    #[cfg(feature = "discovery")]
    fn refresh_ingress_peer_liveness<'a>(
        &self,
        side: RouterSideId,
        bytes: &'a [u8],
    ) -> Option<wire_format::RoutingFrameInfo<'a>> {
        let frame = wire_format::peek_routing_frame_info(bytes).ok()?;
        self.refresh_peer_liveness(side, frame.envelope.source_address);
        #[cfg(feature = "compression")]
        if frame.envelope.ty == crate::DataType::DiscoveryAddress
            && let Ok(Some((_, payload))) =
                wire_format::peek_plain_discovery_payload(bytes, crate::DataType::DiscoveryAddress)
        {
            self.note_payload_codec_address(side, payload, false);
        }
        Some(frame)
    }

    #[cfg(feature = "discovery")]
    #[cfg_attr(not(feature = "std"), inline(never))]
    fn refresh_peer_liveness(&self, side: RouterSideId, address: u32) {
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        #[cfg(feature = "compression")]
        if let Some(transport) = st.side_transport.get_mut(&side) {
            transport
                .payload_codec
                .observe(address, now, DISCOVERY_ROUTE_TTL_MS);
        }
        let Some(route) = st.discovery_routes.get_mut(&side) else {
            return;
        };
        let mut found = None;
        for (name, peer) in &mut route.announcers {
            if peer.advertised_address == Some(address) || sender_address_u32(name) == address {
                // Ambiguous numeric identities must be resolved by discovery.
                if found.is_some() {
                    return;
                }
                found = Some(peer);
            }
        }
        let Some(peer) = found else {
            return;
        };
        peer.last_seen_ms = now;
        route.last_seen_ms = route.last_seen_ms.max(now);
    }

    /// Consume only an exact unsequenced topology retry on its ingress link.
    /// CRC, shape, payload length and reliable-header restrictions are checked
    /// before this path; it cannot bypass receipts, update a graph or allocate.
    #[cfg(feature = "discovery")]
    fn consume_known_packed_topology(
        &self,
        side: RouterSideId,
        bytes: &[u8],
    ) -> TelemetryResult<bool> {
        let Some((address, payload)) =
            wire_format::peek_plain_discovery_payload(bytes, crate::DataType::DiscoveryTopology)?
        else {
            return Ok(false);
        };
        let now = self.clock.now_ms();
        let mut st = self.state.lock();
        let Some(route) = st.discovery_routes.get_mut(&side) else {
            return Ok(false);
        };
        let mut found = None;
        for (name, peer) in &mut route.announcers {
            if peer.advertised_address == Some(address) || sender_address_u32(name) == address {
                if found.is_some() {
                    return Ok(false);
                }
                found = Some(peer);
            }
        }
        let Some(peer) = found else {
            return Ok(false);
        };
        let Some(full) =
            discovery::topology_payload_matches_retained(payload, &peer.topology_boards)
        else {
            return Ok(false);
        };
        peer.has_full_topology |= full;
        peer.last_seen_ms = now;
        route.last_seen_ms = route.last_seen_ms.max(now);
        Ok(true)
    }

    #[cfg(all(feature = "discovery", not(feature = "std")))]
    fn consume_known_packed_schema(
        &self,
        side: RouterSideId,
        bytes: &[u8],
    ) -> TelemetryResult<bool> {
        let Some((address, payload)) =
            wire_format::peek_plain_discovery_payload(bytes, crate::DataType::DiscoverySchema)?
        else {
            return Ok(false);
        };
        self.refresh_peer_liveness(side, address);
        self.merge_schema_changes(payload)?;
        let mut st = self.state.lock();
        if let Some(route) = st.discovery_routes.get_mut(&side) {
            for (name, peer) in &mut route.announcers {
                if peer.advertised_address == Some(address) || sender_address_u32(name) == address {
                    peer.has_schema = true;
                    break;
                }
            }
        }
        Ok(true)
    }

    #[cfg(all(feature = "compression", feature = "discovery"))]
    fn decode_required_schema<T>(
        &self,
        mut decode: impl FnMut() -> TelemetryResult<T>,
    ) -> TelemetryResult<T> {
        loop {
            match decode() {
                Err(error @ TelemetryError::Io("memory pressure")) => {
                    if !self.state.lock().reclaim_codec_metadata() {
                        return Err(error);
                    }
                }
                result => return result,
            }
        }
    }

    #[cfg(all(feature = "discovery", not(feature = "std")))]
    #[inline(never)]
    fn merge_schema_changes(&self, payload: &[u8]) -> TelemetryResult<()> {
        // Validate the entire catalog, then materialize only changed entries.
        // Packed and already-decoded ingress share one atomic budgeted merge.
        #[cfg(feature = "compression")]
        let snapshot = self.decode_required_schema(|| discovery::decode_schema_changes(payload))?;
        #[cfg(not(feature = "compression"))]
        let snapshot = discovery::decode_schema_changes(payload)?;
        let mut st = self.state.lock();
        let budget = st.schema_growth_budget();
        let report = crate::config::merge_owned_schema_snapshot_with_budget(snapshot, budget)?;
        if report.changed() {
            st.fit_discovery_budget();
        }
        Ok(())
    }

    /// Ignore an overheard canonical frame only when every frozen holder is
    /// positively known behind its ingress. Unknown/stale routes, runtime
    /// schema changes, managed state, hop receipts and explicit policies keep
    /// the ordinary receive path. No payload copy, queue slot or ACK is owned.
    #[cfg(all(
        feature = "discovery",
        any(feature = "std", feature = "ingress-target-filter")
    ))]
    fn targets_only_ingress(
        &self,
        side: RouterSideId,
        frame: &wire_format::RoutingFrameInfo<'_>,
    ) -> bool {
        let ty = frame.envelope.ty;
        // Most packets are untargeted bulk data: do not add a schema lookup
        // or registry lock to that existing hot path.
        if is_internal_control_type(ty)
            || frame.envelope.target_senders().len() == 0
            || frame.reliable.is_some_and(|h| {
                h.flags != wire_format::RELIABLE_FLAG_UNSEQUENCED || h.seq != 0 || h.ack != 0
            })
        {
            return false;
        }
        let Some(meta) = crate::config::try_get_message_meta(ty) else {
            return false;
        };
        if frame
            .envelope
            .wire_shape
            .is_some_and(|shape| shape != meta.element)
        {
            return false;
        }
        let local_hash = Self::sender_hash(self.sender_arc().as_ref());
        let st = self.state.lock();
        if st.managed_variable_types.contains(&ty.as_u32())
            || Self::has_explicit_route_policy_locked(&st, Some(side), ty)
        {
            return false;
        }
        let now = self.clock.now_ms();
        frame.envelope.target_senders().all(|target| {
            target != local_hash
                && target != u64::from(st.local_address.address)
                && Self::side_matches_target_senders_locked(
                    &st,
                    side,
                    wire_format::TargetSenderSet::Hashes(&[target]),
                    now,
                )
                && !st.sides.iter().enumerate().any(|(other, entry)| {
                    other != side
                        && entry.as_ref().is_some_and(|e| e.opts.egress_enabled)
                        && Self::side_matches_target_senders_locked(
                            &st,
                            other,
                            wire_format::TargetSenderSet::Hashes(&[target]),
                            now,
                        )
                })
        })
    }

    // A two-sided, fully warmed packed bridge needs no new large metadata.
    // Re-check before dispatch: schemas/templates/routes can change while queued.
    #[cfg(feature = "discovery")]
    fn cached_transit_ready(
        &self,
        side: RouterSideId,
        bytes: &[u8],
        view: Option<&wire_format::RoutingFrameInfo<'_>>,
    ) -> TelemetryResult<bool> {
        // Compressed payloads stay opaque on this fully warmed packed-only
        // path. No decompression workspace is needed unless the current schema,
        // route or local/managed role changes (all rechecked below).
        // Encrypted frames retain their independent conservative admission.
        if bytes.len() > 128 || bytes.first().is_none_or(|flags| flags & 0x10 != 0) {
            return Ok(false);
        }
        let parsed;
        let frame = match view {
            Some(frame) => frame,
            None => {
                parsed = wire_format::peek_routing_frame_info(bytes)?;
                &parsed
            }
        };
        let ty = frame.envelope.ty;
        if is_internal_control_type(ty)
            || frame.envelope.is_reliable
            || frame.reliable.is_some()
            || frame.envelope.target_senders().len() != 0
            // A matching inline schema is immutable metadata on the existing
            // shared frame. It needs no owned decoder state. Unknown or changed
            // shapes still require full admission and payload decoding.
            || frame.envelope.wire_shape.is_some_and(|shape| {
                shape != crate::message_meta(ty).element
            })
            || !(1..=3).contains(&frame.envelope.endpoints().take(4).count())
        {
            return Ok(false);
        }
        if self.is_managed_variable_type(ty)
            || frame.envelope.endpoints().any(|ep| {
                self.endpoint_has_packet_handler(ep) || self.endpoint_has_packed_handler(ep)
            })
        {
            return Ok(false);
        }

        // A known peer's bounded canonical frame needs no optional dictionary
        // entry. Avoid parsing/hashing that header merely to rediscover this
        // fallback. Recheck peer/route state below before granting admission.
        let canonical_possible = {
            let st = self.state.lock();
            st.discovery_routes.get(&side).is_some_and(|route| {
                route.announcers.iter().any(|(name, peer)| {
                    peer.advertised_address == Some(frame.envelope.source_address)
                        || sender_address_u32(name) == frame.envelope.source_address
                })
            }) && st.sides.iter().flatten().all(|entry| {
                entry.opts.max_frame_bytes == 0 || bytes.len() <= entry.opts.max_frame_bytes
            })
        };
        let template_hash = if canonical_possible {
            None
        } else {
            Some(extract_side_header_template_view(bytes)?.0.hash)
        };
        let st = self.state.lock();
        let active: usize = st.sides.iter().filter(|entry| entry.is_some()).count();
        if active != 2 {
            return Ok(false);
        }
        for (id, entry) in st
            .sides
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| entry.as_ref().map(|e| (id, e)))
        {
            if entry.opts.reliable_enabled
                || !matches!(
                    entry.tx_handler,
                    RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
                )
                || !st
                    .side_runtime_stats
                    .get(&id)
                    .is_some_and(|stats| stats.data_types.contains_key(&ty.as_u32()))
            {
                return Ok(false);
            }
            if id == side {
                continue;
            }
            #[cfg(feature = "discovery")]
            if !st.discovery_routes.get(&id).is_some_and(|route| {
                self.clock.now_ms().saturating_sub(route.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
                    && frame
                        .envelope
                        .endpoints()
                        .any(|ep| route.reachable.contains(&ep))
            }) {
                return Ok(false);
            }
            if entry.opts.header_template_enabled
                && entry.opts.max_frame_bytes != 0
                && entry.opts.max_side_transport_templates != 0
                && !self.side_has_multiple_announcers_locked(&st, id, self.clock.now_ms())
                && !template_hash.is_some_and(|hash| {
                    st.side_transport.get(&id).is_some_and(|transport| {
                        transport.tx_template_ids.contains_key(&hash)
                            && transport.tx_templates.contains_key(&hash)
                    })
                })
            {
                // An optional compression entry may have been evicted while
                // routing/statistics remain warm. Canonical forwarding needs
                // no replacement entry, but must fit the transport and belong
                // to an already discovered ingress peer.
                if (entry.opts.max_frame_bytes == 0 || bytes.len() <= entry.opts.max_frame_bytes)
                    && st.discovery_routes.get(&side).is_some_and(|route| {
                        route.announcers.iter().any(|(name, peer)| {
                            peer.advertised_address == Some(frame.envelope.source_address)
                                || sender_address_u32(name) == frame.envelope.source_address
                        })
                    })
                {
                    continue;
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(not(feature = "discovery"))]
    fn cached_transit_ready(
        &self,
        _side: RouterSideId,
        _bytes: &[u8],
        _view: Option<&wire_format::RoutingFrameInfo<'_>>,
    ) -> TelemetryResult<bool> {
        Ok(false)
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn reclaim_for_receive(&self, bytes: &[u8], victim: &mut Option<(u32, u8)>) -> bool {
        let Some((incoming, priority)) = crate::admission_fairness::incoming(bytes) else {
            return false;
        };
        self.reclaim_for_incoming(incoming, priority, victim)
    }
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    fn reclaim_for_incoming(
        &self,
        incoming: u32,
        priority: u8,
        victim: &mut Option<(u32, u8)>,
    ) -> bool {
        let mut st = self.state.lock();
        let (owner, priority) = if let Some(selected) = *victim {
            selected
        } else {
            let Some(owner) = st.competing_bulk_owner(incoming, priority) else {
                return false;
            };
            *victim = Some((owner, priority));
            (owner, priority)
        };
        st.reclaim_bulk_from(owner, priority, None)
    }
    fn admit_received_frame(&self, side: RouterSideId, bytes: &[u8]) -> TelemetryResult<()> {
        self.admit_received_frame_with_view(side, bytes, None)
    }

    // Reuse only the view validated in this ingress call. Queue dispatch still
    // rechecks bytes and current route/schema state independently.
    fn admit_received_frame_with_view(
        &self,
        side: RouterSideId,
        bytes: &[u8],
        view: Option<&wire_format::RoutingFrameInfo<'_>>,
    ) -> TelemetryResult<()> {
        if !crate::memory_admission::has_probe() {
            return Ok(());
        }
        #[cfg(any(feature = "std", feature = "fair-admission"))]
        let mut fair_victim = None;
        if crate::memory_admission::supports_work_kinds()
            && self.cached_transit_ready(side, bytes, view)?
        {
            let result = crate::memory_admission::check_cached_transit(bytes.len());
            #[cfg(all(feature = "compression", feature = "discovery"))]
            let result = {
                let mut result = result;
                while matches!(result, Err(TelemetryError::Io("memory pressure")))
                    && self.state.lock().reclaim_codec_metadata()
                {
                    result = crate::memory_admission::check_cached_transit(bytes.len());
                }
                result
            };

            #[cfg(any(feature = "std", feature = "fair-admission"))]
            let result = {
                let mut result = result;
                while matches!(result, Err(TelemetryError::Io("memory pressure"))) {
                    if !self.reclaim_for_receive(bytes, &mut fair_victim) {
                        break;
                    }
                    result = crate::memory_admission::check_cached_transit(bytes.len());
                }
                result
            };
            result
        } else {
            let managed = wire_format::scheduling_type(bytes)
                .is_some_and(|ty| self.is_managed_variable_type(ty));
            let mut protected = None;
            loop {
                match crate::memory_admission::check_receive_with_role(bytes, managed) {
                    Err(TelemetryError::Io("memory pressure")) => {
                        #[cfg(all(feature = "compression", feature = "discovery"))]
                        if self.state.lock().reclaim_codec_metadata() {
                            continue;
                        }

                        let protected = *protected.get_or_insert_with(|| {
                            wire_format::peek_routing_frame_info(bytes)
                                .ok()
                                .is_some_and(|frame| {
                                    managed
                                        || message_priority(frame.envelope.ty) >= 200
                                        || crate::small_frozen_control(
                                            frame.envelope.ty,
                                            frame.envelope.target_senders().len(),
                                            frame.envelope.wire_shape,
                                        )
                                })
                        });
                        if !protected {
                            #[cfg(any(feature = "std", feature = "fair-admission"))]
                            if self.reclaim_for_receive(bytes, &mut fair_victim) {
                                continue;
                            }
                            return Err(TelemetryError::Io("memory pressure"));
                        }
                        // Queue priority cannot help before the wire copy is
                        // admitted. Reclaim bulk payloads, preserving control
                        // traffic and every learned route/schema.
                        let mut st = self.state.lock();
                        let reclaimed = st
                            .lower_priority_shared_queue(199)
                            .is_some_and(|queue| st.pop_shared_queue_item(queue));
                        if !reclaimed {
                            return Err(TelemetryError::Io("memory pressure"));
                        }
                    }
                    result => return result,
                }
            }
        }
    }

    #[cfg(feature = "discovery")]
    fn consume_known_packed_discovery(
        &self,
        side: RouterSideId,
        bytes: &[u8],
    ) -> TelemetryResult<bool> {
        // Ordinary telemetry pays one bounded type peek, not a parse for each
        // discovery subtype. The selected consumer still checks CRC and shape.
        let result = match wire_format::scheduling_type(bytes) {
            #[cfg(not(feature = "std"))]
            Some(crate::DataType::DiscoverySchema) => self.consume_known_packed_schema(side, bytes),
            Some(crate::DataType::DiscoveryTopology) => {
                self.consume_known_packed_topology(side, bytes)
            }
            Some(crate::DataType::DiscoveryAddress) => {
                match wire_format::peek_plain_discovery_payload(
                    bytes,
                    crate::DataType::DiscoveryAddress,
                ) {
                    Ok(Some((address, payload))) => {
                        self.refresh_peer_liveness(side, address);
                        self.refresh_known_address_payload(payload, side)
                    }
                    Ok(None) => Ok(false),
                    Err(error) => Err(error),
                }
            }
            _ => Ok(false),
        };
        if result.is_err() {
            // Preserve the existing header-level liveness behavior on rejected
            // payloads. A failed CRC still cannot refresh a peer. Valid known
            // discovery avoids this second verification on the normal path.
            let _ = self.refresh_ingress_peer_liveness(side, bytes);
        }
        result
    }

    fn decode_side_transport_frame(
        &self,
        side: RouterSideId,
        bytes: &[u8],
    ) -> TelemetryResult<Option<crate::SharedBytes>> {
        // Reclaim abandoned transfers before admission, even when new work is refused.
        self.expire_side_chunks();
        let Some((kind, body)) = parse_side_transport_wrapper(bytes)? else {
            #[cfg(feature = "discovery")]
            if self.consume_known_packed_discovery(side, bytes)? {
                return Ok(None);
            }
            #[cfg(feature = "discovery")]
            let view = self.refresh_ingress_peer_liveness(side, bytes);
            #[cfg(not(feature = "discovery"))]
            let view = None;
            #[cfg(all(
                feature = "discovery",
                any(feature = "std", feature = "ingress-target-filter")
            ))]
            if bytes.first().is_some_and(|flags| flags & 0x10 == 0)
                && view
                    .as_ref()
                    .is_some_and(|frame| self.targets_only_ingress(side, frame))
            {
                return Ok(None);
            }
            self.admit_received_frame_with_view(side, bytes, view.as_ref())?;
            return Ok(Some(crate::shared_bytes::convert(Arc::<[u8]>::from(bytes))));
        };
        match kind {
            SIDE_TRANSPORT_KIND_FULL => {
                let header_templates_enabled = self
                    .state
                    .lock()
                    .sides
                    .get(side)
                    .and_then(|entry| entry.as_ref())
                    .map(|side| side.opts.header_template_enabled)
                    .unwrap_or(false);
                let mut off = 0usize;
                let template_id = if header_templates_enabled {
                    Some(
                        u32::try_from(read_uleb128_local(body, &mut off)?)
                            .map_err(|_| TelemetryError::Unpack("side template id too large"))?,
                    )
                } else {
                    None
                };
                #[cfg(feature = "discovery")]
                if self.consume_known_packed_discovery(side, &body[off..])? {
                    return Ok(None);
                }
                #[cfg(feature = "discovery")]
                let view = self.refresh_ingress_peer_liveness(side, &body[off..]);
                #[cfg(not(feature = "discovery"))]
                let view = None;
                self.admit_received_frame_with_view(side, &body[off..], view.as_ref())?;
                let raw = Arc::<[u8]>::from(&body[off..]);
                if let (Some(template_id), Ok((template, _, _, _, timestamp, _, _, _))) =
                    (template_id, extract_side_header_template(raw.as_ref()))
                {
                    let mut st = self.state.lock();
                    let max_templates = st
                        .sides
                        .get(side)
                        .and_then(|side| side.as_ref())
                        .map(|side| side.opts.max_side_transport_templates)
                        .unwrap_or(DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT);
                    let evicted = st.side_transport.get_mut(&side).is_some_and(|side_state| {
                        let evicted =
                            side_state.insert_rx_template(template_id, template, max_templates);
                        if max_templates > 0 {
                            side_state.rx_last_timestamps.insert(template_id, timestamp);
                        }
                        evicted
                    });
                    if evicted {
                        st.side_runtime_stats
                            .entry(side)
                            .or_default()
                            .note_side_transport_template_eviction();
                    }
                }
                Ok(Some(crate::shared_bytes::convert(raw)))
            }
            SIDE_TRANSPORT_KIND_COMPACT
            | SIDE_TRANSPORT_KIND_COMPACT_DELTA
            | SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP => {
                if body.is_empty() {
                    return Err(TelemetryError::Unpack("short side compact frame"));
                }
                let mut off = 1usize;
                let template_id = u32::try_from(read_uleb128_local(body, &mut off)?)
                    .map_err(|_| TelemetryError::Unpack("side template id too large"))?;
                let (template, timestamp_base) = {
                    let st = self.state.lock();
                    let state = st.side_transport.get(&side);
                    let template = state
                        .and_then(|state| state.rx_templates_by_id.get(&template_id))
                        .cloned();
                    let timestamp_base = if matches!(
                        kind,
                        SIDE_TRANSPORT_KIND_COMPACT_DELTA
                            | SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP
                    ) {
                        state
                            .and_then(|state| state.rx_last_timestamps.get(&template_id))
                            .copied()
                    } else {
                        None
                    };
                    (template, timestamp_base)
                };
                /* A full template frame can be lost on a datagram/radio side.
                 * Drop this compact frame without tearing down the transport;
                 * the sender periodically emits a full refresh. */
                let Some(template) = template else {
                    return Ok(None);
                };
                // The wrapper CRC and known template identify this peer even
                // if payload allocation is refused. No payload copy is needed.
                #[cfg(feature = "discovery")]
                if let Some(address) = template.source_address() {
                    self.refresh_peer_liveness(side, address);
                }
                let reconstructed_bound = body
                    .len()
                    .saturating_add(template.prefix().len())
                    .saturating_add(template.between().len())
                    .saturating_add(32);
                // Wrapper CRC and the retained full template are validated
                // before compact reconstruction. Preserve the same control
                // priority as canonical ingress while reclaiming only bulk.
                let protected = template.data_type().is_some_and(|ty| {
                    message_priority(ty) >= 200 || self.is_managed_variable_type(ty)
                });
                let ack = template.is_ack();
                #[cfg(any(feature = "std", feature = "fair-admission"))]
                let mut fair_incoming = None;
                #[cfg(any(feature = "std", feature = "fair-admission"))]
                let mut fair_victim = None;
                loop {
                    match crate::memory_admission::check_compact_reconstruction(
                        reconstructed_bound,
                        ack,
                    ) {
                        Err(TelemetryError::Io("memory pressure")) if protected => {
                            let mut st = self.state.lock();
                            let reclaimed = st
                                .lower_priority_shared_queue(199)
                                .is_some_and(|queue| st.pop_shared_queue_item(queue));
                            if !reclaimed {
                                return Err(TelemetryError::Io("memory pressure"));
                            }
                        }
                        Err(TelemetryError::Io("memory pressure")) => {
                            // Compact reports need the same fairness before
                            // allocation as canonical ingress. Otherwise they
                            // never reach the canonical admission/reclaim path.
                            #[cfg(any(feature = "std", feature = "fair-admission"))]
                            if let Some((incoming, priority)) =
                                *fair_incoming.get_or_insert_with(|| {
                                    crate::admission_fairness::compact_incoming(&template)
                                })
                                && self.reclaim_for_incoming(incoming, priority, &mut fair_victim)
                            {
                                continue;
                            }
                            return Err(TelemetryError::Io("memory pressure"));
                        }
                        result => {
                            result?;
                            break;
                        }
                    }
                }
                let timestamp_mode = match kind {
                    SIDE_TRANSPORT_KIND_COMPACT_DELTA => SideCompactTimestampMode::Delta,
                    SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP => SideCompactTimestampMode::Omitted,
                    _ => SideCompactTimestampMode::Absolute,
                };
                let (frame, timestamp) = reconstruct_side_compact_frame(
                    &template,
                    body[0],
                    &body[off..],
                    timestamp_mode,
                    timestamp_base,
                )?;
                {
                    let mut st = self.state.lock();
                    if let Some(side_state) = st.side_transport.get_mut(&side) {
                        side_state.rx_last_timestamps.insert(template_id, timestamp);
                    }
                }
                // Byte reconstruction is not decoder/forwarding admission.
                // Check the canonical frame before queueing, and recheck at
                // dispatch if routes, schemas or available memory have changed.
                if crate::memory_admission::supports_work_kinds() {
                    self.admit_received_frame(side, frame.as_ref())?;
                }
                Ok(Some(frame))
            }
            SIDE_TRANSPORT_KIND_CHUNK => {
                if body.len() < 8 {
                    return Err(TelemetryError::Unpack("short side chunk frame"));
                }
                let transfer_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let index = u16::from_le_bytes([body[4], body[5]]);
                let total = u16::from_le_bytes([body[6], body[7]]);
                if total == 0 || index >= total {
                    return Err(TelemetryError::Unpack("invalid side chunk index"));
                }
                let assembled = {
                    let mut st = self.state.lock();
                    let now_ms = self.clock.now_ms();
                    st.make_side_chunk_room(side, transfer_id, index, total, body.len() - 8)?;
                    // A CRC-validated retry of a retained fragment needs no
                    // allocation. Do not discard other traffic or reject the
                    // retry because unrelated work consumed the idle reserve.
                    if let Some(entry) = st
                        .side_transport
                        .get_mut(&side)
                        .and_then(|state| state.rx_chunks.get_mut(&transfer_id))
                        && entry.contains_index(index)
                    {
                        // Retries are not progress: only new fragments extend
                        // the timeout of a retained, incomplete transfer.
                        return Ok(None);
                    }
                    // Budget only insertion into an existing bounded tree.
                    // The full packet has independent assembly/decode guards.
                    let retained = st
                        .side_transport
                        .get(&side)
                        .and_then(|state| state.rx_chunks.get(&transfer_id))
                        .map(|entry| entry.received_len());
                    loop {
                        match crate::memory_admission::check_retained_fragment(bytes, retained) {
                            Err(TelemetryError::Io("memory pressure")) => {
                                if st
                                    .lower_priority_shared_queue(199)
                                    .is_some_and(|queue| st.pop_shared_queue_item(queue))
                                    || st.reclaim_oldest_side_chunk(Some((side, transfer_id)))
                                {
                                    continue;
                                }
                                return Err(TelemetryError::Io("memory pressure"));
                            }
                            result => {
                                result?;
                                break;
                            }
                        }
                    }
                    let side_state = st
                        .side_transport
                        .get_mut(&side)
                        .ok_or(TelemetryError::BadArg)?;
                    let entry = side_state.rx_chunks.entry(transfer_id).or_default();
                    entry.total = total;
                    let added =
                        entry.insert_with(index, now_ms, || Arc::<[u8]>::from(&body[8..]))?;
                    side_state.rx_chunk_bytes = side_state.rx_chunk_bytes.saturating_add(added);
                    if entry.received_len() == usize::from(total) {
                        let entry = side_state
                            .take_chunk(transfer_id, false)
                            .ok_or(TelemetryError::Unpack("side chunk missing"))?;
                        Some(entry.assemble().inspect_err(|_| {
                            side_state.rx_chunk_reclaims =
                                side_state.rx_chunk_reclaims.saturating_add(1);
                        })?)
                    } else {
                        None
                    }
                };
                match assembled {
                    Some(frame) => self.decode_side_transport_frame(side, frame.as_ref()),
                    None => Ok(None),
                }
            }
            _ => Err(TelemetryError::Unpack("unknown side transport frame")),
        }
    }

    fn packed_handler_call(
        handler: &RouterTxHandlerFn,
        bytes: &[u8],
        priority: u8,
    ) -> TelemetryResult<()> {
        match handler {
            RouterTxHandlerFn::Packed(handler) => handler(bytes),
            RouterTxHandlerFn::PackedWithPriority(handler) => handler(bytes, priority),
            RouterTxHandlerFn::Packet(_) => Err(TelemetryError::BadArg),
        }
    }

    fn effective_transport_priority(&self, ty: DataType) -> u8 {
        if self.is_managed_variable_type(ty) {
            crate::transport_priority(DataType::ManagedVariableValue)
        } else {
            crate::transport_priority(ty)
        }
    }

    fn call_side_tx_handler(
        &self,
        side: RouterSideId,
        handler: &RouterTxHandlerFn,
        data: &RouterItem,
        relayed: bool,
    ) -> TelemetryResult<()> {
        let opts = {
            let st = self.state.lock();
            Self::side_ref(&st, side)?.opts.clone()
        };
        let Some(_side_tx_guard) = self.try_enter_side_tx(side) else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        // Type and priority share one CRC-validated envelope in this call.
        let (ty, priority) = self.item_service_type_priority(data)?;
        #[cfg(all(feature = "discovery", feature = "timesync"))]
        if !Self::timesync_allowed_for_side_locked(
            &self.state.lock(),
            side,
            ty,
            self.clock.now_ms(),
        ) {
            return Ok(());
        }
        let result = match (handler, data) {
            (
                packed @ (RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)),
                RouterItem::Packed(bytes),
            ) => {
                #[cfg(feature = "cryptography")]
                let send_bytes = self.prepare_packed_for_remote(bytes.clone(), None)?;
                #[cfg(not(feature = "cryptography"))]
                let send_bytes = bytes.clone();
                let frames = self.encode_side_transport_frames(side, opts, send_bytes)?;
                let mut attempts_total = 0usize;
                let mut sent_bytes = 0usize;
                self.send_side_frames_resumable(side, frames, |frame| {
                    match self.retry_with_attempts(runtime_max_handler_retries(), || {
                        Self::packed_handler_call(packed, frame, priority)
                    }) {
                        Ok((_, attempts)) => {
                            attempts_total = attempts_total.saturating_add(attempts);
                            sent_bytes = sent_bytes.saturating_add(frame.len());
                        }
                        Err((err, attempts)) => {
                            self.note_side_tx_failure(
                                side,
                                ty,
                                attempts_total.saturating_add(attempts),
                            );
                            return Err(err);
                        }
                    }

                    Ok(())
                })?;
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                return Ok(());
            }
            (RouterTxHandlerFn::Packet(f), RouterItem::Packet(pkt)) => {
                self.retry_with_attempts(runtime_max_handler_retries(), || f(pkt))
            }
            (
                packed @ (RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)),
                RouterItem::Packet(pkt),
            ) => {
                // Internal schemas are plaintext and use self-describing frames.
                // This path is reached after hop-reliable handling; no replay
                // buffer is needed here. Stream fragments from the payload.
                if ty == DataType::DiscoverySchema
                    && opts.max_frame_bytes != 0
                    && pkt.payload().len() > opts.max_frame_bytes
                {
                    let mut attempts_total = 0usize;
                    let mut sent_bytes = 0usize;
                    let key = crate::packet::hash_bytes_u64(
                        pkt.packet_id(),
                        &opts.max_frame_bytes.to_le_bytes(),
                    );
                    let result = self.run_side_chunk_transfer(side, key, |next| {
                        crate::side_transport::send_packet_chunks(
                            pkt,
                            opts.max_frame_bytes,
                            self.sender_arc().as_bytes(),
                            next,
                            |frame| match self
                                .retry_with_attempts(runtime_max_handler_retries(), || {
                                    Self::packed_handler_call(packed, frame, priority)
                                }) {
                                Ok((_, attempts)) => {
                                    attempts_total += attempts;
                                    sent_bytes += frame.len();
                                    Ok(())
                                }
                                Err((err, attempts)) => {
                                    attempts_total += attempts;
                                    Err(err)
                                }
                            },
                        )
                    });
                    let (raw_len, wire_len, chunks) = match result {
                        Ok(stats) => stats,
                        Err(err) => {
                            self.note_side_tx_failure(side, ty, attempts_total);
                            return Err(err);
                        }
                    };
                    {
                        let mut st = self.state.lock();
                        let stats = st.side_runtime_stats.entry(side).or_default();
                        stats.note_side_transport_full(raw_len, wire_len);
                        if chunks > 1 {
                            stats.note_side_transport_chunks(chunks);
                        }
                    }
                    self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                    self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                    return Ok(());
                }
                let owned = self.pack_packet_for_router(pkt, None)?;
                let frames = self.encode_side_transport_frames(side, opts, owned)?;
                let mut attempts_total = 0usize;
                let mut sent_bytes = 0usize;
                self.send_side_frames_resumable(side, frames, |frame| {
                    match self.retry_with_attempts(runtime_max_handler_retries(), || {
                        Self::packed_handler_call(packed, frame, priority)
                    }) {
                        Ok((_, attempts)) => {
                            attempts_total = attempts_total.saturating_add(attempts);
                            sent_bytes = sent_bytes.saturating_add(frame.len());
                        }
                        Err((err, attempts)) => {
                            self.note_side_tx_failure(
                                side,
                                ty,
                                attempts_total.saturating_add(attempts),
                            );
                            return Err(err);
                        }
                    }

                    Ok(())
                })?;
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, relayed, attempts_total);
                return Ok(());
            }
            (RouterTxHandlerFn::Packet(f), RouterItem::Packed(bytes)) => {
                let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                self.retry_with_attempts(runtime_max_handler_retries(), || f(&pkt))
            }
        };
        match result {
            Ok((_, attempts)) => {
                if let Ok(bytes) = Self::router_item_wire_len(data) {
                    self.record_side_tx_sample(side, bytes, started_ms, self.clock.now_ms());
                    self.note_side_tx_success(side, ty, bytes, relayed, attempts);
                }
                Ok(())
            }
            Err((err, attempts)) => {
                self.note_side_tx_failure(side, ty, attempts);
                Err(err)
            }
        }
    }

    fn adjust_reliable_for_side(
        &self,
        opts: RouterSideOptions,
        data: RouterItem,
        preserve_end_to_end_ack: bool,
    ) -> TelemetryResult<Option<RouterItem>> {
        if opts.reliable_enabled {
            return Ok(Some(data));
        }

        match data {
            RouterItem::Packed(bytes) => {
                let frame = wire_format::peek_routing_frame_info(bytes.as_ref())?;
                if is_reliable_type(frame.envelope.ty)
                    && let Some(hdr) = frame.reliable
                {
                    if (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) != 0 {
                        return Ok(None);
                    }
                    if (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) == 0 {
                        let Some(rewritten) = wire_format::rewrite_reliable_header_owned(
                            bytes.as_ref(),
                            wire_format::RELIABLE_FLAG_UNSEQUENCED,
                            hdr.seq,
                            0,
                        )?
                        else {
                            return Ok(Some(RouterItem::Packed(bytes)));
                        };
                        return Ok(Some(RouterItem::Packed(crate::shared_bytes::convert(
                            rewritten,
                        ))));
                    }
                }
                Ok(Some(RouterItem::Packed(bytes)))
            }
            RouterItem::Packet(pkt) => {
                if matches!(
                    pkt.data_type(),
                    DataType::ReliableAck
                        | DataType::ReliablePartialAck
                        | DataType::ReliablePacketRequest
                ) {
                    if preserve_end_to_end_ack && Self::is_end_to_end_ack_packet(&pkt) {
                        return Ok(Some(RouterItem::Packet(pkt)));
                    }
                    return Ok(None);
                }
                Ok(Some(RouterItem::Packet(pkt)))
            }
        }
    }

    fn process_reliable_timeouts(&self) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let mut requeue: Vec<(RouterSideId, DataType, u32)> = Vec::new();

        {
            let mut st = self.state.lock();
            if st.reliable_tx.is_empty() {
                return Ok(());
            }

            for ((side, ty_u32), tx_state) in st.reliable_tx.iter_mut() {
                let Some(ty) = DataType::try_from_u32(*ty_u32) else {
                    continue;
                };
                let sent_order: Vec<u32> = tx_state.sent_order.iter().copied().collect();
                for seq in sent_order {
                    let Some(sent) = tx_state.sent.get_mut(&seq) else {
                        continue;
                    };
                    if sent.queued
                        || now.wrapping_sub(sent.last_send_ms) < runtime_reliable_retransmit_ms()
                    {
                        continue;
                    }
                    if sent.partial_acked {
                        // A partial ACK normally arrives with a request for
                        // the missing sequence. If that request is itself
                        // lost, retaining this flag forever pins the history
                        // entry and eventually rejects unrelated traffic with
                        // `reliable history full`. Give the request one retry
                        // interval, then resume normal bounded retransmission.
                        sent.partial_acked = false;
                        sent.last_send_ms = now;
                        continue;
                    }
                    if sent.retries >= runtime_reliable_max_retries() {
                        tx_state.sent.remove(&seq);
                        tx_state.sent_order.retain(|existing| *existing != seq);
                        continue;
                    }
                    sent.retries += 1;
                    requeue.push((*side, ty, seq));
                }
            }
        }

        for (side, ty, seq) in requeue {
            self.queue_reliable_retransmit(side, ty, seq, true)?;
        }

        Ok(())
    }

    fn process_end_to_end_reliable_timeouts(&self) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let mut requeue = Vec::new();
        let mut failed_ordered_types = BTreeSet::new();

        {
            let mut st = self.state.lock();
            #[cfg(feature = "discovery")]
            {
                if Self::prune_discovery_routes_locked(&mut st, now) {
                    Self::note_discovery_topology_change_locked(&mut st, now);
                    self.reconcile_end_to_end_reliable_destinations_locked(&mut st)?;
                }
                // Route updates reconcile their retained deliveries when the
                // topology changes. Rebuilding the destination map on every
                // queue item adds allocation and graph scans without changing
                // the frozen receipt contract.
            }
            // Retain walks the bounded pending map in place. A queue pass
            // before any retry deadline must not allocate a list of keys.
            st.end_to_end_reliable_tx.retain(|&packet_id, sent| {
                if sent.waiting_for_predecessor
                    || sent.queued
                    || now.wrapping_sub(sent.last_send_ms) < runtime_reliable_retransmit_ms()
                {
                    return true;
                }
                if sent.retries >= runtime_reliable_max_retries() {
                    if let Some(ty) = sent.ordered_type {
                        failed_ordered_types.insert(ty);
                    }
                    return false;
                }
                sent.retries += 1;
                requeue.push(packet_id);
                true
            });
            // Fail the queued tail too; never deliver it past an unconfirmed gap.
            st.end_to_end_reliable_tx.retain(|_, sent| {
                !sent
                    .ordered_type
                    .is_some_and(|ty| failed_ordered_types.contains(&ty))
            });
        }

        for packet_id in requeue {
            self.queue_end_to_end_reliable_retransmit(packet_id)?;
        }
        self.release_ordered_successors()?;
        if !failed_ordered_types.is_empty() {
            return Err(TelemetryError::HandlerError(
                "ordered end-to-end delivery exhausted retries",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "timesync")]
    #[inline]
    fn monotonic_now_ns(&self) -> u64 {
        self.clock.now_ns()
    }

    #[cfg(feature = "timesync")]
    #[inline]
    fn monotonic_now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    #[cfg(feature = "timesync")]
    fn refresh_timesync_state(&self, now_mono_ms: u64) {
        let now_mono_ns = self.monotonic_now_ns();
        let mut st = self.timesync.lock();
        st.clock.prune_expired(now_mono_ms);
        let timeout_ms = st.cfg.map(|cfg| cfg.source_timeout_ms).unwrap_or(0);
        st.remote_sources
            .retain(|_, src| now_mono_ms.saturating_sub(src.last_sample_mono_ms) <= timeout_ms);
        let has_usable_time = Self::timesync_has_usable_time_locked(&st, now_mono_ns);
        let leader = if let Some(tracker) = st.tracker.as_mut() {
            let _ = tracker.refresh(now_mono_ms);
            tracker.leader(now_mono_ms, has_usable_time)
        } else {
            None
        };
        Self::reconcile_pending_timesync_request_locked(&mut st, &leader, now_mono_ms);
        if let Some(TimeSyncLeader::Remote(remote)) = leader.as_ref() {
            let target_ms = st
                .remote_sources
                .get(remote.sender.as_str())
                .map(|src| src.sample_unix_ms);
            if let Some(target_ms) = target_ms {
                st.disciplined_clock.steer_unix_ms(now_mono_ns, target_ms);
            }
        }
    }

    #[cfg(feature = "timesync")]
    /// Inserts or updates a named network-time source with an optional expiration TTL.
    pub fn update_network_time_source(
        &self,
        source: &str,
        priority: u64,
        time: PartialNetworkTime,
        ttl_ms: Option<u64>,
    ) {
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        let mut st = self.timesync.lock();
        st.clock
            .update_source(source, priority, time, now_ms, now_ns, ttl_ms);
        if let Some(unix_ms) = time.to_network_time().and_then(|t| t.as_unix_ms()) {
            st.disciplined_clock.steer_unix_ms(now_ns, unix_ms);
        }
    }

    #[cfg(feature = "timesync")]
    fn set_network_time_source_impl(
        &self,
        source: &str,
        priority: u64,
        time: PartialNetworkTime,
        ttl_ms: Option<u64>,
    ) {
        let observed_mono_ms = self.monotonic_now_ms();
        let observed_mono_ns = self.monotonic_now_ns();
        let mut st = self.timesync.lock();
        let commit_mono_ms = self.monotonic_now_ms();
        let commit_mono_ns = self.monotonic_now_ns();
        let adjusted = if let Some(base) = time.to_network_time() {
            let elapsed_ns = commit_mono_ns.saturating_sub(observed_mono_ns);
            advance_network_time(base, elapsed_ns)
                .map(PartialNetworkTime::from)
                .unwrap_or(time)
        } else {
            time
        };
        let adjusted_mono_ms =
            observed_mono_ms.saturating_add(commit_mono_ms.saturating_sub(observed_mono_ms));
        st.clock.update_source(
            source,
            priority,
            adjusted,
            commit_mono_ms.max(adjusted_mono_ms),
            commit_mono_ns,
            ttl_ms,
        );
        if let Some(unix_ms) = adjusted.to_network_time().and_then(|t| t.as_unix_ms()) {
            st.disciplined_clock.steer_unix_ms(commit_mono_ns, unix_ms);
        }
    }

    #[cfg(feature = "timesync")]
    fn local_network_time_priority(&self) -> u64 {
        let st = self.timesync.lock();
        st.cfg.map(|cfg| cfg.priority).unwrap_or(0)
    }

    #[cfg(feature = "timesync")]
    /// Sets the local node's network time using any combination of date, time, and sub-second fields.
    pub fn set_local_network_time(&self, time: PartialNetworkTime) {
        let priority = self.local_network_time_priority();
        if time.is_complete_date() && time.is_complete_time() {
            self.set_network_time_source_impl(LOCAL_TIMESYNC_FULL_SOURCE_ID, priority, time, None);
            let mut st = self.timesync.lock();
            st.clock.remove_source(LOCAL_TIMESYNC_DATE_SOURCE_ID);
            st.clock.remove_source(LOCAL_TIMESYNC_TOD_SOURCE_ID);
            st.clock.remove_source(LOCAL_TIMESYNC_SUBSEC_SOURCE_ID);
            return;
        }

        {
            let mut st = self.timesync.lock();
            st.clock.remove_source(LOCAL_TIMESYNC_FULL_SOURCE_ID);
        }

        if time.year.is_some() || time.month.is_some() || time.day.is_some() {
            self.set_network_time_source_impl(
                LOCAL_TIMESYNC_DATE_SOURCE_ID,
                priority,
                PartialNetworkTime {
                    year: time.year,
                    month: time.month,
                    day: time.day,
                    ..Default::default()
                },
                None,
            );
        }

        if time.hour.is_some() || time.minute.is_some() || time.second.is_some() {
            self.set_network_time_source_impl(
                LOCAL_TIMESYNC_TOD_SOURCE_ID,
                priority,
                PartialNetworkTime {
                    hour: time.hour,
                    minute: time.minute,
                    second: time.second,
                    nanosecond: time.nanosecond,
                    ..Default::default()
                },
                None,
            );
        }

        if time.nanosecond.is_some() {
            self.set_network_time_source_impl(
                LOCAL_TIMESYNC_SUBSEC_SOURCE_ID,
                priority,
                PartialNetworkTime {
                    nanosecond: time.nanosecond,
                    ..Default::default()
                },
                None,
            );
        }
    }

    #[cfg(feature = "timesync")]
    /// Removes all locally supplied network-time fragments from the assembled clock.
    pub fn clear_local_network_time(&self) {
        let mut st = self.timesync.lock();
        st.clock.remove_source(LOCAL_TIMESYNC_FULL_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_DATE_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_TOD_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_SUBSEC_SOURCE_ID);
    }

    #[cfg(feature = "timesync")]
    /// Sets only the local calendar date portion of network time.
    pub fn set_local_network_date(&self, year: i32, month: u8, day: u8) {
        self.set_local_network_time(PartialNetworkTime {
            year: Some(year),
            month: Some(month),
            day: Some(day),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    /// Sets the local time of day to hour and minute precision.
    pub fn set_local_network_time_hm(&self, hour: u8, minute: u8) {
        self.set_local_network_time(PartialNetworkTime {
            hour: Some(hour),
            minute: Some(minute),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    /// Sets the local time of day to second precision.
    pub fn set_local_network_time_hms(&self, hour: u8, minute: u8, second: u8) {
        self.set_local_network_time(PartialNetworkTime {
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    /// Sets the local time of day with millisecond precision.
    pub fn set_local_network_time_hms_millis(
        &self,
        hour: u8,
        minute: u8,
        second: u8,
        millisecond: u16,
    ) {
        self.set_local_network_time(PartialNetworkTime {
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            nanosecond: Some((millisecond as u32).saturating_mul(1_000_000)),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    /// Sets the local time of day with nanosecond precision.
    pub fn set_local_network_time_hms_nanos(
        &self,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) {
        self.set_local_network_time(PartialNetworkTime {
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            nanosecond: Some(nanosecond),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    /// Sets a complete local date and time with second precision.
    pub fn set_local_network_datetime(
        &self,
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) {
        self.set_local_network_time(PartialNetworkTime {
            year: Some(year),
            month: Some(month),
            day: Some(day),
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            ..Default::default()
        });
    }

    #[cfg(feature = "timesync")]
    #[allow(clippy::too_many_arguments)]
    /// Sets a complete local date and time with millisecond precision.
    pub fn set_local_network_datetime_millis(
        &self,
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        millisecond: u16,
    ) {
        self.set_local_network_time(PartialNetworkTime {
            year: Some(year),
            month: Some(month),
            day: Some(day),
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            nanosecond: Some((millisecond as u32).saturating_mul(1_000_000)),
        });
    }

    #[cfg(feature = "timesync")]
    #[allow(clippy::too_many_arguments)]
    /// Sets a complete local date and time with nanosecond precision.
    pub fn set_local_network_datetime_nanos(
        &self,
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) {
        self.set_local_network_time(PartialNetworkTime {
            year: Some(year),
            month: Some(month),
            day: Some(day),
            hour: Some(hour),
            minute: Some(minute),
            second: Some(second),
            nanosecond: Some(nanosecond),
        });
    }

    #[cfg(feature = "timesync")]
    /// Removes a previously registered named network-time source.
    pub fn clear_network_time_source(&self, source: &str) {
        let mut st = self.timesync.lock();
        st.clock.remove_source(source);
    }

    #[cfg(feature = "timesync")]
    /// Replaces the active time sync configuration and resets runtime state derived from it.
    pub fn set_timesync_config(&self, cfg: Option<TimeSyncConfig>) {
        let mut st = self.timesync.lock();
        let stale_remote_sources: Vec<String> = st.remote_sources.keys().cloned().collect();
        st.cfg = cfg;
        st.tracker = cfg.map(TimeSyncTracker::new);
        st.disciplined_clock = SlewedNetworkClock::new(
            cfg.map(|c| c.max_slew_ppm)
                .unwrap_or(TimeSyncConfig::default().max_slew_ppm),
        );
        st.remote_sources.clear();
        st.next_seq = 1;
        st.next_announce_mono_ms = 0;
        st.next_request_mono_ms = 0;
        st.pending_request = None;
        st.clock.remove_source(INTERNAL_TIMESYNC_SOURCE_ID);
        for source in stale_remote_sources {
            st.clock.remove_source(&source);
        }
        st.clock.remove_source(LOCAL_TIMESYNC_FULL_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_DATE_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_TOD_SOURCE_ID);
        st.clock.remove_source(LOCAL_TIMESYNC_SUBSEC_SOURCE_ID);
    }

    #[cfg(feature = "timesync")]
    /// Returns the best currently known network-time reading, if any.
    pub fn network_time(&self) -> Option<NetworkTimeReading> {
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        self.refresh_timesync_state(now_ms);
        let st = self.timesync.lock();
        if let Some(unix_ms) = st.disciplined_clock.read_unix_ms(now_ns) {
            return Some(NetworkTimeReading {
                time: PartialNetworkTime::from_unix_ms(unix_ms),
                unix_time_ms: Some(unix_ms),
            });
        }
        st.clock.current_time(now_ns)
    }

    #[cfg(feature = "timesync")]
    /// Returns the current network time as Unix milliseconds when available.
    pub fn network_time_ms(&self) -> Option<u64> {
        self.network_time().and_then(|t| t.unix_time_ms)
    }

    #[cfg(feature = "timesync")]
    fn packet_timestamp_ms(&self) -> u64 {
        self.network_time_ms()
            .unwrap_or_else(|| self.monotonic_now_ms())
    }

    #[cfg(not(feature = "timesync"))]
    fn packet_timestamp_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    #[cfg(feature = "timesync")]
    fn queue_internal_timesync_request(
        &self,
        seq: u64,
        t1_mono_ms: u64,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let pkt_ts = self.packet_timestamp_ms();
        if called_from_queue {
            self.log_queue_ts(DataType::TimeSyncRequest, pkt_ts, &[seq, t1_mono_ms])
        } else {
            self.log_ts(DataType::TimeSyncRequest, pkt_ts, &[seq, t1_mono_ms])
        }
    }

    #[cfg(feature = "timesync")]
    fn queue_internal_timesync_response(
        &self,
        seq: u64,
        t1_mono_ms: u64,
        t2_network_ms: u64,
        t3_network_ms: u64,
        dst: Option<RouterSideId>,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let pkt_ts = self.packet_timestamp_ms();
        let payload = encode_slice_le(&[seq, t1_mono_ms, t2_network_ms, t3_network_ms]);
        let sender = self.sender_arc();
        let pkt = Packet::new(
            DataType::TimeSyncResponse,
            &[DataEndpoint::TimeSync],
            sender.as_ref(),
            pkt_ts,
            payload,
        )?;
        match dst {
            Some(dst) => self.emit_internal_tx(
                RouterTxItem::ToSide {
                    src: None,
                    dst,
                    data: RouterItem::Packet(pkt),
                },
                true,
                called_from_queue,
            ),
            None => self.emit_internal_tx(
                RouterTxItem::Broadcast(RouterItem::Packet(pkt)),
                true,
                called_from_queue,
            ),
        }
    }

    #[cfg(feature = "timesync")]
    /// Runs one time sync maintenance cycle and queues any required announce or request packets.
    pub fn poll_timesync(&self) -> TelemetryResult<bool> {
        let now_ms = self.monotonic_now_ms();
        let now_ns = self.monotonic_now_ns();
        let mut queued_any = false;
        let mut announce_priority = None;
        let mut request = None;

        {
            let mut st = self.timesync.lock();
            st.clock.prune_expired(now_ms);
            let timeout_ms = st.cfg.map(|cfg| cfg.source_timeout_ms).unwrap_or(0);
            st.remote_sources
                .retain(|_, src| now_ms.saturating_sub(src.last_sample_mono_ms) <= timeout_ms);
            let Some(cfg) = st.cfg else {
                return Ok(false);
            };

            let has_usable_time = Self::timesync_has_usable_time_locked(&st, now_ns);
            let (leader, announce_prio) = if let Some(tracker) = st.tracker.as_mut() {
                let _ = tracker.refresh(now_ms);
                (
                    tracker.leader(now_ms, has_usable_time),
                    tracker.local_announce_priority(now_ms, has_usable_time),
                )
            } else {
                (None, None)
            };
            Self::reconcile_pending_timesync_request_locked(&mut st, &leader, now_ms);

            if let Some(TimeSyncLeader::Remote(remote)) = leader.as_ref() {
                let target_ms = st
                    .remote_sources
                    .get(&remote.sender)
                    .map(|src| src.sample_unix_ms);
                if let Some(target_ms) = target_ms {
                    st.disciplined_clock.steer_unix_ms(now_ns, target_ms);
                }
            }

            if let Some(priority) = announce_prio
                && now_ms >= st.next_announce_mono_ms
            {
                announce_priority = Some(priority);
                st.next_announce_mono_ms = now_ms.saturating_add(cfg.announce_interval_ms);
            }

            if let Some(TimeSyncLeader::Remote(remote)) = leader
                && now_ms >= st.next_request_mono_ms
                && st.pending_request.is_none()
            {
                let seq = st.next_seq;
                let next = st.next_seq.wrapping_add(1);
                st.next_seq = if next == 0 { 1 } else { next };
                st.next_request_mono_ms = now_ms.saturating_add(cfg.request_interval_ms);
                st.pending_request = Some(PendingTimeSyncRequest {
                    seq,
                    t1_mono_ms: now_ms,
                    source: remote.sender,
                });
                request = Some((seq, now_ms));
            }
        }

        if let Some(priority) = announce_priority {
            let time_ms = self.packet_timestamp_ms();
            self.log_queue_ts(DataType::TimeSyncAnnounce, time_ms, &[priority, time_ms])?;
            queued_any = true;
        }
        if let Some((seq, t1_mono_ms)) = request {
            self.queue_internal_timesync_request(seq, t1_mono_ms, true)?;
            queued_any = true;
        }

        Ok(queued_any)
    }

    #[cfg(feature = "timesync")]
    fn handle_internal_timesync_packet(
        &self,
        pkt: &Packet,
        src: Option<RouterSideId>,
        called_from_queue: bool,
    ) -> TelemetryResult<bool> {
        let Some(cfg) = self.cfg.timesync_config() else {
            if self.should_route_remote(&RouterItem::Packet(pkt.clone()), src)? {
                self.relay_send(RouterItem::Packet(pkt.clone()), src, called_from_queue)?;
            }
            return Ok(true);
        };

        let now_mono_ms = self.monotonic_now_ms();
        let now_mono_ns = self.monotonic_now_ns();
        let mut response = None;
        let mut poll_after = false;

        {
            let mut st = self.timesync.lock();
            st.clock.prune_expired(now_mono_ms);
            let timeout_ms = st.cfg.map(|cfg| cfg.source_timeout_ms).unwrap_or(0);
            st.remote_sources
                .retain(|_, src| now_mono_ms.saturating_sub(src.last_sample_mono_ms) <= timeout_ms);
            let has_usable_time = Self::timesync_has_usable_time_locked(&st, now_mono_ns);
            if st.tracker.is_none() {
                return Ok(true);
            }

            match pkt.data_type() {
                DataType::TimeSyncAnnounce => {
                    let ann = decode_timesync_announce(pkt)?;
                    let should_steer = {
                        let tracker = st.tracker.as_mut().expect("tracker checked above");
                        let _ = tracker.handle_announce(pkt, now_mono_ms)?;
                        matches!(
                            tracker.leader(now_mono_ms, has_usable_time),
                            Some(TimeSyncLeader::Remote(ref remote)) if remote.sender == pkt.sender()
                        )
                    };
                    st.remote_sources.insert(
                        pkt.sender().to_owned(),
                        RemoteTimeSyncSource {
                            priority: ann.priority,
                            last_sample_mono_ms: now_mono_ms,
                            sample_unix_ms: ann.time_ms,
                        },
                    );
                    st.clock.update_source(
                        pkt.sender(),
                        ann.priority,
                        PartialNetworkTime::from_unix_ms(ann.time_ms),
                        now_mono_ms,
                        now_mono_ns,
                        Some(cfg.source_timeout_ms),
                    );
                    if should_steer {
                        st.disciplined_clock.steer_unix_ms(now_mono_ns, ann.time_ms);
                    }
                    poll_after = true;
                }
                DataType::TimeSyncRequest => {
                    let should_serve = {
                        let tracker = st.tracker.as_ref().expect("tracker checked above");
                        tracker.should_serve(now_mono_ms, has_usable_time)
                    };
                    if should_serve {
                        let req = decode_timesync_request(pkt)?;
                        let network_now = st
                            .disciplined_clock
                            .read_unix_ms(now_mono_ns)
                            .or_else(|| {
                                st.clock
                                    .current_time(now_mono_ns)
                                    .and_then(|t| t.unix_time_ms)
                            })
                            .unwrap_or(now_mono_ms);
                        let t2 = network_now;
                        let t3 = network_now;
                        response = Some((req.seq, req.t1_ms, t2, t3, src));
                    }
                }
                DataType::TimeSyncResponse => {
                    let resp = decode_timesync_response(pkt)?;
                    let pending = st.pending_request.clone();
                    if let Some(pending) = pending
                        && pending.seq == resp.seq
                        && pending.source == pkt.sender()
                    {
                        let source_priority = {
                            let tracker = st.tracker.as_ref().expect("tracker checked above");
                            tracker
                                .best_active_source(now_mono_ms)
                                .map(|s| s.priority)
                                .or_else(|| st.remote_sources.get(pkt.sender()).map(|s| s.priority))
                                .unwrap_or(cfg.priority)
                        };
                        let (estimate_ms, _delay_ms) = compute_network_time_sample(
                            pending.t1_mono_ms,
                            resp.t2_ms,
                            resp.t3_ms,
                            now_mono_ms,
                        );
                        st.remote_sources.insert(
                            pkt.sender().to_owned(),
                            RemoteTimeSyncSource {
                                priority: source_priority,
                                last_sample_mono_ms: now_mono_ms,
                                sample_unix_ms: estimate_ms,
                            },
                        );
                        st.clock.update_source(
                            pkt.sender(),
                            source_priority,
                            PartialNetworkTime::from_unix_ms(estimate_ms),
                            now_mono_ms,
                            now_mono_ns,
                            Some(cfg.source_timeout_ms),
                        );
                        st.disciplined_clock.steer_unix_ms(now_mono_ns, estimate_ms);
                        st.pending_request = None;
                    }
                }
                _ => {}
            }
        }

        if let Some((seq, t1, t2, t3, dst)) = response {
            self.queue_internal_timesync_response(seq, t1, t2, t3, dst, called_from_queue)?;
        }
        if poll_after {
            let _ = crate::memory_admission::allow_drain(self.poll_timesync())?;
        }

        if self.should_route_remote(&RouterItem::Packet(pkt.clone()), src)? {
            self.relay_send(RouterItem::Packet(pkt.clone()), src, called_from_queue)?;
        }

        Ok(true)
    }

    /// Create a new Router with an internal monotonic clock.
    #[cfg(feature = "std")]
    pub fn new(cfg: RouterConfig) -> Self {
        Self::new_with_clock(cfg, Box::new(StdMonotonicClock::default()))
    }

    /// Create a new Router with the specified router configuration and clock.
    pub fn new_with_clock(cfg: RouterConfig, clock: Box<dyn Clock + Send + Sync>) -> Self {
        #[cfg(feature = "timesync")]
        let timesync_cfg = cfg.timesync_config();
        #[cfg(feature = "discovery")]
        let preferred_discovery_master = cfg.preferred_discovery_master.clone();
        let memory = cfg.memory_config();
        let hostname: Arc<str> = Arc::from(cfg.sender());
        let address_mode = cfg.address_mode();
        let instance_seq = u64::from(ROUTER_INSTANCE_SEQ.fetch_add(1, Ordering::Relaxed));
        let owner_hash = Self::sender_hash(hostname.as_ref()) ^ instance_seq;
        let fallback = Self::fallback_address_for_hostname(hostname.as_ref());
        let requested = address_mode.requested_address();
        let address = if requested == 0 { fallback } else { requested };
        let local_address = AddressBookEntry {
            hostname: hostname.clone(),
            address,
            requested_address: requested,
            mode: address_mode,
            birth_ms: clock
                .now_ms()
                .saturating_mul(1_000_000)
                .saturating_add(instance_seq),
            owner_hash,
            last_seen_ms: clock.now_ms(),
        };
        let mut address_book = BTreeMap::new();
        address_book.insert(hostname.to_string(), local_address.clone());
        let mut address_by_value = BTreeMap::new();
        address_by_value.insert(address, hostname.to_string());
        Self {
            sender: RouterMutex::new(hostname),
            cfg,
            state: RouterMutex::new(RouterInner {
                #[cfg(feature = "compression")]
                codec_reserved_bytes: 0,
                memory,
                sides: Vec::new(),
                route_overrides: Default::default(),
                typed_route_overrides: Default::default(),
                route_weights: Default::default(),
                route_priorities: Default::default(),
                source_route_modes: Default::default(),
                route_selection_cursors: Default::default(),
                adaptive_route_stats: Default::default(),
                side_runtime_stats: Default::default(),
                side_transport: Default::default(),
                managed_variable_types: BTreeSet::new(),
                managed_variable_permissions: Default::default(),
                managed_variable_latest: Default::default(),
                network_variable_update_handlers: Default::default(),
                local_address,
                address_book,
                address_by_value,
                p2p_port_handlers: Default::default(),
                p2p_stream_handlers: Default::default(),
                p2p_stream_sessions: Default::default(),
                next_p2p_stream_id: 1,
                received_queue: BoundedDeque::new(
                    memory.max_queue_budget,
                    memory.starting_queue_size,
                    memory.queue_grow_step,
                ),
                transmit_queue: BoundedDeque::new(
                    memory.max_queue_budget,
                    memory.starting_queue_size,
                    memory.queue_grow_step,
                ),
                tx_priority_burst: 0,
                has_ordered_retry: false,
                ordered_claim_seq: 0,
                rx_priority_burst: 0,
                recent_rx: BoundedDeque::new(
                    memory.recent_rx_queue_bytes(),
                    memory.recent_rx_queue_bytes(),
                    memory.queue_grow_step,
                ),
                reliable_tx: Default::default(),
                reliable_rx: Default::default(),
                reliable_return_routes: Default::default(),
                reliable_return_route_order: VecDeque::new(),
                end_to_end_reliable_tx: Default::default(),
                end_to_end_reliable_tx_order: VecDeque::new(),
                total_handler_failures: 0,
                total_handler_retries: 0,
                #[cfg(feature = "discovery")]
                discovery_routes: Default::default(),
                #[cfg(feature = "discovery")]
                discovery_cadence: DiscoveryCadenceState::default(),
                #[cfg(feature = "discovery")]
                discovery_side_throttle: Default::default(),
                #[cfg(feature = "discovery")]
                preferred_discovery_master,
                #[cfg(all(feature = "discovery", feature = "timesync"))]
                timesync_side_throttle: Default::default(),
            }),
            isr_rx_queue: IsrRxQueue::new(
                memory.max_queue_budget,
                memory.starting_queue_size,
                memory.queue_grow_step,
            ),
            #[cfg(not(feature = "std"))]
            side_tx_gate: ReentryGate::new(),
            #[cfg(feature = "std")]
            side_tx_activity: crate::lock::SideTxActivity::default(),
            clock,
            #[cfg(feature = "timesync")]
            timesync: RouterMutex::new(TimeSyncRuntime::new(timesync_cfg)),
        }
    }

    #[inline]
    fn sender_arc(&self) -> Arc<str> {
        self.sender.lock().clone()
    }

    #[inline]
    pub fn sender(&self) -> Arc<str> {
        self.sender_arc()
    }

    pub fn current_address(&self) -> NodeAddress {
        self.state.lock().local_address.address
    }

    pub fn hostname(&self) -> Arc<str> {
        self.sender_arc()
    }

    /// Change the preferred discovery master at runtime.
    ///
    /// Passing `None` or an empty hostname restores topology-based election.
    /// This does not alter time-sync leadership or source priority.
    pub fn set_preferred_discovery_master(&self, hostname: Option<&str>) {
        #[cfg(feature = "discovery")]
        {
            let preferred = hostname
                .filter(|value| !value.is_empty())
                .map(Arc::<str>::from);
            let mut st = self.state.lock();
            if st.preferred_discovery_master != preferred {
                st.preferred_discovery_master = preferred;
                Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
            }
        }
        #[cfg(not(feature = "discovery"))]
        let _ = hostname;
    }

    /// Return the currently configured preferred discovery master.
    pub fn preferred_discovery_master(&self) -> Option<Arc<str>> {
        #[cfg(feature = "discovery")]
        {
            return self.state.lock().preferred_discovery_master.clone();
        }
        #[cfg(not(feature = "discovery"))]
        None
    }

    pub fn address_book(&self) -> Vec<AddressBookEntry> {
        self.state.lock().address_book.values().cloned().collect()
    }

    pub fn resolve_hostname(&self, hostname: &str) -> Option<AddressBookEntry> {
        let now_ms = self.clock.now_ms();
        #[allow(unused_mut)]
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        if Self::prune_discovery_routes_locked(&mut st, now_ms) {
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        if let Some(entry) = st.address_book.get(hostname) {
            return Some(entry.clone());
        }
        // Address advertisements are link-local, but topology names cross
        // routers. Mirror resolve_address's topology-only identity support so
        // named P2P messages/OTA streams can reach those downstream devices.
        // Never invent a target merely because an application requested it;
        // the retained topology must resolve its compact identity uniquely.
        let address = sender_address_u32(hostname);
        if Self::hostname_for_address_locked(&st, address).as_deref() != Some(hostname) {
            return None;
        }
        Some(AddressBookEntry {
            hostname: Arc::from(hostname),
            address,
            requested_address: 0,
            mode: AddressAssignmentMode::Dynamic,
            birth_ms: 0,
            owner_hash: Self::sender_hash(hostname),
            last_seen_ms: now_ms,
        })
    }

    pub fn resolve_address(&self, address: NodeAddress) -> Option<AddressBookEntry> {
        let st = self.state.lock();
        let direct = st
            .address_by_value
            .get(&address)
            .and_then(|hostname| st.address_book.get(hostname))
            .cloned();
        if direct.is_some() {
            return direct;
        }

        let hostname = Self::hostname_for_address_locked(&st, address)?;
        if let Some(entry) = st.address_book.get(&hostname) {
            return Some(entry.clone());
        }

        // A topology-only remote has no DHCP-style address record on this
        // link. Return a compact-address identity entry; callers that need to
        // route to it still use discovery, while telemetry consumers can use
        // the stable hostname immediately.
        let hostname: Arc<str> = Arc::from(hostname);
        Some(AddressBookEntry {
            hostname: hostname.clone(),
            address,
            requested_address: 0,
            mode: AddressAssignmentMode::Dynamic,
            birth_ms: 0,
            owner_hash: Self::sender_hash(hostname.as_ref()),
            last_seen_ms: self.clock.now_ms(),
        })
    }

    pub fn bind_p2p_port<F>(&self, port: P2pPort, f: F) -> TelemetryResult<()>
    where
        F: Fn(P2pMessage<'_>) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        if port == 0 {
            return Err(TelemetryError::BadArg);
        }
        let mut st = self.state.lock();
        st.p2p_port_handlers
            .entry(port)
            .or_default()
            .push(P2pPortHandler {
                handler: Arc::new(f),
            });
        Ok(())
    }

    pub fn clear_p2p_port(&self, port: P2pPort) {
        self.state.lock().p2p_port_handlers.remove(&port);
    }

    pub fn bind_p2p_stream_port<F>(&self, port: P2pPort, f: F) -> TelemetryResult<()>
    where
        F: Fn(P2pStreamEvent<'_>) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        if port == 0 {
            return Err(TelemetryError::BadArg);
        }
        let mut st = self.state.lock();
        st.p2p_stream_handlers
            .entry(port)
            .or_default()
            .push(P2pStreamHandler {
                handler: Arc::new(f),
            });
        Ok(())
    }

    pub fn clear_p2p_stream_port(&self, port: P2pPort) {
        self.state.lock().p2p_stream_handlers.remove(&port);
    }

    fn send_p2p_to_entry(
        &self,
        dst: AddressBookEntry,
        dst_port: P2pPort,
        src_port: P2pPort,
        payload: &[u8],
    ) -> TelemetryResult<()> {
        if dst_port == 0 {
            return Err(TelemetryError::BadArg);
        }
        let local = self.state.lock().local_address.clone();
        let payload = Self::encode_p2p_payload(
            local.hostname.as_ref(),
            local.address,
            src_port,
            dst_port,
            payload,
        )?;
        let pkt = Packet::new(
            DataType::P2pMessage,
            &[DataEndpoint::Discovery],
            local.hostname.as_ref(),
            self.packet_timestamp_ms(),
            crate::shared_bytes::convert(payload),
        )?;
        let target = Self::sender_hash(dst.hostname.as_ref());
        let item = self.attach_wire_contract_to_item(RouterItem::Packet(pkt.clone()), &[target])?;
        if target == Self::sender_hash(self.sender_arc().as_ref()) {
            self.dispatch_p2p_packet(&pkt)?;
            return Ok(());
        }
        self.tx_item_impl(RouterTxItem::Broadcast(item), true, false)
    }

    pub fn send_p2p_to_hostname(
        &self,
        hostname: &str,
        dst_port: P2pPort,
        src_port: P2pPort,
        payload: &[u8],
    ) -> TelemetryResult<()> {
        let dst = self
            .resolve_hostname(hostname)
            .ok_or(TelemetryError::BadArg)?;
        self.send_p2p_to_entry(dst, dst_port, src_port, payload)
    }

    pub fn send_p2p_to_address(
        &self,
        address: NodeAddress,
        dst_port: P2pPort,
        src_port: P2pPort,
        payload: &[u8],
    ) -> TelemetryResult<()> {
        let dst = self
            .resolve_address(address)
            .ok_or(TelemetryError::BadArg)?;
        self.send_p2p_to_entry(dst, dst_port, src_port, payload)
    }

    fn open_p2p_stream_to_entry(
        &self,
        dst: AddressBookEntry,
        dst_port: P2pPort,
        src_port: P2pPort,
    ) -> TelemetryResult<P2pStreamId> {
        if dst_port == 0 || src_port == 0 {
            return Err(TelemetryError::BadArg);
        }
        let stream_id = {
            let mut st = self.state.lock();
            let stream_id = Self::allocate_p2p_stream_id_locked(&mut st);
            if stream_id == 0 {
                return Err(TelemetryError::Io("p2p stream id exhausted"));
            }
            st.p2p_stream_sessions.insert(
                stream_id,
                P2pStreamSession {
                    peer_hostname: dst.hostname.clone(),
                    peer_address: dst.address,
                    local_port: src_port,
                    peer_port: dst_port,
                    peer_stream_id: 0,
                    next_sequence: 1,
                    connected: false,
                },
            );
            stream_id
        };
        let payload = Self::encode_p2p_stream_payload(P2P_STREAM_SYN, stream_id, 0, 0, &[])?;
        self.send_p2p_to_entry(dst, dst_port, src_port, &payload)?;
        Ok(stream_id)
    }

    pub fn open_p2p_stream_to_hostname(
        &self,
        hostname: &str,
        dst_port: P2pPort,
        src_port: P2pPort,
    ) -> TelemetryResult<P2pStreamId> {
        let dst = self
            .resolve_hostname(hostname)
            .ok_or(TelemetryError::BadArg)?;
        self.open_p2p_stream_to_entry(dst, dst_port, src_port)
    }

    pub fn open_p2p_stream_to_address(
        &self,
        address: NodeAddress,
        dst_port: P2pPort,
        src_port: P2pPort,
    ) -> TelemetryResult<P2pStreamId> {
        let dst = self
            .resolve_address(address)
            .ok_or(TelemetryError::BadArg)?;
        self.open_p2p_stream_to_entry(dst, dst_port, src_port)
    }

    fn send_p2p_stream_control(
        &self,
        stream_id: P2pStreamId,
        flags: u8,
        payload: &[u8],
    ) -> TelemetryResult<()> {
        let (dst, dst_port, src_port, peer_stream_id, seq, refresh_syn) = {
            let mut st = self.state.lock();
            let Some(session) = st.p2p_stream_sessions.get_mut(&stream_id) else {
                return Err(TelemetryError::BadArg);
            };
            let peer_hostname = session.peer_hostname.clone();
            let peer_address = session.peer_address;
            let peer_port = session.peer_port;
            let local_port = session.local_port;
            let peer_stream_id = session.peer_stream_id;
            let refresh_syn = peer_stream_id == 0 && flags & P2P_STREAM_SYN == 0;
            let seq = session.next_sequence;
            session.next_sequence = session.next_sequence.wrapping_add(1).max(1);
            let dst = st
                .address_book
                .get(peer_hostname.as_ref())
                .cloned()
                .unwrap_or(AddressBookEntry {
                    hostname: peer_hostname.clone(),
                    address: peer_address,
                    requested_address: peer_address,
                    mode: AddressAssignmentMode::Dynamic,
                    birth_ms: self.clock.now_ms(),
                    owner_hash: Self::sender_hash(peer_hostname.as_ref()),
                    last_seen_ms: self.clock.now_ms(),
                });
            (dst, peer_port, local_port, peer_stream_id, seq, refresh_syn)
        };
        if refresh_syn {
            let syn_payload =
                Self::encode_p2p_stream_payload(P2P_STREAM_SYN, stream_id, 0, 0, &[])?;
            self.send_p2p_to_entry(dst.clone(), dst_port, src_port, &syn_payload)?;
        }
        let stream_payload =
            Self::encode_p2p_stream_payload(flags, stream_id, peer_stream_id, seq, payload)?;
        self.send_p2p_to_entry(dst, dst_port, src_port, &stream_payload)?;
        if flags & (P2P_STREAM_FIN | P2P_STREAM_RST) != 0 {
            self.state.lock().p2p_stream_sessions.remove(&stream_id);
        }
        Ok(())
    }

    pub fn send_p2p_stream(&self, stream_id: P2pStreamId, payload: &[u8]) -> TelemetryResult<()> {
        self.send_p2p_stream_control(stream_id, P2P_STREAM_DATA, payload)
    }

    pub fn close_p2p_stream(&self, stream_id: P2pStreamId) -> TelemetryResult<()> {
        self.send_p2p_stream_control(stream_id, P2P_STREAM_FIN, &[])
    }

    pub fn reset_p2p_stream(&self, stream_id: P2pStreamId) -> TelemetryResult<()> {
        self.send_p2p_stream_control(stream_id, P2P_STREAM_RST, &[])
    }

    pub fn set_sender<S: AsRef<str>>(&self, sender: S) {
        let hostname: Arc<str> = Arc::from(sender.as_ref());
        let mut st = self.state.lock();
        let mut local = st.local_address.clone();
        local.hostname = hostname.clone();
        local.owner_hash = Self::sender_hash(hostname.as_ref());
        if matches!(local.mode, AddressAssignmentMode::Dynamic) {
            local.address = Self::fallback_address_for_hostname(hostname.as_ref());
            local.requested_address = 0;
        }
        let change =
            self.update_local_identity_locked(&mut st, local, AddressChangeReason::Configured);
        drop(st);
        let _ = self.notify_address_change(change);
    }

    pub fn set_address_assignment(
        &self,
        mode: AddressAssignmentMode,
    ) -> TelemetryResult<AddressChange> {
        let mut st = self.state.lock();
        let mut local = st.local_address.clone();
        local.mode = mode;
        local.requested_address = mode.requested_address();
        local.address = match mode {
            AddressAssignmentMode::Dynamic => {
                Self::fallback_address_for_hostname(local.hostname.as_ref())
            }
            AddressAssignmentMode::Requested(address) | AddressAssignmentMode::Static(address) => {
                if address == 0 {
                    1
                } else {
                    address
                }
            }
        };
        let change =
            self.update_local_identity_locked(&mut st, local, AddressChangeReason::Configured);
        drop(st);
        self.notify_address_change(change.clone())?;
        Ok(change)
    }

    /// Register a side whose TX callback consumes packed packet bytes.
    ///
    /// `name` is exported in topology/debug views and does not affect routing semantics.
    /// `tx` is called whenever the router decides to send a packet toward this side.
    ///
    /// The default options disable the router's per-link reliable framing on this side. Use
    /// [`Router::add_side_packed_with_options`] when this hop should participate in router
    /// reliable ACK/retransmit behavior.
    pub fn add_side_packed<N, F>(&self, name: N, tx: F) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packed_with_options(name, tx, RouterSideOptions::default())
    }

    /// Register a packed side with the compact small-packet transport preset enabled.
    ///
    /// `max_frame_bytes == 0` keeps header-template reuse enabled without chunking.
    pub fn add_side_packed_small_packets<N, F>(
        &self,
        name: N,
        tx: F,
        max_frame_bytes: usize,
    ) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packed_with_options(
            name,
            tx,
            RouterSideOptions::default().with_small_packet_transport(max_frame_bytes),
        )
    }

    /// Register a packed-output side with explicit side options.
    ///
    /// `opts.reliable_enabled` enables the router's per-hop reliable framing on this side only.
    /// That means reliable schema traffic on this side uses router-managed ACKs, packet requests,
    /// and retransmits before the bytes reach `tx`.
    ///
    /// `opts.link_local_enabled` allows link-local-only endpoints and discovery routes to use this
    /// side. `ingress_enabled` and `egress_enabled` set the initial directional policy.
    pub fn add_side_packed_with_options<N, F>(
        &self,
        name: N,
        tx: F,
        opts: RouterSideOptions,
    ) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut st = self.state.lock();
        let side = Some(RouterSide {
            name: Arc::from(name.as_ref()),
            tx_handler: RouterTxHandlerFn::Packed(Arc::new(tx)),
            opts,
        });
        let id = if let Some(id) = st.sides.iter().position(Option::is_none) {
            st.sides[id] = side;
            id
        } else {
            let id = st.sides.len();
            st.sides.push(side);
            id
        };
        st.side_runtime_stats
            .insert(id, Box::<SideRuntimeStatsInner>::default());
        st.side_transport
            .insert(id, Box::<SideTransportState>::default());
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        id
    }

    /// Register a packed-output side whose callback also receives SEDSNet's
    /// logical scheduler priority for the frame.
    ///
    /// This is intended for asynchronous host transports that must queue the
    /// emitted bytes after this callback returns. Every compact/chunked frame
    /// belonging to a logical packet receives the same priority, so transport
    /// backpressure cannot erase discovery, shared-state, time-sync, or schema
    /// ordering.
    pub fn add_side_packed_with_priority_and_options<N, F>(
        &self,
        name: N,
        tx: F,
        opts: RouterSideOptions,
    ) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&[u8], u8) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut st = self.state.lock();
        let side = Some(RouterSide {
            name: Arc::from(name.as_ref()),
            tx_handler: RouterTxHandlerFn::PackedWithPriority(Arc::new(tx)),
            opts,
        });
        let id = if let Some(id) = st.sides.iter().position(Option::is_none) {
            st.sides[id] = side;
            id
        } else {
            let id = st.sides.len();
            st.sides.push(side);
            id
        };
        st.side_runtime_stats
            .insert(id, Box::<SideRuntimeStatsInner>::default());
        st.side_transport
            .insert(id, Box::<SideTransportState>::default());
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        id
    }

    /// Register a side whose TX callback receives decoded [`Packet`] values.
    ///
    /// Packet-output sides do not preserve the packed reliable hop framing, so
    /// `RouterSideOptions::reliable_enabled` only has effect for packed sides.
    pub fn add_side_packet<N, F>(&self, name: N, tx: F) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packet_with_options(name, tx, RouterSideOptions::default())
    }

    /// Register a packet-output side with explicit side options.
    ///
    /// `opts.reliable_enabled` still records the operator's intent for this side, but packet-based
    /// callbacks receive decoded packets rather than the router's packed reliable hop framing.
    /// For router-managed per-link reliable sequencing and ACKs, use a packed side instead.
    pub fn add_side_packet_with_options<N, F>(
        &self,
        name: N,
        tx: F,
        opts: RouterSideOptions,
    ) -> RouterSideId
    where
        N: AsRef<str>,
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut st = self.state.lock();
        let side = Some(RouterSide {
            name: Arc::from(name.as_ref()),
            tx_handler: RouterTxHandlerFn::Packet(Arc::new(tx)),
            opts,
        });
        let id = if let Some(id) = st.sides.iter().position(Option::is_none) {
            st.sides[id] = side;
            id
        } else {
            let id = st.sides.len();
            st.sides.push(side);
            id
        };
        st.side_runtime_stats
            .insert(id, Box::<SideRuntimeStatsInner>::default());
        st.side_transport
            .insert(id, Box::<SideTransportState>::default());
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        id
    }

    /// Remove a side while keeping existing side IDs stable.
    ///
    /// `side` must be an id returned earlier by one of the `add_side_*` calls. Removed side IDs
    /// are tombstoned rather than renumbered so cached IDs for the remaining sides stay valid.
    pub fn remove_side(&self, side: RouterSideId) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        {
            let mut st = self.state.lock();
            #[cfg(feature = "std")]
            if st
                .side_transport
                .get(&side)
                .is_some_and(|state| state.tx_callback_gate.is_active())
            {
                return Err(TelemetryError::Io("side tx busy"));
            }
            let slot = st.sides.get_mut(side).ok_or(TelemetryError::BadArg)?;
            if slot.is_none() {
                return Err(TelemetryError::BadArg);
            }
            *slot = None;
            while st.sides.last().is_some_and(Option::is_none) {
                st.sides.pop();
            }
            // Keep the small side table allocation for reuse. Embedded links can
            // disappear and return frequently; shrinking here turned every tail
            // remove/add cycle into a free/allocation pair. The retained capacity
            // remains owned by the router and is released when the router drops.
            st.route_overrides
                .retain(|(src_side, dst_side), _| *src_side != Some(side) && *dst_side != side);
            st.typed_route_overrides
                .retain(|(src_side, _, dst_side), _| *src_side != Some(side) && *dst_side != side);
            st.route_weights
                .retain(|(src_side, dst_side), _| *src_side != Some(side) && *dst_side != side);
            st.route_priorities
                .retain(|(src_side, dst_side), _| *src_side != Some(side) && *dst_side != side);
            st.source_route_modes.remove(&Some(side));
            st.route_selection_cursors.remove(&Some(side));
            st.adaptive_route_stats.remove(&side);
            #[cfg(feature = "discovery")]
            st.discovery_side_throttle.remove(&side);
            #[cfg(all(feature = "discovery", feature = "timesync"))]
            st.timesync_side_throttle.remove(&side);
            st.side_runtime_stats.remove(&side);
            st.side_transport.remove(&side);
            st.reliable_return_routes
                .retain(|_, route| route.side != side);
            st.retain_transmit(
                |queued| {
                    !matches!(&queued.item, RouterTxItem::ToSide { dst, .. } if *dst == side)
                        && !matches!(&queued.item, RouterTxItem::ReliableReplay { dst, .. } if *dst == side)
                },
            );
            st.received_queue.retain(|queued| queued.src != Some(side));
            st.reliable_tx.retain(|(side_id, _), _| *side_id != side);
            st.reliable_rx.retain(|(side_id, _), _| *side_id != side);
            #[cfg(feature = "discovery")]
            {
                st.discovery_routes.remove(&side);
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
        }
        let mut isr_rx = self.isr_rx_queue.try_lock()?;
        isr_rx.retain(|queued| queued.src != Some(side));
        Ok(())
    }

    /// Enable or disable ingress processing for a registered side.
    ///
    /// When `enabled` is `false`, packets tagged as arriving from `side` are rejected before local
    /// delivery, discovery learning, or forwarding.
    pub fn set_side_ingress_enabled(
        &self,
        side: RouterSideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let side_ref = st
            .sides
            .get_mut(side)
            .and_then(|side| side.as_mut())
            .ok_or(TelemetryError::BadArg)?;
        side_ref.opts.ingress_enabled = enabled;
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Enable or disable egress toward a registered side.
    ///
    /// When `enabled` is `false`, the router keeps the side but stops routing packets toward it.
    pub fn set_side_egress_enabled(
        &self,
        side: RouterSideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let side_ref = st
            .sides
            .get_mut(side)
            .and_then(|side| side.as_mut())
            .ok_or(TelemetryError::BadArg)?;
        side_ref.opts.egress_enabled = enabled;
        if !enabled {
            st.retain_transmit(
                |queued| {
                    !matches!(&queued.item, RouterTxItem::ToSide { dst, .. } if *dst == side)
                        && !matches!(&queued.item, RouterTxItem::ReliableReplay { dst, .. } if *dst == side)
                },
            );
        }
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Set the route-selection policy for traffic originating from `src`.
    ///
    /// `src == None` targets locally-originated router TX. `src == Some(side)` targets traffic
    /// that was received from a specific ingress side. `mode` only matters when more than one
    /// destination side is currently eligible.
    pub fn set_source_route_mode(
        &self,
        src: Option<RouterSideId>,
        mode: RouteSelectionMode,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        // Keep an explicitly selected Fanout mode distinct from the absence
        // of a policy. With discovery enabled, no policy intentionally uses
        // adaptive single-path selection; explicit Fanout must override that.
        st.source_route_modes.insert(src, mode);
        st.route_selection_cursors.remove(&src);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear any source-specific route-selection override for `src`.
    pub fn clear_source_route_mode(&self, src: Option<RouterSideId>) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.source_route_modes.remove(&src);
        st.route_selection_cursors.remove(&src);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Set the weighted-routing weight from `src` toward `dst`.
    ///
    /// Higher `weight` values make `dst` more likely to be chosen when the source route mode is
    /// [`RouteSelectionMode::Weighted`]. `src == None` applies to locally-originated TX.
    pub fn set_route_weight(
        &self,
        src: Option<RouterSideId>,
        dst: RouterSideId,
        weight: u32,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_weights.insert((src, dst), weight);
        st.route_selection_cursors.remove(&src);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear a previously configured weighted-routing weight override.
    pub fn clear_route_weight(
        &self,
        src: Option<RouterSideId>,
        dst: RouterSideId,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_weights.remove(&(src, dst));
        st.route_selection_cursors.remove(&src);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Set the failover priority from `src` toward `dst`.
    ///
    /// Lower numeric `priority` wins when the source route mode is
    /// [`RouteSelectionMode::Failover`]. `src == None` applies to locally-originated TX.
    pub fn set_route_priority(
        &self,
        src: Option<RouterSideId>,
        dst: RouterSideId,
        priority: u32,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_priorities.insert((src, dst), priority);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear a previously configured failover priority override.
    pub fn clear_route_priority(
        &self,
        src: Option<RouterSideId>,
        dst: RouterSideId,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_priorities.remove(&(src, dst));
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Allow or block routing from `src` toward `dst`.
    ///
    /// `src == None` controls locally-originated router TX. `enabled == false` is the sink-like
    /// building block for disabling specific directions without changing router construction mode.
    pub fn set_route(
        &self,
        src: Option<RouterSideId>,
        dst: RouterSideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_overrides.insert((src, dst), enabled);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Allow or block routing for a specific `DataType` from `src` toward `dst`.
    ///
    /// Typed route rules act as allowlists once any rule exists for the `(src, ty)` pair.
    /// `src == None` targets locally-originated router TX.
    pub fn set_typed_route(
        &self,
        src: Option<RouterSideId>,
        ty: DataType,
        dst: RouterSideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.typed_route_overrides
            .insert((src, ty.as_u32(), dst), enabled);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear a typed route override for the `(src, ty, dst)` triple.
    pub fn clear_typed_route(
        &self,
        src: Option<RouterSideId>,
        ty: DataType,
        dst: RouterSideId,
    ) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.typed_route_overrides.remove(&(src, ty.as_u32(), dst));
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear a non-typed route override so the router falls back to default behavior.
    pub fn clear_route(&self, src: Option<RouterSideId>, dst: RouterSideId) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let _ = Self::side_ref(&st, dst).map_err(|_| TelemetryError::BadArg)?;
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        st.route_overrides.remove(&(src, dst));
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Queue a built-in discovery advertisement describing this router's local endpoints.
    #[cfg(feature = "discovery")]
    pub fn announce_discovery(&self) -> TelemetryResult<()> {
        self.queue_discovery_announce(true, false)
    }

    /// Broadcast that this router is leaving so peers can prune topology immediately.
    #[cfg(feature = "discovery")]
    pub fn announce_leave(&self) -> TelemetryResult<()> {
        let sender = self.sender_arc();
        let pkt = discovery::build_discovery_leave(sender.as_ref(), self.clock.now_ms())?;
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    /// Queue a discovery advertisement if the adaptive cadence says one is due.
    #[cfg(feature = "discovery")]
    pub fn poll_discovery(&self) -> TelemetryResult<bool> {
        self.poll_discovery_announce()
    }

    #[cfg(feature = "discovery")]
    pub fn request_topology(&self) -> TelemetryResult<()> {
        let sender = self.sender_arc();
        let pkt =
            discovery::build_discovery_topology_request(sender.as_ref(), self.clock.now_ms())?;
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    #[cfg(feature = "discovery")]
    pub fn request_schema(&self) -> TelemetryResult<()> {
        let sender = self.sender_arc();
        let pkt = discovery::build_discovery_schema_request(sender.as_ref(), self.clock.now_ms())?;
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    /// Mark a data type as a network-managed variable.
    ///
    /// The router caches the latest packet for this type when it is locally transmitted or
    /// received from the network. Peers can request the latest cached value and the router will
    /// replay the original value packet, so user endpoint handlers see the same API shape as a
    /// normal update.
    pub fn enable_managed_variable(&self, ty: DataType) -> TelemetryResult<()> {
        self.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
    }

    /// Mark a data type as a network variable with local read/write permissions.
    ///
    /// Users do not register a separate endpoint for network variables. Values are cached by
    /// data type and refreshed through SEDSnet's internal managed-variable control packets.
    pub fn enable_network_variable(
        &self,
        ty: DataType,
        permissions: NetworkVariablePermissions,
    ) -> TelemetryResult<()> {
        if is_internal_control_type(ty) {
            return Err(TelemetryError::InvalidType);
        }
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        let newly_advertised = st.managed_variable_types.insert(ty.as_u32());
        #[cfg(not(feature = "discovery"))]
        st.managed_variable_types.insert(ty.as_u32());
        st.managed_variable_permissions
            .insert(ty.as_u32(), permissions);
        #[cfg(feature = "discovery")]
        if newly_advertised {
            Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        }
        Ok(())
    }

    /// Register a callback that runs when an inbound network update changes this variable cache.
    ///
    /// The callback is invoked after the router state lock is released, so it may call back into
    /// the router. Local `set_network_variable` and `seed_managed_variable` calls update the cache
    /// without invoking this network-update callback.
    pub fn on_network_variable_update<F>(&self, ty: DataType, f: F) -> TelemetryResult<()>
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        if is_internal_control_type(ty) {
            return Err(TelemetryError::InvalidType);
        }
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        let newly_advertised = st.managed_variable_types.insert(ty.as_u32());
        #[cfg(not(feature = "discovery"))]
        st.managed_variable_types.insert(ty.as_u32());
        st.network_variable_update_handlers
            .entry(ty.as_u32())
            .or_default()
            .push(NetworkVariableUpdateHandler {
                handler: Arc::new(f),
            });
        #[cfg(feature = "discovery")]
        if newly_advertised {
            Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        }
        Ok(())
    }

    pub fn disable_managed_variable(&self, ty: DataType) {
        let mut st = self.state.lock();
        #[cfg(feature = "discovery")]
        let was_advertised = st.managed_variable_types.remove(&ty.as_u32());
        #[cfg(not(feature = "discovery"))]
        st.managed_variable_types.remove(&ty.as_u32());
        st.managed_variable_permissions.remove(&ty.as_u32());
        st.managed_variable_latest.remove(&ty.as_u32());
        st.network_variable_update_handlers.remove(&ty.as_u32());
        #[cfg(feature = "discovery")]
        if was_advertised {
            Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        }
    }

    pub fn seed_managed_variable(&self, pkt: Packet) -> TelemetryResult<()> {
        if is_internal_control_type(pkt.data_type()) {
            return Err(TelemetryError::InvalidType);
        }
        pkt.validate()?;
        {
            let mut st = self.state.lock();
            #[cfg(feature = "discovery")]
            let newly_advertised = st.managed_variable_types.insert(pkt.data_type().as_u32());
            #[cfg(not(feature = "discovery"))]
            st.managed_variable_types.insert(pkt.data_type().as_u32());
            #[cfg(feature = "discovery")]
            if newly_advertised {
                Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
            }
        }
        self.cache_managed_variable_packet(&pkt, false)
    }

    pub fn cached_managed_variable(&self, ty: DataType) -> Option<Packet> {
        self.managed_variable_latest(ty)
    }

    /// Set a network variable for the whole network, permission policy allowing.
    ///
    /// The packet is cached locally and sent as normal user data. Routers that have seen or enabled
    /// this variable update their local cache internally; applications do not need to register a
    /// managed-variable endpoint.
    pub fn set_network_variable(&self, pkt: Packet) -> TelemetryResult<()> {
        if is_internal_control_type(pkt.data_type()) {
            return Err(TelemetryError::InvalidType);
        }
        pkt.validate()?;
        let ty = pkt.data_type();
        {
            let mut st = self.state.lock();
            st.managed_variable_types.insert(ty.as_u32());
            let perms = Self::managed_variable_permissions_locked(&st, ty);
            if !perms.write {
                return Err(TelemetryError::PermissionDenied);
            }
        }
        self.cache_managed_variable_packet(&pkt, false)?;
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        let item = RouterTxItem::Broadcast(RouterItem::Packet(pkt));
        if self.side_tx_active() {
            return self.tx_queue_item_with_priority(
                item,
                false,
                crate::transport_priority(DataType::ManagedVariableValue),
            );
        }
        self.tx_item(item)
    }

    /// Read a cached network variable, requesting a refresh if missing or stale.
    ///
    /// Returns the cached value when present. If the value is missing, this queues an internal
    /// managed-variable request and returns `Ok(None)`. If the value is stale, this queues a refresh
    /// request and returns the stale cached value so callers can continue operating while the network
    /// catches up.
    #[cfg(feature = "discovery")]
    pub fn get_network_variable(
        &self,
        ty: DataType,
        stale_after_ms: Option<u64>,
    ) -> TelemetryResult<Option<Packet>> {
        if is_internal_control_type(ty) {
            return Err(TelemetryError::InvalidType);
        }
        {
            let mut st = self.state.lock();
            st.managed_variable_types.insert(ty.as_u32());
            let perms = Self::managed_variable_permissions_locked(&st, ty);
            if !perms.read {
                return Err(TelemetryError::PermissionDenied);
            }
        }
        let cached = self.managed_variable_latest_with_age(ty);
        let needs_refresh = match (cached.as_ref(), stale_after_ms) {
            (None, _) => true,
            (Some((_pkt, age_ms)), Some(max_age_ms)) => *age_ms > max_age_ms,
            (Some(_), None) => false,
        };
        if needs_refresh {
            self.request_managed_variable(ty)?;
        }
        Ok(cached.map(|(pkt, _age_ms)| pkt))
    }

    /// Read a cached network variable without issuing a network refresh.
    pub fn get_cached_network_variable(&self, ty: DataType) -> TelemetryResult<Option<Packet>> {
        if is_internal_control_type(ty) {
            return Err(TelemetryError::InvalidType);
        }
        if !self.can_read_managed_variable(ty) {
            return Err(TelemetryError::PermissionDenied);
        }
        Ok(self.managed_variable_latest(ty))
    }

    #[cfg(feature = "discovery")]
    pub fn request_managed_variable(&self, ty: DataType) -> TelemetryResult<()> {
        if is_internal_control_type(ty) {
            return Err(TelemetryError::InvalidType);
        }
        if !self.can_read_managed_variable(ty) {
            return Err(TelemetryError::PermissionDenied);
        }
        let sender = self.sender_arc();
        let pkt =
            discovery::build_managed_variable_request(sender.as_ref(), self.clock.now_ms(), ty)?;
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    #[cfg(feature = "discovery")]
    pub fn request_managed_variable_by_name(&self, ty_name: &str) -> TelemetryResult<()> {
        let ty = DataType::try_named(ty_name).ok_or(TelemetryError::InvalidType)?;
        self.request_managed_variable(ty)
    }

    /// Export the current discovery-driven network topology view.
    #[cfg(feature = "discovery")]
    pub fn export_topology(&self) -> TopologySnapshot {
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        if Self::prune_discovery_routes_locked(&mut st, now_ms) {
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        let routes = st
            .discovery_routes
            .iter()
            .filter_map(|(&side_id, route)| {
                let side = st.sides.get(side_id)?.as_ref()?;
                let announcers = route
                    .announcers
                    .iter()
                    .map(|(sender_id, sender_state)| TopologyAnnouncerRoute {
                        sender_id: sender_id.clone(),
                        reachable_endpoints: sender_state
                            .reachable
                            .iter()
                            .copied()
                            .filter(|ep| !discovery::is_router_control_endpoint(*ep))
                            .collect(),
                        reachable_network_variables: sender_state
                            .reachable_network_variables
                            .clone(),
                        reachable_timesync_sources: sender_state.reachable_timesync_sources.clone(),
                        routers: sender_state.topology_boards.as_ref().clone(),
                        last_seen_ms: sender_state.last_seen_ms,
                        age_ms: now_ms.saturating_sub(sender_state.last_seen_ms),
                    })
                    .collect();
                Some(TopologySideRoute {
                    side_id,
                    side_name: side.name.to_string(),
                    reachable_endpoints: route
                        .reachable
                        .iter()
                        .copied()
                        .filter(|ep| !discovery::is_router_control_endpoint(*ep))
                        .collect(),
                    reachable_network_variables: route.reachable_network_variables.clone(),
                    reachable_timesync_sources: route.reachable_timesync_sources.clone(),
                    announcers,
                    last_seen_ms: route.last_seen_ms,
                    age_ms: now_ms.saturating_sub(route.last_seen_ms),
                })
            })
            .collect();
        let routers = self.advertised_discovery_topology_for_link_locked(&st, now_ms, true, None);
        let advertised_endpoints =
            self.advertised_discovery_endpoints_for_link_locked(&st, now_ms, true, None);
        let advertised_timesync_sources =
            self.advertised_discovery_timesync_sources_for_link_locked(&st, now_ms, None);
        let links = discovery::topology_links_from_boards(&routers);
        TopologySnapshot {
            advertised_endpoints,
            advertised_timesync_sources,
            routers,
            links,
            routes,
            current_announce_interval_ms: st.discovery_cadence.current_interval_ms,
            next_announce_ms: st.discovery_cadence.next_announce_ms,
        }
    }

    #[cfg(feature = "discovery")]
    pub fn client_stats(&self, sender_id: &str) -> Option<ClientStatsSnapshot> {
        let now_ms = self.clock.now_ms();
        let st = self.state.lock();
        let mut side_ids = Vec::new();
        let mut side_names = Vec::new();
        let mut last_seen_ms = None::<u64>;
        let mut reachable_endpoints = Vec::new();
        let mut reachable_timesync_sources = Vec::new();
        let mut packets_sent = 0u64;
        let mut packets_received = 0u64;
        let mut bytes_sent = 0u64;
        let mut bytes_received = 0u64;

        for (side_id, route) in &st.discovery_routes {
            let Some(sender_state) = route.announcers.get(sender_id) else {
                continue;
            };
            side_ids.push(*side_id);
            if let Some(side_name) = st
                .sides
                .get(*side_id)
                .and_then(|side| side.as_ref())
                .map(|side| side.name.clone())
            {
                side_names.push(side_name.to_string());
            }
            last_seen_ms = Some(last_seen_ms.unwrap_or(0).max(sender_state.last_seen_ms));
            reachable_endpoints.extend(sender_state.reachable.iter().copied());
            reachable_timesync_sources
                .extend(sender_state.reachable_timesync_sources.iter().cloned());
            if let Some(stats) = st.side_runtime_stats.get(side_id) {
                packets_sent = packets_sent.saturating_add(stats.tx_packets);
                packets_received = packets_received.saturating_add(stats.rx_packets);
                bytes_sent = bytes_sent.saturating_add(stats.tx_bytes);
                bytes_received = bytes_received.saturating_add(stats.rx_bytes);
            }
        }

        if side_ids.is_empty() {
            return None;
        }
        reachable_endpoints.retain(|ep| !discovery::is_router_control_endpoint(*ep));
        crate::small_sort::sort(&mut reachable_endpoints);
        reachable_endpoints.dedup();
        reachable_timesync_sources.sort_unstable();
        reachable_timesync_sources.dedup();
        crate::small_sort::sort(&mut side_ids);
        side_ids.dedup();
        side_names.sort_unstable();
        side_names.dedup();
        let age_ms = last_seen_ms.map(|seen| now_ms.saturating_sub(seen));
        Some(ClientStatsSnapshot {
            sender_id: sender_id.to_string(),
            connected: age_ms.is_some_and(|age| age <= DISCOVERY_ROUTE_TTL_MS),
            side_ids,
            side_names,
            last_seen_ms,
            age_ms,
            reachable_endpoints,
            reachable_timesync_sources,
            packets_sent,
            packets_received,
            bytes_sent,
            bytes_received,
        })
    }

    /// Copy bounded metadata into caller storage without allocating. Returns
    /// the total pending count across all pages. Copy begins at `first`; rows
    /// outside the pending range and unused owner slots are zeroed.
    pub fn copy_reliable_pending_stats(
        &self,
        first: usize,
        rows: &mut [crate::diagnostics::ReliablePendingRow],
    ) -> usize {
        rows.fill(crate::diagnostics::ReliablePendingRow::default());
        let st = self.state.lock();
        for (row, (&id, sent)) in rows
            .iter_mut()
            .zip(st.end_to_end_reliable_tx.iter().skip(first))
        {
            row.packet_id = id;
            row.last_send_ms = sent.last_send_ms;
            row.data_type = Self::item_data_type(&sent.data).map_or(0, DataType::as_u32);
            row.pending_count = sent.pending_destinations.len().min(u32::MAX as usize) as u32;
            row.retries = sent.retries;
            row.flags = u32::from(sent.queued)
                | (u32::from(sent.waiting_for_predecessor) << 1)
                | (u32::from(
                    st.reliable_return_routes
                        .get(&id)
                        .is_some_and(|route| route.upstream_contract.is_some()),
                ) << 2)
                | (u32::from(sent.tracked_destinations) << 3);
            for (out, owner) in row
                .pending_owners
                .iter_mut()
                .zip(sent.pending_destinations.keys())
            {
                *out = *owner;
            }
        }
        st.end_to_end_reliable_tx.len()
    }

    /// Snapshot outstanding reliable deliveries for diagnostics. Allocates
    /// metadata bounded by the existing pending window; never clones payloads
    /// or changes retry timing. Not needed in the normal dispatch hot path.
    pub fn export_reliable_pending_stats(&self) -> Vec<crate::diagnostics::ReliablePendingStats> {
        let st = self.state.lock();
        st.end_to_end_reliable_tx
            .iter()
            .filter_map(|(&packet_id, sent)| {
                Some(crate::diagnostics::ReliablePendingStats {
                    packet_id,
                    data_type: Self::item_data_type(&sent.data).ok()?,
                    pending_destinations: sent.pending_destinations.keys().copied().collect(),
                    retries: sent.retries,
                    queued: sent.queued,
                    waiting_for_predecessor: sent.waiting_for_predecessor,
                    last_send_ms: sent.last_send_ms,
                })
            })
            .collect()
    }

    pub fn export_runtime_stats(&self) -> RuntimeStatsSnapshot {
        let now_ms = self.clock.now_ms();
        let isr_rx = self.isr_rx_queue.snapshot().unwrap_or((0, 0));
        let st = self.state.lock();

        let mut sides = Vec::new();
        for (side_id, side) in st.sides.iter().enumerate() {
            let Some(side) = side.as_ref() else { continue };
            let empty_stats = SideRuntimeStatsInner::default();
            let stats = st
                .side_runtime_stats
                .get(&side_id)
                .map(Box::as_ref)
                .unwrap_or(&empty_stats);
            let adaptive = st
                .adaptive_route_stats
                .get(&side_id)
                .cloned()
                .unwrap_or_default()
                .snapshot(now_ms, true);
            let (tx_template_count, rx_template_count) = st
                .side_transport
                .get(&side_id)
                .map(|state| (state.tx_template_count(), state.rx_template_count()))
                .unwrap_or((0, 0));
            let mut data_types: Vec<RuntimeTypeStats> = stats
                .data_types
                .iter()
                .map(|(&ty, item)| {
                    let item = item.counters();
                    RuntimeTypeStats {
                        data_type: DataType(ty),
                        tx_packets: item.tx_packets,
                        tx_bytes: item.tx_bytes,
                        rx_packets: item.rx_packets,
                        rx_bytes: item.rx_bytes,
                        relayed_tx_packets: item.relayed_tx_packets,
                        relayed_tx_bytes: item.relayed_tx_bytes,
                        relayed_rx_packets: item.relayed_rx_packets,
                        relayed_rx_bytes: item.relayed_rx_bytes,
                        tx_retries: item.tx_retries,
                        handler_failures: item.handler_failures,
                    }
                })
                .collect();
            data_types.sort_unstable_by_key(|item| item.data_type.as_u32());
            sides.push(RuntimeSideStats {
                side_id,
                side_name: side.name.to_string(),
                reliable_enabled: side.opts.reliable_enabled,
                link_local_enabled: side.opts.link_local_enabled,
                header_template_enabled: side.opts.header_template_enabled,
                max_frame_bytes: side.opts.max_frame_bytes,
                compact_header_target_bytes: side.opts.compact_header_target_bytes,
                side_transport_profile: side.opts.effective_transport_profile().as_str(),
                ingress_enabled: side.opts.ingress_enabled,
                egress_enabled: side.opts.egress_enabled,
                tx_packets: stats.tx_packets,
                tx_bytes: stats.tx_bytes,
                rx_packets: stats.rx_packets,
                rx_bytes: stats.rx_bytes,
                relayed_tx_packets: stats.relayed_tx_packets,
                relayed_tx_bytes: stats.relayed_tx_bytes,
                relayed_rx_packets: stats.relayed_rx_packets,
                relayed_rx_bytes: stats.relayed_rx_bytes,
                local_delivery_packets: stats.local_delivery_packets,
                tx_retries: stats.tx_retries,
                tx_handler_failures: stats.tx_handler_failures,
                local_handler_failures: stats.local_handler_failures,
                total_handler_retries: stats.total_handler_retries,
                side_transport_full_frames: stats.side_transport_full_frames,
                side_transport_compact_frames: stats.side_transport_compact_frames,
                side_transport_compact_delta_frames: stats.side_transport_compact_delta_frames,
                side_transport_compact_omitted_timestamp_frames: stats
                    .side_transport_compact_omitted_timestamp_frames,
                side_transport_chunk_frames: stats.side_transport_chunk_frames,
                side_transport_chunk_reclaims: st
                    .side_transport
                    .get(&side_id)
                    .map_or(0, |state| u64::from(state.rx_chunk_reclaims)),
                side_transport_raw_bytes: stats.side_transport_raw_bytes,
                side_transport_wire_bytes: stats.side_transport_wire_bytes,
                side_transport_bytes_saved: stats.side_transport_bytes_saved,
                side_transport_min_compact_overhead_bytes: stats
                    .side_transport_min_compact_overhead_bytes,
                side_transport_max_compact_overhead_bytes: stats
                    .side_transport_max_compact_overhead_bytes,
                side_transport_compact_target_misses: stats.side_transport_compact_target_misses,
                side_transport_template_evictions: stats.side_transport_template_evictions,
                side_transport_tx_template_count: tx_template_count,
                side_transport_rx_template_count: rx_template_count,
                max_side_transport_templates: side.opts.max_side_transport_templates,
                adaptive,
                data_types,
            });
        }

        let mut route_modes: Vec<RouteModeStats> = st
            .route_selection_cursors
            .iter()
            .map(|(src, cursor)| RouteModeStats {
                src_side_id: *src,
                selection_mode: st.source_route_modes.get(src).copied(),
                cursor: *cursor,
            })
            .collect();
        for src in st.source_route_modes.keys() {
            if !route_modes.iter().any(|mode| mode.src_side_id == *src) {
                route_modes.push(RouteModeStats {
                    src_side_id: *src,
                    selection_mode: st.source_route_modes.get(src).copied(),
                    cursor: 0,
                });
            }
        }
        route_modes.sort_unstable_by_key(|mode| mode.src_side_id.unwrap_or(usize::MAX));

        let mut route_overrides: Vec<RouteOverrideStats> = st
            .route_overrides
            .iter()
            .map(|((src, dst), enabled)| RouteOverrideStats {
                src_side_id: *src,
                dst_side_id: *dst,
                enabled: *enabled,
            })
            .collect();
        route_overrides.sort_unstable_by_key(|item| {
            (item.src_side_id.unwrap_or(usize::MAX), item.dst_side_id)
        });

        let mut typed_route_overrides: Vec<TypedRouteOverrideStats> = st
            .typed_route_overrides
            .iter()
            .map(|((src, ty, dst), enabled)| TypedRouteOverrideStats {
                src_side_id: *src,
                data_type: DataType(*ty),
                dst_side_id: *dst,
                enabled: *enabled,
            })
            .collect();
        typed_route_overrides.sort_unstable_by_key(|item| {
            (
                item.src_side_id.unwrap_or(usize::MAX),
                item.data_type.as_u32(),
                item.dst_side_id,
            )
        });

        let mut route_weights: Vec<RouteWeightStats> = st
            .route_weights
            .iter()
            .map(|((src, dst), weight)| RouteWeightStats {
                src_side_id: *src,
                dst_side_id: *dst,
                weight: *weight,
            })
            .collect();
        route_weights.sort_unstable_by_key(|item| {
            (item.src_side_id.unwrap_or(usize::MAX), item.dst_side_id)
        });

        let mut route_priorities: Vec<RoutePriorityStats> = st
            .route_priorities
            .iter()
            .map(|((src, dst), priority)| RoutePriorityStats {
                src_side_id: *src,
                dst_side_id: *dst,
                priority: *priority,
            })
            .collect();
        route_priorities.sort_unstable_by_key(|item| {
            (item.src_side_id.unwrap_or(usize::MAX), item.dst_side_id)
        });

        #[cfg(feature = "discovery")]
        let discovery = DiscoveryRuntimeStats {
            route_count: st.discovery_routes.len(),
            announcer_count: st
                .discovery_routes
                .values()
                .map(|route| route.announcers.len())
                .sum(),
            current_announce_interval_ms: Some(st.discovery_cadence.current_interval_ms),
            next_announce_ms: Some(st.discovery_cadence.next_announce_ms),
        };
        #[cfg(not(feature = "discovery"))]
        let discovery = DiscoveryRuntimeStats {
            route_count: 0,
            announcer_count: 0,
            current_announce_interval_ms: None,
            next_announce_ms: None,
        };

        RuntimeStatsSnapshot {
            sides,
            route_modes,
            route_overrides,
            typed_route_overrides,
            route_weights,
            route_priorities,
            queues: QueueRuntimeStats {
                rx_len: isr_rx.0.saturating_add(st.received_queue.len()),
                rx_bytes: isr_rx.1.saturating_add(st.received_queue.bytes_used()),
                tx_len: st.transmit_queue.len(),
                tx_bytes: st.transmit_queue.bytes_used(),
                replay_len: 0,
                replay_bytes: 0,
                recent_rx_len: st.recent_rx.len(),
                recent_rx_bytes: st.recent_rx.bytes_used(),
                reliable_rx_buffered_len: st.reliable_rx_buffer_len(),
                reliable_rx_buffered_bytes: st.reliable_rx_buffered_bytes(),
                shared_queue_bytes_used: st.shared_queue_bytes_used(),
            },
            reliable: ReliableRuntimeStats {
                reliable_return_route_count: st.reliable_return_routes.len(),
                end_to_end_pending_count: st.end_to_end_reliable_tx.len(),
                end_to_end_pending_destination_count: st
                    .end_to_end_reliable_tx
                    .values()
                    .map(|sent| sent.pending_destinations.len())
                    .sum(),
                end_to_end_acked_cache_count: 0,
            },
            discovery,
            total_handler_failures: st.total_handler_failures,
            total_handler_retries: st.total_handler_retries,
        }
    }

    /// Allocation-free memory counters, version 1. Values saturate at u32::MAX.
    /// Approximate retained costs exclude allocator headers and shared ownership;
    /// they are component diagnostics, not an independent heap-size estimate.
    /// Whether queued work remains. Bounded workers may yield to their peers
    /// instead of sleeping while a backlog waits. A busy ISR guard is treated
    /// as pending; callers must still enforce their own CPU-service bound.
    pub fn has_queued_work(&self) -> bool {
        if self
            .isr_rx_queue
            .try_lock()
            .map_or(true, |queue| !queue.is_empty())
        {
            return true;
        }
        let state = self.state.lock();
        !state.received_queue.is_empty() || !state.transmit_queue.is_empty()
    }

    /// Allocation-free queue accounting for a caller-owned diagnostic buffer.
    /// Version, RX/TX counts, independently summed costs, front type/priority/
    /// wait, ACK/schema counts, minimum priority, reliable pending count/bytes,
    /// front variant and the monotonic clock words. Packed types remain unknown
    /// (0) so inspection never allocates/pins payloads, parses bytes or drains.
    pub fn queue_counters(&self) -> [u32; 16] {
        let now = self.clock.now_ms();
        let st = self.state.lock();
        let ty_of = |item: &RouterTxItem| match item {
            RouterTxItem::Broadcast(RouterItem::Packet(packet))
            | RouterTxItem::ToSide {
                data: RouterItem::Packet(packet),
                ..
            } => Some(packet.data_type()),
            RouterTxItem::Broadcast(RouterItem::Packed(_))
            | RouterTxItem::ToSide {
                data: RouterItem::Packed(_),
                ..
            }
            | RouterTxItem::ReliableReplay { .. } => None,
            RouterTxItem::EndToEndReplay { packet_id } => st
                .end_to_end_reliable_tx
                .get(packet_id)
                .and_then(|pending| match &pending.data {
                    RouterItem::Packet(packet) => Some(packet.data_type()),
                    RouterItem::Packed(_) => None,
                }),
        };
        let sum_cost = |total: usize, cost: usize| total.saturating_add(cost);
        let front = st.transmit_queue.iter().next();
        let ack_count = st
            .transmit_queue
            .iter()
            .filter(|q| {
                matches!(
                    ty_of(&q.item),
                    Some(
                        DataType::ReliableAck
                            | DataType::ReliablePartialAck
                            | DataType::ReliablePacketRequest
                    )
                )
            })
            .count();
        let schema_count = st
            .transmit_queue
            .iter()
            .filter(|q| ty_of(&q.item) == Some(DataType::DiscoverySchema))
            .count();
        [
            1,
            st.received_queue.len() as u32,
            st.transmit_queue.len() as u32,
            st.received_queue
                .iter()
                .map(ByteCost::byte_cost)
                .fold(0, sum_cost) as u32,
            st.transmit_queue
                .iter()
                .map(ByteCost::byte_cost)
                .fold(0, sum_cost) as u32,
            front
                .and_then(|q| ty_of(&q.item))
                .map_or(0, DataType::as_u32),
            front.map_or(0, |q| q.priority.into()),
            front.map_or(0, |q| {
                q.retry_after_ms.saturating_sub(now).min(u32::MAX.into()) as u32
            }),
            ack_count as u32,
            schema_count as u32,
            st.transmit_queue
                .iter()
                .map(|q| u32::from(q.priority))
                .min()
                .unwrap_or(0),
            st.end_to_end_reliable_tx.len() as u32,
            st.end_to_end_reliable_tx
                .values()
                .map(|entry| match &entry.data {
                    RouterItem::Packet(packet) => packet.byte_cost(),
                    RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
                })
                .fold(0, sum_cost) as u32,
            front.map_or(0, |q| match q.item {
                RouterTxItem::Broadcast(_) => 1,
                RouterTxItem::ToSide { .. } => 2,
                RouterTxItem::ReliableReplay { .. } => 3,
                RouterTxItem::EndToEndReplay { .. } => 4,
            }),
            now as u32,
            (now >> 32) as u32,
        ]
    }

    pub fn memory_counters(&self) -> [u32; 16] {
        let st = self.state.lock();
        #[cfg(feature = "discovery")]
        let discovery = st.discovery_bytes_used();
        #[cfg(not(feature = "discovery"))]
        let discovery = 0;
        let templates = st
            .side_transport
            .values()
            .map(|side| side.tx_templates.len() + side.rx_templates_by_id.len())
            .sum::<usize>();
        let template_bytes = st
            .side_transport
            .values()
            .flat_map(|side| {
                side.tx_templates
                    .values()
                    .chain(side.rx_templates_by_id.values())
            })
            .map(|t| size_of::<SideHeaderTemplate>() + t.prefix().len() + t.between().len())
            .sum::<usize>();
        let chunks = st
            .side_transport
            .values()
            .flat_map(|side| side.rx_chunks.values())
            .flat_map(|assembly| assembly.received.iter().flatten())
            .map(|bytes| bytes.len())
            .sum::<usize>();
        let type_stats = st
            .side_runtime_stats
            .values()
            .map(|side| side.data_types.len())
            .sum::<usize>();
        let managed = st
            .managed_variable_latest
            .values()
            .map(|entry| entry.packet.byte_cost())
            .sum::<usize>();
        let pending = st
            .end_to_end_reliable_tx
            .values()
            .map(|entry| match &entry.data {
                RouterItem::Packet(packet) => packet.byte_cost(),
                RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
            })
            .sum::<usize>();
        [
            1,
            st.memory.max_queue_budget,
            st.shared_queue_bytes_used(),
            st.received_queue.bytes_used(),
            st.transmit_queue.bytes_used(),
            st.received_queue.capacity() * size_of::<RouterRxItem>()
                + st.transmit_queue.capacity() * size_of::<TxQueued>()
                + st.recent_rx.capacity() * size_of::<u64>(),
            st.reliable_rx_buffered_bytes(),
            discovery,
            crate::config::schema_bytes_used(),
            managed,
            pending,
            templates,
            template_bytes,
            chunks,
            type_stats,
            st.side_runtime_stats
                .values()
                .flat_map(|side| side.data_types.values())
                .map(|stats| size_of::<TypeRuntimeStatsInner>() + stats.heap_bytes())
                .sum::<usize>(),
        ]
        .map(|value| u32::try_from(value).unwrap_or(u32::MAX))
    }

    /// Export current router memory usage/layout as JSON for profiling.
    pub fn export_memory_layout_json(&self) -> String {
        let isr_rx = self.isr_rx_queue.snapshot().unwrap_or((0, 0));
        let st = self.state.lock();
        #[cfg(feature = "discovery")]
        let discovery_bytes = st.discovery_bytes_used();
        #[cfg(not(feature = "discovery"))]
        let discovery_bytes = 0usize;
        let schema_bytes = crate::config::schema_bytes_used();
        let network_variable_cache_bytes = st
            .managed_variable_latest
            .values()
            .map(|entry| entry.packet.byte_cost())
            .sum::<usize>();
        let mut out = String::new();
        let memory = st.memory;
        let _ = fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{{\"kind\":\"router\",\
                 \"shared_queue_bytes_used\":{},\"shared_queue_bytes_allocated\":{},\
                 \"rx_queue_bytes_used\":{},\"rx_queue_bytes_allocated\":{},\"rx_queue_len\":{},\
                 \"isr_rx_queue_bytes_used\":{},\"isr_rx_queue_bytes_allocated\":{},\"isr_rx_queue_len\":{},\
                 \"tx_queue_bytes_used\":{},\"tx_queue_bytes_allocated\":{},\"tx_queue_len\":{},\
                 \"recent_rx_bytes_used\":{},\"recent_rx_bytes_allocated\":{},\"recent_rx_len\":{},\
                 \"reliable_rx_buffer_bytes_used\":{},\"reliable_rx_buffer_bytes_allocated\":{},\"reliable_rx_buffer_len\":{},\
                 \"discovery_bytes_used\":{},\"discovery_bytes_allocated\":{},\
                 \"schema_bytes_used\":{},\"schema_bytes_allocated\":{},\
                 \"network_variable_cache_bytes_used\":{},\"network_variable_cache_bytes_allocated\":{},\"network_variable_cache_len\":{}}}",
                st.shared_queue_bytes_used(),
                memory.max_queue_budget,
                st.received_queue.bytes_used(),
                st.received_queue.max_bytes(),
                st.received_queue.len(),
                isr_rx.1,
                memory.max_queue_budget,
                isr_rx.0,
                st.transmit_queue.bytes_used(),
                st.transmit_queue.max_bytes(),
                st.transmit_queue.len(),
                st.recent_rx.bytes_used(),
                st.recent_rx.max_bytes(),
                st.recent_rx.len(),
                st.reliable_rx_buffered_bytes(),
                memory.max_queue_budget,
                st.reliable_rx_buffer_len(),
                discovery_bytes,
                memory.max_queue_budget,
                schema_bytes,
                memory.max_queue_budget,
                network_variable_cache_bytes,
                memory.max_queue_budget,
                st.managed_variable_latest.len(),
            ),
        );
        out
    }

    #[cfg(test)]
    #[cfg(feature = "discovery")]
    pub(crate) fn debug_end_to_end_pending_destination_count(
        &self,
        packet_id: u64,
    ) -> Option<usize> {
        let st = self.state.lock();
        st.end_to_end_reliable_tx
            .get(&packet_id)
            .map(|sent| sent.pending_destinations.len())
    }

    #[cfg(test)]
    #[cfg(feature = "discovery")]
    pub(crate) fn debug_end_to_end_tracked_count(&self) -> usize {
        let st = self.state.lock();
        st.end_to_end_reliable_tx.len()
    }

    #[cfg(test)]
    #[cfg(feature = "discovery")]
    pub(crate) fn debug_reliable_return_route_count(&self) -> usize {
        let st = self.state.lock();
        st.reliable_return_routes.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_side_storage(&self) -> (usize, usize) {
        let st = self.state.lock();
        (st.sides.len(), st.sides.capacity())
    }

    #[cfg(test)]
    pub(crate) fn debug_queue_lengths(&self) -> (usize, usize, usize) {
        let st = self.state.lock();
        (
            st.received_queue.len(),
            st.transmit_queue.len(),
            st.recent_rx.len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn debug_shared_queue_bytes_used(&self) -> usize {
        let st = self.state.lock();
        st.shared_queue_bytes_used()
    }

    #[cfg(test)]
    pub(crate) fn debug_recent_rx_capacity(&self) -> (usize, usize) {
        let st = self.state.lock();
        (st.recent_rx.capacity(), st.recent_rx.max_bytes())
    }

    /// Compute a de-dupe hash for a RouterItem.
    /// Uses packet ID for Packet items, and attempts to extract packet ID from
    /// packed bytes. If extraction fails, hashes raw bytes as a fallback.
    fn get_hash(item: &RouterItem) -> u64 {
        match item {
            RouterItem::Packet(pkt) => pkt.packet_id(),
            RouterItem::Packed(bytes) => {
                match wire_format::packet_id_from_wire(bytes.as_ref()) {
                    Ok(id) => id,
                    Err(_e) => {
                        // Fallback: if bytes are malformed (or compression feature mismatch),
                        // hash raw bytes so we can still dedupe identical network duplicates.
                        let h: u64 = 0x9E37_79B9_7F4A_7C15;
                        hash_bytes_u64(h, bytes.as_ref())
                    }
                }
            }
        }
    }

    /// Remove a hash from the ring buffer of recent RX IDs.
    fn remove_pkt_id(&self, item: &RouterItem) {
        let hash = Self::get_hash(item);
        let mut st = self.state.lock();
        st.recent_rx.remove_value(&hash);
    }

    /// Compute a de-dupe ID for a RouterItem and record it.
    /// Returns true if this item was seen recently (and should be skipped).
    fn is_duplicate_pkt(&self, item: &RouterItem) -> TelemetryResult<bool> {
        let id = Self::get_hash(item);
        let mut st = self.state.lock();
        if st.recent_rx.contains(&id)
            || st
                .reliable_return_routes
                .get(&id)
                .is_some_and(|route| route.locally_delivered)
        {
            Ok(true)
        } else {
            st.push_recent_rx(id)?;
            Ok(false)
        }
    }

    /// Error helper when we have a full Packet.
    ///
    /// Sends a TelemetryError packet to all local endpoints except the failed one (if any).
    /// If no local endpoints remain, falls back to `fallback_stdout`.
    fn handle_callback_error(
        &self,
        pkt: &Packet,
        dest: Option<DataEndpoint>,
        e: TelemetryError,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        // Allocator refusal is backpressure, not a diagnostic packet. Even
        // formatting an error string can exhaust the remaining small blocks.
        if matches!(&e, TelemetryError::Io("memory pressure")) {
            return Err(e);
        }

        let device = self.sender_arc();
        let error_msg = match dest {
            Some(failed_local) => format!(
                "Handler for endpoint {:?} failed on device {:?}: {:?}",
                failed_local, device, e
            ),
            None => format!("TX Handler failed on device {:?}: {:?}", device, e),
        };

        let mut recipients: Vec<DataEndpoint> = pkt
            .endpoints()
            .iter()
            .copied()
            .filter(|&ep| self.cfg.is_local_endpoint(ep))
            .collect();
        crate::small_sort::sort(&mut recipients);
        recipients.dedup();

        if let Some(failed_local) = dest {
            recipients.retain(|&ep| ep != failed_local);
        }

        // A side TX failure cannot be reported through the same failed
        // transport. Doing so recursively creates TelemetryError packets until
        // an embedded caller exhausts its stack.
        if recipients.is_empty() && dest.is_none() {
            fallback_stdout(&error_msg);
            return Ok(());
        }

        // Local endpoint failures may still be reported to the packet's other
        // endpoints when no local error recipient exists.
        if recipients.is_empty() {
            recipients = pkt.endpoints().to_vec();
            crate::small_sort::sort(&mut recipients);
            recipients.dedup();
            if let Some(failed_local) = dest {
                recipients.retain(|&ep| ep != failed_local);
            }
        }

        if recipients.is_empty() {
            fallback_stdout(&error_msg);
            return Ok(());
        }

        let payload = make_error_payload(&error_msg);

        let sender = self.sender_arc();
        let error_pkt = Packet::new(
            DataType::TelemetryError,
            &recipients,
            sender.as_ref(),
            self.packet_timestamp_ms(),
            crate::shared_bytes::convert(payload),
        )?;

        self.emit_internal_tx(
            RouterTxItem::Broadcast(RouterItem::Packet(error_pkt)),
            false,
            called_from_queue,
        )
    }

    // ---------- PUBLIC API: queues ----------

    /// Drain the transmit queue fully.
    #[inline]
    pub fn process_tx_queue(&self) -> TelemetryResult<()> {
        self.process_tx_queue_with_timeout(0)
    }

    /// Drain both TX and RX queues fully (same semantics as `*_with_timeout(0)`).
    #[inline]
    pub fn process_all_queues(&self) -> TelemetryResult<()> {
        self.process_all_queues_with_timeout(0)
    }

    /// Clear both the transmit and receive queues without processing.
    #[inline]
    pub fn clear_queues(&self) {
        let mut st = self.state.lock();
        st.retain_transmit(|_| false);
        st.has_ordered_retry = false;
        st.received_queue.clear();
        st.rx_priority_burst = 0;
        drop(st);
        let _ = self.isr_rx_queue.clear();
    }

    /// Clear only the receive queue without processing.
    #[inline]
    pub fn clear_rx_queue(&self) {
        let mut st = self.state.lock();
        st.received_queue.clear();
        st.rx_priority_burst = 0;
        drop(st);
        let _ = self.isr_rx_queue.clear();
    }

    /// Clear queued TX without processing; retained reliable delivery can retry later.
    #[inline]
    pub fn clear_tx_queue(&self) {
        let mut st = self.state.lock();
        st.retain_transmit(|_| false);
        st.tx_priority_burst = 0;
        st.has_ordered_retry = false;
    }

    #[inline(never)]
    fn pop_transmit_queue_locked(
        st: &mut RouterInner,
        now_ms: u64,
        control_only: bool,
    ) -> Option<TxWork> {
        let slow = st.has_ordered_retry;
        let mut next_token = st.ordered_claim_seq.wrapping_add(1).max(1);
        if slow {
            while st.claim_index(next_token).is_some() {
                next_token = next_token.wrapping_add(1).max(1);
            }
        }
        let selected = st.transmit_queue.select_front_fair_with_context(
            &mut st.tx_priority_burst,
            MAX_PRIORITY_BURST,
            |item| item.priority,
            |_queue, item| {
                !matches!(item.delivery_state,
                    QueuedDelivery::ClaimedOrdered | QueuedDelivery::ClaimedUnordered
                        | QueuedDelivery::OrderedTail)
                    && item.retry_after_ms <= now_ms
                    && (!control_only || item.priority >= 200)
            },
        )?;
        let current = st.transmit_queue.get(selected)?;
        let reliable = RouterInner::reliable_original_type(current).is_some();
        let ordered = reliable && RouterInner::ordered_original_type(current).is_some();
        let (queued, claim) = if reliable {
            let queued = current.clone();
            st.transmit_queue.update_metadata(selected, |item| {
                item.delivery_state = if ordered {
                    QueuedDelivery::ClaimedOrdered
                } else {
                    QueuedDelivery::ClaimedUnordered
                };
                item.deferred_since_ms = u64::from(next_token);
            });
            st.ordered_claim_seq = next_token;
            (
                queued,
                Some(TxClaim {
                    token: next_token,
                    ordered,
                }),
            )
        } else {
            (st.transmit_queue.remove_pos(selected)?, None)
        };
        if claim.is_some() {
            st.has_ordered_retry = true;
        } else if slow {
            st.refresh_retry_hint();
        }
        Some(TxWork { queued, claim })
    }

    /// Process packets in the transmit queue for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains the queue fully.
    fn process_tx_queue_with_timeout_impl(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.expire_side_chunks();
        let start = self.clock.now_ms();
        loop {
            let received_control = crate::memory_admission::allow_drain(
                self.drain_queued_control_rx_before_tx(start, timeout_ms),
            )?;
            let control_budget_used = received_control
                && timeout_ms != 0
                && self.clock.now_ms().wrapping_sub(start) >= u64::from(timeout_ms);
            // Complete one RX/TX pair even after a cooperative RX overrun.
            // Defer timeout cancellation until queued receipts are serviced.
            if !control_budget_used {
                crate::memory_admission::allow_drain(self.process_reliable_timeouts())?;
                crate::memory_admission::allow_drain(self.process_end_to_end_reliable_timeouts())?;
            }

            let pkt_opt = {
                let mut st = self.state.lock();
                Self::pop_transmit_queue_locked(&mut st, self.clock.now_ms(), false)
            };
            let Some(pkt) = pkt_opt else { break };
            self.dispatch_queued_item(pkt)?;
            if timeout_ms != 0 && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                break;
            }
        }
        Ok(())
    }

    /// Process packets in the transmit queue for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains the queue fully.
    pub fn process_tx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "timesync")]
        let _ = crate::memory_admission::allow_drain(self.poll_timesync())?;
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        self.process_tx_queue_with_timeout_impl(timeout_ms)
    }

    /// Drain queued transmit work without generating periodic discovery/time-sync
    /// announcements. Reliable retries and queued discovery reception are still
    /// serviced. Applications using this between ingress bursts must also call
    /// `periodic` or the normal queue methods regularly for maintenance.
    /// A zero timeout drains the queue fully.
    pub fn dispatch_tx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.process_tx_queue_with_timeout_impl(timeout_ms)
    }

    /// Process a single queued receive item.
    #[inline]
    fn process_rx_queue_item(&self, item: RouterRxItem) -> TelemetryResult<()> {
        self.rx_item(&item, true)
    }

    /// Process packets in the receive queue for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains the queue fully.
    fn process_rx_queue_with_timeout_impl(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.expire_side_chunks();
        let start = self.clock.now_ms();
        loop {
            let item_opt = self.isr_rx_queue.pop_front().unwrap_or(None).or_else(|| {
                let mut st = self.state.lock();
                st.pop_received_fair()
            });
            let Some(item) = item_opt else { break };
            self.process_rx_queue_item(item)?;
            if timeout_ms != 0 && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                break;
            }
        }
        Ok(())
    }

    /// Process packets in the receive queue for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains the queue fully.
    pub fn process_rx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "timesync")]
        let _ = crate::memory_admission::allow_drain(self.poll_timesync())?;
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        self.process_rx_queue_with_timeout_impl(timeout_ms)
    }

    /// Process both transmit and receive queues for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains both queues fully.
    fn process_all_queues_with_timeout_impl(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.expire_side_chunks();
        // Share the deadline between directions. Splitting a 1 ms budget in
        // half rounded TX down to zero and serviced only one transmit item,
        // even when the remainder of the pass was idle. One TX/RX pair is
        // atomic for fairness; a slow handler may overrun the deadline.
        let start = self.clock.now_ms();
        loop {
            let received_control = crate::memory_admission::allow_drain(
                self.drain_queued_control_rx_before_tx(start, timeout_ms),
            )?;
            let mut did_any = received_control;
            let control_budget_used = received_control
                && timeout_ms != 0
                && self.clock.now_ms().wrapping_sub(start) >= u64::from(timeout_ms);
            if !control_budget_used {
                crate::memory_admission::allow_drain(self.process_reliable_timeouts())?;
                crate::memory_admission::allow_drain(self.process_end_to_end_reliable_timeouts())?;
            }

            if let Some(pkt) = {
                let mut st = self.state.lock();
                let now = self.clock.now_ms();
                // Complete one fair TX even after RX uses the deadline.
                // Priority burst limits still prefer and protect queued ACKs.
                Self::pop_transmit_queue_locked(&mut st, now, false)
            } {
                self.dispatch_queued_item(pkt)?;
                did_any = true;
            }
            // Control reception must not starve queued ACKs/transmissions.
            if control_budget_used {
                return Ok(());
            }
            if let Some(item) = self.isr_rx_queue.pop_front().unwrap_or(None).or_else(|| {
                let mut st = self.state.lock();
                st.pop_received_fair()
            }) {
                self.process_rx_queue_item(item)?;
                did_any = true;
            }
            if !did_any
                || (timeout_ms != 0
                    && self.clock.now_ms().wrapping_sub(start) >= u64::from(timeout_ms))
            {
                break;
            }
        }

        Ok(())
    }

    /// Process both transmit and receive queues for up to `timeout_ms` milliseconds.
    /// If `timeout_ms == 0`, drains both queues fully.
    pub fn process_all_queues_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "timesync")]
        let _ = crate::memory_admission::allow_drain(self.poll_timesync())?;
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        self.process_all_queues_with_timeout_impl(timeout_ms)
    }

    /// Drain queued RX/TX work without generating periodic announcements.
    /// Reliable retries and received discovery are still processed. Call
    /// `periodic` or poll discovery/time sync separately on a regular cadence.
    /// The deadline is cooperative: a single callback may exceed it.
    pub fn drain_queues_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.process_all_queues_with_timeout_impl(timeout_ms)
    }

    /// Runs one application-loop maintenance cycle.
    ///
    /// This polls built-in time sync and discovery when those features are compiled in, then
    /// drains queued TX/RX work for up to `timeout_ms` milliseconds.
    pub fn periodic(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "timesync")]
        let _ = crate::memory_admission::allow_drain(self.poll_timesync())?;

        #[cfg(feature = "discovery")]
        {
            let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        }

        self.process_all_queues_with_timeout_impl(timeout_ms)
    }

    /// Runs one application-loop maintenance cycle without polling built-in time sync.
    ///
    /// Discovery is still polled when that feature is compiled in, then queued TX/RX work is
    /// drained for up to `timeout_ms` milliseconds.
    pub fn periodic_no_timesync(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        {
            let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        }

        self.process_all_queues_with_timeout_impl(timeout_ms)
    }

    /// Enqueue an item for later transmission with flags.
    #[inline]
    fn tx_queue_item_with_flags(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
    ) -> TelemetryResult<()> {
        self.tx_queue_item_with_flags_at(item, ignore_local, 0)
    }

    #[cfg(feature = "compression")]
    fn retry_codec_owner(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        reservation: &mut Option<crate::payload_codec::QueueReservation<'_, RouterInner>>,
    ) -> TelemetryResult<()> {
        let priority = match &item {
            RouterTxItem::ToSide { data, .. } => self.item_service_priority(data)?,
            _ => return Err(TelemetryError::BadArg),
        };
        let mut state = self.state.lock();
        if let Some(reservation) = reservation {
            reservation.release_locked(&mut state);
        }
        state.push_transmit(TxQueued {
            disposable: true,
            item,
            ignore_local,
            priority,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: self.clock.now_ms().saturating_add(1),
        })
    }

    fn claim_schema_is_current(
        &self,
        ty: DataType,
        claim: Option<TxClaim>,
    ) -> TelemetryResult<bool> {
        let Some(claim) = claim else {
            return Ok(true);
        };
        let expected = if claim.ordered {
            crate::ReliableMode::Ordered
        } else {
            crate::ReliableMode::Unordered
        };
        let current = reliable_mode(ty);
        let mut st = self.state.lock();
        let owned = st.claim_index(claim.token).is_some();
        if !owned {
            return Ok(false);
        }
        if current == expected {
            return Ok(true);
        }
        st.cancel_accepted_type(ty.as_u32());
        st.refresh_retry_hint();
        Err(TelemetryError::HandlerError(
            "accepted reliable schema changed before dispatch",
        ))
    }

    fn mark_claim_local_delivered(&self, claim: Option<TxClaim>) -> bool {
        let Some(claim) = claim else {
            return true;
        };
        let mut st = self.state.lock();
        let index = st.claim_index(claim.token);
        let Some(index) = index else {
            return false;
        };
        st.transmit_queue
            .update_metadata(index, |item| item.ignore_local = true);
        true
    }

    fn dispatch_queued_item(&self, work: TxWork) -> TelemetryResult<()> {
        let queued = work.queued;
        let since = matches!(
            queued.delivery_state,
            QueuedDelivery::DeferredOrdered | QueuedDelivery::DeferredUnordered
        )
        .then_some(queued.deferred_since_ms);
        if !self.claim_schema_is_current(DataType(queued.accepted_type), work.claim)? {
            return Ok(());
        }
        let mut context = DispatchContext {
            claim: work.claim,
            since,
            terminal: false,
            owner_transferred: false,
        };
        let mut result =
            self.tx_item_impl_with_retry(queued.item, queued.ignore_local, true, &mut context);
        if let Some(claim) = work.claim {
            let mut st = self.state.lock();
            if result.is_err() && !context.terminal && !context.owner_transferred {
                let Some(index) = st.claim_index(claim.token) else {
                    return result;
                };
                let original = st.transmit_queue.get(index).expect("claimed owner");
                if !original.ignore_local
                    && let RouterTxItem::Broadcast(data) = &original.item
                {
                    let id = Self::get_hash(data);
                    st.recent_rx.remove_value(&id);
                }
                drop(st);
                result = self.defer_accepted_original(&mut context);
                if result.is_ok() {
                    return Ok(());
                }
                st = self.state.lock();
            }
            if let Some(index) = st.claim_index(claim.token) {
                if context.terminal && claim.ordered {
                    let ty = st
                        .transmit_queue
                        .get(index)
                        .expect("claimed owner")
                        .accepted_type;
                    st.cancel_accepted_type(ty);
                } else {
                    let ty = st.transmit_queue.get(index).expect("claimed owner").accepted_type;
                    let _ = st.transmit_queue.remove_pos(index);
                    if claim.ordered {
                        // Exactly one FIFO head per Ordered type can be eligible.
                        // Promotion changes metadata only, retaining the admitted payload.
                        let next = st.transmit_queue.iter().position(|item|
                            item.delivery_state == QueuedDelivery::OrderedTail && item.accepted_type == ty);
                        if let Some(next) = next {
                            st.transmit_queue.update_metadata(next, |item| item.delivery_state = QueuedDelivery::Ordered);
                        }
                    }
                }
            }
            st.refresh_retry_hint();
        }
        result
    }

    fn expire_deferred_original(
        &self,
        ty: DataType,
        since: u64,
        ordered: bool,
    ) -> TelemetryResult<()> {
        let lifetime = runtime_reliable_retransmit_ms()
            .saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
        let now = self.clock.now_ms();
        if now >= since && now - since < lifetime {
            return Ok(());
        }
        if ordered {
            let mut st = self.state.lock();
            st.cancel_accepted_type(ty.as_u32());
            st.refresh_retry_hint();
        }
        Err(TelemetryError::HandlerError(
            "accepted reliable delivery expired before dispatch",
        ))
    }

    fn defer_accepted_original(&self, context: &mut DispatchContext) -> TelemetryResult<()> {
        let Some(claim) = context.claim else {
            return Err(TelemetryError::Io("reliable owner unavailable"));
        };
        let now = self.clock.now_ms();
        let Some(retry_after_ms) = now.checked_add(1) else {
            context.terminal = true;
            return Err(TelemetryError::HandlerError(
                "accepted reliable clock exhausted",
            ));
        };
        let mut st = self.state.lock();
        let Some(index) = st.claim_index(claim.token) else {
            return Ok(());
        };
        st.transmit_queue.update_metadata(index, |item| {
            item.delivery_state = if claim.ordered {
                QueuedDelivery::DeferredOrdered
            } else {
                QueuedDelivery::DeferredUnordered
            };
            item.deferred_since_ms = context.since.unwrap_or(now);
            item.retry_after_ms = retry_after_ms;
        });
        st.has_ordered_retry = true;
        Ok(())
    }

    #[allow(unused_mut)]
    fn replace_claim_payload(&self, claim: TxClaim, mut data: RouterItem) -> TelemetryResult<()> {
        #[cfg(feature = "compact-packet-store")]
        data.park_for_queue()?;
        let payload_cost = match &data {
            RouterItem::Packet(packet) => packet.byte_cost(),
            RouterItem::Packed(bytes) => size_of::<crate::SharedBytes>() + bytes.len(),
        };
        let mut st = self.state.lock();
        let Some(index) = st.claim_index(claim.token) else {
            return Ok(());
        };
        let original = st.transmit_queue.get(index).expect("claimed owner");
        let old_cost = original.byte_cost();
        let new_cost = old_cost
            .saturating_sub(original.item.byte_cost())
            .saturating_add(payload_cost);
        let priority = original.priority;
        let growth = new_cost.saturating_sub(old_cost);
        if growth != 0 {
            st.make_shared_queue_room(growth, priority, None)?;
        }
        let Some(index) = st.claim_index(claim.token) else {
            return Ok(());
        };
        st.transmit_queue.update_admitted(index, new_cost, |item| {
            item.item = RouterTxItem::Broadcast(data)
        })
    }

    fn tx_queue_item_for_retry(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
    ) -> TelemetryResult<()> {
        self.tx_queue_item_with_flags_at(item, ignore_local, self.clock.now_ms().saturating_add(1))
    }

    fn tx_queue_item_with_flags_at(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        retry_after_ms: u64,
    ) -> TelemetryResult<()> {
        let priority = match &item {
            RouterTxItem::Broadcast(data) => self.item_service_priority(data)?,
            RouterTxItem::EndToEndReplay { .. } => {
                Self::router_item_priority_bumped(DataType::ReliableAck)
            }
            RouterTxItem::ToSide { data, .. } => self.item_service_priority(data)?,
            RouterTxItem::ReliableReplay { ty, .. } => Self::router_item_priority_bumped(*ty),
        };
        self.tx_queue_item_with_priority_at(item, ignore_local, priority, retry_after_ms)
    }

    #[inline]
    fn tx_queue_item_with_priority(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        priority: u8,
    ) -> TelemetryResult<()> {
        self.tx_queue_item_with_priority_at(item, ignore_local, priority, 0)
    }

    fn tx_queue_item_with_priority_at(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        priority: u8,
        retry_after_ms: u64,
    ) -> TelemetryResult<()> {
        let mut st = self.state.lock();
        st.push_transmit(TxQueued {
            disposable: true,
            item,
            ignore_local,
            priority,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms,
        })?;
        Ok(())
    }

    /// Enqueue an item for later transmission (default: local dispatch enabled).
    #[inline]
    fn tx_queue_item(&self, item: RouterTxItem) -> TelemetryResult<()> {
        self.tx_queue_item_with_flags(item, false)
    }

    #[cfg(feature = "std")]
    #[inline]
    fn try_enter_side_tx(&self, side: usize) -> Option<crate::lock::ActiveSideTxGuard<'_>> {
        let gate = self
            .state
            .lock()
            .side_transport
            .get(&side)?
            .tx_callback_gate
            .clone();
        self.side_tx_activity.try_enter(gate)
    }
    #[cfg(not(feature = "std"))]
    #[inline]
    fn try_enter_side_tx(&self, _side: usize) -> Option<crate::lock::ReentryGuard<'_>> {
        self.side_tx_gate.try_enter()
    }
    #[inline]
    fn side_tx_active(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.side_tx_activity.is_active()
        }
        #[cfg(not(feature = "std"))]
        {
            self.side_tx_gate.is_active()
        }
    }

    // ---------- PUBLIC API: RX queue ----------

    /// Drain the receive queue fully.
    #[inline]
    pub fn process_rx_queue(&self) -> TelemetryResult<()> {
        self.process_rx_queue_with_timeout(0)
    }

    /// Enqueue packed bytes for RX processing as locally-originated input.
    #[inline]
    pub fn rx_packed_queue(&self, bytes: &[u8]) -> TelemetryResult<()> {
        crate::memory_admission::check_receive(bytes)?;
        let data = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(bytes)));
        let priority = self.item_service_priority(&data)?;
        let mut st = self.state.lock();
        st.push_received(RouterRxItem {
            src: None,
            data,
            priority,
        })?;
        Ok(())
    }

    /// ISR-safe, non-blocking enqueue of packed bytes for RX processing.
    ///
    /// Returns `TelemetryError::Io("rx queue busy")` if another context is
    /// currently mutating the ISR RX queue.
    #[inline]
    pub fn rx_packed_queue_isr(&self, bytes: &[u8]) -> TelemetryResult<()> {
        crate::memory_admission::check_receive(bytes)?;
        let data = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(bytes)));
        let priority = Self::router_item_priority(&data)?;
        self.isr_rx_queue.push_back_prioritized(RouterRxItem {
            src: None,
            data,
            priority,
        })
    }

    /// Enqueue a decoded packet for RX processing as locally-originated input.
    #[inline]
    pub fn rx_queue(&self, pkt: Packet) -> TelemetryResult<()> {
        pkt.validate()?;
        let data = RouterItem::Packet(pkt);
        let priority = self.item_service_priority(&data)?;
        let mut st = self.state.lock();
        st.push_received(RouterRxItem {
            src: None,
            data,
            priority,
        })?;
        Ok(())
    }

    /// ISR-safe, non-blocking enqueue of a packet for RX processing.
    ///
    /// Returns `TelemetryError::Io("rx queue busy")` if another context is
    /// currently mutating the ISR RX queue.
    #[inline]
    pub fn rx_queue_isr(&self, pkt: Packet) -> TelemetryResult<()> {
        pkt.validate()?;
        let data = RouterItem::Packet(pkt);
        let priority = Self::router_item_priority(&data)?;
        self.isr_rx_queue.push_back_prioritized(RouterRxItem {
            src: None,
            data,
            priority,
        })
    }

    /// Enqueue a decoded packet for RX processing with an explicit ingress side.
    #[inline]
    pub fn rx_queue_from_side(&self, pkt: Packet, side: RouterSideId) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(side)?;
        pkt.validate()?;
        let data = RouterItem::Packet(pkt);
        let priority = self.item_service_priority(&data)?;
        let mut st = self.state.lock();
        st.push_received(RouterRxItem {
            src: Some(side),
            data,
            priority,
        })?;
        Ok(())
    }

    /// ISR-safe, non-blocking enqueue of a packet with explicit source side.
    ///
    /// Returns `TelemetryError::Io("rx queue busy")` if another context is
    /// currently mutating the ISR RX queue.
    #[inline]
    pub fn rx_queue_from_side_isr(&self, pkt: Packet, side: RouterSideId) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(side)?;
        pkt.validate()?;
        let data = RouterItem::Packet(pkt);
        let priority = Self::router_item_priority(&data)?;
        self.isr_rx_queue.push_back_prioritized(RouterRxItem {
            src: Some(side),
            data,
            priority,
        })
    }

    /// Enqueue packed bytes for RX processing with an explicit ingress side.
    #[inline]
    pub fn rx_packed_queue_from_side(
        &self,
        bytes: &[u8],
        side: RouterSideId,
    ) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(side)?;
        let Some(decoded) = self.decode_side_transport_frame(side, bytes)? else {
            return Ok(());
        };
        let data = RouterItem::Packed(decoded);
        let priority = self.item_service_priority(&data)?;
        let mut st = self.state.lock();
        st.push_received(RouterRxItem {
            src: Some(side),
            data,
            priority,
        })?;
        Ok(())
    }

    /// ISR-safe, non-blocking enqueue of packed bytes with source side.
    ///
    /// Returns `TelemetryError::Io("rx queue busy")` if another context is
    /// currently mutating the ISR RX queue.
    #[inline]
    pub fn rx_packed_queue_from_side_isr(
        &self,
        bytes: &[u8],
        side: RouterSideId,
    ) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(side)?;
        crate::memory_admission::check_receive(bytes)?;
        let data = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(bytes)));
        let priority = Self::router_item_priority(&data)?;
        self.isr_rx_queue.push_back_prioritized(RouterRxItem {
            src: Some(side),
            data,
            priority,
        })
    }

    fn retry_with_attempts<F, T>(
        &self,
        times: usize,
        f: F,
    ) -> Result<(T, usize), (TelemetryError, usize)>
    where
        F: Fn() -> TelemetryResult<T>,
    {
        let mut last_err = None;
        for attempt in 0..times {
            match f() {
                Ok(v) => return Ok((v, attempt + 1)),
                // Transport or allocator pressure needs another service pass;
                // repeating the same callback synchronously cannot clear it.
                Err(e) if Self::is_transient_tx_error(&e) => return Err((e, attempt + 1)),
                Err(e) => last_err = Some((e, attempt + 1)),
            }
        }
        Err(last_err.expect("times > 0"))
    }

    /// Check if the specified endpoint has a packet handler registered.
    #[inline]
    fn endpoint_has_packet_handler(&self, ep: DataEndpoint) -> bool {
        self.cfg
            .handlers
            .iter()
            .any(|h| h.endpoint == ep && matches!(h.handler, EndpointHandlerFn::Packet(_)))
    }

    /// Check if the specified endpoint has a packed handler registered.
    #[inline]
    fn endpoint_has_packed_handler(&self, ep: DataEndpoint) -> bool {
        self.cfg
            .handlers
            .iter()
            .any(|h| h.endpoint == ep && matches!(h.handler, EndpointHandlerFn::Packed(_)))
    }

    fn packet_has_local_handler(&self, pkt: &Packet) -> bool {
        pkt.endpoints()
            .iter()
            .copied()
            .any(|ep| self.endpoint_has_packet_handler(ep) || self.endpoint_has_packed_handler(ep))
    }

    /// Whether receiving this packet constitutes delivery at this router.
    ///
    /// Network variables deliberately use their cache/update callback instead of a conventional
    /// endpoint handler. Treat that successful cache delivery as local for end-to-end ACKs;
    /// otherwise a reliable writer waits forever for every variable owner that does not also
    /// happen to register an unrelated packet handler for the variable's endpoint.
    fn packet_has_local_delivery(&self, pkt: &Packet) -> bool {
        self.packet_has_local_handler(pkt) || self.is_managed_variable_type(pkt.data_type())
    }

    /// Call the specified endpoint handler with retries on failure.
    ///
    /// - `data` is present when called from RX processing (queue or immediate).
    /// - `pkt_for_ctx` is required for Packet handlers.
    /// - `env_for_ctx` provides header-only context when we haven't unpacked.
    fn call_handler_with_retries(
        &self,
        dest: DataEndpoint,
        handler: &EndpointHandler,
        data: Option<&[u8]>,
        pkt_for_ctx: Option<&Packet>,
        env_for_ctx: Option<&wire_format::TelemetryEnvelope>,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        let owned_tmp: Option<RouterItem>;

        let item_for_ctx: &RouterItem = match (data, pkt_for_ctx) {
            (Some(d), _) => {
                owned_tmp = Some(RouterItem::Packed(crate::shared_bytes::convert(
                    Arc::<[u8]>::from(d),
                )));
                owned_tmp.as_ref().unwrap()
            }
            (None, Some(pkt)) => {
                owned_tmp = Some(RouterItem::Packet(pkt.clone()));
                owned_tmp.as_ref().unwrap()
            }
            (None, None) => {
                debug_assert!(
                    false,
                    "call_handler_with_retries called without data or packet context"
                );
                return Ok(());
            }
        };

        match (&handler.handler, data) {
            (EndpointHandlerFn::Packet(f), _) => {
                let pkt = pkt_for_ctx.expect("Packet handler requires Packet context");
                with_retries(
                    self,
                    dest,
                    item_for_ctx,
                    pkt_for_ctx,
                    env_for_ctx,
                    called_from_queue,
                    || f(pkt),
                )
            }

            (EndpointHandlerFn::Packed(f), Some(bytes)) => with_retries(
                self,
                dest,
                item_for_ctx,
                pkt_for_ctx,
                env_for_ctx,
                called_from_queue,
                || f(bytes),
            ),

            (EndpointHandlerFn::Packed(_), None) => Ok(()),
        }
    }

    /// Error helper when we only have an envelope (no full packet).
    ///
    /// Sends a TelemetryError packet to all local endpoints except the failed one (if any).
    /// If no local endpoints remain, falls back to `fallback_stdout`.
    fn handle_callback_error_from_env(
        &self,
        env: &wire_format::TelemetryEnvelope,
        dest: Option<DataEndpoint>,
        e: TelemetryError,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        // Allocator refusal is backpressure, not a diagnostic packet. Even
        // formatting an error string can exhaust the remaining small blocks.
        if matches!(&e, TelemetryError::Io("memory pressure")) {
            return Err(e);
        }

        let mut recipients: Vec<DataEndpoint> = env
            .endpoints
            .iter()
            .copied()
            .filter(|&ep| self.cfg.is_local_endpoint(ep))
            .collect();
        crate::small_sort::sort(&mut recipients);
        recipients.dedup();
        if let Some(failed) = dest {
            recipients.retain(|&ep| ep != failed);
        }

        let device = self.sender_arc();
        let error_msg = format!(
            "Handler for endpoint {:?} failed on device {:?}: {:?}",
            dest, device, e
        );

        if recipients.is_empty() && dest.is_none() {
            fallback_stdout(&error_msg);
            return Ok(());
        }

        if recipients.is_empty() {
            recipients = env.endpoints.to_vec();
            crate::small_sort::sort(&mut recipients);
            recipients.dedup();
            if let Some(failed) = dest {
                recipients.retain(|&ep| ep != failed);
            }
        }

        if recipients.is_empty() {
            fallback_stdout(&error_msg);
            return Ok(());
        }

        let payload = make_error_payload(&error_msg);

        let error_pkt = Packet::new(
            DataType::TelemetryError,
            &recipients,
            &env.sender.clone(),
            env.timestamp_ms,
            crate::shared_bytes::convert(payload),
        )?;
        self.emit_internal_tx(
            RouterTxItem::Broadcast(RouterItem::Packet(error_pkt)),
            false,
            called_from_queue,
        )
    }

    fn handle_internal_reliable_packet(
        &self,
        pkt: &Packet,
        src: Option<RouterSideId>,
        called_from_queue: bool,
    ) -> TelemetryResult<bool> {
        if !matches!(
            pkt.data_type(),
            DataType::ReliableAck | DataType::ReliablePartialAck | DataType::ReliablePacketRequest
        ) {
            return Ok(false);
        }

        let Some(src) = src else {
            return Ok(false);
        };

        if Self::is_end_to_end_ack_packet(pkt)
            && let Ok(packet_id) = Self::decode_end_to_end_reliable_ack(pkt.payload())
        {
            let alias = {
                let st = self.state.lock();
                st.reliable_return_routes
                    .get(&packet_id)
                    .filter(|route| route.upstream_contract.is_some())
                    .cloned()
            };
            if let Some(alias) = alias {
                let (upstream_id, publisher_hash) = alias.upstream_contract.expect("checked alias");
                #[cfg(feature = "std")]
                if reliable_trace_enabled() {
                    eprintln!(
                        "[sedsnet-reliable] proxy receipt id={packet_id:#x} upstream={upstream_id:#x} owner={:?}",
                        Self::end_to_end_ack_sender_hash(pkt)
                    );
                }
                let completed = {
                    let mut st = self.state.lock();
                    if let Some(sent) = st.end_to_end_reliable_tx.get_mut(&packet_id) {
                        if let Some(owner) = Self::end_to_end_ack_sender_hash(pkt) {
                            sent.pending_destinations.remove(&owner);
                        }
                        if !sent.pending_destinations.is_empty() {
                            return Ok(true);
                        }
                        st.end_to_end_reliable_tx.remove(&packet_id);
                        true
                    } else {
                        // An expired replay record is not evidence that the
                        // whole child cohort completed. Let the parent retry.
                        return Ok(true);
                    }
                };
                if completed {
                    let mut st = self.state.lock();
                    if Self::remember_reliable_return_route_locked(&mut st, upstream_id) {
                        st.reliable_return_routes.insert(
                            upstream_id,
                            ReliableReturnRouteState {
                                side: alias.side,
                                locally_delivered: false,
                                last_replay_ms: alias.last_replay_ms,
                                upstream_contract: None,
                            },
                        );
                    }
                }
                self.queue_end_to_end_reliable_ack_for_sender_hash(
                    upstream_id,
                    publisher_hash,
                    called_from_queue,
                )?;
                self.release_ordered_successors()?;
                return Ok(true);
            }
            // Relays may also keep a retransmission record for the forwarded
            // packet. Clearing that local record must not consume an ACK whose
            // frozen wire contract targets the original sender beyond this
            // router; it still has to travel back along the learned return
            // route. This occurs when a router is itself one managed-variable
            // owner while additional owners sit behind another side.
            let targets_local_sender = pkt.wire_target_senders().is_empty()
                || pkt
                    .wire_target_senders()
                    .contains(&Self::sender_hash(self.sender_arc().as_ref()));
            let mut st = self.state.lock();
            if let Some(sent) = st.end_to_end_reliable_tx.get_mut(&packet_id) {
                if sent.waiting_for_predecessor {
                    return Ok(targets_local_sender);
                }
                if let Some(sender_hash) = Self::end_to_end_ack_sender_hash(pkt) {
                    let _removed = sent.pending_destinations.remove(&sender_hash);
                    #[cfg(feature = "std")]
                    if reliable_trace_enabled() {
                        eprintln!(
                            "[sedsnet-reliable] receipt time={} id={packet_id:#x} sender={sender_hash:#x} matched={} remaining={:?}",
                            self.clock.now_ms(),
                            _removed.is_some(),
                            sent.pending_destinations
                        );
                    }
                    if sent.pending_destinations.is_empty() {
                        st.end_to_end_reliable_tx.remove(&packet_id);
                    }
                    drop(st);
                    self.release_ordered_successors()?;
                    return Ok(targets_local_sender);
                }
                st.end_to_end_reliable_tx.remove(&packet_id);
                drop(st);
                self.release_ordered_successors()?;
                return Ok(targets_local_sender);
            }
            // A late or duplicate receipt addressed to this publisher is
            // complete locally; it must not leak onto another network side.
            return Ok(targets_local_sender);
        }

        let vals = pkt.data_as_u32()?;
        if vals.len() != 2 {
            return Err(TelemetryError::Unpack("bad reliable control payload"));
        }
        let ty = DataType::try_from_u32(vals[0]).ok_or(TelemetryError::InvalidType)?;
        let seq = vals[1];

        match pkt.data_type() {
            DataType::ReliableAck => {
                self.handle_reliable_ack(src, ty, seq);
                Ok(true)
            }
            DataType::ReliablePartialAck => {
                self.handle_reliable_partial_ack(src, ty, seq);
                Ok(true)
            }
            DataType::ReliablePacketRequest => {
                self.queue_reliable_retransmit(src, ty, seq, called_from_queue)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Core receive function handling both Packet and Packed items.
    ///
    /// Relay mode: if a destination endpoint has no matching local handler and the packet has
    /// any remotely-forwardable endpoints, the router will rebroadcast the packet ONCE, excluding
    /// the ingress side.
    fn rx_item(&self, item: &RouterRxItem, called_from_queue: bool) -> TelemetryResult<()> {
        // Reuse this CRC-validated borrowed envelope for accounting and
        // role/return-route checks in this invocation. Dispatch still rechecks
        // current routing metadata; no validation result survives queueing.
        let packed_frame = match &item.data {
            RouterItem::Packed(bytes) => Some(wire_format::peek_routing_frame_info(bytes.as_ref())),
            RouterItem::Packet(_) => None,
        };
        if crate::memory_admission::supports_work_kinds()
            && let (Some(side), RouterItem::Packed(bytes)) = (item.src, &item.data)
        {
            self.admit_received_frame_with_view(
                side,
                bytes,
                packed_frame.as_ref().and_then(|frame| frame.as_ref().ok()),
            )?;
        }
        let packed_routing = packed_frame
            .as_ref()
            .and_then(|frame| frame.as_ref().ok())
            .map(|frame| &frame.envelope);
        if let Some(src) = item.src {
            self.ensure_side_ingress_enabled(src)?;
            match &item.data {
                RouterItem::Packet(pkt) => {
                    let bytes = wire_format::packet_wire_size(pkt);
                    self.note_side_rx(src, pkt.data_type(), bytes, true);
                }
                RouterItem::Packed(bytes) => {
                    if let Some(env) = packed_routing.as_ref() {
                        self.note_side_rx(src, env.ty, bytes.len(), true);
                    }
                }
            }
            match &item.data {
                RouterItem::Packet(pkt) => {
                    if (is_reliable_type(pkt.data_type()) || !pkt.wire_target_senders().is_empty())
                        && !is_internal_control_type(pkt.data_type())
                        && !self.note_reliable_return_route(src, pkt.packet_id())
                    {
                        return Ok(());
                    }
                }
                RouterItem::Packed(bytes) => {
                    if let Some(env) = packed_routing.as_ref()
                        && (is_reliable_type(env.ty) || env.target_senders().len() != 0)
                        && !is_internal_control_type(env.ty)
                        && let Ok(packet_id) = wire_format::packet_id_from_wire(bytes.as_ref())
                        && !self.note_reliable_return_route(src, packet_id)
                    {
                        return Ok(());
                    }
                }
            }
        }
        match &item.data {
            RouterItem::Packet(pkt) => {
                if !is_internal_control_type(pkt.data_type()) {
                    self.remember_managed_variable_packet(pkt)?;
                }
            }
            RouterItem::Packed(bytes) => {
                if let Some(env) = packed_routing.as_ref()
                    && !is_internal_control_type(env.ty)
                    && self.is_managed_variable_type(env.ty)
                {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    self.remember_managed_variable_packet(&pkt)?;
                }
            }
        }
        let mut released_buffered: Vec<crate::SharedBytes> = Vec::new();
        if let (Some(src), RouterItem::Packed(bytes)) = (item.src, &item.data) {
            let (_opts, handler_is_packed, hop_reliable_enabled) = {
                let st = self.state.lock();
                let side_ref = Self::side_ref(&st, src)?;
                let opts = side_ref.opts.clone();
                (
                    opts.clone(),
                    matches!(
                        side_ref.tx_handler,
                        RouterTxHandlerFn::Packed(_) | RouterTxHandlerFn::PackedWithPriority(_)
                    ),
                    opts.reliable_enabled
                        && self.cfg.reliable_enabled()
                        && !self.side_has_multiple_announcers_locked(&st, src, self.clock.now_ms()),
                )
            };

            if hop_reliable_enabled && handler_is_packed {
                let frame = match packed_frame
                    .as_ref()
                    .expect("packed frame")
                    .as_ref()
                    .map_err(Clone::clone)
                {
                    Ok(frame) => frame,
                    Err(e) => {
                        if matches!(e, TelemetryError::Unpack(msg) if msg == "crc32 mismatch") {
                            if let Ok(frame) =
                                wire_format::peek_frame_info_unchecked(bytes.as_ref())
                                && is_reliable_type(frame.envelope.ty)
                                && let Some(hdr) = frame.reliable
                            {
                                let unordered =
                                    (hdr.flags & wire_format::RELIABLE_FLAG_UNORDERED) != 0;
                                let unsequenced =
                                    (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) != 0;

                                if !unsequenced {
                                    let requested = if unordered {
                                        hdr.seq
                                    } else {
                                        let mut st = self.state.lock();
                                        let rx_state = self.reliable_rx_state_mut(
                                            &mut st,
                                            src,
                                            frame.envelope.ty,
                                        );
                                        rx_state.expected_seq.min(hdr.seq)
                                    };
                                    self.queue_reliable_packet_request(
                                        src,
                                        frame.envelope.ty,
                                        requested,
                                        called_from_queue,
                                    )?;
                                }
                            }
                            return Ok(());
                        }
                        return Err(e);
                    }
                };
                if is_reliable_type(frame.envelope.ty)
                    && let Some(hdr) = frame.reliable
                {
                    if frame.ack_only() {
                        self.handle_reliable_ack(src, frame.envelope.ty, hdr.ack);
                        return Ok(());
                    }
                    let unordered = (hdr.flags & wire_format::RELIABLE_FLAG_UNORDERED) != 0;
                    let unsequenced = (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) != 0;

                    if !unsequenced {
                        if unordered {
                            self.queue_reliable_ack(
                                src,
                                frame.envelope.ty,
                                hdr.seq,
                                called_from_queue,
                            )?;
                        } else {
                            let mut release: Vec<crate::SharedBytes> = Vec::new();
                            let mut last_delivered = None;
                            let mut ack_old = None;
                            let mut request_missing = None;
                            let mut partial_ack = None;
                            {
                                let mut st = self.state.lock();
                                let rx_state =
                                    self.reliable_rx_state_mut(&mut st, src, frame.envelope.ty);
                                let expected_seq = rx_state.expected_seq;
                                if hdr.seq < expected_seq {
                                    ack_old = Some(expected_seq.saturating_sub(1));
                                } else if hdr.seq > expected_seq {
                                    request_missing = Some(expected_seq);
                                    partial_ack = Some(hdr.seq);
                                    st.buffer_reliable_rx(
                                        src,
                                        frame.envelope.ty,
                                        hdr.seq,
                                        bytes.clone(),
                                    )?;
                                } else {
                                    release.push(bytes.clone());
                                    last_delivered = Some(hdr.seq);
                                    let mut next_expected = hdr.seq.wrapping_add(1);
                                    while let Some(buf) = rx_state.buffered.remove(&next_expected) {
                                        release.push(buf);
                                        last_delivered = Some(next_expected);
                                        let next = next_expected.wrapping_add(1);
                                        next_expected = if next == 0 { 1 } else { next };
                                    }
                                    rx_state.expected_seq = next_expected;
                                }
                            }

                            if let Some(ack_seq) = ack_old {
                                self.queue_reliable_ack(
                                    src,
                                    frame.envelope.ty,
                                    ack_seq,
                                    called_from_queue,
                                )?;
                                return Ok(());
                            }
                            if let Some(request_seq) = request_missing {
                                if let Some(partial_seq) = partial_ack {
                                    self.queue_reliable_partial_ack(
                                        src,
                                        frame.envelope.ty,
                                        partial_seq,
                                        called_from_queue,
                                    )?;
                                }
                                self.queue_reliable_packet_request(
                                    src,
                                    frame.envelope.ty,
                                    request_seq,
                                    called_from_queue,
                                )?;
                                return Ok(());
                            }

                            if let Some(ack_seq) = last_delivered {
                                self.queue_reliable_ack(
                                    src,
                                    frame.envelope.ty,
                                    ack_seq,
                                    called_from_queue,
                                )?;
                            }

                            released_buffered.extend(release.into_iter().skip(1));
                        }
                    }
                }
            } else {
                match packed_frame
                    .as_ref()
                    .expect("packed frame")
                    .as_ref()
                    .map_err(Clone::clone)
                {
                    Ok(frame) => {
                        if frame.ack_only() {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        if matches!(e, TelemetryError::Unpack(msg) if msg == "crc32 mismatch") {
                            return Ok(());
                        }
                        return Err(e);
                    }
                }
            }
        }

        if self.is_duplicate_pkt(&item.data)? {
            // A final-ACK retry must cross a router again. Do not redeliver it
            // locally, and rate-limit repeated forwarding to avoid echo loops.
            if (item.src.is_some() && self.item_targets_another_sender(&item.data)?)
                || (item.src.is_some() && self.should_route_remote(&item.data, item.src)? && {
                    let (endpoints, _) = self.item_route_info(&item.data)?;
                    self.item_targets_router_as_intermediate_hop(&item.data, &endpoints)?
                })
            {
                let id = Self::get_hash(&item.data);
                let replay = {
                    let mut st = self.state.lock();
                    st.reliable_return_routes.get_mut(&id).is_some_and(|route| {
                        let now = self.clock.now_ms();
                        if now.saturating_sub(route.last_replay_ms)
                            < runtime_reliable_retransmit_ms()
                        {
                            return false;
                        }
                        route.last_replay_ms = now;
                        true
                    })
                };
                if replay {
                    self.relay_send(item.data.clone(), item.src, called_from_queue)?;
                }
            }
            if item.src.is_some() {
                let local_sender = self.sender_arc();
                match &item.data {
                    RouterItem::Packet(pkt)
                        if (is_reliable_type(pkt.data_type())
                            || !pkt.wire_target_senders().is_empty())
                            && pkt.sender() != local_sender.as_ref()
                            && self.item_targets_local_sender(&item.data)?
                            && self.packet_has_local_delivery(pkt)
                            && !(self.should_route_remote(&item.data, item.src)?
                                && self.item_targets_router_as_intermediate_hop(
                                    &item.data,
                                    pkt.endpoints(),
                                )?) =>
                    {
                        self.queue_end_to_end_reliable_ack(pkt, called_from_queue)?;
                    }
                    RouterItem::Packed(bytes) => {
                        if let Ok(pkt) = self.unpack_packet_for_role(bytes.as_ref())
                            && (is_reliable_type(pkt.data_type())
                                || !pkt.wire_target_senders().is_empty())
                            && pkt.sender() != local_sender.as_ref()
                            && self.item_targets_local_sender(&item.data)?
                            && self.packet_has_local_delivery(&pkt)
                            && !(self.should_route_remote(&item.data, item.src)?
                                && self.item_targets_router_as_intermediate_hop(
                                    &item.data,
                                    pkt.endpoints(),
                                )?)
                        {
                            let packet_id = wire_format::packet_id_from_wire(bytes.as_ref())
                                .unwrap_or_else(|_| pkt.packet_id());
                            self.queue_end_to_end_reliable_ack_for_packet_id(
                                packet_id,
                                pkt.sender(),
                                called_from_queue,
                            )?;
                        }
                    }
                    _ => {}
                }
            }
            return Ok(());
        }

        self.dispatch_rx_data(item, called_from_queue)?;

        for release_bytes in released_buffered {
            let release_data = RouterItem::Packed(release_bytes.clone());
            if self.is_duplicate_pkt(&release_data)? {
                continue;
            }
            let release_item = RouterRxItem {
                src: item.src,
                priority: Self::router_item_priority(&release_data)?,
                data: release_data,
            };
            self.dispatch_rx_data(&release_item, called_from_queue)?;
        }

        Ok(())
    }

    fn dispatch_rx_data(
        &self,
        item: &RouterRxItem,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        match &item.data {
            RouterItem::Packet(pkt) => {
                pkt.validate()?;
                #[cfg(feature = "discovery")]
                if let Some(side) = item.src {
                    self.refresh_peer_liveness(side, sender_address_u32(pkt.sender()));
                }

                if self.handle_internal_reliable_packet(pkt, item.src, called_from_queue)? {
                    return Ok(());
                }

                if pkt.data_type() == DataType::P2pMessage {
                    if self.item_targets_local_sender(&item.data)? {
                        self.dispatch_p2p_packet(pkt)?;
                        if item.src.is_some() {
                            self.queue_end_to_end_reliable_ack(pkt, called_from_queue)?;
                        }
                    }
                    if self.should_route_remote(&item.data, item.src)? {
                        self.relay_send(
                            RouterItem::Packet(pkt.to_owned()),
                            item.src,
                            called_from_queue,
                        )?;
                    }
                    return Ok(());
                }

                #[cfg(feature = "timesync")]
                if matches!(
                    pkt.data_type(),
                    DataType::TimeSyncAnnounce
                        | DataType::TimeSyncRequest
                        | DataType::TimeSyncResponse
                ) {
                    self.handle_internal_timesync_packet(pkt, item.src, called_from_queue)?;
                    return Ok(());
                }

                if self.learn_discovery_packet(pkt, item.src, called_from_queue)? {
                    // Reachability advertisements are hop-local. Learning one
                    // schedules this Router's own aggregated, split-horizon
                    // snapshot; transparently relaying the original packet
                    // would make a distant sender look physically adjacent.
                    if !discovery_is_hop_local_advertisement(pkt.data_type())
                        && self.should_route_remote(&item.data, item.src)?
                    {
                        self.relay_send(
                            RouterItem::Packet(pkt.to_owned()),
                            item.src,
                            called_from_queue,
                        )?;
                    }
                    return Ok(());
                }

                let mut eps: Vec<DataEndpoint> = pkt.endpoints().to_vec();
                crate::small_sort::sort(&mut eps);
                eps.dedup();
                let had_local_handler = eps.iter().copied().any(|ep| {
                    self.endpoint_has_packet_handler(ep) || self.endpoint_has_packed_handler(ep)
                });
                let had_local_delivery =
                    had_local_handler || self.is_managed_variable_type(pkt.data_type());

                let has_remote = self.should_route_remote(&item.data, item.src)?;
                let targets_local = self.item_targets_local_sender(&item.data)?;

                let has_packed_local = eps
                    .iter()
                    .copied()
                    .any(|ep| self.endpoint_has_packed_handler(ep));
                let bytes_opt = if has_packed_local {
                    Some(wire_format::pack_packet(pkt))
                } else {
                    None
                };

                let mut local_delivery_error = None;
                if targets_local {
                    for dest in eps {
                        for h in self.cfg.handlers.iter().filter(|h| h.endpoint == dest) {
                            let result = match (&h.handler, &bytes_opt) {
                                (EndpointHandlerFn::Packed(_), Some(bytes)) => self
                                    .call_handler_with_retries(
                                        dest,
                                        h,
                                        Some(bytes.as_ref()),
                                        Some(pkt),
                                        None,
                                        called_from_queue,
                                    ),
                                (EndpointHandlerFn::Packed(_), None) => {
                                    let bytes = wire_format::pack_packet(pkt);
                                    self.call_handler_with_retries(
                                        dest,
                                        h,
                                        Some(bytes.as_ref()),
                                        Some(pkt),
                                        None,
                                        called_from_queue,
                                    )
                                }
                                (EndpointHandlerFn::Packet(_), _) => self
                                    .call_handler_with_retries(
                                        dest,
                                        h,
                                        None,
                                        Some(pkt),
                                        None,
                                        called_from_queue,
                                    ),
                            };
                            if let Err(error) = result {
                                if let Some(src) = item.src {
                                    self.note_side_local_handler_failure(
                                        src,
                                        pkt.data_type(),
                                        runtime_max_handler_retries(),
                                    );
                                }
                                local_delivery_error.get_or_insert(error);
                            }
                        }
                    }
                }

                if let Some(src) = item.src
                    && had_local_delivery
                    && local_delivery_error.is_none()
                    && targets_local
                {
                    self.note_side_local_delivery(src, pkt.data_type());
                }

                if item.src.is_some()
                    && had_local_delivery
                    && local_delivery_error.is_none()
                    && targets_local
                    && (is_reliable_type(pkt.data_type()) || !pkt.wire_target_senders().is_empty())
                    && !(has_remote
                        && self
                            .item_targets_router_as_intermediate_hop(&item.data, pkt.endpoints())?)
                {
                    self.queue_end_to_end_reliable_ack(pkt, called_from_queue)?;
                }

                if has_remote {
                    let relay_item = RouterItem::Packet(pkt.to_owned());
                    self.relay_send(relay_item, item.src, called_from_queue)?;
                }

                // Do not ACK or retain successful-delivery dedupe after a
                // refused local handoff. Other destinations still receive their
                // forwarding attempt; the origin can retry this same identity.
                local_delivery_error.map_or(Ok(()), Err)
            }
            RouterItem::Packed(bytes) => {
                // Pure best-effort transit needs routing metadata, not an owned
                // sender string or endpoint array. Commands, local handlers,
                // managed variables and internal protocols retain their normal path.
                let routing = wire_format::peek_routing_envelope(bytes.as_ref())?;
                if !is_internal_control_type(routing.ty)
                    && !routing.is_reliable
                    && routing.target_senders().len() == 0
                    && !self.is_managed_variable_type(routing.ty)
                    && !routing.endpoints().any(|ep| {
                        self.endpoint_has_packet_handler(ep) || self.endpoint_has_packed_handler(ep)
                    })
                {
                    // relay_send already resolves the eligible sides, including
                    // an empty plan. A preliminary selection duplicates scratch
                    // allocations and advances weighted cursors twice.
                    return self.relay_send(item.data.clone(), item.src, called_from_queue);
                }

                let env = wire_format::peek_envelope(bytes.as_ref())?;

                if matches!(
                    env.ty,
                    DataType::ReliableAck
                        | DataType::ReliablePartialAck
                        | DataType::ReliablePacketRequest
                ) {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    let handled =
                        self.handle_internal_reliable_packet(&pkt, item.src, called_from_queue)?;
                    // Hop-level ACKs terminate here. End-to-end ACKs for a packet originated
                    // farther upstream continue along the learned packet return route.
                    if !handled && self.should_route_remote(&item.data, item.src)? {
                        self.relay_send(RouterItem::Packet(pkt), item.src, called_from_queue)?;
                    }
                    return Ok(());
                }

                if env.ty == DataType::P2pMessage {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    if self.item_targets_local_sender(&item.data)? {
                        self.dispatch_p2p_packet(&pkt)?;
                        if item.src.is_some() {
                            let packet_id = wire_format::packet_id_from_wire(bytes.as_ref())
                                .unwrap_or_else(|_| pkt.packet_id());
                            self.queue_end_to_end_reliable_ack_for_packet_id(
                                packet_id,
                                pkt.sender(),
                                called_from_queue,
                            )?;
                        }
                    }
                    if self.should_route_remote(&item.data, item.src)? {
                        self.relay_send(RouterItem::Packet(pkt), item.src, called_from_queue)?;
                    }
                    return Ok(());
                }

                #[cfg(feature = "timesync")]
                if matches!(
                    env.ty,
                    DataType::TimeSyncAnnounce
                        | DataType::TimeSyncRequest
                        | DataType::TimeSyncResponse
                ) {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    self.handle_internal_timesync_packet(&pkt, item.src, called_from_queue)?;
                    return Ok(());
                }

                #[cfg(feature = "discovery")]
                if discovery::is_discovery_type(env.ty) {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    let _ = self.learn_discovery_packet(&pkt, item.src, called_from_queue)?;
                    if !discovery_is_hop_local_advertisement(env.ty)
                        && self.should_route_remote(&item.data, item.src)?
                    {
                        self.relay_send(RouterItem::Packet(pkt), item.src, called_from_queue)?;
                    }
                    return Ok(());
                }

                let any_packet_needed = env
                    .endpoints
                    .iter()
                    .copied()
                    .any(|ep| self.endpoint_has_packet_handler(ep));

                let mut pkt_opt = if any_packet_needed {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    Some(pkt)
                } else {
                    None
                };

                let mut eps: Vec<DataEndpoint> = env.endpoints.iter().copied().collect();
                crate::small_sort::sort(&mut eps);
                eps.dedup();
                let had_local_handler = eps.iter().copied().any(|ep| {
                    self.endpoint_has_packet_handler(ep) || self.endpoint_has_packed_handler(ep)
                });
                let had_local_delivery = had_local_handler || self.is_managed_variable_type(env.ty);

                let has_remote = self.should_route_remote(&item.data, item.src)?;
                let targets_local = self.item_targets_local_sender(&item.data)?;

                let mut local_delivery_error = None;
                if targets_local {
                    for dest in eps {
                        for h in self.cfg.handlers.iter().filter(|h| h.endpoint == dest) {
                            let result = match &h.handler {
                                EndpointHandlerFn::Packed(_) => self.call_handler_with_retries(
                                    dest,
                                    h,
                                    Some(bytes.as_ref()),
                                    pkt_opt.as_ref(),
                                    Some(&env),
                                    called_from_queue,
                                ),
                                EndpointHandlerFn::Packet(_) => {
                                    if pkt_opt.is_none() {
                                        let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                                        pkt.validate()?;
                                        pkt_opt = Some(pkt);
                                    }
                                    let pkt_ref = pkt_opt.as_ref().expect("just set");
                                    self.call_handler_with_retries(
                                        dest,
                                        h,
                                        None,
                                        Some(pkt_ref),
                                        Some(&env),
                                        called_from_queue,
                                    )
                                }
                            };
                            if let Err(error) = result {
                                if let Some(src) = item.src {
                                    self.note_side_local_handler_failure(
                                        src,
                                        env.ty,
                                        runtime_max_handler_retries(),
                                    );
                                }
                                local_delivery_error.get_or_insert(error);
                            }
                        }
                    }
                }

                if item.src.is_some()
                    && had_local_delivery
                    && local_delivery_error.is_none()
                    && targets_local
                    && (is_reliable_type(env.ty) || !env.target_senders.is_empty())
                    && !(has_remote
                        && self
                            .item_targets_router_as_intermediate_hop(&item.data, &env.endpoints)?)
                {
                    let packet_id =
                        wire_format::packet_id_from_wire(bytes.as_ref()).or_else(|_| {
                            pkt_opt
                                .as_ref()
                                .map(Packet::packet_id)
                                .ok_or(TelemetryError::Unpack("missing packet id"))
                        })?;
                    self.queue_end_to_end_reliable_ack_for_packet_id(
                        packet_id,
                        &env.sender,
                        called_from_queue,
                    )?;
                }

                if has_remote {
                    let relay_item = match pkt_opt {
                        Some(ref p) => RouterItem::Packet(p.clone()),
                        None => RouterItem::Packed(bytes.clone()),
                    };
                    self.relay_send(relay_item, item.src, called_from_queue)?;
                }

                // Do not ACK or retain successful-delivery dedupe after a
                // refused local handoff. Other destinations still receive their
                // forwarding attempt; the origin can retry this same identity.
                local_delivery_error.map_or(Ok(()), Err)
            }
        }
    }

    fn dispatch_local_for_item(
        &self,
        item: &RouterItem,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        match item {
            RouterItem::Packet(pkt) => {
                pkt.validate()?;
                if is_internal_control_type(pkt.data_type()) {
                    return Ok(());
                }
                self.ensure_e2e_policy_supported_for_type(pkt.data_type())?;
                if !self.item_targets_local_sender(item)? {
                    return Ok(());
                }

                let mut eps: Vec<DataEndpoint> = pkt.endpoints().to_vec();
                crate::small_sort::sort(&mut eps);
                eps.dedup();

                let has_packed_local = eps
                    .iter()
                    .copied()
                    .any(|ep| self.endpoint_has_packed_handler(ep));
                let bytes_opt = if has_packed_local {
                    Some(wire_format::pack_packet(pkt))
                } else {
                    None
                };

                for dest in eps {
                    for h in self.cfg.handlers.iter().filter(|h| h.endpoint == dest) {
                        match (&h.handler, &bytes_opt) {
                            (EndpointHandlerFn::Packed(_), Some(bytes)) => {
                                self.call_handler_with_retries(
                                    dest,
                                    h,
                                    Some(bytes.as_ref()),
                                    Some(pkt),
                                    None,
                                    called_from_queue,
                                )?;
                            }
                            (EndpointHandlerFn::Packed(_), None) => {
                                let bytes = wire_format::pack_packet(pkt);
                                self.call_handler_with_retries(
                                    dest,
                                    h,
                                    Some(bytes.as_ref()),
                                    Some(pkt),
                                    None,
                                    called_from_queue,
                                )?;
                            }
                            (EndpointHandlerFn::Packet(_), _) => {
                                self.call_handler_with_retries(
                                    dest,
                                    h,
                                    None,
                                    Some(pkt),
                                    None,
                                    called_from_queue,
                                )?;
                            }
                        }
                    }
                }
            }
            RouterItem::Packed(bytes) => {
                let env = wire_format::peek_envelope(bytes.as_ref())?;
                if is_internal_control_type(env.ty) {
                    return Ok(());
                }
                self.ensure_e2e_policy_supported_for_type(env.ty)?;
                if !self.item_targets_local_sender(item)? {
                    return Ok(());
                }

                let any_packet_needed = env
                    .endpoints
                    .iter()
                    .copied()
                    .any(|ep| self.endpoint_has_packet_handler(ep));

                let mut pkt_opt = if any_packet_needed {
                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                    pkt.validate()?;
                    Some(pkt)
                } else {
                    None
                };

                let mut eps: Vec<DataEndpoint> = env.endpoints.iter().copied().collect();
                crate::small_sort::sort(&mut eps);
                eps.dedup();

                for dest in eps {
                    for h in self.cfg.handlers.iter().filter(|h| h.endpoint == dest) {
                        match &h.handler {
                            EndpointHandlerFn::Packed(_) => {
                                self.call_handler_with_retries(
                                    dest,
                                    h,
                                    Some(bytes.as_ref()),
                                    pkt_opt.as_ref(),
                                    Some(&env),
                                    called_from_queue,
                                )?;
                            }
                            EndpointHandlerFn::Packet(_) => {
                                if pkt_opt.is_none() {
                                    let pkt = self.unpack_packet_for_role(bytes.as_ref())?;
                                    pkt.validate()?;
                                    pkt_opt = Some(pkt);
                                }
                                let pkt_ref = pkt_opt.as_ref().expect("just set");
                                self.call_handler_with_retries(
                                    dest,
                                    h,
                                    None,
                                    Some(pkt_ref),
                                    Some(&env),
                                    called_from_queue,
                                )?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Internal TX implementation used by `tx*()`, `tx_queue*()`, and relay-mode rebroadcast.
    ///
    /// - Broadcast items are sent to all sides when remote forwarding is required.
    /// - ToSide items are sent only to the specified side.
    /// - If `ignore_local` is false, local handlers are invoked once.
    fn tx_item_impl(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        called_from_queue: bool,
    ) -> TelemetryResult<()> {
        self.tx_item_impl_with_retry(
            item,
            ignore_local,
            called_from_queue,
            &mut DispatchContext::default(),
        )
    }

    fn tx_item_impl_with_retry(
        &self,
        item: RouterTxItem,
        ignore_local: bool,
        called_from_queue: bool,
        context: &mut DispatchContext,
    ) -> TelemetryResult<()> {
        match item {
            RouterTxItem::Broadcast(data) => {
                let claim = context.claim;
                let deferred_since = context.since;
                let ty = Self::item_data_type(&data)?;

                if let Some(since) = deferred_since
                    && let Err(error) = self.expire_deferred_original(
                        ty, since, claim.is_some_and(|claim| claim.ordered))
                {
                    context.terminal = true;
                    return Err(error);
                }
                if !called_from_queue
                    && !ignore_local
                    && matches!(reliable_mode(ty), crate::ReliableMode::Ordered)
                    && self
                        .state
                        .lock()
                        .transmit_queue
                        .iter()
                        .any(|queued| RouterInner::ordered_original_type(queued) == Some(ty))
                {
                    return self.tx_queue_item(RouterTxItem::Broadcast(data));
                }

                self.ensure_e2e_policy_supported_for_type(ty)?;
                if let RouterItem::Packet(pkt) = &data
                    && !is_internal_control_type(pkt.data_type())
                {
                    self.remember_managed_variable_packet(pkt)?;
                }
                #[cfg(feature = "discovery")]
                let is_discovery = discovery::is_discovery_type(ty);
                if !ignore_local {
                    if self.is_duplicate_pkt(&data)? {
                        return Ok(());
                    }
                    #[cfg(feature = "discovery")]
                    if !is_discovery && !is_internal_control_type(ty)
                        && let Err(error) = self.dispatch_local_for_item(&data, called_from_queue)
                    {
                        // Never repeat a partially applied local side effect.
                        if claim.is_some() {
                            context.terminal = true;
                            return Err(TelemetryError::HandlerError("accepted local delivery failed"));
                        }
                        return Err(error);
                    }
                    #[cfg(not(feature = "discovery"))]
                    if !is_internal_control_type(ty)
                        && let Err(error) = self.dispatch_local_for_item(&data, called_from_queue)
                    {
                        // Never repeat a partially applied local side effect.
                        if claim.is_some() {
                            context.terminal = true;
                            return Err(TelemetryError::HandlerError("accepted local delivery failed"));
                        }
                        return Err(error);
                    }
                }

                if !ignore_local && !self.mark_claim_local_delivered(claim) {
                    // An explicit queue clear cancelled the publication during its callback.
                    return Ok(());
                }

                if !self.claim_schema_is_current(ty, claim)? {
                    return Ok(());
                }

                match &data {
                    RouterItem::Packet(packet) => packet.validate()?,
                    // item_data_type already validated the same immutable packed bytes.
                    RouterItem::Packed(_) => {}
                }
                // Skipping local delivery does not waive a remote receipt
                // contract: a queued credit retry must still be registered.
                let freezes_contract = !is_internal_control_type(ty)
                    && self.item_requires_end_to_end_tracking(&data, ty)?;
                // The preliminary reachability check used to select a route,
                // allocate scratch, and advance weighted cursors, then repeat
                // all of it for dispatch. Reuse this per-dispatch plan when no
                // delivery contract can change its destination set. It is not
                // a persistent topology/schema cache.
                #[cfg(feature = "discovery")]
                let cached_plan = if freezes_contract {
                    None
                } else {
                    Some(self.remote_side_plan(&data, None)?)
                };
                #[cfg(feature = "discovery")]
                let send_remote = match &cached_plan {
                    Some(RemoteSidePlan::Target(sides)) => !sides.is_empty(),
                    None => self.should_route_remote(&data, None)?,
                };
                #[cfg(not(feature = "discovery"))]
                let send_remote = self.should_route_remote(&data, None)?;

                if !send_remote {
                    let (endpoints, ty) = self.item_route_info(&data)?;
                    if !is_internal_control_type(ty)
                        && is_reliable_type(ty)
                        && has_nonlocal_endpoint(&endpoints, &self.cfg)
                        && !self
                            .state
                            .lock()
                            .managed_variable_types
                            .contains(&ty.as_u32())
                    {
                        // Nothing was queued or transmitted. Reporting success
                        // here loses application state during route expiry.
                        // Permit retry of the same packet after discovery heals.
                        self.remove_pkt_id(&data);
                        if called_from_queue {
                            return self.defer_accepted_original(context);
                        }
                        return Err(TelemetryError::Io("no discovered route"));
                    }
                    return Ok(());
                }
                #[cfg(feature = "discovery")]
                let mut data = data;
                if freezes_contract {
                    #[cfg(feature = "discovery")]
                    {
                        let pending = {
                            let st = self.state.lock();
                            let mut pending = self.expected_end_to_end_destinations_locked(
                                &st, &data, None, false, false,
                            )?;
                            self.filter_trackable_end_to_end_destinations_locked(
                                &st,
                                ty,
                                &mut pending,
                                false,
                            );
                            pending
                        };
                        if !pending.is_empty() {
                            // RouterMap keys already form a sorted, unique frozen cohort.
                            let targets: Vec<u64> = pending.keys().copied().collect();
                            data = self.attach_wire_contract_to_item(data, &targets)?;
                            match self.register_end_to_end_reliable_tx(&data, Some(pending)) {
                                Ok(ready) => {
                                    context.owner_transferred = true;
                                    if !ready {
                                        return Ok(());
                                    }
                                }
                                Err(error) => {
                                    // Freezing destinations preserves the logical packet ID.
                                    // Clear its dedupe mark without retaining/cloning the old item.
                                    self.remove_pkt_id(&data);
                                    if called_from_queue
                                        && matches!(
                                            error,
                                            TelemetryError::Io("reliable window full")
                                        )
                                    {
                                        // Acceptance transferred ownership to this queue. A full
                                        // receipt window is temporary credit pressure, not loss.
                                        // Retain the frozen identity and skip local delivery on retry.
                                        if let Some(claim) = claim {
                                            self.replace_claim_payload(claim, data)?;
                                        }
                                        self.defer_accepted_original(context)?;
                                        return Ok(());
                                    }
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
                #[cfg(feature = "discovery")]
                let plan = match cached_plan {
                    Some(plan) => plan,
                    None => self.remote_side_plan(&data, None)?,
                };
                #[cfg(not(feature = "discovery"))]
                let plan = self.remote_side_plan(&data, None)?;
                let RemoteSidePlan::Target(sides) = plan;
                for side in sides.iter().copied() {
                    #[cfg(feature = "compression")]
                    let mut side_data = data.clone();
                    #[cfg(feature = "compression")]
                    let (send_result, mut reservation) =
                        self.send_queued_to_side(side, &mut side_data, false);
                    #[cfg(not(feature = "compression"))]
                    let send_result = self.send_reliable_to_side(side, data.clone(), false);
                    if let Err(e) = send_result {
                        if Self::is_transient_tx_error(&e) {
                            #[cfg(feature = "compression")]
                            self.retry_codec_owner(
                                RouterTxItem::ToSide {
                                    src: None,
                                    dst: side,
                                    data: side_data,
                                },
                                true,
                                &mut reservation,
                            )?;
                            #[cfg(not(feature = "compression"))]
                            self.tx_queue_item_for_retry(
                                RouterTxItem::ToSide {
                                    src: None,
                                    dst: side,
                                    data: data.clone(),
                                },
                                true,
                            )?;
                            continue;
                        }
                        match &data {
                            RouterItem::Packet(pkt) => {
                                let _ = self.handle_callback_error(pkt, None, e, called_from_queue);
                            }
                            RouterItem::Packed(bytes) => {
                                if let Ok(env) = wire_format::peek_envelope(bytes.as_ref()) {
                                    let _ = self.handle_callback_error_from_env(
                                        &env,
                                        None,
                                        e,
                                        called_from_queue,
                                    );
                                }
                            }
                        }
                        return Err(TelemetryError::HandlerError("tx handler failed"));
                    }
                }
            }
            RouterTxItem::ToSide { src, dst, data } => {
                #[cfg(feature = "compression")]
                let mut data = data;
                let ty = Self::item_data_type(&data)?;
                self.ensure_e2e_policy_supported_for_type(ty)?;
                if let RouterItem::Packet(pkt) = &data
                    && !is_internal_control_type(pkt.data_type())
                {
                    self.remember_managed_variable_packet(pkt)?;
                }
                if !ignore_local {
                    if self.is_duplicate_pkt(&data)? {
                        return Ok(());
                    }
                    let suppress_local = is_internal_control_type(ty);
                    if !suppress_local {
                        self.dispatch_local_for_item(&data, called_from_queue)?;
                    }
                }
                let allowed = {
                    let st = self.state.lock();
                    let ty = Some(ty);
                    let route_allowed = self.route_allowed_locked(&st, src, ty, dst);
                    #[cfg(all(feature = "discovery", feature = "timesync"))]
                    let timesync_allowed = ty
                        .map(|ty| {
                            Self::timesync_allowed_for_side_locked(
                                &st,
                                dst,
                                ty,
                                self.clock.now_ms(),
                            )
                        })
                        .unwrap_or(true);
                    #[cfg(not(all(feature = "discovery", feature = "timesync")))]
                    let timesync_allowed = true;
                    route_allowed && timesync_allowed
                };
                if !allowed {
                    return Ok(());
                }
                #[cfg(feature = "compression")]
                let (send_result, mut reservation) =
                    self.send_queued_to_side(dst, &mut data, src.is_some());
                #[cfg(not(feature = "compression"))]
                let send_result = self.send_reliable_to_side(dst, data.clone(), src.is_some());
                if let Err(e) = send_result {
                    if Self::is_transient_tx_error(&e) {
                        #[cfg(feature = "compression")]
                        self.retry_codec_owner(
                            RouterTxItem::ToSide { src, dst, data },
                            true,
                            &mut reservation,
                        )?;
                        #[cfg(not(feature = "compression"))]
                        self.tx_queue_item_for_retry(
                            RouterTxItem::ToSide { src, dst, data },
                            true,
                        )?;
                        return Ok(());
                    }
                    match &data {
                        RouterItem::Packet(pkt) => {
                            let _ = self.handle_callback_error(pkt, None, e, called_from_queue);
                        }
                        RouterItem::Packed(bytes) => {
                            if let Ok(env) = wire_format::peek_envelope(bytes.as_ref()) {
                                let _ = self.handle_callback_error_from_env(
                                    &env,
                                    None,
                                    e,
                                    called_from_queue,
                                );
                            }
                        }
                    }
                    return Err(TelemetryError::HandlerError("tx handler failed"));
                }
            }
            RouterTxItem::EndToEndReplay { packet_id } => {
                let Some((data, mut sides)) = self.end_to_end_retransmit_sides(packet_id) else {
                    return Ok(());
                };
                if sides.is_empty() {
                    let RemoteSidePlan::Target(fallback_sides) =
                        self.remote_side_plan(&data, None)?;
                    sides = fallback_sides;
                }
                for side in sides.iter().copied() {
                    #[cfg(feature = "compression")]
                    let mut side_data = data.clone();
                    #[cfg(feature = "compression")]
                    let (send_result, mut reservation) =
                        self.send_queued_to_side(side, &mut side_data, false);
                    #[cfg(not(feature = "compression"))]
                    let send_result = self.send_reliable_to_side(side, data.clone(), false);
                    if let Err(e) = send_result {
                        if Self::is_transient_tx_error(&e) {
                            #[cfg(feature = "compression")]
                            self.retry_codec_owner(
                                RouterTxItem::ToSide {
                                    src: None,
                                    dst: side,
                                    data: side_data,
                                },
                                true,
                                &mut reservation,
                            )?;
                            #[cfg(not(feature = "compression"))]
                            self.tx_queue_item_for_retry(
                                RouterTxItem::ToSide {
                                    src: None,
                                    dst: side,
                                    data: data.clone(),
                                },
                                true,
                            )?;
                            continue;
                        }
                        match &data {
                            RouterItem::Packet(pkt) => {
                                let _ = self.handle_callback_error(pkt, None, e, called_from_queue);
                            }
                            RouterItem::Packed(bytes) => {
                                if let Ok(env) = wire_format::peek_envelope(bytes.as_ref()) {
                                    let _ = self.handle_callback_error_from_env(
                                        &env,
                                        None,
                                        e,
                                        called_from_queue,
                                    );
                                }
                            }
                        }
                        return Err(TelemetryError::HandlerError("tx handler failed"));
                    }
                }
            }
            RouterTxItem::ReliableReplay {
                dst,
                ty,
                seq,
                bytes,
            } => {
                {
                    let mut st = self.state.lock();
                    let Some(sent) = st
                        .reliable_tx
                        .get_mut(&Self::reliable_key(dst, ty))
                        .and_then(|tx| tx.sent.get_mut(&seq))
                    else {
                        return Ok(());
                    };
                    sent.queued = false;
                    sent.last_send_ms = self.clock.now_ms();
                }
                if let Err(e) = self.send_reliable_raw_to_side(dst, bytes.clone(), false) {
                    if Self::is_transient_tx_error(&e) {
                        self.tx_queue_item_for_retry(
                            RouterTxItem::ReliableReplay {
                                dst,
                                ty,
                                seq,
                                bytes,
                            },
                            true,
                        )?;
                        return Ok(());
                    }
                    return Err(e);
                }
                let mut st = self.state.lock();
                let tx_state = self.reliable_tx_state_mut(&mut st, dst, ty);
                if let Some(sent) = tx_state.sent.get_mut(&seq) {
                    sent.last_send_ms = self.clock.now_ms();
                }
            }
        }

        Ok(())
    }

    /// Transmit a telemetry item immediately (remote + local).
    #[inline]
    fn tx_item(&self, item: RouterTxItem) -> TelemetryResult<()> {
        self.tx_item_impl(item, false, false)
    }

    // ---------- PUBLIC API: RX immediate ----------

    /// Process packed bytes immediately as locally-originated input.
    ///
    /// If this call occurs while a side TX callback is already on the stack, the bytes are queued
    /// instead of being processed re-entrantly.
    #[inline]
    pub fn rx_packed(&self, bytes: &[u8]) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return self.rx_packed_queue(bytes);
        }
        crate::memory_admission::check_receive(bytes)?;
        let data = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(bytes)));
        let item = RouterRxItem {
            src: None,
            priority: Self::router_item_priority(&data)?,
            data,
        };
        self.rx_item(&item, false)
    }

    /// Process a decoded packet immediately as locally-originated input.
    ///
    /// If this call occurs while a side TX callback is already on the stack, the packet is queued
    /// instead of being processed re-entrantly.
    #[inline]
    pub fn rx(&self, pkt: &Packet) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return self.rx_queue(pkt.clone());
        }
        let data = RouterItem::Packet(pkt.clone());
        let item = RouterRxItem {
            src: None,
            priority: Self::router_item_priority(&data)?,
            data,
        };
        self.rx_item(&item, false)
    }

    /// Process a decoded packet immediately with an explicit ingress side id.
    ///
    /// If this call occurs while a side TX callback is already on the stack, the packet is queued
    /// instead of being processed re-entrantly.
    #[inline]
    pub fn rx_from_side(&self, pkt: &Packet, side: RouterSideId) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return self.rx_queue_from_side(pkt.clone(), side);
        }
        self.ensure_side_ingress_enabled(side)?;
        let data = RouterItem::Packet(pkt.clone());
        let item = RouterRxItem {
            src: Some(side),
            priority: Self::router_item_priority(&data)?,
            data,
        };
        self.rx_item(&item, false)
    }

    /// Process packed bytes immediately with an explicit ingress side id.
    ///
    /// If this call occurs while a side TX callback is already on the stack, the bytes are queued
    /// instead of being processed re-entrantly.
    #[inline]
    pub fn rx_packed_from_side(&self, bytes: &[u8], side: RouterSideId) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return self.rx_packed_queue_from_side(bytes, side);
        }
        self.ensure_side_ingress_enabled(side)?;
        let Some(decoded) = self.decode_side_transport_frame(side, bytes)? else {
            return Ok(());
        };
        let data = RouterItem::Packed(decoded);
        let item = RouterRxItem {
            src: Some(side),
            priority: Self::router_item_priority(&data)?,
            data,
        };
        self.rx_item(&item, false)
    }

    // ---------- PUBLIC API: TX immediate ----------

    /// Transmit a decoded packet immediately.
    ///
    /// The router delivers locally where appropriate and forwards toward eligible sides. If called
    /// from inside a side TX callback, the packet is queued instead of being sent re-entrantly.
    #[inline]
    pub fn tx(&self, pkt: Packet) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        if self.side_tx_active() {
            return self.tx_queue_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)));
        }
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    /// Transmit packed bytes immediately.
    ///
    /// If called from inside a side TX callback, the bytes are queued instead of being sent
    /// re-entrantly.
    #[inline]
    pub fn tx_packed(&self, pkt: Arc<[u8]>) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
        if self.side_tx_active() {
            return self.tx_queue_item(RouterTxItem::Broadcast(RouterItem::Packed(
                crate::shared_bytes::convert(pkt),
            )));
        }
        self.tx_item(RouterTxItem::Broadcast(RouterItem::Packed(
            crate::shared_bytes::convert(pkt),
        )))
    }

    // ---------- PUBLIC API: TX queue ----------

    /// Queue a decoded packet for later transmission.
    /// Discovery/time-sync maintenance stays on the worker calling `periodic`.
    /// Enqueueing must not serialize topology on a producer's small stack.
    #[inline]
    pub fn tx_queue(&self, pkt: Packet) -> TelemetryResult<()> {
        self.tx_queue_item(RouterTxItem::Broadcast(RouterItem::Packet(pkt)))
    }

    /// Queue packed bytes for later transmission.
    #[inline]
    pub fn tx_packed_queue(&self, data: Arc<[u8]>) -> TelemetryResult<()> {
        self.tx_queue_item(RouterTxItem::Broadcast(RouterItem::Packed(
            crate::shared_bytes::convert(data),
        )))
    }

    // ---------- PUBLIC API: logging ----------

    // Keep one encoder/dispatch closure per representation, rather than four
    // copies for direct/queued and implicit/explicit timestamp entry points.
    // Queued producers never perform discovery work on their small stacks.
    #[inline(never)]
    fn log_dispatch<T: LeBytes>(
        &self,
        ty: DataType,
        data: &[T],
        timestamp: Option<u64>,
        mut queued: bool,
    ) -> TelemetryResult<()> {
        if !queued {
            #[cfg(feature = "discovery")]
            let _ = crate::memory_admission::allow_drain(self.poll_discovery())?;
            queued = self.side_tx_active();
        }
        let timestamp = timestamp.unwrap_or_else(|| self.packet_timestamp_ms());
        log_raw(self.sender_arc(), ty, data, timestamp, |pkt| {
            let item = RouterTxItem::Broadcast(RouterItem::Packet(pkt));
            if queued {
                self.tx_queue_item(item)
            } else {
                self.tx_item(item)
            }
        })
    }

    /// Build a packet from typed elements and send it immediately.
    /// Calls from an active transport callback are deferred to the TX queue.
    #[inline]
    pub fn log<T: LeBytes>(&self, ty: DataType, data: &[T]) -> TelemetryResult<()> {
        self.log_dispatch(ty, data, None, false)
    }

    /// Build a packet from typed elements and queue it for later transmission.
    #[inline]
    pub fn log_queue<T: LeBytes>(&self, ty: DataType, data: &[T]) -> TelemetryResult<()> {
        self.log_dispatch(ty, data, None, true)
    }

    /// Build a packet with an explicit timestamp and send it immediately.
    #[inline]
    pub fn log_ts<T: LeBytes>(
        &self,
        ty: DataType,
        timestamp: u64,
        data: &[T],
    ) -> TelemetryResult<()> {
        self.log_dispatch(ty, data, Some(timestamp), false)
    }

    /// Build a packet with an explicit timestamp and queue it for transmission.
    #[inline]
    pub fn log_queue_ts<T: LeBytes>(
        &self,
        ty: DataType,
        timestamp: u64,
        data: &[T],
    ) -> TelemetryResult<()> {
        self.log_dispatch(ty, data, Some(timestamp), true)
    }
}

#[cfg(all(test, feature = "std", feature = "discovery"))]
mod queued_schema_identity_tests {
    use super::*;

    fn catalog(timestamp: u64, byte: u8) -> Packet {
        Packet::new(
            crate::DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "SCHEMA_PEER",
            timestamp,
            crate::shared_bytes::convert(Arc::<[u8]>::from(vec![byte; 1024])),
        )
        .unwrap()
    }

    #[test]
    fn inline_and_large_typed_publications_share_headers_and_keep_le_bytes() {
        crate::tests::ensure_common_test_schema();
        let endpoint = DataEndpoint::named("SD_CARD");
        let ty = crate::config::register_data_type_with_description(
            "INLINE_TYPED_BOUNDARY",
            "",
            MessageElement::Dynamic(crate::MessageDataType::UInt32, crate::MessageClass::Data),
            &[endpoint],
            crate::ReliableMode::None,
            16,
        )
        .unwrap();
        let sender: Arc<str> = Arc::from("DAQ_SOURCE");
        let endpoints = message_meta(ty);
        for count in [
            0,
            1,
            crate::config::STACK_PAYLOAD_SIZE / 4,
            crate::config::STACK_PAYLOAD_SIZE / 4 + 1,
            64,
        ] {
            let values = (0..count)
                .map(|i| 0x1234_5678u32.wrapping_add(i as u32))
                .collect::<Vec<_>>();
            log_raw(sender.clone(), ty, &values, 42, |packet| {
                let bytes = values
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect::<Vec<_>>();
                assert_eq!(packet.payload(), bytes);
                assert_eq!(packet.sender().as_ptr(), sender.as_ptr());
                assert_eq!(
                    packet.endpoints().as_ptr(),
                    endpoints.endpoints_ref().as_ptr()
                );
                packet.validate().unwrap();
                Ok(())
            })
            .unwrap();
        }
        #[derive(Clone, Copy)]
        struct BadWidth;
        impl LeBytes for BadWidth {
            const WIDTH: usize = 0;
            fn write_le(self, _: &mut [u8]) {
                unreachable!()
            }
            fn from_le_slice(_: &[u8]) -> Self {
                Self
            }
        }
        assert!(matches!(
            log_raw(sender.clone(), ty, &[BadWidth], 42, |_| Ok(())),
            Err(TelemetryError::BadArg)
        ));
        #[derive(Clone, Copy)]
        struct HugeWidth;
        impl LeBytes for HugeWidth {
            const WIDTH: usize = usize::MAX;
            fn write_le(self, _: &mut [u8]) {
                unreachable!()
            }
            fn from_le_slice(_: &[u8]) -> Self {
                Self
            }
        }
        assert!(matches!(
            log_raw(sender, ty, &[HugeWidth, HugeWidth], 42, |_| Ok(())),
            Err(TelemetryError::PacketTooLarge(_))
        ));
    }

    #[test]
    fn queue_accounting_reports_live_cost_without_draining_or_pinning() {
        crate::tests::ensure_common_test_schema();
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 42u64));
        let packet = Packet::new(
            crate::DataType::named("IMU_DATA"),
            &[DataEndpoint::named("SD_CARD")],
            "SOURCE",
            1,
            crate::shared_bytes::convert(Arc::<[u8]>::from([0u8; 24])),
        )
        .unwrap();
        router.tx_queue(packet).unwrap();
        assert!(router.has_queued_work());
        let expected = router.memory_counters();
        let a = router.queue_counters();
        assert_eq!(a[0], 1);
        assert_eq!(a[1], 0);
        assert_eq!(a[2], 1);
        assert_eq!(a[3], expected[3]);
        assert_eq!(a[4], expected[4]);
        assert_eq!(a[5], crate::DataType::named("IMU_DATA").as_u32());
        assert_eq!(a[14], 42);
        assert_eq!(a[15], 0);
        assert_eq!(router.queue_counters(), a);
        assert_eq!(router.memory_counters(), expected);
        router.drain_queues_with_timeout(0).unwrap();
        let empty = router.queue_counters();
        assert_eq!(empty[2], 0);
        assert_eq!(empty[4], 0);
        assert_eq!(router.memory_counters()[4], 0);
        assert!(!router.has_queued_work());
    }

    #[test]
    fn repeated_schema_preserves_partial_transfer_but_updates_and_other_sides_do_not_coalesce() {
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0u64));
        let side = router.add_side_packed("A", |_| Ok(()));
        let other_side = router.add_side_packed("B", |_| Ok(()));
        let original = catalog(1, 42);
        let duplicate = catalog(2, 42);
        assert_ne!(original.packet_id(), duplicate.packet_id());
        let mut st = router.state.lock();
        st.transmit_queue.clear();
        let queued = |dst, pkt| TxQueued {
            disposable: true,
            item: RouterTxItem::ToSide {
                src: None,
                dst,
                data: RouterItem::Packet(pkt),
            },
            ignore_local: true,
            priority: 255,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 123,
        };
        st.push_transmit(queued(side, original.clone())).unwrap();
        st.push_transmit(queued(side, duplicate.clone())).unwrap();
        assert_eq!(st.transmit_queue.len(), 1);
        let pending = st.transmit_queue.iter().next().unwrap();
        assert_eq!(pending.retry_after_ms, 123);
        assert!(
            matches!(&pending.item, RouterTxItem::ToSide { data: RouterItem::Packet(pkt), .. }
            if pkt.packet_id() == original.packet_id())
        );
        st.push_transmit(queued(other_side, duplicate)).unwrap();
        assert_eq!(st.transmit_queue.len(), 2);
        let changed = catalog(3, 43);
        st.push_transmit(queued(side, changed.clone())).unwrap();
        assert_eq!(st.transmit_queue.len(), 2);
        assert!(st.transmit_queue.iter().any(|queued| matches!(&queued.item,
            RouterTxItem::ToSide { dst, data: RouterItem::Packet(pkt), .. }
            if *dst == side && pkt.packet_id() == changed.packet_id())));
    }

    #[test]
    fn repeated_announcements_complete_one_fragment_per_dispatch() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        let allowance = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(std::sync::Mutex::new(Vec::<Arc<[u8]>>::new()));
        let available = allowance.clone();
        let frames = accepted.clone();
        let node = Router::new_with_clock(RouterConfig::default(), Box::new(|| 1u64));
        let side = node.add_side_packed_with_options(
            "bounded CAN",
            move |bytes| {
                if available
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        count.checked_sub(1)
                    })
                    .is_err()
                {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                frames.lock().unwrap().push(Arc::<[u8]>::from(bytes));
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(128),
        );
        let handler = node.state.lock().sides[side]
            .as_ref()
            .unwrap()
            .tx_handler
            .clone();
        let mut complete = false;
        for timestamp in 1..100 {
            // Incompressible bytes ensure this really uses several chunks.
            let mut state = 0x517cc1b7u32;
            let payload: Vec<u8> = (0..3600)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let packet = Packet::new(
                crate::DataType::DiscoverySchema,
                &[crate::DataEndpoint::Discovery],
                "SCHEMA_PEER",
                timestamp,
                crate::shared_bytes::convert(Arc::<[u8]>::from(payload)),
            )
            .unwrap();
            node.state
                .lock()
                .push_transmit(TxQueued {
                    disposable: true,
                    item: RouterTxItem::ToSide {
                        src: None,
                        dst: side,
                        data: RouterItem::Packet(packet),
                    },
                    ignore_local: true,
                    priority: 255,
                    delivery_state: QueuedDelivery::Untracked,
                    accepted_type: 0,
                    deferred_since_ms: 0,
                    retry_after_ms: 0,
                })
                .unwrap();
            let data = match &node.state.lock().transmit_queue.iter().next().unwrap().item {
                RouterTxItem::ToSide { data, .. } => data.clone(),
                _ => panic!("unexpected item"),
            };
            allowance.store(1, Ordering::Relaxed);
            match node.call_side_tx_handler(side, &handler, &data, false) {
                Ok(()) => {
                    complete = true;
                    break;
                }
                Err(TelemetryError::Io(_)) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert!(
            complete,
            "new announcement timestamps must not replay the prefix forever"
        );
        let received = accepted.lock().unwrap();
        // One transfer ID and consecutive fragment indices prove prefix reuse
        // did not create incomplete transfers or duplicate accepted fragments.
        assert!(
            received.len() > 1,
            "fixture must exercise fragmentation, not a compressed single frame"
        );
        let first = &received[0];
        assert_eq!(&first[..4], &[83, 68, 84, 3]);
        assert_eq!(
            u16::from_le_bytes([first[10], first[11]]) as usize,
            received.len()
        );
        let transfer_id = &first[4..8];
        for (index, frame) in received.iter().enumerate() {
            assert_eq!(&frame[4..8], transfer_id);
            assert_eq!(u16::from_le_bytes([frame[8], frame[9]]) as usize, index);
        }
    }
    #[test]
    fn schema_receipt_resolves_assigned_numeric_address_without_adding_peers() {
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0u64));
        let side = router.add_side_packed("A", |_| Ok(()));
        let assigned = 0x1234u32;
        assert_ne!(sender_address_u32("SCHEMA_PEER"), assigned);
        {
            let mut st = router.state.lock();
            st.discovery_routes
                .entry(side)
                .or_default()
                .announcers
                .insert(
                    "SCHEMA_PEER".into(),
                    DiscoverySenderState {
                        advertised_address: Some(assigned),
                        ..DiscoverySenderState::default()
                    },
                );
        }
        router.note_schema_received(side, "@addr:4660");
        router.note_schema_received(side, "@addr:4661");
        let st = router.state.lock();
        let peers = &st.discovery_routes.get(&side).unwrap().announcers;
        assert_eq!(peers.len(), 1);
        assert!(peers["SCHEMA_PEER"].has_schema);
    }
    #[test]
    fn busy_handler_returns_after_one_attempt_and_other_errors_keep_retry_budget() {
        let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0u64));
        let attempts = core::cell::Cell::new(0);
        let result: Result<((), usize), _> = router.retry_with_attempts(8, || {
            attempts.set(attempts.get() + 1);
            Err(TelemetryError::Io("side tx busy"))
        });
        assert!(matches!(
            result,
            Err((TelemetryError::Io("side tx busy"), 1))
        ));
        assert_eq!(attempts.get(), 1);
        attempts.set(0);
        let result: Result<((), usize), _> = router.retry_with_attempts(3, || {
            attempts.set(attempts.get() + 1);
            Err(TelemetryError::Io("permanent handler failure"))
        });
        assert!(matches!(
            result,
            Err((TelemetryError::Io("permanent handler failure"), 3))
        ));
        assert_eq!(attempts.get(), 3);
    }
    #[test]
    fn rejected_first_template_frame_is_retried_self_describing() {
        crate::tests::ensure_common_test_schema();
        let ty = crate::config::register_data_type_with_description(
            "ROUTER_BUSY_FIRST_TEMPLATE",
            "",
            crate::MessageElement::Static(
                1,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[crate::DataEndpoint::named("RADIO")],
            crate::ReliableMode::None,
            1,
        )
        .unwrap();
        let tx = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0u64));
        let rx = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0u64));
        let opts = RouterSideOptions::default().with_small_packet_transport(0);
        let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
        let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
        let packet = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            "BUSY_PEER",
            1,
            crate::shared_bytes::convert(Arc::<[u8]>::from([42u8])),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        // No byte of the dictionary bootstrap reaches the receiver.
        let first = tx
            .encode_side_transport_frames(
                a,
                opts.clone(),
                crate::shared_bytes::convert(raw.clone()),
            )
            .unwrap();
        assert!(
            tx.send_side_frames_resumable(a, first, |_| Err(TelemetryError::Io("side tx busy")))
                .is_err()
        );
        let retry = tx
            .encode_side_transport_frames(
                a,
                opts.clone(),
                crate::shared_bytes::convert(raw.clone()),
            )
            .unwrap();
        let mut received = None;
        tx.send_side_frames_resumable(a, retry, |frame| {
            assert_eq!(
                frame[3], SIDE_TRANSPORT_KIND_FULL,
                "retry requires the unaccepted dictionary bootstrap"
            );
            received = rx.decode_side_transport_frame(b, frame)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(received, Some(crate::shared_bytes::convert(raw.clone())));
        // Compression resumes once a full frame has actually been accepted.
        let next = tx
            .encode_side_transport_frames(a, opts, crate::shared_bytes::convert(raw.clone()))
            .unwrap();
        tx.send_side_frames_resumable(a, next, |frame| {
            assert_eq!(frame[3], SIDE_TRANSPORT_KIND_COMPACT);
            assert_eq!(
                rx.decode_side_transport_frame(b, frame)?,
                Some(crate::shared_bytes::convert(raw.clone()))
            );
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn already_queued_receipt_precedes_ordered_retry_exhaustion() {
        crate::tests::ensure_common_test_schema();
        let ep = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type_with_description(
            "QUEUED_RECEIPT_DEADLINE",
            "",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::Ordered,
            1,
        )
        .unwrap();
        for isr in [false, true] {
            let now = Arc::new(core::sync::atomic::AtomicU64::new(0));
            let clock = now.clone();
            let router = Router::new_with_clock(
                RouterConfig::new([]).with_hostname("FC"),
                Box::new(move || clock.load(Ordering::Relaxed)),
            );
            let side = router.add_side_packed("CAN", |_| Ok(()));
            let packet = Packet::new(ty, &[ep], "FC", 1, Arc::<[u8]>::from([42u8])).unwrap();
            let id = packet.packet_id();
            let owner = Router::sender_hash("GS");
            let mut destinations = BTreeMap::new();
            destinations.insert(owner, side);
            router.state.lock().end_to_end_reliable_tx.insert(
                id,
                EndToEndReliableSent {
                    ordered_type: Some(ty.as_u32()),
                    waiting_for_predecessor: false,
                    data: RouterItem::Packet(packet),
                    pending_destinations: destinations,
                    tracked_destinations: true,
                    last_send_ms: 0,
                    retries: runtime_reliable_max_retries(),
                    queued: false,
                },
            );
            let snapshot = router.export_reliable_pending_stats();
            assert_eq!(snapshot.len(), 1);
            assert_eq!(snapshot[0].packet_id, id);
            assert_eq!(snapshot[0].data_type, ty);
            assert_eq!(snapshot[0].pending_destinations, vec![owner]);
            assert_eq!(snapshot[0].retries, runtime_reliable_max_retries());
            assert!(!snapshot[0].queued);
            assert!(!snapshot[0].waiting_for_predecessor);
            let ack = Packet::new_with_wire_contract(
                DataType::ReliableAck,
                message_meta(DataType::ReliableAck).endpoints_ref(),
                "E2EACK:GS",
                1,
                1,
                Arc::<[u8]>::from(id.to_le_bytes()),
                None,
                Arc::from([owner, Router::sender_hash("FC")]),
            )
            .unwrap();
            let packed = wire_format::pack_packet(&ack);
            if isr {
                router.rx_packed_queue_from_side_isr(&packed, side).unwrap();
            } else {
                router.rx_packed_queue_from_side(&packed, side).unwrap();
            }
            now.store(runtime_reliable_retransmit_ms(), Ordering::Relaxed);
            router
                .drain_queues_with_timeout(1)
                .expect("a received ACK must be processed before cancelling its ordered delivery");
            assert!(!router.state.lock().end_to_end_reliable_tx.contains_key(&id));
            assert!(router.export_reliable_pending_stats().is_empty());
        }
    }
    #[test]
    fn embedded_gateway_receipt_with_numeric_sender_clears_host_pending_owner() {
        crate::tests::ensure_common_test_schema();
        // Captured after the actual gateway UART and Pico mailbox. The owner
        // hash is carried in the contract, because the ACK sender is numeric.
        let bytes = [
            0x0c, 0x01, 0x01, 0x08, 0xd4, 0xe5, 0xea, 0xb6, 0xb7, 0x33, 0xff, 0x90, 0x02, 0xb4,
            0xe6, 0xdd, 0x94, 0x07, 0x14, 0x03, 0x44, 0x02, 0x02, 0x06, 0x25, 0xd2, 0x59, 0x1b,
            0xbb, 0xfc, 0xa7, 0x5f, 0x43, 0x92, 0x9e, 0x12, 0xbb, 0xfc, 0xa7, 0x26, 0xa2, 0xa0,
            0xbe, 0x39, 0x65, 0xe2, 0xd8, 0x61, 0x68, 0x22, 0xfd,
        ];
        let ack = wire_format::unpack_packet(&bytes).unwrap();
        let owner = Router::sender_hash("GB");
        assert_eq!(Router::end_to_end_ack_sender_hash(&ack), Some(owner));
        let id = Router::decode_end_to_end_reliable_ack(ack.payload()).unwrap();
        let router = Router::new(RouterConfig::new([]).with_hostname("GS"));
        let side = router.add_side_packed("Pico", |_| Ok(()));
        let data = ack.clone();
        router.state.lock().end_to_end_reliable_tx.insert(
            id,
            EndToEndReliableSent {
                ordered_type: None,
                waiting_for_predecessor: false,
                data: RouterItem::Packet(data),
                pending_destinations: BTreeMap::from([(owner, side)]),
                tracked_destinations: true,
                last_send_ms: 0,
                retries: 0,
                queued: false,
            },
        );
        router.rx_packed_queue_from_side(&bytes, side).unwrap();
        router.drain_queues_with_timeout(1).unwrap();
        assert!(router.export_reliable_pending_stats().is_empty());
    }

    #[test]
    fn frozen_delivery_contract_bypasses_dictionary_even_for_best_effort_schema() {
        crate::tests::ensure_common_test_schema();
        let ep = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type_with_description(
            "MANAGED_CONTROL_WITH_FROZEN_OWNERS",
            "",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::None,
            16,
        )
        .unwrap();
        let router = Router::new(RouterConfig::new([]).with_hostname("GS"));
        let opts = RouterSideOptions::default().with_template_transport();
        let side = router.add_side_packed_with_options("radio", |_| Ok(()), opts.clone());
        let packet = Packet::new_with_wire_contract(
            ty,
            &[ep],
            "GS",
            1,
            1,
            Arc::<[u8]>::from([1u8]),
            None,
            Arc::from([Router::sender_hash("RF")]),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        assert_eq!(
            router
                .item_service_priority(&RouterItem::Packet(packet.clone()))
                .unwrap(),
            254
        );
        assert_eq!(
            router
                .item_service_priority(&RouterItem::Packed(crate::shared_bytes::convert(
                    raw.clone()
                )))
                .unwrap(),
            254
        );
        assert!(
            !wire_format::peek_routing_frame_info(&raw)
                .unwrap()
                .envelope
                .is_reliable
        );
        for _ in 0..3 {
            let frames = router
                .encode_side_transport_frames(
                    side,
                    opts.clone(),
                    crate::shared_bytes::convert(raw.clone()),
                )
                .unwrap();
            let mut count = 0;
            router
                .send_side_frames_resumable(side, frames, |bytes| {
                    assert_eq!(
                        bytes,
                        raw.as_ref(),
                        "delivery contract must remain independently decodable"
                    );
                    count += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn managed_receive_queues_keep_service_priority_with_low_schema_priority() {
        crate::tests::ensure_common_test_schema();
        let ep = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type_with_description(
            "MANAGED_RX_SERVICE_PRIORITY",
            "",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::None,
            16,
        )
        .unwrap();
        let router = Router::new(RouterConfig::new([]).with_hostname("RF"));
        router
            .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        let side = router.add_side_packed("radio", |_| Ok(()));
        router.clear_queues();
        let packet = Packet::new(ty, &[ep], "GS", 1, Arc::<[u8]>::from([1])).unwrap();
        let wire = wire_format::pack_packet(&packet);
        router.rx_queue(packet.clone()).unwrap();
        router.rx_queue_from_side(packet.clone(), side).unwrap();
        router.rx_packed_queue(&wire).unwrap();
        router.rx_packed_queue_from_side(&wire, side).unwrap();
        for _ in 0..4 {
            let queued = router
                .pop_next_queued_control_rx_item()
                .unwrap()
                .expect("registered managed controls must precede queued bulk work");
            assert_eq!(
                queued.priority,
                crate::transport_priority(DataType::ManagedVariableValue)
            );
        }
        assert!(router.pop_next_queued_control_rx_item().unwrap().is_none());
    }

    #[test]
    fn managed_value_keeps_service_priority_after_side_backpressure() {
        crate::tests::ensure_common_test_schema();
        let ep = DataEndpoint::named("RADIO");
        let ty = crate::config::register_data_type_with_description(
            "MANAGED_RETRY_SERVICE_PRIORITY",
            "",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::None,
            16,
        )
        .unwrap();
        let router = Router::new(RouterConfig::new([]).with_hostname("GS"));
        router
            .enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
            .unwrap();
        let side = router.add_side_packed("radio", |_| Err(TelemetryError::Io("side tx busy")));
        let packet = Packet::new(ty, &[ep], "GS", 1, Arc::<[u8]>::from([1])).unwrap();
        let item = RouterItem::Packet(packet);
        for queued in [
            RouterTxItem::Broadcast(item.clone()),
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: item.clone(),
            },
        ] {
            router.tx_queue_item_for_retry(queued, true).unwrap();
            let queued = router.state.lock().transmit_queue.pop_front().unwrap();
            assert_eq!(
                queued.priority,
                crate::transport_priority(DataType::ManagedVariableValue),
                "a busy side must not demote managed controls to bulk application priority"
            );
            assert!(queued.retry_after_ms > 0);
        }
    }
    #[test]
    fn receipt_budget_does_not_starve_transmit() {
        use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        crate::tests::ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let accepted = count.clone();
        let node = Router::new_with_clock(
            RouterConfig::default(),
            Box::new(move || clock.fetch_add(1, Ordering::Relaxed)),
        );
        let side = node.add_side_packed("wire", move |_| {
            accepted.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        node.clear_queues();
        let packet = Packet::new(
            crate::DataType::ReliableAck,
            &[crate::DataEndpoint::TelemetryError],
            "E2EACK:PEER",
            1,
            Arc::<[u8]>::from([0u8; 8]),
        )
        .unwrap();
        node.state
            .lock()
            .push_transmit(TxQueued {
                disposable: true,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(packet.clone()),
                },
                ignore_local: true,
                priority: 250,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })
            .unwrap();
        node.rx_packed_queue_from_side(
            &wire_format::pack_packet(
                &Packet::new(
                    crate::DataType::ReliableAck,
                    &[crate::DataEndpoint::TelemetryError],
                    "RX_PEER",
                    2,
                    Arc::<[u8]>::from([0u8; 8]),
                )
                .unwrap(),
            ),
            side,
        )
        .unwrap();
        node.drain_queues_with_timeout(1).unwrap();
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "control RX exhausting its cooperative budget must still allow one queued TX"
        );
    }
    #[test]
    fn receipt_budget_does_not_starve_bulk_transmit() {
        use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        crate::tests::ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let accepted = count.clone();
        let node = Router::new_with_clock(
            RouterConfig::default(),
            Box::new(move || clock.fetch_add(1, Ordering::Relaxed)),
        );
        let side = node.add_side_packed("wire", move |_| {
            accepted.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        node.clear_queues();
        let packet = Packet::new(
            crate::DataType::ReliableAck,
            &[crate::DataEndpoint::TelemetryError],
            "E2EACK:PEER",
            1,
            Arc::<[u8]>::from([0u8; 8]),
        )
        .unwrap();
        node.state
            .lock()
            .push_transmit(TxQueued {
                disposable: true,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(packet.clone()),
                },
                ignore_local: true,
                priority: 1,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })
            .unwrap();
        node.rx_packed_queue_from_side(
            &wire_format::pack_packet(
                &Packet::new(
                    crate::DataType::ReliableAck,
                    &[crate::DataEndpoint::TelemetryError],
                    "RX_PEER",
                    2,
                    Arc::<[u8]>::from([0u8; 8]),
                )
                .unwrap(),
            ),
            side,
        )
        .unwrap();
        node.process_all_queues_with_timeout_impl(1).unwrap();
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "control RX exhausting its cooperative budget must still allow one queued bulk TX"
        );
    }
}

#[cfg(all(test, feature = "discovery", feature = "std"))]
fn untemplated_test_node() -> Router {
    Router::new_with_clock(RouterConfig::default(), Box::new(|| 0))
}
#[cfg(all(test, feature = "discovery", feature = "std"))]
fn untemplated_test_options() -> RouterSideOptions {
    RouterSideOptions::default().with_small_packet_transport(64)
}
#[cfg(all(test, feature = "discovery", feature = "std"))]
#[allow(clippy::duplicate_mod)]
#[path = "tests/untemplated_transport.rs"]
mod untemplated_transport_tests;

#[cfg(all(test, feature = "std", feature = "discovery"))]
mod queued_producer_maintenance_tests {
    use super::*;
    #[test]
    fn queued_publication_defers_discovery_to_worker_maintenance() {
        crate::tests::ensure_common_test_schema();
        let ty = DataType::named("GPS_DATA");
        for variant in 0..4 {
            let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
            let output = sent.clone();
            let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
            router.add_side_packed("wire", move |bytes| {
                output
                    .lock()
                    .unwrap()
                    .push(wire_format::unpack_packet(bytes)?.data_type());
                Ok(())
            });
            router.clear_queues();
            let packet =
                Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], message_meta(ty).endpoints_ref(), 42)
                    .unwrap();
            match variant {
                0 => router.tx_queue(packet).unwrap(),
                1 => router
                    .tx_packed_queue(wire_format::pack_packet(&packet))
                    .unwrap(),
                2 => router.log_queue(ty, &[1.0f32, 2.0, 3.0]).unwrap(),
                _ => router.log_queue_ts(ty, 42, &[1.0f32, 2.0, 3.0]).unwrap(),
            }
            assert!(
                sent.lock().unwrap().is_empty(),
                "producer invoked a transport"
            );
            assert_eq!(
                router.state.lock().transmit_queue.len(),
                1,
                "queued API performed discovery on the producer stack (variant {variant})"
            );
            router.periodic(0).unwrap();
            let sent = sent.lock().unwrap();
            assert!(sent.contains(&ty));
            assert!(
                sent.iter().copied().any(discovery::is_discovery_type),
                "worker maintenance must still announce the board"
            );
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod bounded_fair_queue_tests {
    use super::*;
    #[test]
    fn small_canonical_reports_survive_fast_senders_fixed_ring_bursts() {
        let ep = crate::config::register_endpoint("ROUTER_SMALL_QUEUE_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "ROUTER_SMALL_QUEUE_REPORT",
            "",
            crate::MessageElement::Static(
                4,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::None,
            0,
        )
        .unwrap();
        for tx in [false, true] {
            for slow_last in [false, true] {
                let node = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
                let make = |sender| {
                    RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                        &Packet::new(ty, &[ep], sender, 1, Arc::<[u8]>::from([1; 4])).unwrap(),
                    )))
                };
                let rx = |data| RouterRxItem {
                    src: None,
                    data,
                    priority: 0,
                };
                let tx_item = |data| TxQueued {
                    disposable: true,
                    item: RouterTxItem::Broadcast(data),
                    ignore_local: true,
                    priority: 0,
                    delivery_state: QueuedDelivery::Untracked,
                    accepted_type: 0,
                    deferred_since_ms: 0,
                    retry_after_ms: 0,
                };
                let mut st = node.state.lock();
                st.memory.max_queue_budget = usize::MAX;
                if tx {
                    st.transmit_queue = BoundedDeque::new(8192, 3 * size_of::<TxQueued>(), 1.0);
                } else {
                    st.received_queue = BoundedDeque::new(8192, 3 * size_of::<RouterRxItem>(), 1.0);
                }
                let order = if slow_last {
                    ["FAST", "FAST", "SLOW"]
                } else {
                    ["SLOW", "FAST", "FAST"]
                };
                for sender in order.into_iter().chain(core::iter::repeat_n("FAST", 32)) {
                    if tx {
                        st.push_transmit(tx_item(make(sender))).unwrap();
                    } else {
                        st.push_received(rx(make(sender))).unwrap();
                    }
                }
                let slow = wire_format::source_address_for_sender("SLOW");
                let retained = if tx {
                    st.transmit_queue
                        .iter()
                        .any(|item| RouterInner::tx_bulk_owner(item) == Some(slow))
                } else {
                    st.received_queue.iter().any(|item| {
                        RouterInner::fair_bulk_owner(&item.data, item.priority) == Some(slow)
                    })
                };
                assert!(
                    retained,
                    "small report was displaced: tx={tx}, slow_last={slow_last}"
                );
            }
        }
    }

    #[test]
    fn slow_stream_survives_same_board_fast_stream_bursts() {
        let ep = crate::config::register_endpoint("ROUTER_STREAM_QUEUE_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "ROUTER_STREAM_QUEUE_FAST",
            "",
            crate::MessageElement::Static(
                64,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::None,
            0,
        )
        .unwrap();
        let slow_ty = crate::config::register_data_type_with_description(
            "ROUTER_STREAM_QUEUE_SLOW",
            "",
            crate::MessageElement::Static(
                64,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::None,
            0,
        )
        .unwrap();
        for mode in 0..3 {
            for tx in [false, true] {
                for slow_last in [false, true] {
                    let node = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
                    let make = |sender| {
                        let packet = Packet::new(
                            if sender == "SLOW" { slow_ty } else { ty },
                            &[ep],
                            "SAME_BOARD",
                            1,
                            Arc::<[u8]>::from([1; 64]),
                        )
                        .unwrap();
                        if mode == 1 {
                            RouterItem::Packet(packet)
                        } else {
                            RouterItem::Packed(crate::shared_bytes::convert(
                                wire_format::pack_packet(&packet),
                            ))
                        }
                    };
                    let rx = |data| RouterRxItem {
                        src: None,
                        data,
                        priority: 0,
                    };
                    let tx_item = |data| TxQueued {
                        disposable: true,
                        item: RouterTxItem::Broadcast(data),
                        ignore_local: true,
                        priority: 0,
                        delivery_state: QueuedDelivery::Untracked,
                        accepted_type: 0,
                        deferred_since_ms: 0,
                        retry_after_ms: 0,
                    };
                    let mut st = node.state.lock();
                    st.memory.max_queue_budget = usize::MAX;
                    if mode == 0 {
                        if tx {
                            st.transmit_queue =
                                BoundedDeque::new(8192, 3 * size_of::<TxQueued>(), 1.0);
                        } else {
                            st.received_queue =
                                BoundedDeque::new(8192, 3 * size_of::<RouterRxItem>(), 1.0);
                        }
                    } else if mode == 1 {
                        let cost = if tx {
                            tx_item(make("SLOW")).byte_cost()
                                + 2 * tx_item(make("FAST")).byte_cost()
                        } else {
                            rx(make("SLOW")).byte_cost() + 2 * rx(make("FAST")).byte_cost()
                        };
                        if tx {
                            st.transmit_queue = BoundedDeque::new(cost, cost, 2.0);
                        } else {
                            st.received_queue = BoundedDeque::new(cost, cost, 2.0);
                        }
                    }
                    let order = if slow_last {
                        ["FAST", "FAST", "SLOW"]
                    } else {
                        ["SLOW", "FAST", "FAST"]
                    };
                    for (index, sender) in order
                        .into_iter()
                        .chain(core::iter::repeat_n("FAST", 32))
                        .enumerate()
                    {
                        if mode == 2 && index == 3 {
                            st.memory.max_queue_budget = st.shared_queue_bytes_used();
                        }
                        if tx {
                            st.push_transmit(tx_item(make(sender))).unwrap();
                        } else {
                            st.push_received(rx(make(sender))).unwrap();
                        }
                    }
                    let is_slow = |data: &RouterItem| match data {
                        RouterItem::Packet(p) => p.data_type() == slow_ty,
                        RouterItem::Packed(b) => {
                            wire_format::scheduling_type(b.as_ref()) == Some(slow_ty)
                        }
                    };
                    let retained = if tx {
                        st.transmit_queue.iter().any(|item| {
                            let data = match &item.item {
                                RouterTxItem::Broadcast(data)
                                | RouterTxItem::ToSide { data, .. } => data,
                                _ => return false,
                            };
                            is_slow(data)
                        })
                    } else {
                        st.received_queue.iter().any(|item| is_slow(&item.data))
                    };
                    assert!(
                        retained,
                        "slow stream displaced: mode={mode}, tx={tx}, slow_last={slow_last}"
                    );
                }
            }
        }
    }

    #[test]
    fn fast_producer_preserves_slow_reports_at_each_queue_boundary() {
        let ep = crate::config::register_endpoint("QUEUE_FAIR_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "QUEUE_FAIR_REPORT",
            "",
            MessageElement::Static(64, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[ep],
            crate::ReliableMode::None,
            0,
        )
        .unwrap();
        for mode in 0..3 {
            for tx in [false, true] {
                for slow_last in [false, true] {
                    for next_sender in ["FAST", "NEW_SLOW"] {
                        let router =
                            Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
                        let make = |sender| {
                            RouterItem::Packet(
                                Packet::new(ty, &[ep], sender, 1, Arc::<[u8]>::from([1; 64]))
                                    .unwrap(),
                            )
                        };
                        let rx = |data| RouterRxItem {
                            src: None,
                            data,
                            priority: 0,
                        };
                        let tx_item = |data| TxQueued {
                            disposable: true,
                            item: RouterTxItem::Broadcast(data),
                            ignore_local: true,
                            priority: 0,
                            delivery_state: QueuedDelivery::Untracked,
                            accepted_type: 0,
                            deferred_since_ms: 0,
                            retry_after_ms: 0,
                        };
                        let order = if slow_last {
                            ["FAST", "FAST", "SLOW"]
                        } else {
                            ["SLOW", "FAST", "FAST"]
                        };
                        let mut st = router.state.lock();
                        st.memory.max_queue_budget = usize::MAX;
                        let cost = if tx {
                            order.iter().map(|s| tx_item(make(s)).byte_cost()).sum()
                        } else {
                            order.iter().map(|s| rx(make(s)).byte_cost()).sum()
                        };
                        if mode == 0 {
                            if tx {
                                st.transmit_queue = BoundedDeque::new(cost, cost, 2.0);
                            } else {
                                st.received_queue = BoundedDeque::new(cost, cost, 2.0);
                            }
                        } else if mode == 1 {
                            if tx {
                                st.transmit_queue =
                                    BoundedDeque::new(cost * 10, 3 * size_of::<TxQueued>(), 1.0);
                            } else {
                                st.received_queue = BoundedDeque::new(
                                    cost * 10,
                                    3 * size_of::<RouterRxItem>(),
                                    1.0,
                                );
                            }
                        }
                        for sender in order {
                            if tx {
                                st.push_transmit(tx_item(make(sender))).unwrap();
                            } else {
                                st.push_received(rx(make(sender))).unwrap();
                            }
                        }
                        if mode == 2 {
                            st.memory.max_queue_budget = st.shared_queue_bytes_used();
                        }
                        if tx {
                            st.push_transmit(tx_item(make(next_sender))).unwrap_or_else(|error| panic!("admit error {error:?}: mode={mode} tx={tx} slow_last={slow_last} incoming={next_sender}"));
                        } else {
                            st.push_received(rx(make(next_sender))).unwrap_or_else(|error| panic!("admit error {error:?}: mode={mode} tx={tx} slow_last={slow_last} incoming={next_sender}"));
                        }
                        let slow = wire_format::source_address_for_sender("SLOW");
                        let retained = if tx {
                            st.transmit_queue
                                .iter()
                                .any(|item| RouterInner::tx_bulk_owner(item) == Some(slow))
                        } else {
                            st.received_queue.iter().any(|item| {
                                RouterInner::fair_bulk_owner(&item.data, item.priority)
                                    == Some(slow)
                            })
                        };
                        assert!(
                            retained,
                            "slow report evicted: mode={mode} tx={tx} slow_last={slow_last} incoming={next_sender}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "discovery"))]
#[test]
fn cow_discovery_rejected_growth_keeps_original_graph_and_routes() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::default().with_sender("GB"), Box::new(|| 0));
    let side = node.add_side_packed("can", |_| Ok(()));
    let baseline = discovery::build_discovery_topology(
        "PEER",
        0,
        &[TopologyBoardNode {
            sender_id: "PEER".into(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: Vec::new(),
        }],
    )
    .unwrap();
    node.rx_from_side(&baseline, side).unwrap();
    node.process_all_queues().unwrap();
    node.clear_queues();
    let before = node.export_topology();
    let original = {
        let mut st = node.state.lock();
        let graph = st.discovery_routes[&side].announcers["PEER"]
            .topology_boards
            .clone();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
        graph
    };
    let update = discovery::build_discovery_topology_delta(
        "PEER",
        1,
        &[TopologyBoardNode {
            sender_id: "PEER".into(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: vec!["NEW_CLOCK".into()],
            connections: vec!["NEW_NEIGHBOR".into()],
        }],
        &[],
    )
    .unwrap();
    assert!(
        node.rx_from_side(&update, side)
            .and_then(|_| node.process_all_queues())
            .is_err(),
        "growth must fail when no queue budget can be reclaimed"
    );
    assert_eq!(node.export_topology().routes, before.routes);
    let st = node.state.lock();
    assert!(Arc::ptr_eq(
        &original,
        &st.discovery_routes[&side].announcers["PEER"].topology_boards
    ));
    assert!(original[0].connections.is_empty());
    assert!(original[0].reachable_timesync_sources.is_empty());
}

#[cfg(all(test, feature = "std"))]
mod bounded_rx_priority_tests {
    use super::*;
    #[test]
    fn retained_slow_report_cannot_starve_behind_continuous_fast_data() {
        let ep =
            crate::config::register_endpoint("RouterRxItem_FAIR_EP_RouterInner", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "RouterRxItem_FAIR_DATA_RouterInner",
            "",
            crate::MessageElement::Static(
                1,
                crate::MessageDataType::Float32,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::None,
            0,
        )
        .unwrap();
        let node = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
        let mut st = node.state.lock();
        st.memory.max_queue_budget = 65536;
        st.received_queue = BoundedDeque::new(32768, 16 * size_of::<RouterRxItem>(), 1.0);
        let make = |sender: &str, stamp, priority| {
            let packet = Packet::new(ty, &[ep], sender, stamp, Arc::<[u8]>::from([0; 4])).unwrap();
            RouterRxItem {
                src: None,
                data: RouterItem::Packet(packet),
                priority,
            }
        };
        st.push_received(make("VALVE", 0, 0)).unwrap();
        let mut delivered = false;
        for tick in 1..=32u64 {
            for index in 0..3 {
                st.push_received(make("DAQ", tick * 3 + index, 16)).unwrap();
            }
            let item = st.pop_received_fair().unwrap();
            let sender = match &item.data {
                RouterItem::Packet(packet) => packet.sender(),
                _ => panic!("expected packet"),
            };
            if sender == "VALVE" {
                delivered = true;
                assert!(tick <= u64::from(MAX_PRIORITY_BURST) + 1);
                break;
            }
        }
        assert!(
            delivered,
            "retention alone does not deliver low-rate reports under a continuous higher-priority source"
        );
        st.received_queue.clear();
        st.rx_priority_burst = MAX_PRIORITY_BURST;
        st.push_received(make("VALVE", 100, 0)).unwrap();
        st.push_received(make("VALVE", 101, 0)).unwrap();
        st.push_received(make("DAQ", 102, 16)).unwrap();
        st.push_received(make("COMMAND", 103, 254)).unwrap();
        assert_eq!(
            st.pop_received_fair().unwrap().priority,
            254,
            "a fairness turn must never delay protected control"
        );
        let mut first_slow = None;
        for tick in 0..=MAX_PRIORITY_BURST {
            st.push_received(make("DAQ", 200 + u64::from(tick), 16))
                .unwrap();
            let item = st.pop_received_fair().unwrap();
            if let RouterItem::Packet(packet) = &item.data
                && packet.sender() == "VALVE"
            {
                first_slow = Some(packet.timestamp());
                break;
            }
        }
        assert_eq!(
            first_slow,
            Some(100),
            "fairness preserves same-priority FIFO order"
        );
        st.rx_priority_burst = MAX_PRIORITY_BURST;
        drop(st);
        node.clear_rx_queue();
        assert_eq!(node.state.lock().rx_priority_burst, 0);
    }
}
