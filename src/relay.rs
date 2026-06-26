use crate::config::{
    MAX_QUEUE_BUDGET, MAX_RECENT_RX_IDS, QUEUE_GROW_STEP, RECENT_RX_QUEUE_BYTES,
    RELIABLE_MAX_END_TO_END_ACK_CACHE, RELIABLE_MAX_END_TO_END_PENDING, RELIABLE_MAX_PENDING,
    RELIABLE_MAX_RETRIES, RELIABLE_MAX_RETURN_ROUTES, RELIABLE_RETRANSMIT_MS, STARTING_QUEUE_SIZE,
};
use crate::diagnostics::{
    AdaptiveLinkStats, DiscoveryRuntimeStats, QueueRuntimeStats, ReliableRuntimeStats,
    RouteModeStats, RouteOverrideStats, RoutePriorityStats, RouteWeightStats, RuntimeSideStats,
    RuntimeStatsSnapshot, RuntimeTypeStats, TypedRouteOverrideStats,
};
#[cfg(feature = "discovery")]
use crate::discovery::{
    self, ClientStatsSnapshot, DISCOVERY_ROUTE_TTL_MS, DISCOVERY_SLOW_LINK_FULL_INTERVAL_MS,
    DISCOVERY_SLOW_LINK_PING_INTERVAL_MS, DiscoveryCadenceState,
    TIMESYNC_SLOW_LINK_MIN_INTERVAL_MS, TopologyAnnouncerRoute, TopologyBoardNode,
    TopologySideRoute, TopologySnapshot,
};
use crate::packet::{Packet, hash_bytes_u64};
use crate::queue::{BoundedDeque, ByteCost};
use crate::wire_format;
use crate::{is_reliable_type, message_meta, message_priority, reliable_mode};
use crate::{
    router::{Clock, CompactTimestampOmissionPolicy, SideTransportProfile},
    {
        RouteSelectionMode, TelemetryError, TelemetryResult,
        lock::{ReentryGate, ReentryGuard, RouterMutex},
    },
};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::{sync::Arc, vec, vec::Vec};
use core::mem::size_of;
use crc32fast::Hasher as Crc32Hasher;

/// Logical side index (CAN, UART, RADIO, etc.)
pub type RelaySideId = usize;
const SIDE_TRANSPORT_MAGIC: &[u8; 3] = b"SDT";
const SIDE_TRANSPORT_KIND_FULL: u8 = 0x01;
const SIDE_TRANSPORT_KIND_COMPACT: u8 = 0x02;
const SIDE_TRANSPORT_KIND_CHUNK: u8 = 0x03;
const SIDE_TRANSPORT_KIND_COMPACT_DELTA: u8 = 0x04;
const SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP: u8 = 0x05;
const SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED: u8 = 0x01;
const SIDE_TRANSPORT_FLAG_SENDER_COMPRESSED: u8 = 0x02;
const SIDE_TRANSPORT_FLAG_WIRE_CONTRACT: u8 = 0x04;
const SIDE_TRANSPORT_FLAG_PACKET_NONCE: u8 = 0x08;
const SIDE_TRANSPORT_FLAG_ENDPOINT_BITMAP_PRESENT: u8 = 0x20;
const CONTROL_SLOW_LINK_CAPACITY_BPS: u64 = 512;
const SIDE_TRANSPORT_CHUNK_OVERHEAD: usize = 3 + 1 + 4 + 2 + 2 + wire_format::CRC32_BYTES;
const SIDE_TRANSPORT_EP_BITMAP_BITS: usize = (crate::MAX_VALUE_DATA_ENDPOINT as usize) + 1;
const SIDE_TRANSPORT_EP_BITMAP_BYTES: usize = SIDE_TRANSPORT_EP_BITMAP_BITS.div_ceil(8);
pub const IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES: usize =
    crate::router::IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES;
pub const IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES: usize =
    crate::router::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES;
pub const DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT: usize =
    crate::router::DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT;
/// Packet Handler function type
type PacketHandlerFn = dyn Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static;

/// Packed Handler function type
type PackedHandlerFn = dyn Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static;

/// TX handler for a relay side: either packed or packet-based.
#[derive(Clone)]
pub enum RelayTxHandlerFn {
    Packed(Arc<PackedHandlerFn>),
    Packet(Arc<PacketHandlerFn>),
}

#[derive(Clone, Copy, Debug)]
pub struct RelaySideOptions {
    /// Enables the relay's per-link reliable transport layer on this side.
    ///
    /// When `true` and the side uses a packed TX handler, reliable schema traffic on this hop
    /// gains relay-managed sequence numbers, ACKs, packet requests, and retransmits.
    /// Packet-output sides still receive decoded packets rather than packed reliable framing.
    pub reliable_enabled: bool,
    /// Marks the side as eligible for link-local-only endpoints and discovery routes.
    pub link_local_enabled: bool,
    /// Allows packets received from this side to enter relay processing.
    pub ingress_enabled: bool,
    /// Allows the relay to transmit packets toward this side.
    pub egress_enabled: bool,
    /// Enables side-local header-template reuse for packed transport.
    pub header_template_enabled: bool,
    /// Maximum number of bytes to emit per packed TX callback.
    ///
    /// When non-zero and a packed frame would exceed this size, the relay
    /// splits it into ordered side-transport chunks and reassembles them on RX
    /// before normal relay processing. This is intended for fixed-size links
    /// such as CAN or I2C while keeping the user API packet-oriented.
    pub max_frame_bytes: usize,
    /// Target total side-transport overhead for compact follow-up frames.
    pub compact_header_target_bytes: usize,
    /// Maximum side-local header templates retained for TX and RX dictionaries.
    pub max_side_transport_templates: usize,
    /// Omits the timestamp field from compact follow-up frames when it is unchanged.
    pub omit_unchanged_compact_timestamps: bool,
    /// Optional per-data-type timestamp omission policy for compact follow-up frames.
    pub compact_timestamp_omission_types: CompactTimestampOmissionPolicy,
    /// Declared compact-link profile for stats and future negotiation.
    pub side_transport_profile: SideTransportProfile,
}

impl Default for RelaySideOptions {
    fn default() -> Self {
        Self {
            reliable_enabled: false,
            link_local_enabled: false,
            ingress_enabled: true,
            egress_enabled: true,
            header_template_enabled: false,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT,
            omit_unchanged_compact_timestamps: false,
            compact_timestamp_omission_types: CompactTimestampOmissionPolicy::none(),
            side_transport_profile: SideTransportProfile::Canonical,
        }
    }
}

impl RelaySideOptions {
    /// Convenience preset for bounded packed-side transport.
    ///
    /// `max_frame_bytes == 0` leaves packed frames unbounded. Values greater
    /// than zero enable relay-managed chunking/reassembly on this side.
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
    pub fn with_omitted_unchanged_compact_timestamps_for_type(
        mut self,
        ty: crate::DataType,
    ) -> Self {
        self.header_template_enabled = true;
        self.compact_timestamp_omission_types.insert(ty);
        self
    }

    #[inline]
    pub fn effective_transport_profile(self) -> SideTransportProfile {
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
    pub fn link_capabilities(self) -> discovery::LinkCapabilities {
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

/// One side of the relay – a name + TX handler.
#[derive(Clone)]
pub struct RelaySide {
    pub name: &'static str,
    pub tx_handler: RelayTxHandlerFn,
    pub opts: RelaySideOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayItem {
    Packed(Arc<[u8]>),
    Packet(Arc<Packet>),
}

/// Item that was received by the relay from some side.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayRxItem {
    src: RelaySideId,
    data: RelayItem,
    priority: u8,
}

impl ByteCost for RelayRxItem {
    fn byte_cost(&self) -> usize {
        match &self.data {
            RelayItem::Packed(bytes) => bytes.len(),
            RelayItem::Packet(pkt) => pkt.byte_cost(),
        }
    }
}

/// Item that is ready to be transmitted out a destination side.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayTxItem {
    src: Option<RelaySideId>,
    dst: RelaySideId,
    data: RelayItem,
    priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayReplayItem {
    dst: RelaySideId,
    bytes: Arc<[u8]>,
    priority: u8,
}

impl ByteCost for RelayTxItem {
    fn byte_cost(&self) -> usize {
        match &self.data {
            RelayItem::Packed(bytes) => bytes.len(),
            RelayItem::Packet(pkt) => pkt.byte_cost(),
        }
    }
}

impl ByteCost for RelayReplayItem {
    fn byte_cost(&self) -> usize {
        self.bytes.len()
    }
}

// -------------------- Reliable delivery state (relay) --------------------

#[derive(Debug, Clone)]
struct ReliableTxState {
    next_seq: u32,
    sent_order: VecDeque<u32>,
    sent: BTreeMap<u32, ReliableSent>,
}

#[derive(Debug, Clone)]
struct ReliableSent {
    bytes: Arc<[u8]>,
    last_send_ms: u64,
    retries: u32,
    queued: bool,
    partial_acked: bool,
}

#[derive(Debug, Clone)]
struct ReliableRxState {
    expected_seq: u32,
    buffered: BTreeMap<u32, Arc<[u8]>>,
}

#[derive(Debug, Clone)]
struct ReliableReturnRouteState {
    side: RelaySideId,
}

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DiscoverySenderState {
    reachable: Vec<crate::DataEndpoint>,
    reachable_timesync_sources: Vec<String>,
    topology_boards: Vec<TopologyBoardNode>,
    last_seen_ms: u64,
}

#[inline]
fn is_internal_control_type(ty: crate::DataType) -> bool {
    if matches!(
        ty,
        crate::DataType::ReliableAck
            | crate::DataType::ReliablePartialAck
            | crate::DataType::ReliablePacketRequest
    ) {
        return true;
    }

    #[cfg(feature = "timesync")]
    if matches!(
        ty,
        crate::DataType::TimeSyncAnnounce
            | crate::DataType::TimeSyncRequest
            | crate::DataType::TimeSyncResponse
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

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DiscoverySideState {
    reachable: Vec<crate::DataEndpoint>,
    reachable_timesync_sources: Vec<String>,
    last_seen_ms: u64,
    announcers: BTreeMap<String, DiscoverySenderState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SideChunkAssembly {
    total: u16,
    received: BTreeMap<u16, Arc<[u8]>>,
}

#[derive(Clone, Debug, Default)]
struct SideTransportState {
    tx_template_ids: BTreeMap<u64, u32>,
    tx_templates: BTreeMap<u64, SideHeaderTemplate>,
    tx_last_timestamps: BTreeMap<u32, u64>,
    rx_templates: BTreeMap<u64, SideHeaderTemplate>,
    rx_templates_by_id: BTreeMap<u32, SideHeaderTemplate>,
    rx_last_timestamps: BTreeMap<u32, u64>,
    rx_chunks: BTreeMap<u32, SideChunkAssembly>,
    next_chunk_id: u32,
    next_template_id: u32,
}

impl SideTransportState {
    fn tx_template_count(&self) -> usize {
        self.tx_template_ids.len()
    }

    fn rx_template_count(&self) -> usize {
        self.rx_templates_by_id.len()
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
        let mut evicted = false;
        if self.tx_template_ids.len() >= max_templates
            && !self.tx_template_ids.contains_key(&template.hash)
            && let Some(old_hash) = self.tx_template_ids.keys().next().copied()
        {
            if let Some(old_id) = self.tx_template_ids.remove(&old_hash) {
                self.tx_last_timestamps.remove(&old_id);
            }
            self.tx_templates.remove(&old_hash);
            evicted = true;
        }
        self.tx_template_ids.insert(template.hash, template_id);
        self.tx_templates.insert(template.hash, template);
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
        let mut evicted = false;
        if self.rx_templates_by_id.len() >= max_templates
            && !self.rx_templates_by_id.contains_key(&template_id)
            && let Some(old_id) = self.rx_templates_by_id.keys().next().copied()
            && let Some(old_template) = self.rx_templates_by_id.remove(&old_id)
        {
            self.rx_templates.remove(&old_template.hash);
            self.rx_last_timestamps.remove(&old_id);
            evicted = true;
        }
        self.rx_templates_by_id
            .insert(template_id, template.clone());
        self.rx_templates.insert(template.hash, template);
        evicted
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SideHeaderTemplate {
    hash: u64,
    base_flags: u8,
    prefix: Arc<[u8]>,
    between: Arc<[u8]>,
    reliable_flags: Option<u8>,
}

type SideTemplateExtract<'a> = (
    SideHeaderTemplate,
    crate::DataType,
    u8,
    u64,
    u64,
    u16,
    Option<(u32, u32)>,
    &'a [u8],
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SideCompactTimestampMode {
    Absolute,
    Delta,
    Omitted,
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

#[cfg(feature = "discovery")]
#[derive(Debug, Clone, Default)]
struct DiscoverySideThrottleState {
    next_ping_ms: u64,
    next_full_ms: u64,
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
    Full,
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
        ((u128::from(self.window_bytes)).saturating_mul(1000) / u128::from(elapsed_ms))
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

#[derive(Debug, Clone, Default)]
struct TypeRuntimeStatsInner {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    relayed_tx_packets: u64,
    relayed_tx_bytes: u64,
    relayed_rx_packets: u64,
    relayed_rx_bytes: u64,
    tx_retries: u64,
    handler_failures: u64,
}

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
    tx_retries: u64,
    tx_handler_failures: u64,
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
    fn type_stats_mut(&mut self, ty: crate::DataType) -> &mut TypeRuntimeStatsInner {
        self.data_types.entry(ty.as_u32()).or_default()
    }

    fn note_tx(&mut self, ty: crate::DataType, bytes: usize, retries: usize) {
        self.tx_packets = self.tx_packets.saturating_add(1);
        self.tx_bytes = self.tx_bytes.saturating_add(bytes as u64);
        self.relayed_tx_packets = self.relayed_tx_packets.saturating_add(1);
        self.relayed_tx_bytes = self.relayed_tx_bytes.saturating_add(bytes as u64);
        self.tx_retries = self.tx_retries.saturating_add(retries as u64);
        self.total_handler_retries = self.total_handler_retries.saturating_add(retries as u64);
        let stats = self.type_stats_mut(ty);
        stats.tx_packets = stats.tx_packets.saturating_add(1);
        stats.tx_bytes = stats.tx_bytes.saturating_add(bytes as u64);
        stats.relayed_tx_packets = stats.relayed_tx_packets.saturating_add(1);
        stats.relayed_tx_bytes = stats.relayed_tx_bytes.saturating_add(bytes as u64);
        stats.tx_retries = stats.tx_retries.saturating_add(retries as u64);
    }

    fn note_rx(&mut self, ty: crate::DataType, bytes: usize) {
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.rx_bytes = self.rx_bytes.saturating_add(bytes as u64);
        self.relayed_rx_packets = self.relayed_rx_packets.saturating_add(1);
        self.relayed_rx_bytes = self.relayed_rx_bytes.saturating_add(bytes as u64);
        let stats = self.type_stats_mut(ty);
        stats.rx_packets = stats.rx_packets.saturating_add(1);
        stats.rx_bytes = stats.rx_bytes.saturating_add(bytes as u64);
        stats.relayed_rx_packets = stats.relayed_rx_packets.saturating_add(1);
        stats.relayed_rx_bytes = stats.relayed_rx_bytes.saturating_add(bytes as u64);
    }

    fn note_tx_failure(&mut self, ty: crate::DataType, retries: usize) {
        self.tx_handler_failures = self.tx_handler_failures.saturating_add(1);
        self.tx_retries = self.tx_retries.saturating_add(retries as u64);
        self.total_handler_retries = self.total_handler_retries.saturating_add(retries as u64);
        let stats = self.type_stats_mut(ty);
        stats.handler_failures = stats.handler_failures.saturating_add(1);
        stats.tx_retries = stats.tx_retries.saturating_add(retries as u64);
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

/// Internal state, protected by RouterMutex so all public methods can take &self.
struct RelayInner {
    sides: Vec<Option<RelaySide>>,
    route_overrides: BTreeMap<(Option<RelaySideId>, RelaySideId), bool>,
    typed_route_overrides: BTreeMap<(Option<RelaySideId>, u32, RelaySideId), bool>,
    route_weights: BTreeMap<(Option<RelaySideId>, RelaySideId), u32>,
    route_priorities: BTreeMap<(Option<RelaySideId>, RelaySideId), u32>,
    source_route_modes: BTreeMap<Option<RelaySideId>, RouteSelectionMode>,
    route_selection_cursors: BTreeMap<Option<RelaySideId>, u64>,
    adaptive_route_stats: BTreeMap<RelaySideId, AdaptiveRouteStats>,
    side_runtime_stats: BTreeMap<RelaySideId, SideRuntimeStatsInner>,
    side_transport: BTreeMap<RelaySideId, SideTransportState>,
    rx_queue: BoundedDeque<RelayRxItem>,
    tx_queue: BoundedDeque<RelayTxItem>,
    replay_queue: BoundedDeque<RelayReplayItem>,
    recent_rx: BoundedDeque<u64>,
    reliable_tx: BTreeMap<(RelaySideId, u32), ReliableTxState>,
    reliable_rx: BTreeMap<(RelaySideId, u32), ReliableRxState>,
    reliable_return_routes: BTreeMap<u64, ReliableReturnRouteState>,
    reliable_return_route_order: VecDeque<u64>,
    end_to_end_acked_destinations: BTreeMap<u64, BTreeSet<u64>>,
    end_to_end_acked_destination_order: VecDeque<u64>,
    total_handler_failures: u64,
    total_handler_retries: u64,
    #[cfg(feature = "discovery")]
    discovery_routes: BTreeMap<RelaySideId, DiscoverySideState>,
    #[cfg(feature = "discovery")]
    discovery_cadence: DiscoveryCadenceState,
    #[cfg(feature = "discovery")]
    discovery_side_throttle: BTreeMap<RelaySideId, DiscoverySideThrottleState>,
    #[cfg(all(feature = "discovery", feature = "timesync"))]
    timesync_side_throttle: BTreeMap<RelaySideId, TimeSyncSideThrottleState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayQueueKind {
    Rx,
    Tx,
    Replay,
    Recent,
    ReliableRxBuffer,
    #[cfg(feature = "discovery")]
    Discovery,
}

impl RelayInner {
    #[cfg(feature = "discovery")]
    fn topology_board_byte_cost(board: &TopologyBoardNode) -> usize {
        board
            .sender_id
            .len()
            .saturating_add(board.reachable_endpoints.len() * size_of::<crate::DataEndpoint>())
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
            .saturating_add(state.reachable.len() * size_of::<crate::DataEndpoint>())
            .saturating_add(
                state
                    .reachable_timesync_sources
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
    fn discovery_route_byte_cost(route: &DiscoverySideState) -> usize {
        size_of::<DiscoverySideState>()
            .saturating_add(route.reachable.len() * size_of::<crate::DataEndpoint>())
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
    }

    #[cfg(feature = "discovery")]
    fn discovery_bytes_used(&self) -> usize {
        self.discovery_routes
            .values()
            .map(Self::discovery_route_byte_cost)
            .sum()
    }

    #[inline]
    fn reliable_rx_buffered_bytes(&self) -> usize {
        self.reliable_rx
            .values()
            .flat_map(|state| state.buffered.values())
            .map(|bytes| size_of::<Arc<[u8]>>() + bytes.len())
            .sum()
    }

    #[inline]
    fn shared_queue_bytes_used(&self) -> usize {
        self.rx_queue
            .bytes_used()
            .saturating_add(self.tx_queue.bytes_used())
            .saturating_add(self.replay_queue.bytes_used())
            .saturating_add(self.recent_rx.max_bytes())
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
            })
    }

    fn reliable_rx_buffer_len(&self) -> usize {
        self.reliable_rx
            .values()
            .map(|state| state.buffered.len())
            .sum()
    }

    fn pop_reliable_rx_buffered(&mut self) -> Option<Arc<[u8]>> {
        let key = self
            .reliable_rx
            .iter()
            .find_map(|(key, state)| (!state.buffered.is_empty()).then_some(*key))?;
        self.reliable_rx
            .get_mut(&key)?
            .buffered
            .pop_first()
            .map(|(_, v)| v)
    }

    fn pop_shared_queue_item(&mut self, preferred: RelayQueueKind) -> bool {
        match preferred {
            RelayQueueKind::Rx => self.rx_queue.pop_front().is_some(),
            RelayQueueKind::Tx => self.tx_queue.pop_front().is_some(),
            RelayQueueKind::Replay => self.replay_queue.pop_front().is_some(),
            RelayQueueKind::Recent => self.recent_rx.pop_front().is_some(),
            RelayQueueKind::ReliableRxBuffer => self.pop_reliable_rx_buffered().is_some(),
            #[cfg(feature = "discovery")]
            RelayQueueKind::Discovery => self.pop_discovery_route(),
        }
    }

    #[cfg(feature = "discovery")]
    fn pop_discovery_route(&mut self) -> bool {
        let Some((&side, _)) = self
            .discovery_routes
            .iter()
            .min_by_key(|(_, route)| route.last_seen_ms)
        else {
            return false;
        };
        self.discovery_routes.remove(&side);
        Self::queue_budget_warning("topology route evicted because MAX_QUEUE_BUDGET is full");
        true
    }

    fn largest_shared_queue(&self) -> Option<RelayQueueKind> {
        let candidates = [
            (
                RelayQueueKind::Rx,
                self.rx_queue.bytes_used(),
                self.rx_queue.len(),
            ),
            (
                RelayQueueKind::Tx,
                self.tx_queue.bytes_used(),
                self.tx_queue.len(),
            ),
            (
                RelayQueueKind::Replay,
                self.replay_queue.bytes_used(),
                self.replay_queue.len(),
            ),
            (RelayQueueKind::Recent, 0, 0),
            (
                RelayQueueKind::ReliableRxBuffer,
                self.reliable_rx_buffered_bytes(),
                self.reliable_rx_buffer_len(),
            ),
            #[cfg(feature = "discovery")]
            (
                RelayQueueKind::Discovery,
                self.discovery_bytes_used(),
                self.discovery_routes.len(),
            ),
        ];
        candidates
            .into_iter()
            .filter(|(_, bytes, len)| *bytes > 0 && *len > 0)
            .max_by_key(|(kind, bytes, _)| {
                (
                    *bytes,
                    if *kind == RelayQueueKind::ReliableRxBuffer {
                        0
                    } else {
                        1
                    },
                )
            })
            .map(|(kind, _, _)| kind)
    }

    fn make_shared_queue_room(
        &mut self,
        incoming_cost: usize,
        preferred: RelayQueueKind,
    ) -> TelemetryResult<()> {
        if incoming_cost > MAX_QUEUE_BUDGET {
            return Err(TelemetryError::PacketTooLarge(
                "Item exceeds maximum shared queue budget",
            ));
        }

        while self.shared_queue_bytes_used().saturating_add(incoming_cost) > MAX_QUEUE_BUDGET {
            let victim = self.largest_shared_queue().unwrap_or(preferred);
            if victim == RelayQueueKind::Discovery {
                Self::queue_budget_warning("topology data is using the largest queue budget share");
            }
            if !self.pop_shared_queue_item(victim) && !self.pop_shared_queue_item(preferred) {
                return Err(TelemetryError::PacketTooLarge(
                    "Item exceeds maximum shared queue budget",
                ));
            }
        }

        Ok(())
    }

    #[inline]
    fn queue_budget_warning(msg: &str) {
        #[cfg(feature = "std")]
        eprintln!("sedsnet queue budget warning: {msg}");
        let _ = msg;
    }

    #[cfg(feature = "discovery")]
    fn fit_discovery_budget(&mut self) {
        while self.shared_queue_bytes_used() > MAX_QUEUE_BUDGET {
            if !self.pop_discovery_route() {
                break;
            }
        }
    }

    fn push_rx(&mut self, item: RelayRxItem) -> TelemetryResult<()> {
        self.make_shared_queue_room(item.byte_cost(), RelayQueueKind::Rx)?;
        self.rx_queue
            .push_back_prioritized(item, |queued| queued.priority)
    }

    fn push_tx(&mut self, item: RelayTxItem) -> TelemetryResult<()> {
        self.make_shared_queue_room(item.byte_cost(), RelayQueueKind::Tx)?;
        self.tx_queue
            .push_back_prioritized(item, |queued| queued.priority)
    }

    fn push_replay(&mut self, item: RelayReplayItem) -> TelemetryResult<()> {
        self.make_shared_queue_room(item.byte_cost(), RelayQueueKind::Replay)?;
        self.replay_queue
            .push_back_prioritized(item, |queued| queued.priority)
    }

    fn push_recent_rx(&mut self, id: u64) -> TelemetryResult<()> {
        while self.recent_rx.len() >= MAX_RECENT_RX_IDS {
            let _ = self.recent_rx.pop_front();
        }
        self.make_shared_queue_room(0, RelayQueueKind::Recent)?;
        self.recent_rx.push_back(id)
    }

    fn buffer_reliable_rx(
        &mut self,
        side: RelaySideId,
        ty: crate::DataType,
        seq: u32,
        bytes: Arc<[u8]>,
    ) -> TelemetryResult<()> {
        let key = Relay::reliable_key(side, ty);
        if self
            .reliable_rx
            .get(&key)
            .is_some_and(|state| state.buffered.contains_key(&seq))
        {
            return Ok(());
        }
        let cost = size_of::<Arc<[u8]>>() + bytes.len();
        self.make_shared_queue_room(cost, RelayQueueKind::ReliableRxBuffer)?;
        let rx_state = self
            .reliable_rx
            .entry(key)
            .or_insert_with(|| ReliableRxState {
                expected_seq: 1,
                buffered: BTreeMap::new(),
            });
        if rx_state.buffered.len() >= RELIABLE_MAX_PENDING {
            let _ = rx_state.buffered.pop_first();
        }
        rx_state.buffered.insert(seq, bytes);
        Ok(())
    }
}

/// Relay that fans out packets from one side to all others.
/// - Supports both packed bytes and full Packet.
/// - Has RX & TX queues, like Router.
/// - Uses a Clock for the *_with_timeout APIs, same style as Router.
pub struct Relay {
    sender: RouterMutex<Arc<str>>,
    state: RouterMutex<RelayInner>,
    side_tx_gate: ReentryGate,
    clock: Box<dyn Clock + Send + Sync>,
}

enum RemoteSidePlan {
    Target(Vec<RelaySideId>),
}

impl Relay {
    const END_TO_END_ACK_SENDER: &'static str = "E2EACK";
    const END_TO_END_ACK_PREFIX: &'static str = "E2EACK:";

    fn relay_item_priority(data: &RelayItem) -> TelemetryResult<u8> {
        let ty = match data {
            RelayItem::Packet(pkt) => pkt.data_type(),
            RelayItem::Packed(bytes) => wire_format::peek_envelope(bytes.as_ref())?.ty,
        };
        Ok(message_priority(ty))
    }

    #[inline]
    fn is_side_tx_busy(err: &TelemetryError) -> bool {
        matches!(err, TelemetryError::Io("side tx busy"))
    }

    fn process_replay_queue_item(&self) -> TelemetryResult<bool> {
        let Some(item) = ({
            let mut st = self.state.lock();
            st.replay_queue.pop_front()
        }) else {
            return Ok(false);
        };
        let frame = wire_format::peek_frame_info(item.bytes.as_ref())?;
        let ty = frame.envelope.ty;
        let Some(hdr) = frame.reliable else {
            return Ok(false);
        };
        {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, item.dst, ty);
            if !tx_state.sent.contains_key(&hdr.seq) {
                return Ok(false);
            }
        }
        if let Err(e) = self.send_reliable_raw_to_side(item.dst, item.bytes.clone()) {
            if Self::is_side_tx_busy(&e) {
                let mut st = self.state.lock();
                st.push_replay(item)?;
                return Ok(false);
            }
            return Err(e);
        }
        let mut st = self.state.lock();
        let tx_state = self.reliable_tx_state_mut(&mut st, item.dst, ty);
        if let Some(sent) = tx_state.sent.get_mut(&hdr.seq) {
            sent.last_send_ms = self.clock.now_ms();
            sent.queued = false;
        }
        Ok(true)
    }

    fn pop_ready_tx_item(
        &self,
    ) -> Option<(
        Option<RelaySideId>,
        RelaySideId,
        RelayTxHandlerFn,
        RelaySideOptions,
        RelayItem,
    )> {
        let mut st = self.state.lock();
        if let Some(item) = st.tx_queue.pop_front() {
            let side = st.sides.get(item.dst).and_then(|side| side.clone());
            side.map(|s| (item.src, item.dst, s.tx_handler, s.opts, item.data))
        } else {
            None
        }
    }

    fn send_tx_item(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        handler: RelayTxHandlerFn,
        opts: RelaySideOptions,
        data: RelayItem,
    ) -> TelemetryResult<bool> {
        let allowed = {
            let mut st = self.state.lock();
            let ty = match &data {
                RelayItem::Packet(pkt) => Some(pkt.data_type()),
                RelayItem::Packed(bytes) => Some(wire_format::peek_envelope(bytes.as_ref())?.ty),
            };
            let route_allowed = self.route_allowed_locked(&st, src, ty, dst);
            #[cfg(all(feature = "discovery", feature = "timesync"))]
            let timesync_allowed = ty
                .map(|ty| {
                    Self::timesync_allowed_for_side_locked(&mut st, dst, ty, self.clock.now_ms())
                })
                .unwrap_or(true);
            #[cfg(not(all(feature = "discovery", feature = "timesync")))]
            let timesync_allowed = true;
            route_allowed && timesync_allowed
        };
        if !allowed {
            return Ok(false);
        }
        if opts.reliable_enabled && matches!(handler, RelayTxHandlerFn::Packed(_)) {
            self.send_reliable_to_side(dst, data)?;
            Ok(true)
        } else if let Some(adjusted) = self.adjust_reliable_for_side(opts, data)? {
            self.call_tx_handler(dst, &handler, &adjusted)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Create a new relay with the given clock.
    pub fn new(clock: Box<dyn Clock + Send + Sync>) -> Self {
        Self {
            sender: RouterMutex::new(Arc::from("RELAY")),
            state: RouterMutex::new(RelayInner {
                sides: Vec::new(),
                route_overrides: BTreeMap::new(),
                typed_route_overrides: BTreeMap::new(),
                route_weights: BTreeMap::new(),
                route_priorities: BTreeMap::new(),
                source_route_modes: BTreeMap::new(),
                route_selection_cursors: BTreeMap::new(),
                adaptive_route_stats: BTreeMap::new(),
                side_runtime_stats: BTreeMap::new(),
                side_transport: BTreeMap::new(),
                rx_queue: BoundedDeque::new(MAX_QUEUE_BUDGET, STARTING_QUEUE_SIZE, QUEUE_GROW_STEP),
                tx_queue: BoundedDeque::new(MAX_QUEUE_BUDGET, STARTING_QUEUE_SIZE, QUEUE_GROW_STEP),
                replay_queue: BoundedDeque::new(
                    MAX_QUEUE_BUDGET,
                    STARTING_QUEUE_SIZE,
                    QUEUE_GROW_STEP,
                ),
                recent_rx: BoundedDeque::new(
                    RECENT_RX_QUEUE_BYTES.max(1),
                    RECENT_RX_QUEUE_BYTES.max(1),
                    QUEUE_GROW_STEP,
                ),
                reliable_tx: BTreeMap::new(),
                reliable_rx: BTreeMap::new(),
                reliable_return_routes: BTreeMap::new(),
                reliable_return_route_order: VecDeque::new(),
                end_to_end_acked_destinations: BTreeMap::new(),
                end_to_end_acked_destination_order: VecDeque::new(),
                total_handler_failures: 0,
                total_handler_retries: 0,
                #[cfg(feature = "discovery")]
                discovery_routes: BTreeMap::new(),
                #[cfg(feature = "discovery")]
                discovery_cadence: DiscoveryCadenceState::default(),
                #[cfg(feature = "discovery")]
                discovery_side_throttle: BTreeMap::new(),
                #[cfg(all(feature = "discovery", feature = "timesync"))]
                timesync_side_throttle: BTreeMap::new(),
            }),
            side_tx_gate: ReentryGate::new(),
            clock,
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

    pub fn set_sender<S: AsRef<str>>(&self, sender: S) {
        *self.sender.lock() = Arc::from(sender.as_ref());
    }

    #[inline]
    fn try_enter_side_tx(&self) -> Option<ReentryGuard<'_>> {
        self.side_tx_gate.try_enter()
    }

    #[inline]
    fn side_tx_active(&self) -> bool {
        self.side_tx_gate.is_active()
    }

    #[inline]
    fn side_ref(st: &RelayInner, side: RelaySideId) -> TelemetryResult<&RelaySide> {
        st.sides
            .get(side)
            .and_then(|side| side.as_ref())
            .ok_or(TelemetryError::HandlerError("relay: invalid side id"))
    }

    fn note_side_tx_success(
        &self,
        side: RelaySideId,
        ty: crate::DataType,
        bytes: usize,
        attempts: usize,
    ) {
        let mut st = self.state.lock();
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_tx(ty, bytes, attempts.saturating_sub(1));
    }

    fn note_side_tx_failure(&self, side: RelaySideId, ty: crate::DataType, attempts: usize) {
        let mut st = self.state.lock();
        st.total_handler_failures = st.total_handler_failures.saturating_add(1);
        st.total_handler_retries = st.total_handler_retries.saturating_add(attempts as u64);
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_tx_failure(ty, attempts);
    }

    fn note_side_rx(&self, side: RelaySideId, ty: crate::DataType, bytes: usize) {
        let mut st = self.state.lock();
        let entry = st.side_runtime_stats.entry(side).or_default();
        entry.note_rx(ty, bytes);
    }

    #[inline]
    fn ensure_side_ingress_enabled(&self, side: RelaySideId) -> TelemetryResult<()> {
        let st = self.state.lock();
        let side_ref = Self::side_ref(&st, side)?;
        if side_ref.opts.ingress_enabled {
            Ok(())
        } else {
            Err(TelemetryError::HandlerError(
                "relay: ingress disabled for side id",
            ))
        }
    }

    #[inline]
    fn route_allowed_locked(
        &self,
        st: &RelayInner,
        src: Option<RelaySideId>,
        ty: Option<crate::DataType>,
        dst: RelaySideId,
    ) -> bool {
        let Ok(dst_side) = Self::side_ref(st, dst) else {
            return false;
        };
        if !dst_side.opts.egress_enabled {
            return false;
        }
        if let Some(src_id) = src {
            let Ok(src_side) = Self::side_ref(st, src_id) else {
                return false;
            };
            if !src_side.opts.ingress_enabled || src_id == dst {
                return false;
            }
        }
        let base_allowed = st.route_overrides.get(&(src, dst)).copied().unwrap_or(true);
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

    fn has_typed_route_overrides_locked(
        st: &RelayInner,
        src: Option<RelaySideId>,
        ty: crate::DataType,
    ) -> bool {
        st.typed_route_overrides
            .keys()
            .any(|(typed_src, typed_ty, _)| *typed_src == src && *typed_ty == ty.as_u32())
    }

    fn eligible_side_ids_locked(
        &self,
        st: &RelayInner,
        src: Option<RelaySideId>,
        ty: Option<crate::DataType>,
        restrict_link_local: bool,
    ) -> Vec<RelaySideId> {
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
        st: &mut RelayInner,
        src: Option<RelaySideId>,
        mut sides: Vec<RelaySideId>,
        origin: RouteSelectionOrigin,
    ) -> Vec<RelaySideId> {
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
                sides.sort_unstable();
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
        st: &mut RelayInner,
        src: Option<RelaySideId>,
        mut sides: Vec<RelaySideId>,
    ) -> Vec<RelaySideId> {
        sides.sort_unstable();
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
        side: RelaySideId,
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
    /// duration for a frame. The relay does not emit synthetic probe frames by itself.
    pub fn note_side_link_probe_sample(
        &self,
        side: RelaySideId,
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

    fn relay_item_wire_len(data: &RelayItem) -> TelemetryResult<usize> {
        match data {
            RelayItem::Packet(pkt) => Ok(wire_format::pack_packet(pkt).len()),
            RelayItem::Packed(bytes) => Ok(bytes.len()),
        }
    }

    #[inline]
    fn decode_end_to_end_reliable_ack(payload: &[u8]) -> TelemetryResult<u64> {
        if payload.len() != 8 {
            return Err(TelemetryError::Unpack("bad reliable e2e ack payload"));
        }
        Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
    }

    #[inline]
    fn is_end_to_end_ack_sender(sender: &str) -> bool {
        sender == Self::END_TO_END_ACK_SENDER || sender.starts_with(Self::END_TO_END_ACK_PREFIX)
    }

    #[inline]
    fn sender_hash(sender: &str) -> u64 {
        hash_bytes_u64(0x517C_C1B7_2722_0A95, sender.as_bytes())
    }

    fn decode_end_to_end_ack_sender_hash(sender: &str) -> Option<u64> {
        sender
            .strip_prefix(Self::END_TO_END_ACK_PREFIX)
            .filter(|sender| !sender.is_empty())
            .map(Self::sender_hash)
    }

    #[cfg(feature = "discovery")]
    fn is_end_to_end_destination_sender(&self, sender: &str) -> bool {
        sender != self.sender_arc().as_ref() && !Self::is_end_to_end_ack_sender(sender)
    }

    /// Extract the logical packet ID targeted by an end-to-end reliable ACK item.
    ///
    /// Relay queues can hold either decoded packets or packed frames. This
    /// helper normalizes both forms so relay ACK-routing logic can treat them
    /// uniformly.
    ///
    /// Only relay-visible end-to-end `ReliableAck` packets qualify here.
    /// Unrelated traffic returns `Ok(None)`.
    fn reliable_control_target_packet_id(data: &RelayItem) -> TelemetryResult<Option<u64>> {
        match data {
            RelayItem::Packet(pkt) => {
                if pkt.data_type() != crate::DataType::ReliableAck
                    || !Self::is_end_to_end_ack_sender(pkt.sender())
                {
                    return Ok(None);
                }
                Self::decode_end_to_end_reliable_ack(pkt.payload()).map(Some)
            }
            RelayItem::Packed(bytes) => {
                if wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| frame.ack_only())
                {
                    return Ok(None);
                }
                let pkt = wire_format::unpack_packet(bytes.as_ref())?;
                if pkt.data_type() != crate::DataType::ReliableAck
                    || !Self::is_end_to_end_ack_sender(pkt.sender())
                {
                    return Ok(None);
                }
                Self::decode_end_to_end_reliable_ack(pkt.payload()).map(Some)
            }
        }
    }

    fn note_reliable_return_route(&self, side: RelaySideId, packet_id: u64) {
        let mut st = self.state.lock();
        Self::remember_reliable_return_route_locked(&mut st, packet_id);
        st.reliable_return_routes
            .insert(packet_id, ReliableReturnRouteState { side });
    }

    /// Refresh or insert `packet_id` in the bounded reliable return-route cache.
    ///
    /// The relay uses this cache to route end-to-end acknowledgements back
    /// toward the source side that most recently forwarded the corresponding
    /// reliable data packet.
    fn remember_reliable_return_route_locked(st: &mut RelayInner, packet_id: u64) {
        let cap = RELIABLE_MAX_RETURN_ROUTES.max(1);
        st.reliable_return_route_order
            .retain(|id| st.reliable_return_routes.contains_key(id) && *id != packet_id);
        while st.reliable_return_route_order.len() >= cap {
            if let Some(oldest) = st.reliable_return_route_order.pop_front() {
                st.reliable_return_routes.remove(&oldest);
            } else {
                break;
            }
        }
        st.reliable_return_route_order.push_back(packet_id);
    }

    fn note_end_to_end_acked_destination_locked(
        st: &mut RelayInner,
        packet_id: u64,
        sender_hash: u64,
    ) {
        let entry_cap = RELIABLE_MAX_END_TO_END_ACK_CACHE.max(1);
        st.end_to_end_acked_destination_order
            .retain(|id| st.end_to_end_acked_destinations.contains_key(id) && *id != packet_id);
        while st.end_to_end_acked_destination_order.len() >= entry_cap {
            if let Some(oldest) = st.end_to_end_acked_destination_order.pop_front() {
                st.end_to_end_acked_destinations.remove(&oldest);
            } else {
                break;
            }
        }
        st.end_to_end_acked_destination_order.push_back(packet_id);

        let acked = st
            .end_to_end_acked_destinations
            .entry(packet_id)
            .or_default();
        let sender_cap = RELIABLE_MAX_END_TO_END_PENDING.max(1);
        if acked.len() < sender_cap || acked.contains(&sender_hash) {
            acked.insert(sender_hash);
        }
    }

    #[inline]
    fn reliable_key(side: RelaySideId, ty: crate::DataType) -> (RelaySideId, u32) {
        (side, ty.as_u32())
    }

    fn reliable_tx_state_mut<'a>(
        &'a self,
        st: &'a mut RelayInner,
        side: RelaySideId,
        ty: crate::DataType,
    ) -> &'a mut ReliableTxState {
        let key = Self::reliable_key(side, ty);
        st.reliable_tx
            .entry(key)
            .or_insert_with(|| ReliableTxState {
                next_seq: 1,
                sent_order: VecDeque::new(),
                sent: BTreeMap::new(),
            })
    }

    fn reliable_rx_state_mut<'a>(
        &'a self,
        st: &'a mut RelayInner,
        side: RelaySideId,
        ty: crate::DataType,
    ) -> &'a mut ReliableRxState {
        let key = Self::reliable_key(side, ty);
        st.reliable_rx
            .entry(key)
            .or_insert_with(|| ReliableRxState {
                expected_seq: 1,
                buffered: BTreeMap::new(),
            })
    }

    fn handle_reliable_ack(&self, side: RelaySideId, ty: crate::DataType, ack: u32) {
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

    fn handle_reliable_partial_ack(&self, side: RelaySideId, ty: crate::DataType, seq: u32) {
        let mut st = self.state.lock();
        let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
        if let Some(sent) = tx_state.sent.get_mut(&seq) {
            sent.partial_acked = true;
        }
    }

    fn reliable_control_packet(
        &self,
        control_ty: crate::DataType,
        ty: crate::DataType,
        seq: u32,
    ) -> TelemetryResult<Packet> {
        let sender = self.sender_arc();
        Packet::new(
            control_ty,
            message_meta(control_ty).endpoints,
            sender.as_ref(),
            self.clock.now_ms(),
            crate::router::encode_slice_le(&[ty.as_u32(), seq]),
        )
    }

    fn queue_reliable_ack(
        &self,
        side: RelaySideId,
        ty: crate::DataType,
        seq: u32,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(crate::DataType::ReliableAck, ty, seq)?;
        let data = RelayItem::Packet(Arc::new(pkt));
        let priority = Self::relay_item_priority(&data)?;
        let mut st = self.state.lock();
        st.push_tx(RelayTxItem {
            src: None,
            dst: side,
            data,
            priority,
        })?;
        Ok(())
    }

    fn queue_reliable_packet_request(
        &self,
        side: RelaySideId,
        ty: crate::DataType,
        seq: u32,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(crate::DataType::ReliablePacketRequest, ty, seq)?;
        let data = RelayItem::Packet(Arc::new(pkt));
        let priority = Self::relay_item_priority(&data)?;
        let mut st = self.state.lock();
        st.push_tx(RelayTxItem {
            src: None,
            dst: side,
            data,
            priority,
        })?;
        Ok(())
    }

    fn queue_reliable_partial_ack(
        &self,
        side: RelaySideId,
        ty: crate::DataType,
        seq: u32,
    ) -> TelemetryResult<()> {
        let pkt = self.reliable_control_packet(crate::DataType::ReliablePartialAck, ty, seq)?;
        let data = RelayItem::Packet(Arc::new(pkt));
        let priority = Self::relay_item_priority(&data)?;
        let mut st = self.state.lock();
        st.push_tx(RelayTxItem {
            src: None,
            dst: side,
            data,
            priority,
        })?;
        Ok(())
    }

    fn queue_reliable_retransmit(
        &self,
        side: RelaySideId,
        ty: crate::DataType,
        seq: u32,
    ) -> TelemetryResult<()> {
        let mut queued = None;
        {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
            if let Some(sent) = tx_state.sent.get_mut(&seq)
                && !sent.queued
            {
                sent.queued = true;
                sent.partial_acked = false;
                queued = Some(sent.bytes.clone());
            }
        }

        if let Some(bytes) = queued {
            let mut st = self.state.lock();
            st.push_replay(RelayReplayItem {
                dst: side,
                bytes,
                priority: message_priority(ty).saturating_add(16),
            })?;
        }
        Ok(())
    }

    fn send_reliable_raw_to_side(
        &self,
        side: RelaySideId,
        bytes: Arc<[u8]>,
    ) -> TelemetryResult<()> {
        let (handler, opts) = {
            let st = self.state.lock();
            let side_ref = Self::side_ref(&st, side)?;
            if !side_ref.opts.egress_enabled {
                return Ok(());
            }
            (side_ref.tx_handler.clone(), side_ref.opts)
        };

        let Some(_side_tx_guard) = self.try_enter_side_tx() else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        let ty = wire_format::peek_envelope(bytes.as_ref())
            .map(|env| env.ty)
            .unwrap_or(crate::DataType::ReliableAck);
        let result = match handler {
            RelayTxHandlerFn::Packed(f) => {
                let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
                let mut sent_bytes = 0usize;
                for frame in frames {
                    f(frame.as_ref())?;
                    sent_bytes = sent_bytes.saturating_add(frame.len());
                }
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, 1);
                return Ok(());
            }
            RelayTxHandlerFn::Packet(f) => {
                if wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| frame.ack_only())
                {
                    return Ok(());
                }
                let pkt = wire_format::unpack_packet(bytes.as_ref())?;
                f(&pkt)
            }
        };
        if result.is_ok() {
            self.record_side_tx_sample(side, bytes.len(), started_ms, self.clock.now_ms());
            self.note_side_tx_success(side, ty, bytes.len(), 1);
        } else {
            self.note_side_tx_failure(side, ty, 1);
        }
        result
    }

    fn send_reliable_to_side(&self, side: RelaySideId, data: RelayItem) -> TelemetryResult<()> {
        let (handler, opts, hop_reliable_enabled) = {
            let st = self.state.lock();
            let side_ref = Self::side_ref(&st, side)?;
            let opts = side_ref.opts;
            let hop_reliable_enabled = opts.reliable_enabled
                && !self.side_has_multiple_announcers_locked(&st, side, self.clock.now_ms());
            (side_ref.tx_handler.clone(), opts, hop_reliable_enabled)
        };

        let RelayTxHandlerFn::Packed(f) = &handler else {
            return self.call_tx_handler(side, &handler, &data);
        };

        if !hop_reliable_enabled {
            let mut adjusted_opts = opts;
            adjusted_opts.reliable_enabled = false;
            if let Some(adjusted) = self.adjust_reliable_for_side(adjusted_opts, data)? {
                return self.call_tx_handler(side, &handler, &adjusted);
            }
            return Ok(());
        }

        let ty = match &data {
            RelayItem::Packet(pkt) => pkt.data_type(),
            RelayItem::Packed(bytes) => {
                let Ok(frame) = wire_format::peek_frame_info(bytes.as_ref()) else {
                    return self.call_tx_handler(side, &handler, &data);
                };
                frame.envelope.ty
            }
        };

        if !is_reliable_type(ty) {
            if let Some(adjusted) = self.adjust_reliable_for_side(opts, data)? {
                self.call_tx_handler(side, &handler, &adjusted)?;
            }
            return Ok(());
        }

        let (seq, flags) = {
            let mut st = self.state.lock();
            let tx_state = self.reliable_tx_state_mut(&mut st, side, ty);
            if tx_state.sent.len() >= RELIABLE_MAX_PENDING {
                return Err(TelemetryError::PacketTooLarge(
                    "relay reliable history full",
                ));
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

        let bytes: Arc<[u8]> = match data {
            RelayItem::Packet(pkt) => wire_format::pack_packet_with_reliable(
                &pkt,
                wire_format::ReliableHeader { flags, seq, ack: 0 },
            ),
            RelayItem::Packed(bytes) => {
                let mut v = bytes.to_vec();
                if !wire_format::rewrite_reliable_header(&mut v, flags, seq, 0)? {
                    let Some(_side_tx_guard) = self.try_enter_side_tx() else {
                        return Err(TelemetryError::Io("side tx busy"));
                    };
                    let started_ms = self.clock.now_ms();
                    let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
                    let mut sent_bytes = 0usize;
                    for frame in frames {
                        f(frame.as_ref())?;
                        sent_bytes = sent_bytes.saturating_add(frame.len());
                    }
                    self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                    self.note_side_tx_success(side, ty, sent_bytes, 1);
                    return Ok(());
                }
                Arc::from(v)
            }
        };

        let Some(_side_tx_guard) = self.try_enter_side_tx() else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
        let mut sent_bytes = 0usize;
        for frame in frames {
            f(frame.as_ref())?;
            sent_bytes = sent_bytes.saturating_add(frame.len());
        }
        self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
        self.note_side_tx_success(side, ty, sent_bytes, 1);

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

    fn item_route_info(
        &self,
        data: &RelayItem,
    ) -> TelemetryResult<(Vec<crate::DataEndpoint>, crate::DataType)> {
        match data {
            RelayItem::Packet(pkt) => {
                let mut eps = pkt.endpoints().to_vec();
                eps.sort_unstable();
                eps.dedup();
                Ok((eps, pkt.data_type()))
            }
            RelayItem::Packed(bytes) => {
                let env = wire_format::peek_envelope(bytes.as_ref())?;
                let mut eps: Vec<crate::DataEndpoint> = env.endpoints.iter().copied().collect();
                eps.sort_unstable();
                eps.dedup();
                Ok((eps, env.ty))
            }
        }
    }

    fn endpoints_are_link_local_only(eps: &[crate::DataEndpoint]) -> bool {
        !eps.is_empty() && eps.iter().all(|ep| ep.is_link_local_only())
    }

    fn item_target_senders(&self, data: &RelayItem) -> TelemetryResult<Arc<[u64]>> {
        match data {
            RelayItem::Packet(pkt) => Ok(Arc::from(pkt.wire_target_senders())),
            RelayItem::Packed(bytes) => {
                Ok(wire_format::peek_envelope(bytes.as_ref())?.target_senders)
            }
        }
    }

    #[cfg(feature = "discovery")]
    fn has_explicit_route_policy_locked(
        st: &RelayInner,
        src: Option<RelaySideId>,
        ty: crate::DataType,
    ) -> bool {
        st.route_overrides
            .keys()
            .any(|(route_src, _)| *route_src == src)
            || Self::has_typed_route_overrides_locked(st, src, ty)
    }

    #[cfg(feature = "discovery")]
    fn side_matches_target_senders_locked(
        st: &RelayInner,
        side: RelaySideId,
        target_senders: &[u64],
        now_ms: u64,
    ) -> bool {
        st.discovery_routes
            .get(&side)
            .map(|route| {
                if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    return false;
                }
                route.announcers.values().any(|sender_state| {
                    if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                        return false;
                    }
                    sender_state
                        .topology_boards
                        .iter()
                        .any(|board| target_senders.contains(&Self::sender_hash(&board.sender_id)))
                })
            })
            .unwrap_or(false)
    }

    fn remote_side_plan(
        &self,
        data: &RelayItem,
        exclude: RelaySideId,
    ) -> TelemetryResult<RemoteSidePlan> {
        #[cfg(feature = "discovery")]
        {
            let (eps, ty) = self.item_route_info(data)?;
            let target_senders = self.item_target_senders(data)?;
            let preferred_packet_id = Self::reliable_control_target_packet_id(data)?;
            if discovery::is_discovery_type(ty) {
                let mut st = self.state.lock();
                let sides = self.eligible_side_ids_locked(&st, Some(exclude), Some(ty), false);
                return Ok(RemoteSidePlan::Target(self.apply_route_selection_locked(
                    &mut st,
                    Some(exclude),
                    sides,
                    RouteSelectionOrigin::Flood,
                )));
            }

            #[cfg(feature = "timesync")]
            let preferred_timesync_source = self.preferred_timesync_route_source(data, ty)?;
            #[cfg(not(feature = "timesync"))]
            let preferred_timesync_source: Option<String> = None;
            let mut st = self.state.lock();
            if let Some(packet_id) = preferred_packet_id {
                let target_side = self.allowed_target_side_locked(
                    &st,
                    exclude,
                    ty,
                    st.reliable_return_routes
                        .get(&packet_id)
                        .map(|route| route.side),
                );
                if let Some(side) = target_side {
                    #[cfg(feature = "timesync")]
                    if !Self::timesync_allowed_for_side_locked(
                        &mut st,
                        side,
                        ty,
                        self.clock.now_ms(),
                    ) {
                        return Ok(RemoteSidePlan::Target(Vec::new()));
                    }
                    return Ok(RemoteSidePlan::Target(vec![side]));
                }
                return Ok(RemoteSidePlan::Target(Vec::new()));
            }
            let restrict_link_local = Self::endpoints_are_link_local_only(&eps);
            let discovered_origin = if is_reliable_type(ty) {
                RouteSelectionOrigin::Flood
            } else {
                RouteSelectionOrigin::Discovered
            };
            if st.discovery_routes.is_empty() {
                let mut fallback = self.eligible_side_ids_locked(
                    &st,
                    Some(exclude),
                    Some(ty),
                    restrict_link_local,
                );
                #[cfg(feature = "timesync")]
                {
                    fallback = Self::filter_timesync_sides_locked(
                        &mut st,
                        ty,
                        self.clock.now_ms(),
                        fallback,
                    );
                }
                return Ok(RemoteSidePlan::Target(if fallback.len() == 1 {
                    fallback
                } else {
                    Vec::new()
                }));
            }
            let now_ms = self.clock.now_ms();
            let mut had_exact = false;
            let mut exact_targets = Vec::new();
            let mut had_known = false;
            let mut generic_targets = Vec::new();

            for (&side, route) in st.discovery_routes.iter() {
                if side == exclude
                    || now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS
                {
                    continue;
                }
                if restrict_link_local
                    && st
                        .sides
                        .get(side)
                        .and_then(|side| side.as_ref())
                        .map(|s| !s.opts.link_local_enabled)
                        .unwrap_or(true)
                {
                    continue;
                }
                if !self.route_allowed_locked(&st, Some(exclude), Some(ty), side) {
                    continue;
                }
                if !target_senders.is_empty()
                    && !Self::side_matches_target_senders_locked(&st, side, &target_senders, now_ms)
                {
                    continue;
                }
                if preferred_timesync_source.as_deref().is_some_and(|source| {
                    route.reachable_timesync_sources.iter().any(|s| s == source)
                }) {
                    had_exact = true;
                    exact_targets.push(side);
                    continue;
                }
                if eps.iter().copied().any(|ep| route.reachable.contains(&ep)) {
                    had_known = true;
                    generic_targets.push(side);
                }
            }

            if had_exact {
                #[cfg(feature = "timesync")]
                {
                    exact_targets = Self::filter_timesync_sides_locked(
                        &mut st,
                        ty,
                        self.clock.now_ms(),
                        exact_targets,
                    );
                }
                let targets = self.filter_end_to_end_satisfied_sides_locked(
                    &st,
                    data,
                    exact_targets,
                    &eps,
                    ty,
                )?;
                Ok(RemoteSidePlan::Target(self.apply_route_selection_locked(
                    &mut st,
                    Some(exclude),
                    targets,
                    discovered_origin,
                )))
            } else if had_known {
                #[cfg(feature = "timesync")]
                {
                    generic_targets = Self::filter_timesync_sides_locked(
                        &mut st,
                        ty,
                        self.clock.now_ms(),
                        generic_targets,
                    );
                }
                let targets = self.filter_end_to_end_satisfied_sides_locked(
                    &st,
                    data,
                    generic_targets,
                    &eps,
                    ty,
                )?;
                Ok(RemoteSidePlan::Target(self.apply_route_selection_locked(
                    &mut st,
                    Some(exclude),
                    targets,
                    discovered_origin,
                )))
            } else {
                if Self::has_explicit_route_policy_locked(&st, Some(exclude), ty) {
                    let mut sides = self.eligible_side_ids_locked(
                        &st,
                        Some(exclude),
                        Some(ty),
                        restrict_link_local,
                    );
                    #[cfg(feature = "timesync")]
                    {
                        sides = Self::filter_timesync_sides_locked(
                            &mut st,
                            ty,
                            self.clock.now_ms(),
                            sides,
                        );
                    }
                    Ok(RemoteSidePlan::Target(self.apply_route_selection_locked(
                        &mut st,
                        Some(exclude),
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
            let (_, ty) = self.item_route_info(data)?;
            let mut st = self.state.lock();
            if let Some(packet_id) = Self::reliable_control_target_packet_id(data)? {
                let target_side = self.allowed_target_side_locked(
                    &st,
                    exclude,
                    ty,
                    st.reliable_return_routes
                        .get(&packet_id)
                        .map(|route| route.side),
                );
                if let Some(side) = target_side {
                    return Ok(RemoteSidePlan::Target(vec![side]));
                }
                return Ok(RemoteSidePlan::Target(Vec::new()));
            }
            let sides = self.eligible_side_ids_locked(&st, Some(exclude), Some(ty), false);
            Ok(RemoteSidePlan::Target(self.apply_route_selection_locked(
                &mut st,
                Some(exclude),
                sides,
                RouteSelectionOrigin::Flood,
            )))
        }
    }

    #[inline]
    fn allowed_target_side_locked(
        &self,
        st: &RelayInner,
        exclude: RelaySideId,
        ty: crate::DataType,
        target_side: Option<RelaySideId>,
    ) -> Option<RelaySideId> {
        target_side.filter(|side| self.route_allowed_locked(st, Some(exclude), Some(ty), *side))
    }

    fn filter_end_to_end_satisfied_sides_locked(
        &self,
        st: &RelayInner,
        data: &RelayItem,
        sides: Vec<RelaySideId>,
        eps: &[crate::DataEndpoint],
        ty: crate::DataType,
    ) -> TelemetryResult<Vec<RelaySideId>> {
        if !is_reliable_type(ty) || Self::reliable_control_target_packet_id(data)?.is_some() {
            return Ok(sides);
        }
        let packet_id = match data {
            RelayItem::Packet(pkt) => pkt.packet_id(),
            RelayItem::Packed(bytes) => match wire_format::packet_id_from_wire(bytes.as_ref()) {
                Ok(packet_id) => packet_id,
                Err(TelemetryError::Unpack("reliable control frame")) => return Ok(sides),
                Err(err) => return Err(err),
            },
        };
        let Some(acked) = st.end_to_end_acked_destinations.get(&packet_id) else {
            return Ok(sides);
        };
        let now_ms = self.clock.now_ms();
        let mut filtered = Vec::new();
        for side in sides {
            let Some(route) = st.discovery_routes.get(&side) else {
                filtered.push(side);
                continue;
            };
            let mut still_pending = false;
            let mut had_destination_board = false;
            for sender_state in route.announcers.values() {
                if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                for board in sender_state.topology_boards.iter() {
                    if !self.is_end_to_end_destination_sender(&board.sender_id) {
                        continue;
                    }
                    had_destination_board = true;
                    let sender_hash = Self::sender_hash(&board.sender_id);
                    if acked.contains(&sender_hash) {
                        continue;
                    }
                    if eps
                        .iter()
                        .copied()
                        .any(|ep| board.reachable_endpoints.contains(&ep))
                    {
                        still_pending = true;
                        break;
                    }
                    // Keep forwarding while any discovered destination sender for this packet
                    // remains unacked, even if topology/schema metadata changed for new packets.
                    still_pending = true;
                    break;
                }
                if still_pending {
                    break;
                }
            }
            if still_pending || !had_destination_board {
                filtered.push(side);
            }
        }
        Ok(filtered)
    }

    #[cfg(feature = "discovery")]
    fn side_has_multiple_announcers_locked(
        &self,
        st: &RelayInner,
        side: RelaySideId,
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
        _st: &RelayInner,
        _side: RelaySideId,
        _now_ms: u64,
    ) -> bool {
        false
    }

    #[cfg(feature = "discovery")]
    fn sender_topology_board_mut<'a>(
        sender_state: &'a mut DiscoverySenderState,
        sender_id: &str,
    ) -> &'a mut TopologyBoardNode {
        if let Some(idx) = sender_state
            .topology_boards
            .iter()
            .position(|board| board.sender_id == sender_id)
        {
            return &mut sender_state.topology_boards[idx];
        }
        sender_state.topology_boards.push(TopologyBoardNode {
            sender_id: sender_id.to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: Vec::new(),
        });
        sender_state
            .topology_boards
            .last_mut()
            .expect("board inserted above")
    }

    #[cfg(feature = "discovery")]
    fn refresh_sender_topology_state(sender_state: &mut DiscoverySenderState) {
        discovery::normalize_topology_boards(&mut sender_state.topology_boards);
        let (reachable, reachable_timesync_sources) =
            discovery::summarize_topology_boards(&sender_state.topology_boards);
        sender_state.reachable = reachable;
        sender_state.reachable_timesync_sources = reachable_timesync_sources;
    }

    #[cfg(feature = "discovery")]
    fn recompute_discovery_side_state(route: &mut DiscoverySideState) {
        let mut reachable = Vec::new();
        let mut reachable_timesync_sources = Vec::new();
        let mut last_seen_ms = 0u64;
        for sender in route.announcers.values() {
            reachable.extend(sender.reachable.iter().copied());
            reachable_timesync_sources.extend(sender.reachable_timesync_sources.iter().cloned());
            last_seen_ms = last_seen_ms.max(sender.last_seen_ms);
        }
        reachable.sort_unstable();
        reachable.dedup();
        reachable_timesync_sources.sort_unstable();
        reachable_timesync_sources.dedup();
        route.reachable = reachable;
        route.reachable_timesync_sources = reachable_timesync_sources;
        route.last_seen_ms = last_seen_ms;
    }

    #[cfg(feature = "discovery")]
    fn local_discovery_topology_board(&self, st: &RelayInner, now_ms: u64) -> TopologyBoardNode {
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
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections,
        }
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_topology_for_link_locked(
        &self,
        st: &RelayInner,
        now_ms: u64,
        link_local_enabled: bool,
    ) -> Vec<TopologyBoardNode> {
        let mut boards = vec![self.local_discovery_topology_board(st, now_ms)];
        for route in st.discovery_routes.values() {
            if now_ms.saturating_sub(route.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                continue;
            }
            for (announcer, sender_state) in route.announcers.iter() {
                if now_ms.saturating_sub(sender_state.last_seen_ms) > DISCOVERY_ROUTE_TTL_MS {
                    continue;
                }
                let mut sender_boards = sender_state.topology_boards.clone();
                if sender_boards.is_empty() {
                    let sender = self.sender_arc();
                    sender_boards.push(TopologyBoardNode {
                        sender_id: announcer.clone(),
                        reachable_endpoints: sender_state.reachable.clone(),
                        reachable_timesync_sources: sender_state.reachable_timesync_sources.clone(),
                        connections: vec![sender.to_string()],
                    });
                } else if let Some(board) = sender_boards
                    .iter_mut()
                    .find(|board| board.sender_id == *announcer)
                {
                    board.connections.push(self.sender_arc().to_string());
                }
                if !link_local_enabled {
                    for board in sender_boards.iter_mut() {
                        board
                            .reachable_endpoints
                            .retain(|ep| !ep.is_link_local_only());
                    }
                }
                discovery::merge_topology_boards(&mut boards, &sender_boards);
            }
        }
        discovery::normalize_topology_boards(&mut boards);
        boards
    }

    #[cfg(feature = "discovery")]
    fn note_discovery_topology_change_locked(st: &mut RelayInner, now_ms: u64) {
        st.discovery_cadence.on_topology_change(now_ms);
    }

    #[cfg(feature = "discovery")]
    fn prune_discovery_routes_locked(st: &mut RelayInner, now_ms: u64) -> bool {
        let before = st.discovery_routes.clone();
        st.discovery_routes.retain(|_, route| {
            route.announcers.retain(|_, sender| {
                now_ms.saturating_sub(sender.last_seen_ms) <= DISCOVERY_ROUTE_TTL_MS
            });
            Self::recompute_discovery_side_state(route);
            !route.announcers.is_empty()
        });
        st.discovery_routes != before
    }

    #[cfg(feature = "discovery")]
    fn reconcile_end_to_end_acked_destinations_locked(&self, st: &mut RelayInner) {
        let mut active_senders = BTreeSet::new();
        for route in st.discovery_routes.values() {
            for sender_state in route.announcers.values() {
                for board in sender_state.topology_boards.iter() {
                    if self.is_end_to_end_destination_sender(&board.sender_id) {
                        active_senders.insert(Self::sender_hash(&board.sender_id));
                    }
                }
            }
        }
        st.end_to_end_acked_destinations.retain(|_, acked| {
            acked.retain(|sender_hash| active_senders.contains(sender_hash));
            !acked.is_empty()
        });
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_endpoints_for_link_locked(
        &self,
        st: &RelayInner,
        now_ms: u64,
        link_local_enabled: bool,
    ) -> Vec<crate::DataEndpoint> {
        let (reachable_endpoints, _) = discovery::summarize_topology_boards(
            &self.advertised_discovery_topology_for_link_locked(st, now_ms, link_local_enabled),
        );
        reachable_endpoints
            .into_iter()
            .filter(|ep| {
                !discovery::is_discovery_endpoint(*ep)
                    && (link_local_enabled || !ep.is_link_local_only())
            })
            .collect()
    }

    #[cfg(feature = "discovery")]
    fn advertised_discovery_timesync_sources_for_link_locked(
        &self,
        st: &RelayInner,
        now_ms: u64,
    ) -> Vec<String> {
        let (_, sources) = discovery::summarize_topology_boards(
            &self.advertised_discovery_topology_for_link_locked(st, now_ms, true),
        );
        sources
    }

    #[cfg(feature = "discovery")]
    #[cfg(feature = "timesync")]
    fn preferred_timesync_route_source(
        &self,
        data: &RelayItem,
        ty: crate::DataType,
    ) -> TelemetryResult<Option<String>> {
        if !matches!(
            ty,
            crate::DataType::TimeSyncAnnounce | crate::DataType::TimeSyncResponse
        ) {
            return Ok(None);
        }

        let sender = match data {
            RelayItem::Packet(pkt) => pkt.sender().to_owned(),
            RelayItem::Packed(bytes) => {
                if wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| frame.ack_only())
                {
                    return Ok(None);
                }
                wire_format::unpack_packet(bytes.as_ref())?
                    .sender()
                    .to_owned()
            }
        };
        Ok(Some(sender))
    }

    #[cfg(feature = "discovery")]
    #[inline]
    fn side_is_slow_control_link_locked(
        st: &RelayInner,
        side_id: RelaySideId,
        now_ms: u64,
    ) -> bool {
        st.adaptive_route_stats.get(&side_id).is_some_and(|stats| {
            let recent_slow = stats.last_slow_observed_ms > 0
                && now_ms.saturating_sub(stats.last_slow_observed_ms)
                    <= DISCOVERY_SLOW_LINK_FULL_INTERVAL_MS;
            stats.sample_count > 0
                && ((stats.estimated_bandwidth_bps > 0
                    && stats.estimated_bandwidth_bps <= CONTROL_SLOW_LINK_CAPACITY_BPS)
                    || recent_slow)
        })
    }

    #[cfg(feature = "discovery")]
    fn discovery_level_for_side_locked(
        st: &mut RelayInner,
        side_id: RelaySideId,
        now_ms: u64,
    ) -> Option<DiscoveryAdvertiseLevel> {
        if !Self::side_is_slow_control_link_locked(st, side_id, now_ms) {
            st.discovery_side_throttle.remove(&side_id);
            return Some(DiscoveryAdvertiseLevel::Full);
        }

        let throttle = st.discovery_side_throttle.entry(side_id).or_default();
        if now_ms >= throttle.next_full_ms {
            throttle.next_full_ms = now_ms.saturating_add(DISCOVERY_SLOW_LINK_FULL_INTERVAL_MS);
            throttle.next_ping_ms = now_ms.saturating_add(DISCOVERY_SLOW_LINK_PING_INTERVAL_MS);
            return Some(DiscoveryAdvertiseLevel::Full);
        }
        if now_ms >= throttle.next_ping_ms {
            throttle.next_ping_ms = now_ms.saturating_add(DISCOVERY_SLOW_LINK_PING_INTERVAL_MS);
            return Some(DiscoveryAdvertiseLevel::MinimalPing);
        }
        None
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    #[inline]
    fn is_timesync_type(ty: crate::DataType) -> bool {
        matches!(
            ty,
            crate::DataType::TimeSyncAnnounce
                | crate::DataType::TimeSyncRequest
                | crate::DataType::TimeSyncResponse
        )
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    fn timesync_allowed_for_side_locked(
        st: &mut RelayInner,
        side_id: RelaySideId,
        ty: crate::DataType,
        now_ms: u64,
    ) -> bool {
        if !Self::is_timesync_type(ty) {
            return true;
        }
        if !Self::side_is_slow_control_link_locked(st, side_id, now_ms) {
            st.timesync_side_throttle.remove(&side_id);
            return true;
        }

        let throttle = st.timesync_side_throttle.entry(side_id).or_default();
        if now_ms >= throttle.next_allowed_ms {
            throttle.next_allowed_ms = now_ms.saturating_add(TIMESYNC_SLOW_LINK_MIN_INTERVAL_MS);
            return true;
        }
        false
    }

    #[cfg(all(feature = "discovery", feature = "timesync"))]
    fn filter_timesync_sides_locked(
        st: &mut RelayInner,
        ty: crate::DataType,
        now_ms: u64,
        sides: Vec<RelaySideId>,
    ) -> Vec<RelaySideId> {
        sides
            .into_iter()
            .filter(|side| Self::timesync_allowed_for_side_locked(st, *side, ty, now_ms))
            .collect()
    }

    #[cfg(feature = "discovery")]
    fn queue_discovery_announce(&self) -> TelemetryResult<()> {
        let now_ms = self.clock.now_ms();
        let per_side = {
            let mut st = self.state.lock();
            if Self::prune_discovery_routes_locked(&mut st, now_ms) {
                self.reconcile_end_to_end_acked_destinations_locked(&mut st);
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            st.fit_discovery_budget();
            if !st.sides.iter().any(|side| side.is_some()) {
                return Ok(());
            }
            st.discovery_cadence.on_announce_sent(now_ms);
            let side_entries = st
                .sides
                .iter()
                .enumerate()
                .filter_map(|(side_id, side)| {
                    side.as_ref()
                        .map(|side| (side_id, side.opts.link_local_enabled, side.opts))
                })
                .collect::<Vec<_>>();
            let mut per_side = Vec::new();
            for (side_id, link_local_enabled, opts) in side_entries {
                if !self.route_allowed_locked(
                    &st,
                    None,
                    Some(crate::DataType::DiscoveryAnnounce),
                    side_id,
                ) {
                    continue;
                }
                let Some(level) = Self::discovery_level_for_side_locked(&mut st, side_id, now_ms)
                else {
                    continue;
                };
                let capabilities = opts.link_capabilities();
                if level == DiscoveryAdvertiseLevel::MinimalPing {
                    per_side.push((
                        side_id,
                        level,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        capabilities,
                    ));
                    continue;
                }
                let endpoints = self.advertised_discovery_endpoints_for_link_locked(
                    &st,
                    now_ms,
                    link_local_enabled,
                );
                let timesync_sources =
                    self.advertised_discovery_timesync_sources_for_link_locked(&st, now_ms);
                let topology = self.advertised_discovery_topology_for_link_locked(
                    &st,
                    now_ms,
                    link_local_enabled,
                );
                per_side.push((
                    side_id,
                    level,
                    endpoints,
                    timesync_sources,
                    topology,
                    capabilities,
                ));
            }
            per_side
        };
        let mut st = self.state.lock();
        for (dst, level, endpoints, timesync_sources, topology, capabilities) in per_side {
            let sender = self.sender_arc();
            if level == DiscoveryAdvertiseLevel::Full {
                let pkt = discovery::build_discovery_schema(sender.as_ref(), now_ms)?;
                let data = RelayItem::Packet(Arc::new(pkt));
                let priority = Self::relay_item_priority(&data)?;
                st.push_tx(RelayTxItem {
                    src: None,
                    dst,
                    data,
                    priority,
                })?;
            }
            if level == DiscoveryAdvertiseLevel::Full {
                let pkt = discovery::build_discovery_link_capabilities(
                    sender.as_ref(),
                    now_ms,
                    capabilities,
                )?;
                let data = RelayItem::Packet(Arc::new(pkt));
                let priority = Self::relay_item_priority(&data)?;
                st.push_tx(RelayTxItem {
                    src: None,
                    dst,
                    data,
                    priority,
                })?;
            }
            if level == DiscoveryAdvertiseLevel::MinimalPing || !endpoints.is_empty() {
                let pkt = discovery::build_discovery_announce(
                    sender.as_ref(),
                    now_ms,
                    endpoints.as_slice(),
                )?;
                let data = RelayItem::Packet(Arc::new(pkt));
                let priority = Self::relay_item_priority(&data)?;
                st.push_tx(RelayTxItem {
                    src: None,
                    dst,
                    data,
                    priority,
                })?;
            }
            if level == DiscoveryAdvertiseLevel::Full && !timesync_sources.is_empty() {
                let pkt = discovery::build_discovery_timesync_sources(
                    sender.as_ref(),
                    now_ms,
                    timesync_sources.as_slice(),
                )?;
                let data = RelayItem::Packet(Arc::new(pkt));
                let priority = Self::relay_item_priority(&data)?;
                st.push_tx(RelayTxItem {
                    src: None,
                    dst,
                    data,
                    priority,
                })?;
            }
            if level == DiscoveryAdvertiseLevel::Full && !topology.is_empty() {
                let pkt = discovery::build_discovery_topology(sender.as_ref(), now_ms, &topology)?;
                let data = RelayItem::Packet(Arc::new(pkt));
                let priority = Self::relay_item_priority(&data)?;
                st.push_tx(RelayTxItem {
                    src: None,
                    dst,
                    data,
                    priority,
                })?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    fn poll_discovery_announce(&self) -> TelemetryResult<bool> {
        let now_ms = self.clock.now_ms();
        let due = {
            let mut st = self.state.lock();
            let removed = Self::prune_discovery_routes_locked(&mut st, now_ms);
            if removed {
                self.reconcile_end_to_end_acked_destinations_locked(&mut st);
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            st.fit_discovery_budget();
            let has_any = st.sides.iter().enumerate().any(|(side_id, side)| {
                let Some(side) = side.as_ref() else {
                    return false;
                };
                if !self.route_allowed_locked(
                    &st,
                    None,
                    Some(crate::DataType::DiscoveryAnnounce),
                    side_id,
                ) {
                    return false;
                }
                let _ = side;
                true
            });
            if !st.sides.iter().any(|side| side.is_some()) || !has_any {
                return Ok(false);
            }
            st.discovery_cadence.due(now_ms)
        };
        if !due {
            return Ok(false);
        }
        self.queue_discovery_announce()?;
        Ok(true)
    }

    #[cfg(feature = "discovery")]
    fn learn_discovery_item(&self, src: RelaySideId, data: &RelayItem) -> TelemetryResult<()> {
        let pkt = match data {
            RelayItem::Packet(pkt) => {
                if !discovery::is_discovery_type(pkt.data_type()) {
                    return Ok(());
                }
                pkt.as_ref().clone()
            }
            RelayItem::Packed(bytes) => {
                let env = wire_format::peek_envelope(bytes.as_ref())?;
                if !discovery::is_discovery_type(env.ty) {
                    return Ok(());
                }
                if wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| frame.ack_only())
                {
                    return Ok(());
                }
                wire_format::unpack_packet(bytes.as_ref())?
            }
        };

        let now_ms = self.clock.now_ms();
        if pkt.data_type() == crate::DataType::DiscoverySchema {
            let snapshot = discovery::decode_discovery_schema(&pkt)?;
            let incoming_cost = crate::config::owned_schema_byte_cost(&snapshot);
            let mut st = self.state.lock();
            st.make_shared_queue_room(incoming_cost, RelayQueueKind::Discovery)?;
            drop(st);
            let report =
                crate::config::merge_owned_schema_snapshot_with_budget(snapshot, MAX_QUEUE_BUDGET)?;
            if report.changed() {
                let mut st = self.state.lock();
                st.fit_discovery_budget();
                Self::note_discovery_topology_change_locked(&mut st, now_ms);
            }
            return Ok(());
        }
        if pkt.data_type() == crate::DataType::DiscoveryLinkCapabilities {
            let _ = discovery::decode_discovery_link_capabilities(&pkt)?;
            return Ok(());
        }
        let mut st = self.state.lock();
        if pkt.data_type() == crate::DataType::DiscoveryLeave {
            let leaving = pkt.sender();
            let before = st.discovery_routes.clone();
            for route in st.discovery_routes.values_mut() {
                route.announcers.remove(leaving);
                for sender_state in route.announcers.values_mut() {
                    sender_state
                        .topology_boards
                        .retain(|board| board.sender_id != leaving);
                    for board in sender_state.topology_boards.iter_mut() {
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
            }
            let _ = Self::prune_discovery_routes_locked(&mut st, now_ms);
            self.reconcile_end_to_end_acked_destinations_locked(&mut st);
            return Ok(());
        }
        let mut route = st.discovery_routes.get(&src).cloned().unwrap_or_default();
        let side_link_local_enabled = st
            .sides
            .get(src)
            .and_then(|entry| entry.as_ref())
            .map(|side_ref| side_ref.opts.link_local_enabled)
            .unwrap_or(false);
        let mut sender_state = route
            .announcers
            .get(pkt.sender())
            .cloned()
            .unwrap_or_default();
        let changed = match pkt.data_type() {
            crate::DataType::DiscoveryAnnounce => {
                let mut reachable = discovery::decode_discovery_announce(&pkt)?;
                if !side_link_local_enabled {
                    reachable.retain(|ep| !ep.is_link_local_only());
                }
                let board = Self::sender_topology_board_mut(&mut sender_state, pkt.sender());
                let changed = board.reachable_endpoints != reachable;
                board.reachable_endpoints = reachable;
                Self::refresh_sender_topology_state(&mut sender_state);
                changed
            }
            crate::DataType::DiscoveryTimeSyncSources => {
                let sources = discovery::decode_discovery_timesync_sources(&pkt)?;
                let board = Self::sender_topology_board_mut(&mut sender_state, pkt.sender());
                let changed = board.reachable_timesync_sources != sources;
                board.reachable_timesync_sources = sources;
                Self::refresh_sender_topology_state(&mut sender_state);
                changed
            }
            crate::DataType::DiscoveryTopology => {
                let mut boards = discovery::decode_discovery_topology(&pkt)?;
                if !side_link_local_enabled {
                    for board in boards.iter_mut() {
                        board
                            .reachable_endpoints
                            .retain(|ep| !ep.is_link_local_only());
                    }
                }
                let changed = sender_state.topology_boards != boards;
                sender_state.topology_boards = boards;
                Self::refresh_sender_topology_state(&mut sender_state);
                changed
            }
            crate::DataType::DiscoverySchema => false,
            _ => false,
        };
        sender_state.last_seen_ms = now_ms;
        route
            .announcers
            .insert(pkt.sender().to_string(), sender_state);
        Self::recompute_discovery_side_state(&mut route);
        st.discovery_routes.insert(src, route);
        st.fit_discovery_budget();
        if changed {
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        let _ = Self::prune_discovery_routes_locked(&mut st, now_ms);
        self.reconcile_end_to_end_acked_destinations_locked(&mut st);
        Ok(())
    }

    #[cfg(not(feature = "discovery"))]
    fn learn_discovery_item(&self, _src: RelaySideId, _data: &RelayItem) -> TelemetryResult<()> {
        Ok(())
    }

    #[cfg(not(feature = "discovery"))]
    fn queue_discovery_announce(&self) -> TelemetryResult<()> {
        Ok(())
    }

    #[cfg(not(feature = "discovery"))]
    fn poll_discovery_announce(&self) -> TelemetryResult<bool> {
        Ok(false)
    }

    fn process_reliable_timeouts(&self) -> TelemetryResult<()> {
        let now = self.clock.now_ms();
        let mut requeue: Vec<(RelaySideId, crate::DataType, u32)> = Vec::new();

        {
            let mut st = self.state.lock();
            if st.reliable_tx.is_empty() {
                return Ok(());
            }

            for ((side, ty_u32), tx_state) in st.reliable_tx.iter_mut() {
                let Some(ty) = crate::DataType::try_from_u32(*ty_u32) else {
                    continue;
                };
                let sent_order: Vec<u32> = tx_state.sent_order.iter().copied().collect();
                for seq in sent_order {
                    let Some(sent) = tx_state.sent.get_mut(&seq) else {
                        continue;
                    };
                    if sent.queued || now.wrapping_sub(sent.last_send_ms) < RELIABLE_RETRANSMIT_MS {
                        continue;
                    }
                    if sent.partial_acked {
                        continue;
                    }
                    if sent.retries >= RELIABLE_MAX_RETRIES {
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
            self.queue_reliable_retransmit(side, ty, seq)?;
        }

        Ok(())
    }

    /// Compute a de-dupe hash for a QueueItem.
    /// Uses packet ID for Packet items, and attempts to extract packet ID from
    /// packed bytes. If extraction fails, hashes raw bytes as a fallback.
    fn get_hash(item: &RelayRxItem) -> u64 {
        match &item.data {
            RelayItem::Packet(pkt) => pkt.packet_id(),
            RelayItem::Packed(bytes) => {
                let reliable_seq = wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .and_then(|frame| frame.reliable)
                    .and_then(|hdr| {
                        if (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) != 0 {
                            None
                        } else {
                            Some(hdr.seq)
                        }
                    });

                match wire_format::packet_id_from_wire(bytes.as_ref()) {
                    Ok(id) => {
                        if let Some(seq) = reliable_seq {
                            hash_bytes_u64(id, &seq.to_le_bytes())
                        } else {
                            id
                        }
                    }
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

    /// Compute a dedupe ID for an incoming RelayRxItem.
    /// Note: we intentionally do *not* include `src` so that the same
    /// packet coming from multiple sides is only processed once.
    fn is_duplicate_pkt(&self, item: &RelayRxItem) -> TelemetryResult<bool> {
        let id = Self::get_hash(item);

        let mut st = self.state.lock();
        if st.recent_rx.contains(&id) {
            Ok(true)
        } else {
            st.push_recent_rx(id)?;
            Ok(false)
        }
    }

    fn should_forward_duplicate_reliable_item(&self, item: &RelayRxItem) -> TelemetryResult<bool> {
        let (_, ty) = self.item_route_info(&item.data)?;
        if !is_reliable_type(ty)
            || matches!(
                ty,
                crate::DataType::ReliableAck
                    | crate::DataType::ReliablePartialAck
                    | crate::DataType::ReliablePacketRequest
            )
        {
            return Ok(false);
        }

        let RemoteSidePlan::Target(sides) = self.remote_side_plan(&item.data, item.src)?;
        let st = self.state.lock();
        let now_ms = self.clock.now_ms();
        Ok(sides
            .into_iter()
            .any(|side| self.side_has_multiple_announcers_locked(&st, side, now_ms)))
    }

    /// Register a side whose TX callback consumes packed packet bytes.
    ///
    /// Returns the side id later used for ingress APIs such as `rx_packed_from_side`.
    /// The default options disable the relay's per-link reliable framing on this side.
    pub fn add_side_packed<F>(&self, name: &'static str, tx: F) -> RelaySideId
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packed_with_options(name, tx, RelaySideOptions::default())
    }

    /// Register a packed side with bounded-frame transport enabled.
    ///
    /// `max_frame_bytes == 0` leaves frames unbounded.
    pub fn add_side_packed_small_packets<F>(
        &self,
        name: &'static str,
        tx: F,
        max_frame_bytes: usize,
    ) -> RelaySideId
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packed_with_options(
            name,
            tx,
            RelaySideOptions::default().with_small_packet_transport(max_frame_bytes),
        )
    }

    /// Register a packed-output side with explicit side options.
    ///
    /// `opts.reliable_enabled` enables relay-managed per-hop ACK/retransmit behavior on this side.
    /// `opts.link_local_enabled` gates link-local-only forwarding and discovery use of this side.
    /// `ingress_enabled` and `egress_enabled` set the initial directional policy.
    pub fn add_side_packed_with_options<F>(
        &self,
        name: &'static str,
        tx: F,
        opts: RelaySideOptions,
    ) -> RelaySideId
    where
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut st = self.state.lock();
        let id = st.sides.len();
        st.sides.push(Some(RelaySide {
            name,
            tx_handler: RelayTxHandlerFn::Packed(Arc::new(tx)),
            opts,
        }));
        st.side_runtime_stats
            .insert(id, SideRuntimeStatsInner::default());
        st.side_transport.insert(id, SideTransportState::default());
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        id
    }

    /// Register a side whose TX callback receives decoded [`Packet`] values.
    ///
    /// Packet-output sides do not preserve the relay's packed reliable hop framing, so use a
    /// packed side when this hop should participate in relay-managed per-link reliability.
    pub fn add_side_packet<F>(&self, name: &'static str, tx: F) -> RelaySideId
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.add_side_packet_with_options(name, tx, RelaySideOptions::default())
    }

    /// Register a packet-output side with explicit side options.
    pub fn add_side_packet_with_options<F>(
        &self,
        name: &'static str,
        tx: F,
        opts: RelaySideOptions,
    ) -> RelaySideId
    where
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        let mut st = self.state.lock();
        let id = st.sides.len();
        st.sides.push(Some(RelaySide {
            name,
            tx_handler: RelayTxHandlerFn::Packet(Arc::new(tx)),
            opts,
        }));
        st.side_runtime_stats
            .insert(id, SideRuntimeStatsInner::default());
        st.side_transport.insert(id, SideTransportState::default());
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, self.clock.now_ms());
        id
    }

    /// Remove a side while keeping existing side IDs stable.
    ///
    /// `side` must be an id returned by one of the `add_side_*` calls. Remaining side ids are not
    /// renumbered.
    pub fn remove_side(&self, side: RelaySideId) -> TelemetryResult<()> {
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let slot = st.sides.get_mut(side).ok_or(TelemetryError::BadArg)?;
        if slot.is_none() {
            return Err(TelemetryError::BadArg);
        }
        *slot = None;
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
        st.reliable_return_routes
            .retain(|_, route| route.side != side);
        st.rx_queue.retain(|queued| queued.src != side);
        st.tx_queue
            .retain(|queued| queued.dst != side && queued.src != Some(side));
        st.replay_queue.retain(|queued| queued.dst != side);
        st.reliable_tx.retain(|(side_id, _), _| *side_id != side);
        st.reliable_rx.retain(|(side_id, _), _| *side_id != side);
        #[cfg(feature = "discovery")]
        {
            st.discovery_routes.remove(&side);
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        Ok(())
    }

    /// Enable or disable ingress processing for a registered side.
    pub fn set_side_ingress_enabled(
        &self,
        side: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
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
    pub fn set_side_egress_enabled(&self, side: RelaySideId, enabled: bool) -> TelemetryResult<()> {
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        let side_ref = st
            .sides
            .get_mut(side)
            .and_then(|side| side.as_mut())
            .ok_or(TelemetryError::BadArg)?;
        side_ref.opts.egress_enabled = enabled;
        if !enabled {
            st.tx_queue.retain(|queued| queued.dst != side);
            st.replay_queue.retain(|queued| queued.dst != side);
        }
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Set the route-selection policy for traffic originating from `src`.
    ///
    /// `src == None` targets locally-originated relay traffic such as discovery output.
    pub fn set_source_route_mode(
        &self,
        src: Option<RelaySideId>,
        mode: RouteSelectionMode,
    ) -> TelemetryResult<()> {
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        if let Some(src) = src {
            let _ = Self::side_ref(&st, src).map_err(|_| TelemetryError::BadArg)?;
        }
        if mode == RouteSelectionMode::Fanout {
            st.source_route_modes.remove(&src);
        } else {
            st.source_route_modes.insert(src, mode);
        }
        st.route_selection_cursors.remove(&src);
        #[cfg(feature = "discovery")]
        Self::note_discovery_topology_change_locked(&mut st, now_ms);
        Ok(())
    }

    /// Clear a source-specific route-selection override.
    pub fn clear_source_route_mode(&self, src: Option<RelaySideId>) -> TelemetryResult<()> {
        self.set_source_route_mode(src, RouteSelectionMode::Fanout)
    }

    /// Set the weighted-routing weight from `src` toward `dst`.
    pub fn set_route_weight(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        weight: u32,
    ) -> TelemetryResult<()> {
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
        src: Option<RelaySideId>,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
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
    pub fn set_route_priority(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        priority: u32,
    ) -> TelemetryResult<()> {
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
        src: Option<RelaySideId>,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
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
    pub fn set_route(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
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
    pub fn set_typed_route(
        &self,
        src: Option<RelaySideId>,
        ty: crate::DataType,
        dst: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
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
        src: Option<RelaySideId>,
        ty: crate::DataType,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
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

    /// Clear a non-typed route override so the relay falls back to default behavior.
    pub fn clear_route(&self, src: Option<RelaySideId>, dst: RelaySideId) -> TelemetryResult<()> {
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

    #[cfg(feature = "discovery")]
    /// Queues an immediate discovery announcement for this relay.
    pub fn announce_discovery(&self) -> TelemetryResult<()> {
        self.queue_discovery_announce()
    }

    /// Broadcast that this relay is leaving so peers can prune topology immediately.
    pub fn announce_leave(&self) -> TelemetryResult<()> {
        let pkt = discovery::build_discovery_leave("relay", self.clock.now_ms())?;
        let mut st = self.state.lock();
        let dsts: Vec<usize> = st
            .sides
            .iter()
            .enumerate()
            .filter_map(|(idx, side)| side.as_ref().map(|_| idx))
            .collect();
        for dst in dsts {
            let data = RelayItem::Packet(Arc::new(pkt.clone()));
            let priority = Self::relay_item_priority(&data)?;
            st.push_tx(RelayTxItem {
                src: None,
                dst,
                data,
                priority,
            })?;
        }
        Ok(())
    }

    #[cfg(feature = "discovery")]
    /// Polls discovery state and queues an announce if the cadence says one is due.
    pub fn poll_discovery(&self) -> TelemetryResult<bool> {
        self.poll_discovery_announce()
    }

    #[cfg(feature = "discovery")]
    /// Exports the relay's current discovered topology snapshot.
    pub fn export_topology(&self) -> TopologySnapshot {
        let now_ms = self.clock.now_ms();
        let mut st = self.state.lock();
        if Self::prune_discovery_routes_locked(&mut st, now_ms) {
            self.reconcile_end_to_end_acked_destinations_locked(&mut st);
            Self::note_discovery_topology_change_locked(&mut st, now_ms);
        }
        let routes = st
            .discovery_routes
            .iter()
            .filter_map(|(&side_id, route)| {
                let side = st.sides.get(side_id).and_then(|side| side.as_ref())?;
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
                        reachable_timesync_sources: sender_state.reachable_timesync_sources.clone(),
                        routers: sender_state.topology_boards.clone(),
                        last_seen_ms: sender_state.last_seen_ms,
                        age_ms: now_ms.saturating_sub(sender_state.last_seen_ms),
                    })
                    .collect();
                Some(TopologySideRoute {
                    side_id,
                    side_name: side.name,
                    reachable_endpoints: route
                        .reachable
                        .iter()
                        .copied()
                        .filter(|ep| !discovery::is_router_control_endpoint(*ep))
                        .collect(),
                    reachable_timesync_sources: route.reachable_timesync_sources.clone(),
                    announcers,
                    last_seen_ms: route.last_seen_ms,
                    age_ms: now_ms.saturating_sub(route.last_seen_ms),
                })
            })
            .collect();
        let routers = self.advertised_discovery_topology_for_link_locked(&st, now_ms, true);
        let advertised_endpoints =
            self.advertised_discovery_endpoints_for_link_locked(&st, now_ms, true);
        let advertised_timesync_sources =
            self.advertised_discovery_timesync_sources_for_link_locked(&st, now_ms);
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
                .map(|side| side.name)
            {
                side_names.push(side_name);
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
        reachable_endpoints.sort_unstable();
        reachable_endpoints.dedup();
        reachable_timesync_sources.sort_unstable();
        reachable_timesync_sources.dedup();
        side_ids.sort_unstable();
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

    pub fn export_runtime_stats(&self) -> RuntimeStatsSnapshot {
        let now_ms = self.clock.now_ms();
        let st = self.state.lock();

        let mut sides = Vec::new();
        for (side_id, side) in st.sides.iter().enumerate() {
            let Some(side) = side.as_ref() else { continue };
            let stats = st
                .side_runtime_stats
                .get(&side_id)
                .cloned()
                .unwrap_or_default();
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
                .into_iter()
                .map(|(ty, item)| RuntimeTypeStats {
                    data_type: crate::DataType(ty),
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
                })
                .collect();
            data_types.sort_unstable_by_key(|item| item.data_type.as_u32());
            sides.push(RuntimeSideStats {
                side_id,
                side_name: side.name,
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
                local_delivery_packets: 0,
                tx_retries: stats.tx_retries,
                tx_handler_failures: stats.tx_handler_failures,
                local_handler_failures: 0,
                total_handler_retries: stats.total_handler_retries,
                side_transport_full_frames: stats.side_transport_full_frames,
                side_transport_compact_frames: stats.side_transport_compact_frames,
                side_transport_compact_delta_frames: stats.side_transport_compact_delta_frames,
                side_transport_compact_omitted_timestamp_frames: stats
                    .side_transport_compact_omitted_timestamp_frames,
                side_transport_chunk_frames: stats.side_transport_chunk_frames,
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
                data_type: crate::DataType(*ty),
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
                rx_len: st.rx_queue.len(),
                rx_bytes: st.rx_queue.bytes_used(),
                tx_len: st.tx_queue.len(),
                tx_bytes: st.tx_queue.bytes_used(),
                replay_len: st.replay_queue.len(),
                replay_bytes: st.replay_queue.bytes_used(),
                recent_rx_len: st.recent_rx.len(),
                recent_rx_bytes: st.recent_rx.bytes_used(),
                reliable_rx_buffered_len: st.reliable_rx_buffer_len(),
                reliable_rx_buffered_bytes: st.reliable_rx_buffered_bytes(),
                shared_queue_bytes_used: st.shared_queue_bytes_used(),
            },
            reliable: ReliableRuntimeStats {
                reliable_return_route_count: st.reliable_return_routes.len(),
                end_to_end_pending_count: 0,
                end_to_end_pending_destination_count: 0,
                end_to_end_acked_cache_count: st.end_to_end_acked_destinations.len(),
            },
            discovery,
            total_handler_failures: st.total_handler_failures,
            total_handler_retries: st.total_handler_retries,
        }
    }

    /// Export current relay memory usage/layout as JSON for profiling.
    pub fn export_memory_layout_json(&self) -> String {
        let st = self.state.lock();
        #[cfg(feature = "discovery")]
        let discovery_bytes = st.discovery_bytes_used();
        #[cfg(not(feature = "discovery"))]
        let discovery_bytes = 0usize;
        let schema_bytes = crate::config::schema_bytes_used();
        let mut out = String::new();
        let _ = core::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{{\"kind\":\"relay\",\
                 \"shared_queue_bytes_used\":{},\"shared_queue_bytes_allocated\":{},\
                 \"rx_queue_bytes_used\":{},\"rx_queue_bytes_allocated\":{},\"rx_queue_len\":{},\
                 \"tx_queue_bytes_used\":{},\"tx_queue_bytes_allocated\":{},\"tx_queue_len\":{},\
                 \"replay_queue_bytes_used\":{},\"replay_queue_bytes_allocated\":{},\"replay_queue_len\":{},\
                 \"recent_rx_bytes_used\":{},\"recent_rx_bytes_allocated\":{},\"recent_rx_len\":{},\
                 \"reliable_rx_buffer_bytes_used\":{},\"reliable_rx_buffer_bytes_allocated\":{},\"reliable_rx_buffer_len\":{},\
                 \"discovery_bytes_used\":{},\"discovery_bytes_allocated\":{},\
                 \"schema_bytes_used\":{},\"schema_bytes_allocated\":{}}}",
                st.shared_queue_bytes_used(),
                MAX_QUEUE_BUDGET,
                st.rx_queue.bytes_used(),
                st.rx_queue.max_bytes(),
                st.rx_queue.len(),
                st.tx_queue.bytes_used(),
                st.tx_queue.max_bytes(),
                st.tx_queue.len(),
                st.replay_queue.bytes_used(),
                st.replay_queue.max_bytes(),
                st.replay_queue.len(),
                st.recent_rx.bytes_used(),
                st.recent_rx.max_bytes(),
                st.recent_rx.len(),
                st.reliable_rx_buffered_bytes(),
                MAX_QUEUE_BUDGET,
                st.reliable_rx_buffer_len(),
                discovery_bytes,
                MAX_QUEUE_BUDGET,
                schema_bytes,
                MAX_QUEUE_BUDGET,
            ),
        );
        out
    }

    #[cfg(test)]
    pub(crate) fn debug_end_to_end_acked_destination_count(&self, packet_id: u64) -> Option<usize> {
        let st = self.state.lock();
        st.end_to_end_acked_destinations
            .get(&packet_id)
            .map(BTreeSet::len)
    }

    #[cfg(test)]
    pub(crate) fn debug_end_to_end_acked_packet_count(&self) -> usize {
        let st = self.state.lock();
        st.end_to_end_acked_destinations.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_reliable_return_route_count(&self) -> usize {
        let st = self.state.lock();
        st.reliable_return_routes.len()
    }

    /// Enqueue packed bytes that originated from `src` into the relay RX queue.
    ///
    /// Note: `Arc::from(bytes)` allocates and copies `len` bytes into a new `Arc<[u8]>`.
    /// This is still “fast enough” for many cases, but it is not allocation-free / ISR-safe.
    pub fn rx_packed_from_side(&self, src: RelaySideId, bytes: &[u8]) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(src)?;
        let Some(bytes) = self.decode_side_transport_frame(src, bytes)? else {
            return Ok(());
        };
        let mut st = self.state.lock();

        let data = RelayItem::Packed(bytes);
        let priority = Self::relay_item_priority(&data)?;
        st.push_rx(RelayRxItem {
            src,
            data,
            priority,
        })
    }

    /// Enqueue a full packet that originated from `src` into the relay RX queue.
    ///
    /// The packet is wrapped in `Arc<Packet>` so fanout can clone the pointer cheaply.
    pub fn rx_from_side(&self, src: RelaySideId, packet: Packet) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(src)?;
        let mut st = self.state.lock();

        let data = RelayItem::Packet(Arc::new(packet));
        let priority = Self::relay_item_priority(&data)?;
        st.push_rx(RelayRxItem {
            src,
            data,
            priority,
        })
    }

    /// Clear both RX and TX queues.
    pub fn clear_queues(&self) {
        let mut st = self.state.lock();
        st.rx_queue.clear();
        st.tx_queue.clear();
    }

    /// Clear only RX queue.
    pub fn clear_rx_queue(&self) {
        let mut st = self.state.lock();
        st.rx_queue.clear();
    }

    /// Clear only TX queue.
    pub fn clear_tx_queue(&self) {
        let mut st = self.state.lock();
        st.tx_queue.clear();
        st.replay_queue.clear();
    }

    /// Internal: expand one RX item into TX items for all other sides.
    ///
    /// Fanout is cheap: the `RelayItem` is cloned (Arc bump) and reused across all destinations.
    fn process_rx_queue_item(&self, item: RelayRxItem) -> TelemetryResult<()> {
        self.ensure_side_ingress_enabled(item.src)?;
        match &item.data {
            RelayItem::Packet(pkt) => {
                let bytes = wire_format::pack_packet(pkt).len();
                self.note_side_rx(item.src, pkt.data_type(), bytes);
            }
            RelayItem::Packed(bytes) => {
                if let Ok(env) = wire_format::peek_envelope(bytes.as_ref()) {
                    self.note_side_rx(item.src, env.ty, bytes.len());
                }
            }
        }
        match &item.data {
            RelayItem::Packet(pkt) => {
                if is_reliable_type(pkt.data_type()) && !is_internal_control_type(pkt.data_type()) {
                    self.note_reliable_return_route(item.src, pkt.packet_id());
                }
            }
            RelayItem::Packed(bytes) => {
                if let Ok(env) = wire_format::peek_envelope(bytes.as_ref())
                    && is_reliable_type(env.ty)
                    && !is_internal_control_type(env.ty)
                    && let Ok(packet_id) = wire_format::packet_id_from_wire(bytes.as_ref())
                {
                    self.note_reliable_return_route(item.src, packet_id);
                }
            }
        }
        let mut released_buffered: Vec<Arc<[u8]>> = Vec::new();
        if let RelayItem::Packed(bytes) = &item.data {
            let (_opts, handler_is_packed, hop_reliable_enabled) = {
                let st = self.state.lock();
                let side_ref = Self::side_ref(&st, item.src)?;
                let opts = side_ref.opts;
                (
                    opts,
                    matches!(side_ref.tx_handler, RelayTxHandlerFn::Packed(_)),
                    opts.reliable_enabled
                        && !self.side_has_multiple_announcers_locked(
                            &st,
                            item.src,
                            self.clock.now_ms(),
                        ),
                )
            };

            let frame = match wire_format::peek_frame_info(bytes.as_ref()) {
                Ok(frame) => frame,
                Err(e) => {
                    if matches!(e, TelemetryError::Unpack(msg) if msg == "crc32 mismatch")
                        && hop_reliable_enabled
                        && handler_is_packed
                        && let Ok(frame) = wire_format::peek_frame_info_unchecked(bytes.as_ref())
                    {
                        if is_reliable_type(frame.envelope.ty)
                            && let Some(hdr) = frame.reliable
                        {
                            let unordered = (hdr.flags & wire_format::RELIABLE_FLAG_UNORDERED) != 0;
                            let unsequenced =
                                (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) != 0;

                            if !unsequenced {
                                let requested = if unordered {
                                    hdr.seq
                                } else {
                                    let mut st = self.state.lock();
                                    let rx_state = self.reliable_rx_state_mut(
                                        &mut st,
                                        item.src,
                                        frame.envelope.ty,
                                    );
                                    rx_state.expected_seq.min(hdr.seq)
                                };
                                self.queue_reliable_packet_request(
                                    item.src,
                                    frame.envelope.ty,
                                    requested,
                                )?;
                            }
                        }
                        return Ok(());
                    }
                    return Err(e);
                }
            };

            if hop_reliable_enabled
                && handler_is_packed
                && is_reliable_type(frame.envelope.ty)
                && let Some(hdr) = frame.reliable
            {
                if frame.ack_only() {
                    self.handle_reliable_ack(item.src, frame.envelope.ty, hdr.ack);
                    return Ok(());
                }
                let unordered = (hdr.flags & wire_format::RELIABLE_FLAG_UNORDERED) != 0;
                let unsequenced = (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) != 0;

                if !unsequenced {
                    if unordered {
                        self.queue_reliable_ack(item.src, frame.envelope.ty, hdr.seq)?;
                    } else {
                        let mut release: Vec<Arc<[u8]>> = Vec::new();
                        let mut last_delivered = None;
                        let mut ack_old = None;
                        let mut request_missing = None;
                        let mut partial_ack = None;
                        {
                            let mut st = self.state.lock();
                            let rx_state =
                                self.reliable_rx_state_mut(&mut st, item.src, frame.envelope.ty);
                            let expected_seq = rx_state.expected_seq;
                            if hdr.seq < expected_seq {
                                ack_old = Some(expected_seq.saturating_sub(1));
                            } else if hdr.seq > expected_seq {
                                request_missing = Some(expected_seq);
                                partial_ack = Some(hdr.seq);
                                st.buffer_reliable_rx(
                                    item.src,
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
                            self.queue_reliable_ack(item.src, frame.envelope.ty, ack_seq)?;
                            return Ok(());
                        }
                        if let Some(request_seq) = request_missing {
                            if let Some(partial_seq) = partial_ack {
                                self.queue_reliable_partial_ack(
                                    item.src,
                                    frame.envelope.ty,
                                    partial_seq,
                                )?;
                            }
                            self.queue_reliable_packet_request(
                                item.src,
                                frame.envelope.ty,
                                request_seq,
                            )?;
                            return Ok(());
                        }
                        if let Some(ack_seq) = last_delivered {
                            self.queue_reliable_ack(item.src, frame.envelope.ty, ack_seq)?;
                        }
                        released_buffered.extend(release.into_iter().skip(1));
                    }
                }
            }
        }

        if self.is_duplicate_pkt(&item)? && !self.should_forward_duplicate_reliable_item(&item)? {
            // Already fanned out this packet recently; skip.
            return Ok(());
        }

        self.dispatch_relay_rx_item(&item)?;

        for release_bytes in released_buffered {
            let release_item = RelayRxItem {
                src: item.src,
                priority: Self::relay_item_priority(&RelayItem::Packed(release_bytes.clone()))?,
                data: RelayItem::Packed(release_bytes),
            };
            if self.is_duplicate_pkt(&release_item)?
                && !self.should_forward_duplicate_reliable_item(&release_item)?
            {
                continue;
            }
            self.dispatch_relay_rx_item(&release_item)?;
        }
        Ok(())
    }

    fn dispatch_relay_rx_item(&self, item: &RelayRxItem) -> TelemetryResult<()> {
        match &item.data {
            RelayItem::Packet(pkt) => {
                if matches!(
                    pkt.data_type(),
                    crate::DataType::ReliableAck
                        | crate::DataType::ReliablePartialAck
                        | crate::DataType::ReliablePacketRequest
                ) {
                    if pkt.data_type() == crate::DataType::ReliableAck
                        && Self::is_end_to_end_ack_sender(pkt.sender())
                        && Self::decode_end_to_end_reliable_ack(pkt.payload()).is_ok()
                    {
                        if let Ok(packet_id) = Self::decode_end_to_end_reliable_ack(pkt.payload())
                            && let Some(sender_hash) =
                                Self::decode_end_to_end_ack_sender_hash(pkt.sender())
                        {
                            let mut st = self.state.lock();
                            Self::note_end_to_end_acked_destination_locked(
                                &mut st,
                                packet_id,
                                sender_hash,
                            );
                        }
                    } else {
                        let vals = pkt.data_as_u32()?;
                        if vals.len() != 2 {
                            return Err(TelemetryError::Unpack("bad reliable control payload"));
                        }
                        let ty = crate::DataType::try_from_u32(vals[0])
                            .ok_or(TelemetryError::InvalidType)?;
                        let seq = vals[1];
                        match pkt.data_type() {
                            crate::DataType::ReliableAck => {
                                self.handle_reliable_ack(item.src, ty, seq)
                            }
                            crate::DataType::ReliablePartialAck => {
                                self.handle_reliable_partial_ack(item.src, ty, seq)
                            }
                            crate::DataType::ReliablePacketRequest => {
                                self.queue_reliable_retransmit(item.src, ty, seq)?
                            }
                            _ => {}
                        }
                        return Ok(());
                    }
                }
            }
            RelayItem::Packed(bytes) => {
                let env = wire_format::peek_envelope(bytes.as_ref())?;
                if matches!(
                    env.ty,
                    crate::DataType::ReliableAck
                        | crate::DataType::ReliablePacketRequest
                        | crate::DataType::ReliablePartialAck
                ) {
                    let pkt = wire_format::unpack_packet(bytes.as_ref())?;
                    return self.dispatch_relay_rx_item(&RelayRxItem {
                        src: item.src,
                        data: RelayItem::Packet(Arc::new(pkt)),
                        priority: item.priority,
                    });
                }
            }
        }

        let src = item.src;
        let data = item.data.clone();
        self.learn_discovery_item(src, &data)?;

        let plan = self.remote_side_plan(&data, src)?;
        let mut st = self.state.lock();
        let RemoteSidePlan::Target(sides) = plan;
        for dst in sides {
            let priority = Self::relay_item_priority(&data)?;
            st.push_tx(RelayTxItem {
                src: Some(src),
                dst,
                data: data.clone(),
                priority,
            })?;
        }
        Ok(())
    }

    #[inline]
    fn crc32_bytes(data: &[u8]) -> u32 {
        let mut hasher = Crc32Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn wrap_side_transport_frame(kind: u8, body: &[u8]) -> Arc<[u8]> {
        let mut out = Vec::with_capacity(
            SIDE_TRANSPORT_MAGIC.len() + 1 + body.len() + wire_format::CRC32_BYTES,
        );
        out.extend_from_slice(SIDE_TRANSPORT_MAGIC);
        out.push(kind);
        out.extend_from_slice(body);
        let crc = Self::crc32_bytes(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Arc::from(out)
    }

    fn parse_side_transport_wrapper(bytes: &[u8]) -> TelemetryResult<Option<(u8, &[u8])>> {
        if bytes.len() < SIDE_TRANSPORT_MAGIC.len() + 1 + wire_format::CRC32_BYTES {
            return Ok(None);
        }
        if &bytes[..SIDE_TRANSPORT_MAGIC.len()] != SIDE_TRANSPORT_MAGIC {
            return Ok(None);
        }
        let data_len = bytes.len() - wire_format::CRC32_BYTES;
        let expected = u32::from_le_bytes([
            bytes[data_len],
            bytes[data_len + 1],
            bytes[data_len + 2],
            bytes[data_len + 3],
        ]);
        let data = &bytes[..data_len];
        if Self::crc32_bytes(data) != expected {
            return Err(TelemetryError::Unpack("side transport crc32 mismatch"));
        }
        let kind = data[SIDE_TRANSPORT_MAGIC.len()];
        Ok(Some((kind, &data[SIDE_TRANSPORT_MAGIC.len() + 1..])))
    }

    fn read_uleb128_local(buf: &[u8], off: &mut usize) -> TelemetryResult<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let byte = *buf.get(*off).ok_or(TelemetryError::Unpack("short read"))?;
            *off += 1;
            result |= u64::from(byte & 0x7F) << shift;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(TelemetryError::Unpack("uleb128 too long"))
    }

    fn write_uleb128_local(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn uleb128_len_local(mut value: u64) -> usize {
        let mut len = 1;
        while value >= 0x80 {
            value >>= 7;
            len += 1;
        }
        len
    }

    fn extract_side_header_template(bytes: &[u8]) -> TelemetryResult<SideTemplateExtract<'_>> {
        if bytes.len() < wire_format::CRC32_BYTES + 4 {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        let data_len = bytes.len() - wire_format::CRC32_BYTES;
        let data = &bytes[..data_len];
        let mut off = 0usize;
        let flags = *data
            .get(off)
            .ok_or(TelemetryError::Unpack("short prelude"))?;
        off += 1;
        off += 1; // NEP
        let ty_u64 = Self::read_uleb128_local(data, &mut off)?;
        let ty_u32 = u32::try_from(ty_u64).map_err(|_| TelemetryError::Unpack("bad data type"))?;
        if ty_u32 > crate::MAX_VALUE_DATA_TYPE {
            return Err(TelemetryError::Unpack("bad data type"));
        }
        let ty = crate::DataType(ty_u32);
        let data_size_off = off;
        let data_size = Self::read_uleb128_local(data, &mut off)?;
        let timestamp = Self::read_uleb128_local(data, &mut off)?;
        let nonce = if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
            u16::try_from(Self::read_uleb128_local(data, &mut off)?)
                .map_err(|_| TelemetryError::Unpack("packet nonce too large"))?
        } else {
            0
        };
        let between_start = off;
        let sender_len = usize::try_from(Self::read_uleb128_local(data, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("sender length too large"))?;
        let sender_wire_len = if (flags & SIDE_TRANSPORT_FLAG_SENDER_COMPRESSED) != 0 {
            usize::try_from(Self::read_uleb128_local(data, &mut off)?)
                .map_err(|_| TelemetryError::Unpack("sender wire length too large"))?
        } else {
            sender_len
        };
        let endpoint_bitmap_bytes = if (flags & SIDE_TRANSPORT_FLAG_ENDPOINT_BITMAP_PRESENT) != 0 {
            SIDE_TRANSPORT_EP_BITMAP_BYTES
        } else {
            0
        };
        if data.len() < off + endpoint_bitmap_bytes + sender_wire_len {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        off += endpoint_bitmap_bytes + sender_wire_len;
        if (flags & SIDE_TRANSPORT_FLAG_WIRE_CONTRACT) != 0 {
            let contract_len = usize::try_from(Self::read_uleb128_local(data, &mut off)?)
                .map_err(|_| TelemetryError::Unpack("wire contract length"))?;
            if data.len() < off + contract_len {
                return Err(TelemetryError::Unpack("short buffer"));
            }
            off += contract_len;
        }
        let reliable_off = wire_format::reliable_header_offset(bytes)?;
        let (reliable_flags, reliable_seq_ack, payload_off) = if let Some(rel_off) = reliable_off {
            if data.len() < rel_off + wire_format::RELIABLE_HEADER_BYTES {
                return Err(TelemetryError::Unpack("short buffer"));
            }
            let rel_flags = data[rel_off];
            let seq = u32::from_le_bytes([
                data[rel_off + 1],
                data[rel_off + 2],
                data[rel_off + 3],
                data[rel_off + 4],
            ]);
            let ack = u32::from_le_bytes([
                data[rel_off + 5],
                data[rel_off + 6],
                data[rel_off + 7],
                data[rel_off + 8],
            ]);
            (
                Some(rel_flags),
                Some((seq, ack)),
                rel_off + wire_format::RELIABLE_HEADER_BYTES,
            )
        } else {
            (None, None, off)
        };
        if payload_off > data.len() {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        let payload = &data[payload_off..];
        let prefix = Arc::<[u8]>::from(&data[1..data_size_off]);
        let between = Arc::<[u8]>::from(&data[between_start..reliable_off.unwrap_or(payload_off)]);
        let base_flags =
            flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE);
        let mut hash = 0xD1B5_4A32_9C7E_01F3u64;
        hash = hash_bytes_u64(hash, &[base_flags]);
        hash = hash_bytes_u64(hash, &prefix);
        hash = hash_bytes_u64(hash, &between);
        if let Some(rel_flags) = reliable_flags {
            hash = hash_bytes_u64(hash, &[rel_flags]);
        }
        let template = SideHeaderTemplate {
            hash,
            base_flags,
            prefix,
            between,
            reliable_flags,
        };
        Ok((
            template,
            ty,
            flags,
            data_size,
            timestamp,
            nonce,
            reliable_seq_ack,
            payload,
        ))
    }

    fn reconstruct_side_compact_frame(
        template: &SideHeaderTemplate,
        body: &[u8],
        timestamp_mode: SideCompactTimestampMode,
        timestamp_base: Option<u64>,
    ) -> TelemetryResult<(Arc<[u8]>, u64)> {
        if body.is_empty() {
            return Err(TelemetryError::Unpack("short side compact frame"));
        }
        let mut off = 0usize;
        let flags = body[off];
        off += 1;
        if (flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE))
            != template.base_flags
        {
            return Err(TelemetryError::Unpack("side compact flags mismatch"));
        }
        let data_size = Self::read_uleb128_local(body, &mut off)?;
        let timestamp = match timestamp_mode {
            SideCompactTimestampMode::Absolute => Self::read_uleb128_local(body, &mut off)?,
            SideCompactTimestampMode::Delta => {
                let timestamp_field = Self::read_uleb128_local(body, &mut off)?;
                let base = timestamp_base.ok_or(TelemetryError::Unpack(
                    "missing side compact timestamp context",
                ))?;
                base.checked_add(timestamp_field)
                    .ok_or(TelemetryError::Unpack(
                        "side compact timestamp delta overflow",
                    ))?
            }
            SideCompactTimestampMode::Omitted => timestamp_base.ok_or(TelemetryError::Unpack(
                "missing side compact timestamp context",
            ))?,
        };
        let nonce = if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
            Some(Self::read_uleb128_local(body, &mut off)?)
        } else {
            None
        };
        let reliable_seq_ack = if template.reliable_flags.is_some() {
            if body.len() < off + 8 {
                return Err(TelemetryError::Unpack("short side compact reliable"));
            }
            let seq = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
            let ack =
                u32::from_le_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
            off += 8;
            Some((seq, ack))
        } else {
            None
        };
        let payload = &body[off..];
        let mut raw = Vec::with_capacity(
            1 + template.prefix.len() + template.between.len() + payload.len() + 32,
        );
        raw.push(flags);
        raw.extend_from_slice(&template.prefix);
        Self::write_uleb128_local(data_size, &mut raw);
        Self::write_uleb128_local(timestamp, &mut raw);
        if let Some(nonce) = nonce {
            Self::write_uleb128_local(nonce, &mut raw);
        }
        raw.extend_from_slice(&template.between);
        if let Some(rel_flags) = template.reliable_flags {
            raw.push(rel_flags);
            let (seq, ack) =
                reliable_seq_ack.ok_or(TelemetryError::Unpack("missing side compact reliable"))?;
            raw.extend_from_slice(&seq.to_le_bytes());
            raw.extend_from_slice(&ack.to_le_bytes());
        }
        raw.extend_from_slice(payload);
        let crc = Self::crc32_bytes(&raw);
        raw.extend_from_slice(&crc.to_le_bytes());
        Ok((Arc::from(raw), timestamp))
    }

    fn split_side_transport_frame(
        &self,
        side: RelaySideId,
        frame: Arc<[u8]>,
        max_frame_bytes: usize,
    ) -> TelemetryResult<Vec<Arc<[u8]>>> {
        if max_frame_bytes <= SIDE_TRANSPORT_CHUNK_OVERHEAD {
            return Err(TelemetryError::BadArg);
        }
        let payload_budget = max_frame_bytes - SIDE_TRANSPORT_CHUNK_OVERHEAD;
        let mut st = self.state.lock();
        let side_state = st
            .side_transport
            .get_mut(&side)
            .ok_or(TelemetryError::BadArg)?;
        let transfer_id = side_state.next_chunk_id.wrapping_add(1).max(1);
        side_state.next_chunk_id = transfer_id;
        drop(st);

        let total = frame.len().div_ceil(payload_budget);
        let total_u16 =
            u16::try_from(total).map_err(|_| TelemetryError::PacketTooLarge("too many chunks"))?;
        let mut frames = Vec::with_capacity(total);
        for (idx, chunk) in frame.chunks(payload_budget).enumerate() {
            let mut body = Vec::with_capacity(8 + chunk.len());
            body.extend_from_slice(&transfer_id.to_le_bytes());
            body.extend_from_slice(&(idx as u16).to_le_bytes());
            body.extend_from_slice(&total_u16.to_le_bytes());
            body.extend_from_slice(chunk);
            frames.push(Self::wrap_side_transport_frame(
                SIDE_TRANSPORT_KIND_CHUNK,
                &body,
            ));
        }
        Ok(frames)
    }

    fn encode_side_transport_frames(
        &self,
        side: RelaySideId,
        opts: RelaySideOptions,
        raw: Arc<[u8]>,
    ) -> TelemetryResult<Vec<Arc<[u8]>>> {
        if !opts.header_template_enabled && opts.max_frame_bytes == 0 {
            return Ok(vec![raw]);
        }
        let raw_len = raw.len();
        let mut compact_payload_len = None;
        let mut used_compact = false;
        let mut used_timestamp_delta = false;
        let mut omitted_timestamp = false;
        let (template, ty, flags, data_size, timestamp, nonce, reliable_seq_ack, payload) =
            Self::extract_side_header_template(raw.as_ref())?;
        let (template_id, use_compact, previous_timestamp) = {
            let mut st = self.state.lock();
            let side_state = st
                .side_transport
                .get_mut(&side)
                .ok_or(TelemetryError::BadArg)?;
            if let Some(id) = side_state.tx_template_ids.get(&template.hash).copied() {
                let previous = side_state.tx_last_timestamps.get(&id).copied();
                (id, true, previous)
            } else {
                let next = side_state.next_template_id.wrapping_add(1).max(1);
                side_state.next_template_id = next;
                let evicted = side_state.insert_tx_template(
                    template,
                    next,
                    opts.max_side_transport_templates,
                );
                if evicted {
                    st.side_runtime_stats
                        .entry(side)
                        .or_default()
                        .note_side_transport_template_eviction();
                }
                if let Some(side_state) = st.side_transport.get_mut(&side) {
                    side_state.tx_last_timestamps.insert(next, timestamp);
                }
                (next, false, None)
            }
        };
        let wrapped = if use_compact {
            used_compact = true;
            compact_payload_len = Some(payload.len());
            let timestamp_field = if let Some(previous) = previous_timestamp {
                let delta = timestamp.saturating_sub(previous);
                let omit_timestamp = opts.omit_unchanged_compact_timestamps
                    || opts.compact_timestamp_omission_types.contains(ty);
                if omit_timestamp && timestamp == previous {
                    omitted_timestamp = true;
                    None
                } else if timestamp >= previous
                    && Self::uleb128_len_local(delta) < Self::uleb128_len_local(timestamp)
                {
                    used_timestamp_delta = true;
                    Some(delta)
                } else {
                    Some(timestamp)
                }
            } else {
                Some(timestamp)
            };
            let mut body = Vec::with_capacity(payload.len() + 32);
            body.push(flags);
            Self::write_uleb128_local(u64::from(template_id), &mut body);
            Self::write_uleb128_local(data_size, &mut body);
            if let Some(timestamp_field) = timestamp_field {
                Self::write_uleb128_local(timestamp_field, &mut body);
            }
            if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
                Self::write_uleb128_local(u64::from(nonce), &mut body);
            }
            if let Some((seq, ack)) = reliable_seq_ack {
                body.extend_from_slice(&seq.to_le_bytes());
                body.extend_from_slice(&ack.to_le_bytes());
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
            Self::wrap_side_transport_frame(kind, &body)
        } else {
            let mut body = Vec::with_capacity(raw.len() + 4);
            Self::write_uleb128_local(u64::from(template_id), &mut body);
            body.extend_from_slice(raw.as_ref());
            Self::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &body)
        };
        let frames = if opts.max_frame_bytes != 0 && wrapped.len() > opts.max_frame_bytes {
            self.split_side_transport_frame(side, wrapped, opts.max_frame_bytes)
        } else {
            Ok(vec![wrapped])
        }?;
        let wire_len = frames.iter().map(|frame| frame.len()).sum::<usize>();
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

    fn decode_side_transport_frame(
        &self,
        side: RelaySideId,
        bytes: &[u8],
    ) -> TelemetryResult<Option<Arc<[u8]>>> {
        let Some((kind, body)) = Self::parse_side_transport_wrapper(bytes)? else {
            return Ok(Some(Arc::from(bytes)));
        };
        match kind {
            SIDE_TRANSPORT_KIND_FULL => {
                let mut off = 0usize;
                let template_id = u32::try_from(Self::read_uleb128_local(body, &mut off)?)
                    .map_err(|_| TelemetryError::Unpack("side template id too large"))?;
                let raw = Arc::<[u8]>::from(&body[off..]);
                if let Ok((template, _, _, _, timestamp, _, _, _)) =
                    Self::extract_side_header_template(raw.as_ref())
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
                        side_state.rx_last_timestamps.insert(template_id, timestamp);
                        evicted
                    });
                    if evicted {
                        st.side_runtime_stats
                            .entry(side)
                            .or_default()
                            .note_side_transport_template_eviction();
                    }
                }
                Ok(Some(raw))
            }
            SIDE_TRANSPORT_KIND_COMPACT
            | SIDE_TRANSPORT_KIND_COMPACT_DELTA
            | SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP => {
                if body.is_empty() {
                    return Err(TelemetryError::Unpack("short side compact frame"));
                }
                let mut off = 1usize;
                let template_id = u32::try_from(Self::read_uleb128_local(body, &mut off)?)
                    .map_err(|_| TelemetryError::Unpack("side template id too large"))?;
                let mut compact_body = Vec::with_capacity(1 + body.len().saturating_sub(off));
                compact_body.push(body[0]);
                compact_body.extend_from_slice(&body[off..]);
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
                let template =
                    template.ok_or(TelemetryError::Unpack("unknown side compact template"))?;
                let timestamp_mode = match kind {
                    SIDE_TRANSPORT_KIND_COMPACT_DELTA => SideCompactTimestampMode::Delta,
                    SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP => SideCompactTimestampMode::Omitted,
                    _ => SideCompactTimestampMode::Absolute,
                };
                let (frame, timestamp) = Self::reconstruct_side_compact_frame(
                    &template,
                    &compact_body,
                    timestamp_mode,
                    timestamp_base,
                )?;
                let mut st = self.state.lock();
                if let Some(side_state) = st.side_transport.get_mut(&side) {
                    side_state.rx_last_timestamps.insert(template_id, timestamp);
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
                let payload = Arc::<[u8]>::from(&body[8..]);
                let assembled = {
                    let mut st = self.state.lock();
                    let side_state = st
                        .side_transport
                        .get_mut(&side)
                        .ok_or(TelemetryError::BadArg)?;
                    let entry = side_state.rx_chunks.entry(transfer_id).or_default();
                    if entry.total == 0 {
                        entry.total = total;
                    } else if entry.total != total {
                        side_state.rx_chunks.remove(&transfer_id);
                        return Err(TelemetryError::Unpack("side chunk total mismatch"));
                    }
                    entry.received.entry(index).or_insert(payload);
                    if entry.received.len() == usize::from(total) {
                        let entry = side_state
                            .rx_chunks
                            .remove(&transfer_id)
                            .ok_or(TelemetryError::Unpack("side chunk missing"))?;
                        let mut out = Vec::new();
                        for idx in 0..entry.total {
                            let chunk = entry
                                .received
                                .get(&idx)
                                .ok_or(TelemetryError::Unpack("side chunk gap"))?;
                            out.extend_from_slice(chunk);
                        }
                        Some(Arc::<[u8]>::from(out))
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

    /// Helper: call a TX handler with the best representation we have.
    /// - Packet handler + Packet item: direct.
    /// - Packed handler + Packed item: direct.
    /// - Packet handler + Packed item: unpack for this call.
    /// - Packed handler + Packet item: pack for this call.
    fn call_tx_handler(
        &self,
        side: RelaySideId,
        handler: &RelayTxHandlerFn,
        data: &RelayItem,
    ) -> TelemetryResult<()> {
        let opts = {
            let st = self.state.lock();
            Self::side_ref(&st, side)?.opts
        };
        let Some(_side_tx_guard) = self.try_enter_side_tx() else {
            return Err(TelemetryError::Io("side tx busy"));
        };
        let started_ms = self.clock.now_ms();
        let ty = match data {
            RelayItem::Packet(pkt) => pkt.data_type(),
            RelayItem::Packed(bytes) => wire_format::peek_envelope(bytes.as_ref())?.ty,
        };
        let result = match (handler, data) {
            // Fast paths
            (RelayTxHandlerFn::Packed(f), RelayItem::Packed(bytes)) => {
                let frames = self.encode_side_transport_frames(side, opts, bytes.clone())?;
                let mut sent_bytes = 0usize;
                for frame in frames {
                    f(frame.as_ref())?;
                    sent_bytes = sent_bytes.saturating_add(frame.len());
                }
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, 1);
                return Ok(());
            }
            (RelayTxHandlerFn::Packet(f), RelayItem::Packet(pkt)) => f(pkt),

            // Conversion paths
            (RelayTxHandlerFn::Packed(f), RelayItem::Packet(pkt)) => {
                let owned = wire_format::pack_packet(pkt);
                let frames = self.encode_side_transport_frames(side, opts, owned)?;
                let mut sent_bytes = 0usize;
                for frame in frames {
                    f(frame.as_ref())?;
                    sent_bytes = sent_bytes.saturating_add(frame.len());
                }
                self.record_side_tx_sample(side, sent_bytes, started_ms, self.clock.now_ms());
                self.note_side_tx_success(side, ty, sent_bytes, 1);
                return Ok(());
            }
            (RelayTxHandlerFn::Packet(f), RelayItem::Packed(bytes)) => {
                if wire_format::peek_frame_info(bytes.as_ref())
                    .ok()
                    .is_some_and(|frame| frame.ack_only())
                {
                    return Ok(());
                }
                let pkt = wire_format::unpack_packet(bytes.as_ref())?;
                f(&pkt)
            }
        };
        if result.is_ok()
            && let Ok(bytes) = Self::relay_item_wire_len(data)
        {
            self.record_side_tx_sample(side, bytes, started_ms, self.clock.now_ms());
            self.note_side_tx_success(side, ty, bytes, 1);
        } else if result.is_err() {
            self.note_side_tx_failure(side, ty, 1);
        }
        result
    }

    fn adjust_reliable_for_side(
        &self,
        opts: RelaySideOptions,
        data: RelayItem,
    ) -> TelemetryResult<Option<RelayItem>> {
        if opts.reliable_enabled {
            return Ok(Some(data));
        }

        match data {
            RelayItem::Packed(bytes) => {
                let frame = match wire_format::peek_frame_info(bytes.as_ref()) {
                    Ok(frame) => frame,
                    Err(_) => return Ok(Some(RelayItem::Packed(bytes))),
                };
                if is_reliable_type(frame.envelope.ty)
                    && let Some(hdr) = frame.reliable
                {
                    if (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) != 0 {
                        return Ok(None);
                    }
                    if (hdr.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED) == 0 {
                        let mut v = bytes.to_vec();
                        let _ = wire_format::rewrite_reliable_header(
                            &mut v,
                            wire_format::RELIABLE_FLAG_UNSEQUENCED,
                            hdr.seq,
                            0,
                        )?;
                        return Ok(Some(RelayItem::Packed(Arc::from(v))));
                    }
                }
                Ok(Some(RelayItem::Packed(bytes)))
            }
            RelayItem::Packet(pkt) => {
                if matches!(
                    pkt.data_type(),
                    crate::DataType::ReliableAck
                        | crate::DataType::ReliablePartialAck
                        | crate::DataType::ReliablePacketRequest
                ) {
                    return Ok(None);
                }
                Ok(Some(RelayItem::Packet(pkt)))
            }
        }
    }

    /// Drain the RX queue fully, expanding to TX items.
    #[inline]
    pub fn process_rx_queue(&self) -> TelemetryResult<()> {
        self.process_rx_queue_with_timeout(0)
    }

    /// Drain the TX queue fully, invoking per-side TX handlers.
    ///
    /// If called from inside a side TX callback, this becomes a no-op so relay TX handlers cannot
    /// recurse into nested queue drains on the same stack.
    #[inline]
    pub fn process_tx_queue(&self) -> TelemetryResult<()> {
        self.process_tx_queue_with_timeout(0)
    }

    /// Drain RX then TX queues fully (one pass).
    #[inline]
    pub fn process_all_queues(&self) -> TelemetryResult<()> {
        self.process_all_queues_with_timeout(0)
    }

    /// Process the TX queue for up to `timeout_ms` milliseconds.
    ///
    /// `timeout_ms == 0` drains fully. If called from inside a side TX callback, this becomes a
    /// no-op so relay TX handlers cannot recurse into nested queue drains on the same stack.
    pub fn process_tx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return Ok(());
        }
        #[cfg(feature = "discovery")]
        {
            let _ = self.poll_discovery()?;
        }
        let start = self.clock.now_ms();
        loop {
            self.process_reliable_timeouts()?;
            if self.process_replay_queue_item()? {
                if timeout_ms != 0 && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                    break;
                }
                continue;
            }
            let Some((src, dst, handler, opts, data)) = self.pop_ready_tx_item() else {
                break;
            };
            match self.send_tx_item(src, dst, handler, opts, data.clone()) {
                Ok(sent) => {
                    if sent
                        && timeout_ms != 0
                        && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64
                    {
                        break;
                    }
                }
                Err(e) if Self::is_side_tx_busy(&e) => {
                    let priority = Self::relay_item_priority(&data)?;
                    let mut st = self.state.lock();
                    st.push_tx(RelayTxItem {
                        src,
                        dst,
                        data,
                        priority,
                    })?;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Process RX queue with timeout.
    pub fn process_rx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        {
            let _ = self.poll_discovery()?;
        }
        let start = self.clock.now_ms();
        loop {
            let item_opt = {
                let mut st = self.state.lock();
                st.rx_queue.pop_front()
            };
            let Some(item) = item_opt else { break };
            self.process_rx_queue_item(item)?;

            if timeout_ms != 0 && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                break;
            }
        }
        Ok(())
    }

    /// Process RX and TX queues interleaved for up to `timeout_ms` milliseconds.
    ///
    /// `timeout_ms == 0` drains fully. If called from inside a side TX callback, this becomes a
    /// no-op so relay TX handlers cannot recurse into nested queue drains on the same stack.
    pub fn process_all_queues_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        if self.side_tx_active() {
            return Ok(());
        }
        #[cfg(feature = "discovery")]
        {
            let _ = self.poll_discovery()?;
        }
        let drain_fully = timeout_ms == 0;
        let start = if drain_fully { 0 } else { self.clock.now_ms() };

        loop {
            let mut did_any = false;
            self.process_reliable_timeouts()?;

            // First move RX → TX
            if let Some(item) = {
                let mut st = self.state.lock();
                st.rx_queue.pop_front()
            } {
                self.process_rx_queue_item(item)?;
                did_any = true;
            }

            if !drain_fully && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                break;
            }

            if self.process_replay_queue_item()? {
                did_any = true;
            }

            // Then send out TX
            let sent_one = if let Some((src, dst, handler, opts, data)) = self.pop_ready_tx_item() {
                self.send_tx_item(src, dst, handler, opts, data)?
            } else {
                false
            };

            if sent_one {
                did_any = true;
            }

            if !drain_fully && self.clock.now_ms().wrapping_sub(start) >= timeout_ms as u64 {
                break;
            }

            if !did_any {
                break;
            }
        }

        Ok(())
    }

    /// Runs one application-loop maintenance cycle.
    ///
    /// This polls built-in discovery when that feature is compiled in, then drains queued RX/TX
    /// work for up to `timeout_ms` milliseconds.
    pub fn periodic(&self, timeout_ms: u32) -> TelemetryResult<()> {
        #[cfg(feature = "discovery")]
        {
            let _ = self.poll_discovery()?;
        }

        self.process_all_queues_with_timeout(timeout_ms)
    }
}
