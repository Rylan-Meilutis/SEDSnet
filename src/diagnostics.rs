use alloc::{string::String, vec::Vec};

use crate::{DataType, RouteSelectionMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTypeStats {
    pub data_type: DataType,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub relayed_tx_packets: u64,
    pub relayed_tx_bytes: u64,
    pub relayed_rx_packets: u64,
    pub relayed_rx_bytes: u64,
    pub tx_retries: u64,
    pub handler_failures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveLinkStats {
    pub auto_balancing_enabled: bool,
    pub estimated_capacity_bps: u64,
    pub peak_capacity_bps: u64,
    pub current_usage_bps: u64,
    pub peak_usage_bps: u64,
    pub available_headroom_bps: u64,
    pub effective_weight: u64,
    pub last_observed_ms: u64,
    pub sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSideStats {
    pub side_id: usize,
    pub side_name: String,
    pub reliable_enabled: bool,
    pub link_local_enabled: bool,
    pub header_template_enabled: bool,
    pub max_frame_bytes: usize,
    pub compact_header_target_bytes: usize,
    pub side_transport_profile: &'static str,
    pub ingress_enabled: bool,
    pub egress_enabled: bool,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub relayed_tx_packets: u64,
    pub relayed_tx_bytes: u64,
    pub relayed_rx_packets: u64,
    pub relayed_rx_bytes: u64,
    pub local_delivery_packets: u64,
    pub tx_retries: u64,
    pub tx_handler_failures: u64,
    pub local_handler_failures: u64,
    pub total_handler_retries: u64,
    pub side_transport_full_frames: u64,
    pub side_transport_compact_frames: u64,
    pub side_transport_compact_delta_frames: u64,
    pub side_transport_compact_omitted_timestamp_frames: u64,
    pub side_transport_chunk_frames: u64,
    /// Incomplete transfers reclaimed under pressure, expiry or the per-link cap.
    pub side_transport_chunk_reclaims: u64,
    pub side_transport_raw_bytes: u64,
    pub side_transport_wire_bytes: u64,
    pub side_transport_bytes_saved: u64,
    pub side_transport_min_compact_overhead_bytes: Option<usize>,
    pub side_transport_max_compact_overhead_bytes: Option<usize>,
    pub side_transport_compact_target_misses: u64,
    pub side_transport_template_evictions: u64,
    pub side_transport_tx_template_count: usize,
    pub side_transport_rx_template_count: usize,
    pub max_side_transport_templates: usize,
    pub adaptive: AdaptiveLinkStats,
    pub data_types: Vec<RuntimeTypeStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteModeStats {
    pub src_side_id: Option<usize>,
    pub selection_mode: Option<RouteSelectionMode>,
    pub cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOverrideStats {
    pub src_side_id: Option<usize>,
    pub dst_side_id: usize,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedRouteOverrideStats {
    pub src_side_id: Option<usize>,
    pub data_type: DataType,
    pub dst_side_id: usize,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteWeightStats {
    pub src_side_id: Option<usize>,
    pub dst_side_id: usize,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePriorityStats {
    pub src_side_id: Option<usize>,
    pub dst_side_id: usize,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRuntimeStats {
    pub rx_len: usize,
    pub rx_bytes: usize,
    pub tx_len: usize,
    pub tx_bytes: usize,
    pub replay_len: usize,
    pub replay_bytes: usize,
    pub recent_rx_len: usize,
    pub recent_rx_bytes: usize,
    pub reliable_rx_buffered_len: usize,
    pub reliable_rx_buffered_bytes: usize,
    pub shared_queue_bytes_used: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReliableRuntimeStats {
    pub reliable_return_route_count: usize,
    pub end_to_end_pending_count: usize,
    pub end_to_end_pending_destination_count: usize,
    pub end_to_end_acked_cache_count: usize,
    /// Reliable deliveries that ran out of retries since the router started.
    pub exhausted: ReliableExhaustionCounts,
}

/// Reliable deliveries given up after the last retry, by path and mode. An
/// Ordered one also fails the stream's queued tail (not counted here); an
/// Unordered one is dropped alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReliableExhaustionCounts {
    pub end_to_end_ordered: u64,
    pub end_to_end_unordered: u64,
    pub hop_ordered: u64,
    pub hop_unordered: u64,
    /// Owners retired from end-to-end frames after missing every retry of one
    /// (a silent station), counted per frame, by the frame's mode. Only
    /// Unordered frames retire owners; the Ordered counts stay 0.
    pub silent_owner_retired_ordered: u64,
    pub silent_owner_retired_unordered: u64,
    /// End-to-end frames completed only because a silent owner was retired
    /// (every other owner had acknowledged them).
    pub silent_owner_completed_ordered: u64,
    pub silent_owner_completed_unordered: u64,
}

/// One reliable delivery given up after its last retry (std builds keep the
/// most recent few for [`crate::router::Router::take_exhausted_reliable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExhaustedReliable {
    /// None when the retained delivery's type is not known without decoding.
    pub data_type: Option<DataType>,
    /// The end-to-end packet ID; hop deliveries carry their hop sequence.
    pub packet_id: u64,
    pub ordered: bool,
    pub end_to_end: bool,
}

/// Fixed-size, allocation-free pending-delivery summary for constrained diagnostics.
/// `pending_owners` contains at most four hashes; `pending_count` is the total.
/// Flags: bit 0 queued, bit 1 waiting for predecessor, bit 2 proxy contract,
/// bit 3 tracks explicit destination owners. Unused rows/owners are zeroed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReliablePendingRow {
    pub packet_id: u64,
    pub last_send_ms: u64,
    pub data_type: u32,
    pub pending_count: u32,
    pub retries: u32,
    pub flags: u32,
    pub pending_owners: [u64; 4],
}

/// On-demand metadata for an outstanding reliable transmission. Payloads are
/// neither decoded nor copied; destination identifiers are sender hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReliablePendingStats {
    pub packet_id: u64,
    pub data_type: DataType,
    pub pending_destinations: Vec<u64>,
    pub retries: u32,
    pub queued: bool,
    pub waiting_for_predecessor: bool,
    pub last_send_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRuntimeStats {
    pub route_count: usize,
    pub announcer_count: usize,
    pub current_announce_interval_ms: Option<u64>,
    pub next_announce_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatsSnapshot {
    pub sides: Vec<RuntimeSideStats>,
    pub route_modes: Vec<RouteModeStats>,
    pub route_overrides: Vec<RouteOverrideStats>,
    pub typed_route_overrides: Vec<TypedRouteOverrideStats>,
    pub route_weights: Vec<RouteWeightStats>,
    pub route_priorities: Vec<RoutePriorityStats>,
    pub queues: QueueRuntimeStats,
    pub reliable: ReliableRuntimeStats,
    pub discovery: DiscoveryRuntimeStats,
    pub total_handler_failures: u64,
    pub total_handler_retries: u64,
    /// Time sync exchanges rejected because their round trip measured below
    /// the path's physical minimum (proof of a wrong stamp).
    pub timesync_sub_minimum_rejects: u64,
}
