//! Configuration shared by every routing role.

use crate::DataType;
#[cfg(feature = "discovery")]
use crate::discovery;
use crate::router::{
    CompactTimestampOmissionPolicy, DEFAULT_SIDE_TRANSPORT_TEMPLATE_LIMIT,
    IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES, IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES,
    SideTransportProfile,
};

#[derive(Clone, Debug)]
pub struct SideOptions {
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

impl Default for SideOptions {
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

impl SideOptions {
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
