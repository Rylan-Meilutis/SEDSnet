use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::E2eEncryptionPolicy;
#[cfg(feature = "std")]
use crate::config::export_schema;
use crate::router::encode_slice_le;
use crate::{
    DataEndpoint, DataType, MessageElement, TelemetryError, TelemetryResult,
    config::{
        OwnedDataTypeDefinition, OwnedEndpointDefinition, OwnedRuntimeSchemaSnapshot,
        RuntimeSchemaSnapshot, e2e_encryption_policy_code, e2e_encryption_policy_from_code,
        message_class_code, message_class_from_code, message_data_type_code,
        message_data_type_from_code, reliable_code, reliable_from_code,
    },
    packet::Packet,
};

pub const DISCOVERY_ROUTE_TTL_MS: u64 = 30_000;
pub const DISCOVERY_FAST_INTERVAL_MS: u64 = 250;
pub const DISCOVERY_SLOW_INTERVAL_MS: u64 = 5_000;
pub const DISCOVERY_SLOW_LINK_CAPACITY_BPS: u64 = 512;
pub const DISCOVERY_SLOW_LINK_PING_INTERVAL_MS: u64 = 15_000;
pub const DISCOVERY_SLOW_LINK_FULL_INTERVAL_MS: u64 = 120_000;
/// Retry only links with an unreceived topology baseline, not healthy links.
pub const DISCOVERY_BASELINE_RETRY_MS: u64 = 5_000;
/// Let the address and full topology in a normal bootstrap arrive together.
pub const DISCOVERY_BASELINE_GRACE_MS: u64 = 1_000;
/// Number of compact topology advertisements emitted for each change. These
/// packets are intentionally idempotent, so a small bounded repeat avoids a
/// 120-second repair delay after one lossy control frame without resending the
/// complete graph.
pub const DISCOVERY_INCREMENTAL_RETRY_COUNT: u8 = 3;
pub const TIMESYNC_SLOW_LINK_MIN_INTERVAL_MS: u64 = 30_000;
// A zero-node full topology is never emitted. Reusing zero as the extension
// marker makes older decoders reject the trailing delta payload cheaply
// instead of interpreting a marker as an enormous allocation count.
const DISCOVERY_TOPOLOGY_DELTA_MARKER: u32 = 0;

/// Validate an untrusted wire count before reserving collection storage.
///
/// Every decoded element consumes at least `minimum_encoded_bytes` from the
/// remaining payload. Checking that relationship before `Vec::with_capacity`
/// prevents a corrupt count from reaching Rust's infallible capacity path and
/// halting an embedded router with `capacity overflow`.
fn bounded_wire_vec<T>(
    payload: &[u8],
    cursor: usize,
    count: usize,
    minimum_encoded_bytes: usize,
    label: &'static str,
) -> TelemetryResult<Vec<T>> {
    let remaining = payload.len().saturating_sub(cursor);
    if minimum_encoded_bytes == 0 || count > remaining / minimum_encoded_bytes {
        return Err(TelemetryError::Unpack(label));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| TelemetryError::Unpack(label))?;
    Ok(values)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryCadenceState {
    pub current_interval_ms: u64,
    pub next_announce_ms: u64,
}

impl Default for DiscoveryCadenceState {
    fn default() -> Self {
        Self {
            current_interval_ms: DISCOVERY_FAST_INTERVAL_MS,
            next_announce_ms: 0,
        }
    }
}

impl DiscoveryCadenceState {
    /// Switches discovery back to fast cadence and schedules an immediate announce.
    pub fn on_topology_change(&mut self, now_ms: u64) {
        self.current_interval_ms = DISCOVERY_FAST_INTERVAL_MS;
        self.next_announce_ms = now_ms;
    }

    /// Advances the cadence after sending an announce, backing off toward the slow interval.
    pub fn on_announce_sent(&mut self, now_ms: u64) {
        self.next_announce_ms = now_ms.saturating_add(self.current_interval_ms);
        self.current_interval_ms = core::cmp::min(
            self.current_interval_ms.saturating_mul(2),
            DISCOVERY_SLOW_INTERVAL_MS,
        );
    }

    /// Returns `true` when discovery should emit another announce at `now_ms`.
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_announce_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyBoardNode {
    pub sender_id: String,
    pub reachable_endpoints: Vec<DataEndpoint>,
    pub reachable_timesync_sources: Vec<String>,
    pub connections: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyLink {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyAnnouncerRoute {
    pub sender_id: String,
    pub reachable_endpoints: Vec<DataEndpoint>,
    pub reachable_network_variables: Vec<DataType>,
    pub reachable_timesync_sources: Vec<String>,
    pub routers: Vec<TopologyBoardNode>,
    pub last_seen_ms: u64,
    pub age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologySideRoute {
    pub side_id: usize,
    pub side_name: String,
    pub reachable_endpoints: Vec<DataEndpoint>,
    pub reachable_network_variables: Vec<DataType>,
    pub reachable_timesync_sources: Vec<String>,
    pub announcers: Vec<TopologyAnnouncerRoute>,
    pub last_seen_ms: u64,
    pub age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologySnapshot {
    pub advertised_endpoints: Vec<DataEndpoint>,
    pub advertised_timesync_sources: Vec<String>,
    pub routers: Vec<TopologyBoardNode>,
    pub links: Vec<TopologyLink>,
    pub routes: Vec<TopologySideRoute>,
    pub current_announce_interval_ms: u64,
    pub next_announce_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStatsSnapshot {
    pub sender_id: String,
    pub connected: bool,
    pub side_ids: Vec<usize>,
    pub side_names: Vec<String>,
    pub last_seen_ms: Option<u64>,
    pub age_ms: Option<u64>,
    pub reachable_endpoints: Vec<DataEndpoint>,
    pub reachable_timesync_sources: Vec<String>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub const LINK_CAPABILITY_HEADER_TEMPLATES: u32 = 0x0000_0001;
pub const LINK_CAPABILITY_CHUNKING: u32 = 0x0000_0002;
pub const LINK_CAPABILITY_RELIABILITY: u32 = 0x0000_0004;
pub const LINK_CAPABILITY_CRYPTO: u32 = 0x0000_0008;
pub const LINK_CAPABILITY_END_TO_END_RELIABILITY: u32 = 0x0000_0010;
pub const LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS: u32 = 0x0000_0020;

pub const LINK_PROFILE_CANONICAL: u8 = 0;
pub const LINK_PROFILE_TEMPLATE: u8 = 1;
pub const LINK_PROFILE_IPV6_LIKE: u8 = 2;
pub const LINK_PROFILE_IPV4_LIKE: u8 = 3;

pub const ADDRESS_MODE_DYNAMIC: u8 = 0;
pub const ADDRESS_MODE_REQUESTED: u8 = 1;
pub const ADDRESS_MODE_STATIC: u8 = 2;
pub const ADDRESS_STATE_REQUEST: u8 = 0;
pub const ADDRESS_STATE_APPROVED: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkCapabilities {
    pub version: u8,
    pub flags: u32,
    pub profile: u8,
    pub max_frame_bytes: u32,
    pub compact_header_target_bytes: u32,
    pub max_side_transport_templates: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAdvertisement {
    pub hostname: String,
    pub address: u32,
    pub requested_address: u32,
    pub mode: u8,
    pub state: u8,
    pub birth_ms: u64,
    pub owner_hash: u64,
    pub reachable_endpoints: Vec<DataEndpoint>,
    /// Network-variable data types available through this sender and the
    /// routers behind it. This lets routing distinguish variables that share
    /// a broad schema endpoint without falling back to link fanout.
    pub reachable_network_variables: Vec<DataType>,
    pub reachable_timesync_sources: Vec<String>,
    pub link_capabilities: LinkCapabilities,
}

#[inline]
pub const fn is_router_control_endpoint(ep: DataEndpoint) -> bool {
    matches!(
        ep,
        DataEndpoint::TelemetryError | DataEndpoint::TimeSync | DataEndpoint::Discovery
    )
}

/// Returns `true` when the endpoint is reserved for discovery control traffic.
#[inline]
pub const fn is_discovery_endpoint(ep: DataEndpoint) -> bool {
    matches!(ep, DataEndpoint::Discovery)
}

/// Returns `true` when the data type is a discovery control packet type.
#[inline]
pub const fn is_discovery_type(ty: DataType) -> bool {
    matches!(
        ty,
        DataType::DiscoveryAnnounce
            | DataType::DiscoveryTimeSyncSources
            | DataType::DiscoveryTopology
            | DataType::DiscoverySchema
            | DataType::DiscoveryTopologyRequest
            | DataType::DiscoverySchemaRequest
            | DataType::ManagedVariableRequest
            | DataType::ManagedVariableValue
            | DataType::DiscoveryLeave
            | DataType::DiscoveryLinkCapabilities
            | DataType::DiscoveryAddress
    )
}

#[inline]
pub const fn is_discovery_request_type(ty: DataType) -> bool {
    matches!(
        ty,
        DataType::DiscoveryTopologyRequest
            | DataType::DiscoverySchemaRequest
            | DataType::ManagedVariableRequest
            | DataType::DiscoveryLeave
            | DataType::DiscoveryAddress
    )
}

fn sort_dedup_strings(items: &mut Vec<String>) {
    items.sort_unstable();
    items.dedup();
}

/// Normalizes a topology-board list in place so it can be compared, exported, or encoded.
pub fn normalize_topology_boards(boards: &mut Vec<TopologyBoardNode>) {
    for board in boards.iter_mut() {
        board
            .reachable_endpoints
            .retain(|ep| !is_router_control_endpoint(*ep));
        crate::small_sort::sort(&mut board.reachable_endpoints);
        board.reachable_endpoints.dedup();
        sort_dedup_strings(&mut board.reachable_timesync_sources);
        board.connections.retain(|peer| peer != &board.sender_id);
        sort_dedup_strings(&mut board.connections);
    }
    boards.sort_unstable_by(|a, b| a.sender_id.cmp(&b.sender_id));
    boards.dedup_by(|a, b| a.sender_id == b.sender_id);
}

pub fn topology_links_from_boards(boards: &[TopologyBoardNode]) -> Vec<TopologyLink> {
    let mut links = Vec::new();
    for board in boards {
        for peer in &board.connections {
            if peer == &board.sender_id {
                continue;
            }
            let (source, target) = if board.sender_id <= *peer {
                (board.sender_id.clone(), peer.clone())
            } else {
                (peer.clone(), board.sender_id.clone())
            };
            links.push(TopologyLink { source, target });
        }
    }
    links.sort_unstable_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
    links.dedup_by(|a, b| a.source == b.source && a.target == b.target);
    links
}

/// Merges board topology views keyed by sender ID.
pub fn merge_topology_boards(dst: &mut Vec<TopologyBoardNode>, src: &[TopologyBoardNode]) {
    // Reuse retained nodes. Building a BTreeMap from cloned nodes briefly
    // duplicated the complete topology (plus a second copy of each key),
    // exhausting constrained bridges during incremental discovery updates.
    // Preserve the old map's last-wins behavior for duplicate destination IDs.
    let mut index = 0;
    while index < dst.len() {
        if dst[index + 1..]
            .iter()
            .any(|node| node.sender_id == dst[index].sender_id)
        {
            dst.remove(index);
        } else {
            index += 1;
        }
    }
    for board in src {
        if let Some(entry) = dst
            .iter_mut()
            .find(|node| node.sender_id == board.sender_id)
        {
            for endpoint in &board.reachable_endpoints {
                if !entry.reachable_endpoints.contains(endpoint) {
                    entry.reachable_endpoints.push(*endpoint);
                }
            }
            for source in &board.reachable_timesync_sources {
                if !entry.reachable_timesync_sources.contains(source) {
                    entry.reachable_timesync_sources.push(source.clone());
                }
            }
            for connection in &board.connections {
                if !entry.connections.contains(connection) {
                    entry.connections.push(connection.clone());
                }
            }
        } else {
            dst.push(board.clone());
        }
    }
    normalize_topology_boards(dst);
}

/// Summarizes a board topology list into aggregated endpoint and time-source reachability.
pub fn summarize_topology_boards(boards: &[TopologyBoardNode]) -> (Vec<DataEndpoint>, Vec<String>) {
    let mut reachable_endpoints = Vec::new();
    let mut reachable_timesync_sources = Vec::new();
    for board in boards {
        for endpoint in &board.reachable_endpoints {
            if !is_router_control_endpoint(*endpoint) && !reachable_endpoints.contains(endpoint) {
                reachable_endpoints.push(*endpoint);
            }
        }
        for source in &board.reachable_timesync_sources {
            if !reachable_timesync_sources.contains(source) {
                reachable_timesync_sources.push(source.clone());
            }
        }
    }
    crate::small_sort::sort(&mut reachable_endpoints);
    reachable_endpoints.dedup();
    reachable_endpoints.retain(|ep| !is_router_control_endpoint(*ep));
    sort_dedup_strings(&mut reachable_timesync_sources);
    (reachable_endpoints, reachable_timesync_sources)
}

/// Builds a discovery announce packet advertising reachable non-discovery endpoints.
pub fn build_discovery_announce(
    sender: &str,
    timestamp_ms: u64,
    endpoints: &[DataEndpoint],
) -> TelemetryResult<Packet> {
    let payload_words: Vec<u32> = endpoints.iter().copied().map(|ep| ep.as_u32()).collect();
    Packet::new(
        DataType::DiscoveryAnnounce,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        encode_slice_le(payload_words.as_slice()),
    )
}

/// Decodes a discovery announce packet into its advertised endpoints.
pub fn decode_discovery_announce(pkt: &Packet) -> TelemetryResult<Vec<DataEndpoint>> {
    if pkt.data_type() != DataType::DiscoveryAnnounce {
        return Err(TelemetryError::InvalidType);
    }
    decode_discovery_payload(pkt.payload())
}

/// Decodes a discovery announce payload into a sorted, deduplicated endpoint list.
pub fn decode_discovery_payload(payload: &[u8]) -> TelemetryResult<Vec<DataEndpoint>> {
    if !payload.len().is_multiple_of(4) {
        return Err(TelemetryError::Unpack("discovery payload width"));
    }

    let mut endpoints = Vec::with_capacity(payload.len() / 4);
    for chunk in payload.as_chunks::<4>().0 {
        let raw = u32::from_le_bytes(*chunk);
        let ep = DataEndpoint(raw);
        if is_discovery_endpoint(ep) {
            continue;
        }
        endpoints.push(ep);
    }
    crate::small_sort::sort(&mut endpoints);
    endpoints.dedup();
    Ok(endpoints)
}

/// Builds a discovery packet advertising reachable time sync source identifiers.
pub fn build_discovery_timesync_sources<S: AsRef<str>>(
    sender: &str,
    timestamp_ms: u64,
    sources: &[S],
) -> TelemetryResult<Packet> {
    let mut payload = Vec::new();
    let mut deduped: Vec<&str> = sources.iter().map(|s| s.as_ref()).collect();
    crate::small_sort::sort(&mut deduped);
    deduped.dedup();

    payload.extend_from_slice(&(deduped.len() as u32).to_le_bytes());
    for source in deduped {
        let bytes = source.as_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| TelemetryError::Pack("discovery source id too long"))?;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(bytes);
    }

    Packet::new(
        DataType::DiscoveryTimeSyncSources,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

pub fn build_discovery_topology_request(
    sender: &str,
    timestamp_ms: u64,
) -> TelemetryResult<Packet> {
    Packet::new(
        DataType::DiscoveryTopologyRequest,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        Vec::<u8>::new().into(),
    )
}

pub fn build_discovery_schema_request(sender: &str, timestamp_ms: u64) -> TelemetryResult<Packet> {
    Packet::new(
        DataType::DiscoverySchemaRequest,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        Vec::<u8>::new().into(),
    )
}

pub fn build_discovery_leave(sender: &str, timestamp_ms: u64) -> TelemetryResult<Packet> {
    Packet::new(
        DataType::DiscoveryLeave,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        Vec::<u8>::new().into(),
    )
}

pub fn build_discovery_link_capabilities(
    sender: &str,
    timestamp_ms: u64,
    capabilities: LinkCapabilities,
) -> TelemetryResult<Packet> {
    let mut payload = Vec::with_capacity(18);
    payload.push(capabilities.version);
    payload.extend_from_slice(&capabilities.flags.to_le_bytes());
    payload.push(capabilities.profile);
    payload.extend_from_slice(&capabilities.max_frame_bytes.to_le_bytes());
    payload.extend_from_slice(&capabilities.compact_header_target_bytes.to_le_bytes());
    payload.extend_from_slice(&capabilities.max_side_transport_templates.to_le_bytes());
    Packet::new(
        DataType::DiscoveryLinkCapabilities,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

pub fn decode_discovery_link_capabilities(pkt: &Packet) -> TelemetryResult<LinkCapabilities> {
    if pkt.data_type() != DataType::DiscoveryLinkCapabilities {
        return Err(TelemetryError::InvalidType);
    }
    let payload = pkt.payload();
    if payload.len() != 18 {
        return Err(TelemetryError::Unpack("discovery link capabilities width"));
    }
    Ok(LinkCapabilities {
        version: payload[0],
        flags: u32::from_le_bytes(payload[1..5].try_into().expect("4-byte flags")),
        profile: payload[5],
        max_frame_bytes: u32::from_le_bytes(payload[6..10].try_into().expect("4-byte max frame")),
        compact_header_target_bytes: u32::from_le_bytes(
            payload[10..14].try_into().expect("4-byte target"),
        ),
        max_side_transport_templates: u32::from_le_bytes(
            payload[14..18].try_into().expect("4-byte templates"),
        ),
    })
}

pub fn build_discovery_address(
    sender: &str,
    timestamp_ms: u64,
    ad: &AddressAdvertisement,
) -> TelemetryResult<Packet> {
    let mut payload = Vec::new();
    payload.push(2);
    payload.push(ad.mode);
    payload.push(ad.state);
    payload.extend_from_slice(&ad.address.to_le_bytes());
    payload.extend_from_slice(&ad.requested_address.to_le_bytes());
    payload.extend_from_slice(&ad.birth_ms.to_le_bytes());
    payload.extend_from_slice(&ad.owner_hash.to_le_bytes());
    encode_string(&mut payload, &ad.hostname)?;
    let mut endpoints = ad.reachable_endpoints.clone();
    endpoints.retain(|ep| !is_discovery_endpoint(*ep));
    crate::small_sort::sort(&mut endpoints);
    endpoints.dedup();
    let endpoint_count = u32::try_from(endpoints.len())
        .map_err(|_| TelemetryError::Pack("discovery address endpoint count"))?;
    payload.extend_from_slice(&endpoint_count.to_le_bytes());
    for ep in endpoints {
        payload.extend_from_slice(&ep.as_u32().to_le_bytes());
    }
    let mut network_variables = ad.reachable_network_variables.clone();
    crate::small_sort::sort(&mut network_variables);
    network_variables.dedup();
    let network_variable_count = u32::try_from(network_variables.len())
        .map_err(|_| TelemetryError::Pack("discovery address network variable count"))?;
    payload.extend_from_slice(&network_variable_count.to_le_bytes());
    for ty in network_variables {
        payload.extend_from_slice(&ty.as_u32().to_le_bytes());
    }
    let mut sources = ad.reachable_timesync_sources.clone();
    sort_dedup_strings(&mut sources);
    let source_count = u32::try_from(sources.len())
        .map_err(|_| TelemetryError::Pack("discovery address source count"))?;
    payload.extend_from_slice(&source_count.to_le_bytes());
    for source in sources {
        encode_string(&mut payload, &source)?;
    }
    payload.push(ad.link_capabilities.version);
    payload.extend_from_slice(&ad.link_capabilities.flags.to_le_bytes());
    payload.push(ad.link_capabilities.profile);
    payload.extend_from_slice(&ad.link_capabilities.max_frame_bytes.to_le_bytes());
    payload.extend_from_slice(
        &ad.link_capabilities
            .compact_header_target_bytes
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &ad.link_capabilities
            .max_side_transport_templates
            .to_le_bytes(),
    );
    Packet::new(
        DataType::DiscoveryAddress,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

pub fn decode_discovery_address(pkt: &Packet) -> TelemetryResult<AddressAdvertisement> {
    if pkt.data_type() != DataType::DiscoveryAddress {
        return Err(TelemetryError::InvalidType);
    }
    let payload = pkt.payload();
    let mut cursor = 0usize;
    let version = read_u8(payload, &mut cursor, "discovery address version")?;
    if version != 1 && version != 2 {
        return Err(TelemetryError::Unpack("discovery address version"));
    }
    let mode = read_u8(payload, &mut cursor, "discovery address mode")?;
    let state = read_u8(payload, &mut cursor, "discovery address state")?;
    let address = read_u32(payload, &mut cursor, "discovery address current")?;
    let requested_address = read_u32(payload, &mut cursor, "discovery address requested")?;
    if payload.len().saturating_sub(cursor) < 8 {
        return Err(TelemetryError::Unpack("discovery address birth"));
    }
    let birth_ms = u64::from_le_bytes(
        payload[cursor..cursor + 8]
            .try_into()
            .expect("8-byte birth"),
    );
    cursor += 8;
    if payload.len().saturating_sub(cursor) < 8 {
        return Err(TelemetryError::Unpack("discovery address owner"));
    }
    let owner_hash = u64::from_le_bytes(
        payload[cursor..cursor + 8]
            .try_into()
            .expect("8-byte owner"),
    );
    cursor += 8;
    let hostname = decode_string(payload, &mut cursor, "discovery address hostname")?;
    let endpoint_count =
        read_u32(payload, &mut cursor, "discovery address endpoint count")? as usize;
    let mut reachable_endpoints = bounded_wire_vec(
        payload,
        cursor,
        endpoint_count,
        4,
        "discovery address endpoint count",
    )?;
    for _ in 0..endpoint_count {
        let raw = read_u32(payload, &mut cursor, "discovery address endpoint")?;
        let ep = DataEndpoint(raw);
        if !is_discovery_endpoint(ep) {
            reachable_endpoints.push(ep);
        }
    }
    crate::small_sort::sort(&mut reachable_endpoints);
    reachable_endpoints.dedup();
    let mut reachable_network_variables = Vec::new();
    if version >= 2 {
        let count = read_u32(
            payload,
            &mut cursor,
            "discovery address network variable count",
        )? as usize;
        reachable_network_variables = bounded_wire_vec(
            payload,
            cursor,
            count,
            4,
            "discovery address network variable count",
        )?;
        for _ in 0..count {
            let raw = read_u32(payload, &mut cursor, "discovery address network variable")?;
            /* A relay may hear the address advertisement before the matching
             * runtime-schema fragment. Preserve the stable wire id so the
             * route is usable immediately and the later schema merge can add
             * its name/shape without requiring a blank-slate rediscovery. */
            let ty = DataType(raw);
            if !is_discovery_type(ty) {
                reachable_network_variables.push(ty);
            }
        }
        crate::small_sort::sort(&mut reachable_network_variables);
        reachable_network_variables.dedup();
    }
    let source_count = read_u32(payload, &mut cursor, "discovery address source count")? as usize;
    let mut reachable_timesync_sources = bounded_wire_vec(
        payload,
        cursor,
        source_count,
        4,
        "discovery address source count",
    )?;
    for _ in 0..source_count {
        let source = decode_string(payload, &mut cursor, "discovery address source")?;
        if !source.is_empty() {
            reachable_timesync_sources.push(source);
        }
    }
    sort_dedup_strings(&mut reachable_timesync_sources);
    let version = read_u8(payload, &mut cursor, "discovery address link version")?;
    let flags = read_u32(payload, &mut cursor, "discovery address link flags")?;
    let profile = read_u8(payload, &mut cursor, "discovery address link profile")?;
    let max_frame_bytes = read_u32(payload, &mut cursor, "discovery address link max frame")?;
    let compact_header_target_bytes = read_u32(
        payload,
        &mut cursor,
        "discovery address link compact target",
    )?;
    let max_side_transport_templates =
        read_u32(payload, &mut cursor, "discovery address link templates")?;
    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery address trailing bytes"));
    }
    if hostname.is_empty() || address == 0 {
        return Err(TelemetryError::Unpack("bad discovery address"));
    }
    Ok(AddressAdvertisement {
        hostname,
        address,
        requested_address,
        mode,
        state,
        birth_ms,
        owner_hash,
        reachable_endpoints,
        reachable_network_variables,
        reachable_timesync_sources,
        link_capabilities: LinkCapabilities {
            version,
            flags,
            profile,
            max_frame_bytes,
            compact_header_target_bytes,
            max_side_transport_templates,
        },
    })
}

pub fn build_managed_variable_request(
    sender: &str,
    timestamp_ms: u64,
    ty: DataType,
) -> TelemetryResult<Packet> {
    Packet::new(
        DataType::ManagedVariableRequest,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        encode_slice_le(&[ty.as_u32()]),
    )
}

pub fn decode_managed_variable_request(pkt: &Packet) -> TelemetryResult<DataType> {
    if pkt.data_type() != DataType::ManagedVariableRequest {
        return Err(TelemetryError::InvalidType);
    }
    let payload = pkt.payload();
    if payload.len() != 4 {
        return Err(TelemetryError::Unpack("managed variable request width"));
    }
    let raw = u32::from_le_bytes(payload.try_into().expect("4-byte payload"));
    /* Managed-variable requests are routable by their stable wire id. The
     * relay itself need not have received that type's schema yet. */
    Ok(DataType(raw))
}

/// Decodes a discovery time sync source packet into source identifiers.
pub fn decode_discovery_timesync_sources(pkt: &Packet) -> TelemetryResult<Vec<String>> {
    if pkt.data_type() != DataType::DiscoveryTimeSyncSources {
        return Err(TelemetryError::InvalidType);
    }
    decode_discovery_timesync_sources_payload(pkt.payload())
}

/// Decodes a discovery time sync source payload into a sorted, deduplicated source list.
pub fn decode_discovery_timesync_sources_payload(payload: &[u8]) -> TelemetryResult<Vec<String>> {
    if payload.len() < 4 {
        return Err(TelemetryError::Unpack("discovery timesync source count"));
    }

    let count = u32::from_le_bytes(payload[..4].try_into().expect("4-byte count")) as usize;
    let mut cursor = 4usize;
    let mut out = bounded_wire_vec(payload, cursor, count, 4, "discovery timesync source count")?;

    for _ in 0..count {
        if payload.len().saturating_sub(cursor) < 4 {
            return Err(TelemetryError::Unpack("discovery timesync source len"));
        }
        let len = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().expect("4-byte len"))
            as usize;
        cursor += 4;
        if payload.len().saturating_sub(cursor) < len {
            return Err(TelemetryError::Unpack("discovery timesync source bytes"));
        }
        let raw = &payload[cursor..cursor + len];
        cursor += len;
        let source = core::str::from_utf8(raw)
            .map_err(|_| TelemetryError::Unpack("discovery timesync source utf8"))?;
        if !source.is_empty() {
            out.push(source.to_string());
        }
    }

    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery timesync trailing bytes"));
    }

    out.sort_unstable();
    out.dedup();
    Ok(out)
}

type TopologyScratchPeer<'a> = (
    &'a str,
    &'a [DataEndpoint],
    &'a [String],
    &'a [TopologyBoardNode],
);

/// Conservative scratch for the unique topology union, without constructing
/// an owned graph. Include vector growth and the caller's concurrent copies.
pub(crate) fn topology_snapshot_scratch<'a>(
    sender: &str,
    local_endpoints: usize,
    variables: usize,
    graph_copies: usize,
    include_wire: bool,
    peers: impl Iterator<Item = TopologyScratchPeer<'a>> + Clone,
) -> (usize, usize) {
    topology_snapshot_scratch_impl(
        sender,
        local_endpoints,
        variables,
        graph_copies,
        include_wire,
        &|index| peers.clone().nth(index),
    )
}

#[inline(never)]
fn topology_snapshot_scratch_impl<'a>(
    sender: &str,
    local_endpoints: usize,
    variables: usize,
    graph_copies: usize,
    include_wire: bool,
    peer_at: &dyn Fn(usize) -> Option<TopologyScratchPeer<'a>>,
) -> (usize, usize) {
    // One calculation body avoids duplicating nested iterator chains for every
    // caller's routing-table iterator; access remains borrowed and allocation-free.
    let peers = core::iter::from_fn({
        let mut index = 0usize;
        move || {
            let peer = peer_at(index);
            index = index.saturating_add(1);
            peer
        }
    });
    #[derive(Clone, Copy)]
    struct View<'a> {
        name: &'a str,
        endpoints: &'a [DataEndpoint],
        sources: &'a [String],
        connections: &'a [String],
        backlink: bool,
    }
    let node_size = core::mem::size_of::<TopologyBoardNode>();
    let string_size = core::mem::size_of::<String>();
    let mut nodes = 1usize;
    let mut graph = node_size
        .saturating_add(sender.len().saturating_mul(2))
        .saturating_add(local_endpoints.saturating_add(1).saturating_mul(4))
        .saturating_add(string_size);
    let mut wire = 24usize
        .saturating_add(sender.len().saturating_mul(2))
        .saturating_add(local_endpoints.saturating_add(1).saturating_mul(4));
    for (index, (name, _, _, _)) in peers.clone().enumerate() {
        if name != sender && !peers.clone().take(index).any(|(old, _, _, _)| old == name) {
            graph = graph.saturating_add(string_size).saturating_add(name.len());
            wire = wire.saturating_add(4).saturating_add(name.len());
        }
    }
    // Mirror the union used by merge_topology_boards without creating owned
    // scratch. Overlapping peer catalogs retain each node and field only once.
    let views = peers.flat_map(|(name, endpoints, sources, boards)| {
        core::iter::once(View {
            name,
            endpoints,
            sources,
            connections: &[],
            backlink: true,
        })
        .filter(move |_| boards.is_empty())
        .chain(boards.iter().map(move |board| View {
            name: &board.sender_id,
            endpoints: &board.reachable_endpoints,
            sources: &board.reachable_timesync_sources,
            connections: &board.connections,
            backlink: board.sender_id == name,
        }))
    });
    for (index, node) in views.clone().enumerate() {
        let prior = || {
            views
                .clone()
                .take(index)
                .filter(|old| old.name == node.name)
        };
        if node.name != sender && prior().next().is_none() {
            nodes = nodes.saturating_add(1);
            graph = graph
                .saturating_add(node_size)
                .saturating_add(node.name.len());
            wire = wire.saturating_add(20).saturating_add(node.name.len());
        }
        for endpoint in node.endpoints {
            if !prior().any(|old| old.endpoints.contains(endpoint)) {
                graph = graph.saturating_add(4);
                wire = wire.saturating_add(4);
            }
        }
        for source in node.sources {
            if !prior().any(|old| old.sources.contains(source)) {
                graph = graph
                    .saturating_add(string_size)
                    .saturating_add(source.len());
                wire = wire.saturating_add(4).saturating_add(source.len());
            }
        }
        for connection in node.connections {
            if connection != node.name
                && !prior().any(|old| {
                    old.connections.contains(connection) || (old.backlink && connection == sender)
                })
            {
                graph = graph
                    .saturating_add(string_size)
                    .saturating_add(connection.len());
                wire = wire.saturating_add(4).saturating_add(connection.len());
            }
        }
        if node.backlink
            && node.name != sender
            && !node.connections.iter().any(|value| value == sender)
            && !prior()
                .any(|old| old.backlink || old.connections.iter().any(|value| value == sender))
        {
            graph = graph
                .saturating_add(string_size)
                .saturating_add(sender.len());
            wire = wire.saturating_add(4).saturating_add(sender.len());
        }
    }
    let grow = |bytes: usize| bytes.checked_next_power_of_two().unwrap_or(usize::MAX);
    let largest = 1024usize
        .max(grow(nodes).saturating_mul(node_size))
        .max(if include_wire { grow(wire) } else { 0 });
    // Election and per-side serialization run in separate phases. Account for
    // the live graph copies in this phase, plus geometric vector growth;
    // packet headers, statistics and queue bookkeeping have separate headroom.
    let additional = 2048usize
        .saturating_add(graph.saturating_mul(graph_copies))
        .saturating_add(variables.saturating_mul(32));
    (additional, largest)
}

// Advertisers already normalize their graphs. Borrow those buffers instead of
// duplicating every node/string just to serialize them again. Public unsorted
// inputs retain the original normalization behavior.
#[inline(never)]
fn topology_payload(
    boards: &[TopologyBoardNode],
    removed: Option<&[String]>,
) -> TelemetryResult<Vec<u8>> {
    let canonical = boards
        .windows(2)
        .all(|pair| pair[0].sender_id < pair[1].sender_id)
        && boards.iter().all(|board| {
            board
                .reachable_endpoints
                .iter()
                .all(|ep| !is_router_control_endpoint(*ep))
                && board
                    .reachable_endpoints
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && board
                    .reachable_timesync_sources
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && board
                    .connections
                    .iter()
                    .all(|peer| peer != &board.sender_id)
                && board.connections.windows(2).all(|pair| pair[0] < pair[1])
        });
    let mut owned = Vec::new();
    let normalized = if canonical {
        boards
    } else {
        owned.extend_from_slice(boards);
        normalize_topology_boards(&mut owned);
        &owned
    };
    let board_count = normalized.len();
    let mut length = 4usize;
    let mut add = |bytes: usize| {
        length = length.saturating_add(bytes);
    };
    for board in normalized {
        add(16);
        add(board.sender_id.len());
        add(board.reachable_endpoints.len().saturating_mul(4));
        for value in board
            .reachable_timesync_sources
            .iter()
            .chain(&board.connections)
        {
            add(4);
            add(value.len());
        }
    }
    if let Some(removed) = removed {
        add(8);
        for value in removed {
            add(4);
            add(value.len());
        }
    }
    let mut payload = Vec::new();
    if canonical {
        // Saturation becomes a fallible capacity error, never wrapped growth.
        payload
            .try_reserve_exact(length)
            .map_err(|_| TelemetryError::Io("memory pressure"))?;
    } else {
        // Preserve the legacy fallback peak: consume normalized owned nodes
        // as the payload grows instead of retaining another full graph.
        owned.reverse();
    }
    if removed.is_some() {
        payload.extend_from_slice(&DISCOVERY_TOPOLOGY_DELTA_MARKER.to_le_bytes());
    }
    payload.extend_from_slice(&(board_count as u32).to_le_bytes());
    for original in boards.iter().take(board_count) {
        let owned_board = owned.pop();
        let board = owned_board.as_ref().unwrap_or(original);
        encode_string(&mut payload, &board.sender_id)?;

        payload.extend_from_slice(&(board.reachable_endpoints.len() as u32).to_le_bytes());
        for ep in &board.reachable_endpoints {
            payload.extend_from_slice(&ep.as_u32().to_le_bytes());
        }

        payload.extend_from_slice(&(board.reachable_timesync_sources.len() as u32).to_le_bytes());
        for source in &board.reachable_timesync_sources {
            encode_string(&mut payload, source)?;
        }

        payload.extend_from_slice(&(board.connections.len() as u32).to_le_bytes());
        for peer in &board.connections {
            encode_string(&mut payload, peer)?;
        }
    }

    if let Some(removed) = removed {
        payload.extend_from_slice(&(removed.len() as u32).to_le_bytes());
        for sender_id in removed {
            encode_string(&mut payload, sender_id)?;
        }
    }
    debug_assert_eq!(payload.len(), length);
    Ok(payload)
}

/// Builds a discovery packet advertising the sender's current board/edge topology graph.
pub fn build_discovery_topology(
    sender: &str,
    timestamp_ms: u64,
    boards: &[TopologyBoardNode],
) -> TelemetryResult<Packet> {
    let payload = topology_payload(boards, None)?;

    Packet::new(
        DataType::DiscoveryTopology,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

/// A topology update decoded from the wire. Full snapshots replace an
/// announcer's graph; incremental updates only upsert/remove named nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryTopologyUpdate {
    pub incremental: bool,
    pub boards: Vec<TopologyBoardNode>,
    pub removed: Vec<String>,
}

/// Applies a decoded, normalized full graph or node delta without copying the
/// retained graph merely to detect changes. Replacement nodes own their buffers.
pub fn apply_topology_update(
    retained: &mut Vec<TopologyBoardNode>,
    update: DiscoveryTopologyUpdate,
) -> bool {
    if !update.incremental {
        if *retained == update.boards {
            return false;
        }
        *retained = update.boards;
        return true;
    }
    let old_len = retained.len();
    retained.retain(|board| {
        !update.removed.iter().any(|id| id == &board.sender_id)
            || update
                .boards
                .iter()
                .any(|replacement| replacement.sender_id == board.sender_id)
    });
    let mut changed = old_len != retained.len();
    for board in update.boards {
        if let Some(old) = retained
            .iter_mut()
            .find(|old| old.sender_id == board.sender_id)
        {
            if *old != board {
                *old = board;
                changed = true;
            }
        } else {
            retained.push(board);
            changed = true;
        }
    }
    if changed {
        normalize_topology_boards(retained);
    }
    changed
}

/// Computes the minimal named-node delta from one normalized graph to another.
pub fn topology_delta(
    previous: &[TopologyBoardNode],
    current: &[TopologyBoardNode],
) -> (Vec<TopologyBoardNode>, Vec<String>) {
    let boards = current
        .iter()
        .filter(|node| previous.iter().find(|old| old.sender_id == node.sender_id) != Some(*node))
        .cloned()
        .collect();
    let removed = previous
        .iter()
        .filter(|old| !current.iter().any(|node| node.sender_id == old.sender_id))
        .map(|old| old.sender_id.clone())
        .collect();
    (boards, removed)
}

/// Builds a compact topology delta containing only changed and removed nodes.
pub fn build_discovery_topology_delta(
    sender: &str,
    timestamp_ms: u64,
    boards: &[TopologyBoardNode],
    removed: &[String],
) -> TelemetryResult<Packet> {
    let payload = topology_payload(boards, Some(removed))?;
    Packet::new(
        DataType::DiscoveryTopology,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

fn decode_string(
    payload: &[u8],
    cursor: &mut usize,
    label: &'static str,
) -> TelemetryResult<String> {
    if payload.len().saturating_sub(*cursor) < 4 {
        return Err(TelemetryError::Unpack(label));
    }
    let len = u32::from_le_bytes(
        payload[*cursor..*cursor + 4]
            .try_into()
            .expect("4-byte len"),
    ) as usize;
    *cursor += 4;
    if payload.len().saturating_sub(*cursor) < len {
        return Err(TelemetryError::Unpack(label));
    }
    let raw = &payload[*cursor..*cursor + len];
    *cursor += len;
    core::str::from_utf8(raw)
        .map(|s| s.to_string())
        .map_err(|_| TelemetryError::Unpack(label))
}

/// Decodes a discovery topology packet into board-node records.
pub fn decode_discovery_topology(pkt: &Packet) -> TelemetryResult<Vec<TopologyBoardNode>> {
    if pkt.data_type() != DataType::DiscoveryTopology {
        return Err(TelemetryError::InvalidType);
    }
    Ok(decode_discovery_topology_update(pkt)?.boards)
}

/// Decodes either a legacy/full topology snapshot or an incremental delta.
pub fn decode_discovery_topology_update(pkt: &Packet) -> TelemetryResult<DiscoveryTopologyUpdate> {
    if pkt.data_type() != DataType::DiscoveryTopology {
        return Err(TelemetryError::InvalidType);
    }
    let payload = pkt.payload();
    if payload.len() < 4 {
        return Err(TelemetryError::Unpack("discovery topology board count"));
    }
    let first = u32::from_le_bytes(payload[..4].try_into().expect("4-byte count"));
    if first != DISCOVERY_TOPOLOGY_DELTA_MARKER {
        return Ok(DiscoveryTopologyUpdate {
            incremental: false,
            boards: decode_discovery_topology_payload(payload)?,
            removed: Vec::new(),
        });
    }
    if payload.len() < 8 {
        return Err(TelemetryError::Unpack("discovery topology delta count"));
    }
    let count = u32::from_le_bytes(payload[4..8].try_into().expect("4-byte count")) as usize;
    let mut cursor = 8usize;
    let mut boards = decode_topology_boards(payload, &mut cursor, count)?;
    if payload.len().saturating_sub(cursor) < 4 {
        return Err(TelemetryError::Unpack("discovery topology removal count"));
    }
    let removed_count = u32::from_le_bytes(
        payload[cursor..cursor + 4]
            .try_into()
            .expect("4-byte count"),
    ) as usize;
    cursor += 4;
    let mut removed = bounded_wire_vec(
        payload,
        cursor,
        removed_count,
        4,
        "discovery topology removal count",
    )?;
    for _ in 0..removed_count {
        removed.push(decode_string(
            payload,
            &mut cursor,
            "discovery topology removed sender id",
        )?);
    }
    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery topology trailing bytes"));
    }
    normalize_topology_boards(&mut boards);
    removed.sort_unstable();
    removed.dedup();
    Ok(DiscoveryTopologyUpdate {
        incremental: true,
        boards,
        removed,
    })
}

/// Decodes a discovery topology payload into normalized board-node records.
pub fn decode_discovery_topology_payload(
    payload: &[u8],
) -> TelemetryResult<Vec<TopologyBoardNode>> {
    if payload.len() < 4 {
        return Err(TelemetryError::Unpack("discovery topology board count"));
    }

    let count = u32::from_le_bytes(payload[..4].try_into().expect("4-byte count")) as usize;
    let mut cursor = 4usize;
    let mut boards = decode_topology_boards(payload, &mut cursor, count)?;

    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery topology trailing bytes"));
    }

    normalize_topology_boards(&mut boards);
    Ok(boards)
}

fn decode_topology_boards(
    payload: &[u8],
    cursor: &mut usize,
    count: usize,
) -> TelemetryResult<Vec<TopologyBoardNode>> {
    /* Each board has at minimum a string length and three collection counts. */
    let mut boards = bounded_wire_vec(
        payload,
        *cursor,
        count,
        16,
        "discovery topology board count",
    )?;

    for _ in 0..count {
        let sender_id = decode_string(payload, cursor, "discovery topology sender id")?;

        if payload.len().saturating_sub(*cursor) < 4 {
            return Err(TelemetryError::Unpack("discovery topology endpoint count"));
        }
        let endpoint_count = u32::from_le_bytes(
            payload[*cursor..*cursor + 4]
                .try_into()
                .expect("4-byte count"),
        ) as usize;
        *cursor += 4;
        let mut reachable_endpoints = bounded_wire_vec(
            payload,
            *cursor,
            endpoint_count,
            4,
            "discovery topology endpoint count",
        )?;
        for _ in 0..endpoint_count {
            if payload.len().saturating_sub(*cursor) < 4 {
                return Err(TelemetryError::Unpack("discovery topology endpoint"));
            }
            let raw =
                u32::from_le_bytes(payload[*cursor..*cursor + 4].try_into().expect("4-byte ep"));
            *cursor += 4;
            let ep = DataEndpoint(raw);
            if !is_discovery_endpoint(ep) {
                reachable_endpoints.push(ep);
            }
        }

        if payload.len().saturating_sub(*cursor) < 4 {
            return Err(TelemetryError::Unpack(
                "discovery topology timesync source count",
            ));
        }
        let source_count = u32::from_le_bytes(
            payload[*cursor..*cursor + 4]
                .try_into()
                .expect("4-byte count"),
        ) as usize;
        *cursor += 4;
        let mut reachable_timesync_sources = bounded_wire_vec(
            payload,
            *cursor,
            source_count,
            4,
            "discovery topology timesync source count",
        )?;
        for _ in 0..source_count {
            let source = decode_string(payload, cursor, "discovery topology timesync source")?;
            if !source.is_empty() {
                reachable_timesync_sources.push(source);
            }
        }

        if payload.len().saturating_sub(*cursor) < 4 {
            return Err(TelemetryError::Unpack(
                "discovery topology connection count",
            ));
        }
        let connection_count = u32::from_le_bytes(
            payload[*cursor..*cursor + 4]
                .try_into()
                .expect("4-byte count"),
        ) as usize;
        *cursor += 4;
        let mut connections = bounded_wire_vec(
            payload,
            *cursor,
            connection_count,
            4,
            "discovery topology connection count",
        )?;
        for _ in 0..connection_count {
            let peer = decode_string(payload, cursor, "discovery topology connection")?;
            if !peer.is_empty() {
                connections.push(peer);
            }
        }

        boards.push(TopologyBoardNode {
            sender_id,
            reachable_endpoints,
            reachable_timesync_sources,
            connections,
        });
    }

    Ok(boards)
}

fn encode_string(payload: &mut Vec<u8>, value: &str) -> TelemetryResult<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| TelemetryError::Pack("discovery schema string too long"))?;
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_u8(payload: &[u8], cursor: &mut usize, label: &'static str) -> TelemetryResult<u8> {
    if payload.len().saturating_sub(*cursor) < 1 {
        return Err(TelemetryError::Unpack(label));
    }
    let out = payload[*cursor];
    *cursor += 1;
    Ok(out)
}

fn read_u32(payload: &[u8], cursor: &mut usize, label: &'static str) -> TelemetryResult<u32> {
    if payload.len().saturating_sub(*cursor) < 4 {
        return Err(TelemetryError::Unpack(label));
    }
    let out = u32::from_le_bytes(
        payload[*cursor..*cursor + 4]
            .try_into()
            .expect("4-byte u32"),
    );
    *cursor += 4;
    Ok(out)
}

#[cfg(any(not(feature = "std"), test))]
fn skip_string(payload: &[u8], cursor: &mut usize, label: &'static str) -> TelemetryResult<()> {
    let len = read_u32(payload, cursor, label)? as usize;
    if payload.len().saturating_sub(*cursor) < len {
        return Err(TelemetryError::Unpack(label));
    }
    *cursor += len;
    Ok(())
}

#[cfg(any(not(feature = "std"), test))]
fn borrowed_schema_string<'a>(
    payload: &'a [u8],
    cursor: &mut usize,
    label: &'static str,
) -> TelemetryResult<&'a str> {
    let len = read_u32(payload, cursor, label)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(TelemetryError::Unpack(label))?;
    let bytes = payload
        .get(*cursor..end)
        .ok_or(TelemetryError::Unpack(label))?;
    *cursor = end;
    core::str::from_utf8(bytes).map_err(|_| TelemetryError::Unpack(label))
}

/// Checks a version-3 schema payload without allocating any owned strings or
/// vectors. Embedded routers use this before the full decoder so repeated
/// snapshots equivalent to compiled/previously learned definitions do not create a
/// large transient heap burst merely to discard every decoded definition.
#[cfg(any(not(feature = "std"), test))]
pub(crate) fn discovery_schema_payload_is_fully_known(payload: &[u8]) -> TelemetryResult<bool> {
    let mut cursor = 0usize;
    if read_u32(payload, &mut cursor, "discovery schema version")? != 3 {
        return Ok(false);
    }

    let endpoint_count =
        read_u32(payload, &mut cursor, "discovery schema endpoint count")? as usize;
    if endpoint_count > payload.len().saturating_sub(cursor) / 13 {
        return Err(TelemetryError::Unpack("discovery schema endpoint count"));
    }
    let mut all_known = true;
    for _ in 0..endpoint_count {
        let id = DataEndpoint(read_u32(
            payload,
            &mut cursor,
            "discovery schema endpoint id",
        )?);
        let known = crate::config::endpoint_exists(id);
        let meta = crate::config::get_endpoint_meta(id);
        let link_local_only =
            read_u8(payload, &mut cursor, "discovery schema endpoint flags")? != 0;
        let name = borrowed_schema_string(payload, &mut cursor, "discovery schema endpoint name")?;
        all_known &= known
            && AsRef::<str>::as_ref(&meta.name) == name
            && (!link_local_only || meta.link_local_only);
        skip_string(
            payload,
            &mut cursor,
            "discovery schema endpoint description",
        )?;
    }

    let type_count = read_u32(payload, &mut cursor, "discovery schema type count")? as usize;
    if type_count > payload.len().saturating_sub(cursor) / 19 {
        return Err(TelemetryError::Unpack("discovery schema type count"));
    }
    for _ in 0..type_count {
        let id = DataType(read_u32(payload, &mut cursor, "discovery schema type id")?);
        let meta = crate::config::try_get_message_meta(id);
        let name = borrowed_schema_string(payload, &mut cursor, "discovery schema type name")?;
        skip_string(payload, &mut cursor, "discovery schema type description")?;
        let element_kind = read_u8(payload, &mut cursor, "discovery schema element kind")?;
        if element_kind > 1 {
            return Err(TelemetryError::Unpack("discovery schema element kind"));
        }
        let count = read_u32(payload, &mut cursor, "discovery schema element count")? as usize;
        let data_type = message_data_type_from_code(read_u8(
            payload,
            &mut cursor,
            "discovery schema data type",
        )?)
        .ok_or(TelemetryError::Unpack("discovery schema data type"))?;
        let class =
            message_class_from_code(read_u8(payload, &mut cursor, "discovery schema class")?)
                .ok_or(TelemetryError::Unpack("discovery schema class"))?;
        let reliable =
            reliable_from_code(read_u8(payload, &mut cursor, "discovery schema reliable")?)
                .ok_or(TelemetryError::Unpack("discovery schema reliable"))?;
        let priority = read_u8(payload, &mut cursor, "discovery schema priority")?;
        let encryption = e2e_encryption_policy_from_code(read_u8(
            payload,
            &mut cursor,
            "discovery schema e2e cryptography",
        )?)
        .ok_or(TelemetryError::Unpack("discovery schema e2e cryptography"))?;
        let endpoint_count =
            read_u32(payload, &mut cursor, "discovery schema type endpoint count")? as usize;
        if endpoint_count > payload.len().saturating_sub(cursor) / 4 {
            return Err(TelemetryError::Unpack(
                "discovery schema type endpoint count",
            ));
        }
        let element = if element_kind == 0 {
            MessageElement::Static(count, data_type, class)
        } else {
            MessageElement::Dynamic(data_type, class)
        };
        all_known &= meta.as_ref().is_some_and(|meta| {
            AsRef::<str>::as_ref(&meta.name) == name
                && meta.element == element
                && meta.reliable == reliable
                && meta.priority >= priority
                && meta.e2e_encryption == encryption
        });
        for _ in 0..endpoint_count {
            let ep = DataEndpoint(read_u32(
                payload,
                &mut cursor,
                "discovery schema type endpoint",
            )?);
            all_known &= meta
                .as_ref()
                .is_some_and(|meta| meta.endpoints.contains(&ep));
        }
    }
    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery schema trailing bytes"));
    }
    Ok(all_known)
}

/// Builds a discovery packet containing the complete runtime schema snapshot.
pub fn build_discovery_schema(sender: &str, timestamp_ms: u64) -> TelemetryResult<Packet> {
    #[cfg(feature = "std")]
    return build_discovery_schema_from_owned_snapshot(sender, timestamp_ms, export_schema());
    #[cfg(not(feature = "std"))]
    return Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        crate::config::encode_embedded_schema_payload()?,
    );
}

/// Elects the authoritative discovery/schema master for the current topology view.
///
/// Tie-breaks are deterministic:
/// 1. Fewest unreachable boards.
/// 2. Lowest maximum hop distance to any reachable board.
/// 3. Lowest total hop distance across all reachable boards.
/// 4. Lexicographically smallest sender ID.
pub fn elect_discovery_master(local_sender: &str, boards: &[TopologyBoardNode]) -> String {
    let mut nodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for board in boards {
        nodes.entry(board.sender_id.clone()).or_default();
        for peer in board.connections.iter() {
            nodes
                .entry(peer.clone())
                .or_default()
                .push(board.sender_id.clone());
            nodes
                .entry(board.sender_id.clone())
                .or_default()
                .push(peer.clone());
        }
    }
    nodes.entry(local_sender.to_string()).or_default();
    for peers in nodes.values_mut() {
        peers.sort_unstable();
        peers.dedup();
    }

    let mut best_sender = local_sender.to_string();
    let mut best_unreachable = usize::MAX;
    let mut best_max_hops = usize::MAX;
    let mut best_total_hops = usize::MAX;

    for sender in nodes.keys() {
        let mut frontier = vec![sender.clone()];
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        seen.insert(sender.clone(), 0);
        let mut idx = 0;
        while idx < frontier.len() {
            let cur = frontier[idx].clone();
            idx += 1;
            let cur_dist = seen[&cur];
            if let Some(peers) = nodes.get(&cur) {
                for peer in peers {
                    if !seen.contains_key(peer) {
                        seen.insert(peer.clone(), cur_dist + 1);
                        frontier.push(peer.clone());
                    }
                }
            }
        }

        let unreachable = nodes.len().saturating_sub(seen.len());
        let max_hops = seen.values().copied().max().unwrap_or(0);
        let total_hops = seen.values().copied().sum();
        let better = unreachable < best_unreachable
            || (unreachable == best_unreachable && max_hops < best_max_hops)
            || (unreachable == best_unreachable
                && max_hops == best_max_hops
                && total_hops < best_total_hops)
            || (unreachable == best_unreachable
                && max_hops == best_max_hops
                && total_hops == best_total_hops
                && sender < &best_sender);
        if better {
            best_sender = sender.clone();
            best_unreachable = unreachable;
            best_max_hops = max_hops;
            best_total_hops = total_hops;
        }
    }

    best_sender
}

/// Builds a discovery schema packet from an explicit snapshot.
pub fn build_discovery_schema_from_snapshot(
    sender: &str,
    timestamp_ms: u64,
    schema: RuntimeSchemaSnapshot,
) -> TelemetryResult<Packet> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3u32.to_le_bytes());

    payload.extend_from_slice(&(schema.endpoints.len() as u32).to_le_bytes());
    for ep in schema.endpoints {
        payload.extend_from_slice(&ep.id.as_u32().to_le_bytes());
        payload.push(ep.link_local_only as u8);
        encode_string(&mut payload, ep.name)?;
        #[cfg(feature = "std")]
        encode_string(&mut payload, ep.description)?;
        #[cfg(not(feature = "std"))]
        encode_string(&mut payload, "")?;
    }

    payload.extend_from_slice(&(schema.types.len() as u32).to_le_bytes());
    for ty in schema.types {
        payload.extend_from_slice(&ty.id.as_u32().to_le_bytes());
        encode_string(&mut payload, ty.name)?;
        #[cfg(feature = "std")]
        encode_string(&mut payload, ty.description)?;
        #[cfg(not(feature = "std"))]
        encode_string(&mut payload, "")?;
        match ty.element {
            MessageElement::Static(count, data_type, class) => {
                payload.push(0);
                payload.extend_from_slice(&(count as u32).to_le_bytes());
                payload.push(message_data_type_code(data_type));
                payload.push(message_class_code(class));
            }
            MessageElement::Dynamic(data_type, class) => {
                payload.push(1);
                payload.extend_from_slice(&0u32.to_le_bytes());
                payload.push(message_data_type_code(data_type));
                payload.push(message_class_code(class));
            }
        }
        payload.push(reliable_code(ty.reliable));
        payload.push(ty.priority);
        payload.push(e2e_encryption_policy_code(ty.e2e_encryption));
        payload.extend_from_slice(&(ty.endpoints.len() as u32).to_le_bytes());
        for ep in ty.endpoints {
            payload.extend_from_slice(&ep.as_u32().to_le_bytes());
        }
    }

    Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

/// Builds a discovery schema packet from an owned snapshot.
pub fn build_discovery_schema_from_owned_snapshot(
    sender: &str,
    timestamp_ms: u64,
    schema: OwnedRuntimeSchemaSnapshot,
) -> TelemetryResult<Packet> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3u32.to_le_bytes());

    payload.extend_from_slice(&(schema.endpoints.len() as u32).to_le_bytes());
    for ep in schema.endpoints {
        payload.extend_from_slice(&ep.id.as_u32().to_le_bytes());
        payload.push(ep.link_local_only as u8);
        encode_string(&mut payload, &ep.name)?;
        // Descriptions are documentation, not routing metadata. Every node
        // keeps its local copy, while omitting them here prevents schema sync
        // from consuming constrained radio/CAN queue capacity.
        encode_string(&mut payload, "")?;
    }

    payload.extend_from_slice(&(schema.types.len() as u32).to_le_bytes());
    for ty in schema.types {
        payload.extend_from_slice(&ty.id.as_u32().to_le_bytes());
        encode_string(&mut payload, &ty.name)?;
        encode_string(&mut payload, "")?;
        match ty.element {
            MessageElement::Static(count, data_type, class) => {
                payload.push(0);
                payload.extend_from_slice(&(count as u32).to_le_bytes());
                payload.push(message_data_type_code(data_type));
                payload.push(message_class_code(class));
            }
            MessageElement::Dynamic(data_type, class) => {
                payload.push(1);
                payload.extend_from_slice(&0u32.to_le_bytes());
                payload.push(message_data_type_code(data_type));
                payload.push(message_class_code(class));
            }
        }
        payload.push(reliable_code(ty.reliable));
        payload.push(ty.priority);
        payload.push(e2e_encryption_policy_code(ty.e2e_encryption));
        payload.extend_from_slice(&(ty.endpoints.len() as u32).to_le_bytes());
        for ep in ty.endpoints {
            payload.extend_from_slice(&ep.as_u32().to_le_bytes());
        }
    }

    Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        sender,
        timestamp_ms,
        payload.into(),
    )
}

/// Decodes a discovery schema packet.
pub fn decode_discovery_schema(pkt: &Packet) -> TelemetryResult<OwnedRuntimeSchemaSnapshot> {
    if pkt.data_type() != DataType::DiscoverySchema {
        return Err(TelemetryError::InvalidType);
    }
    decode_discovery_schema_payload(pkt.payload())
}

/// Decodes a discovery schema payload into runtime definitions.
pub fn decode_discovery_schema_payload(
    payload: &[u8],
) -> TelemetryResult<OwnedRuntimeSchemaSnapshot> {
    let mut cursor = 0usize;
    let version = read_u32(payload, &mut cursor, "discovery schema version")?;
    #[cfg(feature = "std")]
    if version != 1 && version != 2 && version != 3 {
        return Err(TelemetryError::Unpack("discovery schema version"));
    }
    #[cfg(not(feature = "std"))]
    if version != 3 {
        return Err(TelemetryError::Unpack("discovery schema version"));
    }

    let endpoint_count =
        read_u32(payload, &mut cursor, "discovery schema endpoint count")? as usize;
    let mut endpoints = bounded_wire_vec(
        payload,
        cursor,
        endpoint_count,
        13,
        "discovery schema endpoint count",
    )?;
    for _ in 0..endpoint_count {
        let id = DataEndpoint(read_u32(
            payload,
            &mut cursor,
            "discovery schema endpoint id",
        )?);
        let link_local_only =
            read_u8(payload, &mut cursor, "discovery schema endpoint flags")? != 0;
        let name = decode_string(payload, &mut cursor, "discovery schema endpoint name")?;
        #[cfg(feature = "std")]
        let description = if version >= 2 {
            decode_string(
                payload,
                &mut cursor,
                "discovery schema endpoint description",
            )?
        } else {
            String::new()
        };
        #[cfg(not(feature = "std"))]
        let description = {
            skip_string(
                payload,
                &mut cursor,
                "discovery schema endpoint description",
            )?;
            String::new()
        };
        endpoints.push(OwnedEndpointDefinition {
            id,
            name,
            description,
            link_local_only,
        });
    }

    let type_count = read_u32(payload, &mut cursor, "discovery schema type count")? as usize;
    let mut types = bounded_wire_vec(
        payload,
        cursor,
        type_count,
        19,
        "discovery schema type count",
    )?;
    for _ in 0..type_count {
        let id = DataType(read_u32(payload, &mut cursor, "discovery schema type id")?);
        let name = decode_string(payload, &mut cursor, "discovery schema type name")?;
        #[cfg(feature = "std")]
        let description = if version >= 2 {
            decode_string(payload, &mut cursor, "discovery schema type description")?
        } else {
            String::new()
        };
        #[cfg(not(feature = "std"))]
        let description = {
            skip_string(payload, &mut cursor, "discovery schema type description")?;
            String::new()
        };
        let element_kind = read_u8(payload, &mut cursor, "discovery schema element kind")?;
        let count = read_u32(payload, &mut cursor, "discovery schema element count")? as usize;
        let data_type = message_data_type_from_code(read_u8(
            payload,
            &mut cursor,
            "discovery schema data type",
        )?)
        .ok_or(TelemetryError::Unpack("discovery schema data type"))?;
        let class =
            message_class_from_code(read_u8(payload, &mut cursor, "discovery schema class")?)
                .ok_or(TelemetryError::Unpack("discovery schema class"))?;
        let element = match element_kind {
            0 => MessageElement::Static(count, data_type, class),
            1 => MessageElement::Dynamic(data_type, class),
            _ => return Err(TelemetryError::Unpack("discovery schema element kind")),
        };
        let reliable =
            reliable_from_code(read_u8(payload, &mut cursor, "discovery schema reliable")?)
                .ok_or(TelemetryError::Unpack("discovery schema reliable"))?;
        let priority = read_u8(payload, &mut cursor, "discovery schema priority")?;
        #[cfg(feature = "std")]
        let e2e_encryption = if version >= 3 {
            e2e_encryption_policy_from_code(read_u8(
                payload,
                &mut cursor,
                "discovery schema e2e cryptography",
            )?)
            .ok_or(TelemetryError::Unpack("discovery schema e2e cryptography"))?
        } else {
            E2eEncryptionPolicy::PreferOff
        };
        #[cfg(not(feature = "std"))]
        let e2e_encryption = e2e_encryption_policy_from_code(read_u8(
            payload,
            &mut cursor,
            "discovery schema e2e cryptography",
        )?)
        .ok_or(TelemetryError::Unpack("discovery schema e2e cryptography"))?;
        let endpoint_count =
            read_u32(payload, &mut cursor, "discovery schema type endpoint count")? as usize;
        let mut type_endpoints = bounded_wire_vec(
            payload,
            cursor,
            endpoint_count,
            4,
            "discovery schema type endpoint count",
        )?;
        for _ in 0..endpoint_count {
            type_endpoints.push(DataEndpoint(read_u32(
                payload,
                &mut cursor,
                "discovery schema type endpoint",
            )?));
        }
        types.push(OwnedDataTypeDefinition {
            id,
            name,
            description,
            element,
            endpoints: type_endpoints,
            reliable,
            priority,
            e2e_encryption,
        });
    }

    if cursor != payload.len() {
        return Err(TelemetryError::Unpack("discovery schema trailing bytes"));
    }
    Ok(OwnedRuntimeSchemaSnapshot { endpoints, types })
}

/// An unchanged catalog can reuse a queued/in-progress transfer. Timestamp and
/// nonce intentionally differ on repeated announcements; routing contracts do
/// not. Changed metadata, sender or destination must still replace the snapshot.
pub(crate) fn same_schema_snapshot(existing: &Packet, incoming: &Packet) -> bool {
    existing.data_type() == DataType::DiscoverySchema
        && incoming.data_type() == DataType::DiscoverySchema
        && existing.sender() == incoming.sender()
        && existing.endpoints() == incoming.endpoints()
        && existing.wire_target_senders() == incoming.wire_target_senders()
        && existing.payload() == incoming.payload()
}

#[cfg(test)]
mod bounded_decode_tests {
    use super::{
        ADDRESS_MODE_STATIC, ADDRESS_STATE_APPROVED, AddressAdvertisement, LinkCapabilities,
        build_discovery_address, build_managed_variable_request, decode_discovery_address,
        decode_discovery_schema_payload, decode_discovery_timesync_sources_payload,
        decode_discovery_topology_payload, decode_managed_variable_request,
        discovery_schema_payload_is_fully_known,
    };
    use crate::{DataEndpoint, DataType};

    #[test]
    fn equivalent_schema_definitions_are_detected_without_owned_decode() {
        fn one_endpoint(id: DataEndpoint) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&3u32.to_le_bytes());
            payload.extend_from_slice(&1u32.to_le_bytes());
            payload.extend_from_slice(&id.0.to_le_bytes());
            payload.push(0);
            let meta = crate::config::get_endpoint_meta(id);
            payload.extend_from_slice(&(meta.name.len() as u32).to_le_bytes());
            payload.extend_from_slice(meta.name.as_bytes());
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload
        }

        assert!(
            discovery_schema_payload_is_fully_known(&one_endpoint(DataEndpoint::Discovery,))
                .unwrap()
        );
        assert!(
            !discovery_schema_payload_is_fully_known(&one_endpoint(DataEndpoint(u32::MAX - 7),))
                .unwrap()
        );
    }

    #[test]
    fn reused_ids_with_changed_schema_are_not_treated_as_known() {
        let schema = crate::config::export_schema();
        let original =
            super::build_discovery_schema_from_owned_snapshot("test", 1, schema.clone()).unwrap();
        assert!(discovery_schema_payload_is_fully_known(original.payload()).unwrap());
        for change in 0..4 {
            let mut updated = schema.clone();
            match change {
                0 => updated.endpoints[0].name.push_str("_CHANGED"),
                1 => updated.endpoints[0].link_local_only = !updated.endpoints[0].link_local_only,
                2 => updated.types[0].name.push_str("_CHANGED"),
                _ => updated.types[0].endpoints.push(DataEndpoint(u32::MAX - 7)),
            }
            let packet =
                super::build_discovery_schema_from_owned_snapshot("test", 2, updated).unwrap();
            assert!(
                !discovery_schema_payload_is_fully_known(packet.payload()).unwrap(),
                "change {change} was silently ignored"
            );
        }
    }

    #[test]
    fn unknown_managed_variable_ids_survive_discovery_before_schema_merge() {
        let unknown = DataType(4090);
        let unknown_endpoint = DataEndpoint(4090);
        let advertisement = AddressAdvertisement {
            hostname: "flight".into(),
            address: 42,
            requested_address: 42,
            mode: ADDRESS_MODE_STATIC,
            state: ADDRESS_STATE_APPROVED,
            birth_ms: 10,
            owner_hash: 20,
            reachable_endpoints: vec![unknown_endpoint],
            reachable_network_variables: vec![unknown],
            reachable_timesync_sources: Vec::new(),
            link_capabilities: LinkCapabilities {
                version: 1,
                flags: 0,
                profile: 0,
                max_frame_bytes: 128,
                compact_header_target_bytes: 40,
                max_side_transport_templates: 4,
            },
        };
        let packet = build_discovery_address("FC", 1, &advertisement).unwrap();
        let decoded = decode_discovery_address(&packet).unwrap();
        assert_eq!(decoded.reachable_endpoints, vec![unknown_endpoint]);
        assert_eq!(decoded.reachable_network_variables, vec![unknown]);

        let request = build_managed_variable_request("GS", 2, unknown).unwrap();
        assert_eq!(decode_managed_variable_request(&request).unwrap(), unknown);
    }

    #[test]
    fn corrupt_timesync_count_is_rejected_without_reserving() {
        assert!(decode_discovery_timesync_sources_payload(&u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn corrupt_topology_count_is_rejected_without_reserving() {
        assert!(decode_discovery_topology_payload(&u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn corrupt_schema_counts_are_rejected_without_reserving() {
        let mut endpoints = 3u32.to_le_bytes().to_vec();
        endpoints.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_discovery_schema_payload(&endpoints).is_err());

        let mut types = 3u32.to_le_bytes().to_vec();
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_discovery_schema_payload(&types).is_err());
    }
}
