//! Runtime telemetry configuration and schema registry.
//!
//! v4 removes compile-time schema generation. `DataType` and `DataEndpoint`
//! are stable runtime IDs, and metadata is looked up through the process-local
//! registry. Applications may seed the registry from JSON at startup, or add
//! endpoints/types as the network announces them.

use crate::{
    E2eEncryptionPolicy, EndpointMeta, MessageClass, MessageDataType, MessageElement, MessageMeta,
    ReliableMode, TelemetryError, TelemetryResult, parse_f64, parse_strings, parse_usize,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

#[cfg(feature = "std")]
use std::sync::OnceLock;
#[cfg(feature = "std")]
use std::sync::RwLock;

// -----------------------------------------------------------------------------
// Device-/build-time constants
// -----------------------------------------------------------------------------

pub const DEVICE_IDENTIFIER: &str = match option_env!("DEVICE_IDENTIFIER") {
    Some(val) => parse_strings(val),
    None => "TEST_PLATFORM",
};

#[cfg(feature = "std")]
static RUNTIME_DEVICE_IDENTIFIER: OnceLock<RwLock<String>> = OnceLock::new();

pub fn runtime_device_identifier() -> String {
    #[cfg(feature = "std")]
    {
        RUNTIME_DEVICE_IDENTIFIER
            .get_or_init(|| RwLock::new(DEVICE_IDENTIFIER.to_string()))
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| DEVICE_IDENTIFIER.to_string())
    }
    #[cfg(not(feature = "std"))]
    {
        DEVICE_IDENTIFIER.to_string()
    }
}

pub fn set_runtime_device_identifier(value: &str) -> TelemetryResult<()> {
    if value.is_empty() {
        return Err(TelemetryError::BadArg);
    }
    #[cfg(feature = "std")]
    {
        let lock =
            RUNTIME_DEVICE_IDENTIFIER.get_or_init(|| RwLock::new(DEVICE_IDENTIFIER.to_string()));
        let mut guard = lock
            .write()
            .map_err(|_| TelemetryError::Io("device id lock"))?;
        *guard = value.to_string();
        Ok(())
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = value;
        Err(TelemetryError::BadArg)
    }
}

pub const MAX_RECENT_RX_IDS: usize = match option_env!("MAX_RECENT_RX_IDS") {
    Some(val) => parse_usize(val),
    None => 128,
};

pub const STARTING_QUEUE_SIZE: usize = match option_env!("STARTING_QUEUE_SIZE") {
    Some(val) => parse_usize(val),
    None => 128,
};

pub const MAX_QUEUE_BUDGET: usize = match option_env!("MAX_QUEUE_BUDGET") {
    Some(val) => parse_usize(val),
    None => match option_env!("MAX_QUEUE_SIZE") {
        Some(val) => parse_usize(val),
        None => 1024 * 100,
    },
};

pub const RECENT_RX_QUEUE_BYTES: usize = {
    let requested = MAX_RECENT_RX_IDS.saturating_mul(size_of::<u64>());
    if requested < MAX_QUEUE_BUDGET {
        requested
    } else {
        MAX_QUEUE_BUDGET
    }
};

pub const QUEUE_GROW_STEP: f64 = match option_env!("QUEUE_GROW_STEP") {
    Some(val) => parse_f64(val),
    None => 3.2,
};

pub const PAYLOAD_COMPRESS_THRESHOLD: usize = match option_env!("PAYLOAD_COMPRESS_THRESHOLD") {
    Some(val) => parse_usize(val),
    None => 128,
};

pub const STATIC_STRING_LENGTH: usize = match option_env!("STATIC_STRING_LENGTH") {
    Some(val) => parse_usize(val),
    None => 1024,
};

pub const STATIC_HEX_LENGTH: usize = match option_env!("STATIC_HEX_LENGTH") {
    Some(val) => parse_usize(val),
    None => 1024,
};

pub const STRING_PRECISION: usize = match option_env!("STRING_PRECISION") {
    Some(val) => parse_usize(val),
    None => 8,
};

sedsnet_macros::define_stack_payload!(env = "MAX_STACK_PAYLOAD", default = 64);

pub const MAX_HANDLER_RETRIES: usize = match option_env!("MAX_HANDLER_RETRIES") {
    Some(val) => parse_usize(val),
    None => 3,
};

pub const RELIABLE_RETRANSMIT_MS: u64 = match option_env!("RELIABLE_RETRANSMIT_MS") {
    Some(val) => parse_usize(val) as u64,
    None => 200,
};

pub const RELIABLE_MAX_RETRIES: u32 = match option_env!("RELIABLE_MAX_RETRIES") {
    Some(val) => parse_usize(val) as u32,
    None => 8,
};

pub const RELIABLE_MAX_PENDING: usize = match option_env!("RELIABLE_MAX_PENDING") {
    Some(val) => parse_usize(val),
    None => 32,
};

pub const RELIABLE_MAX_RETURN_ROUTES: usize = match option_env!("RELIABLE_MAX_RETURN_ROUTES") {
    Some(val) => parse_usize(val),
    None => MAX_RECENT_RX_IDS,
};

pub const RELIABLE_MAX_END_TO_END_PENDING: usize =
    match option_env!("RELIABLE_MAX_END_TO_END_PENDING") {
        Some(val) => parse_usize(val),
        None => RELIABLE_MAX_PENDING,
    };

pub const RELIABLE_MAX_END_TO_END_ACK_CACHE: usize =
    match option_env!("RELIABLE_MAX_END_TO_END_ACK_CACHE") {
        Some(val) => parse_usize(val),
        None => MAX_RECENT_RX_IDS,
    };

static RUNTIME_PAYLOAD_COMPRESS_THRESHOLD: AtomicUsize =
    AtomicUsize::new(PAYLOAD_COMPRESS_THRESHOLD);
static RUNTIME_STATIC_STRING_LENGTH: AtomicUsize = AtomicUsize::new(STATIC_STRING_LENGTH);
static RUNTIME_STATIC_HEX_LENGTH: AtomicUsize = AtomicUsize::new(STATIC_HEX_LENGTH);
static RUNTIME_STRING_PRECISION: AtomicUsize = AtomicUsize::new(STRING_PRECISION);
static RUNTIME_MAX_HANDLER_RETRIES: AtomicUsize = AtomicUsize::new(MAX_HANDLER_RETRIES);
static RUNTIME_RELIABLE_RETRANSMIT_MS: AtomicU32 = AtomicU32::new(RELIABLE_RETRANSMIT_MS as u32);
static RUNTIME_RELIABLE_MAX_RETRIES: AtomicU32 = AtomicU32::new(RELIABLE_MAX_RETRIES);
static RUNTIME_RELIABLE_MAX_PENDING: AtomicUsize = AtomicUsize::new(RELIABLE_MAX_PENDING);
static RUNTIME_RELIABLE_MAX_RETURN_ROUTES: AtomicUsize =
    AtomicUsize::new(RELIABLE_MAX_RETURN_ROUTES);
static RUNTIME_RELIABLE_MAX_END_TO_END_PENDING: AtomicUsize =
    AtomicUsize::new(RELIABLE_MAX_END_TO_END_PENDING);
static RUNTIME_RELIABLE_MAX_END_TO_END_ACK_CACHE: AtomicUsize =
    AtomicUsize::new(RELIABLE_MAX_END_TO_END_ACK_CACHE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTuningConfig {
    pub payload_compress_threshold: usize,
    pub static_string_length: usize,
    pub static_hex_length: usize,
    pub string_precision: usize,
    pub max_handler_retries: usize,
    pub reliable_retransmit_ms: u32,
    pub reliable_max_retries: u32,
    pub reliable_max_pending: usize,
    pub reliable_max_return_routes: usize,
    pub reliable_max_end_to_end_pending: usize,
    pub reliable_max_end_to_end_ack_cache: usize,
}

impl Default for RuntimeTuningConfig {
    fn default() -> Self {
        Self {
            payload_compress_threshold: PAYLOAD_COMPRESS_THRESHOLD,
            static_string_length: STATIC_STRING_LENGTH,
            static_hex_length: STATIC_HEX_LENGTH,
            string_precision: STRING_PRECISION,
            max_handler_retries: MAX_HANDLER_RETRIES,
            reliable_retransmit_ms: RELIABLE_RETRANSMIT_MS as u32,
            reliable_max_retries: RELIABLE_MAX_RETRIES,
            reliable_max_pending: RELIABLE_MAX_PENDING,
            reliable_max_return_routes: RELIABLE_MAX_RETURN_ROUTES,
            reliable_max_end_to_end_pending: RELIABLE_MAX_END_TO_END_PENDING,
            reliable_max_end_to_end_ack_cache: RELIABLE_MAX_END_TO_END_ACK_CACHE,
        }
    }
}

impl RuntimeTuningConfig {
    pub fn validate(self) -> TelemetryResult<()> {
        if self.static_string_length == 0
            || self.static_hex_length == 0
            || self.max_handler_retries == 0
            || self.reliable_retransmit_ms == 0
            || self.reliable_max_retries == 0
            || self.reliable_max_pending == 0
            || self.reliable_max_return_routes == 0
            || self.reliable_max_end_to_end_pending == 0
            || self.reliable_max_end_to_end_ack_cache == 0
        {
            return Err(TelemetryError::BadArg);
        }
        Ok(())
    }
}

pub fn set_runtime_tuning_config(cfg: RuntimeTuningConfig) -> TelemetryResult<()> {
    cfg.validate()?;
    RUNTIME_PAYLOAD_COMPRESS_THRESHOLD.store(cfg.payload_compress_threshold, Ordering::Relaxed);
    RUNTIME_STATIC_STRING_LENGTH.store(cfg.static_string_length, Ordering::Relaxed);
    RUNTIME_STATIC_HEX_LENGTH.store(cfg.static_hex_length, Ordering::Relaxed);
    RUNTIME_STRING_PRECISION.store(cfg.string_precision, Ordering::Relaxed);
    RUNTIME_MAX_HANDLER_RETRIES.store(cfg.max_handler_retries, Ordering::Relaxed);
    RUNTIME_RELIABLE_RETRANSMIT_MS.store(cfg.reliable_retransmit_ms, Ordering::Relaxed);
    RUNTIME_RELIABLE_MAX_RETRIES.store(cfg.reliable_max_retries, Ordering::Relaxed);
    RUNTIME_RELIABLE_MAX_PENDING.store(cfg.reliable_max_pending, Ordering::Relaxed);
    RUNTIME_RELIABLE_MAX_RETURN_ROUTES.store(cfg.reliable_max_return_routes, Ordering::Relaxed);
    RUNTIME_RELIABLE_MAX_END_TO_END_PENDING
        .store(cfg.reliable_max_end_to_end_pending, Ordering::Relaxed);
    RUNTIME_RELIABLE_MAX_END_TO_END_ACK_CACHE
        .store(cfg.reliable_max_end_to_end_ack_cache, Ordering::Relaxed);
    Ok(())
}

pub fn runtime_tuning_config() -> RuntimeTuningConfig {
    RuntimeTuningConfig {
        payload_compress_threshold: runtime_payload_compress_threshold(),
        static_string_length: runtime_static_string_length(),
        static_hex_length: runtime_static_hex_length(),
        string_precision: runtime_string_precision(),
        max_handler_retries: runtime_max_handler_retries(),
        reliable_retransmit_ms: runtime_reliable_retransmit_ms() as u32,
        reliable_max_retries: runtime_reliable_max_retries(),
        reliable_max_pending: runtime_reliable_max_pending(),
        reliable_max_return_routes: runtime_reliable_max_return_routes(),
        reliable_max_end_to_end_pending: runtime_reliable_max_end_to_end_pending(),
        reliable_max_end_to_end_ack_cache: runtime_reliable_max_end_to_end_ack_cache(),
    }
}

#[inline]
pub fn runtime_payload_compress_threshold() -> usize {
    RUNTIME_PAYLOAD_COMPRESS_THRESHOLD.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_static_string_length() -> usize {
    RUNTIME_STATIC_STRING_LENGTH.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_static_hex_length() -> usize {
    RUNTIME_STATIC_HEX_LENGTH.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_string_precision() -> usize {
    RUNTIME_STRING_PRECISION.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_max_handler_retries() -> usize {
    RUNTIME_MAX_HANDLER_RETRIES.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_reliable_retransmit_ms() -> u64 {
    u64::from(RUNTIME_RELIABLE_RETRANSMIT_MS.load(Ordering::Relaxed))
}

#[inline]
pub fn runtime_reliable_max_retries() -> u32 {
    RUNTIME_RELIABLE_MAX_RETRIES.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_reliable_max_pending() -> usize {
    RUNTIME_RELIABLE_MAX_PENDING.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_reliable_max_return_routes() -> usize {
    RUNTIME_RELIABLE_MAX_RETURN_ROUTES.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_reliable_max_end_to_end_pending() -> usize {
    RUNTIME_RELIABLE_MAX_END_TO_END_PENDING.load(Ordering::Relaxed)
}

#[inline]
pub fn runtime_reliable_max_end_to_end_ack_cache() -> usize {
    RUNTIME_RELIABLE_MAX_END_TO_END_ACK_CACHE.load(Ordering::Relaxed)
}

/// Runtime memory limits for router/relay queue-backed state.
///
/// Compile-time environment values remain the defaults for embedded builds, but applications using
/// prebuilt binaries can now choose per-instance budgets at construction time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeMemoryConfig {
    pub max_queue_budget: usize,
    pub max_recent_rx_ids: usize,
    pub starting_queue_size: usize,
    pub queue_grow_step: f64,
}

impl RuntimeMemoryConfig {
    pub const fn default_const() -> Self {
        Self {
            max_queue_budget: MAX_QUEUE_BUDGET,
            max_recent_rx_ids: MAX_RECENT_RX_IDS,
            starting_queue_size: STARTING_QUEUE_SIZE,
            queue_grow_step: QUEUE_GROW_STEP,
        }
    }

    pub fn new(
        max_queue_budget: usize,
        max_recent_rx_ids: usize,
        starting_queue_size: usize,
        queue_grow_step: f64,
    ) -> TelemetryResult<Self> {
        let cfg = Self {
            max_queue_budget,
            max_recent_rx_ids,
            starting_queue_size,
            queue_grow_step,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(self) -> TelemetryResult<()> {
        if self.max_queue_budget == 0 {
            return Err(TelemetryError::BadArg);
        }
        if self.max_recent_rx_ids == 0 {
            return Err(TelemetryError::BadArg);
        }
        if self.starting_queue_size == 0 || self.starting_queue_size > self.max_queue_budget {
            return Err(TelemetryError::BadArg);
        }
        if !self.queue_grow_step.is_finite() || self.queue_grow_step <= 1.0 {
            return Err(TelemetryError::BadArg);
        }
        Ok(())
    }

    pub fn recent_rx_queue_bytes(self) -> usize {
        self.max_recent_rx_ids
            .saturating_mul(size_of::<u64>())
            .min(self.max_queue_budget)
            .max(1)
    }
}

impl Default for RuntimeMemoryConfig {
    fn default() -> Self {
        Self::default_const()
    }
}

// -----------------------------------------------------------------------------
// Runtime IDs
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct DataEndpoint(pub u32);

impl DataEndpoint {
    pub const TIME_SYNC: Self = Self(200);
    pub const DISCOVERY: Self = Self(201);
    pub const TELEMETRY_ERROR: Self = Self(202);

    #[allow(non_upper_case_globals)]
    pub const TelemetryError: Self = Self::TELEMETRY_ERROR;
    #[allow(non_upper_case_globals)]
    pub const TimeSync: Self = Self::TIME_SYNC;
    #[allow(non_upper_case_globals)]
    pub const Discovery: Self = Self::DISCOVERY;

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn try_from_u32(x: u32) -> Option<Self> {
        if endpoint_exists(Self(x)) {
            Some(Self(x))
        } else {
            None
        }
    }

    #[inline]
    pub fn try_named(name: &str) -> Option<Self> {
        endpoint_definition_by_name(name).map(|def| def.id)
    }

    #[inline]
    pub fn named(name: &str) -> Self {
        Self::try_named(name).unwrap_or_else(|| panic!("unknown data endpoint: {name}"))
    }
}

impl core::fmt::Debug for DataEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::TelemetryError => "SEDSNET_ERROR",
            Self::TimeSync => "SEDSNET_TIME_SYNC",
            Self::Discovery => "SEDSNET_DISCOVERY",
            _ => {
                let meta = get_endpoint_meta(*self);
                if meta.name != "UNKNOWN_ENDPOINT" {
                    return f.write_str(meta.name);
                }
                return write!(f, "DataEndpoint({})", self.0);
            }
        };
        f.write_str(name)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct DataType(pub u32);

impl DataType {
    pub const TELEMETRY_ERROR: Self = Self(0);
    pub const RELIABLE_ACK: Self = Self(1);
    pub const RELIABLE_PACKET_REQUEST: Self = Self(2);
    pub const RELIABLE_PARTIAL_ACK: Self = Self(3);
    pub const TIME_SYNC_ANNOUNCE: Self = Self(4);
    pub const TIME_SYNC_REQUEST: Self = Self(5);
    pub const TIME_SYNC_RESPONSE: Self = Self(6);
    pub const DISCOVERY_ANNOUNCE: Self = Self(7);
    pub const DISCOVERY_TIMESYNC_SOURCES: Self = Self(8);
    pub const DISCOVERY_TOPOLOGY: Self = Self(9);
    pub const DISCOVERY_SCHEMA: Self = Self(10);
    pub const DISCOVERY_TOPOLOGY_REQUEST: Self = Self(11);
    pub const DISCOVERY_SCHEMA_REQUEST: Self = Self(12);
    pub const MANAGED_VARIABLE_REQUEST: Self = Self(13);
    pub const MANAGED_VARIABLE_VALUE: Self = Self(14);
    pub const DISCOVERY_LEAVE: Self = Self(15);
    pub const DISCOVERY_LINK_CAPABILITIES: Self = Self(16);
    pub const DISCOVERY_ADDRESS: Self = Self(17);
    pub const P2P_MESSAGE: Self = Self(18);

    #[allow(non_upper_case_globals)]
    pub const TelemetryError: Self = Self::TELEMETRY_ERROR;
    #[allow(non_upper_case_globals)]
    pub const ReliableAck: Self = Self::RELIABLE_ACK;
    #[allow(non_upper_case_globals)]
    pub const ReliablePacketRequest: Self = Self::RELIABLE_PACKET_REQUEST;
    #[allow(non_upper_case_globals)]
    pub const ReliablePartialAck: Self = Self::RELIABLE_PARTIAL_ACK;
    #[allow(non_upper_case_globals)]
    pub const TimeSyncAnnounce: Self = Self::TIME_SYNC_ANNOUNCE;
    #[allow(non_upper_case_globals)]
    pub const TimeSyncRequest: Self = Self::TIME_SYNC_REQUEST;
    #[allow(non_upper_case_globals)]
    pub const TimeSyncResponse: Self = Self::TIME_SYNC_RESPONSE;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryAnnounce: Self = Self::DISCOVERY_ANNOUNCE;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryTimeSyncSources: Self = Self::DISCOVERY_TIMESYNC_SOURCES;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryTopology: Self = Self::DISCOVERY_TOPOLOGY;
    #[allow(non_upper_case_globals)]
    pub const DiscoverySchema: Self = Self::DISCOVERY_SCHEMA;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryTopologyRequest: Self = Self::DISCOVERY_TOPOLOGY_REQUEST;
    #[allow(non_upper_case_globals)]
    pub const DiscoverySchemaRequest: Self = Self::DISCOVERY_SCHEMA_REQUEST;
    #[allow(non_upper_case_globals)]
    pub const ManagedVariableRequest: Self = Self::MANAGED_VARIABLE_REQUEST;
    #[allow(non_upper_case_globals)]
    pub const ManagedVariableValue: Self = Self::MANAGED_VARIABLE_VALUE;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryLeave: Self = Self::DISCOVERY_LEAVE;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryLinkCapabilities: Self = Self::DISCOVERY_LINK_CAPABILITIES;
    #[allow(non_upper_case_globals)]
    pub const DiscoveryAddress: Self = Self::DISCOVERY_ADDRESS;
    #[allow(non_upper_case_globals)]
    pub const P2pMessage: Self = Self::P2P_MESSAGE;

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn try_from_u32(x: u32) -> Option<Self> {
        if data_type_exists(Self(x)) {
            Some(Self(x))
        } else {
            None
        }
    }

    #[inline]
    pub fn try_named(name: &str) -> Option<Self> {
        data_type_definition_by_name(name).map(|def| def.id)
    }

    #[inline]
    pub fn named(name: &str) -> Self {
        Self::try_named(name).unwrap_or_else(|| panic!("unknown data type: {name}"))
    }
}

impl core::fmt::Debug for DataType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::TelemetryError => "SEDSNET_ERROR",
            Self::ReliableAck => "ReliableAck",
            Self::ReliablePacketRequest => "ReliablePacketRequest",
            Self::ReliablePartialAck => "ReliablePartialAck",
            Self::TimeSyncAnnounce => "SedsnetTimeSyncAnnounce",
            Self::TimeSyncRequest => "SedsnetTimeSyncRequest",
            Self::TimeSyncResponse => "SedsnetTimeSyncResponse",
            Self::DiscoveryAnnounce => "SedsnetDiscoveryAnnounce",
            Self::DiscoveryTimeSyncSources => "SedsnetDiscoveryTimeSyncSources",
            Self::DiscoveryTopology => "SedsnetDiscoveryTopology",
            Self::DiscoverySchema => "SedsnetDiscoverySchema",
            Self::DiscoveryTopologyRequest => "SedsnetDiscoveryTopologyRequest",
            Self::DiscoverySchemaRequest => "SedsnetDiscoverySchemaRequest",
            Self::ManagedVariableRequest => "SedsnetManagedVariableRequest",
            Self::ManagedVariableValue => "SedsnetManagedVariableValue",
            Self::DiscoveryLeave => "SedsnetDiscoveryLeave",
            Self::DiscoveryLinkCapabilities => "SedsnetDiscoveryLinkCapabilities",
            Self::DiscoveryAddress => "SedsnetDiscoveryAddress",
            Self::P2pMessage => "SedsnetP2pMessage",
            _ => {
                let meta = get_message_meta(*self);
                if meta.name != "UNKNOWN_TYPE" {
                    return f.write_str(meta.name);
                }
                return write!(f, "DataType({})", self.0);
            }
        };
        f.write_str(name)
    }
}

// -----------------------------------------------------------------------------
// Runtime registry
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDefinition {
    pub id: DataEndpoint,
    pub name: &'static str,
    pub description: &'static str,
    pub link_local_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataTypeDefinition {
    pub id: DataType,
    pub name: &'static str,
    pub description: &'static str,
    pub element: MessageElement,
    pub endpoints: &'static [DataEndpoint],
    pub reliable: ReliableMode,
    pub priority: u8,
    pub e2e_encryption: E2eEncryptionPolicy,
}

#[derive(Debug, Clone)]
pub struct RuntimeSchemaSnapshot {
    pub endpoints: Vec<EndpointDefinition>,
    pub types: Vec<DataTypeDefinition>,
}

#[derive(Debug, Clone)]
pub struct OwnedEndpointDefinition {
    pub id: DataEndpoint,
    pub name: String,
    pub description: String,
    pub link_local_only: bool,
}

#[derive(Debug, Clone)]
pub struct OwnedDataTypeDefinition {
    pub id: DataType,
    pub name: String,
    pub description: String,
    pub element: MessageElement,
    pub endpoints: Vec<DataEndpoint>,
    pub reliable: ReliableMode,
    pub priority: u8,
    pub e2e_encryption: E2eEncryptionPolicy,
}

#[derive(Debug, Clone)]
pub struct OwnedRuntimeSchemaSnapshot {
    pub endpoints: Vec<OwnedEndpointDefinition>,
    pub types: Vec<OwnedDataTypeDefinition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaMergeDecision {
    Added,
    Unchanged,
    ReplacedLocal,
    KeptLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaMergeReport {
    pub endpoints_added: usize,
    pub endpoints_replaced: usize,
    pub endpoints_kept: usize,
    pub types_added: usize,
    pub types_replaced: usize,
    pub types_kept: usize,
}

impl SchemaMergeReport {
    #[inline]
    pub const fn changed(&self) -> bool {
        self.endpoints_added != 0
            || self.endpoints_replaced != 0
            || self.types_added != 0
            || self.types_replaced != 0
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct Registry {
    endpoints: Vec<(DataEndpoint, EndpointMeta)>,
    types: Vec<(DataType, MessageMeta)>,
    next_endpoint_id: u32,
    next_type_id: u32,
}

#[cfg(feature = "std")]
impl Registry {
    fn new() -> Self {
        let mut reg = Self {
            endpoints: Vec::new(),
            types: Vec::new(),
            next_endpoint_id: 100,
            next_type_id: 100,
        };
        reg.register_endpoint_definition(EndpointDefinition {
            id: DataEndpoint::TelemetryError,
            name: "SEDSNET_ERROR",
            description: "",
            link_local_only: false,
        })
        .expect("built-in endpoint");
        reg.register_endpoint_definition(EndpointDefinition {
            id: DataEndpoint::TimeSync,
            name: "SEDSNET_TIME_SYNC",
            description: "",
            link_local_only: false,
        })
        .expect("built-in endpoint");
        reg.register_endpoint_definition(EndpointDefinition {
            id: DataEndpoint::Discovery,
            name: "SEDSNET_DISCOVERY",
            description: "",
            link_local_only: false,
        })
        .expect("built-in endpoint");

        reg.register_type_definition(DataTypeDefinition {
            id: DataType::TelemetryError,
            name: "SEDSNET_ERROR",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::String, MessageClass::Error),
            endpoints: leak_endpoints(vec![DataEndpoint::TelemetryError]),
            reliable: ReliableMode::None,
            priority: 255,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::ReliableAck,
            name: "SEDSNET_RELIABLE_ACK",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TelemetryError]),
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::ReliablePacketRequest,
            name: "SEDSNET_RELIABLE_PACKET_REQUEST",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TelemetryError]),
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::ReliablePartialAck,
            name: "SEDSNET_RELIABLE_PARTIAL_ACK",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TelemetryError]),
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::TimeSyncAnnounce,
            name: "SEDSNET_TIME_SYNC_ANNOUNCE",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt64, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TimeSync]),
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::TimeSyncRequest,
            name: "SEDSNET_TIME_SYNC_REQUEST",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt64, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TimeSync]),
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::TimeSyncResponse,
            name: "SEDSNET_TIME_SYNC_RESPONSE",
            description: "",
            element: MessageElement::Static(4, MessageDataType::UInt64, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::TimeSync]),
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryAnnounce,
            name: "SEDSNET_DISCOVERY_ANNOUNCE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt32, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryTimeSyncSources,
            name: "SEDSNET_DISCOVERY_TIMESYNC_SOURCES",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryTopology,
            name: "SEDSNET_DISCOVERY_TOPOLOGY",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoverySchema,
            name: "SEDSNET_DISCOVERY_SCHEMA",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 241,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryTopologyRequest,
            name: "SEDSNET_DISCOVERY_TOPOLOGY_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 242,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoverySchemaRequest,
            name: "SEDSNET_DISCOVERY_SCHEMA_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 242,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::ManagedVariableRequest,
            name: "SEDSNET_MANAGED_VARIABLE_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 243,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::ManagedVariableValue,
            name: "SEDSNET_MANAGED_VARIABLE_VALUE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 243,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryLeave,
            name: "SEDSNET_DISCOVERY_LEAVE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::None,
            priority: 244,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryLinkCapabilities,
            name: "SEDSNET_DISCOVERY_LINK_CAPABILITIES",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::DiscoveryAddress,
            name: "SEDSNET_DISCOVERY_ADDRESS",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 244,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        reg.register_type_definition(DataTypeDefinition {
            id: DataType::P2pMessage,
            name: "SEDSNET_P2P_MESSAGE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: leak_endpoints(vec![DataEndpoint::Discovery]),
            reliable: ReliableMode::Ordered,
            priority: 246,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .expect("built-in type");
        #[cfg(all(feature = "embedded", sedsnet_has_telemetry_config_json))]
        if let Ok(snapshot) = bundled_schema_snapshot() {
            let _ = register_schema_snapshot_into(&mut reg, snapshot);
        }
        if let Some(cfg) = read_runtime_json_config("SEDSNET_STATIC_SCHEMA_PATH", &[]) {
            let _ = register_json_config_into(&mut reg, cfg, false);
        }
        if let Some(cfg) = read_runtime_json_config("SEDSNET_STATIC_IPC_SCHEMA_PATH", &[]) {
            let _ = register_json_config_into(&mut reg, cfg, true);
        }
        reg
    }

    fn register_endpoint_definition(&mut self, def: EndpointDefinition) -> TelemetryResult<()> {
        if let Some((_, existing)) = self.endpoints.iter().find(|(id, _)| *id == def.id) {
            if existing.name == def.name
                && existing.description == def.description
                && existing.link_local_only == def.link_local_only
            {
                return Ok(());
            }
            return Err(TelemetryError::BadArg);
        }
        if self.endpoints.iter().any(|(_, meta)| meta.name == def.name) {
            return Err(TelemetryError::BadArg);
        }
        self.next_endpoint_id = self.next_endpoint_id.max(def.id.0.saturating_add(1));
        self.endpoints.push((
            def.id,
            EndpointMeta {
                name: def.name,
                description: def.description,
                link_local_only: def.link_local_only,
            },
        ));
        self.endpoints.sort_unstable_by_key(|(id, _)| id.0);
        Ok(())
    }

    fn register_type_definition(&mut self, def: DataTypeDefinition) -> TelemetryResult<()> {
        if let Some((_, existing)) = self.types.iter().find(|(id, _)| *id == def.id) {
            if existing.name == def.name
                && existing.description == def.description
                && existing.element == def.element
                && existing.endpoints == def.endpoints
                && existing.reliable == def.reliable
                && existing.priority == def.priority
                && existing.e2e_encryption == def.e2e_encryption
            {
                return Ok(());
            }
            return Err(TelemetryError::BadArg);
        }
        if self.types.iter().any(|(_, meta)| meta.name == def.name) {
            return Err(TelemetryError::BadArg);
        }
        for ep in def.endpoints {
            if !self.endpoints.iter().any(|(id, _)| id == ep) {
                return Err(TelemetryError::BadArg);
            }
        }
        self.next_type_id = self.next_type_id.max(def.id.0.saturating_add(1));
        self.types.push((
            def.id,
            MessageMeta {
                name: def.name,
                description: def.description,
                element: def.element,
                endpoints: def.endpoints,
                reliable: def.reliable,
                priority: def.priority,
                e2e_encryption: def.e2e_encryption,
            },
        ));
        self.types.sort_unstable_by_key(|(id, _)| id.0);
        Ok(())
    }

    fn schema_byte_cost(&self) -> usize {
        self.endpoints
            .iter()
            .map(|(_, meta)| endpoint_schema_byte_cost(meta.name.len(), meta.description.len()))
            .sum::<usize>()
            .saturating_add(
                self.types
                    .iter()
                    .map(|(_, meta)| {
                        type_schema_byte_cost(
                            meta.name.len(),
                            meta.description.len(),
                            meta.endpoints.len(),
                        )
                    })
                    .sum::<usize>(),
            )
    }

    fn merge_endpoint_definition(&mut self, def: EndpointDefinition) -> SchemaMergeDecision {
        let id_match = self.endpoints.iter().position(|(id, _)| *id == def.id);
        let name_match = self
            .endpoints
            .iter()
            .position(|(_, meta)| meta.name == def.name);
        let conflict = match (id_match, name_match) {
            (Some(a), Some(b)) if a != b => Some(a.min(b)),
            (Some(a), _) | (_, Some(a)) => Some(a),
            (None, None) => None,
        };

        let Some(idx) = conflict else {
            self.next_endpoint_id = self.next_endpoint_id.max(def.id.0.saturating_add(1));
            self.endpoints.push((
                def.id,
                EndpointMeta {
                    name: def.name,
                    description: def.description,
                    link_local_only: def.link_local_only,
                },
            ));
            self.endpoints.sort_unstable_by_key(|(id, _)| id.0);
            return SchemaMergeDecision::Added;
        };

        let existing = self.endpoints[idx];
        let existing_def = EndpointDefinition {
            id: existing.0,
            name: existing.1.name,
            description: existing.1.description,
            link_local_only: existing.1.link_local_only,
        };
        if endpoint_def_equivalent(&existing_def, &def) {
            return SchemaMergeDecision::Unchanged;
        }
        if endpoint_winner(&existing_def, &def) == def {
            self.endpoints[idx] = (
                def.id,
                EndpointMeta {
                    name: def.name,
                    description: def.description,
                    link_local_only: def.link_local_only,
                },
            );
            self.endpoints.sort_unstable_by_key(|(id, _)| id.0);
            self.next_endpoint_id = self.next_endpoint_id.max(def.id.0.saturating_add(1));
            SchemaMergeDecision::ReplacedLocal
        } else {
            SchemaMergeDecision::KeptLocal
        }
    }

    fn merge_type_definition(&mut self, def: DataTypeDefinition) -> SchemaMergeDecision {
        let id_match = self.types.iter().position(|(id, _)| *id == def.id);
        let name_match = self
            .types
            .iter()
            .position(|(_, meta)| meta.name == def.name);
        let conflict = match (id_match, name_match) {
            (Some(a), Some(b)) if a != b => Some(a.min(b)),
            (Some(a), _) | (_, Some(a)) => Some(a),
            (None, None) => None,
        };

        let Some(idx) = conflict else {
            self.next_type_id = self.next_type_id.max(def.id.0.saturating_add(1));
            self.types.push((
                def.id,
                MessageMeta {
                    name: def.name,
                    description: def.description,
                    element: def.element,
                    endpoints: def.endpoints,
                    reliable: def.reliable,
                    priority: def.priority,
                    e2e_encryption: def.e2e_encryption,
                },
            ));
            self.types.sort_unstable_by_key(|(id, _)| id.0);
            return SchemaMergeDecision::Added;
        };

        let existing = self.types[idx];
        let existing_def = DataTypeDefinition {
            id: existing.0,
            name: existing.1.name,
            description: existing.1.description,
            element: existing.1.element,
            endpoints: existing.1.endpoints,
            reliable: existing.1.reliable,
            priority: existing.1.priority,
            e2e_encryption: existing.1.e2e_encryption,
        };
        if type_def_equivalent(&existing_def, &def) {
            return SchemaMergeDecision::Unchanged;
        }
        if type_winner(&existing_def, &def) == def {
            self.types[idx] = (
                def.id,
                MessageMeta {
                    name: def.name,
                    description: def.description,
                    element: def.element,
                    endpoints: def.endpoints,
                    reliable: def.reliable,
                    priority: def.priority,
                    e2e_encryption: def.e2e_encryption,
                },
            );
            self.types.sort_unstable_by_key(|(id, _)| id.0);
            self.next_type_id = self.next_type_id.max(def.id.0.saturating_add(1));
            SchemaMergeDecision::ReplacedLocal
        } else {
            SchemaMergeDecision::KeptLocal
        }
    }
}

fn endpoint_schema_byte_cost(name_len: usize, description_len: usize) -> usize {
    size_of::<(DataEndpoint, EndpointMeta)>()
        .saturating_add(name_len)
        .saturating_add(description_len)
}

fn type_schema_byte_cost(name_len: usize, description_len: usize, endpoint_count: usize) -> usize {
    size_of::<(DataType, MessageMeta)>()
        .saturating_add(name_len)
        .saturating_add(description_len)
        .saturating_add(endpoint_count.saturating_mul(size_of::<DataEndpoint>()))
}

pub fn owned_schema_byte_cost(snapshot: &OwnedRuntimeSchemaSnapshot) -> usize {
    snapshot
        .endpoints
        .iter()
        .map(|def| endpoint_schema_byte_cost(def.name.len(), def.description.len()))
        .sum::<usize>()
        .saturating_add(
            snapshot
                .types
                .iter()
                .map(|def| {
                    type_schema_byte_cost(
                        def.name.len(),
                        def.description.len(),
                        def.endpoints.len(),
                    )
                })
                .sum::<usize>(),
        )
}

#[cfg(feature = "std")]
static REGISTRY: OnceLock<std::sync::Mutex<Registry>> = OnceLock::new();

#[cfg(feature = "std")]
fn registry() -> &'static std::sync::Mutex<Registry> {
    REGISTRY.get_or_init(|| std::sync::Mutex::new(Registry::new()))
}

#[cfg(all(
    feature = "serde",
    feature = "embedded",
    sedsnet_has_telemetry_config_json
))]
fn bundled_schema_snapshot() -> TelemetryResult<RuntimeSchemaSnapshot> {
    schema_snapshot_from_json_bytes(include_bytes!("../telemetry_config.json"))
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak_endpoints(eps: Vec<DataEndpoint>) -> &'static [DataEndpoint] {
    Box::leak(eps.into_boxed_slice())
}

#[cfg(feature = "std")]
fn read_runtime_json_config(env_key: &str, fallback_paths: &[&str]) -> Option<JsonConfig> {
    if let Ok(path) = std::env::var(env_key)
        && let Ok(json) = std::fs::read_to_string(path)
        && let Ok(cfg) = serde_json::from_str::<JsonConfig>(&json)
    {
        return Some(cfg);
    }
    for path in fallback_paths {
        if let Ok(json) = std::fs::read_to_string(path)
            && let Ok(cfg) = serde_json::from_str::<JsonConfig>(&json)
        {
            return Some(cfg);
        }
    }
    None
}

#[cfg(feature = "std")]
pub fn register_endpoint(name: &str, link_local_only: bool) -> TelemetryResult<DataEndpoint> {
    register_endpoint_with_description(name, "", link_local_only)
}

#[cfg(feature = "std")]
pub fn register_endpoint_with_description(
    name: &str,
    description: &str,
    link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    let mut reg = registry().lock().expect("schema registry poisoned");
    let id = DataEndpoint(reg.next_endpoint_id);
    reg.register_endpoint_definition(EndpointDefinition {
        id,
        name: leak_str(name.to_string()),
        description: leak_str(description.to_string()),
        link_local_only,
    })?;
    Ok(id)
}

#[cfg(feature = "std")]
pub fn register_endpoint_id(
    id: DataEndpoint,
    name: &str,
    link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    register_endpoint_id_with_description(id, name, "", link_local_only)
}

#[cfg(feature = "std")]
pub fn register_endpoint_id_with_description(
    id: DataEndpoint,
    name: &str,
    description: &str,
    link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .register_endpoint_definition(EndpointDefinition {
            id,
            name: leak_str(name.to_string()),
            description: leak_str(description.to_string()),
            link_local_only,
        })?;
    Ok(id)
}

#[cfg(feature = "std")]
pub fn ensure_endpoint_id(
    id: DataEndpoint,
    link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    if endpoint_exists(id) {
        return Ok(id);
    }
    register_endpoint_id(id, &format!("ENDPOINT_{}", id.0), link_local_only)
}

#[cfg(feature = "std")]
pub fn register_endpoint_definition(def: EndpointDefinition) -> TelemetryResult<()> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .register_endpoint_definition(def)
}

#[cfg(feature = "std")]
pub fn register_data_type(
    name: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
) -> TelemetryResult<DataType> {
    register_data_type_with_description(name, "", element, endpoints, reliable, priority)
}

#[cfg(feature = "std")]
pub fn register_data_type_with_description(
    name: &str,
    description: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
) -> TelemetryResult<DataType> {
    register_data_type_with_description_and_e2e_encryption(
        name,
        description,
        element,
        endpoints,
        reliable,
        priority,
        E2eEncryptionPolicy::PreferOff,
    )
}

#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub fn register_data_type_with_description_and_e2e_encryption(
    name: &str,
    description: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
    e2e_encryption: E2eEncryptionPolicy,
) -> TelemetryResult<DataType> {
    let mut reg = registry().lock().expect("schema registry poisoned");
    let id = DataType(reg.next_type_id);
    reg.register_type_definition(DataTypeDefinition {
        id,
        name: leak_str(name.to_string()),
        description: leak_str(description.to_string()),
        element,
        endpoints: leak_endpoints(endpoints.to_vec()),
        reliable,
        priority,
        e2e_encryption,
    })?;
    Ok(id)
}

#[cfg(feature = "std")]
pub fn register_data_type_definition(def: DataTypeDefinition) -> TelemetryResult<()> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .register_type_definition(def)
}

#[cfg(feature = "std")]
pub fn set_data_type_e2e_encryption_policy(
    ty: DataType,
    policy: E2eEncryptionPolicy,
) -> TelemetryResult<()> {
    let mut reg = registry().lock().expect("schema registry poisoned");
    let Some((_, meta)) = reg.types.iter_mut().find(|(id, _)| *id == ty) else {
        return Err(TelemetryError::InvalidType);
    };
    meta.e2e_encryption = policy;
    Ok(())
}

#[cfg(feature = "std")]
pub fn register_data_type_id(
    id: DataType,
    name: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
) -> TelemetryResult<DataType> {
    register_data_type_id_with_description(id, name, "", element, endpoints, reliable, priority)
}

#[cfg(feature = "std")]
pub fn register_data_type_id_with_description(
    id: DataType,
    name: &str,
    description: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
) -> TelemetryResult<DataType> {
    register_data_type_id_with_description_and_e2e_encryption(
        id,
        name,
        description,
        element,
        endpoints,
        reliable,
        priority,
        E2eEncryptionPolicy::PreferOff,
    )
}

#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub fn register_data_type_id_with_description_and_e2e_encryption(
    id: DataType,
    name: &str,
    description: &str,
    element: MessageElement,
    endpoints: &[DataEndpoint],
    reliable: ReliableMode,
    priority: u8,
    e2e_encryption: E2eEncryptionPolicy,
) -> TelemetryResult<DataType> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .register_type_definition(DataTypeDefinition {
            id,
            name: leak_str(name.to_string()),
            description: leak_str(description.to_string()),
            element,
            endpoints: leak_endpoints(endpoints.to_vec()),
            reliable,
            priority,
            e2e_encryption,
        })?;
    Ok(id)
}

#[cfg(feature = "std")]
pub fn merge_schema_snapshot(snapshot: RuntimeSchemaSnapshot) -> SchemaMergeReport {
    let mut reg = registry().lock().expect("schema registry poisoned");
    merge_schema_snapshot_locked(&mut reg, snapshot)
}

#[cfg(feature = "std")]
pub fn merge_owned_schema_snapshot(snapshot: OwnedRuntimeSchemaSnapshot) -> SchemaMergeReport {
    merge_owned_schema_snapshot_with_budget(snapshot, usize::MAX)
        .expect("unbounded schema merge should not fail budget")
}

#[cfg(feature = "std")]
pub fn merge_owned_schema_snapshot_with_budget(
    mut snapshot: OwnedRuntimeSchemaSnapshot,
    max_schema_bytes: usize,
) -> TelemetryResult<SchemaMergeReport> {
    snapshot.endpoints.sort_unstable_by_key(|def| def.id.0);
    snapshot.endpoints.dedup_by_key(|def| def.id.0);
    snapshot.types.sort_unstable_by_key(|def| def.id.0);
    snapshot.types.dedup_by_key(|def| def.id.0);

    let reg = registry().lock().expect("schema registry poisoned");
    if reg
        .schema_byte_cost()
        .saturating_add(owned_schema_byte_cost(&snapshot))
        > max_schema_bytes
    {
        return Err(TelemetryError::PacketTooLarge(
            "Schema exceeds maximum shared queue budget",
        ));
    }
    drop(reg);

    let mut converted = RuntimeSchemaSnapshot {
        endpoints: Vec::with_capacity(snapshot.endpoints.len()),
        types: Vec::with_capacity(snapshot.types.len()),
    };
    for endpoint in snapshot.endpoints {
        converted.endpoints.push(EndpointDefinition {
            id: endpoint.id,
            name: leak_str(endpoint.name),
            description: leak_str(endpoint.description),
            link_local_only: endpoint.link_local_only,
        });
    }
    for ty in snapshot.types {
        converted.types.push(DataTypeDefinition {
            id: ty.id,
            name: leak_str(ty.name),
            description: leak_str(ty.description),
            element: ty.element,
            endpoints: leak_endpoints(ty.endpoints),
            reliable: ty.reliable,
            priority: ty.priority,
            e2e_encryption: ty.e2e_encryption,
        });
    }

    let mut reg = registry().lock().expect("schema registry poisoned");
    let mut preview = reg.clone();
    let report = merge_schema_snapshot_locked(&mut preview, converted.clone());
    if preview.schema_byte_cost() > max_schema_bytes {
        return Err(TelemetryError::PacketTooLarge(
            "Schema exceeds maximum shared queue budget",
        ));
    }
    *reg = preview;
    Ok(report)
}

#[cfg(feature = "std")]
fn merge_schema_snapshot_locked(
    reg: &mut Registry,
    mut snapshot: RuntimeSchemaSnapshot,
) -> SchemaMergeReport {
    snapshot.endpoints.sort_unstable_by_key(|def| def.id.0);
    snapshot.endpoints.dedup_by_key(|def| def.id.0);
    snapshot.types.sort_unstable_by_key(|def| def.id.0);
    snapshot.types.dedup_by_key(|def| def.id.0);

    let mut report = SchemaMergeReport {
        endpoints_added: 0,
        endpoints_replaced: 0,
        endpoints_kept: 0,
        types_added: 0,
        types_replaced: 0,
        types_kept: 0,
    };
    for endpoint in snapshot.endpoints {
        match reg.merge_endpoint_definition(endpoint) {
            SchemaMergeDecision::Added => report.endpoints_added += 1,
            SchemaMergeDecision::ReplacedLocal => report.endpoints_replaced += 1,
            SchemaMergeDecision::KeptLocal => report.endpoints_kept += 1,
            SchemaMergeDecision::Unchanged => {}
        }
    }
    for ty in snapshot.types {
        if ty
            .endpoints
            .iter()
            .all(|ep| reg.endpoints.iter().any(|(known_ep, _)| known_ep == ep))
        {
            match reg.merge_type_definition(ty) {
                SchemaMergeDecision::Added => report.types_added += 1,
                SchemaMergeDecision::ReplacedLocal => report.types_replaced += 1,
                SchemaMergeDecision::KeptLocal => report.types_kept += 1,
                SchemaMergeDecision::Unchanged => {}
            }
        } else {
            report.types_kept += 1;
        }
    }
    report
}

#[cfg(feature = "std")]
pub fn export_schema() -> RuntimeSchemaSnapshot {
    let reg = registry().lock().expect("schema registry poisoned");
    RuntimeSchemaSnapshot {
        endpoints: reg
            .endpoints
            .iter()
            .map(|(id, meta)| EndpointDefinition {
                id: *id,
                name: meta.name,
                description: meta.description,
                link_local_only: meta.link_local_only,
            })
            .collect(),
        types: reg
            .types
            .iter()
            .map(|(id, meta)| DataTypeDefinition {
                id: *id,
                name: meta.name,
                description: meta.description,
                element: meta.element,
                endpoints: meta.endpoints,
                reliable: meta.reliable,
                priority: meta.priority,
                e2e_encryption: meta.e2e_encryption,
            })
            .collect(),
    }
}

#[cfg(feature = "std")]
pub fn known_endpoints() -> Vec<EndpointDefinition> {
    export_schema().endpoints
}

#[cfg(feature = "std")]
pub fn known_data_types() -> Vec<DataTypeDefinition> {
    export_schema().types
}

#[cfg(feature = "std")]
pub fn schema_fingerprint() -> u64 {
    let snapshot = export_schema();
    let mut h = 0x5E_D5_50_4F_52_49_4E_54u64;
    for ep in snapshot.endpoints {
        h = hash_u32(h, ep.id.0);
        h = hash_bytes(h, ep.name.as_bytes());
        h = hash_bytes(h, ep.description.as_bytes());
        h = hash_u8(h, ep.link_local_only as u8);
    }
    for ty in snapshot.types {
        h = hash_u32(h, ty.id.0);
        h = hash_bytes(h, ty.name.as_bytes());
        h = hash_bytes(h, ty.description.as_bytes());
        h = hash_message_element(h, ty.element);
        h = hash_u8(h, reliable_code(ty.reliable));
        h = hash_u8(h, ty.priority);
        for ep in ty.endpoints {
            h = hash_u32(h, ep.0);
        }
    }
    h
}

#[cfg(feature = "std")]
pub fn schema_bytes_used() -> usize {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .schema_byte_cost()
}

#[cfg(feature = "std")]
pub fn endpoint_exists(ep: DataEndpoint) -> bool {
    #[cfg(all(test, feature = "std"))]
    seed_test_schema();
    registry()
        .lock()
        .expect("schema registry poisoned")
        .endpoints
        .iter()
        .any(|(id, _)| *id == ep)
}

#[cfg(feature = "std")]
pub fn data_type_exists(ty: DataType) -> bool {
    #[cfg(all(test, feature = "std"))]
    seed_test_schema();
    registry()
        .lock()
        .expect("schema registry poisoned")
        .types
        .iter()
        .any(|(id, _)| *id == ty)
}

#[cfg(feature = "std")]
pub fn get_endpoint_meta(endpoint_type: DataEndpoint) -> EndpointMeta {
    #[cfg(all(test, feature = "std"))]
    seed_test_schema();
    registry()
        .lock()
        .expect("schema registry poisoned")
        .endpoints
        .iter()
        .find(|(id, _)| *id == endpoint_type)
        .map(|(_, meta)| *meta)
        .unwrap_or(EndpointMeta {
            name: "UNKNOWN_ENDPOINT",
            description: "",
            link_local_only: false,
        })
}

#[cfg(feature = "std")]
pub fn get_message_meta(data_type: DataType) -> MessageMeta {
    #[cfg(all(test, feature = "std"))]
    seed_test_schema();
    registry()
        .lock()
        .expect("schema registry poisoned")
        .types
        .iter()
        .find(|(id, _)| *id == data_type)
        .map(|(_, meta)| *meta)
        .unwrap_or(MessageMeta {
            name: "UNKNOWN_TYPE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
            endpoints: &[],
            reliable: ReliableMode::None,
            priority: 0,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
}

#[cfg(feature = "std")]
pub fn max_endpoint_id() -> u32 {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .endpoints
        .iter()
        .map(|(id, _)| id.0)
        .max()
        .unwrap_or(0)
}

#[cfg(feature = "std")]
pub fn max_data_type_id() -> u32 {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .types
        .iter()
        .map(|(id, _)| id.0)
        .max()
        .unwrap_or(0)
}

#[cfg(feature = "std")]
fn hash_u8(h: u64, v: u8) -> u64 {
    hash_bytes(h, &[v])
}

#[cfg(feature = "std")]
fn hash_u32(h: u64, v: u32) -> u64 {
    hash_bytes(h, &v.to_le_bytes())
}

#[cfg(feature = "std")]
fn hash_usize(h: u64, v: usize) -> u64 {
    hash_bytes(h, &(v as u64).to_le_bytes())
}

#[cfg(feature = "std")]
fn hash_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01B3;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(feature = "std")]
fn endpoint_fingerprint(def: EndpointDefinition) -> u64 {
    let mut h = 0x4550_4445_4600_0001;
    h = hash_u32(h, def.id.0);
    h = hash_bytes(h, def.name.as_bytes());
    h = hash_bytes(h, def.description.as_bytes());
    hash_u8(h, def.link_local_only as u8)
}

#[cfg(feature = "std")]
fn type_fingerprint(def: DataTypeDefinition) -> u64 {
    let mut h = 0x5459_4445_4600_0001;
    h = hash_u32(h, def.id.0);
    h = hash_bytes(h, def.name.as_bytes());
    h = hash_bytes(h, def.description.as_bytes());
    h = hash_message_element(h, def.element);
    h = hash_u8(h, reliable_code(def.reliable));
    h = hash_u8(h, def.priority);
    h = hash_u8(h, e2e_encryption_policy_code(def.e2e_encryption));
    for ep in def.endpoints {
        h = hash_u32(h, ep.0);
    }
    h
}

#[cfg(feature = "std")]
fn hash_message_element(mut h: u64, element: MessageElement) -> u64 {
    match element {
        MessageElement::Static(count, data_type, class) => {
            h = hash_u8(h, 0);
            h = hash_usize(h, count);
            h = hash_u8(h, message_data_type_code(data_type));
            hash_u8(h, message_class_code(class))
        }
        MessageElement::Dynamic(data_type, class) => {
            h = hash_u8(h, 1);
            h = hash_u8(h, message_data_type_code(data_type));
            hash_u8(h, message_class_code(class))
        }
    }
}

#[cfg(feature = "std")]
pub fn endpoint_definition(ep: DataEndpoint) -> Option<EndpointDefinition> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .endpoints
        .iter()
        .find(|(id, _)| *id == ep)
        .map(|(id, meta)| EndpointDefinition {
            id: *id,
            name: meta.name,
            description: meta.description,
            link_local_only: meta.link_local_only,
        })
}

#[cfg(feature = "std")]
pub fn data_type_definition(ty: DataType) -> Option<DataTypeDefinition> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .types
        .iter()
        .find(|(id, _)| *id == ty)
        .map(|(id, meta)| DataTypeDefinition {
            id: *id,
            name: meta.name,
            description: meta.description,
            element: meta.element,
            endpoints: meta.endpoints,
            reliable: meta.reliable,
            priority: meta.priority,
            e2e_encryption: meta.e2e_encryption,
        })
}

#[cfg(feature = "std")]
pub fn endpoint_definition_by_name(name: &str) -> Option<EndpointDefinition> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .endpoints
        .iter()
        .find(|(_, meta)| meta.name == name)
        .map(|(id, meta)| EndpointDefinition {
            id: *id,
            name: meta.name,
            description: meta.description,
            link_local_only: meta.link_local_only,
        })
}

#[cfg(feature = "std")]
pub fn data_type_definition_by_name(name: &str) -> Option<DataTypeDefinition> {
    registry()
        .lock()
        .expect("schema registry poisoned")
        .types
        .iter()
        .find(|(_, meta)| meta.name == name)
        .map(|(id, meta)| DataTypeDefinition {
            id: *id,
            name: meta.name,
            description: meta.description,
            element: meta.element,
            endpoints: meta.endpoints,
            reliable: meta.reliable,
            priority: meta.priority,
            e2e_encryption: meta.e2e_encryption,
        })
}

#[cfg(feature = "std")]
fn is_internal_endpoint(ep: DataEndpoint) -> bool {
    matches!(
        ep,
        DataEndpoint::TelemetryError | DataEndpoint::TimeSync | DataEndpoint::Discovery
    )
}

#[cfg(feature = "std")]
fn is_internal_data_type(ty: DataType) -> bool {
    matches!(
        ty,
        DataType::TelemetryError
            | DataType::ReliableAck
            | DataType::ReliablePacketRequest
            | DataType::ReliablePartialAck
            | DataType::TimeSyncAnnounce
            | DataType::TimeSyncRequest
            | DataType::TimeSyncResponse
            | DataType::DiscoveryAnnounce
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
            | DataType::P2pMessage
    )
}

#[cfg(feature = "std")]
pub fn remove_endpoint(ep: DataEndpoint) -> TelemetryResult<bool> {
    if is_internal_endpoint(ep) {
        return Err(TelemetryError::BadArg);
    }
    let mut reg = registry().lock().expect("schema registry poisoned");
    let before = reg.endpoints.len();
    reg.endpoints.retain(|(id, _)| *id != ep);
    if reg.endpoints.len() == before {
        return Ok(false);
    }
    reg.types.retain(|(_, meta)| !meta.endpoints.contains(&ep));
    Ok(true)
}

#[cfg(feature = "std")]
pub fn remove_endpoint_by_name(name: &str) -> TelemetryResult<bool> {
    if let Some(def) = endpoint_definition_by_name(name) {
        remove_endpoint(def.id)
    } else {
        Ok(false)
    }
}

#[cfg(feature = "std")]
pub fn remove_data_type(ty: DataType) -> TelemetryResult<bool> {
    if is_internal_data_type(ty) {
        return Err(TelemetryError::BadArg);
    }
    let mut reg = registry().lock().expect("schema registry poisoned");
    let before = reg.types.len();
    reg.types.retain(|(id, _)| *id != ty);
    Ok(reg.types.len() != before)
}

#[cfg(feature = "std")]
pub fn remove_data_type_by_name(name: &str) -> TelemetryResult<bool> {
    if let Some(def) = data_type_definition_by_name(name) {
        remove_data_type(def.id)
    } else {
        Ok(false)
    }
}

#[cfg(feature = "std")]
fn endpoint_def_equivalent(a: &EndpointDefinition, b: &EndpointDefinition) -> bool {
    a.id == b.id
        && a.name == b.name
        && a.description == b.description
        && a.link_local_only == b.link_local_only
}

#[cfg(feature = "std")]
fn type_def_equivalent(a: &DataTypeDefinition, b: &DataTypeDefinition) -> bool {
    a.id == b.id
        && a.name == b.name
        && a.description == b.description
        && a.element == b.element
        && a.endpoints == b.endpoints
        && a.reliable == b.reliable
        && a.priority == b.priority
}

#[cfg(feature = "std")]
fn endpoint_winner(a: &EndpointDefinition, b: &EndpointDefinition) -> EndpointDefinition {
    let a_key = (endpoint_fingerprint(*a), a.id.0, a.name);
    let b_key = (endpoint_fingerprint(*b), b.id.0, b.name);
    if a_key <= b_key { *a } else { *b }
}

#[cfg(feature = "std")]
fn type_winner(a: &DataTypeDefinition, b: &DataTypeDefinition) -> DataTypeDefinition {
    let a_key = (type_fingerprint(*a), a.id.0, a.name);
    let b_key = (type_fingerprint(*b), b.id.0, b.name);
    if a_key <= b_key { *a } else { *b }
}

pub(crate) fn message_data_type_code(dt: MessageDataType) -> u8 {
    match dt {
        MessageDataType::Float64 => 0,
        MessageDataType::Float32 => 1,
        MessageDataType::UInt8 => 2,
        MessageDataType::UInt16 => 3,
        MessageDataType::UInt32 => 4,
        MessageDataType::UInt64 => 5,
        MessageDataType::UInt128 => 6,
        MessageDataType::Int8 => 7,
        MessageDataType::Int16 => 8,
        MessageDataType::Int32 => 9,
        MessageDataType::Int64 => 10,
        MessageDataType::Int128 => 11,
        MessageDataType::Bool => 12,
        MessageDataType::String => 13,
        MessageDataType::Binary => 14,
        MessageDataType::NoData => 15,
    }
}

pub(crate) fn message_data_type_from_code(code: u8) -> Option<MessageDataType> {
    match code {
        0 => Some(MessageDataType::Float64),
        1 => Some(MessageDataType::Float32),
        2 => Some(MessageDataType::UInt8),
        3 => Some(MessageDataType::UInt16),
        4 => Some(MessageDataType::UInt32),
        5 => Some(MessageDataType::UInt64),
        6 => Some(MessageDataType::UInt128),
        7 => Some(MessageDataType::Int8),
        8 => Some(MessageDataType::Int16),
        9 => Some(MessageDataType::Int32),
        10 => Some(MessageDataType::Int64),
        11 => Some(MessageDataType::Int128),
        12 => Some(MessageDataType::Bool),
        13 => Some(MessageDataType::String),
        14 => Some(MessageDataType::Binary),
        15 => Some(MessageDataType::NoData),
        _ => None,
    }
}

pub(crate) fn message_class_code(class: MessageClass) -> u8 {
    match class {
        MessageClass::Data => 0,
        MessageClass::Error => 1,
        MessageClass::Warning => 2,
    }
}

pub(crate) fn message_class_from_code(code: u8) -> Option<MessageClass> {
    match code {
        0 => Some(MessageClass::Data),
        1 => Some(MessageClass::Error),
        2 => Some(MessageClass::Warning),
        _ => None,
    }
}

pub(crate) fn reliable_code(mode: ReliableMode) -> u8 {
    match mode {
        ReliableMode::None => 0,
        ReliableMode::Ordered => 1,
        ReliableMode::Unordered => 2,
    }
}

pub(crate) fn reliable_from_code(code: u8) -> Option<ReliableMode> {
    match code {
        0 => Some(ReliableMode::None),
        1 => Some(ReliableMode::Ordered),
        2 => Some(ReliableMode::Unordered),
        _ => None,
    }
}

pub(crate) fn e2e_encryption_policy_code(policy: E2eEncryptionPolicy) -> u8 {
    match policy {
        E2eEncryptionPolicy::PreferOff => 0,
        E2eEncryptionPolicy::PreferOn => 1,
        E2eEncryptionPolicy::RequireOn => 2,
    }
}

pub(crate) fn e2e_encryption_policy_from_code(code: u8) -> Option<E2eEncryptionPolicy> {
    match code {
        0 => Some(E2eEncryptionPolicy::PreferOff),
        1 => Some(E2eEncryptionPolicy::PreferOn),
        2 => Some(E2eEncryptionPolicy::RequireOn),
        _ => None,
    }
}

#[cfg(not(feature = "std"))]
pub fn register_endpoint(_name: &str, _link_local_only: bool) -> TelemetryResult<DataEndpoint> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_endpoint_with_description(
    _name: &str,
    _description: &str,
    _link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_endpoint_definition(_def: EndpointDefinition) -> TelemetryResult<()> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_endpoint_id(
    _id: DataEndpoint,
    _name: &str,
    _link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_endpoint_id_with_description(
    _id: DataEndpoint,
    _name: &str,
    _description: &str,
    _link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn ensure_endpoint_id(
    id: DataEndpoint,
    _link_local_only: bool,
) -> TelemetryResult<DataEndpoint> {
    if endpoint_exists(id) {
        Ok(id)
    } else {
        Err(TelemetryError::BadArg)
    }
}

#[cfg(not(feature = "std"))]
pub fn register_data_type(
    _name: &str,
    _element: MessageElement,
    _endpoints: &[DataEndpoint],
    _reliable: ReliableMode,
    _priority: u8,
) -> TelemetryResult<DataType> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_data_type_with_description(
    _name: &str,
    _description: &str,
    _element: MessageElement,
    _endpoints: &[DataEndpoint],
    _reliable: ReliableMode,
    _priority: u8,
) -> TelemetryResult<DataType> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_data_type_definition(_def: DataTypeDefinition) -> TelemetryResult<()> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn set_data_type_e2e_encryption_policy(
    _ty: DataType,
    _policy: E2eEncryptionPolicy,
) -> TelemetryResult<()> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_data_type_id(
    _id: DataType,
    _name: &str,
    _element: MessageElement,
    _endpoints: &[DataEndpoint],
    _reliable: ReliableMode,
    _priority: u8,
) -> TelemetryResult<DataType> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn register_data_type_id_with_description(
    _id: DataType,
    _name: &str,
    _description: &str,
    _element: MessageElement,
    _endpoints: &[DataEndpoint],
    _reliable: ReliableMode,
    _priority: u8,
) -> TelemetryResult<DataType> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
#[allow(clippy::too_many_arguments)]
pub fn register_data_type_id_with_description_and_e2e_encryption(
    _id: DataType,
    _name: &str,
    _description: &str,
    _element: MessageElement,
    _endpoints: &[DataEndpoint],
    _reliable: ReliableMode,
    _priority: u8,
    _e2e_encryption: E2eEncryptionPolicy,
) -> TelemetryResult<DataType> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn export_schema() -> RuntimeSchemaSnapshot {
    RuntimeSchemaSnapshot {
        endpoints: known_endpoints(),
        types: known_data_types(),
    }
}

#[cfg(not(feature = "std"))]
pub fn known_endpoints() -> Vec<EndpointDefinition> {
    #[cfg_attr(
        not(all(feature = "serde", sedsnet_has_telemetry_config_json)),
        allow(unused_mut)
    )]
    let mut endpoints = vec![
        EndpointDefinition {
            id: DataEndpoint::TelemetryError,
            name: "SEDSNET_ERROR",
            description: "",
            link_local_only: false,
        },
        EndpointDefinition {
            id: DataEndpoint::TimeSync,
            name: "SEDSNET_TIME_SYNC",
            description: "",
            link_local_only: false,
        },
        EndpointDefinition {
            id: DataEndpoint::Discovery,
            name: "SEDSNET_DISCOVERY",
            description: "",
            link_local_only: false,
        },
    ];
    #[cfg(all(feature = "serde", sedsnet_has_telemetry_config_json))]
    if let Ok(snapshot) = bundled_schema_snapshot() {
        for endpoint in snapshot.endpoints {
            if !endpoints
                .iter()
                .any(|known| known.id == endpoint.id || known.name == endpoint.name)
            {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints
}

#[cfg(not(feature = "std"))]
pub fn known_data_types() -> Vec<DataTypeDefinition> {
    #[cfg_attr(
        not(all(feature = "serde", sedsnet_has_telemetry_config_json)),
        allow(unused_mut)
    )]
    let mut types = vec![
        DataTypeDefinition {
            id: DataType::TelemetryError,
            name: "SEDSNET_ERROR",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::String, MessageClass::Error),
            endpoints: &[DataEndpoint::TelemetryError],
            reliable: ReliableMode::None,
            priority: 255,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::ReliableAck,
            name: "SEDSNET_RELIABLE_ACK",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: &[DataEndpoint::TelemetryError],
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::ReliablePacketRequest,
            name: "SEDSNET_RELIABLE_PACKET_REQUEST",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: &[DataEndpoint::TelemetryError],
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::ReliablePartialAck,
            name: "SEDSNET_RELIABLE_PARTIAL_ACK",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt32, MessageClass::Data),
            endpoints: &[DataEndpoint::TelemetryError],
            reliable: ReliableMode::None,
            priority: 250,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::TimeSyncAnnounce,
            name: "SEDSNET_TIME_SYNC_ANNOUNCE",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt64, MessageClass::Data),
            endpoints: &[DataEndpoint::TimeSync],
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::TimeSyncRequest,
            name: "SEDSNET_TIME_SYNC_REQUEST",
            description: "",
            element: MessageElement::Static(2, MessageDataType::UInt64, MessageClass::Data),
            endpoints: &[DataEndpoint::TimeSync],
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::TimeSyncResponse,
            name: "SEDSNET_TIME_SYNC_RESPONSE",
            description: "",
            element: MessageElement::Static(4, MessageDataType::UInt64, MessageClass::Data),
            endpoints: &[DataEndpoint::TimeSync],
            reliable: ReliableMode::None,
            priority: 245,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryAnnounce,
            name: "SEDSNET_DISCOVERY_ANNOUNCE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt32, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryTimeSyncSources,
            name: "SEDSNET_DISCOVERY_TIMESYNC_SOURCES",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryTopology,
            name: "SEDSNET_DISCOVERY_TOPOLOGY",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoverySchema,
            name: "SEDSNET_DISCOVERY_SCHEMA",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 241,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryTopologyRequest,
            name: "SEDSNET_DISCOVERY_TOPOLOGY_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 242,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoverySchemaRequest,
            name: "SEDSNET_DISCOVERY_SCHEMA_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 242,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::ManagedVariableRequest,
            name: "SEDSNET_MANAGED_VARIABLE_REQUEST",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 243,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::ManagedVariableValue,
            name: "SEDSNET_MANAGED_VARIABLE_VALUE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 243,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryLeave,
            name: "SEDSNET_DISCOVERY_LEAVE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::None,
            priority: 244,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryLinkCapabilities,
            name: "SEDSNET_DISCOVERY_LINK_CAPABILITIES",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::None,
            priority: 240,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::DiscoveryAddress,
            name: "SEDSNET_DISCOVERY_ADDRESS",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 244,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
        DataTypeDefinition {
            id: DataType::P2pMessage,
            name: "SEDSNET_P2P_MESSAGE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            endpoints: &[DataEndpoint::Discovery],
            reliable: ReliableMode::Ordered,
            priority: 246,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        },
    ];
    #[cfg(all(feature = "serde", sedsnet_has_telemetry_config_json))]
    if let Ok(snapshot) = bundled_schema_snapshot() {
        for ty in snapshot.types {
            if !types
                .iter()
                .any(|known| known.id == ty.id || known.name == ty.name)
            {
                types.push(ty);
            }
        }
    }
    types
}

#[cfg(not(feature = "std"))]
pub fn merge_schema_snapshot(_snapshot: RuntimeSchemaSnapshot) -> SchemaMergeReport {
    SchemaMergeReport {
        endpoints_added: 0,
        endpoints_replaced: 0,
        endpoints_kept: 0,
        types_added: 0,
        types_replaced: 0,
        types_kept: 0,
    }
}

#[cfg(not(feature = "std"))]
pub fn merge_owned_schema_snapshot_with_budget(
    _snapshot: OwnedRuntimeSchemaSnapshot,
    _max_schema_bytes: usize,
) -> TelemetryResult<SchemaMergeReport> {
    Ok(SchemaMergeReport {
        endpoints_added: 0,
        endpoints_replaced: 0,
        endpoints_kept: 0,
        types_added: 0,
        types_replaced: 0,
        types_kept: 0,
    })
}

#[cfg(not(feature = "std"))]
pub fn schema_fingerprint() -> u64 {
    0
}

#[cfg(not(feature = "std"))]
pub fn schema_bytes_used() -> usize {
    known_endpoints()
        .iter()
        .map(|def| {
            size_of::<EndpointDefinition>()
                .saturating_add(def.name.len())
                .saturating_add(def.description.len())
        })
        .sum::<usize>()
        .saturating_add(
            known_data_types()
                .iter()
                .map(|def| {
                    size_of::<DataTypeDefinition>()
                        .saturating_add(def.name.len())
                        .saturating_add(def.description.len())
                        .saturating_add(
                            def.endpoints
                                .len()
                                .saturating_mul(size_of::<DataEndpoint>()),
                        )
                })
                .sum::<usize>(),
        )
}

#[cfg(not(feature = "std"))]
pub fn endpoint_exists(ep: DataEndpoint) -> bool {
    known_endpoints().iter().any(|def| def.id == ep)
}

#[cfg(not(feature = "std"))]
pub fn data_type_exists(ty: DataType) -> bool {
    known_data_types().iter().any(|def| def.id == ty)
}

#[cfg(not(feature = "std"))]
pub fn endpoint_definition(ep: DataEndpoint) -> Option<EndpointDefinition> {
    known_endpoints().into_iter().find(|def| def.id == ep)
}

#[cfg(not(feature = "std"))]
pub fn data_type_definition(ty: DataType) -> Option<DataTypeDefinition> {
    known_data_types().into_iter().find(|def| def.id == ty)
}

#[cfg(not(feature = "std"))]
pub fn endpoint_definition_by_name(name: &str) -> Option<EndpointDefinition> {
    known_endpoints().into_iter().find(|def| def.name == name)
}

#[cfg(not(feature = "std"))]
pub fn data_type_definition_by_name(name: &str) -> Option<DataTypeDefinition> {
    known_data_types().into_iter().find(|def| def.name == name)
}

#[cfg(not(feature = "std"))]
pub fn remove_endpoint(_ep: DataEndpoint) -> TelemetryResult<bool> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn remove_endpoint_by_name(_name: &str) -> TelemetryResult<bool> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn remove_data_type(_ty: DataType) -> TelemetryResult<bool> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn remove_data_type_by_name(_name: &str) -> TelemetryResult<bool> {
    Err(TelemetryError::BadArg)
}

#[cfg(not(feature = "std"))]
pub fn get_endpoint_meta(endpoint_type: DataEndpoint) -> EndpointMeta {
    known_endpoints()
        .iter()
        .find(|def| def.id == endpoint_type)
        .map(|def| EndpointMeta {
            name: def.name,
            description: def.description,
            link_local_only: def.link_local_only,
        })
        .unwrap_or(EndpointMeta {
            name: "UNKNOWN_ENDPOINT",
            description: "",
            link_local_only: false,
        })
}

#[cfg(not(feature = "std"))]
pub fn get_message_meta(data_type: DataType) -> MessageMeta {
    known_data_types()
        .iter()
        .find(|def| def.id == data_type)
        .map(|def| MessageMeta {
            name: def.name,
            description: def.description,
            element: def.element,
            endpoints: def.endpoints,
            reliable: def.reliable,
            priority: def.priority,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
        .unwrap_or(MessageMeta {
            name: "UNKNOWN_TYPE",
            description: "",
            element: MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
            endpoints: &[],
            reliable: ReliableMode::None,
            priority: 0,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        })
}

#[cfg(not(feature = "std"))]
pub fn max_endpoint_id() -> u32 {
    known_endpoints()
        .iter()
        .map(|def| def.id.as_u32())
        .max()
        .unwrap_or(DataEndpoint::TelemetryError.as_u32())
}

#[cfg(not(feature = "std"))]
pub fn max_data_type_id() -> u32 {
    known_data_types()
        .iter()
        .map(|def| def.id.as_u32())
        .max()
        .unwrap_or(DataType::DiscoverySchema.as_u32())
}

// -----------------------------------------------------------------------------
// Optional JSON seeding for std builds
// -----------------------------------------------------------------------------

#[cfg(feature = "std")]
pub fn register_schema_json_str(json: &str) -> TelemetryResult<()> {
    register_schema_json_bytes(json.as_bytes())
}

#[cfg(feature = "std")]
pub fn register_schema_json_bytes(json: &[u8]) -> TelemetryResult<()> {
    let cfg: JsonConfig =
        serde_json::from_slice(json).map_err(|_| TelemetryError::Unpack("schema json"))?;
    register_json_config(cfg, false)
}

#[cfg(feature = "std")]
pub fn register_schema_json_file(path: impl AsRef<std::path::Path>) -> TelemetryResult<()> {
    let json = std::fs::read_to_string(path).map_err(|_| TelemetryError::Io("schema json file"))?;
    register_schema_json_str(&json)
}

#[cfg(feature = "std")]
pub fn register_schema_json_path(path: &str) -> TelemetryResult<()> {
    register_schema_json_file(path)
}

#[cfg(not(feature = "std"))]
pub fn register_schema_json_bytes(_json: &[u8]) -> TelemetryResult<()> {
    Err(TelemetryError::BadArg)
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct JsonConfig {
    endpoints: Vec<JsonEndpoint>,
    types: Vec<JsonType>,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct JsonEndpoint {
    rust: Option<String>,
    name: String,
    #[serde(default, alias = "doc")]
    description: Option<String>,
    #[serde(default, alias = "link_local_only")]
    link_local_only: Option<bool>,
    #[serde(default, alias = "broadcast_mode")]
    broadcast_mode: Option<String>,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct JsonType {
    rust: Option<String>,
    name: String,
    #[serde(default, alias = "doc")]
    description: Option<String>,
    class: String,
    element: JsonElement,
    endpoints: Vec<String>,
    #[serde(default)]
    reliable: Option<bool>,
    #[serde(default)]
    reliable_mode: Option<String>,
    #[serde(default)]
    priority: Option<u8>,
    #[serde(default)]
    e2e_encryption: Option<String>,
}

fn parse_e2e_encryption_policy(raw: Option<&str>) -> TelemetryResult<E2eEncryptionPolicy> {
    match raw.unwrap_or("PreferOff") {
        "PreferOff" | "prefer_off" | "off" | "false" => Ok(E2eEncryptionPolicy::PreferOff),
        "PreferOn" | "prefer_on" | "preferred" | "true" => Ok(E2eEncryptionPolicy::PreferOn),
        "RequireOn" | "require_on" | "required" => Ok(E2eEncryptionPolicy::RequireOn),
        _ => Err(TelemetryError::BadArg),
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(tag = "kind")]
enum JsonElement {
    Static {
        data_type: String,
        count: Option<usize>,
    },
    Dynamic {
        data_type: String,
    },
}

#[cfg(feature = "serde")]
fn json_config_to_snapshot(
    cfg: JsonConfig,
    link_local_overlay: bool,
    mut next_endpoint_id: u32,
    mut next_type_id: u32,
) -> TelemetryResult<RuntimeSchemaSnapshot> {
    let mut endpoint_ids: Vec<(String, DataEndpoint)> = Vec::new();
    let mut endpoints = Vec::with_capacity(cfg.endpoints.len());
    for ep in cfg.endpoints {
        let rust_name = ep.rust.clone().unwrap_or_else(|| ep.name.clone());
        let link_local = link_local_overlay
            || ep.link_local_only.unwrap_or(false)
            || matches!(ep.broadcast_mode.as_deref(), Some("Never"));
        let id = known_endpoint_compat_id(&rust_name).unwrap_or_else(|| {
            let id = DataEndpoint(next_endpoint_id);
            next_endpoint_id = next_endpoint_id.saturating_add(1);
            id
        });
        next_endpoint_id = next_endpoint_id.max(id.0.saturating_add(1));
        endpoints.push(EndpointDefinition {
            id,
            name: leak_str(ep.name),
            description: leak_str(ep.description.unwrap_or_default()),
            link_local_only: link_local,
        });
        endpoint_ids.push((rust_name, id));
    }

    let mut types = Vec::with_capacity(cfg.types.len());
    for ty in cfg.types {
        let rust_name = ty.rust.clone().unwrap_or_else(|| ty.name.clone());
        let endpoints_for_type: Vec<DataEndpoint> = ty
            .endpoints
            .iter()
            .map(|name| {
                endpoint_ids
                    .iter()
                    .find(|(ep_name, _)| ep_name == name)
                    .map(|(_, id)| *id)
                    .ok_or(TelemetryError::BadArg)
            })
            .collect::<TelemetryResult<Vec<_>>>()?;
        let id = known_type_compat_id(&rust_name).unwrap_or_else(|| {
            let id = DataType(next_type_id);
            next_type_id = next_type_id.saturating_add(1);
            id
        });
        next_type_id = next_type_id.max(id.0.saturating_add(1));
        let class = parse_message_class(&ty.class)?;
        let element = match ty.element {
            JsonElement::Static { data_type, count } => MessageElement::Static(
                count.unwrap_or(1),
                parse_message_data_type(&data_type)?,
                class,
            ),
            JsonElement::Dynamic { data_type } => {
                MessageElement::Dynamic(parse_message_data_type(&data_type)?, class)
            }
        };
        let reliable = match ty.reliable_mode.as_deref() {
            Some("Ordered") => ReliableMode::Ordered,
            Some("Unordered") => ReliableMode::Unordered,
            Some("None") | None => {
                if ty.reliable.unwrap_or(false) {
                    ReliableMode::Ordered
                } else {
                    ReliableMode::None
                }
            }
            _ => return Err(TelemetryError::BadArg),
        };
        types.push(DataTypeDefinition {
            id,
            name: leak_str(ty.name),
            description: leak_str(ty.description.unwrap_or_default()),
            element,
            endpoints: leak_endpoints(endpoints_for_type),
            reliable,
            priority: ty.priority.unwrap_or(0),
            e2e_encryption: parse_e2e_encryption_policy(ty.e2e_encryption.as_deref())?,
        });
    }
    Ok(RuntimeSchemaSnapshot { endpoints, types })
}

#[cfg(feature = "serde")]
pub fn schema_snapshot_from_json_bytes(json: &[u8]) -> TelemetryResult<RuntimeSchemaSnapshot> {
    let cfg: JsonConfig =
        serde_json::from_slice(json).map_err(|_| TelemetryError::Unpack("schema json"))?;
    json_config_to_snapshot(cfg, false, 100, 100)
}

#[cfg(feature = "std")]
fn register_json_config(cfg: JsonConfig, link_local_overlay: bool) -> TelemetryResult<()> {
    let mut reg = registry().lock().expect("schema registry poisoned");
    register_json_config_into(&mut reg, cfg, link_local_overlay)
}

#[cfg(feature = "std")]
fn register_json_config_into(
    reg: &mut Registry,
    cfg: JsonConfig,
    link_local_overlay: bool,
) -> TelemetryResult<()> {
    let snapshot = json_config_to_snapshot(
        cfg,
        link_local_overlay,
        reg.next_endpoint_id,
        reg.next_type_id,
    )?;
    register_schema_snapshot_into(reg, snapshot)
}

#[cfg(feature = "std")]
fn register_schema_snapshot_into(
    reg: &mut Registry,
    snapshot: RuntimeSchemaSnapshot,
) -> TelemetryResult<()> {
    for endpoint in snapshot.endpoints {
        reg.register_endpoint_definition(endpoint)?;
    }
    for ty in snapshot.types {
        reg.register_type_definition(ty)?;
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn known_endpoint_compat_id(name: &str) -> Option<DataEndpoint> {
    match name {
        "SdCard" => Some(DataEndpoint(100)),
        "Radio" => Some(DataEndpoint(101)),
        "SoftwareBus" => Some(DataEndpoint(102)),
        _ => None,
    }
}

#[cfg(feature = "serde")]
fn known_type_compat_id(name: &str) -> Option<DataType> {
    match name {
        "GpsData" => Some(DataType(100)),
        "ImuData" => Some(DataType(101)),
        "BatteryStatus" => Some(DataType(102)),
        "SystemStatus" => Some(DataType(103)),
        "BarometerData" => Some(DataType(104)),
        "MessageData" => Some(DataType(105)),
        "Heartbeat" => Some(DataType(106)),
        "IpcMessage" => Some(DataType(107)),
        _ => None,
    }
}

#[cfg(feature = "serde")]
fn parse_message_class(s: &str) -> TelemetryResult<MessageClass> {
    match s {
        "Data" => Ok(MessageClass::Data),
        "Error" => Ok(MessageClass::Error),
        "Warning" => Ok(MessageClass::Warning),
        _ => Err(TelemetryError::BadArg),
    }
}

#[cfg(feature = "serde")]
fn parse_message_data_type(s: &str) -> TelemetryResult<MessageDataType> {
    match s {
        "Float64" => Ok(MessageDataType::Float64),
        "Float32" => Ok(MessageDataType::Float32),
        "UInt8" => Ok(MessageDataType::UInt8),
        "UInt16" => Ok(MessageDataType::UInt16),
        "UInt32" => Ok(MessageDataType::UInt32),
        "UInt64" => Ok(MessageDataType::UInt64),
        "UInt128" => Ok(MessageDataType::UInt128),
        "Int8" => Ok(MessageDataType::Int8),
        "Int16" => Ok(MessageDataType::Int16),
        "Int32" => Ok(MessageDataType::Int32),
        "Int64" => Ok(MessageDataType::Int64),
        "Int128" => Ok(MessageDataType::Int128),
        "Bool" => Ok(MessageDataType::Bool),
        "String" => Ok(MessageDataType::String),
        "Binary" => Ok(MessageDataType::Binary),
        "NoData" => Ok(MessageDataType::NoData),
        _ => Err(TelemetryError::BadArg),
    }
}

#[cfg(all(test, feature = "std"))]
pub(crate) fn seed_test_schema() {
    static SEEDED: OnceLock<()> = OnceLock::new();
    SEEDED.get_or_init(|| {
        let _ = register_schema_json_str(include_str!("../telemetry_config.test.json"));
        let ipc = include_str!("../telemetry_config.ipc.test.json");
        let cfg: JsonConfig = serde_json::from_str(ipc).expect("test ipc schema json");
        let _ = register_json_config(cfg, true);
    });
}
