//! Compatibility facade for the forwarding-only role of the shared router.
//! All queue ownership, transport, discovery and reliability live in `Router`.
#[cfg(feature = "discovery")]
use crate::discovery::{ClientStatsSnapshot, TopologySnapshot};
use crate::{
    RouteSelectionMode, TelemetryError, TelemetryResult,
    config::RuntimeMemoryConfig,
    diagnostics::RuntimeStatsSnapshot,
    packet::Packet,
    router::{Clock, Router},
};
use alloc::{boxed::Box, string::String, sync::Arc};

pub type RelaySideId = usize;
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

pub use crate::routing_config::SideOptions as RelaySideOptions;

/// One side of the relay – a name + TX handler.
#[derive(Clone)]
pub struct RelaySide {
    pub name: Arc<str>,
    pub tx_handler: RelayTxHandlerFn,
    pub opts: RelaySideOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayItem {
    Packed(crate::SharedBytes),
    Packet(Arc<Packet>),
}

/// Compatibility builder backed by the same configuration as Router.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    core: crate::router::RouterConfig,
}

impl RelayConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sender<S: AsRef<str>>(mut self, sender: S) -> Self {
        self.core = self.core.with_sender(sender);
        self
    }

    pub fn with_memory_config(mut self, memory: RuntimeMemoryConfig) -> TelemetryResult<Self> {
        self.core = self.core.with_memory_config(memory)?;
        Ok(self)
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            core: crate::router::RouterConfig::relay(),
        }
    }
}

/// A forwarding-only view of the same engine used by Router.
/// It exposes no application publishing or local endpoint registration API.
pub struct Relay {
    pub(crate) core: Router,
}

impl Relay {
    pub fn new(clock: Box<dyn Clock + Send + Sync>) -> Self {
        Self::new_with_config(RelayConfig::default(), clock)
    }

    pub fn new_with_config(cfg: RelayConfig, clock: Box<dyn Clock + Send + Sync>) -> Self {
        Self {
            core: Router::new_with_clock(cfg.core, clock),
        }
    }

    pub fn sender(&self) -> Arc<str> {
        self.core.sender()
    }

    pub fn set_sender<S: AsRef<str>>(&self, sender: S) {
        self.core.set_sender(sender)
    }

    pub fn note_side_link_probe_sample(
        &self,
        side: RelaySideId,
        bytes: usize,
        duration_ms: u64,
    ) -> TelemetryResult<()> {
        self.core
            .note_side_link_probe_sample(side, bytes, duration_ms)
    }

    pub fn add_side_packed<N, F>(&self, name: N, tx: F) -> RelaySideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.core.add_side_packed(name, tx)
    }

    pub fn add_side_packed_small_packets<N, F>(
        &self,
        name: N,
        tx: F,
        max_frame_bytes: usize,
    ) -> RelaySideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.core
            .add_side_packed_small_packets(name, tx, max_frame_bytes)
    }

    pub fn add_side_packed_with_options<N, F>(
        &self,
        name: N,
        tx: F,
        opts: RelaySideOptions,
    ) -> RelaySideId
    where
        N: AsRef<str>,
        F: Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.core
            .add_side_packed_with_options(name, tx, legacy_chunk_options(opts))
    }

    pub fn add_side_packet<N, F>(&self, name: N, tx: F) -> RelaySideId
    where
        N: AsRef<str>,
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.core.add_side_packet(name, tx)
    }

    pub fn add_side_packet_with_options<N, F>(
        &self,
        name: N,
        tx: F,
        opts: RelaySideOptions,
    ) -> RelaySideId
    where
        N: AsRef<str>,
        F: Fn(&Packet) -> TelemetryResult<()> + Send + Sync + 'static,
    {
        self.core.add_side_packet_with_options(name, tx, opts)
    }

    pub fn remove_side(&self, side: RelaySideId) -> TelemetryResult<()> {
        self.core.remove_side(side)
    }

    pub fn set_side_ingress_enabled(
        &self,
        side: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        self.core.set_side_ingress_enabled(side, enabled)
    }

    pub fn set_side_egress_enabled(&self, side: RelaySideId, enabled: bool) -> TelemetryResult<()> {
        self.core.set_side_egress_enabled(side, enabled)
    }

    pub fn set_source_route_mode(
        &self,
        src: Option<RelaySideId>,
        mode: RouteSelectionMode,
    ) -> TelemetryResult<()> {
        self.core.set_source_route_mode(src, mode)
    }

    pub fn clear_source_route_mode(&self, src: Option<RelaySideId>) -> TelemetryResult<()> {
        self.core.clear_source_route_mode(src)
    }

    pub fn set_route_weight(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        weight: u32,
    ) -> TelemetryResult<()> {
        self.core.set_route_weight(src, dst, weight)
    }

    pub fn clear_route_weight(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
        self.core.clear_route_weight(src, dst)
    }

    pub fn set_route_priority(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        priority: u32,
    ) -> TelemetryResult<()> {
        self.core.set_route_priority(src, dst, priority)
    }

    pub fn clear_route_priority(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
        self.core.clear_route_priority(src, dst)
    }

    pub fn set_route(
        &self,
        src: Option<RelaySideId>,
        dst: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        self.core.set_route(src, dst, enabled)
    }

    pub fn set_typed_route(
        &self,
        src: Option<RelaySideId>,
        ty: crate::DataType,
        dst: RelaySideId,
        enabled: bool,
    ) -> TelemetryResult<()> {
        self.core.set_typed_route(src, ty, dst, enabled)
    }

    pub fn clear_typed_route(
        &self,
        src: Option<RelaySideId>,
        ty: crate::DataType,
        dst: RelaySideId,
    ) -> TelemetryResult<()> {
        self.core.clear_typed_route(src, ty, dst)
    }

    pub fn clear_route(&self, src: Option<RelaySideId>, dst: RelaySideId) -> TelemetryResult<()> {
        self.core.clear_route(src, dst)
    }

    #[cfg(feature = "discovery")]
    pub fn announce_discovery(&self) -> TelemetryResult<()> {
        self.core.announce_discovery()
    }

    #[cfg(feature = "discovery")]
    pub fn announce_leave(&self) -> TelemetryResult<()> {
        self.core.announce_leave()
    }

    #[cfg(feature = "discovery")]
    pub fn poll_discovery(&self) -> TelemetryResult<bool> {
        self.core.poll_discovery()
    }

    #[cfg(feature = "discovery")]
    pub fn export_topology(&self) -> TopologySnapshot {
        self.core.export_topology()
    }

    #[cfg(feature = "discovery")]
    pub fn client_stats(&self, sender_id: &str) -> Option<ClientStatsSnapshot> {
        self.core.client_stats(sender_id)
    }

    pub fn export_runtime_stats(&self) -> RuntimeStatsSnapshot {
        self.core.export_runtime_stats()
    }

    pub fn export_memory_layout_json(&self) -> String {
        self.core.export_memory_layout_json()
    }

    pub fn rx_packed_from_side(&self, src: RelaySideId, bytes: &[u8]) -> TelemetryResult<()> {
        self.core
            .rx_packed_queue_from_side(bytes, src)
            .map_err(legacy_ingress_error)
    }

    pub fn rx_from_side(&self, src: RelaySideId, packet: Packet) -> TelemetryResult<()> {
        self.core
            .rx_queue_from_side(packet, src)
            .map_err(legacy_ingress_error)
    }

    pub fn clear_queues(&self) {
        self.core.clear_queues()
    }

    pub fn clear_rx_queue(&self) {
        self.core.clear_rx_queue()
    }

    pub fn clear_tx_queue(&self) {
        self.core.clear_tx_queue()
    }

    pub fn process_rx_queue(&self) -> TelemetryResult<()> {
        self.core.process_rx_queue()
    }

    pub fn process_tx_queue(&self) -> TelemetryResult<()> {
        self.core.process_tx_queue()
    }

    pub fn process_all_queues(&self) -> TelemetryResult<()> {
        self.core.process_all_queues()
    }

    pub fn process_tx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.core.process_tx_queue_with_timeout(timeout_ms)
    }

    pub fn process_rx_queue_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.core.process_rx_queue_with_timeout(timeout_ms)
    }

    pub fn process_all_queues_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.core.process_all_queues_with_timeout(timeout_ms)
    }

    pub fn drain_queues_with_timeout(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.core.drain_queues_with_timeout(timeout_ms)
    }

    pub fn periodic(&self, timeout_ms: u32) -> TelemetryResult<()> {
        self.core.periodic(timeout_ms)
    }
}

// Internal legacy tests can inspect the actual shared engine. This is not a
// public delegation escape hatch: production Relay exposes only its facade.
#[cfg(test)]
impl core::ops::Deref for Relay {
    type Target = Router;
    fn deref(&self) -> &Router {
        &self.core
    }
}

// Legacy Relay treated a finite packed-frame size as implicit template mode,
// even when the caller left the old header flag false. Normalize that preset
// once at the facade boundary; the common codec/configuration remains singular.
fn legacy_chunk_options(mut opts: RelaySideOptions) -> RelaySideOptions {
    if opts.max_frame_bytes != 0 {
        opts.header_template_enabled = true;
    }
    opts
}
fn legacy_ingress_error(error: TelemetryError) -> TelemetryError {
    match error {
        TelemetryError::HandlerError("router: invalid side id") => {
            TelemetryError::HandlerError("relay: invalid side id")
        }
        other => other,
    }
}
