//! Additive conservative accounting for no-eviction prepared admission.
use super::*;
impl RouterInner {
    #[cfg(feature = "discovery")]
    fn topology_board_byte_cost_saturated(board: &TopologyBoardNode) -> usize {
        board
            .sender_id
            .len()
            .saturating_add(
                board
                    .reachable_endpoints
                    .len()
                    .saturating_mul(size_of::<DataEndpoint>()),
            )
            .saturating_add(
                board
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                board
                    .connections
                    .iter()
                    .map(|s| s.len())
                    .fold(0usize, usize::saturating_add),
            )
    }
    #[cfg(feature = "discovery")]
    fn discovery_sender_byte_cost_saturated(sender: &str, state: &DiscoverySenderState) -> usize {
        sender
            .len()
            .saturating_add(
                state
                    .reachable
                    .len()
                    .saturating_mul(size_of::<DataEndpoint>()),
            )
            .saturating_add(
                state
                    .advertised_reachable
                    .len()
                    .saturating_mul(size_of::<DataEndpoint>()),
            )
            .saturating_add(
                state
                    .reachable_network_variables
                    .len()
                    .saturating_mul(size_of::<DataType>()),
            )
            .saturating_add(
                state
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                state
                    .advertised_reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                state
                    .topology_boards
                    .iter()
                    .map(Self::topology_board_byte_cost_saturated)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(crate::peer_record::allocation_bytes::<DiscoverySenderState>())
    }
    #[cfg(feature = "discovery")]
    fn discovery_route_byte_cost_saturated(
        side: RouterSideId,
        route: &DiscoverySideState,
    ) -> usize {
        size_of::<RouterSideId>()
            .saturating_add(size_of::<DiscoverySideState>())
            .saturating_add(
                route
                    .reachable
                    .len()
                    .saturating_mul(size_of::<DataEndpoint>()),
            )
            .saturating_add(
                route
                    .reachable_network_variables
                    .len()
                    .saturating_mul(size_of::<DataType>()),
            )
            .saturating_add(
                route
                    .requested_network_variables
                    .len()
                    .saturating_mul(size_of::<ManagedVariableSubscription>()),
            )
            .saturating_add(
                route
                    .reachable_timesync_sources
                    .iter()
                    .map(|s| s.len())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                route
                    .announcers
                    .iter()
                    .map(|(sender, state)| {
                        Self::discovery_sender_byte_cost_saturated(sender, state)
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(side.saturating_sub(side))
    }
    #[cfg(feature = "discovery")]
    fn discovery_bytes_used_saturated(&self) -> usize {
        self.discovery_routes
            .iter()
            .map(|(side, route)| Self::discovery_route_byte_cost_saturated(*side, route))
            .fold(0usize, usize::saturating_add)
    }
    pub(in crate::router) fn queued_packet_budget_used(
        &self,
        schema: &crate::config::PreparedSchemaGuard,
    ) -> usize {
        let mut used = self
            .received_queue
            .bytes_used()
            .saturating_add(self.transmit_queue.bytes_used());
        for side in self.side_transport.values() {
            used = used.saturating_add(side.rx_chunk_bytes);
            #[cfg(all(feature = "compression", feature = "discovery"))]
            {
                used = used.saturating_add(side.payload_codec.heap_bytes_saturated());
            }
        }
        for sent in self.end_to_end_reliable_tx.values() {
            used = used
                .saturating_add(PENDING_TYPE_METADATA_BYTES)
                .saturating_add(
                    usize::from(sent.completion_epoch != 0).saturating_mul(size_of::<u64>()),
                );
        }
        used = used.saturating_add(
            self.reliable_return_routes
                .len()
                .saturating_mul(RELIABLE_RETURN_ROUTE_EXTRA_LOGICAL_BYTES),
        );
        used = used.saturating_add(self.recent_rx.max_bytes());
        for bytes in self
            .reliable_rx
            .values()
            .flat_map(|state| state.buffered.values())
        {
            used = used
                .saturating_add(size_of::<crate::SharedBytes>())
                .saturating_add(bytes.len());
        }
        used = used.saturating_add(schema.bytes_used_saturated());
        #[cfg(feature = "discovery")]
        {
            used = used.saturating_add(self.discovery_bytes_used_saturated());
        }
        #[cfg(feature = "compression")]
        {
            used = used.saturating_add(self.codec_reserved_bytes);
        }
        used
    }
}
