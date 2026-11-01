//! Existing Relay contracts, exercised against the shared routing engine.
use super::*;
#[cfg(feature = "discovery")]
use crate::relay::RelayConfig;
use crate::relay::{Relay, RelaySideId, RelaySideOptions};

#[cfg(all(test, feature = "std"))]
#[path = "independent_side_tx_relay.rs"]
mod independent_side_tx;
#[cfg(all(test, feature = "std", feature = "discovery", feature = "compression"))]
#[path = "payload_codec_relay.rs"]
mod payload_codec_negotiation;
#[cfg(all(test, feature = "std"))]
#[path = "reliable_tx_window_backpressure_relay.rs"]
mod reliable_tx_window_backpressure_tests;
#[cfg(all(test, feature = "std", feature = "discovery"))]
#[path = "shared_chunk_budget_relay.rs"]
mod shared_chunk_budget_tests;
// Apply the same cache contract independently to router and relay state.
#[cfg(all(test, feature = "discovery"))]
#[path = "relay_ack_recovery.rs"]
mod ack_recovery_tests;
#[cfg(all(test, feature = "discovery"))]
#[path = "relay_ack_split_horizon.rs"]
mod ack_split_horizon;
#[cfg(all(test, feature = "std"))]
#[path = "relay_control_priority.rs"]
mod control_priority_tests;
#[cfg(all(test, feature = "std"))]
#[path = "replay_ownership_relay.rs"]
mod replay_ownership_tests;
#[cfg(all(test, feature = "discovery"))]
#[path = "relay_restart_transport.rs"]
mod restart_transport_tests;
#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "side_template_index.rs"]
mod side_template_index_tests;

#[cfg(all(test, feature = "discovery"))]
mod compact_summary_tests {
    use super::*;

    #[test]
    fn compact_loss_and_reordering_preserve_packet_identity() {
        crate::tests::ensure_common_test_schema();
        let tx = Relay::new(Box::new(|| 0));
        let rx = Relay::new(Box::new(|| 0));
        let opts = RelaySideOptions::default().with_small_packet_transport(0);
        let a = tx.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
        let b = rx.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
        let mut encoded = Vec::new();
        for timestamp in [10000, 10010, 10020, 10030] {
            let pkt = Packet::new(
                crate::DataType::named("GPS_DATA"),
                &[crate::DataEndpoint::named("RADIO")],
                "VB",
                timestamp,
                Arc::<[u8]>::from([0u8; 12]),
            )
            .unwrap();
            let raw = wire_format::pack_packet(&pkt);
            let frames = tx
                .encode_side_transport_frames(
                    a,
                    opts.clone(),
                    crate::shared_bytes::convert(raw.clone()),
                )
                .unwrap();
            assert_eq!(frames.len(), 1);
            encoded.push((raw, frames.into_iter().next().unwrap()));
        }
        // Establish template, lose frame 1, reorder and duplicate later frames.
        for index in [0, 3, 2, 3] {
            let (raw, frame) = &encoded[index];
            let received = rx.decode_side_transport_frame(b, frame).unwrap().unwrap();
            assert_eq!(&received, raw);
        }
    }

    #[test]
    fn relay_preserves_compact_routes_without_inventing_endpoint_ownership() {
        crate::tests::ensure_common_test_schema();
        let endpoint = crate::DataEndpoint::named("RADIO");
        let relay = Relay::new(Box::new(|| 0));
        let mut sender = DiscoverySenderState {
            advertised_reachable: vec![endpoint],
            advertised_reachable_timesync_sources: vec!["clock-behind-bridge".into()],
            topology_boards: Arc::new(vec![TopologyBoardNode {
                sender_id: "bridge".into(),
                reachable_endpoints: vec![],
                reachable_timesync_sources: vec![],
                connections: vec![],
            }]),
            ..Default::default()
        };
        Router::refresh_sender_topology_state(&mut sender);
        let mut route = DiscoverySideState::default();
        route.announcers.insert("bridge".into(), Box::new(sender));
        Router::recompute_discovery_side_state(&mut route);
        let mut state = relay.state.lock();
        state.discovery_routes.insert(0, route);
        assert!(
            relay
                .advertised_discovery_endpoints_for_link_locked(&state, 0, true, Some(1))
                .contains(&endpoint)
        );
        assert!(
            !relay
                .advertised_discovery_endpoints_for_link_locked(&state, 0, true, Some(0))
                .contains(&endpoint)
        );
        assert!(
            !relay
                .advertised_discovery_endpoints_for_link_locked(
                    &state,
                    DISCOVERY_ROUTE_TTL_MS + 1,
                    true,
                    Some(1)
                )
                .contains(&endpoint)
        );
        assert_eq!(
            relay.advertised_discovery_timesync_sources_for_link_locked(&state, 0, Some(1)),
            vec!["clock-behind-bridge".to_string()]
        );
        assert!(
            relay
                .advertised_discovery_timesync_sources_for_link_locked(&state, 0, Some(0))
                .is_empty()
        );
        assert!(
            relay
                .advertised_discovery_timesync_sources_for_link_locked(
                    &state,
                    DISCOVERY_ROUTE_TTL_MS + 1,
                    Some(1)
                )
                .is_empty()
        );
        let topology =
            relay.advertised_discovery_topology_for_link_locked(&state, 0, true, Some(1));
        assert!(
            topology
                .iter()
                .find(|node| node.sender_id == "bridge")
                .unwrap()
                .reachable_endpoints
                .is_empty()
        );
    }
}

#[cfg(all(test, feature = "std", feature = "discovery"))]
mod discovery_reclaim_tests {
    use super::*;
    use crate::DataType;
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn relay_discovery_reclaims_telemetry_without_discarding_controls() {
        crate::tests::ensure_common_test_schema();
        static REFUSALS: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn scratch_after_reclaim(additional: usize, _: usize) -> bool {
            additional < 2048 || REFUSALS.fetch_add(1, Ordering::SeqCst) >= 2
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::memory_admission::set_probe(None);
            }
        }
        let relay = Relay::new(Box::new(|| 1));
        let side = relay.add_side_packet("CAN", |_| Ok(()));
        for priority in [1, 2, 200, 254, 255] {
            relay
                .state
                .lock()
                .push_tx(RelayTxItem {
                    src: None,
                    dst: side,
                    data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(
                        [0; 32],
                    ))),
                    priority,
                    retry_after_ms: 0,
                })
                .unwrap();
        }
        REFUSALS.store(0, Ordering::SeqCst);
        let _reset = Reset;
        crate::memory_admission::set_probe(Some(scratch_after_reclaim));
        relay
            .emit_discovery_snapshot_on_side(true, false, true, true, None)
            .unwrap();
        let st = relay.state.lock();
        assert_eq!(
            st.transmit_queue.lowest_priority(|item| item.priority),
            Some(200)
        );
        for priority in [200, 254] {
            assert_eq!(
                st.transmit_queue
                    .iter()
                    .filter(|item| item.priority == priority)
                    .count(),
                1
            );
        }
        assert!(
            st.transmit_queue
                .iter()
                .any(|item| matches!(queued_data(item), RouterItem::Packet(pkt)
            if pkt.data_type() == DataType::DiscoveryLinkCapabilities))
        );
    }
}

#[cfg(all(test, feature = "std", feature = "discovery"))]
mod queued_schema_identity_tests {
    use super::*;

    fn catalog(timestamp: u64, byte: u8) -> Packet {
        Packet::new(
            crate::DataType::DiscoverySchema,
            &[crate::DataEndpoint::Discovery],
            "SCHEMA_PEER",
            timestamp,
            crate::shared_bytes::convert(Arc::<[u8]>::from(vec![byte; 1024])),
        )
        .unwrap()
    }

    #[test]
    fn repeated_schema_preserves_partial_transfer_but_updates_and_other_sides_do_not_coalesce() {
        let relay = Relay::new(Box::new(|| 0u64));
        let side = relay.add_side_packed("A", |_| Ok(()));
        let other_side = relay.add_side_packed("B", |_| Ok(()));
        let original = catalog(1, 42);
        let duplicate = catalog(2, 42);
        assert_ne!(original.packet_id(), duplicate.packet_id());
        let mut st = relay.state.lock();
        st.transmit_queue.clear();
        let queued = |dst, pkt| RelayTxItem {
            src: None,
            dst,
            data: RouterItem::Packet(pkt),
            priority: 255,
            retry_after_ms: 123,
        };
        st.push_tx(queued(side, original.clone())).unwrap();
        st.push_tx(queued(side, duplicate.clone())).unwrap();
        assert_eq!(st.transmit_queue.len(), 1);
        let pending = st.transmit_queue.iter().next().unwrap();
        assert_eq!(pending.retry_after_ms, 123);
        assert!(matches!(queued_data(pending), RouterItem::Packet(pkt)
            if pkt.packet_id() == original.packet_id()));
        st.push_tx(queued(other_side, duplicate)).unwrap();
        assert_eq!(st.transmit_queue.len(), 2);
        let changed = catalog(3, 43);
        st.push_tx(queued(side, changed.clone())).unwrap();
        assert_eq!(st.transmit_queue.len(), 2);
        assert!(
            st.transmit_queue
                .iter()
                .any(|queued| queued_destination(queued) == side
                    && matches!(queued_data(queued),
            RouterItem::Packet(pkt) if pkt.packet_id() == changed.packet_id()))
        );
    }

    #[test]
    fn repeated_announcements_complete_one_fragment_per_dispatch() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        let allowance = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(std::sync::Mutex::new(Vec::<Arc<[u8]>>::new()));
        let available = allowance.clone();
        let frames = accepted.clone();
        let node = Relay::new(Box::new(|| 1u64));
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
            RelaySideOptions::default().with_small_packet_transport(128),
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
                .push_tx(RelayTxItem {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(packet),
                    priority: 255,
                    retry_after_ms: 0,
                })
                .unwrap();
            let data = queued_data(node.state.lock().transmit_queue.iter().next().unwrap()).clone();
            allowance.store(1, Ordering::Relaxed);
            match node.call_side_tx_handler(side, &handler, &data, true) {
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
        let relay = Relay::new(Box::new(|| 0u64));
        let side = relay.add_side_packed("A", |_| Ok(()));
        let assigned = 0x1234u32;
        assert_ne!(sender_address_u32("SCHEMA_PEER"), assigned);
        {
            let mut st = relay.state.lock();
            st.discovery_routes
                .entry(side)
                .or_default()
                .announcers
                .insert(
                    "SCHEMA_PEER".into(),
                    Box::new(DiscoverySenderState {
                        advertised_address: Some(assigned),
                        ..DiscoverySenderState::default()
                    }),
                );
        }
        relay.note_schema_received(side, "@addr:4660");
        relay.note_schema_received(side, "@addr:4661");
        let st = relay.state.lock();
        let peers = &st.discovery_routes.get(&side).unwrap().announcers;
        assert_eq!(peers.len(), 1);
        assert!(peers["SCHEMA_PEER"].has_schema);
    }
}

#[cfg(all(test, feature = "discovery", feature = "std"))]
fn untemplated_test_node() -> Relay {
    Relay::new(Box::new(|| 0))
}
#[cfg(all(test, feature = "discovery", feature = "std"))]
fn untemplated_test_options() -> RelaySideOptions {
    RelaySideOptions::default().with_small_packet_transport(64)
}
#[cfg(all(test, feature = "discovery", feature = "std"))]
#[allow(clippy::duplicate_mod)]
#[path = "untemplated_transport.rs"]
mod untemplated_transport_tests;

#[cfg(all(test, feature = "std"))]
mod frozen_control_delivery_tests {
    use super::*;
    use crate::router::{NetworkVariablePermissions, Router, RouterConfig, RouterSideOptions};
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn control() -> Packet {
        let ep = crate::config::register_endpoint("FROZEN_RELAY_CONTROL", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "FROZEN_RELAY_CONTROL",
            "",
            crate::MessageElement::Static(
                1,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::None,
            16,
        )
        .unwrap();
        Packet::new_with_wire_contract(
            ty,
            &[ep],
            "GS",
            1,
            7,
            Arc::<[u8]>::from([1]),
            None,
            Arc::from([Router::sender_hash("FC")]),
        )
        .unwrap()
    }

    #[test]
    fn foreign_frozen_control_retains_priority_and_full_reserved_admission() {
        let packet = control();
        let bytes = wire_format::pack_packet(&packet);
        let relay = Relay::new(Box::new(|| 0u64));
        let side = relay.add_side_packed("radio", |_| Ok(()));
        relay.rx_packed_from_side(side, &bytes).unwrap();
        relay.clear_queues();
        let foreign = Router::new(RouterConfig::new([]).with_sender("FOREIGN"));
        let foreign_side = foreign.add_side_packed("radio", |_| Ok(()));
        foreign
            .rx_packed_queue_from_side(&bytes, foreign_side)
            .unwrap();
        foreign.clear_queues();
        assert_eq!(
            Router::router_item_priority(&RouterItem::Packet(packet)).unwrap(),
            254
        );
        assert_eq!(
            Router::router_item_priority(&RouterItem::Packed(crate::shared_bytes::convert(
                bytes.clone()
            )))
            .unwrap(),
            254
        );
        extern "C" fn protected_only(additional: usize, largest: usize, kind: u32) -> bool {
            kind == crate::memory_admission::WORK_SMALL_PROTECTED
                && (2048..=2432).contains(&additional)
                && largest <= 160
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::memory_admission::set_probe_v2(None);
            }
        }
        let _reset = Reset;
        crate::memory_admission::set_probe_v2(Some(protected_only));
        assert_eq!(wire_format::unpack_packet(&bytes).unwrap().payload(), &[1]);
        relay.rx_packed_from_side(side, &bytes).unwrap();
        foreign
            .rx_packed_queue_from_side(&bytes, foreign_side)
            .unwrap();
        let mut corrupt = bytes.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(relay.rx_packed_from_side(side, &corrupt).is_err());
    }

    #[test]
    fn best_effort_schema_frozen_contract_retries_through_standalone_relay() {
        let packet = control();
        let bytes = wire_format::pack_packet(&packet);
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let relay = Relay::new(Box::new(move || clock.load(Ordering::Relaxed)));
        let upstream = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = upstream.clone();
        let radio = relay.add_side_packed_with_options(
            "radio",
            move |bytes| {
                output.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RelaySideOptions {
                header_template_enabled: false,
                reliable_enabled: false,
                ..Default::default()
            },
        );
        let downstream = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = downstream.clone();
        let can = relay.add_side_packed_with_options(
            "CAN",
            move |bytes| {
                output.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RelaySideOptions {
                header_template_enabled: false,
                reliable_enabled: false,
                ..Default::default()
            },
        );
        relay.set_route(Some(radio), can, true).unwrap();
        relay.set_route(Some(can), radio, true).unwrap();
        let child = Router::new(RouterConfig::new([]).with_sender("FC"));
        child
            .enable_network_variable(packet.data_type(), NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        let effects = Arc::new(AtomicUsize::new(0));
        let count = effects.clone();
        child
            .on_network_variable_update(packet.data_type(), move |_| {
                count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .unwrap();
        let receipts = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let output = receipts.clone();
        let child_side = child.add_side_packed_with_options(
            "CAN",
            move |bytes| {
                output.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                header_template_enabled: false,
                reliable_enabled: false,
                ..Default::default()
            },
        );
        relay.clear_queues();
        child.clear_queues();
        for attempt in 0..3 {
            now.store(
                u64::from(crate::config::runtime_tuning_config().reliable_retransmit_ms) * attempt,
                Ordering::Relaxed,
            );
            relay.rx_packed_from_side(radio, &bytes).unwrap();
            relay.drain_queues_with_timeout(0).unwrap();
            let frames = core::mem::take(&mut *downstream.lock().unwrap());
            let values: Vec<_> = frames
                .into_iter()
                .filter(|bytes| wire_format::peek_envelope(bytes).unwrap().ty == packet.data_type())
                .collect();
            assert!(
                !values.is_empty(),
                "frozen Off-schema retry was swallowed by relay dedupe"
            );
            if attempt == 0 {
                continue;
            } // The first data transmission is lost.
            for bytes in values {
                child.rx_packed_queue_from_side(&bytes, child_side).unwrap();
            }
            child.drain_queues_with_timeout(0).unwrap();
            for bytes in core::mem::take(&mut *receipts.lock().unwrap()) {
                relay.rx_packed_from_side(can, &bytes).unwrap();
            }
            relay.drain_queues_with_timeout(0).unwrap();
            assert_eq!(
                effects.load(Ordering::Relaxed),
                1,
                "receipt retry repeated application effect"
            );
            assert!(
                core::mem::take(&mut *upstream.lock().unwrap())
                    .iter()
                    .any(|bytes| {
                        let ack = wire_format::unpack_packet(bytes).unwrap();
                        ack.data_type() == crate::DataType::ReliableAck
                            && ack.payload() == packet.packet_id().to_le_bytes()
                    }),
                "the endpoint receipt did not return through the relay"
            );
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod bounded_fair_queue_tests {
    use super::*;
    #[test]
    fn small_canonical_reports_survive_fast_senders_fixed_ring_bursts() {
        let ep = crate::config::register_endpoint("RELAY_SMALL_QUEUE_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "RELAY_SMALL_QUEUE_REPORT",
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
                let node = Relay::new(Box::new(|| 0));
                let make = |sender| {
                    RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                        &Packet::new(ty, &[ep], sender, 1, Arc::<[u8]>::from([1; 4])).unwrap(),
                    )))
                };
                let rx = |data| RouterRxItem {
                    src: Some(0),
                    data,
                    priority: 0,
                };
                let tx_item = |data| RelayTxItem {
                    src: None,
                    dst: 1,
                    data,
                    priority: 0,
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
                        st.push_tx(tx_item(make(sender))).unwrap();
                    } else {
                        st.push_rx(rx(make(sender))).unwrap();
                    }
                }
                let slow = wire_format::source_address_for_sender("SLOW");
                let retained = if tx {
                    st.transmit_queue.iter().any(|item| {
                        RouterInner::fair_bulk_owner(queued_data(item), item.priority) == Some(slow)
                    })
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
        let ep = crate::config::register_endpoint("RELAY_STREAM_QUEUE_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "RELAY_STREAM_QUEUE_FAST",
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
            "RELAY_STREAM_QUEUE_SLOW",
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
                    let node = Relay::new(Box::new(|| 0));
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
                        src: Some(0),
                        data,
                        priority: 0,
                    };
                    let tx_item = |data| RelayTxItem {
                        src: None,
                        dst: 1,
                        data,
                        priority: 0,
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
                            st.push_tx(tx_item(make(sender))).unwrap();
                        } else {
                            st.push_rx(rx(make(sender))).unwrap();
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
                            let data = queued_data(item);
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
        let ep = crate::config::register_endpoint("RELAY_QUEUE_FAIR_DEST", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "RELAY_QUEUE_FAIR_REPORT",
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
                    for next_sender in ["FAST", "NEW_SLOW"] {
                        let router = Relay::new(Box::new(|| 0));
                        let make = |sender| {
                            RouterItem::Packet(
                                Packet::new(ty, &[ep], sender, 1, Arc::<[u8]>::from([1; 64]))
                                    .unwrap(),
                            )
                        };
                        let rx = |data| RouterRxItem {
                            src: Some(0),
                            data,
                            priority: 0,
                        };
                        let tx_item = |data| RelayTxItem {
                            src: None,
                            dst: 1,
                            data,
                            priority: 0,
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
                                st.push_tx(tx_item(make(sender))).unwrap();
                            } else {
                                st.push_rx(rx(make(sender))).unwrap();
                            }
                        }
                        if mode == 2 {
                            st.memory.max_queue_budget = st.shared_queue_bytes_used();
                        }
                        if tx {
                            st.push_tx(tx_item(make(next_sender))).unwrap_or_else(|error| panic!("admit error {error:?}: mode={mode} tx={tx} slow_last={slow_last} incoming={next_sender}"));
                        } else {
                            st.push_rx(rx(make(next_sender))).unwrap_or_else(|error| panic!("admit error {error:?}: mode={mode} tx={tx} slow_last={slow_last} incoming={next_sender}"));
                        }
                        let slow = wire_format::source_address_for_sender("SLOW");
                        let retained = if tx {
                            st.transmit_queue.iter().any(|item| {
                                RouterInner::fair_bulk_owner(queued_data(item), item.priority)
                                    == Some(slow)
                            })
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
    let node = Relay::new_with_config(RelayConfig::default().with_sender("GB"), Box::new(|| 0));
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
    node.rx_from_side(side, baseline).unwrap();
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
        node.rx_from_side(side, update)
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
        let node = Relay::new(Box::new(|| 0));
        let mut st = node.state.lock();
        st.memory.max_queue_budget = 65536;
        st.received_queue = BoundedDeque::new(32768, 16 * size_of::<RouterRxItem>(), 1.0);
        let make = |sender: &str, stamp, priority| {
            let packet = Packet::new(ty, &[ep], sender, stamp, Arc::<[u8]>::from([0; 4])).unwrap();
            RouterRxItem {
                src: Some(0),
                data: RouterItem::Packet(packet),
                priority,
            }
        };
        st.push_rx(make("VALVE", 0, 0)).unwrap();
        let mut delivered = false;
        for tick in 1..=32u64 {
            for index in 0..3 {
                st.push_rx(make("DAQ", tick * 3 + index, 16)).unwrap();
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
        st.push_rx(make("VALVE", 100, 0)).unwrap();
        st.push_rx(make("VALVE", 101, 0)).unwrap();
        st.push_rx(make("DAQ", 102, 16)).unwrap();
        st.push_rx(make("COMMAND", 103, 254)).unwrap();
        assert_eq!(
            st.pop_received_fair().unwrap().priority,
            254,
            "a fairness turn must never delay protected control"
        );
        let mut first_slow = None;
        for tick in 0..=MAX_PRIORITY_BURST {
            st.push_rx(make("DAQ", 200 + u64::from(tick), 16)).unwrap();
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

#[derive(Clone)]
struct RelayTxItem {
    src: Option<usize>,
    dst: usize,
    data: RouterItem,
    priority: u8,
    retry_after_ms: u64,
}
impl RelayTxItem {
    fn into_shared(self) -> TxQueued {
        TxQueued {
            disposable: TX_DISPOSABLE,
            item: RouterTxItem::ToSide {
                src: self.src,
                dst: self.dst,
                data: self.data,
            },
            ignore_local: true,
            priority: self.priority,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: self.retry_after_ms,
        }
    }
}
impl ByteCost for RelayTxItem {
    fn byte_cost(&self) -> usize {
        self.clone().into_shared().byte_cost()
    }
}
impl RouterInner {
    fn push_tx(&mut self, item: RelayTxItem) -> TelemetryResult<()> {
        self.push_transmit(item.into_shared())
    }
    fn push_rx(&mut self, item: RouterRxItem) -> TelemetryResult<()> {
        self.push_received(item)
    }
}
impl Relay {
    #[cfg(feature = "discovery")]
    fn learn_discovery_item(&self, side: usize, data: &RouterItem) -> TelemetryResult<()> {
        match data {
            RouterItem::Packet(packet) => {
                self.core.learn_discovery_packet(packet, Some(side), true)?;
            }
            RouterItem::Packed(bytes) => {
                self.core.learn_discovery_packet(
                    &wire_format::unpack_packet(bytes.as_ref())?,
                    Some(side),
                    true,
                )?;
            }
        }
        Ok(())
    }
}

fn queued_data(queued: &TxQueued) -> &RouterItem {
    match &queued.item {
        RouterTxItem::ToSide { data, .. } | RouterTxItem::Broadcast(data) => data,
        _ => panic!("expected original publication, found replay marker"),
    }
}
#[cfg(feature = "discovery")]
fn queued_destination(queued: &TxQueued) -> usize {
    match &queued.item {
        RouterTxItem::ToSide { dst, .. } => *dst,
        _ => panic!("expected side-owned original publication"),
    }
}
/// Keep the baseline ACK outstanding: dispatch actual queued originals but do
/// not generate retries or consume shared replay markers in this cadence test.
#[cfg(feature = "discovery")]
fn drain_originals_without_reliable_timeouts(relay: &Relay) -> TelemetryResult<()> {
    loop {
        let queued = {
            let mut state = relay.state.lock();
            let at = state.transmit_queue.iter().position(|queued| {
                matches!(queued.item, RouterTxItem::ToSide { .. })
                    && queued.retry_after_ms <= relay.clock.now_ms()
            });
            at.and_then(|at| state.transmit_queue.remove_pos(at))
        };
        let Some(queued) = queued else {
            return Ok(());
        };
        relay.core.dispatch_queued_item(TxWork {
            queued,
            claim: None,
            owed_turn: false,
            #[cfg(feature = "latest-value-egress")]
            service: EgressService::default(),
        })?;
    }
}
