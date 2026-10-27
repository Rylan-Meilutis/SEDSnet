use super::*;
use crate::routing_config::RoutingRole;

#[test]
fn relay_role_allocates_no_local_services_and_cannot_originate_application_data() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::relay(), Box::new(|| 0));
    assert_eq!(node.cfg.role, RoutingRole::Relay);
    assert!(node.state.lock().local_services.is_none());
    assert!(node.isr_rx_queue.is_none());
    assert!(node.cfg.local.is_none());
    #[cfg(feature = "timesync")]
    {
        assert!(node.timesync.is_none());
        assert!(node.network_time().is_none());
        assert!(!node.poll_timesync().unwrap());
    }
    assert!(node.address_book().is_empty());
    let packet = Packet::new(
        DataType::named("GPS_DATA"),
        &[DataEndpoint::named("RADIO")],
        "SOURCE",
        123,
        Arc::<[u8]>::from([0u8; 12]),
    )
    .unwrap();
    let wire = wire_format::pack_packet(&packet);
    for result in [
        node.tx(packet.clone()),
        node.tx_queue(packet),
        node.tx_packed(wire.clone()),
        node.tx_packed_queue(wire.clone()),
        node.log(DataType::named("GPS_DATA"), &[0u8; 12]),
        node.log_queue(DataType::named("GPS_DATA"), &[0u8; 12]),
    ] {
        assert!(matches!(result, Err(TelemetryError::PermissionDenied)));
    }
    let stats = node.export_runtime_stats();
    assert_eq!(stats.queues.tx_len, 0);
    assert_eq!(stats.reliable.end_to_end_pending_count, 0);
    assert_eq!(node.state.lock().local_cache_bytes(), 0);
}

#[test]
fn relay_role_forwards_through_shared_engine_and_keeps_protocol_control_enabled() {
    crate::tests::ensure_common_test_schema();
    let node = Router::new_with_clock(RouterConfig::relay(), Box::new(|| 100));
    let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let ingress = node.add_side_packed("ingress", |_| Ok(()));
    let capture = sent.clone();
    node.add_side_packed("egress", move |bytes| {
        capture.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });
    node.announce_discovery().unwrap();
    node.process_all_queues().unwrap();
    assert!(sent.lock().unwrap().iter().any(|bytes| {
        wire_format::unpack_packet(bytes).is_ok_and(|p| discovery::is_discovery_type(p.data_type()))
    }));
    sent.lock().unwrap().clear();
    let packet = Packet::new(
        DataType::named("GPS_DATA"),
        &[DataEndpoint::named("RADIO")],
        "SOURCE",
        123,
        Arc::<[u8]>::from([0u8; 12]),
    )
    .unwrap();
    let id = packet.packet_id();
    node.rx_queue_from_side(packet, ingress).unwrap();
    assert_eq!(node.export_runtime_stats().queues.rx_len, 1);
    node.set_sender("RENAMED_RELAY");
    assert_eq!(node.sender().as_ref(), "RENAMED_RELAY");
    assert!(node.address_book().is_empty());
    assert_eq!(node.export_runtime_stats().queues.rx_len, 1);
    node.process_all_queues().unwrap();
    assert!(
        sent.lock()
            .unwrap()
            .iter()
            .any(|bytes| { wire_format::unpack_packet(bytes).is_ok_and(|p| p.packet_id() == id) })
    );
    assert!(node.state.lock().local_services.is_none());
}

#[test]
fn repeated_protocol_catalog_cannot_amplify_across_parallel_bridges() {
    crate::tests::ensure_common_test_schema();
    for relay_role in [false, true] {
        for packed in [false, true] {
            let cfg = if relay_role {
                RouterConfig::relay()
            } else {
                RouterConfig::default().with_sender("BRIDGE")
            };
            let node = Router::new_with_clock(cfg, Box::new(|| 0));
            let ingress = node.add_side_packed("ingress", |_| Ok(()));
            let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
            let capture = sent.clone();
            let egress = node.add_side_packed("shared-egress", move |bytes| {
                capture.lock().unwrap().push(bytes.to_vec());
                Ok(())
            });
            for peer in ["SINK_A", "SINK_B"] {
                node.rx_queue_from_side(
                    discovery::build_discovery_announce(peer, 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    egress,
                )
                .unwrap();
                node.drain_queues_with_timeout(0).unwrap();
            }
            let catalog = discovery::build_discovery_schema("SOURCE", 0).unwrap();
            let id = catalog.packet_id();
            let wire = wire_format::pack_packet(&catalog);
            let deliver = || {
                if packed {
                    node.rx_packed_queue_from_side(&wire, ingress).unwrap();
                } else {
                    node.rx_queue_from_side(catalog.clone(), ingress).unwrap();
                }
                node.drain_queues_with_timeout(0).unwrap();
            };
            deliver();
            let count = || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .filter_map(|b| wire_format::unpack_packet(b).ok())
                    .filter(|p| p.packet_id() == id)
                    .count()
            };
            assert_eq!(
                count(),
                1,
                "first complete catalog must still cross the bridge"
            );
            for _ in 0..16 {
                deliver();
            }
            assert_eq!(
                count(),
                1,
                "protocol catalog echoes are not application owner retries: role={relay_role} packed={packed}"
            );
            assert_eq!(node.export_runtime_stats().queues.rx_len, 0);
            assert_eq!(node.export_runtime_stats().queues.tx_len, 0);
        }
    }
}
