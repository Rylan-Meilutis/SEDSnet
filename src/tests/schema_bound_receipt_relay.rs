//! Actual three-node transport ownership: Publisher -> forwarding-only Relay -> shared receiver.
//! Included as a child of router.rs; all owner mutation goes through actual public receive/send.
use super::*;
use crate::relay::{Relay, RelayConfig, RelaySideOptions};
use std::sync::Mutex;

type CapturedWire = Arc<Mutex<Vec<Vec<u8>>>>;

fn capture() -> (CapturedWire, impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static) {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let output = frames.clone();
    (frames, move |wire| {
        output.lock().unwrap().push(wire.to_vec());
        Ok(())
    })
}

// Relay facade ingress is asynchronous; exercise its actual queue worker before assertions.
// No periodic announcements or clock advance are introduced by this drain.
fn relay_receive(relay: &Relay, side: usize, wire: &[u8]) {
    relay.rx_packed_from_side(side, wire).unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
}

fn schema_wire(frames: &CapturedWire, original: u64) -> Vec<u8> {
    frames
        .lock()
        .unwrap()
        .iter()
        .find(|wire| {
            wire_format::unpack_packet(wire).is_ok_and(|packet| {
                packet.data_type() == DataType::DiscoverySchema && packet.packet_id() == original
            })
        })
        .expect("the actual transport must emit this original Schema")
        .clone()
}

fn bound_receipt_wire(frames: &CapturedWire, original: u64) -> Vec<u8> {
    frames
        .lock()
        .unwrap()
        .iter()
        .find(|wire| {
            wire_format::unpack_packet(wire).is_ok_and(|packet| {
                packet.data_type() == DataType::ReliableAck
                    && packet.payload() == original.to_le_bytes()
                    && packet.wire_target_senders().len() == 2
            })
        })
        .expect("successful actual shared Schema reception must emit its exact bound receipt")
        .clone()
}

fn history(relay: &Relay, side: usize) -> Vec<(u32, u64)> {
    let rows = {
        let state = relay.core.state.lock();
        state.reliable_tx.get(&(side, DataType::DiscoverySchema.as_u32()))
            .map(|stream| stream.sent_order.iter().map(|seq| {
                (*seq, stream.sent.get(seq).expect("ordered row has retained bytes").bytes.clone())
            }).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    // Decode outside the actual Core owner, including in read-only assertions.
    rows.into_iter().map(|(seq, bytes)| {
        let packet = wire_format::unpack_packet(bytes.as_ref()).unwrap();
        (seq, packet.packet_id())
    }).collect()
}

fn synthetic_receipt(receiver: &Router, id: u64, publisher_hash: u64) -> Vec<u8> {
    match receiver.build_end_to_end_ack_data(id, publisher_hash).unwrap() {
        RouterItem::Packet(packet) => wire_format::pack_packet(&packet).as_ref().to_vec(),
        RouterItem::Packed(bytes) => bytes.as_ref().to_vec(),
    }
}

#[test]
fn actual_relay_owned_schema_accepts_publisher_bound_receipt_without_local_service_authority() {
    // Seed before any fixture memory observation; no production schema/default changes.
    let _ = crate::config::try_get_message_meta(DataType::TelemetryError);
    crate::tests::ensure_common_test_schema();
    let publisher = Router::new_with_clock(
        RouterConfig::default().with_sender("SCHEMA_ORIGIN"), Box::new(|| 1000),
    );
    let relay = Relay::new_with_config(
        RelayConfig::default().with_sender("SCHEMA_RELAY"), Box::new(|| 1000),
    );
    let receiver = Router::new_with_clock(
        RouterConfig::default().with_sender("SCHEMA_RECEIVER"), Box::new(|| 1000),
    );
    assert!(!relay.core.cfg.role.local_services());
    assert!(relay.core.state.lock().local_services.is_none());
    let (publisher_wire, publisher_output) = capture();
    publisher.add_side_packed("publisher-to-relay", publisher_output);
    let ingress = relay.add_side_packed("relay-upstream", |_| Ok(()));
    let (relay_wire, relay_output) = capture();
    let egress = relay.add_side_packed_with_options(
        "relay-shared-downstream", relay_output,
        RelaySideOptions { reliable_enabled: true, ..Default::default() },
    );
    let (receiver_wire, receiver_output) = capture();
    let receiver_side = receiver.add_side_packed_with_options(
        "receiver-shared", receiver_output,
        RouterSideOptions { reliable_enabled: true, ..Default::default() },
    );
    // Actual discovery teaches the original name upstream. Receiver observes two real
    // logical announcers on its shared side; the relay itself has no multi-peer egress hint.
    let origin_announce = discovery::build_discovery_announce(
        "SCHEMA_ORIGIN", 1000, &[DataEndpoint::Discovery],
    ).unwrap();
    let origin_wire = wire_format::pack_packet(&origin_announce);
    relay_receive(&relay, ingress, origin_wire.as_ref());
    receiver.rx_packed_from_side(origin_wire.as_ref(), receiver_side).unwrap();
    let relay_announce = discovery::build_discovery_announce(
        "SCHEMA_RELAY", 1000, &[DataEndpoint::Discovery],
    ).unwrap();
    receiver.rx_packed_from_side(
        wire_format::pack_packet(&relay_announce).as_ref(), receiver_side,
    ).unwrap();
    assert!(receiver.side_has_multiple_announcers_locked(
        &receiver.state.lock(), receiver_side, 1000,
    ));
    assert!(!relay.core.side_has_multiple_announcers_locked(
        &relay.core.state.lock(), egress, 1000,
    ));
    publisher.clear_queues(); relay.clear_queues(); receiver.clear_queues();
    publisher_wire.lock().unwrap().clear();
    relay_wire.lock().unwrap().clear(); receiver_wire.lock().unwrap().clear();

    let first = discovery::build_discovery_schema("SCHEMA_ORIGIN", 1001).unwrap();
    let second = discovery::build_discovery_schema("SCHEMA_ORIGIN", 1002).unwrap();
    let first_id = first.packet_id(); let second_id = second.packet_id();
    assert_ne!(first_id, second_id);
    for packet in [first, second] {
        let id = packet.packet_id();
        publisher.tx(packet).unwrap();
        relay_receive(&relay, ingress, &schema_wire(&publisher_wire, id));
    }
    let retained = history(&relay, egress);
    assert_eq!(retained.len(), 2, "actual relay output must retain two hop owners");
    assert_eq!(retained.iter().map(|(_, id)| *id).collect::<Vec<_>>(), vec![first_id, second_id]);
    let first_wire = schema_wire(&relay_wire, first_id);
    let forwarded = wire_format::unpack_packet(&first_wire).unwrap();
    assert_eq!(sender_address_u32(forwarded.sender()), sender_address_u32("SCHEMA_ORIGIN"));
    assert_ne!(sender_address_u32(forwarded.sender()), sender_address_u32(relay.sender().as_ref()));
    let first_header = wire_format::peek_routing_frame_info(&first_wire).unwrap().reliable.unwrap();
    assert_eq!(first_header.seq, retained[0].0);

    receiver.rx_packed_from_side(&first_wire, receiver_side).unwrap();
    receiver.process_all_queues().unwrap();
    let receipt = bound_receipt_wire(&receiver_wire, first_id);
    let decoded = wire_format::unpack_packet(&receipt).unwrap();
    let publisher_hash = Router::sender_hash("SCHEMA_ORIGIN");
    assert_eq!(decoded.wire_target_senders()[1], publisher_hash);
    assert_ne!(decoded.wire_target_senders()[1], Router::sender_hash(relay.sender().as_ref()));

    assert_ne!(first_id ^ 1, second_id, "negative ID must not target the other accepted original");
    // Controlled negative packets use the actual receipt encoder; no retained owner is injected.
    relay_receive(&relay, ingress, &receipt);
    assert_eq!(history(&relay, egress), retained, "another ingress cannot clear this hop");
    for wrong in [
        synthetic_receipt(&receiver, first_id, Router::sender_hash("WRONG_ORIGINAL_PUBLISHER")),
        synthetic_receipt(&receiver, first_id ^ 1, publisher_hash),
    ] {
        relay_receive(&relay, egress, &wrong);
        assert_eq!(history(&relay, egress), retained, "wrong publisher/ID is not completion");
    }
    relay_receive(&relay, egress, &receipt);
    assert_eq!(history(&relay, egress), vec![retained[1]], "exact receipt clears only first relay-owned hop");
    relay_receive(&relay, egress, &receipt);
    assert_eq!(history(&relay, egress), vec![retained[1]], "duplicate receipt cannot clear another original");
    receiver.rx_packed_from_side(&schema_wire(&relay_wire, second_id), receiver_side).unwrap();
    receiver.process_all_queues().unwrap();
    relay_receive(&relay, egress, &bound_receipt_wire(&receiver_wire, second_id));
    assert!(history(&relay, egress).is_empty());
    assert!(relay.core.state.lock().local_services.is_none());
}
