//! Public-API compatibility with the last standalone Relay implementation.
#![cfg(feature = "std")]
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{self, DataEndpoint, DataType},
    packet::Packet,
    relay::{Relay, RelayConfig, RelaySideOptions},
    wire_format,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
const EP: DataEndpoint = DataEndpoint(50);
const TY: DataType = DataType(99);
fn options(name: &str) -> RelaySideOptions {
    match name {
        "default" => RelaySideOptions::default(),
        "frame110_templates_false" => RelaySideOptions {
            max_frame_bytes: 110,
            header_template_enabled: false,
            ..Default::default()
        },
        "frame400_templates_false" => RelaySideOptions {
            max_frame_bytes: 400,
            header_template_enabled: false,
            ..Default::default()
        },
        "template" => RelaySideOptions::default()
            .with_template_transport()
            .with_point_to_point(),
        "small_packet110" => RelaySideOptions::default()
            .with_small_packet_transport(110)
            .with_point_to_point(),
        _ => panic!("unrecognized frozen legacy fixture"),
    }
}
fn node(sender: &str) -> Relay {
    Relay::new_with_config(RelayConfig::new().with_sender(sender), Box::new(|| 0))
}
fn normalize_link_identifiers(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .map(|frame| {
            let mut wire = frame.clone();
            let kind = wire[0];
            if kind & 0x60 != 0x60 {
                return wire;
            }
            match kind {
                // Chunk: transfer ids are content hashes of the sender's frame.
                0x61 => {
                    assert!(wire.len() >= 8);
                    wire[1..3].fill(0);
                }
                // FULL and COMPACT: template ids are local dictionary keys.
                // Version-independent byte identity is proved after COMPLETE
                // CRC-checked decoding.
                0x60 | 0x70..=0x73 => {
                    let start = 1;
                    let mut end = start;
                    loop {
                        let byte = wire[end];
                        end += 1;
                        if byte & 128 == 0 {
                            break;
                        }
                        assert!(end - start < 5);
                    }
                    wire.splice(start..end, [1]);
                }
                _ => panic!("unexpected frozen fixture frame kind"),
            }
            let end = wire.len();
            wire[end - 4..].fill(0);
            wire
        })
        .collect()
}

fn receive(name: &str, frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let receiver = node("NEW_RECEIVER");
    let input = receiver.add_side_packed_with_options("wire", |_| Ok(()), options(name));
    let canonical = Arc::new(Mutex::new(Vec::new()));
    let out = canonical.clone();
    receiver.add_side_packet("sink", move |packet| {
        if packet.data_type() == TY {
            out.lock()
                .unwrap()
                .push(wire_format::pack_packet(packet).to_vec());
        }
        Ok(())
    });
    receiver.clear_queues();
    for frame in frames {
        receiver.rx_packed_from_side(input, frame).unwrap();
        receiver.drain_queues_with_timeout(0).unwrap();
    }
    canonical.lock().unwrap().clone()
}
fn assert_public_replay_statistics_partition_one_shared_queue() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let ty = DataType(900_001);
    config::register_data_type_id_with_description(
        ty,
        "INTEROP_RELIABLE_SAMPLE",
        "public replay diagnostic contract",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[EP],
        ReliableMode::Ordered,
        37,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let read = clock.clone();
    let relay = Relay::new_with_config(
        RelayConfig::new().with_sender("REPLAY_BRIDGE"),
        Box::new(move || read.load(Ordering::Relaxed)),
    );
    let input = relay.add_side_packet("source", |_| Ok(()));
    let ready = Arc::new(AtomicBool::new(true));
    let available = ready.clone();
    relay.add_side_packed_with_options(
        "wire",
        move |_| {
            if available.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(sedsnet::TelemetryError::Io("side tx busy"))
            }
        },
        RelaySideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    relay.clear_queues();
    relay
        .rx_from_side(
            input,
            Packet::new(ty, &[EP], "PUBLISHER", 1000, Arc::<[u8]>::from([7u8])).unwrap(),
        )
        .unwrap();
    relay.drain_queues_with_timeout(0).unwrap();
    ready.store(false, Ordering::Relaxed);
    clock.store(
        config::runtime_reliable_retransmit_ms() + 1,
        Ordering::Relaxed,
    );
    relay.drain_queues_with_timeout(0).unwrap();
    let stats = relay.export_runtime_stats();
    assert_eq!(
        stats.queues.replay_len, 1,
        "refused hop replay remains owned"
    );
    assert_eq!(
        stats.queues.tx_len, 0,
        "a shared replay marker is not an original publication"
    );
    assert!(stats.queues.replay_bytes > 0);
    let memory: Value = serde_json::from_str(&relay.export_memory_layout_json()).unwrap();
    assert_eq!(memory["replay_queue_len"], 1);
    assert_eq!(memory["tx_queue_len"], 0);
    assert_eq!(memory["tx_queue_bytes_used"], 0);
    assert_eq!(memory["replay_queue_bytes_used"], stats.queues.replay_bytes);
}
#[test]
fn public_relay_preserves_legacy_wire_and_canonical_identity() {
    config::register_endpoint_id_with_description(
        EP,
        "LEGACY_INTEROP_SINK",
        "explicit application fixture",
        false,
    )
    .unwrap();
    config::register_data_type_id_with_description(
        TY,
        "LEGACY_INTEROP_SAMPLES",
        "explicit application fixture",
        MessageElement::Static(256, MessageDataType::UInt8, MessageClass::Data),
        &[EP],
        ReliableMode::None,
        37,
    )
    .unwrap();
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/relay-wire-c324.json")).unwrap();
    let mut new_transmissions = Vec::new();
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let expected: Vec<Vec<u8>> = scenario["canonical_packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| serde_json::from_value(p["wirebytes"].clone()).unwrap())
            .collect();
        // Frames a SEDSnet 7 transmitter produced for these packets
        // (regenerate with SEDSNET_RELAY_INTEROP_REGENERATE=1 and
        // SEDSNET_RELAY_INTEROP_OUTPUT=<path> after an intended wire change).
        let old_frames: Vec<Vec<u8>> =
            serde_json::from_value(scenario["old_tx_frames"].clone()).unwrap();
        let regenerate = std::env::var_os("SEDSNET_RELAY_INTEROP_REGENERATE").is_some();
        let receiver = node("NEW_RECEIVER");
        let input = receiver.add_side_packed_with_options("wire", |_| Ok(()), options(name));
        let canonical = Arc::new(Mutex::new(Vec::new()));
        let received = canonical.clone();
        receiver.add_side_packet("sink", move |packet| {
            if packet.data_type() == TY {
                received
                    .lock()
                    .unwrap()
                    .push(wire_format::pack_packet(packet).to_vec());
            }
            Ok(())
        });
        receiver.clear_queues();
        for bytes in old_frames.iter().filter(|_| !regenerate) {
            receiver.rx_packed_from_side(input, bytes).unwrap();
            receiver.drain_queues_with_timeout(0).unwrap();
        }
        if !regenerate {
            assert_eq!(
                *canonical.lock().unwrap(),
                expected,
                "recorded TX -> RX {name}: exact canonical bytes/identity/timestamp"
            );
        }
        let transmitter = node("NEW_BRIDGE");
        let source = transmitter.add_side_packet("source", |_| Ok(()));
        let frames = Arc::new(Mutex::new(Vec::new()));
        let capture = frames.clone();
        transmitter.add_side_packed_with_options(
            "wire",
            move |bytes| {
                capture.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            options(name),
        );
        transmitter.clear_queues();
        for bytes in &expected {
            let packet: Packet = wire_format::unpack_packet(bytes).unwrap();
            transmitter.rx_from_side(source, packet).unwrap();
            transmitter.drain_queues_with_timeout(0).unwrap();
        }
        assert_eq!(
            receive(name, &frames.lock().unwrap()),
            expected,
            "new TX -> complete receiver {name}: canonical byte identity and CRC"
        );
        if !regenerate {
            assert_eq!(
                normalize_link_identifiers(&frames.lock().unwrap()),
                normalize_link_identifiers(&old_frames),
                "{name}: recorded/new wire shapes differ beyond internal link identifiers"
            );
        }
        new_transmissions.push(json!({"name": name, "frames": *frames.lock().unwrap(), "expected_canonical_packets": expected}));
    }
    assert_public_replay_statistics_partition_one_shared_queue();
    if let Some(path) = std::env::var_os("SEDSNET_RELAY_INTEROP_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&new_transmissions).unwrap()).unwrap();
    }
}
