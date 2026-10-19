#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::{Arc, Mutex};

fn transfer(max_frame: usize, payload: &[u8]) -> (usize, usize) {
    let ep = register_endpoint_with_description(&format!("PACKING_DEST_{max_frame}"), "", false)
        .unwrap();
    let ty = register_data_type_with_description(
        &format!("PACKING_DATA_{max_frame}"),
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let output = received.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            ep,
            move |packet| {
                output.lock().unwrap().push(packet.payload().to_vec());
                Ok(())
            },
        )]),
        Box::new(|| 0),
    ));
    // Always use the smaller receiver, including the old128-byte sender case:
    // changing an outbound cap must not break mixed-firmware reception.
    let mut receive_options = RouterSideOptions::default().with_small_packet_transport(110);
    receive_options.max_side_transport_templates = 0;
    let ingress = receiver.add_side_packed_with_options("wire", |_| Ok(()), receive_options);
    let frames = Arc::new(Mutex::new(Vec::new()));
    let captured = frames.clone();
    let sink = receiver.clone();
    let sender = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let mut options = RouterSideOptions::default().with_small_packet_transport(max_frame);
    options.max_side_transport_templates = 0;
    let side = sender.add_side_packed_with_options(
        "wire",
        move |bytes| {
            captured.lock().unwrap().push(bytes.len());
            sink.rx_packed_from_side(bytes, ingress)
        },
        options,
    );
    sender
        .rx_from_side(
            &build_discovery_topology(
                "PACKING_SINK",
                0,
                &[TopologyBoardNode {
                    sender_id: "PACKING_SINK".into(),
                    reachable_endpoints: vec![ep],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }],
            )
            .unwrap(),
            side,
        )
        .unwrap();
    sender.drain_queues_with_timeout(0).unwrap();
    receiver.drain_queues_with_timeout(0).unwrap();
    frames.lock().unwrap().clear();
    received.lock().unwrap().clear();
    sender
        .tx(Packet::new(ty, &[ep], "PACKING_SOURCE", 1, Arc::from(payload)).unwrap())
        .unwrap();
    sender.drain_queues_with_timeout(0).unwrap();
    receiver.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        *received.lock().unwrap(),
        vec![payload.to_vec()],
        "full logical payload must arrive exactly once"
    );
    let lengths = frames.lock().unwrap();
    assert!(lengths.iter().all(|len| *len <= max_frame));
    // Existing hardware framing:55 payload bytes per fragment. Multipart
    // frames retain64-byte DLC, preserving compatibility with current peers.
    let physical_frames: usize = lengths.iter().map(|len| len.div_ceil(55)).sum();
    let padded_bytes: usize = lengths
        .iter()
        .map(|len| {
            if *len > 55 {
                len.div_ceil(55) * 64
            } else {
                let used = len + 9;
                [12, 16, 20, 24, 32, 48, 64]
                    .into_iter()
                    .find(|dlc| *dlc >= used)
                    .unwrap()
            }
        })
        .sum();
    (physical_frames, padded_bytes)
}

#[test]
fn aligned_chunks_reduce_physical_frames_without_reducing_logical_messages() {
    let mut state = 0x5EED1234u32;
    let payload: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let old = transfer(128, &payload);
    let aligned = transfer(110, &payload);
    println!(
        "4KiB logical payload: old {old:?}, aligned {aligned:?} (physical frames,padded bytes)"
    );
    assert!(aligned.0 < old.0 && aligned.1 < old.1);
}
