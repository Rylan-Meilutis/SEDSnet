use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::wire_format;
use std::sync::Arc;

const FLAG_COMPRESSED_PAYLOAD: u8 = 0x01;

fn make_message_packet(payload: &[u8], ts: u64) -> Packet {
    Packet::new(
        DataType::named("MESSAGE_DATA"),
        &[DataEndpoint::named("SD_CARD")],
        "CMP_NODE",
        ts,
        Arc::<[u8]>::from(payload),
    )
    .expect("packet build failed")
}

#[test]
fn compressible_payload_sets_compressed_flag_and_roundtrips() {
    let payload = vec![0u8; 4096];
    let pkt = make_message_packet(&payload, 11);

    let wire = wire_format::pack_packet(&pkt);
    assert_eq!(wire[0] & FLAG_COMPRESSED_PAYLOAD, FLAG_COMPRESSED_PAYLOAD);

    let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
    assert_eq!(decoded.payload(), payload.as_slice());
}

#[test]
fn below_threshold_payload_stays_uncompressed_and_roundtrips() {
    let payload = b"small-msg".to_vec();
    let pkt = make_message_packet(&payload, 22);

    let wire = wire_format::pack_packet(&pkt);
    assert_eq!(wire[0] & FLAG_COMPRESSED_PAYLOAD, 0);

    let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
    assert_eq!(decoded.payload(), payload.as_slice());
}

#[test]
fn mixed_payload_workload_roundtrips_without_failures() {
    for i in 0..1500u64 {
        let payload = if i % 2 == 0 {
            vec![b'Z'; 192]
        } else {
            let mut v = Vec::with_capacity(192);
            for j in 0..192u16 {
                v.push(32u8 + (((i as u16 + j) as u8) % 95));
            }
            v
        };

        let pkt = make_message_packet(&payload, i);
        let wire = wire_format::pack_packet(&pkt);
        let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
        assert_eq!(decoded.payload(), payload.as_slice());
    }
}
