use super::*;
use crate::{DataEndpoint, DataType};

#[test]
fn compact_ack_uses_frozen_owner_and_returns_after_cache_churn() {
    crate::tests::ensure_common_test_schema();
    for original in [false, true] {
        for packed in [false, true] {
            for extra_side in [false, true] {
                let relay = Relay::new(Box::new(|| 0));
                let output = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
                let sent = output.clone();
                let uart = relay.add_side_packed("uart", move |bytes| {
                    sent.lock().unwrap().push(bytes.to_vec());
                    Ok(())
                });
                let can = relay.add_side_packed("can", |_| Ok(()));
                if extra_side {
                    relay.add_side_packed("other", |_| Ok(()));
                }
                relay
                    .rx_from_side(
                        uart,
                        discovery::build_discovery_announce(
                            "GS",
                            0,
                            &[DataEndpoint::named("RADIO")],
                        )
                        .unwrap(),
                    )
                    .unwrap();
                relay.process_all_queues().unwrap();
                output.lock().unwrap().clear();
                let packet_id = 1234u64;
                relay.note_reliable_return_route(uart, packet_id);
                for index in 0..runtime_reliable_max_return_routes().max(1) {
                    relay.note_reliable_return_route(can, 10000 + index as u64);
                }
                assert!(
                    !relay
                        .state
                        .lock()
                        .reliable_return_routes
                        .contains_key(&packet_id)
                );
                let ack = Packet::new(
                    DataType::ReliableAck,
                    &[DataEndpoint::Discovery],
                    "@addr:305441741",
                    1,
                    Arc::<[u8]>::from(packet_id.to_le_bytes()),
                )
                .unwrap();
                let mut targets = vec![Relay::sender_hash("VB")];
                if original {
                    targets.push(Relay::sender_hash("GS"));
                }
                let raw = wire_format::pack_packet_with_wire_contract(&ack, None, None, &targets)
                    .unwrap();
                assert!(
                    wire_format::unpack_packet(&raw)
                        .unwrap()
                        .sender()
                        .starts_with("@addr:")
                );
                if packed {
                    relay.rx_packed_from_side(can, &raw).unwrap();
                } else {
                    relay
                        .rx_from_side(can, wire_format::unpack_packet(&raw).unwrap())
                        .unwrap();
                }
                relay.process_all_queues().unwrap();
                let count = output
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|bytes| wire_format::unpack_packet(bytes).ok())
                    .filter(|p| p.data_type() == DataType::ReliableAck)
                    .count();
                assert_eq!(
                    count,
                    usize::from(original || !extra_side),
                    "use the frozen publisher route or an unambiguous bridge path"
                );
            }
        }
    }
}
