use super::*;

#[test]
fn named_receipts_do_not_escape_the_publishers_ingress_segment() {
    crate::tests::ensure_common_test_schema();
    for packed in [false, true] {
        for publisher_side in [Some(0), Some(1), None] {
            let router = Router::new_with_clock(
                RouterConfig::new([]).with_sender("BRIDGE"),
                Box::new(|| 100),
            );
            let output = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
            let can = router.add_side_packed("can", |_| Ok(()));
            let captured = output.clone();
            let ethernet = router.add_side_packed("ethernet", move |bytes| {
                captured.lock().unwrap().push(bytes.to_vec());
                Ok(())
            });
            assert_eq!((can, ethernet), (0, 1));
            let announce_side = publisher_side.unwrap_or(can);
            let name = if publisher_side.is_some() {
                "VB"
            } else {
                "UNRELATED"
            };
            router
                .rx_from_side(
                    &discovery::build_discovery_announce(name, 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    announce_side,
                )
                .unwrap();
            router.process_all_queues().unwrap();
            output.lock().unwrap().clear();
            let ack = Packet::new(
                DataType::ReliableAck,
                &[DataEndpoint::Discovery],
                "E2EACK:DAQ",
                100,
                Arc::<[u8]>::from(1234_u64.to_le_bytes()),
            )
            .unwrap();
            let wire = wire_format::pack_packet_with_wire_contract(
                &ack,
                None,
                None,
                &[Router::sender_hash("DAQ"), Router::sender_hash("VB")],
            )
            .unwrap();
            if packed {
                router.rx_packed_from_side(&wire, can).unwrap();
            } else {
                router
                    .rx_from_side(&wire_format::unpack_packet(&wire).unwrap(), can)
                    .unwrap();
            }
            router.process_all_queues().unwrap();
            let receipts = output
                .lock()
                .unwrap()
                .iter()
                .filter_map(|bytes| wire_format::unpack_packet(bytes).ok())
                .filter(|packet| packet.data_type() == DataType::ReliableAck)
                .count();
            assert_eq!(
                receipts,
                usize::from(publisher_side != Some(can)),
                "packed={packed} publisher_side={publisher_side:?}: a same-segment receipt must not flood the other network; remote and unknown publisher recovery must still work"
            );
        }
    }
}
