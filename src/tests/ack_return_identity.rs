use super::*;

#[test]
fn generated_ack_keeps_original_sender_after_return_cache_eviction() {
    check_ack_return_identity("AB");
}

#[test]
fn compact_sender_ack_returns_after_cache_eviction() {
    check_ack_return_identity(&format!("@addr:{}", sender_address_u32("AB")));
}

fn check_ack_return_identity(original_sender: &str) {
    crate::tests::ensure_common_test_schema();
    let router = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("GS")
            .with_reliable_enabled(true),
        Box::new(|| 0u64),
    );
    let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let output = sent.clone();
    let side = router.add_side_packed_with_options(
        "CAN",
        move |bytes| {
            output.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default(),
    );
    let endpoint = DataEndpoint::named("RADIO");
    router
        .rx_from_side(
            &discovery::build_discovery_announce("AB", 0, &[endpoint]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues().unwrap();
    sent.lock().unwrap().clear();
    let packet = Packet::new(
        DataType::named("GPS_DATA"),
        &[endpoint],
        original_sender,
        1,
        Arc::<[u8]>::from([0u8; 12]),
    )
    .unwrap();
    router.note_reliable_return_route(side, packet.packet_id());
    router.queue_end_to_end_reliable_ack(&packet, true).unwrap();
    for index in 0..runtime_reliable_max_return_routes().max(1) {
        router.note_reliable_return_route(side, packet.packet_id().wrapping_add(index as u64 + 1));
    }
    assert!(
        !router
            .state
            .lock()
            .reliable_return_routes
            .contains_key(&packet.packet_id())
    );
    router.process_all_queues().unwrap();
    let frames = sent.lock().unwrap();
    let acks: Vec<_> = frames
        .iter()
        .filter_map(|bytes| wire_format::unpack_packet(bytes).ok())
        .filter(Router::is_end_to_end_ack_packet)
        .collect();
    assert_eq!(
        acks.len(),
        1,
        "ACK must return to AB even after its per-packet return route is evicted"
    );
    assert_eq!(
        Router::end_to_end_ack_sender_hash(&acks[0]),
        Some(Router::sender_hash("GS"))
    );
    assert_eq!(
        acks[0].wire_target_senders().get(1),
        Some(&Router::sender_hash("AB"))
    );
}
