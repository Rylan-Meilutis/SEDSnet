use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

#[test]
fn lost_chunk_cannot_poison_later_frames_from_same_router() {
    crate::tests::ensure_common_test_schema();
    let rf = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 0));
    let fc = Router::new_with_clock(RouterConfig::new([]).with_sender("FC"), Box::new(|| 0));
    let side = fc.add_side_packed_with_options("CAN", |_| Ok(()), RouterSideOptions::default());
    let first = Router::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[1; 180]);
    let second = Router::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &[2; 180]);
    // CRC including the appended CRC has a constant residue: it is NOT an ID.
    assert_eq!(Router::crc32_bytes(&first), Router::crc32_bytes(&second));
    let a = rf.split_side_transport_frame(0, first, 128).unwrap();
    let b = rf.split_side_transport_frame(0, second, 128).unwrap();
    assert_ne!(
        &a[0][4..8],
        &b[0][4..8],
        "different packets need different transfer IDs"
    );
    assert!(
        fc.decode_side_transport_frame(side, &a[0])
            .unwrap()
            .is_none()
    );
    // Drop A's tail; all of B must still be decodable.
    let mut result = None;
    for frame in b {
        result = fc.decode_side_transport_frame(side, &frame).unwrap();
    }
    assert_eq!(result.unwrap().as_ref(), &[2; 180]);
}

#[test]
fn incomplete_side_transfers_stay_bounded_under_repeated_loss() {
    crate::tests::ensure_common_test_schema();
    let router = Router::new_with_clock(RouterConfig::new([]).with_sender("RF"), Box::new(|| 0));
    let side = router.add_side_packed_with_options("CAN", |_| Ok(()), RouterSideOptions::default());
    for i in 0..1000u32 {
        let mut data = vec![0; 180];
        data[..4].copy_from_slice(&i.to_le_bytes());
        let frame = Router::wrap_side_transport_frame(SIDE_TRANSPORT_KIND_FULL, &data);
        let chunks = router.split_side_transport_frame(side, frame, 128).unwrap();
        assert!(
            router
                .decode_side_transport_frame(side, &chunks[0])
                .unwrap()
                .is_none()
        );
        assert!(router.state.lock().side_transport[&side].rx_chunks.len() <= 4);
    }
}

#[test]
fn unacknowledged_topology_does_not_silence_discovery_liveness() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let emitted = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let output = emitted.clone();
    let rf = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let side = rf.add_side_packed_with_options(
        "CAN",
        move |packet| {
            output.lock().unwrap().push(packet.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..Default::default()
        },
    );
    rf.announce_discovery().unwrap();
    rf.process_tx_queue().unwrap();
    // Deliberately withhold the hop ACK for a transmitted topology baseline.
    assert!(
        rf.state
            .lock()
            .reliable_tx
            .iter()
            .any(|((s, ty), tx)| *s == side
                && *ty == DataType::DiscoveryTopology.as_u32()
                && !tx.sent.is_empty())
    );
    emitted.lock().unwrap().clear();
    let fc_clock = now.clone();
    let fc = Router::new_with_clock(
        RouterConfig::new([]).with_sender("FC"),
        Box::new(move || fc_clock.load(Ordering::Relaxed)),
    );
    let endpoint = DataEndpoint::named("RADIO");
    let sensor_type = crate::config::register_data_type_with_description(
        "DISCOVERY_LIVENESS_SENSOR",
        "live sensor across RF",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    let sensor_count = Arc::new(AtomicU64::new(0));
    let sent = sensor_count.clone();
    let ingress = fc.add_side_packet("CAN", move |packet| {
        if packet.data_type() == sensor_type {
            sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    fc.rx_from_side(
        &discovery::build_discovery_topology(
            "RF",
            0,
            &[
                TopologyBoardNode {
                    sender_id: "RF".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GS".into()],
                },
                TopologyBoardNode {
                    sender_id: "GS".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into()],
                },
            ],
        )
        .unwrap(),
        ingress,
    )
    .unwrap();
    let mut delivered = 0;
    for ms in (1_000..=60_000).step_by(1_000) {
        now.store(ms, Ordering::Relaxed);
        rf.poll_discovery().unwrap();
        // Drain newly queued advertisements without running timeout/retry
        // maintenance: keep the original pending ACK outstanding throughout.
        loop {
            let queued = Router::pop_transmit_queue_locked(&mut rf.state.lock());
            let Some(queued) = queued else {
                break;
            };
            rf.tx_item_impl(queued.item, queued.ignore_local, true)
                .unwrap();
        }
        let frames = emitted.lock().unwrap();
        for frame in &frames[delivered..] {
            let packet = crate::wire_format::unpack_packet(frame).unwrap();
            fc.rx_from_side(&packet, ingress).unwrap();
        }
        delivered = frames.len();
        drop(frames);
        // PB continues to announce on the same CAN segment but is not a
        // GroundStation subscriber. Its liveness must not hide loss of RF.
        fc.rx_from_side(
            &discovery::build_discovery_announce("PB", ms, &[]).unwrap(),
            ingress,
        )
        .unwrap();
        assert!(
            fc.export_topology()
                .routes
                .iter()
                .any(|route| route.reachable_endpoints.contains(&endpoint)),
            "FC must retain GS reachability while RF keepalives continue at {ms} ms"
        );
        let before = sensor_count.load(Ordering::Relaxed);
        fc.log(sensor_type, &[1u8]).unwrap();
        assert_eq!(
            sensor_count.load(Ordering::Relaxed),
            before + 1,
            "FC must actually transmit each sensor packet, not just return success at {ms} ms"
        );
    }
    let frames = emitted.lock().unwrap();
    let types: Vec<_> = frames
        .iter()
        .map(|p| crate::wire_format::peek_envelope(p).unwrap().ty)
        .collect();
    let pings: Vec<_> = types
        .iter()
        .filter(|ty| **ty == DataType::DiscoveryAnnounce)
        .collect();
    assert!(
        pings.len() >= 3,
        "a lost topology ACK must not suppress bounded keepalives for an entire route TTL"
    );
    assert!(
        pings.len() <= 5,
        "keepalives must not run at the firmware polling rate"
    );
    assert!(
        types.iter().all(|ty| *ty != DataType::DiscoveryTopology),
        "do not retransmit full topology just to refresh liveness"
    );
    let expired = 60_000 + DISCOVERY_ROUTE_TTL_MS + 1;
    now.store(expired, Ordering::Relaxed);
    fc.rx_from_side(
        &discovery::build_discovery_announce("PB", expired, &[]).unwrap(),
        ingress,
    )
    .unwrap();
    assert!(
        !fc.export_topology()
            .routes
            .iter()
            .any(|route| route.reachable_endpoints.contains(&endpoint)),
        "a genuinely silent RF must still expire even with PB present"
    );
}
