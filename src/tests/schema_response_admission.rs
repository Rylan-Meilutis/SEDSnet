//! Bounded response generation for captured startup and restart requests.

use super::*;

#[test]
fn schema_request_capture_burst_has_one_active_and_one_pending_response() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1966));
    let clock = now.clone();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("DAQ_CAPTURE"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    ));
    let sent = Arc::new(RouterMutex::new(Vec::new()));
    let capture = sent.clone();
    let link = Arc::new(AtomicUsize::new(usize::MAX));
    let callback_link = link.clone();
    let weak = Arc::downgrade(&router);
    let callback_clock = now.clone();
    let side = router.add_side_packet("CAN", move |pkt| {
        if pkt.data_type() == DataType::DiscoverySchema {
            let first = {
                let mut capture = capture.lock();
                capture.push(pkt.packet_id());
                capture.len() == 1
            };
            if first {
                // Second captured request arrives while the first catalog
                // is active. Its callback then completes at 2054 ms.
                callback_clock.store(1967, Ordering::SeqCst);
                let request = discovery::build_discovery_schema_request("RF", 1967).unwrap();
                weak.upgrade()
                    .unwrap()
                    .learn_discovery_packet(
                        &request,
                        Some(callback_link.load(Ordering::SeqCst)),
                        true,
                    )
                    .unwrap();
                callback_clock.store(2054, Ordering::SeqCst);
            }
        }
        Ok(())
    });
    link.store(side, Ordering::SeqCst);
    let request = discovery::build_discovery_schema_request("FC", 1966).unwrap();
    router
        .learn_discovery_packet(&request, Some(side), true)
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    // Third captured request lands just after that 88 ms transmission.
    now.store(2059, Ordering::SeqCst);
    let request = discovery::build_discovery_schema_request("RF", 2059).unwrap();
    router
        .learn_discovery_packet(&request, Some(side), true)
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        sent.lock().len(),
        1,
        "later requests wait for one fresh generation"
    );
    now.store(2216, Ordering::SeqCst);
    router.poll_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(
        sent.lock().len(),
        2,
        "startup burst must retain only one fresh pending generation"
    );
}

#[test]
fn schema_response_failures_retain_pending_without_growing_the_queue() {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1000));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let refuse = Arc::new(AtomicBool::new(true));
    let blocked = refuse.clone();
    let sent = Arc::new(RouterMutex::new(Vec::new()));
    let capture = sent.clone();
    let side = router.add_side_packet("CAN", move |pkt| {
        if pkt.data_type() == DataType::DiscoverySchema {
            if blocked.load(Ordering::SeqCst) {
                return Err(TelemetryError::BadArg);
            }
            capture.lock().push(pkt.clone());
        }
        Ok(())
    });
    let request = discovery::build_discovery_schema_request("PEER", 1).unwrap();
    router
        .learn_discovery_packet(&request, Some(side), true)
        .unwrap();
    assert!(router.drain_queues_with_timeout(0).is_err());
    for tick in 1001..1250 {
        now.store(tick, Ordering::SeqCst);
        router
            .learn_discovery_packet(&request, Some(side), true)
            .unwrap();
        assert!(router.state.lock().transmit_queue.len() <= 1);
    }
    assert!(router.state.lock().discovery_side_throttle[&side].schema_response_pending);
    // The eventual generation is rebuilt from the current catalog, not a
    // retained clone made before this late schema registration.
    let ty = crate::config::register_data_type_with_description(
        "COALESCED_LATE_CATALOG",
        "pending response must see this entry",
        MessageElement::Dynamic(crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[DataEndpoint::Discovery],
        crate::ReliableMode::None,
        16,
    )
    .unwrap();
    refuse.store(false, Ordering::SeqCst);
    now.store(1250, Ordering::SeqCst);
    router.poll_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let packets = sent.lock();
    assert_eq!(packets.len(), 1);
    assert!(
        packets[0]
            .payload()
            .windows(b"COALESCED_LATE_CATALOG".len())
            .any(|w| w == b"COALESCED_LATE_CATALOG"),
        "fresh schema {ty:?} missing"
    );
    drop(packets);
    assert!(!router.state.lock().discovery_side_throttle[&side].schema_response_pending);
    // A peer restarting after the old response gets another full response.
    now.store(1500, Ordering::SeqCst);
    router
        .learn_discovery_packet(&request, Some(side), true)
        .unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(sent.lock().len(), 2);
}

#[test]
fn schema_response_partial_fragments_survive_bursts_and_refresh_only_at_start() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1000));
    let clock = now.clone();
    let allowance = Arc::new(AtomicUsize::new(0));
    let available = allowance.clone();
    let frames = Arc::new(RouterMutex::new(Vec::<Vec<u8>>::new()));
    let capture = frames.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let side = router.add_side_packed_with_options(
        "CAN",
        move |bytes| {
            if available
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_err()
            {
                return Err(TelemetryError::Io("side tx busy"));
            }
            capture.lock().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(128),
    );
    let request = discovery::build_discovery_schema_request("PEER", 1).unwrap();
    router
        .state
        .lock()
        .side_transport
        .get_mut(&side)
        .unwrap()
        .tx_compact_uses
        .insert(99, 7);
    router
        .learn_discovery_packet(&request, Some(side), true)
        .unwrap();
    assert_eq!(
        router.state.lock().side_transport[&side].tx_compact_uses[&99],
        u8::MAX
    );
    let packet = {
        let st = router.state.lock();
        st.transmit_queue
            .iter()
            .find_map(|entry| match &entry.item {
                RouterTxItem::ToSide {
                    data: RouterItem::Packet(pkt),
                    ..
                } if pkt.data_type() == DataType::DiscoverySchema => Some(pkt.clone()),
                _ => None,
            })
            .unwrap()
    };
    // Queue admission starts one generation, refreshing headers immediately.
    // Actual TX begins later; requests/retries must not refresh it again.
    router
        .state
        .lock()
        .side_transport
        .get_mut(&side)
        .unwrap()
        .tx_compact_uses
        .insert(99, 11);
    now.store(1200, Ordering::SeqCst);
    let mut complete = false;
    for tick in 1200..2200 {
        now.store(tick, Ordering::SeqCst);
        allowance.store(1, Ordering::SeqCst);
        let result = router.send_reliable_to_side(side, RouterItem::Packet(packet.clone()), false);
        let mut st = router.state.lock();
        let transport = st.side_transport.get_mut(&side).unwrap();
        if tick == 1200 {
            assert_eq!(transport.tx_compact_uses[&99], u8::MAX);
            transport.tx_compact_uses.insert(99, 11);
        } else {
            assert_eq!(transport.tx_compact_uses[&99], 11);
        }
        drop(st);
        router
            .learn_discovery_packet(&request, Some(side), true)
            .unwrap();
        assert_eq!(
            router.state.lock().side_transport[&side].tx_compact_uses[&99],
            11,
            "requests cannot reset a partial transfer's templates"
        );
        match result {
            Ok(()) => {
                complete = true;
                break;
            }
            Err(TelemetryError::Io(_)) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(complete);
    let received = frames.lock();
    assert!(received.len() > 1);
    let transfer_id = &received[0][4..8];
    for (index, frame) in received.iter().enumerate() {
        assert_eq!(&frame[..4], b"SDT\x03");
        assert_eq!(&frame[4..8], transfer_id);
        assert_eq!(u16::from_le_bytes([frame[8], frame[9]]) as usize, index);
    }
    drop(received);
    // The production queue retains this exact owner through partial IO.
    // Remove it as dispatch would after completion, then serve the pending
    // restart response at the actual start+250 ms (not admission+250 ms).
    router.state.lock().transmit_queue.clear();
    now.store(1449, Ordering::SeqCst);
    assert!(!router.poll_schema_response_on_side(side).unwrap());
    now.store(1450, Ordering::SeqCst);
    assert!(router.poll_schema_response_on_side(side).unwrap());
    let st = router.state.lock();
    assert_ne!(
        st.discovery_side_throttle[&side].schema_response_packet_id,
        packet.packet_id()
    );
    assert_eq!(
        st.side_transport[&side].tx_compact_uses[&99],
        u8::MAX,
        "a fresh pending generation refreshes headers for a restarting peer"
    );
}

#[test]
fn schema_response_queue_admission_failure_is_retried() {
    use core::sync::atomic::{AtomicU64, Ordering};
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1000));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let sent = Arc::new(RouterMutex::new(0usize));
    let capture = sent.clone();
    let side = router.add_side_packet("CAN", move |pkt| {
        if pkt.data_type() == DataType::DiscoverySchema {
            *capture.lock() += 1;
        }
        Ok(())
    });
    let original_budget = router.state.lock().memory.max_queue_budget;
    router.state.lock().memory.max_queue_budget = 1;
    let request = discovery::build_discovery_schema_request("PEER", 1).unwrap();
    assert!(
        router
            .learn_discovery_packet(&request, Some(side), true)
            .is_err()
    );
    assert!(router.state.lock().discovery_side_throttle[&side].schema_response_pending);
    router.state.lock().memory.max_queue_budget = original_budget;
    now.store(1250, Ordering::SeqCst);
    router.poll_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(*sent.lock(), 1);
}

#[test]
fn coalesced_restarts_receive_full_headers_after_pending_dispatch() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let ty = crate::config::register_data_type_with_description(
        "COALESCED_RESTART_APP",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[DataEndpoint::Discovery],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    let application = Packet::new(
        ty,
        &[DataEndpoint::Discovery],
        "DAQ",
        1970,
        crate::shared_bytes::convert(Arc::<[u8]>::from([42u8])),
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(1966));
    let clock = now.clone();
    let tx = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("DAQ"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    ));
    let opts = RouterSideOptions::default().with_small_packet_transport(0);
    let callback_opts = opts.clone();
    let callback_app = application.clone();
    let side_index = Arc::new(AtomicUsize::new(usize::MAX));
    let link = side_index.clone();
    let weak = Arc::downgrade(&tx);
    let callback_clock = now.clone();
    let schemas = Arc::new(AtomicUsize::new(0));
    let count = schemas.clone();
    let side = tx.add_side_packet_with_options(
        "CAN",
        move |pkt| {
            if pkt.data_type() == DataType::DiscoverySchema
                && count.fetch_add(1, Ordering::SeqCst) == 0
            {
                let node = weak.upgrade().unwrap();
                let side = link.load(Ordering::SeqCst);
                callback_clock.store(1967, Ordering::SeqCst);
                node.learn_discovery_packet(
                    &discovery::build_discovery_schema_request("B", 1967).unwrap(),
                    Some(side),
                    true,
                )
                .unwrap();
                // This full application header reaches B, before C restarts.
                callback_clock.store(1970, Ordering::SeqCst);
                let frames = node
                    .encode_side_transport_frames(
                        side,
                        callback_opts.clone(),
                        crate::shared_bytes::convert(wire_format::pack_packet(&callback_app)),
                    )
                    .unwrap()
                    .collect::<Vec<_>>();
                assert_eq!(frames[0][3], SIDE_TRANSPORT_KIND_FULL);
                callback_clock.store(2054, Ordering::SeqCst);
            }
            Ok(())
        },
        opts.clone(),
    );
    side_index.store(side, Ordering::SeqCst);
    // Warm the template before A requests its fresh response generation.
    tx.encode_side_transport_frames(
        side,
        opts.clone(),
        crate::shared_bytes::convert(wire_format::pack_packet(&application)),
    )
    .unwrap()
    .for_each(drop);
    tx.learn_discovery_packet(
        &discovery::build_discovery_schema_request("A", 1966).unwrap(),
        Some(side),
        true,
    )
    .unwrap();
    tx.drain_queues_with_timeout(0).unwrap();
    now.store(2059, Ordering::SeqCst);
    tx.learn_discovery_packet(
        &discovery::build_discovery_schema_request("C", 2059).unwrap(),
        Some(side),
        true,
    )
    .unwrap();
    let restarted = Router::new(RouterConfig::default());
    let rx_side = restarted.add_side_packed_with_options("CAN", |_| Ok(()), opts.clone());
    let before = tx
        .encode_side_transport_frames(
            side,
            opts.clone(),
            crate::shared_bytes::convert(wire_format::pack_packet(&application)),
        )
        .unwrap()
        .collect::<Vec<_>>();
    assert_ne!(before[0][3], SIDE_TRANSPORT_KIND_FULL);
    assert!(
        restarted
            .decode_side_transport_frame(rx_side, &before[0])
            .ok()
            .flatten()
            .is_none(),
        "fixture peer really missed the old prefix"
    );
    now.store(2216, Ordering::SeqCst);
    tx.poll_schema_response_on_side(side).unwrap();
    tx.drain_queues_with_timeout(0).unwrap();
    let after = tx
        .encode_side_transport_frames(
            side,
            opts.clone(),
            crate::shared_bytes::convert(wire_format::pack_packet(&application)),
        )
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(after[0][3], SIDE_TRANSPORT_KIND_FULL);
    assert!(
        restarted
            .decode_side_transport_frame(rx_side, &after[0])
            .unwrap()
            .is_some()
    );
    assert_eq!(schemas.load(Ordering::SeqCst), 2);

    // Stronger queue-delay case: a later generation is admitted, an application
    // consumes its immediate refresh, then another receiver restarts before TX.
    now.store(2466, Ordering::SeqCst);
    tx.learn_discovery_packet(
        &discovery::build_discovery_schema_request("D", 2466).unwrap(),
        Some(side),
        true,
    )
    .unwrap();
    tx.encode_side_transport_frames(
        side,
        opts.clone(),
        crate::shared_bytes::convert(wire_format::pack_packet(&application)),
    )
    .unwrap()
    .for_each(drop);
    now.store(2467, Ordering::SeqCst);
    tx.learn_discovery_packet(
        &discovery::build_discovery_schema_request("E", 2467).unwrap(),
        Some(side),
        true,
    )
    .unwrap();
    let late = Router::new(RouterConfig::default());
    let late_side = late.add_side_packed_with_options("CAN", |_| Ok(()), opts.clone());
    now.store(2470, Ordering::SeqCst);
    tx.drain_queues_with_timeout(0).unwrap();
    let after = tx
        .encode_side_transport_frames(
            side,
            opts,
            crate::shared_bytes::convert(wire_format::pack_packet(&application)),
        )
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(after[0][3], SIDE_TRANSPORT_KIND_FULL);
    assert!(
        late.decode_side_transport_frame(late_side, &after[0])
            .unwrap()
            .is_some()
    );
}
