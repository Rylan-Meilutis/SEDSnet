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

#[test]
fn refused_reliable_replay_keeps_priority_ahead_of_partial_schema() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    for mode in [crate::ReliableMode::Ordered, crate::ReliableMode::Unordered] {
        let endpoint = crate::config::register_endpoint("SCHEMA_REPLAY_OWNER", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            &format!("SCHEMA_REPLAY_{mode:?}"),
            "",
            MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
            &[endpoint],
            mode,
            16,
        )
        .unwrap();
        assert_eq!(crate::transport_priority(ty), 16);
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([]).with_sender("GS"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let credit = Arc::new(AtomicUsize::new(1));
        let allowance = credit.clone();
        let frames = Arc::new(RouterMutex::new(Vec::new()));
        let capture = frames.clone();
        let side = router.add_side_packed_with_options(
            "RFD",
            move |bytes| {
                allowance
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                capture.lock().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(192),
        );
        let catalog = discovery::build_discovery_schema("GS", 0).unwrap();
        assert!(matches!(
            router.send_reliable_to_side(side, RouterItem::Packet(catalog.clone()), false),
            Err(TelemetryError::Io(_))
        ));
        assert_eq!(&frames.lock()[0][..4], b"SDT\x03");
        router
            .tx_queue_item_with_flags(
                RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(catalog),
                },
                true,
            )
            .unwrap();
        let packet = Packet::new(
            ty,
            &[endpoint],
            "GS",
            1,
            Arc::<[u8]>::from(1u32.to_le_bytes()),
        )
        .unwrap();
        let id = packet.packet_id();
        router.state.lock().end_to_end_reliable_tx.insert(
            id,
            EndToEndReliableSent {
                ordered_type: matches!(mode, crate::ReliableMode::Ordered).then_some(ty.as_u32()),
                waiting_for_predecessor: false,
                data: RouterItem::Packet(packet),
                pending_destinations: BTreeMap::from([(Router::sender_hash("RF"), side)]),
                tracked_destinations: true,
                last_send_ms: 0,
                retries: 1,
                queued: false,
            },
        );
        router.queue_end_to_end_reliable_retransmit(id).unwrap();
        // The original high-priority replay callback is refused. Repeat that
        // refusal before a transport slot opens, as in the captured campaign.
        for tick in 1..=3 {
            now.store(tick, Ordering::Relaxed);
            router.dispatch_tx_queue_with_timeout(0).unwrap();
        }
        now.store(4, Ordering::Relaxed);
        credit.store(1, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        let captured = frames.lock();
        assert_eq!(captured.len(), 2);
        assert_eq!(
            wire_format::peek_frame_info(&captured[1])
                .ok()
                .map(|info| info.envelope.ty),
            Some(ty),
            "a denied replay must retain its service priority for the next ready slot instead of falling behind schema chunks"
        );
        drop(captured);
        assert_eq!(
            crate::message_priority(ty),
            16,
            "application schema priority stays unchanged"
        );
        // Resume the same partial catalog, proving the replay did not reset
        // its prefix, transfer identity or chunk order.
        for tick in 5..500 {
            now.store(tick, Ordering::Relaxed);
            credit.store(1, Ordering::SeqCst);
            router.dispatch_tx_queue_with_timeout(0).unwrap();
            if !router.has_queued_work() {
                break;
            }
        }
        let captured = frames.lock();
        let chunks: Vec<_> = captured
            .iter()
            .filter(|bytes| bytes.starts_with(b"SDT\x03"))
            .collect();
        assert!(chunks.len() > 1);
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(&chunk[4..8], &chunks[0][4..8]);
            assert_eq!(u16::from_le_bytes([chunk[8], chunk[9]]) as usize, index);
        }
    }
}

#[test]
fn refused_ordinary_turn_survives_until_admission_during_partial_schema() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::config::register_endpoint("SCHEMA_ORDINARY_OWNER", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "SCHEMA_ORDINARY_REPORT",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let credit = Arc::new(AtomicUsize::new(1));
    let allowance = credit.clone();
    let frames = Arc::new(RouterMutex::new(Vec::new()));
    let capture = frames.clone();
    let side = router.add_side_packed_with_options(
        "RFD",
        move |bytes| {
            allowance
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .map_err(|_| TelemetryError::Io("side tx busy"))?;
            capture.lock().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    let catalog = discovery::build_discovery_schema("RF", 0).unwrap();
    assert!(matches!(
        router.send_reliable_to_side(side, RouterItem::Packet(catalog.clone()), false),
        Err(TelemetryError::Io(_))
    ));
    router
        .tx_queue_item_with_flags(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(catalog),
            },
            true,
        )
        .unwrap();
    let packet = Packet::new(
        ty,
        &[endpoint],
        "RF",
        1,
        Arc::<[u8]>::from(1u32.to_le_bytes()),
    )
    .unwrap();
    router
        .tx_queue_item_with_flags(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(packet),
            },
            true,
        )
        .unwrap();
    // Refusals and later one-frame opportunities match the fixed-capacity
    // driver: failed attempts cannot use up an ordinary stream's owed turn.
    for tick in 1..=10 {
        now.store(tick, Ordering::Relaxed);
        credit.store(usize::from(tick >= 4), Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
    }
    let decoder = Router::new(RouterConfig::default());
    let decode_side = decoder.add_side_packed_with_options(
        "trace",
        |_| Ok(()),
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    let mut delivered = false;
    for frame in frames.lock().iter() {
        if let Some(canonical) = decoder
            .decode_side_transport_frame(decode_side, frame)
            .unwrap()
        {
            delivered |= wire_format::peek_frame_info(&canonical)
                .unwrap()
                .envelope
                .ty
                == ty;
        }
    }
    assert!(
        delivered,
        "ordinary report must reach an actual ready slot before another full schema completes"
    );
    assert_eq!(crate::message_priority(ty), 0);
    for tick in 11..500 {
        now.store(tick, Ordering::Relaxed);
        credit.store(1, Ordering::SeqCst);
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        if !router.has_queued_work() {
            break;
        }
    }
    let capture = frames.lock();
    let chunks: Vec<_> = capture
        .iter()
        .filter(|bytes| bytes.starts_with(b"SDT\x03"))
        .collect();
    assert!(chunks.len() > 1);
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(&chunk[4..8], &chunks[0][4..8]);
        assert_eq!(u16::from_le_bytes([chunk[8], chunk[9]]) as usize, index);
    }
}

#[test]
fn refused_turn_cannot_overwrite_reentrant_side_admission() {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::config::register_endpoint("FAIR_REENTRANT_OWNER", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "FAIR_REENTRANT_REPORT",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let node = Arc::new(Router::new_with_clock(
        RouterConfig::new([]),
        Box::new(move || clock.load(Ordering::Relaxed)),
    ));
    let weak = Arc::downgrade(&node);
    let open = Arc::new(AtomicBool::new(false));
    let ready = open.clone();
    let low = node.add_side_packed("blocked", move |_| {
        if ready.load(Ordering::Relaxed) {
            return Ok(());
        }
        weak.upgrade()
            .unwrap()
            .dispatch_tx_queue_with_timeout(0)
            .unwrap();
        Err(TelemetryError::Io("side tx busy"))
    });
    let accepted = Arc::new(AtomicUsize::new(0));
    let observed = accepted.clone();
    let high = node.add_side_packet("other", move |_| {
        observed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let catalog = discovery::build_discovery_schema("RF", 0).unwrap();
    node.tx_queue_item_with_flags(
        RouterTxItem::ToSide {
            src: None,
            dst: high,
            data: RouterItem::Packet(catalog),
        },
        true,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[endpoint],
        "RF",
        1,
        Arc::<[u8]>::from(1u32.to_le_bytes()),
    )
    .unwrap();
    node.tx_queue_item_with_flags(
        RouterTxItem::ToSide {
            src: None,
            dst: low,
            data: RouterItem::Packet(packet),
        },
        true,
    )
    .unwrap();
    node.state.lock().tx_priority_burst = MAX_PRIORITY_BURST;
    node.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    let st = node.state.lock();
    assert!(
        st.transmit_queue.iter().any(|item| item.priority == 0),
        "refused report retains its original band and owner"
    );
    drop(st);
    open.store(true, Ordering::Relaxed);
    now.store(1, Ordering::Relaxed);
    node.dispatch_tx_queue_with_timeout(0).unwrap();
    assert!(!node.has_queued_work());
    assert_eq!(
        node.state.lock().tx_priority_burst,
        0,
        "actual radio admission settles the owed turn after the independent side's admission"
    );
}

#[test]
fn unrelated_nested_admission_does_not_credit_selected_dispatch() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::config::register_endpoint("NESTED_PROGRESS_OWNER", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "NESTED_PROGRESS_REPORT",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let node = Arc::new(Router::new(RouterConfig::new([])));
    let accepted = Arc::new(AtomicUsize::new(0));
    let observed = accepted.clone();
    let other = node.add_side_packet("other", move |_| {
        observed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let nested = Packet::new(
        ty,
        &[endpoint],
        "RF",
        1,
        Arc::<[u8]>::from(1u32.to_le_bytes()),
    )
    .unwrap();
    let weak = Arc::downgrade(&node);
    let blocked = node.add_side_packed("blocked", move |_| {
        weak.upgrade()
            .unwrap()
            .send_reliable_to_side(other, RouterItem::Packet(nested.clone()), false)
            .unwrap();
        Err(TelemetryError::Io("side tx busy"))
    });
    let catalog = discovery::build_discovery_schema("RF", 0).unwrap();
    let mut admitted = false;
    assert!(matches!(
        node.send_reliable_to_side_with_progress(
            blocked,
            RouterItem::Packet(catalog),
            false,
            &mut admitted
        ),
        Err(TelemetryError::Io(_))
    ));
    assert!(accepted.load(Ordering::Relaxed) > 0);
    assert!(
        !admitted,
        "only the selected callback's successful admission counts, even during reentry"
    );
}

#[test]
fn refused_turn_cannot_roll_back_reentrant_clear() {
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::config::register_endpoint("FAIR_CLEAR_OWNER", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "FAIR_CLEAR_REPORT",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let node = Arc::new(Router::new(RouterConfig::new([])));
    let weak = Arc::downgrade(&node);
    let side = node.add_side_packed("blocked", move |_| {
        weak.upgrade().unwrap().clear_tx_queue();
        Err(TelemetryError::Io("side tx busy"))
    });
    let packet = Packet::new(
        ty,
        &[endpoint],
        "RF",
        1,
        Arc::<[u8]>::from(1u32.to_le_bytes()),
    )
    .unwrap();
    node.tx_queue_item_with_flags(
        RouterTxItem::ToSide {
            src: None,
            dst: side,
            data: RouterItem::Packet(packet),
        },
        true,
    )
    .unwrap();
    node.state.lock().tx_priority_burst = MAX_PRIORITY_BURST;
    node.dispatch_tx_queue_with_timeout(0).unwrap();
    let st = node.state.lock();
    assert_eq!(st.tx_priority_burst, 0);
    assert_eq!(st.transmit_queue.priority_fair_cursor(), u8::MAX);
}

#[test]
fn one_partial_schema_request_completes_without_inventing_another_generation() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    for packed in [false, true] {
        let now = Arc::new(AtomicU64::new(1000));
        let clock = now.clone();
        let node = Router::new_with_clock(
            RouterConfig::new([]).with_sender("SOURCE"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let credit = Arc::new(AtomicUsize::new(1));
        let allowance = credit.clone();
        let frames = Arc::new(RouterMutex::new(Vec::new()));
        let capture = frames.clone();
        let side = node.add_side_packed_with_options(
            "slow",
            move |bytes| {
                allowance
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                capture.lock().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(192),
        );
        let request = discovery::build_discovery_schema_request("PEER", 1000).unwrap();
        node.learn_discovery_packet(&request, Some(side), true)
            .unwrap();
        if packed {
            let mut st = node.state.lock();
            let index=st.transmit_queue.iter().position(|item|matches!(&item.item,RouterTxItem::ToSide{data:RouterItem::Packet(p),..}if p.data_type()==DataType::DiscoverySchema)).unwrap();
            let old = st.transmit_queue.get(index).unwrap().clone();
            let old_cost = old.byte_cost();
            let RouterTxItem::ToSide {
                src,
                dst,
                data: RouterItem::Packet(p),
            } = old.item
            else {
                unreachable!()
            };
            let item = RouterTxItem::ToSide {
                src,
                dst,
                data: RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                    &p,
                ))),
            };
            let cost = old_cost
                .saturating_sub(p.byte_cost())
                .saturating_add(item.byte_cost());
            st.transmit_queue
                .update_admitted(index, cost, |entry| entry.item = item)
                .unwrap();
        }
        for tick in 1000..2000 {
            now.store(tick, Ordering::Relaxed);
            credit.store(1, Ordering::Relaxed);
            node.dispatch_tx_queue_with_timeout(0).unwrap();
            if !node.has_queued_work() {
                break;
            }
        }
        assert!(!node.has_queued_work());
        now.store(3000, Ordering::Relaxed);
        assert!(
            !node.poll_schema_response_on_side(side).unwrap(),
            "retained partial IO is a continuation, not a fresh request (packed={packed})"
        );
        let state = node.state.lock();
        assert!(!state.discovery_side_throttle[&side].schema_response_active);
        assert!(!state.discovery_side_throttle[&side].schema_response_pending);
        drop(state);
        let decoder = Router::new(RouterConfig::default());
        let rx = decoder.add_side_packed_with_options(
            "trace",
            |_| Ok(()),
            RouterSideOptions::default().with_small_packet_transport(192),
        );
        let mut catalogs = 0;
        for frame in frames.lock().iter() {
            if let Some(bytes) = decoder.decode_side_transport_frame(rx, frame).unwrap() {
                catalogs += usize::from(
                    wire_format::peek_frame_info(&bytes).unwrap().envelope.ty
                        == DataType::DiscoverySchema,
                );
            }
        }
        assert_eq!(catalogs, 1);
        let restart = discovery::build_discovery_schema_request("PEER", 3001).unwrap();
        now.store(3001, Ordering::Relaxed);
        node.learn_discovery_packet(&restart, Some(side), true)
            .unwrap();
        assert!(
            node.state.lock().discovery_side_throttle[&side].schema_response_active,
            "a genuine restart still gets a fresh generation"
        );
    }
}

#[test]
fn owed_radio_progress_survives_continuously_ready_reentrant_metadata() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    let endpoint = crate::config::register_endpoint("SUSTAINED_RADIO_OWNER", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "SUSTAINED_RADIO_REPORT",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt32, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let node = Arc::new(Router::new_with_clock(
        RouterConfig::new([]),
        Box::new(move || clock.load(Ordering::Relaxed)),
    ));
    let metadata = discovery::build_discovery_topology_request("METADATA", 0).unwrap();
    let refill = metadata.clone();
    let weak = Arc::downgrade(&node);
    let fill_side = Arc::new(AtomicUsize::new(usize::MAX));
    let fill = fill_side.clone();
    let time = now.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let accepted = count.clone();
    let high = node.add_side_packet("ready", move |_| {
        accepted.fetch_add(1, Ordering::Relaxed);
        time.fetch_add(1, Ordering::Relaxed);
        weak.upgrade()
            .unwrap()
            .tx_queue_item_with_flags(
                RouterTxItem::ToSide {
                    src: None,
                    dst: fill.load(Ordering::Relaxed),
                    data: RouterItem::Packet(refill.clone()),
                },
                true,
            )
            .unwrap();
        Ok(())
    });
    fill_side.store(high, Ordering::Relaxed);
    let delivered = Arc::new(AtomicU64::new(u64::MAX));
    let effect = delivered.clone();
    let time = now.clone();
    let weak = Arc::downgrade(&node);
    let radio = node.add_side_packed("periodic", move |_| {
        let at = time.load(Ordering::Relaxed);
        if at != 0 && at.is_multiple_of(40) {
            effect.store(at, Ordering::Relaxed);
            time.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            // Another side settles a real metadata admission during each
            // refusal; it must not erase this radio's owed service band.
            weak.upgrade()
                .unwrap()
                .dispatch_tx_queue_with_timeout(1)
                .unwrap();
            Err(TelemetryError::Io("side tx busy"))
        }
    });
    node.tx_queue_item_with_flags(
        RouterTxItem::ToSide {
            src: None,
            dst: high,
            data: RouterItem::Packet(metadata),
        },
        true,
    )
    .unwrap();
    let packet = Packet::new(
        ty,
        &[endpoint],
        "RF",
        1,
        Arc::<[u8]>::from(1u32.to_le_bytes()),
    )
    .unwrap();
    node.tx_queue_item_with_flags(
        RouterTxItem::ToSide {
            src: None,
            dst: radio,
            data: RouterItem::Packet(packet),
        },
        true,
    )
    .unwrap();
    for _ in 0..100 {
        node.dispatch_tx_queue_with_timeout(1).unwrap();
        assert!(node.state.lock().transmit_queue.len() <= 2);
        if delivered.load(Ordering::Relaxed) != u64::MAX {
            break;
        }
    }
    assert_eq!(
        delivered.load(Ordering::Relaxed),
        40,
        "first ready40ms radio slot must survive independent metadata admissions"
    );
    assert!(count.load(Ordering::Relaxed) >= 40);
    assert_eq!(crate::message_priority(ty), 0);
}

#[test]
fn lost_partial_schema_owner_can_recover_after_clear_eviction_or_readmission_failure() {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    crate::tests::ensure_common_test_schema();
    for loss in ["clear", "eviction", "readmission", "policy"] {
        let now = Arc::new(AtomicU64::new(1000));
        let clock = now.clone();
        let node = Router::new_with_clock(
            RouterConfig::new([]),
            Box::new(move || clock.load(Ordering::Relaxed)),
        );
        let credit = Arc::new(AtomicUsize::new(1));
        let allowance = credit.clone();
        let chunks = Arc::new(AtomicUsize::new(0));
        let seen = chunks.clone();
        let side = node.add_side_packed_with_options(
            "slow",
            move |bytes| {
                allowance
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    .map_err(|_| TelemetryError::Io("side tx busy"))?;
                if bytes.starts_with(b"SDT\x03") {
                    seen.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(192),
        );
        let request = discovery::build_discovery_schema_request("PEER", 1000).unwrap();
        node.learn_discovery_packet(&request, Some(side), true)
            .unwrap();
        for tick in 1000..1100 {
            now.store(tick, Ordering::Relaxed);
            credit.store(1, Ordering::Relaxed);
            node.dispatch_tx_queue_with_timeout(0).unwrap();
            if chunks.load(Ordering::Relaxed) > 0 {
                break;
            }
        }
        assert!(chunks.load(Ordering::Relaxed) > 0);
        let original = node.state.lock().discovery_side_throttle[&side].schema_response_packet_id;
        assert!(node.state.lock().discovery_side_throttle[&side].schema_response_active);
        match loss {
            "clear" => node.clear_tx_queue(),
            "eviction" => assert!(
                node.state
                    .lock()
                    .pop_shared_queue_item(RouterQueueKind::Transmit)
            ),
            "policy" => {
                node.set_typed_route(None, DataType::DiscoverySchema, side, false)
                    .unwrap();
                now.fetch_add(1, Ordering::Relaxed);
                credit.store(0, Ordering::Relaxed);
                node.dispatch_tx_queue_with_timeout(0).unwrap();
            }
            _ => {
                let budget = node.state.lock().memory.max_queue_budget;
                node.state.lock().memory.max_queue_budget = 1;
                now.fetch_add(1, Ordering::Relaxed);
                credit.store(0, Ordering::Relaxed);
                assert!(node.dispatch_tx_queue_with_timeout(0).is_err());
                node.state.lock().memory.max_queue_budget = budget;
            }
        }
        {
            let st = node.state.lock();
            let state = &st.discovery_side_throttle[&side];
            if loss == "clear" {
                assert!(!state.schema_response_active);
                assert!(
                    state.schema_response_pending,
                    "explicit clear requests a fresh prefix"
                );
            } else {
                assert!(state.schema_response_active);
                assert_eq!(
                    state.schema_response_phase,
                    SchemaResponsePhase::CatalogWaiting,
                    "quota/policy retirement preserves the already admitted prefix: {loss}"
                );
                assert_eq!(state.schema_response_packet_id, 0);
            }
        }
        if loss == "policy" {
            node.set_typed_route(None, DataType::DiscoverySchema, side, true)
                .unwrap();
        }
        now.store(3000, Ordering::Relaxed);
        credit.store(0, Ordering::Relaxed);
        assert!(
            node.poll_schema_response_on_side(side).unwrap(),
            "restart after {loss}"
        );
        let st = node.state.lock();
        let state = &st.discovery_side_throttle[&side];
        assert!(state.schema_response_active);
        assert_ne!(state.schema_response_packet_id, original);
    }
}
