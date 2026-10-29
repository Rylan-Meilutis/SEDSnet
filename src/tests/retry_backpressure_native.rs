use super::*;
use crate::discovery::{TopologyBoardNode, build_discovery_topology};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
struct Fixture {
    router: Router,
    side: usize,
    ty: DataType,
    ep: DataEndpoint,
    now: Arc<AtomicU64>,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    frames: Arc<Mutex<Vec<Arc<[u8]>>>>,
}
// A bounded shared catalog avoids growing global schema accounting per test case.
fn schema(large: bool) -> (DataEndpoint, DataType) {
    static SMALL: std::sync::OnceLock<(DataEndpoint, DataType)> = std::sync::OnceLock::new();
    static LARGE: std::sync::OnceLock<(DataEndpoint, DataType)> = std::sync::OnceLock::new();
    *if large { &LARGE } else { &SMALL }.get_or_init(|| {
        let ep = crate::config::register_endpoint("RETRY_NATIVE", false).unwrap();
        let ty = crate::config::register_data_type(
            if large {
                "RETRY_NATIVE_LARGE"
            } else {
                "RETRY_NATIVE_BYTE"
            },
            MessageElement::Static(
                if large { 512 } else { 1 },
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::Ordered,
            255,
        )
        .unwrap();
        (ep, ty)
    })
}
fn setup(name: &str) -> Fixture {
    setup_element(
        name,
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
    )
}
fn setup_element(_name: &str, element: MessageElement) -> Fixture {
    let (ep, ty) = schema(matches!(element, MessageElement::Static(512, _, _)));
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let mode = Arc::new(AtomicUsize::new(1));
    let behavior = mode.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let output = frames.clone();
    let side = router.add_side_packed_with_options(
        "radio",
        move |raw| {
            if wire_format::peek_frame_info(raw).is_ok_and(|f| f.envelope.ty == ty && !f.ack_only())
            {
                seen.fetch_add(1, Ordering::SeqCst);
                if behavior.load(Ordering::SeqCst) == 0 {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                if behavior.load(Ordering::SeqCst) == 1 {
                    output.lock().unwrap().push(Arc::from(raw));
                }
            }
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: false,
            header_template_enabled: false,
            ..Default::default()
        },
    );
    let topology = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    router.rx_from_side(&topology, side).unwrap();
    router.clear_tx_queue();
    Fixture {
        router,
        side,
        ty,
        ep,
        now,
        mode,
        calls,
        frames,
    }
}
fn publish(f: &Fixture) {
    f.router
        .tx(Packet::new(f.ty, &[f.ep], "GS", 1, Arc::from([1u8])).unwrap())
        .unwrap();
    assert_eq!(f.router.state.lock().end_to_end_reliable_tx.len(), 1);
}
fn owned_count(f: &Fixture) -> usize {
    f.router.state.lock().transmit_queue.iter().filter(|q|matches!(&q.item,RouterTxItem::ToSide{data,..} if Router::item_data_type(data).ok()==Some(f.ty))).count()
}
#[test]
fn blocked_side_keeps_one_owner_without_minting_e2e_retry_copies() {
    let f = setup("RETRY_BOUNDED_NATIVE");
    f.mode.store(0, Ordering::SeqCst);
    publish(&f);
    assert_eq!(owned_count(&f), 1);
    let interval = runtime_reliable_retransmit_ms();
    for tick in 1..=8 {
        f.now.store(tick * interval, Ordering::SeqCst);
        f.router.process_end_to_end_reliable_timeouts().unwrap();
        f.router.dispatch_tx_queue_with_timeout(0).unwrap();
        eprintln!(
            "tick={tick} queue={} calls={}",
            owned_count(&f),
            f.calls.load(Ordering::SeqCst)
        );
    }
    assert_eq!(
        owned_count(&f),
        1,
        "one accepted side-owned retry must suppress new copies while WouldBlock"
    );
    assert_eq!(f.router.state.lock().end_to_end_reliable_tx.len(), 1);
}
#[test]
fn accepted_after_backpressure_gets_a_real_post_admission_retry_interval() {
    let f = setup("RETRY_POST_WRITE_NATIVE");
    f.mode.store(0, Ordering::SeqCst);
    publish(&f);
    let interval = runtime_reliable_retransmit_ms();
    f.now.store(interval * 3, Ordering::SeqCst);
    f.mode.store(1, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(owned_count(&f), 0);
    assert_eq!(
        f.frames.lock().unwrap().len(),
        1,
        "first admitted retry must not immediately mint a second write"
    );
    let before = f.calls.load(Ordering::SeqCst);
    f.router.process_end_to_end_reliable_timeouts().unwrap();
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        before,
        "admission must restart timer, rather than immediately duplicate just-written work"
    );
    f.now.store(interval * 4, Ordering::SeqCst);
    f.router.process_end_to_end_reliable_timeouts().unwrap();
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert!(
        f.calls.load(Ordering::SeqCst) > before,
        "genuine lost/absent receipt still retries"
    );
}
#[test]
fn lost_first_write_still_retries_and_delivers_with_real_receipt() {
    let f = setup("RETRY_FIRST_LOST_NATIVE");
    f.mode.store(2, Ordering::SeqCst);
    publish(&f);
    let interval = runtime_reliable_retransmit_ms();
    assert!(f.frames.lock().unwrap().is_empty());
    f.mode.store(1, Ordering::SeqCst);
    f.now.store(interval, Ordering::SeqCst);
    f.router.process_end_to_end_reliable_timeouts().unwrap();
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(f.frames.lock().unwrap().len(), 1);
    let delivered = Arc::new(AtomicUsize::new(0));
    let target = delivered.clone();
    let handler = EndpointHandler::new_packet_handler(f.ep, move |_| {
        target.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let receiver = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("FC"),
        Box::new(move || interval),
    );
    let acks = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let out = acks.clone();
    let side = receiver.add_side_packed("return", move |wire| {
        out.lock().unwrap().push(Arc::from(wire));
        Ok(())
    });
    for wire in f.frames.lock().unwrap().iter() {
        receiver.rx_packed_from_side(wire, side).unwrap();
    }
    receiver.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    for wire in acks.lock().unwrap().iter() {
        f.router.rx_packed_from_side(wire, f.side).unwrap();
    }
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(
        f.router.state.lock().end_to_end_reliable_tx.len(),
        0,
        "actual owner receipt retires pending command"
    );
}
#[test]
fn blocked_radio_does_not_suppress_genuine_retry_on_another_destination() {
    let ep1 = crate::config::register_endpoint("RETRY_SPLIT_RADIO", false).unwrap();
    let ep2 = crate::config::register_endpoint("RETRY_SPLIT_WIRED", false).unwrap();
    let ty = crate::config::register_data_type(
        "RETRY_SPLIT_CONTROL",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep1, ep2],
        crate::ReliableMode::Ordered,
        255,
    )
    .unwrap();
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let radio = Arc::new(AtomicUsize::new(0));
    let rc = radio.clone();
    let wired = Arc::new(AtomicUsize::new(0));
    let wc = wired.clone();
    let a = router.add_side_packed("blocked-radio", move |raw| {
        if wire_format::peek_frame_info(raw).is_ok_and(|f| f.envelope.ty == ty) {
            rc.fetch_add(1, Ordering::SeqCst);
            return Err(TelemetryError::Io("side tx busy"));
        }
        Ok(())
    });
    let b = router.add_side_packed("accepted-but-first-lost-wired", move |raw| {
        if wire_format::peek_frame_info(raw).is_ok_and(|f| f.envelope.ty == ty) {
            wc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    for (side, sender, ep) in [(a, "FC", ep1), (b, "VB", ep2)] {
        let t = build_discovery_topology(
            sender,
            0,
            &[TopologyBoardNode {
                sender_id: sender.into(),
                reachable_endpoints: vec![ep],
                reachable_timesync_sources: vec![],
                connections: vec!["GS".into()],
            }],
        )
        .unwrap();
        router.rx_from_side(&t, side).unwrap();
    }
    router.clear_tx_queue();
    router
        .tx(Packet::new(ty, &[ep1, ep2], "GS", 1, Arc::from([1u8])).unwrap())
        .unwrap();
    assert_eq!(
        router
            .state
            .lock()
            .end_to_end_reliable_tx
            .values()
            .next()
            .unwrap()
            .pending_destinations
            .len(),
        2
    );
    assert_eq!(radio.load(Ordering::SeqCst), 1);
    assert_eq!(wired.load(Ordering::SeqCst), 1);
    now.store(runtime_reliable_retransmit_ms(), Ordering::SeqCst);
    router.process_end_to_end_reliable_timeouts().unwrap();
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(
        radio.load(Ordering::SeqCst),
        2,
        "retry existing blocked owner only, not a second encoded copy"
    );
    assert_eq!(
        wired.load(Ordering::SeqCst),
        2,
        "independent accepted/lost destination still gets its genuine retry"
    );
}
#[test]
fn reentrant_timeout_during_initial_and_claimed_child_callbacks_cannot_mint_copy() {
    use std::sync::Weak;
    let (ep, ty) = schema(false);
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    ));
    let weak: Weak<Router> = Arc::downgrade(&router);
    let ticks = now.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let side = router.add_side_packed("radio", move |raw| {
        if wire_format::peek_frame_info(raw).is_ok_and(|f| f.envelope.ty == ty) {
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            ticks.store(
                n as u64 * runtime_reliable_retransmit_ms() * 3,
                Ordering::SeqCst,
            );
            let router = weak.upgrade().unwrap();
            router.process_end_to_end_reliable_timeouts().unwrap();
            assert!(
                !router
                    .state
                    .lock()
                    .transmit_queue
                    .iter()
                    .any(|q| matches!(&q.item, RouterTxItem::EndToEndReplay { .. })),
                "in-flight lease must remain visible to reentrant timers"
            );
            return Err(TelemetryError::Io("side tx busy"));
        }
        Ok(())
    });
    let t = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    router.rx_from_side(&t, side).unwrap();
    router.clear_tx_queue();
    router
        .tx(Packet::new(ty, &[ep], "GS", 1, Arc::from([1u8])).unwrap())
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    now.fetch_add(1, Ordering::SeqCst);
    for _ in 0..8 {
        if calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        let work = Router::pop_transmit_queue_locked(
            &mut router.state.lock(),
            now.load(Ordering::SeqCst),
            false,
        )
        .unwrap();
        router.dispatch_queued_item(work).unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        router
            .state
            .lock()
            .transmit_queue
            .iter()
            .filter(|q| q.disposable & TX_E2E_CHILD != 0)
            .count(),
        1
    );
}
#[test]
fn child_retry_reuses_existing_slot_at_exact_shared_and_queue_budget() {
    let f = setup("RETRY_EXACT_BUDGET");
    f.mode.store(0, Ordering::SeqCst);
    publish(&f);
    {
        let mut st = f.router.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
    }
    for tick in 1..=12 {
        f.now
            .store(tick * runtime_reliable_retransmit_ms(), Ordering::SeqCst);
        f.router.process_end_to_end_reliable_timeouts().unwrap();
        f.router.dispatch_tx_queue_with_timeout(0).unwrap();
        assert_eq!(owned_count(&f), 1);
    }
}
#[cfg(feature = "compression")]
#[test]
fn opaque_child_fault_injection_uses_parent_metadata_without_payload_inspection() {
    let f = setup("RETRY_OPAQUE_KEY");
    f.mode.store(0, Ordering::SeqCst);
    publish(&f);
    // Force an opaque owned payload: timer correlation must use cached parent,
    // not inspect/decompress/hash child data. Restore original before actual send.
    let original = f
        .router
        .state
        .lock()
        .transmit_queue
        .iter()
        .find(|q| q.disposable & TX_E2E_CHILD != 0)
        .unwrap()
        .clone();
    // Use a different-cost admitted replacement while preserving its parent tag.
    {
        let mut st = f.router.state.lock();
        let mut opaque = original.clone();
        if let RouterTxItem::ToSide { data, .. } = &mut opaque.item {
            *data = RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from([0x11; 1])));
        }
        let cost = opaque.byte_cost();
        let index = st
            .transmit_queue
            .iter()
            .position(|q| q.disposable & TX_E2E_CHILD != 0)
            .unwrap();
        st.transmit_queue
            .update_admitted(index, cost, |q| *q = opaque)
            .unwrap();
    }
    for tick in 1..=6 {
        f.now
            .store(tick * runtime_reliable_retransmit_ms(), Ordering::SeqCst);
        f.router.process_end_to_end_reliable_timeouts().unwrap();
        assert_eq!(
            f.router
                .state
                .lock()
                .transmit_queue
                .iter()
                .filter(|q| q.disposable & TX_E2E_CHILD != 0)
                .count(),
            1
        );
    }
    {
        let mut st = f.router.state.lock();
        let cost = original.byte_cost();
        let index = st
            .transmit_queue
            .iter()
            .position(|q| q.disposable & TX_E2E_CHILD != 0)
            .unwrap();
        st.transmit_queue
            .update_admitted(index, cost, |q| *q = original)
            .unwrap();
    }
    f.mode.store(1, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(f.frames.lock().unwrap().len(), 1);
}
#[test]
fn partial_sdt_history_resumes_once_with_one_parent_owned_slot() {
    let (ep, ty) = schema(true);
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let quota = Arc::new(AtomicUsize::new(1000));
    let allowance = quota.clone();
    let wires = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let output = wires.clone();
    let chunk_calls = Arc::new(AtomicUsize::new(0));
    let counted = chunk_calls.clone();
    let options = RouterSideOptions {
        reliable_enabled: false,
        header_template_enabled: false,
        max_frame_bytes: 64,
        ..Default::default()
    };
    let side = router.add_side_packed_with_options(
        "radio",
        move |raw| {
            if raw.starts_with(b"SDT") && raw[3] == SIDE_TRANSPORT_KIND_CHUNK {
                counted.fetch_add(1, Ordering::SeqCst);
                if allowance
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |x| x.checked_sub(1))
                    .is_err()
                {
                    return Err(TelemetryError::Io("side tx busy"));
                }
            }
            output.lock().unwrap().push(Arc::from(raw));
            Ok(())
        },
        options.clone(),
    );
    let topo = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    router.rx_from_side(&topo, side).unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    router.clear_tx_queue();
    wires.lock().unwrap().clear();
    chunk_calls.store(0, Ordering::SeqCst);
    quota.store(1, Ordering::SeqCst);
    let payload: Arc<[u8]> = Arc::from(
        (0..512)
            .map(|x| ((x * 73 + x / 7) % 251) as u8)
            .collect::<Vec<_>>(),
    );
    router
        .tx(Packet::new(ty, &[ep], "GS", 1, payload.clone()).unwrap())
        .unwrap();
    assert_eq!(chunk_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        wires
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.starts_with(b"SDT") && w[3] == SIDE_TRANSPORT_KIND_CHUNK)
            .count(),
        1
    );
    for n in 1..=8 {
        now.store(n * runtime_reliable_retransmit_ms(), Ordering::SeqCst);
        router.process_end_to_end_reliable_timeouts().unwrap();
        assert_eq!(
            router
                .state
                .lock()
                .transmit_queue
                .iter()
                .filter(|q| q.disposable & TX_E2E_CHILD != 0)
                .count(),
            1
        );
    }
    quota.store(1000, Ordering::SeqCst);
    now.fetch_add(1, Ordering::SeqCst);
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(
        router
            .state
            .lock()
            .transmit_queue
            .iter()
            .filter(|q| q.disposable & TX_E2E_CHILD != 0)
            .count(),
        0
    );
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let seen = delivered.clone();
    let target = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |p| {
            seen.lock().unwrap().push(p.payload().to_vec());
            Ok(())
        })])
        .with_sender("FC"),
        Box::new(|| 0),
    );
    let acks = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let returned = acks.clone();
    let ingress = target.add_side_packed_with_options(
        "return",
        move |w| {
            returned.lock().unwrap().push(Arc::from(w));
            Ok(())
        },
        options,
    );
    for w in wires.lock().unwrap().iter() {
        target.rx_packed_from_side(w, ingress).unwrap();
    }
    target.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(delivered.lock().unwrap().as_slice(), [payload.to_vec()]);
    for ack in acks.lock().unwrap().iter() {
        router.rx_packed_from_side(ack, side).unwrap();
    }
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert!(router.state.lock().end_to_end_reliable_tx.is_empty());
}
#[test]
fn lost_first_owner_ack_replays_receipt_without_reapplying_control() {
    let f = setup("RETRY_ACK_FIRST_LOST");
    publish(&f);
    let interval = runtime_reliable_retransmit_ms();
    let applied = Arc::new(AtomicUsize::new(0));
    let calls = applied.clone();
    let target = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(f.ep, move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })])
        .with_sender("FC"),
        Box::new(move || interval),
    );
    let acks = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let output = acks.clone();
    let side = target.add_side_packed("return", move |w| {
        output.lock().unwrap().push(Arc::from(w));
        Ok(())
    });
    for w in f.frames.lock().unwrap().drain(..) {
        target.rx_packed_from_side(&w, side).unwrap();
    }
    target.dispatch_tx_queue_with_timeout(0).unwrap();
    acks.lock().unwrap().clear(); // explicit first-receipt loss
    f.now.store(interval, Ordering::SeqCst);
    f.router.process_end_to_end_reliable_timeouts().unwrap();
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    for w in f.frames.lock().unwrap().drain(..) {
        target.rx_packed_from_side(&w, side).unwrap();
    }
    target.dispatch_tx_queue_with_timeout(0).unwrap();
    for w in acks.lock().unwrap().iter() {
        f.router.rx_packed_from_side(w, f.side).unwrap();
    }
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(applied.load(Ordering::SeqCst), 1);
    assert!(f.router.state.lock().end_to_end_reliable_tx.is_empty());
}
#[cfg(feature = "compression")]
#[test]
fn compressed_downgrade_refusal_keeps_parent_and_publishes_prepared_owner_before_send() {
    let f = setup_element(
        "RETRY_CODEC_DOWNGRADE",
        MessageElement::Static(
            512,
            crate::MessageDataType::UInt8,
            crate::MessageClass::Data,
        ),
    );
    f.mode.store(0, Ordering::SeqCst);
    let payload: Arc<[u8]> = Arc::from([7u8; 512]);
    f.router
        .tx(Packet::new(f.ty, &[f.ep], "GS", 1, payload.clone()).unwrap())
        .unwrap();
    let (index, mut owner) = {
        let st = f.router.state.lock();
        st.transmit_queue
            .iter()
            .enumerate()
            .find(|(_, q)| q.disposable & TX_E2E_CHILD != 0)
            .map(|(n, q)| (n, q.clone()))
            .unwrap()
    };
    let RouterTxItem::ToSide { data, .. } = &mut owner.item else {
        unreachable!()
    };
    let raw = match data {
        RouterItem::Packet(p) => wire_format::pack_packet(p),
        RouterItem::Packed(bytes) => {
            crate::shared_bytes::with_slice(bytes, |raw| Arc::<[u8]>::from(raw)).unwrap()
        }
    };
    let compressed = wire_format::payload_encoding_for_side(&raw, true, 65536)
        .unwrap()
        .unwrap_or(raw);
    assert_ne!(compressed[0] & 1, 0);
    *data = RouterItem::Packed(crate::shared_bytes::convert(compressed));
    let parent = owner.deferred_since_ms;
    let original_budget = {
        let mut st = f.router.state.lock();
        let cost = owner.byte_cost();
        st.transmit_queue
            .update_admitted(index, cost, |q| *q = owner)
            .unwrap();
        let limit = st.memory.max_queue_budget;
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
        limit
    };
    let calls = f.calls.load(Ordering::SeqCst);
    f.now
        .store(runtime_reliable_retransmit_ms() * 3, Ordering::SeqCst);
    // Required expansion cannot fit: no codec/callback progress, original compressed owner survives.
    for _ in 0..4 {
        let work = Router::pop_transmit_queue_locked(
            &mut f.router.state.lock(),
            f.now.load(Ordering::SeqCst),
            false,
        );
        let Some(work) = work else { break };
        f.router.dispatch_queued_item(work).unwrap();
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), calls);
    {
        let st = f.router.state.lock();
        let q = st
            .transmit_queue
            .iter()
            .find(|q| q.disposable & TX_E2E_CHILD != 0)
            .unwrap();
        assert_eq!(q.deferred_since_ms, parent);
        let RouterTxItem::ToSide {
            data: RouterItem::Packed(bytes),
            ..
        } = &q.item
        else {
            panic!("compressed owner retained")
        };
        assert_ne!(bytes[0] & 1, 0);
        assert_eq!(st.codec_reserved_bytes, 0);
    }
    f.router.state.lock().memory.max_queue_budget = original_budget;
    f.now.fetch_add(1, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    {
        let st = f.router.state.lock();
        let q = st
            .transmit_queue
            .iter()
            .find(|q| q.disposable & TX_E2E_CHILD != 0)
            .unwrap();
        let RouterTxItem::ToSide {
            data: RouterItem::Packed(bytes),
            ..
        } = &q.item
        else {
            panic!("prepared plain owner retained")
        };
        assert_eq!(bytes[0] & 1, 0);
        assert_eq!(q.deferred_since_ms, parent);
        assert_eq!(st.codec_reserved_bytes, 0);
    }
    f.mode.store(1, Ordering::SeqCst);
    f.now.fetch_add(1, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    let frames = f.frames.lock().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        wire_format::unpack_packet(&frames[0]).unwrap().payload(),
        payload.as_ref()
    );
}

// Read-only completion-evidence audit. No production query/pruning API.
#[test]
fn egress_completion_audit_authoritative_local_receipt_leaves_no_completion_cache() {
    let f = setup("EGRESS_LOCAL_COMPLETION_AUDIT");
    publish(&f);
    let id = *f
        .router
        .state
        .lock()
        .end_to_end_reliable_tx
        .keys()
        .next()
        .unwrap();
    let target = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(f.ep, |_| Ok(()))])
            .with_sender("FC"),
        Box::new(|| 0),
    );
    let receipts = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let out = receipts.clone();
    let side = target.add_side_packed("return", move |w| {
        out.lock().unwrap().push(Arc::from(w));
        Ok(())
    });
    for wire in f.frames.lock().unwrap().iter() {
        target.rx_packed_from_side(wire, side).unwrap();
    }
    target.dispatch_tx_queue_with_timeout(0).unwrap();
    for receipt in receipts.lock().unwrap().iter() {
        f.router.rx_packed_from_side(receipt, f.side).unwrap();
    }
    let state = f.router.state.lock();
    assert!(!state.end_to_end_reliable_tx.contains_key(&id));
    assert!(
        state
            .forwarded_receipts
            .as_ref()
            .is_none_or(|cache| !cache.destinations.contains_key(&id)),
        "local publisher completion does not populate forwarding-receipt cache"
    );
    assert!(
        !state
            .reliable_return_routes
            .get(&id)
            .is_some_and(|route| route.delivery_completed),
        "local application-delivery marker is not publisher all-owner completion"
    );
}

#[test]
fn egress_completion_audit_timeout_has_same_absent_parent_and_receipt_cache() {
    let f = setup("EGRESS_TIMEOUT_AUDIT");
    publish(&f);
    let id = *f
        .router
        .state
        .lock()
        .end_to_end_reliable_tx
        .keys()
        .next()
        .unwrap();
    f.router
        .state
        .lock()
        .end_to_end_reliable_tx
        .get_mut(&id)
        .unwrap()
        .retries = runtime_reliable_max_retries();
    f.now
        .store(runtime_reliable_retransmit_ms(), Ordering::SeqCst);
    let _ = f.router.process_end_to_end_reliable_timeouts();
    let state = f.router.state.lock();
    assert!(!state.end_to_end_reliable_tx.contains_key(&id));
    assert!(
        state
            .forwarded_receipts
            .as_ref()
            .is_none_or(|cache| !cache.destinations.contains_key(&id))
    );
    assert!(
        !state
            .reliable_return_routes
            .get(&id)
            .is_some_and(|route| route.delivery_completed)
    );
}

#[test]
fn egress_completion_audit_packet_id_does_not_bind_frozen_owner_contract() {
    let f = setup("EGRESS_CONTRACT_AUDIT");
    let p = |targets: Vec<u64>| {
        Packet::new_with_wire_contract(
            f.ty,
            &[f.ep],
            "GS",
            123,
            7,
            Arc::from([1u8]),
            Some(crate::config::get_message_meta(f.ty).element),
            targets.into(),
        )
        .unwrap()
    };
    let first = p(vec![Router::sender_hash("FC")]);
    let changed = p(vec![Router::sender_hash("RF"), Router::sender_hash("FC")]);
    assert_eq!(first.packet_id(), changed.packet_id());
    assert_ne!(first.wire_target_senders(), changed.wire_target_senders());
    assert_ne!(
        wire_format::pack_packet(&first),
        wire_format::pack_packet(&changed)
    );
}

fn completion_actual_receipts(f: &Fixture, sender: &str, wire: &[u8]) -> Vec<Arc<[u8]>> {
    let receiver = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(f.ep, |_| Ok(()))])
            .with_sender(sender),
        Box::new(|| 0),
    );
    let receipts = Arc::new(Mutex::new(Vec::<Arc<[u8]>>::new()));
    let output = receipts.clone();
    let side = receiver.add_side_packed("return", move |wire| {
        if wire_format::peek_envelope(wire).is_ok_and(|env| env.ty == DataType::ReliableAck) {
            output.lock().unwrap().push(Arc::from(wire));
        }
        Ok(())
    });
    receiver.rx_packed_from_side(wire, side).unwrap();
    receiver.dispatch_tx_queue_with_timeout(0).unwrap();
    let result = receipts.lock().unwrap().clone();
    assert!(
        !result.is_empty(),
        "actual successful owner must generate a receipt"
    );
    result
}

fn tracked_fixture(admit: bool) -> (Fixture, RetryTracker, Arc<Mutex<Vec<PackedWriteLease>>>) {
    let f = setup("INTERNAL_TRACKER");
    f.router.remove_side(f.side).unwrap();
    let leases = Arc::new(Mutex::new(Vec::new()));
    let out = leases.clone();
    let frames = f.frames.clone();
    let ty = f.ty;
    let behavior = f.mode.clone();
    let (side, tracker) = f
        .router
        .add_side_packed_leased_with_priority_and_options(
            "radio",
            move |lease, _| {
                if wire_format::peek_envelope(lease.bytes()).is_ok_and(|env| env.ty == ty) {
                    if behavior.load(Ordering::SeqCst) == 0 {
                        return Err(TelemetryError::Io("side tx busy"));
                    }
                    if admit {
                        lease.admit()?;
                    }
                    frames.lock().unwrap().push(Arc::from(lease.bytes()));
                    out.lock().unwrap().push(lease);
                }
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: false,
                header_template_enabled: false,
                ..Default::default()
            },
            RetryTrackerLimits::default(),
        )
        .unwrap();
    assert_eq!(side, f.side);
    let topology = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![f.ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    f.router.rx_from_side(&topology, side).unwrap();
    f.router.clear_tx_queue();
    (f, tracker, leases)
}
fn next_tracked_retry(f: &Fixture) {
    f.now
        .fetch_add(runtime_reliable_retransmit_ms(), Ordering::SeqCst);
    f.router.process_end_to_end_reliable_timeouts().unwrap();
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
}
fn finish_tracked(f: &Fixture, wire: &[u8]) {
    for receipt in completion_actual_receipts(f, "FC", wire) {
        f.router.rx_packed_from_side(&receipt, f.side).unwrap();
    }
}
#[test]
fn tracker_final_owner_retires_only_sdk_retry_after_physical_drain() {
    let (f, _tracker, leases) = tracked_fixture(true);
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    next_tracked_retry(&f);
    let retry = leases.lock().unwrap().last().unwrap().clone();
    finish_tracked(&f, first.bytes());
    assert!(retry.discard_if_retired());
    assert_eq!(retry.try_start(), WriteStart::Retired);
    assert_eq!(first.try_start(), WriteStart::Ready);
}
#[test]
fn tracker_first_unknown_and_started_retries_are_retained() {
    for drained in [false, true] {
        let (f, _t, leases) = tracked_fixture(true);
        publish(&f);
        let first = leases.lock().unwrap()[0].clone();
        if drained {
            assert_eq!(first.try_start(), WriteStart::Ready);
            first.report_drained().unwrap();
        }
        next_tracked_retry(&f);
        let retry = leases.lock().unwrap().last().unwrap().clone();
        if drained {
            assert_eq!(retry.try_start(), WriteStart::Ready);
        }
        finish_tracked(&f, first.bytes());
        assert!(!retry.discard_if_retired());
        assert_eq!(retry.try_start(), WriteStart::Ready);
        assert!(!first.discard_if_retired());
    }
}
#[test]
fn tracker_late_admission_cannot_consume_prior_completion() {
    let (f, _t, leases) = tracked_fixture(false);
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::PendingAdmission);
    first.admit().unwrap();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    next_tracked_retry(&f);
    let retry = leases.lock().unwrap().last().unwrap().clone();
    finish_tracked(&f, first.bytes());
    retry.admit().unwrap();
    assert!(!retry.discard_if_retired());
    assert_eq!(retry.try_start(), WriteStart::Ready);
}
#[test]
fn tracker_reconnect_invalidates_unconsumed_retirement_but_not_consumed_discard() {
    for discard in [false, true] {
        let (f, t, leases) = tracked_fixture(true);
        publish(&f);
        let first = leases.lock().unwrap()[0].clone();
        assert_eq!(first.try_start(), WriteStart::Ready);
        first.report_drained().unwrap();
        next_tracked_retry(&f);
        let retry = leases.lock().unwrap().last().unwrap().clone();
        finish_tracked(&f, first.bytes());
        if discard {
            assert!(retry.discard_if_retired());
        }
        t.invalidate_generation().unwrap();
        assert_eq!(
            retry.try_start(),
            if discard {
                WriteStart::Retired
            } else {
                WriteStart::Ready
            }
        );
    }
}
#[test]
fn tracker_unrelated_side_reset_does_not_invalidate_radio() {
    let (f, _t, leases) = tracked_fixture(true);
    let (_, other) = f
        .router
        .add_side_packed_leased_with_priority_and_options(
            "other",
            |_, _| Ok(()),
            RouterSideOptions::default(),
            RetryTrackerLimits::default(),
        )
        .unwrap();
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    next_tracked_retry(&f);
    let retry = leases.lock().unwrap().last().unwrap().clone();
    other.invalidate_generation().unwrap();
    finish_tracked(&f, first.bytes());
    assert!(retry.discard_if_retired());
}

#[test]
fn tracker_waits_for_all_frozen_owners_and_rejects_unknown_receipts() {
    let (f, _t, leases) = tracked_fixture(true);
    let topology = build_discovery_topology(
        "RF",
        0,
        &[TopologyBoardNode {
            sender_id: "RF".into(),
            reachable_endpoints: vec![f.ep],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    f.router.rx_from_side(&topology, f.side).unwrap();
    f.router.clear_tx_queue();
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    next_tracked_retry(&f);
    let retry = leases.lock().unwrap().last().unwrap().clone();
    finish_tracked(&f, first.bytes());
    assert!(!retry.discard_if_retired());
    for receipt in completion_actual_receipts(&f, "RF", first.bytes()) {
        f.router.rx_packed_from_side(&receipt, f.side).unwrap();
    }
    assert!(retry.discard_if_retired());
}
#[test]
fn tracker_wrong_owner_publisher_and_legacy_receipts_retain_work() {
    for mode in 0..3 {
        let (f, _t, leases) = tracked_fixture(true);
        publish(&f);
        let first = leases.lock().unwrap()[0].clone();
        assert_eq!(first.try_start(), WriteStart::Ready);
        first.report_drained().unwrap();
        next_tracked_retry(&f);
        let retry = leases.lock().unwrap().last().unwrap().clone();
        let receipt = completion_actual_receipts(&f, "FC", first.bytes()).remove(0);
        let ack = wire_format::unpack_packet(&receipt).unwrap();
        let altered = if mode == 2 {
            Packet::new(
                ack.data_type(),
                ack.endpoints(),
                "E2EACK:FC",
                ack.timestamp(),
                Arc::from(ack.payload()),
            )
            .unwrap()
        } else {
            Packet::new_with_wire_contract(
                ack.data_type(),
                ack.endpoints(),
                ack.sender(),
                ack.timestamp(),
                ack.nonce().wrapping_add(1),
                Arc::from(ack.payload()),
                ack.wire_shape(),
                if mode == 0 {
                    vec![Router::sender_hash("UNKNOWN"), Router::sender_hash("GS")]
                } else {
                    vec![
                        Router::sender_hash("FC"),
                        Router::sender_hash("OTHER_PUBLISHER"),
                    ]
                }
                .into(),
            )
            .unwrap()
        };
        f.router
            .rx_packed_from_side(&wire_format::pack_packet(&altered), f.side)
            .unwrap();
        assert!(!retry.discard_if_retired());
        if mode == 0 {
            f.router.rx_packed_from_side(&receipt, f.side).unwrap();
            assert!(retry.discard_if_retired());
        }
    }
}
#[test]
fn tracker_timeout_and_side_reuse_never_authorize_old_proofs() {
    let (f, t, leases) = tracked_fixture(true);
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    next_tracked_retry(&f);
    let retry = leases.lock().unwrap().last().unwrap().clone();
    f.router.remove_side(f.side).unwrap();
    let (side, _new) = f
        .router
        .add_side_packed_leased_with_priority_and_options(
            "replacement",
            |_, _| Ok(()),
            RouterSideOptions::default(),
            RetryTrackerLimits::default(),
        )
        .unwrap();
    assert_eq!(side, f.side);
    finish_tracked(&f, first.bytes());
    assert!(!retry.discard_if_retired());
    assert_eq!(retry.try_start(), WriteStart::Ready);
    t.invalidate_generation().unwrap();
}

#[test]
fn tracker_retry_provenance_survives_child_queue_admission_and_refusal() {
    let (f, _t, leases) = tracked_fixture(true);
    publish(&f);
    let first = leases.lock().unwrap()[0].clone();
    assert_eq!(first.try_start(), WriteStart::Ready);
    first.report_drained().unwrap();
    f.mode.store(0, Ordering::SeqCst);
    next_tracked_retry(&f);
    assert!(
        f.router
            .state
            .lock()
            .transmit_queue
            .iter()
            .any(|q| q.disposable & TX_E2E_CHILD != 0 && q.disposable & TX_E2E_RETRY != 0)
    );
    f.now.fetch_add(2, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert_eq!(leases.lock().unwrap().len(), 1);
    f.mode.store(1, Ordering::SeqCst);
    f.now.fetch_add(2, Ordering::SeqCst);
    f.router.dispatch_tx_queue_with_timeout(0).unwrap();
    let retry = leases.lock().unwrap().last().unwrap().clone();
    assert_ne!(retry.bytes().as_ptr(), first.bytes().as_ptr());
    finish_tracked(&f, first.bytes());
    assert!(retry.discard_if_retired());
}
