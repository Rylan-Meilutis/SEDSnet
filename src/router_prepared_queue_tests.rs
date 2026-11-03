use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

fn schema() -> (DataEndpoint, DataType, DataType) {
    let ep = crate::config::register_endpoint("ATOMIC_FENCE_EP", false).unwrap();
    let signal = crate::config::register_data_type(
        "ATOMIC_FENCE_SIGNAL",
        MessageElement::Dynamic(MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        240,
    )
    .unwrap();
    let candidate = crate::config::register_data_type(
        "ATOMIC_FENCE_CANDIDATE",
        MessageElement::Dynamic(MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        23,
    )
    .unwrap();
    (ep, signal, candidate)
}
fn packet(ty: DataType, ep: DataEndpoint) -> Packet {
    Packet::new_with_nonce(ty, &[ep], "ATOMIC_SOURCE", 9001, 57, Arc::from([1, 2, 3])).unwrap()
}
fn node() -> Router {
    let mut memory = crate::config::RuntimeMemoryConfig::default();
    memory.starting_queue_size = 16384;
    memory.max_queue_budget = memory.max_queue_budget.max(2 * 1024 * 1024);
    let r = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("ATOMIC_SOURCE")
            .with_memory_config(memory)
            .unwrap(),
        Box::new(|| 10000),
    );
    r.clear_queues();
    r
}
fn counts(r: &Router) -> (usize, usize, usize, usize) {
    let st = r.state.lock();
    (
        st.transmit_queue.len(),
        st.transmit_queue.bytes_used(),
        st.end_to_end_reliable_tx.len(),
        st.reliable_tx.len(),
    )
}
fn plan<'a>(r: &'a Router, p: Packet) -> PreparedQueuedPacket<'a> {
    r.prepare_tx_queue(p)
        .unwrap_or_else(|e| panic!("prepare {:?}", e.error))
}
#[test]
fn atomic_queue_old_separate_query_causal_retains_both_after_interleaving() {
    let (ep, signal, candidate) = schema();
    let r = node();
    assert!(!r.has_pending_reliable_tx_type(signal));
    r.tx_queue(packet(signal, ep)).unwrap(); // another producer wins after query
    r.try_tx_queue(packet(candidate, ep)).unwrap();
    let st = r.state.lock();
    assert!(
        st.transmit_queue
            .iter()
            .any(|q| q.accepted_type == signal.as_u32())
    );
    assert!(
        st.transmit_queue
            .iter()
            .any(|q| q.accepted_type == candidate.as_u32()),
        "published separate query fails to fence retention"
    );
}
#[test]
fn atomic_queue_same_interleaving_blocks_and_preserves_original() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let p = packet(candidate, ep);
    let mut prep = plan(&r, p.clone());
    assert_eq!(r.try_has_pending_reliable_tx_type(signal), Ok(false));
    r.tx_queue(packet(signal, ep)).unwrap();
    let before = counts(&r);
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::BlockedPendingReliableType)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(prep.into_packet(), Some(p));
}
#[test]
fn atomic_queue_core_and_schema_busy_preserve_packet_without_waiting() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let p = packet(candidate, ep);
    let mut prep = plan(&r, p.clone());
    let before = counts(&r);
    std::thread::scope(|scope| {
        let held = r.state.lock();
        let (rr, pp) = (&r, &mut prep);
        let (tx, rx) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let start = Instant::now();
            tx.send((
                rr.try_tx_queue_unless_pending_reliable_type(pp, signal),
                rr.try_has_pending_reliable_tx_type(signal),
                start.elapsed(),
            ))
            .unwrap();
        });
        let result = rx.recv_timeout(Duration::from_millis(500));
        drop(held);
        let (a, b, elapsed) = result.expect("core try API waited");
        assert_eq!(a, Err(TryQueuedPacketError::CoreBusy));
        assert_eq!(b, Err(TryPendingTypeError::CoreBusy));
        assert!(elapsed < Duration::from_millis(250));
    });
    let held = crate::config::try_prepared_schema_guard().unwrap();
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::SchemaBusy)
    );
    drop(held);
    assert_eq!(counts(&r), before);
    assert_eq!(prep.packet.as_ref(), Some(&p));
    r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal)
        .unwrap();
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::AlreadyAdmitted)
    );
    assert_eq!(counts(&r).0, before.0 + 1);
    assert!(prep.into_packet().is_none());
}
#[test]
fn atomic_queue_capacity_overflow_and_stale_preserve_existing_owners() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let p = packet(candidate, ep);
    let mut prep = plan(&r, p.clone());
    let before = counts(&r);
    let budget = r.state.lock().memory.max_queue_budget;
    r.state.lock().memory.max_queue_budget = 0;
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::Capacity)
    );
    r.state.lock().memory.max_queue_budget = budget;
    let cost = prep.cost;
    prep.cost = usize::MAX;
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::Capacity)
    );
    prep.cost = cost;
    prep.meta.priority ^= 1;
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::StalePreparation)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(prep.into_packet(), Some(p));
}
#[test]
fn atomic_queue_saturated_nested_budget_matches_ordinary_then_refuses_overflow() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let mut prep = plan(&r, packet(candidate, ep));
    {
        let st = r.state.lock();
        let old = st.shared_queue_bytes_used();
        let schema = crate::config::try_prepared_schema_guard().unwrap();
        assert_eq!(st.queued_packet_budget_used(&schema), old);
    }
    // Exercise an actual nested component (not merely candidate+used overflow).
    let side = r.add_side_packed("budget-side", |_| Ok(()));
    {
        let mut st = r.state.lock();
        st.side_transport.get_mut(&side).unwrap().rx_chunk_bytes = usize::MAX;
    }
    let before = counts(&r);
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::Capacity)
    );
    assert_eq!(counts(&r), before);
    r.state
        .lock()
        .side_transport
        .get_mut(&side)
        .unwrap()
        .rx_chunk_bytes = 0;
    r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal)
        .unwrap();
    {
        let st = r.state.lock();
        let old = st.shared_queue_bytes_used();
        let schema = crate::config::try_prepared_schema_guard().unwrap();
        assert_eq!(st.queued_packet_budget_used(&schema), old);
    }
}
fn assert_pending(r: &Router, ty: DataType, expected: bool) {
    assert_eq!(r.has_pending_reliable_tx_type(ty), expected);
    assert_eq!(r.try_has_pending_reliable_tx_type(ty), Ok(expected));
}
#[test]
fn atomic_queue_pending_active_unknown_packed_replay_and_owner_matrix() {
    let (ep, signal, candidate) = schema();
    let r = node();
    for (total, slots, expected) in [
        (1, vec![(signal.as_u32(), 1)], true),
        (1, vec![(candidate.as_u32(), 1)], false),
        (1, vec![(0, 1)], true),
        (2, vec![(candidate.as_u32(), 1)], true),
        (0, vec![(candidate.as_u32(), 1)], true),
    ] {
        {
            let mut st = r.state.lock();
            st.active_queued_types.fill((0, 0));
            for (i, v) in slots.iter().enumerate() {
                st.active_queued_types[i] = *v;
            }
            r.active_queued_tx.store(total, Ordering::Release);
        }
        assert_pending(&r, signal, expected);
        let mut prep = plan(&r, packet(candidate, ep));
        let before = counts(&r);
        if expected {
            assert_eq!(
                r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
                Err(TryQueuedPacketError::BlockedPendingReliableType)
            );
            assert_eq!(counts(&r), before);
        }
    }
    {
        let mut st = r.state.lock();
        st.active_queued_types.fill((0, 0));
        r.active_queued_tx.store(0, Ordering::Release);
    }
    let q = |item, accepted_type| TxQueued {
        disposable: 0,
        item,
        ignore_local: false,
        priority: 0,
        delivery_state: QueuedDelivery::Untracked,
        accepted_type,
        deferred_since_ms: 0,
        retry_after_ms: 0,
    };
    let variants = vec![
        q(
            RouterTxItem::Broadcast(RouterItem::Packed(crate::shared_bytes::convert(
                Arc::<[u8]>::from(&b"unknown"[..]),
            ))),
            0,
        ),
        q(
            RouterTxItem::ReliableReplay {
                dst: 0,
                ty: signal,
                seq: 1,
                bytes: crate::shared_bytes::convert(Arc::<[u8]>::from(&b"retry"[..])),
            },
            0,
        ),
    ];
    for item in variants {
        r.state.lock().transmit_queue.push_back(item).unwrap();
        assert_pending(&r, signal, true);
        r.clear_queues();
    }
    for pending_type in [0, signal.as_u32(), candidate.as_u32()] {
        let owner = EndToEndReliableSent {
            completion_epoch: 0,
            pending_type,
            ordered_type: None,
            waiting_for_predecessor: false,
            data: RouterItem::Packet(packet(candidate, ep)),
            pending_destinations: BTreeMap::new(),
            tracked_destinations: false,
            last_send_ms: 0,
            retries: 0,
            queued: false,
        };
        r.state
            .lock()
            .end_to_end_reliable_tx
            .insert(123, Box::new(owner));
        assert_pending(&r, signal, pending_type != candidate.as_u32());
        r.state.lock().end_to_end_reliable_tx.clear();
    }
    let mut sent = BTreeMap::new();
    sent.insert(
        1,
        ReliableSent {
            bytes: crate::shared_bytes::convert(Arc::<[u8]>::from(&b"retry"[..])),
            last_send_ms: 0,
            retries: 0,
            queued: false,
            partial_acked: false,
        },
    );
    r.state.lock().reliable_tx.insert(
        (0, signal.as_u32()),
        ReliableTxState {
            next_seq: 2,
            sent_order: VecDeque::from([1]),
            sent,
        },
    );
    assert_pending(&r, signal, true);
}
#[test]
fn atomic_queue_schema_classification_matches_legacy_managed_and_ordered_tail() {
    let (ep, signal, candidate) = schema();
    let r = node();
    for p in [packet(candidate, ep), packet(signal, ep)] {
        let mut prep = plan(&r, p.clone());
        let legacy_priority = Router::item_type_priority(&RouterItem::Packet(p.clone()))
            .unwrap()
            .1;
        assert_eq!(prep.priority, legacy_priority);
        let old_disposable = RouterInner::classify_transmit_disposable(&TxQueued {
            disposable: 0,
            item: RouterTxItem::Broadcast(RouterItem::Packet(p)),
            ignore_local: false,
            priority: 0,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        });
        assert_eq!(prep.untracked_disposable, old_disposable);
        r.try_tx_queue_unless_pending_reliable_type(&mut prep, DataType::ReliableAck)
            .unwrap();
    }
    r.clear_queues();
    r.state
        .lock()
        .local_services
        .as_mut()
        .unwrap()
        .managed_variable_types
        .insert(candidate.as_u32());
    let mut first = plan(&r, packet(candidate, ep));
    r.try_tx_queue_unless_pending_reliable_type(&mut first, signal)
        .unwrap();
    {
        let mut st = r.state.lock();
        let mut first = st.transmit_queue.remove_pos(0).unwrap();
        assert_eq!(first.priority, 254);
        first.priority = 19;
        st.transmit_queue.push_back(first).unwrap();
    }
    let mut second = plan(&r, packet(candidate, ep));
    r.try_tx_queue_unless_pending_reliable_type(&mut second, signal)
        .unwrap();
    let st = r.state.lock();
    let tail = st.transmit_queue.get(1).unwrap();
    assert_eq!(tail.priority, 19);
    assert_eq!(tail.delivery_state, QueuedDelivery::OrderedTail);
    assert_eq!(tail.disposable, 0);
    assert!(!tail.ignore_local);
}
#[test]
fn atomic_queue_role_failure_returns_exact_packet_and_wrong_router_is_stale() {
    let (ep, signal, candidate) = schema();
    let p = packet(candidate, ep);
    let relay = Router::new(RouterConfig::relay());
    let failure = relay
        .prepare_tx_queue(p.clone())
        .err()
        .expect("relay must refuse");
    assert_eq!(failure.packet, p);
    assert!(matches!(failure.error, TelemetryError::PermissionDenied));
    let r = node();
    let other = node();
    let mut prep = plan(&r, p.clone());
    let before = counts(&other);
    assert_eq!(
        other.try_tx_queue_unless_pending_reliable_type(&mut prep, signal),
        Err(TryQueuedPacketError::StalePreparation)
    );
    assert_eq!(counts(&other), before);
    assert_eq!(prep.into_packet(), Some(p));
}
#[test]
fn atomic_queue_actual_worker_preserves_packet_and_never_runs_callback_or_clock_in_commit() {
    let (ep, signal, candidate) = schema();
    let inside = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let flag = inside.clone();
    let output = seen.clone();
    let handler = EndpointHandler::new_packet_handler(ep, move |p| {
        assert!(!flag.load(Ordering::SeqCst));
        output.lock().unwrap().push(p.clone());
        Ok(())
    });
    let flag = inside.clone();
    let r = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("ATOMIC_SOURCE"),
        Box::new(move || {
            assert!(!flag.load(Ordering::SeqCst));
            10000
        }),
    );
    r.clear_queues();
    let p = packet(candidate, ep);
    let mut prep = plan(&r, p.clone());
    inside.store(true, Ordering::SeqCst);
    r.try_tx_queue_unless_pending_reliable_type(&mut prep, signal)
        .unwrap();
    inside.store(false, Ordering::SeqCst);
    assert!(seen.lock().unwrap().is_empty());
    r.process_all_queues().unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![p]);
}
#[test]
fn atomic_queue_small_frozen_and_targeted_untracked_match_legacy() {
    let (ep, signal, _) = schema();
    let r = node();
    let ty = crate::config::register_data_type(
        "ATOMIC_FROZEN_CONTROL",
        MessageElement::Static(3, MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::None,
        7,
    )
    .unwrap();
    for targets in [None, Some(Arc::<[u64]>::from([123]))] {
        let p = Packet::new_with_owned_wire_contract(
            ty,
            Arc::from([ep]),
            Arc::from("ATOMIC_SOURCE"),
            9001,
            57,
            crate::config::StandardSmallPayload::from_arc(Arc::from([1, 2, 3])),
            None,
            targets,
        )
        .unwrap();
        let expected_priority = Router::item_type_priority(&RouterItem::Packet(p.clone()))
            .unwrap()
            .1;
        let targeted = !p.wire_target_senders().is_empty();
        let mut prepared = plan(&r, p);
        assert_eq!(prepared.priority, expected_priority);
        assert_eq!(prepared.priority, if targeted { 254 } else { 7 });
        assert_eq!(prepared.untracked_disposable, !targeted);
        r.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal)
            .unwrap();
        let st = r.state.lock();
        let q = st.transmit_queue.iter().last().unwrap();
        assert_eq!(q.disposable, if targeted { 0 } else { TX_DISPOSABLE });
        assert_eq!(q.delivery_state, QueuedDelivery::Untracked);
        #[cfg(feature = "latest-value-egress")]
        {
            assert!(!st.canonical_catalog_owner(q));
            assert!(!st.latest_entry_eligible(q));
        }
        drop(st);
        r.clear_queues();
    }
}
#[test]
fn atomic_queue_physical_slot_refusal_does_not_evict_prior_owner() {
    let (ep, signal, candidate) = schema();
    let r = node();
    r.state.lock().transmit_queue = BoundedDeque::new(4096, 1, 1.0);
    let mut first = plan(&r, packet(candidate, ep));
    r.try_tx_queue_unless_pending_reliable_type(&mut first, signal)
        .unwrap();
    let before = counts(&r);
    let p = packet(candidate, ep);
    let mut next = plan(&r, p.clone());
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut next, signal),
        Err(TryQueuedPacketError::Capacity)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(next.into_packet(), Some(p));
}
#[test]
fn atomic_queue_actual_two_router_packed_delivery_preserves_nonce_and_original_utc() {
    let (ep, signal, candidate) = schema();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let a = node();
    let handler = EndpointHandler::new_packet_handler(ep, move |p| {
        if p.data_type() == candidate {
            output.lock().unwrap().push((
                p.packet_id(),
                p.nonce(),
                p.timestamp(),
                p.payload().to_vec(),
            ));
        }
        Ok(())
    });
    let b = Router::new_with_clock(
        RouterConfig::new([handler]).with_sender("ATOMIC_SINK"),
        Box::new(|| 10000),
    );
    let ab = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let ba = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let out = ab.clone();
    let aside = a.add_side_packed("ab", move |wire| {
        out.lock().unwrap().push(wire.to_vec());
        Ok(())
    });
    let out = ba.clone();
    let bside = b.add_side_packed("ba", move |wire| {
        out.lock().unwrap().push(wire.to_vec());
        Ok(())
    });
    a.clear_queues();
    b.clear_queues();
    let p = packet(candidate, ep);
    let mut prepared = plan(&a, p.clone());
    let held = a.state.lock();
    assert_eq!(
        a.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal),
        Err(TryQueuedPacketError::CoreBusy)
    );
    drop(held);
    a.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal)
        .unwrap();
    for _ in 0..20 {
        a.process_all_queues_with_timeout(0).unwrap();
        b.process_all_queues_with_timeout(0).unwrap();
        let frames = std::mem::take(&mut *ab.lock().unwrap());
        for wire in frames {
            b.rx_packed_from_side(&wire, bside).unwrap();
        }
        let frames = std::mem::take(&mut *ba.lock().unwrap());
        for wire in frames {
            a.rx_packed_from_side(&wire, aside).unwrap();
        }
    }
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(p.packet_id(), 57, 9001, vec![1, 2, 3])]
    );
}
#[test]
fn atomic_queue_actual_schema_mutation_refuses_without_rebuilding_original() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let p = packet(candidate, ep);
    let mut prepared = plan(&r, p.clone());
    let before = counts(&r);
    let policy = prepared.meta.e2e_encryption;
    crate::config::set_data_type_e2e_encryption_policy(candidate, E2eEncryptionPolicy::PreferOn)
        .unwrap();
    let result = r.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal);
    crate::config::set_data_type_e2e_encryption_policy(candidate, policy).unwrap();
    assert_eq!(result, Err(TryQueuedPacketError::StalePreparation));
    assert_eq!(counts(&r), before);
    assert_eq!(prepared.into_packet(), Some(p));
}
#[test]
fn atomic_queue_mixed_priority_queue_bytes_refuse_without_evicting_original() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let large = |ty| {
        Packet::new_with_nonce(
            ty,
            &[ep],
            "ATOMIC_SOURCE",
            9001,
            57,
            Arc::from(vec![42u8; 1024]),
        )
        .unwrap()
    };
    let mut first = plan(&r, large(candidate));
    let limit = first.cost * 2 - 1;
    r.state.lock().transmit_queue = BoundedDeque::new(limit, limit, 1.0);
    assert!(r.state.lock().transmit_queue.capacity() >= 2);
    r.try_tx_queue_unless_pending_reliable_type(&mut first, DataType::ReliableAck)
        .unwrap();
    let before = counts(&r);
    let p = large(signal);
    let mut higher = plan(&r, p.clone());
    assert!(higher.priority > 23);
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut higher, DataType::ReliableAck),
        Err(TryQueuedPacketError::Capacity)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(
        r.state
            .lock()
            .transmit_queue
            .iter()
            .next()
            .unwrap()
            .accepted_type,
        candidate.as_u32()
    );
    assert_eq!(higher.into_packet(), Some(p));
}
#[test]
fn atomic_queue_missing_schema_prepare_error_returns_original_packet() {
    let (ep, _, _) = schema();
    let r = node();
    let p = Packet::new_with_owned_wire_contract(
        DataType(u32::MAX - 1),
        Arc::from([ep]),
        Arc::from("ATOMIC_SOURCE"),
        9001,
        57,
        crate::config::StandardSmallPayload::from_arc(Arc::from([1, 2, 3])),
        Some(MessageElement::Static(
            3,
            MessageDataType::UInt8,
            crate::MessageClass::Data,
        )),
        None,
    )
    .unwrap();
    let before = counts(&r);
    let failure = r
        .prepare_tx_queue(p.clone())
        .err()
        .expect("unknown schema must refuse");
    assert!(matches!(failure.error, TelemetryError::BadArg));
    assert_eq!(failure.packet, p);
    assert_eq!(counts(&r), before);
}
#[cfg(feature = "compact-packet-store")]
#[test]
fn atomic_queue_compact_actual_parking_and_pressure_fallback_retain_identity() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let p = Packet::new_with_nonce(
        candidate,
        &[ep],
        "ATOMIC_SOURCE",
        9001,
        57,
        Arc::from(vec![42u8; 256]),
    )
    .unwrap();
    let original_store = crate::packet_store::default_store();
    let tiny = crate::packet_store::PacketStore::new(1, 1, usize::MAX).unwrap();
    crate::packet_store::set_default_store(Some(tiny.clone()));
    // Actual compact queue parking intentionally treats arena pressure as a
    // successful existing-Arc fallback, not an externally observable Err.
    let prepared = plan(&r, p.clone());
    assert!(tiny.stats().rejected > 0);
    assert_eq!(prepared.into_packet(), Some(p.clone()));
    let store = crate::packet_store::PacketStore::new(4096, 4, usize::MAX).unwrap();
    crate::packet_store::set_default_store(Some(store.clone()));
    let mut prepared = plan(&r, p.clone());
    assert_eq!(store.stats().live_bytes, 256);
    let held = r.state.lock();
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal),
        Err(TryQueuedPacketError::CoreBusy)
    );
    drop(held);
    assert_eq!(prepared.packet.as_ref().unwrap().packet_id(), p.packet_id());
    r.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal)
        .unwrap();
    assert!(prepared.into_packet().is_none());
    r.clear_queues();
    crate::packet_store::set_default_store(original_store);
}
#[test]
fn atomic_queue_nested_side_sum_overflow_is_conservative_capacity() {
    let (ep, signal, candidate) = schema();
    let r = node();
    let mut prepared = plan(&r, packet(candidate, ep));
    let a = r.add_side_packed("overflow-a", |_| Ok(()));
    let b = r.add_side_packed("overflow-b", |_| Ok(()));
    {
        let mut st = r.state.lock();
        for side in [a, b] {
            st.side_transport.get_mut(&side).unwrap().rx_chunk_bytes = usize::MAX / 2 + 1;
        }
    }
    let before = counts(&r);
    assert_eq!(
        r.try_tx_queue_unless_pending_reliable_type(&mut prepared, signal),
        Err(TryQueuedPacketError::Capacity)
    );
    assert_eq!(counts(&r), before);
    {
        let mut st = r.state.lock();
        for side in [a, b] {
            st.side_transport.get_mut(&side).unwrap().rx_chunk_bytes = 0;
        }
    }
}
#[test]
fn atomic_queue_concurrent_same_type_inspection_and_retention_have_one_winner() {
    let (ep, _, candidate) = schema();
    let r = node();
    let mut a = plan(&r, packet(candidate, ep));
    let mut b = plan(&r, packet(candidate, ep));
    let barrier = std::sync::Barrier::new(3);
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            r.try_tx_queue_unless_pending_reliable_type(&mut a, candidate)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            r.try_tx_queue_unless_pending_reliable_type(&mut b, candidate)
        });
        barrier.wait();
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
    assert!(results.iter().any(|v| matches!(
        v,
        Err(TryQueuedPacketError::CoreBusy | TryQueuedPacketError::BlockedPendingReliableType)
    )));
    assert_eq!(counts(&r).0, 1);
    assert_eq!(
        usize::from(a.packet.is_some()) + usize::from(b.packet.is_some()),
        1
    );
}
