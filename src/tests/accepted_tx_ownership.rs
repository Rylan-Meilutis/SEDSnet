//! Host-only inspection of accepted TX ownership, including the popped retry gap.
use super::*;
use std::sync::{
    Barrier,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

fn schema(name: &str) -> (DataType, DataEndpoint) {
    let ep = crate::config::register_endpoint(name, false).unwrap();
    let ty = crate::config::register_data_type(
        name,
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        255,
    )
    .unwrap();
    (ty, ep)
}

fn retry_gap(all_queues: bool) {
    let (ty, _) = schema(if all_queues {
        "TX_OWNER_ALL"
    } else {
        "TX_OWNER_ONLY"
    });
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    ));
    let phase = Arc::new(AtomicUsize::new(0));
    let stage = phase.clone();
    let entered = Arc::new(Barrier::new(2));
    let ready = entered.clone();
    let release = Arc::new(Barrier::new(2));
    let go = release.clone();
    router.add_side_packed("unknown_peer", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|f| f.envelope.ty == ty) {
            if stage.load(Ordering::SeqCst) == 0 {
                return Err(TelemetryError::Io("side tx busy"));
            }
            ready.wait();
            go.wait();
        }
        Ok(())
    });
    router.process_all_queues_with_timeout(0).unwrap();
    router.log_queue(ty, &[1u8]).unwrap();
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert!(router.has_pending_reliable_tx_type(ty));
    phase.store(1, Ordering::SeqCst);
    now.store(2, Ordering::SeqCst);
    let worker_router = router.clone();
    let worker = std::thread::spawn(move || {
        if all_queues {
            worker_router.process_all_queues_with_timeout(0)
        } else {
            worker_router.dispatch_tx_queue_with_timeout(0)
        }
        .unwrap();
    });
    entered.wait();
    // The historical queue/pending query pair both missed this exact interval.
    let old_queued = router.has_queued_work();
    let old_pending = router
        .export_reliable_pending_stats()
        .iter()
        .any(|r| r.data_type == ty);
    let observed = router.has_pending_reliable_tx_type(ty);
    release.wait();
    worker.join().unwrap();
    assert!(
        !old_queued && !old_pending,
        "fixture must exercise the untracked retry pop gap"
    );
    assert!(
        observed,
        "accepted retry remains owned while its callback is running"
    );
    assert_eq!(router.active_queued_tx.load(Ordering::Acquire), 0);
    assert!(!router.has_pending_reliable_tx_type(ty));
}

#[test]
fn transmit_only_retry_stays_visible_during_callback() {
    retry_gap(false);
}
#[test]
fn combined_worker_retry_stays_visible_during_callback() {
    retry_gap(true);
}

#[test]
fn dispatch_unwind_releases_host_activity_counter() {
    let (ty, _) = schema("TX_OWNER_UNWIND");
    let router = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 0));
    router.add_side_packed("panic_side", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|f| f.envelope.ty == ty) {
            panic!("intentional transport panic");
        }
        Ok(())
    });
    router.log_queue(ty, &[1u8]).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        router.dispatch_tx_queue_with_timeout(0).unwrap();
    }));
    assert!(result.is_err());
    assert_eq!(router.active_queued_tx.load(Ordering::Acquire), 0);
    // The original remains owned: clearing the activity count must not erase it.
    assert!(router.has_pending_reliable_tx_type(ty));
}

#[test]
fn unrelated_typed_queue_does_not_block_and_packed_unknown_fails_closed() {
    let (ty, ep) = schema("TX_OWNER_TARGET");
    let (other, _) = schema("TX_OWNER_UNRELATED");
    let router = Router::new_with_clock(RouterConfig::new([]), Box::new(|| 0));
    router.log_queue(other, &[2u8]).unwrap();
    assert!(!router.has_pending_reliable_tx_type(ty));
    assert!(router.has_pending_reliable_tx_type(other));
    router.clear_tx_queue();
    let packet = Packet::new(ty, &[ep], "GS", 0, Arc::<[u8]>::from([1u8])).unwrap();
    router.tx_queue(packet).unwrap();
    for _ in 0..64 {
        assert!(router.has_pending_reliable_tx_type(ty));
    }
    router.clear_tx_queue();
    assert!(!router.has_pending_reliable_tx_type(ty));
    // Unknown packed work is inspected only through cached metadata. Even an
    // unreadable frame conservatively blocks without unpacking/pinning it.
    router
        .state
        .lock()
        .push_transmit(TxQueued {
            disposable: false,
            item: RouterTxItem::ToSide {
                src: None,
                dst: 0,
                data: RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(
                    [0xffu8; 64],
                ))),
            },
            ignore_local: true,
            priority: 255,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })
        .unwrap();
    for _ in 0..64 {
        assert!(router.has_pending_reliable_tx_type(ty));
    }
    router.clear_tx_queue();
    assert!(!router.has_pending_reliable_tx_type(ty));
}

#[test]
fn advertised_owner_and_replay_remain_pending_until_actual_ack() {
    let (ty, ep) = schema("TX_OWNER_ACK");
    let now = Arc::new(AtomicU64::new(1));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let side = router.add_side_packed("radio", |_| Ok(()));
    router
        .rx_from_side(
            &crate::discovery::build_discovery_announce("FC", 1, &[ep]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    let packet = Packet::new(ty, &[ep], "GS", 1, Arc::<[u8]>::from([1u8])).unwrap();
    let id = packet.packet_id();
    router.tx_queue(packet).unwrap();
    router.dispatch_tx_queue_with_timeout(0).unwrap();
    assert!(
        router
            .export_reliable_pending_stats()
            .iter()
            .any(|r| r.packet_id == id)
    );
    assert!(router.has_pending_reliable_tx_type(ty));
    now.store(runtime_reliable_retransmit_ms() + 2, Ordering::SeqCst);
    router.process_tx_queue_with_timeout(0).unwrap();
    assert!(
        router.has_pending_reliable_tx_type(ty),
        "replay handoff keeps reliable owner"
    );
    let ack = Packet::new_with_wire_contract(
        DataType::ReliableAck,
        message_meta(DataType::ReliableAck).endpoints_ref(),
        "E2EACK:FC",
        1,
        1,
        Arc::<[u8]>::from(id.to_le_bytes()),
        None,
        Arc::from([Router::sender_hash("FC"), Router::sender_hash("GS")]),
    )
    .unwrap();
    router
        .rx_packed_queue_from_side(&wire_format::pack_packet(&ack), side)
        .unwrap();
    router.process_all_queues_with_timeout(0).unwrap();
    assert!(!router.has_pending_reliable_tx_type(ty));
    assert_eq!(router.active_queued_tx.load(Ordering::Acquire), 0);
}

#[test]
fn codec_chunk_callback_and_busy_retry_keep_accepted_ownership() {
    let ep = crate::config::register_endpoint("TX_OWNER_CODEC", false).unwrap();
    let ty = crate::config::register_data_type(
        "TX_OWNER_CODEC",
        MessageElement::Static(
            512,
            crate::MessageDataType::UInt8,
            crate::MessageClass::Data,
        ),
        &[ep],
        crate::ReliableMode::Unordered,
        255,
    )
    .unwrap();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new([]),
        Box::new(|| 0),
    ));
    let phase = Arc::new(AtomicUsize::new(0));
    let stage = phase.clone();
    let entered = Arc::new(Barrier::new(2));
    let ready = entered.clone();
    let release = Arc::new(Barrier::new(2));
    let go = release.clone();
    let seen = Arc::new(AtomicUsize::new(0));
    let chunks = seen.clone();
    router.add_side_packed_small_packets(
        "codec",
        move |wire| {
            if stage.load(Ordering::SeqCst) == 1 {
                assert!(wire.len() <= 64);
                if chunks.fetch_add(1, Ordering::SeqCst) == 0 {
                    ready.wait();
                    go.wait();
                    return Err(TelemetryError::Io("side tx busy"));
                }
            }
            Ok(())
        },
        64,
    );
    router.process_all_queues_with_timeout(0).unwrap();
    phase.store(1, Ordering::SeqCst);
    router.log_queue(ty, &[0u8; 512]).unwrap();
    let worker_router = router.clone();
    let worker = std::thread::spawn(move || worker_router.dispatch_tx_queue_with_timeout(0));
    entered.wait();
    let pending = router.has_pending_reliable_tx_type(ty);
    release.wait();
    worker.join().unwrap().unwrap();
    assert!(pending);
    assert!(
        router.has_pending_reliable_tx_type(ty),
        "busy codec retains work after active callback ends"
    );
    assert_eq!(router.active_queued_tx.load(Ordering::Acquire), 0);
}
