use super::*;
fn kinds() -> (DataEndpoint, Vec<DataType>) {
    let ep = crate::config::register_endpoint("ACTIVE_TYPES_EP", false).unwrap();
    let types = (0..20)
        .map(|n| {
            crate::config::register_data_type_with_description(
                &format!("ACTIVE_TYPES_DATA_{n}"),
                "",
                MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
                &[ep],
                crate::ReliableMode::None,
                0,
            )
            .unwrap()
        })
        .collect();
    (ep, types)
}
fn work(ty: DataType, ep: DataEndpoint, unknown: bool) -> TxWork {
    let packet =
        Packet::new_with_nonce(ty, &[ep], "active-test", 1, 11, Arc::from([7u8].as_slice()))
            .unwrap();
    let item = if unknown {
        RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(&packet)))
    } else {
        RouterItem::Packet(packet)
    };
    TxWork {
        queued: TxQueued {
            disposable: 0,
            item: RouterTxItem::Broadcast(item),
            ignore_local: false,
            priority: 0,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: if unknown { 0 } else { ty.as_u32() },
            deferred_since_ms: 0,
            retry_after_ms: 0,
        },
        claim: None,
        owed_turn: false,
        #[cfg(feature = "latest-value-egress")]
        service: EgressService::default(),
    }
}
fn claim<'a>(
    router: &'a Router,
    ty: DataType,
    ep: DataEndpoint,
    unknown: bool,
) -> (TxWork, QueuedTxActivityGuard<'a>) {
    let work = work(ty, ep, unknown);
    let tracked = {
        let mut state = router.state.lock();
        router.track_queued_tx(&mut state, Some(work))
    };
    tracked.unwrap()
}
fn empty(router: &Router) {
    assert_eq!(
        router
            .active_queued_tx
            .load(core::sync::atomic::Ordering::Acquire),
        0
    );
    assert!(
        router
            .state
            .lock()
            .active_queued_types
            .iter()
            .all(|slot| *slot == (0, 0))
    );
}
#[test]
fn active_types_same_different_last_holder_and_slot_reuse() {
    let (ep, t) = kinds();
    let r = Router::new(RouterConfig::new([]));
    let a = claim(&r, t[0], ep, false);
    let a2 = claim(&r, t[0], ep, false);
    let b = claim(&r, t[1], ep, false);
    assert!(r.has_pending_reliable_tx_type(t[0]) && r.has_pending_reliable_tx_type(t[1]));
    assert!(!r.has_pending_reliable_tx_type(t[2]));
    drop(a);
    assert!(r.has_pending_reliable_tx_type(t[0]));
    drop(a2);
    assert!(!r.has_pending_reliable_tx_type(t[0]));
    let c = claim(&r, t[2], ep, false);
    drop(b);
    assert!(!r.has_pending_reliable_tx_type(t[1]));
    assert!(r.has_pending_reliable_tx_type(t[2]));
    drop(c);
    empty(&r);
}
#[test]
fn active_types_sixteen_known_then_exhaustion_is_conservative_until_release() {
    let (ep, t) = kinds();
    let r = Router::new(RouterConfig::new([]));
    let held: Vec<_> = t[..16].iter().map(|ty| claim(&r, *ty, ep, false)).collect();
    assert!(!r.has_pending_reliable_tx_type(t[19]));
    let overflow = claim(&r, t[16], ep, false);
    assert!(overflow.1.key.is_none());
    assert!(r.has_pending_reliable_tx_type(t[19]));
    drop(overflow);
    assert!(!r.has_pending_reliable_tx_type(t[19]));
    assert!(t[..16].iter().all(|ty| r.has_pending_reliable_tx_type(*ty)));
    drop(held);
    empty(&r);
}
#[test]
fn active_types_unknown_and_per_slot_overflow_never_guess_absence() {
    let (ep, t) = kinds();
    let r = Router::new(RouterConfig::new([]));
    // Explicit private unknown work bypasses producer parking/cache on purpose.
    // It is not a claim that a valid ToSide prefix remains uncached in production.
    let unknown = claim(&r, t[0], ep, true);
    assert!(unknown.1.key.is_none());
    assert!(r.has_pending_reliable_tx_type(t[19]));
    drop(unknown);
    empty(&r);
    let held = claim(&r, t[0], ep, false);
    let key = held.1.key.unwrap();
    {
        let mut state = r.state.lock();
        state.active_queued_types[usize::from(key.slot.get() - 1)].1 = u32::MAX;
        r.active_queued_tx
            .store(u32::MAX as usize, core::sync::atomic::Ordering::Release);
    }
    // On a32-bit host the total preflight stops further claims first.
    #[cfg(target_pointer_width = "64")]
    {
        let overflow = claim(&r, t[0], ep, false);
        assert!(overflow.1.key.is_none());
        assert!(r.has_pending_reliable_tx_type(t[19]));
        drop(overflow);
    }
    {
        let mut state = r.state.lock();
        state.active_queued_types[usize::from(key.slot.get() - 1)].1 = 1;
        r.active_queued_tx
            .store(0, core::sync::atomic::Ordering::Release);
    }
    assert!(
        r.has_pending_reliable_tx_type(t[19]),
        "inconsistent total<known must be conservative"
    );
    r.active_queued_tx
        .store(1, core::sync::atomic::Ordering::Release);
    drop(held);
    empty(&r);
}
#[test]
fn active_types_concurrent_claims_and_unwind_release_without_state_lock_over_work() {
    use std::sync::{Condvar, Mutex, mpsc};
    let (ep, t) = kinds();
    let r = Router::new(RouterConfig::new([]));
    std::thread::scope(|scope| {
        let (ready, rx) = mpsc::channel();
        let gates: Vec<_> = (0..2)
            .map(|_| Arc::new((Mutex::new(false), Condvar::new())))
            .collect();
        for i in 0..2 {
            let ready = ready.clone();
            let gate = gates[i].clone();
            let router = &r;
            let ty = t[i];
            scope.spawn(move || {
                let held = claim(router, ty, ep, false);
                ready.send(()).unwrap();
                let (lock, cv) = &*gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = cv.wait(open).unwrap();
                }
                drop(open);
                drop(held);
            });
        }
        rx.recv().unwrap();
        rx.recv().unwrap();
        assert!(r.has_pending_reliable_tx_type(t[0]));
        assert!(r.has_pending_reliable_tx_type(t[1]));
        assert!(!r.has_pending_reliable_tx_type(t[19]));
        for gate in gates {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
    });
    empty(&r);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = claim(&r, t[0], ep, false);
        panic!("test callback unwind");
    }));
    assert!(result.is_err());
    empty(&r);
    assert!(!r.has_pending_reliable_tx_type(t[19]));
}
#[test]
fn active_types_actual_dispatch_error_releases_and_total_overflow_leaves_queue_owned() {
    let (ep, t) = kinds();
    let ty = t[0];
    let missing = t[19];
    let r = Arc::new(Router::new(
        RouterConfig::new([]).with_sender("active-host"),
    ));
    let weak = Arc::downgrade(&r);
    let side = r.add_side_packed("refused", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|frame| frame.envelope.ty == ty) {
            let router = weak.upgrade().unwrap();
            assert!(router.has_pending_reliable_tx_type(ty));
            assert!(!router.has_pending_reliable_tx_type(missing));
            return Err(TelemetryError::Io("active error control"));
        }
        Ok(())
    });
    r.rx_from_side(
        &crate::discovery::build_discovery_announce("active-leaf", 1, &[ep]).unwrap(),
        side,
    )
    .unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    r.tx_queue(
        Packet::new_with_nonce(ty, &[ep], "active-host", 1, 99, Arc::from([7u8].as_slice()))
            .unwrap(),
    )
    .unwrap();
    r.active_queued_tx
        .store(usize::MAX, core::sync::atomic::Ordering::Release);
    assert!(r.process_tx_queue_with_timeout(0).is_ok());
    assert_eq!(r.queue_counters()[2], 1);
    assert!(r.has_pending_reliable_tx_type(missing));
    r.active_queued_tx
        .store(0, core::sync::atomic::Ordering::Release);
    let _ = r.process_all_queues_with_timeout(0);
    empty(&r);
}
#[test]
fn active_types_layout_reports_host_cost() {
    eprintln!(
        "ACTIVE_TYPE_LAYOUT router={} inner={} slot={} slots16={} guard={} key={}",
        size_of::<Router>(),
        size_of::<RouterInner>(),
        size_of::<(u32, u32)>(),
        size_of::<[(u32, u32); 16]>(),
        size_of::<QueuedTxActivityGuard<'_>>(),
        size_of::<Option<ActiveQueuedTypeKey>>()
    );
    assert_eq!(size_of::<[(u32, u32); 16]>(), 128);
    assert!(size_of::<Option<ActiveQueuedTypeKey>>() <= 8);
}

#[test]
fn active_types_actual_callback_unwind_drops_guard_without_poisoning_state() {
    let (ep, t) = kinds();
    let ty = t[0];
    let r = Router::new(RouterConfig::new([]).with_sender("active-unwind-host"));
    let side = r.add_side_packed("panic", move |wire| {
        if wire_format::peek_frame_info(wire).is_ok_and(|frame| frame.envelope.ty == ty) {
            panic!("actual callback unwind control");
        }
        Ok(())
    });
    r.rx_from_side(
        &crate::discovery::build_discovery_announce("active-unwind-leaf", 1, &[ep]).unwrap(),
        side,
    )
    .unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    r.tx_queue(
        Packet::new_with_nonce(
            ty,
            &[ep],
            "active-unwind-host",
            1,
            102,
            Arc::from([7u8].as_slice()),
        )
        .unwrap(),
    )
    .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        r.process_all_queues_with_timeout(0)
    }));
    assert!(result.is_err());
    empty(&r);
    assert!(!r.has_pending_reliable_tx_type(t[19]));
}
