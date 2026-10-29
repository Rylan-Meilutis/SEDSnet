//! Full schema intent must outlive descriptor pressure behind its route prefix.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
fn router(slots: usize) -> (Router, Arc<AtomicU64>) {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let memory =
        RuntimeMemoryConfig::new(1024 * 1024, 16, slots * size_of::<TxQueued>(), 1.0).unwrap();
    (
        Router::new_with_clock(
            RouterConfig::default()
                .with_sender("PB")
                .with_memory_config(memory)
                .unwrap(),
            Box::new(move || now.load(Ordering::Relaxed)),
        ),
        clock,
    )
}
#[test]
fn two_slot_full_announce_and_schema_request_recover_without_repeating_prefix() {
    for request in [false, true] {
        let (router, clock) = router(2);
        let sent = Arc::new(RouterMutex::new(Vec::new()));
        let out = sent.clone();
        let side = router.add_side_packet("CAN", move |p| {
            out.lock().push(p.data_type());
            Ok(())
        });
        assert_eq!(router.state.lock().transmit_queue.capacity(), 2);
        if request {
            let p = discovery::build_discovery_schema_request("FC", 0).unwrap();
            router.learn_discovery_packet(&p, Some(side), true).unwrap();
        } else {
            router.announce_discovery().unwrap();
        }
        {
            let st = router.state.lock();
            assert_eq!(st.transmit_queue.len(), 2);
            assert_eq!(
                st.discovery_side_throttle[&side].schema_response_phase,
                SchemaResponsePhase::CatalogWaiting
            );
        }
        for ms in (0..=1000).step_by(10) {
            clock.store(ms, Ordering::Relaxed);
            router.drain_queues_with_timeout(0).unwrap();
            router.poll_schema_response_on_side(side).unwrap();
        }
        let types = sent.lock();
        assert_eq!(
            types
                .iter()
                .filter(|t| **t == DataType::DiscoveryAddress)
                .count(),
            1
        );
        assert_eq!(
            types
                .iter()
                .filter(|t| **t == DataType::DiscoveryTopology)
                .count(),
            1
        );
        assert_eq!(
            types
                .iter()
                .filter(|t| **t == DataType::DiscoverySchema)
                .count(),
            1
        );
        assert!(!router.state.lock().discovery_side_throttle[&side].schema_response_active);
    }
}
#[test]
fn multiple_sides_with_refused_schema_keep_independent_generation_intents() {
    let (router, clock) = router(2);
    let ready = Arc::new(AtomicBool::new(false));
    let released = ready.clone();
    let first = Arc::new(RouterMutex::new(0));
    let a = first.clone();
    let side0 = router.add_side_packet("busy", move |p| {
        if p.data_type() == DataType::DiscoverySchema {
            if !released.load(Ordering::Relaxed) {
                return Err(TelemetryError::Io("side tx busy"));
            }
            *a.lock() += 1;
        }
        Ok(())
    });
    let second = Arc::new(RouterMutex::new(0));
    let b = second.clone();
    let side1 = router.add_side_packet("healthy", move |p| {
        if p.data_type() == DataType::DiscoverySchema {
            *b.lock() += 1;
        }
        Ok(())
    });
    let _ = router.announce_discovery();
    for ms in (0..=5000).step_by(10) {
        clock.store(ms, Ordering::Relaxed);
        for side in [side0, side1] {
            let _ = router.poll_schema_response_on_side(side);
        }
        let _ = router.drain_queues_with_timeout(0);
        if ms == 1000 {
            ready.store(true, Ordering::Relaxed);
        }
        assert!(router.state.lock().transmit_queue.len() <= 2);
    }
    assert!(*first.lock() >= 1, "busy side never recovered");
    assert!(*second.lock() >= 1, "healthy side lost schema intent");
}

#[test]
fn clear_and_restart_during_catalog_build_rejects_the_stale_generation() {
    let (router, _) = router(2);
    let side = router.add_side_packet("CAN", |_| Ok(()));
    router.announce_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let old = discovery::build_discovery_schema("PB", 10).unwrap();
    let old_id = old.packet_id();
    let fresh = discovery::build_discovery_schema("PB", 11).unwrap();
    let fresh_id = fresh.packet_id();
    let admitted = router
        .admit_schema_response_catalog_with(side, || {
            router.clear_tx_queue();
            router.announce_discovery().unwrap();
            router.drain_queues_with_timeout(0).unwrap();
            assert!(
                router
                    .admit_schema_response_catalog_with(side, || Ok(fresh))
                    .unwrap()
            );
            Ok(old)
        })
        .unwrap();
    assert!(
        !admitted,
        "old builder must not claim the new generation's identical phase"
    );
    let st = router.state.lock();
    assert_eq!(
        st.discovery_side_throttle[&side].schema_response_packet_id,
        fresh_id
    );
    assert!(
        st.transmit_queue
            .iter()
            .any(|q| RouterInner::schema_response_owner(&q.item) == Some((side, fresh_id)))
    );
    assert!(
        !st.transmit_queue
            .iter()
            .any(|q| RouterInner::schema_response_owner(&q.item) == Some((side, old_id)))
    );
}

#[test]
fn clear_racing_atomic_catalog_admission_cannot_leave_an_orphan() {
    for _ in 0..32 {
        let (router, _) = router(2);
        let router = Arc::new(router);
        let side = router.add_side_packet("CAN", |_| Ok(()));
        router.announce_discovery().unwrap();
        router.drain_queues_with_timeout(0).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let entered = barrier.clone();
        let worker = router.clone();
        let thread = std::thread::spawn(move || {
            worker.admit_schema_response_catalog_with(side, || {
                let packet = discovery::build_discovery_schema("PB", 1)?;
                entered.wait();
                Ok(packet)
            })
        });
        barrier.wait();
        router.clear_tx_queue();
        thread.join().unwrap().unwrap();
        let st = router.state.lock();
        assert!(!st.discovery_side_throttle[&side].schema_response_active);
        assert!(
            !st.transmit_queue
                .iter()
                .any(|q| RouterInner::schema_response_owner(&q.item).is_some())
        );
    }
}

#[test]
fn waiting_catalog_respects_policy_without_allocating_and_recovers_after_allow() {
    let (router, _) = router(2);
    let side = router.add_side_packet("CAN", |_| Ok(()));
    router.announce_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    router
        .set_typed_route(None, DataType::DiscoverySchema, side, false)
        .unwrap();
    for _ in 0..10 {
        assert!(
            !router
                .admit_schema_response_catalog_with(side, || panic!(
                    "blocked schema policy must not allocate a catalog"
                ))
                .unwrap()
        );
    }
    router
        .set_typed_route(None, DataType::DiscoverySchema, side, true)
        .unwrap();
    assert!(router.admit_schema_response_catalog(side).unwrap());
}

#[test]
fn generation_counter_exhaustion_never_wraps_or_reuses_an_old_claim() {
    let (router, _) = router(2);
    let side = router.add_side_packet("CAN", |_| Ok(()));
    router.announce_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    router.state.lock().schema_response_sequence = u64::MAX;
    assert!(matches!(
        router.admit_schema_response_catalog(side),
        Err(TelemetryError::Io("schema generation exhausted"))
    ));
    let st = router.state.lock();
    assert_eq!(st.schema_response_sequence, u64::MAX);
    assert_eq!(
        st.discovery_side_throttle[&side].schema_response_phase,
        SchemaResponsePhase::CatalogWaiting
    );
    assert_eq!(st.transmit_queue.len(), 0);
}

#[test]
fn coalesced_explicit_announce_cannot_rearm_an_already_admitted_prefix() {
    let (router, _) = router(2);
    let sent = Arc::new(RouterMutex::new(Vec::new()));
    let out = sent.clone();
    let side = router.add_side_packet("CAN", move |p| {
        out.lock().push(p.data_type());
        Ok(())
    });
    router.announce_discovery().unwrap();
    assert!(router.state.lock().discovery_side_throttle[&side].has_sent_full);
    router.announce_discovery().unwrap();
    assert!(router.state.lock().discovery_side_throttle[&side].has_sent_full);
    router.drain_queues_with_timeout(0).unwrap();
    router.poll_schema_response_on_side(side).unwrap();
    router.announce_discovery().unwrap();
    assert_eq!(
        sent.lock()
            .iter()
            .filter(|t| **t == DataType::DiscoveryAddress)
            .count(),
        1
    );
    assert!(router.state.lock().discovery_side_throttle[&side].has_sent_full);
}

#[test]
fn old_prefix_payload_cannot_enqueue_after_clear_and_new_generation() {
    let (router, _) = router(2);
    let side = router.add_side_packet("CAN", |_| Ok(()));
    // Pause a real generation at its unlocked prefix-construction boundary.
    let claim = {
        let mut st = router.state.lock();
        st.schema_response_sequence += 1;
        let claim = st.schema_response_sequence;
        let phase = st.discovery_side_throttle.entry(side).or_default();
        phase.schema_response_active = true;
        phase.schema_response_phase = SchemaResponsePhase::PrefixBuilding;
        phase.schema_response_packet_id = claim;
        claim
    };
    let old = discovery::build_discovery_topology("PB", 0, &[]).unwrap();
    router.clear_tx_queue();
    router.announce_discovery().unwrap();
    let before = router.state.lock().transmit_queue.len();
    assert!(matches!(
        router.emit_discovery_prefix_item(
            RouterTxItem::ToSide {
                src: None,
                dst: side,
                data: RouterItem::Packet(old)
            },
            true,
            true,
            Some((side, claim))
        ),
        Err(TelemetryError::Io("schema prefix cancelled"))
    ));
    assert_eq!(
        router.state.lock().transmit_queue.len(),
        before,
        "old Address/Topology cannot slip behind the new generation's prefix"
    );
}

#[test]
fn continuously_refilled_bulk_cannot_block_catalog_priority_admission() {
    let (router, clock) = router(2);
    let seen = Arc::new(RouterMutex::new((0usize, 0usize)));
    let out = seen.clone();
    let side = router.add_side_packet("CAN", move |p| {
        let mut count = out.lock();
        if p.data_type() == DataType::DiscoverySchema {
            count.0 += 1;
        } else {
            count.1 += 1;
        }
        Ok(())
    });
    router.announce_discovery().unwrap();
    router.drain_queues_with_timeout(0).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "SCHEMA_PREFIX_BULK",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[DataEndpoint::Discovery],
        crate::ReliableMode::None,
        1,
    )
    .unwrap();
    for tick in 0..40 {
        clock.store(tick, Ordering::Relaxed);
        for offset in 0..2 {
            let packet = Packet::new(
                ty,
                &[DataEndpoint::Discovery],
                "PB",
                tick * 2 + offset,
                vec![1].into(),
            )
            .unwrap();
            let _ = router.state.lock().push_transmit(TxQueued {
                disposable: TX_DISPOSABLE,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(packet),
                },
                ignore_local: true,
                priority: 1,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            });
        }
        router.poll_schema_response_on_side(side).unwrap();
        router.drain_queues_with_timeout(0).unwrap();
        assert!(router.state.lock().transmit_queue.len() <= 2);
    }
    let counts = seen.lock();
    assert_eq!(counts.0, 1);
    assert!(counts.1 >= 40);
}

#[test]
fn topology_and_catalog_recover_under_protected_refill_with_existing_eviction_policy() {
    let (router, clock) = router(2);
    let seen = Arc::new(RouterMutex::new(Vec::new()));
    let out = seen.clone();
    let side = router.add_side_packet("CAN", move |p| {
        out.lock().push(p.data_type());
        Ok(())
    });
    let protected_type = crate::config::register_data_type_with_description(
        "PREFIX_PROTECTED_ORDERED",
        "",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[DataEndpoint::Discovery],
        crate::ReliableMode::Ordered,
        200,
    )
    .unwrap();
    let protected = |tick| {
        Packet::new(
            protected_type,
            &[DataEndpoint::Discovery],
            "RF",
            tick,
            vec![0].into(),
        )
        .unwrap()
    };
    let fill = |tick| {
        router
            .state
            .lock()
            .push_transmit(TxQueued {
                disposable: TX_DISPOSABLE,
                item: RouterTxItem::ToSide {
                    src: None,
                    dst: side,
                    data: RouterItem::Packet(protected(tick)),
                },
                ignore_local: true,
                priority: 255,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })
            .unwrap()
    };
    fill(0);
    assert!(
        !router
            .state
            .lock()
            .transmit_queue
            .get(0)
            .unwrap()
            .disposable
            & TX_DISPOSABLE
            != 0
    );
    let _ = router.announce_discovery();
    for tick in (250..=5000).step_by(250) {
        router.drain_queues_with_timeout(0).unwrap();
        fill(tick);
        clock.store(tick, Ordering::Relaxed);
        let _ = router.poll_schema_response_on_side(side);
        assert!(router.state.lock().transmit_queue.len() <= 2);
    }
    router.drain_queues_with_timeout(0).unwrap();
    assert!(
        seen.lock().contains(&DataType::DiscoveryTopology),
        "Topology must recover under recurring protected refill"
    );
    assert!(
        seen.lock().contains(&DataType::DiscoverySchema),
        "protected refill must still leave bounded catalog recovery"
    );
}

#[test]
fn genuine_prefix_build_refusal_preserves_intent_until_memory_recovers() {
    let (router, clock) = router(2);
    let sent = Arc::new(RouterMutex::new(0));
    let out = sent.clone();
    let side = router.add_side_packet("CAN", move |p| {
        if p.data_type() == DataType::DiscoverySchema {
            *out.lock() += 1;
        }
        Ok(())
    });
    extern "C" fn deny(_: usize, _: usize) -> bool {
        false
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    let reset = Reset;
    crate::memory_admission::set_probe(Some(deny));
    assert!(router.announce_discovery().is_err());
    drop(reset);
    {
        let st = router.state.lock();
        let phase = &st.discovery_side_throttle[&side];
        assert!(!phase.schema_response_active);
        assert!(phase.schema_response_pending);
        assert_eq!(phase.schema_response_phase, SchemaResponsePhase::Idle);
    }
    for tick in (250..=1000).step_by(10) {
        clock.store(tick, Ordering::Relaxed);
        router.poll_schema_response_on_side(side).unwrap();
        router.drain_queues_with_timeout(0).unwrap();
    }
    assert_eq!(*sent.lock(), 1);
}
