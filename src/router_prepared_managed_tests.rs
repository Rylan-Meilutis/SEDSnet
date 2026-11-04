use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
fn schema() -> (DataEndpoint, DataType, Vec<DataType>) {
    let ep = crate::config::register_endpoint("MANAGED_BATCH_GENERIC_EP", false).unwrap();
    let types = (0..5)
        .map(|i| {
            crate::config::register_data_type(
                &format!("MANAGED_BATCH_GENERIC_{i}"),
                MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
                &[ep],
                crate::ReliableMode::Ordered,
                40,
            )
            .unwrap()
        })
        .collect();
    let blocked = crate::config::register_data_type(
        "MANAGED_BATCH_GENERIC_BLOCK",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Unordered,
        240,
    )
    .unwrap();
    (ep, blocked, types)
}
fn node() -> (Router, Arc<AtomicU64>, Arc<AtomicU64>) {
    let time = Arc::new(AtomicU64::new(9000));
    let calls = Arc::new(AtomicU64::new(0));
    let t = time.clone();
    let c = calls.clone();
    let mut memory = crate::config::RuntimeMemoryConfig::default();
    memory.starting_queue_size = 16384;
    memory.max_queue_budget = memory.max_queue_budget.max(2 * 1024 * 1024);
    let r = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("MANAGED_GENERIC_SOURCE")
            .with_memory_config(memory)
            .unwrap(),
        Box::new(move || {
            c.fetch_add(1, Ordering::Relaxed);
            t.load(Ordering::Relaxed)
        }),
    );
    r.clear_queues();
    (r, time, calls)
}
fn packet(ty: DataType, ep: DataEndpoint, time: u64, value: u8) -> Packet {
    Packet::new_with_nonce(
        ty,
        &[ep],
        "MANAGED_GENERIC_SOURCE",
        time,
        value as u16,
        Arc::from(vec![value; 48]),
    )
    .unwrap()
}
fn limits() -> ManagedBatchPreparationLimits {
    ManagedBatchPreparationLimits {
        max_batch_packets: 8,
        max_snapshot_types: 64,
        max_snapshot_entries: 64,
        max_original_payload_bytes: 8192,
        max_snapshot_logical_bytes: 65536,
    }
}
fn originals(ep: DataEndpoint, types: &[DataType]) -> Vec<Packet> {
    types
        .iter()
        .enumerate()
        .map(|(i, ty)| packet(*ty, ep, 1000, i as u8))
        .collect()
}
fn counts(r: &Router) -> (usize, usize, usize, u64, u64) {
    let st = r.state.lock();
    let l = st.local_services.as_ref().unwrap();
    (
        l.managed_variable_latest.len(),
        l.managed_variable_types.len(),
        st.transmit_queue.len(),
        l.managed_registration_epoch,
        l.managed_cache_epoch,
    )
}
fn prepared<'a>(r: &'a Router, p: Vec<Packet>) -> PreparedManagedBatch<'a> {
    r.prepare_network_variable_batch(p, limits())
        .unwrap_or_else(|e| panic!("prepare {:?}", e.error))
}
#[test]
fn managed_batch_first_value_all_five_atomic_original_owners_no_clock_or_callback() {
    let (ep, blocked, types) = schema();
    let (r, _, calls) = node();
    let effects = Arc::new(AtomicU64::new(0));
    let e = effects.clone();
    r.add_side_packet("inert", move |_| {
        e.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    r.clear_queues();
    let input = originals(ep, &types);
    let ids = input.iter().map(Packet::packet_id).collect::<Vec<_>>();
    let mut p = prepared(&r, input);
    assert_eq!(counts(&r).0, 0);
    let before = calls.load(Ordering::Relaxed);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Ok(ManagedBatchAccepted { queued_packets: 5 })
    );
    assert_eq!(calls.load(Ordering::Relaxed), before);
    assert_eq!(effects.load(Ordering::Relaxed), 0);
    assert_eq!(counts(&r).0, 5);
    assert_eq!(counts(&r).2, 5);
    {
        let st = r.state.lock();
        let l = st.local_services.as_ref().unwrap();
        for (i, ty) in types.iter().enumerate() {
            assert_eq!(
                l.managed_variable_latest[&ty.as_u32()].packet.packet_id(),
                ids[i]
            );
            assert_eq!(
                l.managed_variable_latest[&ty.as_u32()].packet.timestamp(),
                1000
            );
        }
    }
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::AlreadyAdmitted)
    );
    drop(p);
    r.process_all_queues_with_timeout(0).unwrap();
    assert!(effects.load(Ordering::Relaxed) >= 5);
}
#[test]
fn managed_batch_core_schema_busy_and_last_item_capacity_leave_everything_unowned() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let input = originals(ep, &types);
    let mut p = prepared(&r, input.clone());
    let before = counts(&r);
    {
        let _core = r.state.lock();
        assert_eq!(
            r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
            Err(TryManagedBatchError::CoreBusy)
        );
    }
    {
        let _schema = crate::config::try_prepared_schema_guard().unwrap();
        assert_eq!(
            r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
            Err(TryManagedBatchError::SchemaBusy)
        );
    }
    {
        let mut st = r.state.lock();
        let schema = crate::config::try_prepared_schema_guard().unwrap();
        let used = st.queued_packet_budget_used(&schema);
        st.memory.max_queue_budget = used + p.total_cost - 1;
    }
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::Capacity)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(p.into_packets(), Some(input));
}
#[test]
fn managed_batch_real_pending_packet_and_unknown_packed_fence_whole_batch() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let mut p = prepared(&r, originals(ep, &types));
    r.tx_queue(packet(blocked, ep, 1001, 3)).unwrap();
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::BlockedPendingReliableType)
    );
    assert_eq!(counts(&r), before);
    r.clear_queues();
    let unknown = TxQueued {
        item: RouterTxItem::Broadcast(RouterItem::Packed(crate::shared_bytes::convert(
            Arc::<[u8]>::from(&b"unknown"[..]),
        ))),
        disposable: 0,
        ignore_local: false,
        priority: 0,
        delivery_state: QueuedDelivery::Untracked,
        accepted_type: 0,
        deferred_since_ms: 0,
        retry_after_ms: 0,
    };
    r.state.lock().transmit_queue.push_back(unknown).unwrap();
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::BlockedPendingReliableType)
    );
    assert_eq!(counts(&r), before);
}
#[test]
fn managed_batch_cache_rebase_preserves_ids_time_and_initial_age_anchor() {
    let (ep, blocked, types) = schema();
    let (r, time, _) = node();
    let input = originals(ep, &types[..2]);
    let mut p = prepared(&r, input.clone());
    let anchor = p.age_anchor_ms;
    r.seed_managed_variable(packet(types[3], ep, 2000, 7))
        .unwrap();
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::RegistrationChanged)
    );
    // Existing unrelated registered variable changes cache only.
    let mut p = prepared(&r, input.clone());
    r.seed_managed_variable(packet(types[3], ep, 2001, 8))
        .unwrap();
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::CacheSnapshotChanged)
    );
    time.store(999999, Ordering::Relaxed);
    r.refresh_network_variable_batch_cache_snapshot(&mut p)
        .unwrap();
    assert_eq!(p.age_anchor_ms, anchor);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Ok(ManagedBatchAccepted { queued_packets: 2 })
    );
    let st = r.state.lock();
    let l = st.local_services.as_ref().unwrap();
    for original in input {
        let e = &l.managed_variable_latest[&original.data_type().as_u32()];
        assert_eq!(e.packet, original);
        #[cfg(feature = "discovery")]
        assert_eq!(e.cached_at_ms, anchor);
    }
}
#[test]
fn managed_batch_registration_permission_aba_terminal_even_after_restore() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    r.enable_network_variable(types[0], NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    let mut p = prepared(&r, originals(ep, &types[..1]));
    r.enable_network_variable(types[0], NetworkVariablePermissions::NONE)
        .unwrap();
    r.enable_network_variable(types[0], NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::RegistrationChanged)
    );
    assert_eq!(
        r.refresh_network_variable_batch_cache_snapshot(&mut p),
        Err(TryManagedBatchError::RegistrationChanged)
    );
    assert_eq!(counts(&r).0, 0);
    let mut p = prepared(&r, originals(ep, &types[..1]));
    r.disable_managed_variable(types[0]);
    r.enable_managed_variable(types[0]).unwrap();
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::RegistrationChanged)
    );
}
#[test]
fn managed_batch_same_source_older_refuses_whole_equal_time_allowed_and_duplicate_type_refused() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    r.seed_managed_variable(packet(types[0], ep, 2000, 1))
        .unwrap();
    let old = packet(types[0], ep, 1000, 2);
    let result = r
        .prepare_network_variable_batch(vec![old.clone(), packet(types[1], ep, 1000, 3)], limits());
    assert!(matches!(
        result,
        Err(PrepareManagedBatchFailure {
            error: TryManagedBatchError::OriginalValueObsolete,
            ..
        })
    ));
    assert_eq!(counts(&r).2, 0);
    let equal = packet(types[0], ep, 2000, 2);
    let mut p = prepared(&r, vec![equal.clone()]);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert_eq!(
        r.get_cached_network_variable(types[0]).unwrap(),
        Some(equal)
    );
    assert!(matches!(
        r.prepare_network_variable_batch(vec![old.clone(), old], limits()),
        Err(PrepareManagedBatchFailure {
            error: TryManagedBatchError::DuplicateType,
            ..
        })
    ));
}
#[test]
fn managed_batch_epoch_exhaustion_changes_nothing_and_legacy_services_continue() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let mut p = prepared(&r, originals(ep, &types[..1]));
    {
        let mut st = r.state.lock();
        let local = st.local_services.as_mut().unwrap();
        local.managed_cache_epoch = u64::MAX - 1;
        p.cache_epoch = u64::MAX - 1;
    }
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::EpochExhausted)
    );
    assert_eq!(counts(&r), before);
    drop(p);
    r.seed_managed_variable(packet(types[0], ep, 1001, 9))
        .unwrap();
    assert!(r.cached_managed_variable(types[0]).is_some());
    assert!(matches!(
        r.prepare_network_variable_batch(originals(ep, &types[..1]), limits()),
        Err(PrepareManagedBatchFailure {
            error: TryManagedBatchError::EpochExhausted,
            ..
        })
    ));
}
#[test]
fn managed_batch_old_payload_retired_only_after_prepared_owner_outside_guard() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let payload: Arc<[u8]> = Arc::from(vec![41; 4096]);
    let weak = Arc::downgrade(&payload);
    let old = Packet::new_with_nonce(types[0], &[ep], "MANAGED_GENERIC_SOURCE", 1000, 21, payload)
        .unwrap();
    r.seed_managed_variable(old).unwrap();
    let mut p = prepared(&r, vec![packet(types[0], ep, 1001, 9)]);
    let app_guard = std::sync::Mutex::new(());
    let held = app_guard.lock().unwrap();
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert!(
        weak.upgrade().is_some(),
        "old payload must remain caller-retired while guard held"
    );
    drop(held);
    drop(p);
    assert!(
        weak.upgrade().is_none(),
        "actual old map owners retired outside guard"
    );
}
#[test]
fn managed_batch_wrong_router_and_relay_cannot_originate() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let (other, _, _) = node();
    let mut p = prepared(&r, originals(ep, &types[..1]));
    assert_eq!(
        other.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::WrongRouter)
    );
    let relay = crate::relay::Relay::new(Box::new(|| 9000));
    assert!(matches!(
        relay.prepare_network_variable_batch(originals(ep, &types[..1]), limits()),
        Err(PrepareManagedBatchFailure {
            error: TryManagedBatchError::OriginNotAllowed,
            ..
        })
    ));
}

#[test]
fn managed_batch_actual_schema_change_refuses_all_and_discovery_dirty_deferred() {
    let (ep, blocked, _) = schema();
    let (r, _, calls) = node();
    let ty = crate::config::register_data_type(
        "MANAGED_BATCH_SCHEMA_NEGATIVE",
        MessageElement::Dynamic(crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        40,
    )
    .unwrap();
    let mut p = prepared(&r, vec![packet(ty, ep, 1000, 3)]);
    crate::config::set_data_type_e2e_encryption_policy(ty, crate::E2eEncryptionPolicy::RequireOn)
        .unwrap();
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::SchemaChanged)
    );
    assert_eq!(counts(&r), before);
    crate::config::set_data_type_e2e_encryption_policy(ty, crate::E2eEncryptionPolicy::PreferOff)
        .unwrap();
    let before_clock = calls.load(Ordering::Relaxed);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), before_clock);
    #[cfg(feature = "discovery")]
    {
        assert!(
            r.state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .managed_registration_dirty
        );
        r.poll_discovery().unwrap();
        assert!(
            !r.state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .managed_registration_dirty
        );
    }
}
#[test]
fn managed_batch_p2p_and_registration_exhaustion_preflight_no_partial_cache() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let mut p = prepared(&r, originals(ep, &types[..1]));
    #[cfg(feature = "discovery")]
    {
        r.state.lock().p2p_revision = u64::MAX - 1;
        let before = counts(&r);
        assert_eq!(
            r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
            Err(TryManagedBatchError::EpochExhausted)
        );
        assert_eq!(counts(&r), before);
        r.state.lock().p2p_revision = 0;
    }
    {
        let mut st = r.state.lock();
        st.local_services
            .as_mut()
            .unwrap()
            .managed_registration_epoch = u64::MAX - 1;
        p.registration_epoch = u64::MAX - 1;
    }
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::EpochExhausted)
    );
    assert_eq!(counts(&r), before);
}
#[test]
fn managed_batch_active_unknown_owner_and_aged_original_refuse_without_new_identity() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    r.enable_managed_variable(types[0]).unwrap();
    let mut p = prepared(&r, originals(ep, &types[..1]));
    r.active_queued_tx.store(1, Ordering::Release);
    r.state.lock().active_queued_types.fill((0, 0));
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::BlockedPendingReliableType)
    );
    r.active_queued_tx.store(0, Ordering::Release);
    r.seed_managed_variable(packet(types[0], ep, 2000, 9))
        .unwrap();
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::CacheSnapshotChanged)
    );
    let original = p.items[0].packet.as_ref().unwrap().clone();
    assert_eq!(
        r.refresh_network_variable_batch_cache_snapshot(&mut p),
        Err(TryManagedBatchError::OriginalValueObsolete)
    );
    assert_eq!(p.into_packets(), Some(vec![original]));
}

#[test]
fn managed_batch_exact_duplicate_preserves_upstream_and_local_callback_suppression() {
    let (ep, blocked, types) = schema();
    let (r, _, calls) = node();
    let effects = Arc::new(AtomicU64::new(0));
    let e = effects.clone();
    r.on_network_variable_update(types[0], move |_| {
        e.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();
    let side = r.add_side_packet("actual-inbound", |_| Ok(()));
    let original = packet(types[0], ep, 1000, 8);
    r.rx_from_side(&original, side).unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    let initial_effects = effects.load(Ordering::Relaxed);
    assert_eq!(initial_effects, 1);
    #[cfg(feature = "discovery")]
    let upstream = r
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .managed_variable_latest[&types[0].as_u32()]
        .upstream;
    let mut p = prepared(&r, vec![original.clone()]);
    let before = calls.load(Ordering::Relaxed);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), before);
    assert_eq!(effects.load(Ordering::Relaxed), initial_effects);
    #[cfg(feature = "discovery")]
    assert_eq!(
        r.state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .managed_variable_latest[&types[0].as_u32()]
            .upstream,
        upstream
    );
    drop(p);
    r.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(effects.load(Ordering::Relaxed), initial_effects);
    assert_eq!(
        r.get_cached_network_variable(types[0]).unwrap(),
        Some(original)
    );
}
#[cfg(feature = "discovery")]
#[test]
fn managed_batch_actual_get_refresh_returns_original_committed_packet() {
    let (ep, blocked, types) = schema();
    let (r, _, _) = node();
    let source = Arc::new(r);
    let original = packet(types[0], ep, 1234, 19);
    let mut p = prepared(&source, vec![original.clone()]);
    source
        .try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    drop(p);
    let client = Arc::new(Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(ep, |_| Ok(()))])
            .with_sender("MANAGED_BATCH_GET_CLIENT"),
        Box::new(|| 9000),
    ));
    client.enable_managed_variable(types[0]).unwrap();
    let c = client.clone();
    source.add_side_packet("source-client", move |p| c.rx_from_side(p, 0));
    let s = source.clone();
    client.add_side_packet("client-source", move |p| s.rx_from_side(p, 0));
    assert!(
        client
            .get_network_variable(types[0], None)
            .unwrap()
            .is_none()
    );
    for _ in 0..4 {
        source.process_all_queues_with_timeout(0).unwrap();
        client.process_all_queues_with_timeout(0).unwrap();
    }
    let cached = client
        .get_cached_network_variable(types[0])
        .unwrap()
        .unwrap();
    assert_eq!(cached.packet_id(), original.packet_id());
    assert_eq!(cached.timestamp(), 1234);
    assert_eq!(cached.payload(), original.payload());
}
#[test]
fn managed_batch_preparation_budget_and_type_size_receipt() {
    let (ep, _, types) = schema();
    let (r, _, _) = node();
    let original = packet(types[0], ep, 1000, 5);
    let mut small = limits();
    small.max_batch_packets = 0;
    let failure = r
        .prepare_network_variable_batch(vec![original.clone()], small)
        .err()
        .unwrap();
    assert_eq!(failure.error, TryManagedBatchError::PreparationLimit);
    assert_eq!(failure.originals, vec![original]);
    eprintln!(
        "MANAGED_BATCH_LAYOUT LocalServicesState={} PreparedManagedBatch={} ManagedItem={} CacheEntry={} default_or_compact={}",
        size_of::<LocalServicesState>(),
        size_of::<PreparedManagedBatch<'_>>(),
        size_of::<ManagedItem>(),
        size_of::<ManagedVariableCacheEntry>(),
        cfg!(feature = "compact-packet-store")
    );
}

#[cfg(feature = "discovery")]
#[test]
fn managed_batch_discovery_outage_matches_existing_bounded_cadence() {
    use std::sync::atomic::AtomicBool;
    fn scenario(batch: bool) -> (u64, bool, u64) {
        let (ep, blocked, types) = schema();
        let (r, time, _) = node();
        let ty = types[0];
        let fail = Arc::new(AtomicBool::new(true));
        let failed_address = Arc::new(AtomicU64::new(0));
        let observed = Arc::new(AtomicBool::new(false));
        let f = fail.clone();
        let n = failed_address.clone();
        let seen = observed.clone();
        r.add_side_packet_with_options(
            "same-modern-link",
            move |packet| {
                let carries = packet.data_type() == DataType::DiscoveryAddress
                    && crate::discovery::decode_discovery_address(packet)?
                        .reachable_network_variables
                        .contains(&ty);
                if f.load(Ordering::Relaxed) {
                    if carries {
                        n.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(TelemetryError::HandlerError(
                        "paired existing bounded discovery refusal",
                    ));
                }
                if carries {
                    seen.store(true, Ordering::Relaxed);
                }
                Ok(())
            },
            RouterSideOptions {
                link_local_enabled: true,
                ..Default::default()
            },
        );
        r.clear_queues();
        let original = packet(ty, ep, 1234, 17);
        if batch {
            let mut p = prepared(&r, vec![original]);
            r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
                .unwrap();
            drop(p);
        } else {
            r.enable_managed_variable(ty).unwrap();
            r.seed_managed_variable(original).unwrap();
        }
        for step in 0..10 {
            time.store(9000 + step * 100, Ordering::Relaxed);
            let _ = r.process_all_queues_with_timeout(0);
        }
        fail.store(false, Ordering::Relaxed);
        for step in 10..210 {
            time.store(9000 + step * 100, Ordering::Relaxed);
            let _ = r.process_all_queues_with_timeout(0);
        }
        let early = observed.load(Ordering::Relaxed);
        let mut late = 0;
        for step in 210..1310 {
            time.store(9000 + step * 100, Ordering::Relaxed);
            let _ = r.process_all_queues_with_timeout(0);
            if observed.load(Ordering::Relaxed) {
                late = step * 100;
                break;
            }
        }
        assert!(r.cached_managed_variable(ty).is_some());
        (failed_address.load(Ordering::Relaxed), early, late)
    }
    let legacy = scenario(false);
    let batch = scenario(true);
    eprintln!("PAIRED_DISCOVERY_OUTAGE legacy={legacy:?} prepared={batch:?}");
    assert!(legacy.0 > 0 && batch.0 > 0);
    assert_eq!(
        batch, legacy,
        "prototype must preserve existing bounded advertisement cadence, not invent unlimited retry/air delivery"
    );
    // Root-reviewed contract: same local ownership/maintenance profile,
    // not guaranteed physical delivery on a one-way inert link.
    // Both legacy and prepared retained the cache above; no new retry timing.
}
#[cfg(feature = "discovery")]
#[test]
fn managed_batch_single_discovery_refusal_retains_existing_retry_work() {
    use std::sync::atomic::AtomicBool;
    let (ep, blocked, types) = schema();
    let (r, time, calls) = node();
    let ty = types[0];
    let refuse_once = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicU64::new(0));
    let seen = Arc::new(AtomicBool::new(false));
    let fail = refuse_once.clone();
    let a = attempts.clone();
    let observed = seen.clone();
    r.add_side_packet_with_options(
        "actual-modern-retry",
        move |packet| {
            if packet.data_type() == DataType::DiscoveryAddress
                && crate::discovery::decode_discovery_address(packet)?
                    .reachable_network_variables
                    .contains(&ty)
            {
                a.fetch_add(1, Ordering::Relaxed);
                if fail.swap(false, Ordering::Relaxed) {
                    return Err(TelemetryError::HandlerError(
                        "single actual advertisement refusal",
                    ));
                }
                observed.store(true, Ordering::Relaxed);
            }
            Ok(())
        },
        RouterSideOptions {
            link_local_enabled: true,
            ..Default::default()
        },
    );
    r.clear_queues();
    let mut p = prepared(&r, vec![packet(ty, ep, 1234, 18)]);
    let clock_before = calls.load(Ordering::Relaxed);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), clock_before);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    drop(p);
    for step in 0..40 {
        time.store(9000 + step * 100, Ordering::Relaxed);
        let _ = r.process_all_queues_with_timeout(0);
        if seen.load(Ordering::Relaxed) {
            break;
        }
    }
    assert!(
        seen.load(Ordering::Relaxed) && attempts.load(Ordering::Relaxed) >= 2,
        "existing actual retry must retain first-value registration after one transport refusal"
    );
}

#[cfg(feature = "discovery")]
#[test]
fn managed_batch_age_delayed_ordinary_drain_refreshes_observation_not_original_or_owner() {
    let (ep, blocked, types) = schema();
    let (r, time, _) = node();
    let source_utc = 1_793_612_345_678;
    let original = packet(types[0], ep, source_utc, 51);
    let id = original.packet_id();
    let mut p = prepared(&r, vec![original.clone()]);
    let anchor = p.age_anchor_ms;
    time.store(10000, Ordering::Relaxed);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    assert_eq!(
        r.state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .managed_variable_latest[&types[0].as_u32()]
            .cached_at_ms,
        anchor
    );
    time.store(25000, Ordering::Relaxed);
    r.process_all_queues_with_timeout(0).unwrap();
    let after = r
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .managed_variable_latest[&types[0].as_u32()]
        .clone();
    eprintln!(
        "AGE_DELAYED_DRAIN initial_anchor={anchor} ordinary_cached_at={} original_id={id} source_timestamp={}",
        after.cached_at_ms,
        after.packet.timestamp()
    );
    assert_eq!(
        after.cached_at_ms, 25000,
        "ordinary dispatch retains legacy local-observation age refresh"
    );
    assert_eq!(after.packet.packet_id(), id);
    assert_eq!(after.packet.timestamp(), source_utc);
    assert_eq!(after.packet.payload(), original.payload());
    assert_eq!(
        p.age_anchor_ms, anchor,
        "caller-owned preparation anchor itself was not renewed"
    );
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::AlreadyAdmitted)
    );
    assert_eq!(
        r.refresh_network_variable_batch_cache_snapshot(&mut p),
        Err(TryManagedBatchError::AlreadyAdmitted)
    );
    assert_eq!(counts(&r), before);
}
#[cfg(feature = "discovery")]
#[test]
fn managed_batch_age_same_id_broadcast_and_ingress_duplicates_keep_source_time() {
    let (ep, blocked, types) = schema();
    let (r, time, _) = node();
    let source_utc = 1_793_612_345_678;
    let original = packet(types[0], ep, source_utc, 52);
    let mut p = prepared(&r, vec![original.clone()]);
    r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked)
        .unwrap();
    drop(p);
    r.process_all_queues_with_timeout(0).unwrap();
    time.store(30000, Ordering::Relaxed);
    r.tx_queue(original.clone()).unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    let broadcast = r
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .managed_variable_latest[&types[0].as_u32()]
        .clone();
    assert_eq!(broadcast.cached_at_ms, 30000);
    assert_eq!(broadcast.packet.packet_id(), original.packet_id());
    assert_eq!(broadcast.packet.timestamp(), source_utc);
    let side = r.add_side_packet("actual-duplicate-ingress", |_| Ok(()));
    time.store(40000, Ordering::Relaxed);
    r.rx_from_side(&original, side).unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    let ingress = r
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .managed_variable_latest[&types[0].as_u32()]
        .clone();
    eprintln!(
        "AGE_DUPLICATE broadcast_cached_at={} ingress_cached_at={} unchanged_source_timestamp={}",
        broadcast.cached_at_ms,
        ingress.cached_at_ms,
        ingress.packet.timestamp()
    );
    assert_eq!(
        ingress.cached_at_ms, 40000,
        "same-ID actual ingress keeps legacy local observation refresh"
    );
    assert_eq!(ingress.packet.packet_id(), original.packet_id());
    assert_eq!(ingress.packet.timestamp(), source_utc);
    assert_eq!(ingress.packet.payload(), original.payload());
}
#[cfg(feature = "discovery")]
#[test]
fn managed_batch_age_fresh_observation_does_not_renew_caller_deadline_or_bypass_pending_stop() {
    use std::time::{Duration, Instant};
    #[derive(Debug, PartialEq, Eq)]
    enum CallerError {
        Expired,
        Sdk(TryManagedBatchError),
    }
    // RAM-only CALLER policy fixture, not an SDK deadline API or GS integration.
    // The real GS still uses only the public registry version4 dependency.
    fn caller_admit(
        r: &Router,
        p: &mut PreparedManagedBatch<'_>,
        blocked: DataType,
        deadline: Instant,
        now: Instant,
    ) -> Result<ManagedBatchAccepted, CallerError> {
        if now >= deadline {
            return Err(CallerError::Expired);
        }
        r.try_commit_network_variable_batch_unless_pending_type(p, blocked)
            .map_err(CallerError::Sdk)
    }
    let (ep, blocked, types) = schema();
    let (r, time, _) = node();
    let source_utc = 1_793_612_345_678;
    let existing = packet(types[0], ep, source_utc, 20);
    r.seed_managed_variable(existing.clone()).unwrap();
    let original = packet(types[0], ep, source_utc + 1, 21);
    let mut p = prepared(&r, vec![original.clone()]);
    let anchor = p.age_anchor_ms;
    let deadline = Instant::now() + Duration::from_millis(10);
    // Paired positive caller-policy control uses a separate real SDK owner.
    let (control, _, _) = node();
    let mut control_prepared = prepared(&control, vec![original.clone()]);
    assert_eq!(
        caller_admit(
            &control,
            &mut control_prepared,
            blocked,
            deadline,
            deadline - Duration::from_millis(1)
        ),
        Ok(ManagedBatchAccepted { queued_packets: 1 })
    );
    assert_eq!(
        control.get_cached_network_variable(types[0]).unwrap(),
        Some(original.clone())
    );
    drop(control_prepared);
    time.store(800000, Ordering::Relaxed);
    r.tx_queue(existing).unwrap();
    r.process_all_queues_with_timeout(0).unwrap();
    let cache = r
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .managed_variable_latest[&types[0].as_u32()]
        .clone();
    assert_eq!(
        cache.cached_at_ms, 800000,
        "SDK observation is locally fresh even though source timestamp is old"
    );
    assert_eq!(cache.packet.timestamp(), source_utc);
    r.refresh_network_variable_batch_cache_snapshot(&mut p)
        .unwrap();
    assert_eq!(p.age_anchor_ms, anchor);
    assert_eq!(p.items[0].packet.as_ref(), Some(&original));
    let before = counts(&r);
    assert_eq!(
        caller_admit(
            &r,
            &mut p,
            blocked,
            deadline,
            deadline + Duration::from_millis(1)
        ),
        Err(CallerError::Expired)
    );
    assert_eq!(
        counts(&r),
        before,
        "expired CALLER plan never invokes SDK admission despite fresh cache"
    );
    // Independent SDK authority fence: a real pending reliable-type owner
    // wins even after a valid cache snapshot rebase. It does not consult age.
    r.tx_queue(packet(blocked, ep, source_utc + 2, 22)).unwrap();
    let before = counts(&r);
    assert_eq!(
        r.try_commit_network_variable_batch_unless_pending_type(&mut p, blocked),
        Err(TryManagedBatchError::BlockedPendingReliableType)
    );
    assert_eq!(counts(&r), before);
    assert_eq!(p.into_packets(), Some(vec![original]));
}
