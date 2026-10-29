//! New metadata allocation failures must leave authoritative routes/clocks intact.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

static SEEN: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(0);
extern "C" fn record_probe(additional: usize, largest: usize) -> bool {
    if additional == largest.saturating_add(5 * size_of::<usize>()) {
        let n = SEEN.fetch_add(1, Ordering::Relaxed) + 1;
        return n != FAIL_AT.load(Ordering::Relaxed);
    }
    true
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        crate::memory_admission::set_probe(None);
        FAIL_AT.store(0, Ordering::Relaxed);
        SEEN.store(0, Ordering::Relaxed);
    }
}
fn fail_record(n: usize) {
    SEEN.store(0, Ordering::Relaxed);
    FAIL_AT.store(n, Ordering::Relaxed);
    crate::memory_admission::set_probe(Some(record_probe));
}

#[test]
fn failed_discovery_working_copy_keeps_every_original_announcer() {
    let _reset = Reset;
    let mut route = DiscoverySideState::default();
    for name in ["PB", "FC", "RF"] {
        let mut state = DiscoverySenderState {
            last_seen_ms: 17,
            ..Default::default()
        };
        state.advertised_reachable.push(DataEndpoint::TimeSync);
        route.announcers.insert(name.into(), Box::new(state));
    }
    let original = route.clone();
    let addresses: Vec<usize> = route
        .announcers
        .values()
        .map(|x| x.as_ref() as *const _ as usize)
        .collect();
    for n in 1..=3 {
        fail_record(n);
        assert!(matches!(
            route.try_clone(),
            Err(TelemetryError::Io("memory pressure"))
        ));
        assert_eq!(route, original);
        assert_eq!(
            route
                .announcers
                .values()
                .map(|x| x.as_ref() as *const _ as usize)
                .collect::<Vec<_>>(),
            addresses
        );
    }
    fail_record(0);
    assert_eq!(route.try_clone().unwrap(), original);
    assert_eq!(SEEN.load(Ordering::Relaxed), 3);
    let charged = RouterInner::discovery_route_byte_cost(0, &route);
    assert!(charged >= 3 * crate::peer_record::allocation_bytes::<DiscoverySenderState>());
}

#[test]
fn cold_peer_refusal_precedes_hostname_conflict_and_warm_refresh_reuses_record() {
    let _reset = Reset;
    let router =
        Router::new_with_clock(RouterConfig::default().with_sender("LOCAL"), Box::new(|| 0));
    let old = router.sender.lock().clone();
    let local_ptr = router.state.lock().address_book[old.as_ref()].as_ref() as *const _ as usize;
    let ad = discovery::AddressAdvertisement {
        hostname: old.to_string(),
        address: router.current_address(),
        requested_address: 0,
        mode: discovery::ADDRESS_MODE_STATIC,
        state: discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 0,
        reachable_endpoints: Vec::new(),
        reachable_network_variables: Vec::new(),
        reachable_timesync_sources: Vec::new(),
        link_capabilities: discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 64,
            compact_header_target_bytes: 40,
            max_side_transport_templates: 8,
        },
    };
    fail_record(1);
    assert!(matches!(
        router.ingest_address_advertisement(ad.clone()),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(*router.sender.lock(), old);
    assert_eq!(router.state.lock().address_book.len(), 1);
    fail_record(0);
    router.ingest_address_advertisement(ad.clone()).unwrap();
    let current = router.sender.lock().clone();
    assert_ne!(current, old);
    assert_eq!(
        router.state.lock().address_book[current.as_ref()].as_ref() as *const _ as usize,
        local_ptr
    );
    assert_eq!(SEEN.load(Ordering::Relaxed), 1);
    let peer_ptr = router.state.lock().address_book[old.as_ref()].as_ref() as *const _ as usize;
    fail_record(1);
    router.ingest_address_advertisement(ad).unwrap();
    assert_eq!(SEEN.load(Ordering::Relaxed), 0);
    assert_eq!(
        router.state.lock().address_book[old.as_ref()].as_ref() as *const _ as usize,
        peer_ptr
    );
}

#[test]
fn timesync_announce_stages_all_three_peer_records_before_commit() {
    let _reset = Reset;
    for n in 1..=3 {
        crate::memory_admission::set_probe(None);
        let router = Router::new_with_clock(
            RouterConfig::default()
                .with_sender("FC")
                .with_timesync(TimeSyncConfig::default()),
            Box::new(|| 1_000),
        );
        router
            .try_set_local_network_time(PartialNetworkTime::from_unix_ms(100_000))
            .unwrap();
        let packet =
            crate::timesync::build_timesync_announce_with_sender("GS", 0, 200_000).unwrap();
        let before = router
            .timesync
            .as_ref()
            .unwrap()
            .lock()
            .clock
            .current_time(1_000_000_000);
        fail_record(n);
        assert!(matches!(
            router.handle_internal_timesync_packet(&packet, None, false),
            Err(TelemetryError::Io("memory pressure"))
        ));
        let st = router.timesync.as_ref().unwrap().lock();
        assert!(st.remote_sources.is_empty());
        assert!(
            st.tracker
                .as_ref()
                .unwrap()
                .best_active_source(1_000)
                .is_none()
        );
        assert_eq!(st.clock.current_time(1_000_000_000), before);
    }
}

#[test]
fn local_time_fragment_refusal_preserves_the_previous_full_reading() {
    let _reset = Reset;
    for n in 1..=3 {
        crate::memory_admission::set_probe(None);
        let router = Router::new_with_clock(
            RouterConfig::default()
                .with_sender("FC")
                .with_timesync(TimeSyncConfig::default()),
            Box::new(|| 0),
        );
        router
            .try_set_local_network_time(PartialNetworkTime::from_unix_ms(100_000))
            .unwrap();
        let before = router
            .timesync
            .as_ref()
            .unwrap()
            .lock()
            .clock
            .current_time(0);
        let partial = PartialNetworkTime {
            year: Some(2026),
            hour: Some(4),
            nanosecond: Some(7),
            ..Default::default()
        };
        fail_record(n);
        assert!(matches!(
            router.try_set_local_network_time(partial),
            Err(TelemetryError::Io("memory pressure"))
        ));
        assert_eq!(
            router
                .timesync
                .as_ref()
                .unwrap()
                .lock()
                .clock
                .current_time(0),
            before
        );
    }
}

#[test]
fn refused_cold_address_record_does_not_publish_its_discovery_route() {
    let _reset = Reset;
    let ep = crate::config::register_endpoint("FOOTPRINT_COLD_ROUTE", false).unwrap();
    let router =
        Router::new_with_clock(RouterConfig::default().with_sender("LOCAL"), Box::new(|| 0));
    let side = router.add_side_packed("can", |_| Ok(()));
    let ad = discovery::AddressAdvertisement {
        hostname: "REMOTE".into(),
        address: 42,
        requested_address: 42,
        mode: discovery::ADDRESS_MODE_STATIC,
        state: discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 77,
        reachable_endpoints: vec![ep],
        reachable_network_variables: Vec::new(),
        reachable_timesync_sources: Vec::new(),
        link_capabilities: discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 64,
            compact_header_target_bytes: 40,
            max_side_transport_templates: 8,
        },
    };
    let packet = discovery::build_discovery_address("REMOTE", 0, &ad).unwrap();
    // First record is the working announcer; second is the cold address record.
    fail_record(2);
    assert!(matches!(
        router.learn_discovery_packet(&packet, Some(side), false),
        Err(TelemetryError::Io("memory pressure"))
    ));
    {
        let state = router.state.lock();
        assert!(state.discovery_routes.get(&side).is_none());
        assert_eq!(state.address_book.len(), 1);
    }
    fail_record(0);
    router
        .learn_discovery_packet(&packet, Some(side), false)
        .unwrap();
    let state = router.state.lock();
    assert_eq!(state.address_book["REMOTE"].owner_hash, 77);
    assert!(
        state
            .discovery_routes
            .get(&side)
            .unwrap()
            .reachable
            .contains(&ep)
    );
}

#[test]
fn relay_conflict_reserves_missing_local_record_before_identity_changes() {
    let _reset = Reset;
    let router = Router::new_with_clock(RouterConfig::relay().with_sender("RELAY"), Box::new(|| 0));
    let old = router.state.lock().local_address.hostname.clone();
    assert!(router.state.lock().address_book.is_empty());
    let ad = discovery::AddressAdvertisement {
        hostname: old.to_string(),
        address: router.current_address(),
        requested_address: 0,
        mode: discovery::ADDRESS_MODE_STATIC,
        state: discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 0,
        reachable_endpoints: Vec::new(),
        reachable_network_variables: Vec::new(),
        reachable_timesync_sources: Vec::new(),
        link_capabilities: discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: 0,
            max_frame_bytes: 64,
            compact_header_target_bytes: 40,
            max_side_transport_templates: 8,
        },
    };
    fail_record(2);
    assert!(matches!(
        router.ingest_address_advertisement(ad.clone()),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(router.state.lock().local_address.hostname, old);
    assert!(router.state.lock().address_book.is_empty());
    fail_record(0);
    router.ingest_address_advertisement(ad).unwrap();
    assert_ne!(router.state.lock().local_address.hostname, old);
    assert_eq!(router.state.lock().address_book.len(), 2);
}

#[test]
fn leave_snapshot_record_refusal_preserves_every_route() {
    let _reset = Reset;
    let router =
        Router::new_with_clock(RouterConfig::default().with_sender("LOCAL"), Box::new(|| 0));
    let side = router.add_side_packed("can", |_| Ok(()));
    {
        let mut st = router.state.lock();
        let mut route = DiscoverySideState::default();
        for sender in ["LEAVING", "RETAINED"] {
            route
                .announcers
                .insert(sender.into(), Box::new(DiscoverySenderState::default()));
        }
        st.discovery_routes.insert(side, route);
    }
    let before = router.state.lock().discovery_routes.clone();
    let leave = discovery::build_discovery_leave("LEAVING", 0).unwrap();
    fail_record(2);
    assert!(matches!(
        router.learn_discovery_packet(&leave, Some(side), false),
        Err(TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(router.state.lock().discovery_routes, before);
    fail_record(0);
    router
        .learn_discovery_packet(&leave, Some(side), false)
        .unwrap();
    let st = router.state.lock();
    assert!(
        !st.discovery_routes[&side]
            .announcers
            .contains_key("LEAVING")
    );
    assert!(
        st.discovery_routes[&side]
            .announcers
            .contains_key("RETAINED")
    );
}
