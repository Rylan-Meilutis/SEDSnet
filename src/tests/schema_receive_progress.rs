//! Exact captured receiver progress must not request a redundant active catalog.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

fn receiver() -> (
    Router,
    RouterSideId,
    Arc<AtomicU64>,
    Arc<RouterMutex<Vec<Packet>>>,
) {
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("GS"),
        Box::new(move || now.load(Ordering::Relaxed)),
    );
    let sent = Arc::new(RouterMutex::new(Vec::new()));
    let out = sent.clone();
    let side = router.add_side_packet("radio", move |p| {
        out.lock().push(p.clone());
        Ok(())
    });
    (router, side, clock, sent)
}
fn missing(router: &Router, side: RouterSideId, name: &str, address: u32, now: u64, due: u64) {
    let mut st = router.state.lock();
    st.discovery_routes
        .entry(side)
        .or_default()
        .announcers
        .insert(
            name.into(),
            DiscoverySenderState {
                advertised_address: Some(address),
                has_full_topology: true,
                last_seen_ms: now,
                ..DiscoverySenderState::default()
            },
        );
    st.discovery_side_throttle
        .entry(side)
        .or_default()
        .next_schema_request_ms = due;
}
fn requests(router: &Router, sent: &Arc<RouterMutex<Vec<Packet>>>) -> usize {
    router.drain_queues_with_timeout(0).unwrap();
    sent.lock()
        .iter()
        .filter(|p| p.data_type() == DataType::DiscoverySchemaRequest)
        .count()
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/schema-progress-20261027.json")).unwrap()
}
fn frame(v: &serde_json::Value) -> Vec<u8> {
    v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect()
}
#[test]
fn captured_same_peer_progress_defers_redundant_schema_request_until_complete() {
    const CHILD: &str = "SEDS_SCHEMA_PROGRESS_CAPTURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "router::schema_receive_progress::captured_same_peer_progress_defers_redundant_schema_request_until_complete", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (router, side, clock, sent) = receiver();
    let f = fixture();
    // Actual retained RF topology advertises an assigned numeric address;
    // its captured canonical schema uses the legacy hash accepted at completion.
    missing(&router, side, "RF", 3757742741, 4620, 4620);
    for v in f["frames"].as_array().unwrap() {
        let now = v["at_us"].as_u64().unwrap() / 1000;
        if now > 4620 {
            break;
        }
        clock.store(now, Ordering::Relaxed);
        assert!(
            router
                .decode_side_transport_frame(side, &frame(v))
                .unwrap()
                .is_none()
        );
    }
    clock.store(4620, Ordering::Relaxed);
    router.poll_discovery_announce().unwrap();
    assert_eq!(
        requests(&router, &sent),
        0,
        "captured peer RF is actively sending this catalog; requesting another creates a fresh pending response"
    );
    assert!(
        !router.state.lock().discovery_routes[&side].announcers["RF"].has_schema,
        "incomplete progress is not schema completion"
    );
    for v in f["frames"].as_array().unwrap() {
        let now = v["at_us"].as_u64().unwrap() / 1000;
        if now <= 4620 {
            continue;
        }
        clock.store(now, Ordering::Relaxed);
        if let Some(bytes) = router.decode_side_transport_frame(side, &frame(v)).unwrap() {
            let p = wire_format::unpack_packet(&bytes).unwrap();
            assert_eq!(p.data_type(), DataType::DiscoverySchema);
            router.learn_discovery_packet(&p, Some(side), true).unwrap();
        }
    }
    assert!(router.state.lock().discovery_routes[&side].announcers["RF"].has_schema);
    clock.store(6000, Ordering::Relaxed);
    router.poll_discovery_announce().unwrap();
    assert_eq!(requests(&router, &sent), 0);
}

#[test]
fn duplicates_stall_and_expiry_resume_the_original_due_recovery() {
    let (router, side, clock, sent) = receiver();
    let f = fixture();
    let first = frame(&f["frames"][0]);
    missing(&router, side, "RF", 3997908571, 3001, 1500);
    clock.store(1000, Ordering::Relaxed);
    router.decode_side_transport_frame(side, &first).unwrap();
    clock.store(1500, Ordering::Relaxed);
    router.poll_discovery_announce().unwrap();
    assert_eq!(requests(&router, &sent), 0);
    assert_eq!(
        router.state.lock().discovery_side_throttle[&side].next_schema_request_ms,
        1500,
        "progress cannot push out the existing recovery deadline"
    );
    clock.store(2000, Ordering::Relaxed);
    router.decode_side_transport_frame(side, &first).unwrap();
    clock.store(3000, Ordering::Relaxed);
    router.poll_discovery_announce().unwrap();
    assert_eq!(
        requests(&router, &sent),
        0,
        "exactly2s retains the existing assembly"
    );
    clock.store(3001, Ordering::Relaxed);
    router.poll_discovery_announce().unwrap();
    assert_eq!(
        requests(&router, &sent),
        1,
        "duplicate/replayed fragments cannot suppress the due request beyond2s useful inactivity"
    );
    router.expire_side_chunks();
    assert!(
        router.state.lock().side_transport[&side]
            .rx_chunks
            .is_empty()
    );
}

#[test]
fn unrelated_peer_or_transfer_cannot_defer_schema_recovery() {
    for other_peer in [false, true] {
        let (router, side, clock, sent) = receiver();
        let f = fixture();
        missing(
            &router,
            side,
            if other_peer { "PB" } else { "RF" },
            if other_peer { 213986670 } else { 3997908571 },
            1500,
            1500,
        );
        clock.store(1000, Ordering::Relaxed);
        if other_peer {
            router
                .decode_side_transport_frame(side, &frame(&f["frames"][0]))
                .unwrap();
        } else {
            let packet = Packet::new(
                DataType::DiscoveryTopology,
                &[DataEndpoint::Discovery],
                "RF",
                1000,
                vec![0; 1000].into(),
            )
            .unwrap();
            let canonical = wire_format::pack_packet(&packet);
            let first =
                SideTransportFrames::split(crate::shared_bytes::convert(canonical), 192, b"RF")
                    .unwrap()
                    .next()
                    .unwrap();
            router.decode_side_transport_frame(side, &first).unwrap();
        }
        clock.store(1500, Ordering::Relaxed);
        router.poll_discovery_announce().unwrap();
        assert_eq!(
            requests(&router, &sent),
            1,
            "other-peer schema and unrelated large transfers must not defer this peer's request"
        );
    }
}

#[test]
fn restart_without_first_chunk_and_corrupt_fragment_keep_recovery() {
    for corrupt in [false, true] {
        let (router, side, clock, sent) = receiver();
        let f = fixture();
        missing(&router, side, "RF", 3997908571, 1500, 1500);
        clock.store(1000, Ordering::Relaxed);
        if corrupt {
            let mut first = frame(&f["frames"][0]);
            first[15] ^= 1;
            assert!(router.decode_side_transport_frame(side, &first).is_err());
        } else {
            router
                .decode_side_transport_frame(side, &frame(&f["frames"][1]))
                .unwrap();
        }
        clock.store(1500, Ordering::Relaxed);
        router.poll_discovery_announce().unwrap();
        assert_eq!(
            requests(&router, &sent),
            1,
            "no valid first header means no suppression of restart recovery"
        );
    }
}

/// Offline peer-identity audit; never a linked timing/forwarding qualification.
#[test]
#[ignore = "offline capture diagnostic; without capture arguments validates the bundled actual-codec peer fixture"]
fn audit_captured_can_schema_peers() {
    let (path, output) = match (
        std::env::var_os("SEDS_SCHEMA_PEER_AUDIT_INPUT"),
        std::env::var_os("SEDS_SCHEMA_PEER_AUDIT_OUTPUT"),
    ) {
        (None, None) => {
            // Full validation must exercise the codec and peer learning without
            // depending on an external, machine-specific diagnostic capture.
            captured_same_peer_progress_defers_redundant_schema_request_until_complete();
            return;
        }
        (Some(input), Some(output)) if !input.is_empty() && !output.is_empty() => (input, output),
        _ => panic!("peer audit input and output must both be explicitly provided and nonempty"),
    };
    assert!(std::fs::metadata(&path).unwrap().len() <= 8 * 1024 * 1024);
    let input: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    crate::config::register_schema_json_file_with_budget(
        input["schema"].as_str().unwrap(),
        2 * 1024 * 1024,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("FC"),
        Box::new(move || now.load(Ordering::Relaxed)),
    );
    let mut opts = RouterSideOptions::default().with_small_packet_transport(110);
    opts.max_side_transport_templates = 64;
    let side = router.add_side_packed_with_options("CAN", |_| Ok(()), opts);
    let mut snapshots = Vec::new();
    let mut errors = Vec::new();
    for v in input["frames"].as_array().unwrap() {
        let ms = v["at_us"].as_u64().unwrap() / 1000;
        clock.fetch_max(ms, Ordering::Relaxed);
        let bytes = frame(v);
        match router.decode_side_transport_frame(side, &bytes) {
            Ok(Some(bytes)) => {
                let p = wire_format::unpack_packet(&bytes).unwrap();
                if discovery::is_discovery_type(p.data_type()) {
                    if let Err(e) = router.learn_discovery_packet(&p, Some(side), true) {
                        errors.push(format!("{ms}:{e:?}"));
                    }
                    if p.data_type() == DataType::DiscoverySchema {
                        let st = router.state.lock();
                        let peers=st.discovery_routes.get(&side).map(|r|r.announcers.iter().map(|(name,p)|serde_json::json!({"name":name,"address":p.advertised_address,"full_topology":p.has_full_topology,"has_schema":p.has_schema,"last_seen_ms":p.last_seen_ms})).collect::<Vec<_>>()).unwrap_or_default();
                        snapshots.push(serde_json::json!({"at_ms":ms,"schema_sender":p.sender(),"peers":peers}));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => errors.push(format!("{ms}:{e:?}")),
        }
    }
    std::fs::write(output,serde_json::to_vec_pretty(&serde_json::json!({"scope":"Offline discovery-learning replay of captured CAN RX; no scheduler timing or observed runtime state claim","errors":errors,"snapshots":snapshots})).unwrap()).unwrap();
}

#[test]
fn progressive_catalog_closed_loop_avoids_a_second_full_response() {
    use core::sync::atomic::AtomicUsize;
    let f = fixture();
    let canonical: Vec<u8> = f["frames"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| {
            let b = frame(v);
            b[12..b.len() - 4].to_vec()
        })
        .collect();
    let initial = wire_format::unpack_packet(&canonical).unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let producer = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("RF"),
        Box::new(move || now.load(Ordering::Relaxed)),
    ));
    let quota = Arc::new(AtomicUsize::new(0));
    let available = quota.clone();
    let emitted = Arc::new(RouterMutex::new(Vec::<Vec<u8>>::new()));
    let out = emitted.clone();
    let pside = producer.add_side_packed_with_options(
        "radio",
        move |bytes| {
            if available
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
                .is_err()
            {
                return Err(TelemetryError::Io("side tx busy"));
            }
            out.lock().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    producer
        .state
        .lock()
        .push_transmit(TxQueued {
            disposable: true,
            item: RouterTxItem::ToSide {
                src: None,
                dst: pside,
                data: RouterItem::Packet(initial),
            },
            ignore_local: true,
            priority: 253,
            delivery_state: QueuedDelivery::Untracked,
            accepted_type: 0,
            deferred_since_ms: 0,
            retry_after_ms: 0,
        })
        .unwrap();
    let now = clock.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::default().with_sender("GS"),
        Box::new(move || now.load(Ordering::Relaxed)),
    );
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let peer = producer.clone();
    let side = receiver.add_side_packet("radio", move |packet| {
        if packet.data_type() == DataType::DiscoverySchemaRequest {
            count.fetch_add(1, Ordering::Relaxed);
            peer.learn_discovery_packet(packet, Some(pside), true)?;
        }
        Ok(())
    });
    missing(&receiver, side, "RF", 3757742741, 6500, 1000);
    let mut catalogs = 0;
    let mut schema_wire_bytes = 0;
    for ms in (0..=6500).step_by(100) {
        clock.store(ms, Ordering::Relaxed);
        quota.store(1, Ordering::Relaxed);
        producer.poll_schema_response_on_side(pside).unwrap();
        producer.drain_queues_with_timeout(0).unwrap();
        let frames = core::mem::take(&mut *emitted.lock());
        for bytes in frames {
            if bytes.starts_with(b"SDT\x03") {
                schema_wire_bytes += bytes.len();
            }
            if let Some(canonical) = receiver.decode_side_transport_frame(side, &bytes).unwrap() {
                let packet = wire_format::unpack_packet(&canonical).unwrap();
                if packet.data_type() == DataType::DiscoverySchema {
                    discovery::decode_discovery_schema(&packet).unwrap();
                    receiver.note_schema_received(side, packet.sender());
                    catalogs += 1;
                }
            }
        }
        receiver.poll_discovery_announce().unwrap();
        receiver.drain_queues_with_timeout(0).unwrap();
    }
    println!(
        "SCHEMA_PROGRESS_CLOSED_LOOP requests={} completed_catalogs={} schema_wire_bytes={schema_wire_bytes}",
        requests.load(Ordering::Relaxed),
        catalogs
    );
    assert_eq!(requests.load(Ordering::Relaxed), 0);
    assert_eq!(
        catalogs, 1,
        "a retry during useful prefix progress must not schedule a second full catalog"
    );
}
