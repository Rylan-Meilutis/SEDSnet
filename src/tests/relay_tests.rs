//! Tests for the packed relay fan-out behavior and timeout semantics.

use crate::config::{DataEndpoint, DataType};
use crate::discovery::build_discovery_announce;
use crate::router::Clock;

use crate::relay::{Relay, RelaySideOptions};
use crate::tests::timeout_tests::StepClock;
use crate::tests::{count_packed_frames_of_type, packed_frame_type};
use crate::{TelemetryError, TelemetryResult, packet::Packet, wire_format};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Simple zero clock for tests that don't care about timeouts.
fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

#[cfg(feature = "discovery")]
#[test]
fn relay_routes_targeted_status_to_a_direct_discovery_address_announcer() {
    use crate::config::{register_data_type_with_description, register_endpoint_with_description};
    use crate::discovery::{
        ADDRESS_MODE_DYNAMIC, ADDRESS_STATE_APPROVED, AddressAdvertisement, LinkCapabilities,
        build_discovery_address,
    };
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};

    let ground_station =
        DataEndpoint::try_named("RELAY_TEST_GROUND_STATION").unwrap_or_else(|| {
            register_endpoint_with_description(
                "RELAY_TEST_GROUND_STATION",
                "target behind the relay uplink",
                false,
            )
            .unwrap()
        });
    let status = DataType::try_named("RELAY_TEST_STATUS").unwrap_or_else(|| {
        register_data_type_with_description(
            "RELAY_TEST_STATUS",
            "reliable status returned through a two-sided relay",
            MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
            &[ground_station],
            ReliableMode::Ordered,
            200,
        )
        .unwrap()
    });

    let uplink_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let uplink_frames_c = uplink_frames.clone();
    let relay = Relay::new(zero_clock());
    let uplink = relay.add_side_packed_with_options(
        "pico-uart",
        move |bytes: &[u8]| {
            uplink_frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    let can = relay.add_side_packed_with_options(
        "can",
        |_bytes| Ok(()),
        RelaySideOptions {
            reliable_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    let address = AddressAdvertisement {
        hostname: "GS".into(),
        address: 42,
        requested_address: 0,
        mode: ADDRESS_MODE_DYNAMIC,
        state: ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 42,
        reachable_endpoints: vec![ground_station],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: LinkCapabilities {
            version: 1,
            flags: 0,
            profile: crate::discovery::LINK_PROFILE_CANONICAL,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    relay
        .rx_from_side(uplink, build_discovery_address("GS", 0, &address).unwrap())
        .unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    uplink_frames.lock().unwrap().clear();

    let packet = Packet::new(status, &[ground_station], "VB", 1, Arc::<[u8]>::from([1u8])).unwrap();
    // Compact links may preserve only the assigned source address. The
    // frozen destination identity must still resolve through the direct
    // DiscoveryAddress advertisement instead of requiring a hostname.
    let gs_hash = 42u64;
    let packed = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(MessageElement::Static(
            1,
            MessageDataType::UInt8,
            MessageClass::Data,
        )),
        &[gs_hash],
    )
    .unwrap();
    relay.rx_packed_from_side(can, packed.as_ref()).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();

    assert_eq!(
        count_packed_frames_of_type(&uplink_frames.lock().unwrap(), status),
        1,
        "a target learned from a direct DiscoveryAddress must route across the relay",
    );

    uplink_frames.lock().unwrap().clear();
    let packet = Packet::new(status, &[ground_station], "VB", 2, Arc::<[u8]>::from([2u8])).unwrap();
    let packed = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(MessageElement::Static(
            1,
            MessageDataType::UInt8,
            MessageClass::Data,
        )),
        &[99u64],
    )
    .unwrap();
    relay.rx_packed_from_side(can, packed.as_ref()).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        count_packed_frames_of_type(&uplink_frames.lock().unwrap(), status),
        1,
        "an unresolved compact target may use one unambiguous endpoint route",
    );

    uplink_frames.lock().unwrap().clear();
    let mut bridge_only_address = address.clone();
    bridge_only_address.reachable_endpoints.clear();
    relay
        .rx_from_side(
            uplink,
            build_discovery_address("GS", 0, &bridge_only_address).unwrap(),
        )
        .unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    uplink_frames.lock().unwrap().clear();
    let packet = Packet::new(status, &[ground_station], "VB", 3, Arc::<[u8]>::from([3u8])).unwrap();
    let packed = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(MessageElement::Static(
            1,
            MessageDataType::UInt8,
            MessageClass::Data,
        )),
        &[98u64],
    )
    .unwrap();
    relay.rx_packed_from_side(can, packed.as_ref()).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        count_packed_frames_of_type(&uplink_frames.lock().unwrap(), status),
        1,
        "a two-sided bridge must use its sole non-ingress path without echoing",
    );

    uplink_frames.lock().unwrap().clear();
    let packet = Packet::new(status, &[ground_station], "VB", 4, Arc::<[u8]>::from([4u8])).unwrap();
    let packed = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(MessageElement::Static(
            1,
            MessageDataType::UInt8,
            MessageClass::Data,
        )),
        &[],
    )
    .unwrap();
    relay.rx_packed_from_side(can, packed.as_ref()).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        count_packed_frames_of_type(&uplink_frames.lock().unwrap(), status),
        1,
        "an untargeted nonlocal packet must cross a two-sided bridge once",
    );

    uplink_frames.lock().unwrap().clear();
    relay
        .rx_from_side(uplink, build_discovery_address("GS", 0, &address).unwrap())
        .unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    uplink_frames.lock().unwrap().clear();
    let alternate_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let alternate_frames_c = alternate_frames.clone();
    let alternate = relay.add_side_packed_with_options(
        "alternate-uplink",
        move |bytes: &[u8]| {
            alternate_frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    let mut alternate_address = address;
    alternate_address.hostname = "OTHER".into();
    alternate_address.address = 43;
    relay
        .rx_from_side(
            alternate,
            build_discovery_address("OTHER", 0, &alternate_address).unwrap(),
        )
        .unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    uplink_frames.lock().unwrap().clear();
    alternate_frames.lock().unwrap().clear();

    let packet = Packet::new(status, &[ground_station], "VB", 5, Arc::<[u8]>::from([5u8])).unwrap();
    let packed = wire_format::pack_packet_with_wire_contract(
        &packet,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(MessageElement::Static(
            1,
            MessageDataType::UInt8,
            MessageClass::Data,
        )),
        &[100u64],
    )
    .unwrap();
    relay.rx_packed_from_side(can, packed.as_ref()).unwrap();
    relay.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(
        count_packed_frames_of_type(&uplink_frames.lock().unwrap(), status)
            + count_packed_frames_of_type(&alternate_frames.lock().unwrap(), status),
        0,
        "an unresolved target must not fan out across ambiguous endpoint routes",
    );
}

#[test]
fn relay_packed_side_chunking_reassembles_for_fixed_size_links() {
    crate::tests::ensure_common_test_schema();
    use crate::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};

    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let chunk_count = Arc::new(AtomicUsize::new(0));
    let chunk_count_c = chunk_count.clone();
    let max_seen = Arc::new(AtomicUsize::new(0));
    let max_seen_c = max_seen.clone();
    let receiver_c = receiver.clone();
    let relay = Relay::new(zero_clock());
    let max_frame_bytes = 48usize;

    let input_side = relay.add_side_packet("input", |_pkt| Ok(()));
    relay.add_side_packed_small_packets(
        "fixed-link",
        move |bytes: &[u8]| {
            chunk_count_c.fetch_add(1, Ordering::SeqCst);
            let mut current = max_seen_c.load(Ordering::SeqCst);
            while bytes.len() > current
                && max_seen_c
                    .compare_exchange(current, bytes.len(), Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                current = max_seen_c.load(Ordering::SeqCst);
            }
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        max_frame_bytes,
    );
    let rx_side = receiver.add_side_packed_with_options(
        "fixed-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            max_frame_bytes,
            ..RouterSideOptions::default()
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);

    let payload = vec![b'R'; 180];
    let pkt = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::named("SD_CARD")],
        "RELAY_CHUNK_SRC",
        55,
        Arc::<[u8]>::from(payload),
    )
    .unwrap()
    .with_nonce(31);

    relay.rx_from_side(input_side, pkt).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    assert!(chunk_count.load(Ordering::SeqCst) > 1);
    assert!(max_seen.load(Ordering::SeqCst) <= max_frame_bytes);
}

#[test]
fn relay_packed_side_templates_preserve_absolute_unchanged_timestamps() {
    crate::tests::ensure_common_test_schema();
    use crate::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};

    let delivered = Arc::new(AtomicUsize::new(0));
    let delivered_c = delivered.clone();
    let receiver = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                delivered_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )]),
        zero_clock(),
    ));
    let receiver_side_id = Arc::new(Mutex::new(None));
    let receiver_side_id_c = receiver_side_id.clone();
    let receiver_c = receiver.clone();
    let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
    let frames_c = frames.clone();
    let relay = Relay::new(zero_clock());

    let input_side = relay.add_side_packet("input", |_pkt| Ok(()));
    let output_side = relay.add_side_packed_with_options(
        "compact-link",
        move |bytes: &[u8]| {
            frames_c.lock().unwrap().push(bytes.len());
            let side = receiver_side_id_c
                .lock()
                .unwrap()
                .expect("receiver side id");
            receiver_c.rx_packed_from_side(bytes, side)
        },
        RelaySideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RelaySideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
        },
    );
    let rx_side = receiver.add_side_packed_with_options(
        "compact-link",
        |_bytes| Ok(()),
        RouterSideOptions {
            header_template_enabled: true,
            compact_header_target_bytes: 20,
            ..RouterSideOptions::default()
                .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
        },
    );
    *receiver_side_id.lock().unwrap() = Some(rx_side);
    advertise_side(
        &relay,
        output_side,
        "DST_SIDE",
        DataEndpoint::named("SD_CARD"),
    );
    relay.process_all_queues().unwrap();
    frames.lock().unwrap().clear();
    let delivered_before = delivered.load(Ordering::SeqCst);
    let stats_before = relay.export_runtime_stats();
    let side_before = stats_before
        .sides
        .iter()
        .find(|side| side.side_name == "compact-link")
        .expect("compact-link side stats before data")
        .clone();

    let pkt_a = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(41);
    let pkt_b = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0_f32, 5.0, 6.0],
        &[DataEndpoint::named("SD_CARD")],
        10_000,
    )
    .unwrap()
    .with_nonce(42);

    relay.rx_from_side(input_side, pkt_a).unwrap();
    relay.rx_from_side(input_side, pkt_b).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        delivered
            .load(Ordering::SeqCst)
            .saturating_sub(delivered_before),
        2
    );
    let lens = frames.lock().unwrap();
    assert!(lens.len() >= 2);
    drop(lens);

    let stats = relay.export_runtime_stats();
    let side = stats
        .sides
        .iter()
        .find(|side| side.side_name == "compact-link")
        .expect("compact-link side stats");
    assert!(side.side_transport_full_frames > side_before.side_transport_full_frames);
    assert!(side.side_transport_compact_frames > side_before.side_transport_compact_frames);
    assert_eq!(
        side.side_transport_compact_omitted_timestamp_frames
            - side_before.side_transport_compact_omitted_timestamp_frames,
        0
    );
}

fn wire_for_value(v: u64) -> Arc<[u8]> {
    crate::tests::ensure_common_test_schema();
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[v as f32, 0.0, 0.0],
        &[DataEndpoint::named("SD_CARD")],
        v,
    )
    .unwrap();
    wire_format::pack_packet(&pkt)
}

/// A small "bus" that records frames seen by each relay side.
#[derive(Clone)]
struct SideBus {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SideBus {
    fn new() -> (
        Self,
        impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    ) {
        let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let frames_c = frames.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            frames_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        };
        (Self { frames }, tx)
    }
}

fn advertise_side(relay: &Relay, side: usize, sender: &str, endpoint: DataEndpoint) {
    let pkt = build_discovery_announce(sender, 0, &[endpoint]).unwrap();
    relay.rx_from_side(side, pkt).unwrap();
}

/// Basic fan-out: one source side should be relayed to all *other* sides,
/// and never loop back to the source.
#[test]
fn relay_basic_fan_out() {
    let relay = Arc::new(Relay::new(zero_clock()));

    // Three sides: A, B, C
    let (bus_a, tx_a) = SideBus::new();
    let (bus_b, tx_b) = SideBus::new();
    let (bus_c, tx_c) = SideBus::new();

    let id_a = relay.add_side_packed("A", tx_a);
    let id_b = relay.add_side_packed("B", tx_b);
    let id_c = relay.add_side_packed("C", tx_c);

    advertise_side(&relay, id_b, "SIDE_B", DataEndpoint::named("SD_CARD"));
    advertise_side(&relay, id_c, "SIDE_C", DataEndpoint::named("SD_CARD"));
    relay.process_all_queues().unwrap();
    bus_a.frames.lock().unwrap().clear();
    bus_b.frames.lock().unwrap().clear();
    bus_c.frames.lock().unwrap().clear();

    let frame = wire_for_value(1);

    // Inject from A
    relay
        .rx_packed_from_side(id_a, frame.as_ref())
        .expect("rx_packed_from_side failed");

    // Drain all queues → should deliver once to B and once to C.
    relay
        .process_all_queues()
        .expect("process_all_queues failed");

    let frames_a = bus_a.frames.lock().unwrap().clone();
    let frames_b = bus_b.frames.lock().unwrap().clone();
    let frames_c = bus_c.frames.lock().unwrap().clone();
    assert_eq!(
        count_packed_frames_of_type(&frames_a, DataType::named("GPS_DATA")),
        0,
        "source side must not receive its own GPS frame"
    );
    assert_eq!(
        count_packed_frames_of_type(&frames_b, DataType::named("GPS_DATA")),
        1,
        "side B should see one GPS frame"
    );
    assert_eq!(
        count_packed_frames_of_type(&frames_c, DataType::named("GPS_DATA")),
        1,
        "side C should see one GPS frame"
    );

    assert!(
        frames_b
            .iter()
            .any(|bytes| bytes.as_slice() == frame.as_ref())
    );
    assert!(
        frames_c
            .iter()
            .any(|bytes| bytes.as_slice() == frame.as_ref())
    );
}

/// Ensure invalid side IDs are rejected with a TelemetryError::HandlerError.
#[test]
fn relay_invalid_side_id_returns_error() {
    let relay = Relay::new(zero_clock());

    // No sides registered; any index is invalid.
    let res = relay.rx_packed_from_side(0, &[0x01, 0x02]);
    match res {
        Err(TelemetryError::HandlerError(msg)) => {
            assert!(
                msg.contains("relay: invalid side id"),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("expected HandlerError for invalid side id, got {other:?}"),
    }
}

/// After clear_queues, no pending TX/RX items should be processed.
#[test]
fn relay_clear_queues_drops_pending_work() {
    let relay = Relay::new(zero_clock());

    let tx_count_b = Arc::new(AtomicUsize::new(0));
    let tx_count_c = Arc::new(AtomicUsize::new(0));

    let tx_b_c = tx_count_b.clone();
    let tx_b = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        tx_b_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };

    let tx_c_c = tx_count_c.clone();
    let tx_c = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        tx_c_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };

    let id_a = relay.add_side_packed("A", |_b| Ok(()));
    relay.add_side_packed("B", tx_b);
    relay.add_side_packed("C", tx_c);

    // Queue some RX work from A.
    let frame_a = wire_for_value(1);
    let frame_b = wire_for_value(2);
    relay.rx_packed_from_side(id_a, frame_a.as_ref()).unwrap();
    relay.rx_packed_from_side(id_a, frame_b.as_ref()).unwrap();

    // Expand RX → TX, but do not deliver yet.
    relay.process_rx_queue().unwrap();

    // Drop all queued items.
    relay.clear_queues();

    // Nothing should be delivered now.
    relay.process_all_queues().unwrap();

    assert_eq!(
        tx_count_b.load(Ordering::SeqCst),
        0,
        "no frames should be sent to side B after clear_queues"
    );
    assert_eq!(
        tx_count_c.load(Ordering::SeqCst),
        0,
        "no frames should be sent to side C after clear_queues"
    );
}

/// Non-zero timeout budget should be able to stop processing early,
/// leaving additional work for a later drain.
#[test]
fn relay_timeout_limits_work_per_call() {
    // Step clock: each now_ms() call advances by 10ms.
    let clock = StepClock::new_box(0, 10);
    let relay = Relay::new(clock);

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
    let id_dst = relay.add_side_packed("DST", tx);
    advertise_side(&relay, id_dst, "DST_SIDE", DataEndpoint::named("SD_CARD"));
    relay.process_all_queues_with_timeout(0).unwrap();

    // Queue multiple RX items from SRC, each with a unique frame to avoid dedup.
    for i in 0..5u8 {
        let frame = wire_for_value(i as u64);
        relay.rx_packed_from_side(id_src, frame.as_ref()).unwrap();
    }

    // With step=10 and timeout=5:
    //   - start = 0
    //   - after first RX, now_ms() == 10 → exceeds budget before any TX.
    relay
        .process_all_queues_with_timeout(5)
        .expect("process_all_queues_with_timeout failed");

    // No TX should have happened yet, but there is still work queued.
    assert_eq!(
        tx_count.load(Ordering::SeqCst),
        0,
        "timeout should have prevented any TX in first call"
    );

    // Now drain fully; all fan-out TX items should be delivered.
    relay
        .process_all_queues_with_timeout(0)
        .expect("final drain failed");

    // Each of the 5 RX frames fans out from SRC -> DST (1 destination).
    assert_eq!(tx_count.load(Ordering::SeqCst), 5,);
}

/// Basic sanity: concurrent RX producers should not panic and should
/// deliver all frames after a full drain.
#[test]
fn relay_concurrent_rx_is_thread_safe() {
    use std::thread;

    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 25;
    let total_frames = THREADS * ITERS_PER_THREAD;

    let relay = Arc::new(Relay::new(zero_clock()));

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();
    relay.add_side_packed("SRC", |_b| Ok(()));
    let dst = relay.add_side_packed("DST", move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    advertise_side(&relay, dst, "DST_SIDE", DataEndpoint::named("SD_CARD"));
    relay.process_all_queues_with_timeout(0).unwrap();

    let mut threads_vec = Vec::new();
    for tid in 0..THREADS {
        let r = relay.clone();
        threads_vec.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                let idx = (tid * ITERS_PER_THREAD + i) as u8;
                // Unique last byte per (thread, iteration) to avoid dedup.
                let frame = wire_for_value(idx as u64);
                r.rx_packed_from_side(0, frame.as_ref()).unwrap();
            }
        }));
    }

    for t in threads_vec {
        t.join().expect("producer thread panicked");
    }

    relay
        .process_all_queues_with_timeout(0)
        .expect("drain failed");

    assert_eq!(tx_count.load(Ordering::SeqCst), total_frames);
}

#[test]
fn relay_side_tx_reentry_defers_recursive_queue_drains() {
    let relay = Arc::new(Relay::new(zero_clock()));
    let remaining = Arc::new(AtomicUsize::new(6));
    let ingress = relay.add_side_packed("INGRESS", move |_bytes| Ok(()));

    let relay_c = relay.clone();
    let remaining_c = remaining.clone();
    let loop_hits = Arc::new(AtomicUsize::new(0));
    let loop_hits_c = loop_hits.clone();
    let in_tx = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reentered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let in_tx_c = in_tx.clone();
    let reentered_c = reentered.clone();
    relay.add_side_packed("LOOP", move |bytes| {
        loop_hits_c.fetch_add(1, Ordering::SeqCst);
        if in_tx_c.swap(true, Ordering::SeqCst) {
            reentered_c.store(true, Ordering::SeqCst);
        }
        if remaining_c
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            relay_c.rx_packed_from_side(ingress, bytes)?;
            relay_c.process_all_queues()?;
        }
        in_tx_c.store(false, Ordering::SeqCst);
        Ok(())
    });

    relay
        .rx_packed_from_side(ingress, wire_for_value(1).as_ref())
        .unwrap();
    relay.process_all_queues().unwrap();
    for _ in 0..8 {
        relay.process_all_queues().unwrap();
    }

    assert!(!reentered.load(Ordering::SeqCst));
    assert!(remaining.load(Ordering::SeqCst) < 6);
    assert!(loop_hits.load(Ordering::SeqCst) > 0);
}
