
//! Basic smoke tests for packet roundtrip, string formatting, and simple
//! router send/receive paths.

use crate::tests::timeout_tests::StepClock;
use crate::tests::{SeenType, count_packed_frames_of_type, get_sd_card_handler, packed_frame_type};
use crate::{
    TelemetryResult,
    config::{DataEndpoint, DataType},
    packet::Packet,
    router::Router,
    wire_format,
};
use std::sync::{Arc, Mutex};
use std::vec::Vec;

/// Pack/unpack a GPS packet and ensure all fields and payload
/// bytes round-trip exactly.
#[test]
fn pack_roundtrip_gps() {
    // GPS: 3 * f32
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[5.2141414, 3.1342144, 1.1231232],
        endpoints,
        0,
    )
    .unwrap();

    pkt.validate().unwrap();

    let bytes = wire_format::pack_packet(&pkt);
    let rpkt = wire_format::unpack_packet(&bytes).unwrap();

    rpkt.validate().unwrap();
    assert_eq!(rpkt.data_type(), pkt.data_type());
    assert_eq!(rpkt.data_size(), pkt.data_size());
    assert_eq!(rpkt.timestamp(), pkt.timestamp());
    assert_eq!(rpkt.endpoints(), pkt.endpoints());
    assert_eq!(rpkt.payload(), pkt.payload());
}

/// Verify `header_string()` format for a simple GPS packet.
#[test]
fn header_string_matches_expectation() {
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
        .unwrap();
    let s = pkt.header_string();
    assert_eq!(
        s,
        "Type: GPS_DATA, Data Size: 12, Sender: TEST_PLATFORM, Endpoints: [SD_CARD, RADIO], Timestamp: 0 (0s 000ms)"
    );
}

/// Ensure `to_string()` includes the float values and the general header.
#[test]
fn packet_to_string_formats_floats() {
    let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.5, 3.25], endpoints, 0)
        .unwrap();

    let text = pkt.as_string();
    assert!(text.starts_with(
            "{Type: GPS_DATA, Data Size: 12, Sender: TEST_PLATFORM, Endpoints: [SD_CARD, RADIO], Timestamp: 0 (0s 000ms), Data: "
        ));
    assert!(text.contains("1"));
    assert!(text.contains("2.5"));
    assert!(text.contains("3.25"));
}

/// End-to-end test: `Router::log` → TX callback (pack/unpack) →
/// local handler decoding f32 payload.
#[test]
fn router_sends_and_receives() {
    use crate::router::{Router, RouterConfig};

    // capture spaces
    let tx_seen: Arc<Mutex<Option<Packet>>> = Arc::new(Mutex::new(None));
    let sd_seen_decoded: SeenType = Arc::new(Mutex::new(None));

    // transmitter: record the unpacked packet we "sent"
    let tx_seen_c = tx_seen.clone();
    let transmit = move |bytes: &[u8]| -> TelemetryResult<()> {
        let pkt = wire_format::unpack_packet(bytes)?;
        *tx_seen_c.lock().unwrap() = Some(pkt);
        Ok(())
    };

    // local SD handler: decode payload to f32s and record (ty, values)
    let sd_seen_c = sd_seen_decoded.clone();
    let sd_handler = get_sd_card_handler(sd_seen_c);
    let box_clock = StepClock::new_default_box();

    let router = Router::new_with_clock(RouterConfig::new(vec![sd_handler]), box_clock);
    router.add_side_packed("tx", transmit);

    // send GPS_DATA (3 * f32) using Router::log (uses default endpoints from schema)
    let data = [1.0_f32, 2.0, 3.0];
    router.log(DataType::named("GPS_DATA"), &data).unwrap();

    // --- assertions ---

    // remote transmitter saw the same type & bytes
    let tx_pkt = tx_seen
        .lock()
        .unwrap()
        .clone()
        .expect("no tx packet recorded");
    assert_eq!(tx_pkt.data_type(), DataType::named("GPS_DATA"));
    assert_eq!(tx_pkt.payload().len(), 3 * 4);
    // compare bytes exactly to what log() would have produced
    let mut expected = Vec::new();
    for v in data {
        expected.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(tx_pkt.payload(), &*expected);

    // local SD handler decoded to f32s and recorded (type, values)
    let (seen_ty, seen_vals) = sd_seen_decoded
        .lock()
        .unwrap()
        .clone()
        .expect("no sd packet recorded");
    assert_eq!(seen_ty, DataType::named("GPS_DATA"));
    assert_eq!(seen_vals, data);
}

#[test]
fn router_load_balancing_smoke_exercises_public_runtime_controls() {
    use crate::RouteSelectionMode;
    use crate::discovery::build_discovery_announce;
    use crate::router::{Router, RouterConfig};

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), StepClock::new_default_box());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    router.set_route_weight(None, side_a, 1).unwrap();
    router.set_route_weight(None, side_b, 1).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    let pkt_failover = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    router.tx(pkt.clone()).unwrap();

    router
        .set_source_route_mode(None, RouteSelectionMode::Failover)
        .unwrap();
    router.set_route_priority(None, side_a, 0).unwrap();
    router.set_route_priority(None, side_b, 1).unwrap();
    router.tx(pkt_failover).unwrap();

    router.clear_route_weight(None, side_a).unwrap();
    router.clear_route_priority(None, side_b).unwrap();
    router.clear_source_route_mode(None).unwrap();

    let total = seen_a.lock().unwrap().len() + seen_b.lock().unwrap().len();
    assert_eq!(total, 2);
}

#[test]
fn relay_load_balancing_smoke_exercises_public_runtime_controls() {
    crate::tests::ensure_common_test_schema();
    use crate::RouteSelectionMode;
    use crate::discovery::build_discovery_announce;
    use crate::relay::Relay;

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(StepClock::new_default_box());
    let ingress = relay.add_side_packet("INGRESS", |_pkt: &Packet| Ok(()));
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay
        .set_source_route_mode(Some(ingress), RouteSelectionMode::Weighted)
        .unwrap();
    relay.set_route_weight(Some(ingress), side_a, 2).unwrap();
    relay.set_route_weight(Some(ingress), side_b, 1).unwrap();
    relay
        .set_source_route_mode(Some(ingress), RouteSelectionMode::Failover)
        .unwrap();
    relay.set_route_priority(Some(ingress), side_a, 0).unwrap();
    relay.set_route_priority(Some(ingress), side_b, 1).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(ingress, pkt).unwrap();
    relay.process_all_queues().unwrap();

    relay.clear_route_weight(Some(ingress), side_a).unwrap();
    relay.clear_route_priority(Some(ingress), side_b).unwrap();
    relay.clear_source_route_mode(Some(ingress)).unwrap();

    let total =
        crate::tests::count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"))
            + crate::tests::count_packets_of_type(
                &seen_b.lock().unwrap(),
                DataType::named("GPS_DATA"),
            );
    assert_eq!(total, 1);
}

#[test]
fn discovery_prefers_direct_topology_path_over_reflected_route() {
    crate::tests::ensure_common_test_schema();
    use crate::discovery::{TopologyBoardNode, build_discovery_announce, build_discovery_topology};
    use crate::relay::Relay;

    let direct_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let reflected_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let direct_seen_cb = direct_seen.clone();
    let reflected_seen_cb = reflected_seen.clone();
    let relay = Relay::new(StepClock::new_default_box());
    let endpoint = DataEndpoint::named("RADIO");
    let ingress = relay.add_side_packet("INGRESS", |_packet| Ok(()));
    let direct = relay.add_side_packet("DIRECT", move |packet| {
        direct_seen_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let reflected = relay.add_side_packet("REFLECTED", move |packet| {
        reflected_seen_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });

    for (side, announcer, boards) in [
        (
            direct,
            "GATEWAY",
            vec![
                TopologyBoardNode {
                    sender_id: "GATEWAY".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["VALVE".into()],
                },
                TopologyBoardNode {
                    sender_id: "VALVE".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GATEWAY".into()],
                },
            ],
        ),
        (
            reflected,
            "RF",
            vec![
                TopologyBoardNode {
                    sender_id: "RF".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GROUND".into()],
                },
                TopologyBoardNode {
                    sender_id: "GROUND".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into(), "GATEWAY".into()],
                },
                TopologyBoardNode {
                    sender_id: "GATEWAY".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GROUND".into(), "VALVE".into()],
                },
                TopologyBoardNode {
                    sender_id: "VALVE".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GATEWAY".into()],
                },
            ],
        ),
    ] {
        relay
            .rx_from_side(
                side,
                build_discovery_announce(announcer, 1, &[endpoint]).unwrap(),
            )
            .unwrap();
        relay
            .rx_from_side(
                side,
                build_discovery_topology(announcer, 2, &boards).unwrap(),
            )
            .unwrap();
    }
    relay.process_all_queues().unwrap();
    direct_seen.lock().unwrap().clear();
    reflected_seen.lock().unwrap().clear();

    relay
        .rx_from_side(
            ingress,
            Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[endpoint],
                3,
            )
            .unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        direct_seen
            .lock()
            .unwrap()
            .iter()
            .filter(|packet| packet.data_type() == DataType::named("GPS_DATA"))
            .count(),
        1
    );
    assert_eq!(
        reflected_seen
            .lock()
            .unwrap()
            .iter()
            .filter(|packet| packet.data_type() == DataType::named("GPS_DATA"))
            .count(),
        0
    );
}

#[test]
fn relay_explicit_fanout_overrides_adaptive_discovery_selection() {
    crate::tests::ensure_common_test_schema();
    use crate::RouteSelectionMode;
    use crate::discovery::build_discovery_announce;
    use crate::relay::Relay;

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_cb = seen_a.clone();
    let seen_b_cb = seen_b.clone();
    let relay = Relay::new(StepClock::new_default_box());
    let ingress = relay.add_side_packet("INGRESS", |_packet| Ok(()));
    let side_a = relay.add_side_packet("A", move |packet| {
        seen_a_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |packet| {
        seen_b_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let endpoint = DataEndpoint::named("RADIO");
    relay
        .rx_from_side(
            side_a,
            build_discovery_announce("A", 1, &[endpoint]).unwrap(),
        )
        .unwrap();
    relay
        .rx_from_side(
            side_b,
            build_discovery_announce("B", 1, &[endpoint]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    relay
        .set_source_route_mode(Some(ingress), RouteSelectionMode::Fanout)
        .unwrap();
    relay
        .rx_from_side(
            ingress,
            Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[endpoint],
                2,
            )
            .unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        crate::tests::count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        crate::tests::count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
}

/// A small “bus” that records transmitted frames for TX/RX queue tests.
struct TestBus {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl TestBus {
    /// Create a `TestBus` and a TX function that pushes any transmitted bytes
    /// into an internal `Vec<Vec<u8>>`.
    fn new() -> (
        Self,
        impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static,
    ) {
        let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let tx_frames = frames.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            // capture the exact wire bytes
            tx_frames.lock().unwrap().push(bytes.to_vec());
            Ok(())
        };
        (Self { frames }, tx)
    }
}

/// TX router enqueues packets, flushes to a `TestBus`, and an RX router
/// consumes them from its receive queue and delivers to a local handler.
#[test]
fn queued_roundtrip_between_two_routers() {
    // --- Set up a TX router that only sends (no local endpoints) ---
    let (bus, tx_fn) = TestBus::new();
    let box_clock_tx = StepClock::new_default_box();
    let box_clock_rx = StepClock::new_default_box();

    let tx_router = Router::new_with_clock(Default::default(), box_clock_tx);
    tx_router.add_side_packed("tx", tx_fn);

    // --- Set up an RX router with a local SD handler that decodes f32 payloads ---
    let seen: SeenType = Arc::new(Mutex::new(None));
    let seen_c = seen.clone();
    let sd_handler = get_sd_card_handler(seen_c);
    fn tx_handler(_bytes: &[u8]) -> TelemetryResult<()> {
        // RX router does not transmit in this test
        Ok(())
    }

    let rx_router = Router::new_with_clock(
        crate::router::RouterConfig::new(vec![sd_handler]),
        box_clock_rx,
    );
    rx_router.add_side_packed("tx", tx_handler);

    // --- 1) Sender enqueues a packet for TX ---
    let data = [1.0_f32, 2.0, 3.0];
    tx_router
        .log_queue(DataType::named("GPS_DATA"), &data)
        .unwrap();

    // --- 2) Flush TX queue -> pushes wire frames into TestBus ---
    tx_router.process_tx_queue().unwrap();

    // --- 3) Deliver captured frames into RX router's *received queue* ---
    let frames = bus.frames.lock().unwrap().clone();
    let gps_frames: Vec<Vec<u8>> = frames
        .iter()
        .filter(|frame| packed_frame_type(frame.as_slice()) == Some(DataType::named("GPS_DATA")))
        .cloned()
        .collect();
    assert_eq!(
        gps_frames.len(),
        1,
        "expected exactly one GPS_DATA TX frame"
    );
    for frame in &gps_frames {
        rx_router.rx_packed_queue(frame).unwrap();
    }

    // --- 4) Drain RX queue -> invokes local handlers ---
    rx_router.process_rx_queue().unwrap();

    // --- Assertions: handler got the right data ---
    let (ty, vals) = seen.lock().unwrap().clone().expect("no packet delivered");
    assert_eq!(ty, DataType::named("GPS_DATA"));
    assert_eq!(vals, data);
}

/// Demonstrate “self-delivery” by feeding packed frames from a router’s
/// own TX back into its RX queue.
#[test]
fn queued_self_delivery_via_receive_queue() {
    let (bus, tx_fn) = TestBus::new();
    let box_clock = StepClock::new_default_box();

    let router = Router::new_with_clock(Default::default(), box_clock);
    router.add_side_packed("tx", tx_fn);

    // Enqueue for transmit
    let data = [10.0_f32, 10.25, 10.5];
    router
        .log_queue(DataType::named("GPS_DATA"), &data)
        .unwrap();

    let data = [10.0_f32, 10.25];
    router
        .log_queue(DataType::named("BATTERY_STATUS"), &data)
        .unwrap();

    let data = [10.0_f32, 10.25, 10.2];
    router
        .log_queue(DataType::named("GPS_DATA"), &data)
        .unwrap();
    // Flush -> frame appears on the "bus"
    router.process_tx_queue().unwrap();
    let frames = bus.frames.lock().unwrap().clone();
    assert_eq!(
        count_packed_frames_of_type(&frames, DataType::named("GPS_DATA")),
        2
    );
    assert_eq!(
        count_packed_frames_of_type(&frames, DataType::named("BATTERY_STATUS")),
        1
    );

    // Feed back into *the same* router's received queue
    router.rx_packed_queue(&frames[0]).unwrap();

    // Now draining the received queue should dispatch to any matching local endpoints.
    // (This router has no endpoints; this test just proves the queue path is exercised.)
    router.process_rx_queue().unwrap();
}
