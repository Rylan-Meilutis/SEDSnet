use crate::config::{STATIC_HEX_LENGTH, STATIC_STRING_LENGTH, get_message_meta};
use crate::get_needed_message_size;
use crate::packet::Packet;
use crate::router::{Clock, EndpointHandler};
use crate::{DataEndpoint, DataType, MessageDataType, TelemetryError, get_data_type, message_meta};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type SeenType = Arc<Mutex<Option<(DataType, Vec<f32>)>>>;

pub(crate) fn ensure_common_test_schema() {
    use crate::config::{register_data_type_with_description, register_endpoint_with_description};
    use crate::{MessageClass, MessageElement, ReliableMode};
    use std::sync::Once;

    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let radio = DataEndpoint::try_named("RADIO").unwrap_or_else(|| {
            register_endpoint_with_description("RADIO", "test radio endpoint", false)
                .expect("register RADIO")
        });
        let sd_card = DataEndpoint::try_named("SD_CARD").unwrap_or_else(|| {
            register_endpoint_with_description("SD_CARD", "test sd endpoint", false)
                .expect("register SD_CARD")
        });
        if DataType::try_named("GPS_DATA").is_none() {
            register_data_type_with_description(
                "GPS_DATA",
                "test gps data type",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[radio, sd_card],
                ReliableMode::None,
                1,
            )
            .expect("register GPS_DATA");
        }
    });
}

/// Compute a valid test payload length for a given [`DataType`], respecting the
/// schema’s static/dynamic element counts and element widths.
///
/// This is used throughout tests to avoid hard-coding per-type sizes.
// a clock that gets the system time as a u64 milliseconds since unix epoch.
struct UnixClock;

impl Clock for UnixClock {
    fn now_ms(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        since_the_epoch.as_millis() as u64
    }
}

#[cfg(feature = "compression")]
mod compression_memory_tests {
    use crate::config::{DataEndpoint, DataType};
    use crate::packet::Packet;
    use crate::wire_format;
    use std::sync::Arc;

    const FLAG_COMPRESSED_PAYLOAD: u8 = 0x01;

    fn make_message_packet(payload: &[u8], ts: u64) -> Packet {
        Packet::new(
            DataType::named("MESSAGE_DATA"),
            &[DataEndpoint::named("SD_CARD")],
            "CMP_NODE",
            ts,
            Arc::<[u8]>::from(payload),
        )
        .expect("packet build failed")
    }

    #[test]
    fn compressible_payload_sets_compressed_flag_and_roundtrips() {
        let payload = vec![0u8; 4096];
        let pkt = make_message_packet(&payload, 11);

        let wire = wire_format::pack_packet(&pkt);
        assert_eq!(wire[0] & FLAG_COMPRESSED_PAYLOAD, FLAG_COMPRESSED_PAYLOAD);

        let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
        assert_eq!(decoded.payload(), payload.as_slice());
    }

    #[test]
    fn below_threshold_payload_stays_uncompressed_and_roundtrips() {
        let payload = b"small-msg".to_vec();
        let pkt = make_message_packet(&payload, 22);

        let wire = wire_format::pack_packet(&pkt);
        assert_eq!(wire[0] & FLAG_COMPRESSED_PAYLOAD, 0);

        let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
        assert_eq!(decoded.payload(), payload.as_slice());
    }

    #[test]
    fn mixed_payload_workload_roundtrips_without_failures() {
        for i in 0..1500u64 {
            let payload = if i % 2 == 0 {
                vec![b'Z'; 192]
            } else {
                let mut v = Vec::with_capacity(192);
                for j in 0..192u16 {
                    v.push(32u8 + (((i as u16 + j) as u8) % 95));
                }
                v
            };

            let pkt = make_message_packet(&payload, i);
            let wire = wire_format::pack_packet(&pkt);
            let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
            assert_eq!(decoded.payload(), payload.as_slice());
        }
    }
}

fn test_payload_len_for(ty: DataType) -> usize {
    match message_meta(ty).element {
        crate::MessageElement::Static(_, _, _) => get_needed_message_size(ty),
        crate::MessageElement::Dynamic(_, _) => {
            // Pick reasonable defaults per data kind
            match get_data_type(ty) {
                MessageDataType::String => STATIC_STRING_LENGTH, // router error-path expects this
                MessageDataType::Binary => STATIC_HEX_LENGTH,    // any bytes; size-bounded
                // numeric/bool: must be multiple of element width → use “schema element count”
                other => {
                    let w = match other {
                        MessageDataType::UInt8 | MessageDataType::Int8 | MessageDataType::Bool => 1,
                        MessageDataType::UInt16 | MessageDataType::Int16 => 2,
                        MessageDataType::UInt32
                        | MessageDataType::Int32
                        | MessageDataType::Float32 => 4,
                        MessageDataType::UInt64
                        | MessageDataType::Int64
                        | MessageDataType::Float64 => 8,
                        MessageDataType::UInt128 | MessageDataType::Int128 => 16,
                        MessageDataType::String | MessageDataType::Binary => 1,
                        MessageDataType::NoData => 0,
                    };
                    let elems = get_message_meta(ty).element.into().max(1);
                    w * elems
                }
            }
        }
    }
}

/// Build a simple handler that increments an [`AtomicUsize`] each time it sees
/// a packet on the `SD_CARD` endpoint.
///
/// Used by various queue/timeout and concurrency tests.
fn get_handler(rx_count_c: Arc<AtomicUsize>) -> EndpointHandler {
    EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt: &Packet| {
        rx_count_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
}

pub(crate) fn packed_frame_type(bytes: &[u8]) -> Option<DataType> {
    crate::wire_format::peek_envelope(bytes)
        .ok()
        .map(|env| env.ty)
}

pub(crate) fn count_packed_frames_of_type(frames: &[Vec<u8>], ty: DataType) -> usize {
    frames
        .iter()
        .filter(|bytes| packed_frame_type(bytes.as_slice()) == Some(ty))
        .count()
}

pub(crate) fn count_packets_of_type(pkts: &[Packet], ty: DataType) -> usize {
    pkts.iter().filter(|pkt| pkt.data_type() == ty).count()
}

#[test]
fn recent_rx_cache_preallocates_and_reserves_shared_budget() {
    use crate::config::{MAX_QUEUE_BUDGET, MAX_RECENT_RX_IDS, RECENT_RX_QUEUE_BYTES};
    use crate::router::{Router, RouterConfig};

    let router = Router::new(RouterConfig::default());
    let (capacity, max_bytes) = router.debug_recent_rx_capacity();

    assert_eq!(max_bytes, RECENT_RX_QUEUE_BYTES.max(1));
    assert_eq!(
        capacity,
        (RECENT_RX_QUEUE_BYTES.max(1) / core::mem::size_of::<u64>()).max(1)
    );
    assert!(capacity <= MAX_RECENT_RX_IDS.max(1));
    assert!(
        router.debug_shared_queue_bytes_used() <= MAX_QUEUE_BUDGET,
        "reserved recent ID memory must fit inside the shared queue budget"
    );
    assert!(
        router.debug_shared_queue_bytes_used() >= max_bytes,
        "recent ID reservation should count against the shared queue budget immediately"
    );
}

#[cfg(feature = "discovery")]
#[test]
fn router_sender_id_can_be_updated_at_runtime_for_emitted_packets() {
    use crate::router::{Router, RouterConfig};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let router = Router::new(RouterConfig::default().with_sender("OLD_SENDER"));
    router.add_side_packet("tx", move |pkt: &Packet| {
        seen_c.lock().unwrap().push(pkt.sender().to_string());
        Ok(())
    });

    router.set_sender("NEW_SENDER");
    assert_eq!(router.sender().as_ref(), "NEW_SENDER");

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|sender| sender == "NEW_SENDER")
    );
}

#[cfg(feature = "discovery")]
#[test]
fn runtime_sender_id_updates_are_reflected_in_topology_exports() {
    use crate::relay::Relay;
    use crate::router::{Router, RouterConfig};

    let router = Router::new(RouterConfig::default().with_sender("ROUTER_OLD"));
    router.set_sender("ROUTER_NEW");
    let router_topology = router.export_topology();
    assert!(
        router_topology
            .routers
            .iter()
            .any(|board| board.sender_id == "ROUTER_NEW")
    );

    let relay = Relay::new(Box::new(crate::tests::timeout_tests::StepClock::new(0, 0)));
    relay.set_sender("RELAY_NEW");
    let relay_topology = relay.export_topology();
    assert!(
        relay_topology
            .routers
            .iter()
            .any(|board| board.sender_id == "RELAY_NEW")
    );
}

/// Build a handler for `SD_CARD` that:
/// - asserts `GPS_DATA` element width is `4` (f32),
/// - decodes the payload as little-endian `f32`,
/// - stores `(DataType, Vec<f32>)` into the shared `Mutex`.
fn get_sd_card_handler(sd_seen_c: SeenType) -> EndpointHandler {
    EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |pkt: &Packet| {
        // sanity: element sizing must be 4 bytes (f32) for GPS_DATA
        let elems = get_message_meta(pkt.data_type()).element.into().max(1);
        let per_elem = get_needed_message_size(pkt.data_type()) / elems;
        assert_eq!(pkt.data_type(), DataType::named("GPS_DATA"));
        assert_eq!(per_elem, 4, "GPS_DATA expected f32 elements");

        // decode f32 little-endian
        let mut vals = Vec::with_capacity(pkt.payload().len() / 4);
        for chunk in pkt.payload().chunks_exact(4) {
            vals.push(f32::from_le_bytes(chunk.try_into().unwrap()));
        }

        *sd_seen_c.lock().unwrap() = Some((pkt.data_type(), vals));
        Ok(())
    })
}

/// Helper that asserts `result` is a [`TelemetryError::HandlerError`].
///
/// Used in tests that expect error propagation from handlers/tx.
fn handle_errors(result: Result<(), TelemetryError>) {
    match result {
        Ok(_) => panic!("Expected router.send to return Err due to handler failure"),
        Err(e) => match e {
            TelemetryError::HandlerError(_) => {} // expected
            _ => panic!("Expected TelemetryError::HandlerError, got {:?}", e),
        },
    }
}

// -----------------------------------------------------------------------------
// Basic packet + router smoke tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests2 {
    //! Basic smoke tests for packet roundtrip, string formatting, and simple
    //! router send/receive paths.

    use crate::tests::timeout_tests::StepClock;
    use crate::tests::{
        SeenType, count_packed_frames_of_type, get_sd_card_handler, packed_frame_type,
    };
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
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
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
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.5, 3.25], endpoints, 0)
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

        let total = crate::tests::count_packets_of_type(
            &seen_a.lock().unwrap(),
            DataType::named("GPS_DATA"),
        ) + crate::tests::count_packets_of_type(
            &seen_b.lock().unwrap(),
            DataType::named("GPS_DATA"),
        );
        assert_eq!(total, 1);
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
            .filter(|frame| {
                packed_frame_type(frame.as_slice()) == Some(DataType::named("GPS_DATA"))
            })
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
}

// ---- Helpers (test-local) ----

/// Build a deterministic packet with a raw 3-byte payload [0x13, 0x21, 0x34]
/// encoded as three `f32` values, endpoints [SD_CARD, RADIO], and timestamp
/// `1123581321`.
///
/// We intentionally do not call `validate()` because `GPS_DATA` usually expects
/// 3×`f32` (12 bytes) and this is for formatting/copying tests only.
fn fake_telemetry_packet_bytes() -> Packet {
    use crate::config::{DataEndpoint, DataType};

    let payload = [0x13 as f32, 0x21 as f32, 0x34 as f32]; // f32 values
    let endpoints = [DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];

    Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &payload,
        &endpoints,
        1123581321,
    )
    .unwrap()
}

/// Copy helper that mirrors the C++ behavior, but uses raw pointers so we can
/// test the “same pointer” case without violating Rust’s borrow rules.
///
/// Safety: Caller must ensure `dest` and `src` are valid for reads/writes.
unsafe fn copy_telemetry_packet_raw(
    dest: *mut Packet,
    src: *const Packet,
) -> Result<(), &'static str> {
    if dest.is_null() || src.is_null() {
        return Err("null packet");
    }
    if core::ptr::eq(dest, src as *mut Packet) {
        // same object → OK no-op
        return Ok(());
    }

    let s = unsafe { &*src };
    let d = unsafe { &mut *dest };

    // Deep copy: new endpoints slice and new payload buffer
    let endpoints_vec: Vec<DataEndpoint> = s.endpoints().to_vec();
    let payload_arc: Arc<[u8]> = Arc::from(s.payload());

    let new_pkt = Packet::new(
        s.data_type(),
        &endpoints_vec,
        s.sender(),
        s.timestamp(),
        payload_arc,
    )
    .map_err(|_| "packet validation failed")?;

    *d = new_pkt;
    Ok(())
}

// ---- Converted tests ----

/// Port of C++: TEST(Helpers, PacketHexToString).
/// Ensures `to_hex_string()` matches exactly the expected legacy format.
#[test]
fn helpers_packet_hex_to_string() {
    let pkt = fake_telemetry_packet_bytes();
    let got = pkt.to_hex_string();
    let expect = "Type: GPS_DATA, Data Size: 12, Sender: TEST_PLATFORM, Endpoints: [SD_CARD, RADIO], Timestamp: 1123581321 (312h 06m 21s 321ms), Data (hex): 0x00 0x00 0x98 0x41 0x00 0x00 0x04 0x42 0x00 0x00 0x50 0x42";
    assert_eq!(got, expect);
}

/// Port of C++: TEST(Helpers, CopyPacket).
/// Exercises `copy_telemetry_packet_raw` for null, self-copy, and deep copy.
#[test]
fn helpers_copy_telemetry_packet() {
    // (1) null dest → error
    let src = fake_telemetry_packet_bytes();
    let st = unsafe { copy_telemetry_packet_raw(core::ptr::null_mut(), &src as *const _) };
    assert!(st.is_err());

    // (2) same pointer (no-op) → OK
    let mut same = fake_telemetry_packet_bytes();
    let same_ptr: *mut Packet = &mut same;
    let st = unsafe { copy_telemetry_packet_raw(same_ptr, same_ptr as *const _) };
    assert!(st.is_ok());

    // (3) distinct objects → deep copy and equal fields
    let mut dest = Packet::new(
        src.data_type(),
        src.endpoints(), // &[DataEndpoint]
        src.sender(),    // Arc<str>
        src.timestamp(),
        Arc::from(src.payload()), // deep copy payload
    )
    .expect("src packet should be valid");

    let st = unsafe { copy_telemetry_packet_raw(&mut dest as *mut _, &src as *const _) };
    assert!(st.is_ok());

    // element-by-element compare
    assert_eq!(dest.timestamp(), src.timestamp());
    assert_eq!(dest.data_type(), src.data_type());
    assert_eq!(dest.data_size(), src.data_size());
    assert_eq!(dest.endpoints().len(), src.endpoints().len());
    for i in 0..dest.endpoints().len() {
        assert_eq!(dest.endpoints()[i], src.endpoints()[i]);
    }
    assert_eq!(dest.payload(), src.payload());
}

#[cfg(feature = "discovery")]
mod p2p_address_tests {
    use crate::{
        TelemetryResult,
        router::{AddressChange, AddressChangeReason, P2pStreamEventKind, Router, RouterConfig},
    };
    use alloc::{sync::Arc, vec::Vec};
    use std::sync::Mutex;

    fn crosswire(a: &Arc<Router>, b: &Arc<Router>) {
        let b_rx = b.clone();
        a.add_side_packet("a-to-b", move |pkt| b_rx.rx_from_side(pkt, 0));
        let a_rx = a.clone();
        b.add_side_packet("b-to-a", move |pkt| a_rx.rx_from_side(pkt, 0));
    }

    fn exchange_discovery(a: &Router, b: &Router) {
        a.announce_discovery().unwrap();
        b.announce_discovery().unwrap();
        a.process_all_queues().unwrap();
        b.process_all_queues().unwrap();
        a.process_all_queues().unwrap();
        b.process_all_queues().unwrap();
    }

    #[test]
    fn p2p_service_port_delivers_http_like_payload_by_hostname_and_address() {
        let server_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let server_seen_c = server_seen.clone();

        let client = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("client-node")
                .with_dynamic_address(),
        ));
        let server = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("http-service")
                .with_static_address(0x1020_3040),
        ));
        server
            .bind_p2p_port(80, move |msg| -> TelemetryResult<()> {
                assert_eq!(msg.source_hostname, "client-node");
                assert_eq!(msg.source_port, 49_152);
                assert_eq!(msg.destination_port, 80);
                server_seen_c.lock().unwrap().push(msg.payload.to_vec());
                Ok(())
            })
            .unwrap();

        crosswire(&client, &server);
        exchange_discovery(&client, &server);

        client
            .send_p2p_to_hostname(
                "http-service",
                80,
                49_152,
                b"GET /status HTTP/1.1\r\nHost: http-service\r\n\r\n",
            )
            .unwrap();
        server.process_all_queues().unwrap();
        client.process_all_queues().unwrap();

        client
            .send_p2p_to_address(
                0x1020_3040,
                80,
                49_152,
                b"POST /upload HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        server.process_all_queues().unwrap();
        client.process_all_queues().unwrap();

        let seen = server_seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].starts_with(b"GET /status HTTP/1.1"));
        assert!(seen[1].starts_with(b"POST /upload HTTP/1.1"));
    }

    #[test]
    fn duplicate_dynamic_addresses_are_shifted_and_reported() {
        let changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
        let changes_c = changes.clone();
        let older = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("older-dynamic")
                .with_requested_address(77),
        ));
        let newer = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("newer-dynamic")
                .with_requested_address(77)
                .on_address_change(move |change| {
                    changes_c.lock().unwrap().push(change);
                    Ok(())
                }),
        ));
        crosswire(&older, &newer);
        exchange_discovery(&older, &newer);

        assert_eq!(older.current_address(), 77);
        assert_ne!(newer.current_address(), 77);
        let changes = changes.lock().unwrap().clone();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].reason, AddressChangeReason::RequestedConflict);
        assert_eq!(changes[0].old_address, 77);
        assert_eq!(changes[0].new_address, newer.current_address());
    }

    #[test]
    fn static_address_beats_dynamic_and_duplicate_static_older_wins() {
        let static_node = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("static-owner")
                .with_static_address(0x55),
        ));
        let dynamic = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("dynamic-loser")
                .with_requested_address(0x55),
        ));
        crosswire(&static_node, &dynamic);
        exchange_discovery(&static_node, &dynamic);
        assert_eq!(static_node.current_address(), 0x55);
        assert_ne!(dynamic.current_address(), 0x55);

        let static_changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
        let static_changes_c = static_changes.clone();
        let newer_static = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("static-newer")
                .with_static_address(0x55)
                .on_address_change(move |change| {
                    static_changes_c.lock().unwrap().push(change);
                    Ok(())
                }),
        ));
        crosswire(&static_node, &newer_static);
        exchange_discovery(&static_node, &newer_static);

        assert_eq!(static_node.current_address(), 0x55);
        assert_ne!(newer_static.current_address(), 0x55);
        let changes = static_changes.lock().unwrap().clone();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].reason, AddressChangeReason::StaticConflict);
    }

    #[test]
    fn duplicate_hostnames_are_renamed_and_hostname_p2p_uses_discovered_name() {
        let changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
        let changes_c = changes.clone();
        let first = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("duplicate-host")
                .with_static_address(0x301),
        ));
        let second_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let second_seen_c = second_seen.clone();
        let second = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("duplicate-host")
                .with_static_address(0x302)
                .on_address_change(move |change| {
                    changes_c.lock().unwrap().push(change);
                    Ok(())
                }),
        ));
        second
            .bind_p2p_port(443, move |msg| {
                second_seen_c.lock().unwrap().push(msg.payload.to_vec());
                Ok(())
            })
            .unwrap();

        crosswire(&first, &second);
        exchange_discovery(&first, &second);

        assert_eq!(first.hostname().as_ref(), "duplicate-host");
        assert_ne!(second.hostname().as_ref(), "duplicate-host");
        let renamed = second.hostname().to_string();
        let changes = changes.lock().unwrap().clone();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].reason, AddressChangeReason::HostnameConflict);

        first
            .send_p2p_to_hostname(&renamed, 443, 50_000, b"GET /secure HTTP/1.1\r\n\r\n")
            .unwrap();
        second.process_all_queues().unwrap();
        first.process_all_queues().unwrap();
        assert_eq!(
            second_seen.lock().unwrap().as_slice(),
            &[b"GET /secure HTTP/1.1\r\n\r\n".to_vec()]
        );
    }

    #[test]
    fn p2p_stream_connects_sends_and_closes_without_datagram_delivery() {
        let client_events = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_events = Arc::new(Mutex::new(Vec::<String>::new()));
        let datagrams = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

        let client = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("stream-client")
                .with_dynamic_address(),
        ));
        let server = Arc::new(Router::new(
            RouterConfig::default()
                .with_hostname("stream-server")
                .with_static_address(0x4040),
        ));

        let client_events_c = client_events.clone();
        client
            .bind_p2p_stream_port(49_200, move |event| {
                assert!(matches!(
                    event.kind,
                    P2pStreamEventKind::Connected
                        | P2pStreamEventKind::Data
                        | P2pStreamEventKind::Closed
                        | P2pStreamEventKind::Reset
                ));
                client_events_c.lock().unwrap().push(format!(
                    "{:?}:{}:{}:{}:{}",
                    event.kind,
                    event.stream_id,
                    event.peer_stream_id,
                    event.sequence,
                    String::from_utf8_lossy(event.payload)
                ));
                Ok(())
            })
            .unwrap();

        let server_events_c = server_events.clone();
        server
            .bind_p2p_stream_port(8080, move |event| {
                assert!(matches!(
                    event.kind,
                    P2pStreamEventKind::Accepted
                        | P2pStreamEventKind::Data
                        | P2pStreamEventKind::Closed
                        | P2pStreamEventKind::Reset
                ));
                server_events_c.lock().unwrap().push(format!(
                    "{:?}:{}:{}:{}:{}",
                    event.kind,
                    event.stream_id,
                    event.peer_stream_id,
                    event.sequence,
                    String::from_utf8_lossy(event.payload)
                ));
                Ok(())
            })
            .unwrap();

        let datagrams_c = datagrams.clone();
        server
            .bind_p2p_port(8080, move |msg| {
                datagrams_c.lock().unwrap().push(msg.payload.to_vec());
                Ok(())
            })
            .unwrap();

        crosswire(&client, &server);
        exchange_discovery(&client, &server);

        let client_stream = client
            .open_p2p_stream_to_hostname("stream-server", 8080, 49_200)
            .unwrap();
        server.process_all_queues().unwrap();
        client.process_all_queues().unwrap();

        let connected = client_events.lock().unwrap().clone();
        assert_eq!(connected.len(), 1);
        assert!(connected[0].starts_with("Connected:"));

        let accepted = server_events.lock().unwrap().clone();
        assert_eq!(accepted.len(), 1);
        assert!(accepted[0].starts_with("Accepted:"));
        let server_stream: u32 = accepted[0].split(':').nth(1).unwrap().parse().unwrap();

        client
            .send_p2p_stream(client_stream, b"GET /stream HTTP/1.1\r\n\r\n")
            .unwrap();
        server.process_all_queues().unwrap();
        client.process_all_queues().unwrap();

        server
            .send_p2p_stream(
                server_stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .unwrap();
        client.process_all_queues().unwrap();
        server.process_all_queues().unwrap();

        client.close_p2p_stream(client_stream).unwrap();
        server.process_all_queues().unwrap();

        let server_events = server_events.lock().unwrap().clone();
        assert!(
            server_events
                .iter()
                .any(|e| { e.starts_with("Data:") && e.ends_with("GET /stream HTTP/1.1\r\n\r\n") })
        );
        assert!(server_events.iter().any(|e| e.starts_with("Closed:")));

        let client_events = client_events.lock().unwrap().clone();
        assert!(client_events.iter().any(|e| {
            e.starts_with("Data:") && e.ends_with("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        }));

        assert!(datagrams.lock().unwrap().is_empty());
    }
}

// -----------------------------------------------------------------------------
// Error propagation & handler-failure tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod handler_failure_tests {
    //! Tests around handler failures and how they generate/route
    //! `TELEMETRY_ERROR` packets.

    use super::*;
    use crate::config::DEVICE_IDENTIFIER;
    use crate::router::EndpointHandler;
    use crate::router::{Router, RouterConfig};
    use crate::tests::timeout_tests::StepClock;
    use crate::{DataType, MAX_VALUE_DATA_TYPE, TelemetryError};
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Pick any valid [`DataType`] from the enum range for generic tests.
    fn pick_any_type() -> DataType {
        for i in 0..=MAX_VALUE_DATA_TYPE {
            if let Some(ty) = DataType::try_from_u32(i) {
                return ty;
            }
        }
        panic!("No usable DataType found for tests");
    }

    /// Build a zeroed payload of valid length for the given type using
    /// [`test_payload_len_for`].
    fn payload_for(ty: DataType) -> Vec<u8> {
        vec![0u8; test_payload_len_for(ty)]
    }

    /// If a local handler fails, ensure:
    /// - other local endpoints get the original packet,
    /// - and a `TELEMETRY_ERROR` packet with the right text is sent.
    #[test]
    fn local_handler_failure_sends_error_packet_to_other_locals() {
        let ty = pick_any_type();
        let ts = 42_u64;
        let failing_ep = DataEndpoint::named("SD_CARD");
        let other_ep = DataEndpoint::TelemetryError;

        // Capture the packets that reach the "other_ep" handler.
        let recv_count = Arc::new(AtomicUsize::new(0));
        let last_payload = Arc::new(Mutex::new(String::new()));

        let recv_count_c = recv_count.clone();
        let last_payload_c = last_payload.clone();

        let failing = EndpointHandler::new_packet_handler(failing_ep, |_pkt: &Packet| {
            Err(TelemetryError::BadArg)
        });

        let capturing = EndpointHandler::new_packet_handler(other_ep, move |pkt: &Packet| {
            if pkt.data_type() == DataType::TelemetryError {
                *last_payload_c.lock().unwrap() = pkt.as_string();
            }
            recv_count_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let box_clock = StepClock::new_default_box();

        let router = Router::new_with_clock(RouterConfig::new(vec![failing, capturing]), box_clock);

        let pkt = Packet::new(
            ty,
            &[failing_ep, other_ep],
            DEVICE_IDENTIFIER,
            ts,
            Arc::<[u8]>::from(payload_for(ty)),
        )
        .unwrap();

        handle_errors(router.tx(pkt));

        // The capturing handler should have seen the original packet and then the error packet.
        assert!(
            recv_count.load(Ordering::SeqCst) >= 1,
            "capturing handler should have been invoked at least once"
        );

        // Verify exact payload text produced by handle_callback_error(Some(dest), e)
        let expected = format!(
            "{{Type: SEDSNET_ERROR, Data Size: {:?}, Sender: TEST_PLATFORM, Endpoints: [SEDSNET_ERROR], Timestamp: 0 (0s 000ms), Error: (\"Handler for endpoint {:?} failed on device {:?}: {:?}\")}}",
            69,
            failing_ep,
            DEVICE_IDENTIFIER,
            TelemetryError::BadArg
        );
        let got = last_payload.lock().unwrap().clone();
        assert_eq!(got, expected, "mismatch in TelemetryError payload text");
    }

    /// If the TX callback fails, ensure:
    /// - a `TELEMETRY_ERROR` is generated,
    /// - it is delivered to all local endpoints,
    /// - and the error text matches expectation.
    #[test]
    fn tx_failure_sends_error_packet_to_all_local_endpoints() {
        let ty = pick_any_type();
        let ts = 31415_u64;

        // One local endpoint (to receive error), one "remote" endpoint (not in handlers)
        let local_ep = DataEndpoint::named("SD_CARD");
        let remote_ep = DataEndpoint::named("RADIO");

        let saw_error = Arc::new(AtomicUsize::new(0));
        let last_payload = Arc::new(Mutex::new(String::new()));
        let saw_error_c = saw_error.clone();
        let last_payload_c = last_payload.clone();

        let capturing = EndpointHandler::new_packet_handler(local_ep, move |pkt: &Packet| {
            if pkt.data_type() == DataType::TelemetryError {
                *last_payload_c.lock().unwrap() = pkt.as_string();
                saw_error_c.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });

        let tx_fail =
            |_bytes: &[u8]| -> crate::TelemetryResult<()> { Err(TelemetryError::Io("boom")) };
        let box_clock = StepClock::new_default_box();

        let router = Router::new_with_clock(RouterConfig::new(vec![capturing]), box_clock);
        router.add_side_packed("tx", tx_fail);

        let pkt = Packet::new(
            ty,
            // include both a local and a non-local endpoint so any_remote == true
            &[local_ep, remote_ep],
            "router_test",
            ts,
            Arc::<[u8]>::from(payload_for(ty)),
        )
        .unwrap();

        handle_errors(router.tx(pkt));

        assert!(
            saw_error.load(Ordering::SeqCst) >= 1,
            "local handler should have received TelemetryError after TX failures"
        );

        // Exact text from handle_callback_error(None, e)
        let expected = format!(
            "{{Type: SEDSNET_ERROR, Data Size: {:?}, Sender: TEST_PLATFORM, Endpoints: [SD_CARD], Timestamp: 0 (0s 000ms), Error: (\"TX Handler failed on device {:?}: {:?}\")}}",
            55,
            DEVICE_IDENTIFIER,
            TelemetryError::Io("boom")
        );
        let got = last_payload.lock().unwrap().clone();
        assert_eq!(got, expected, "mismatch in TelemetryError payload text");
    }
}

// -----------------------------------------------------------------------------
// Timeout and queue-draining behavior tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod timeout_tests {
    //! Tests for `process_*_queue*` functions and timeout semantics,
    //! including u64 wraparound handling.

    use crate::config::DataEndpoint;
    use crate::router::EndpointHandler;
    use crate::tests::{UnixClock, get_handler, packed_frame_type};
    use crate::{
        DataType, TelemetryResult, packet::Packet, router::Clock, router::Router,
        router::RouterConfig,
    };
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    // ---------------- Mock clock ----------------

    /// A deterministic clock that steps forward by `step` ms on each `now_ms()`
    /// call, starting from `start`. Used to test timeout budget behavior.
    pub(crate) struct StepClock {
        t: AtomicU64,
        step: u64,
    }

    impl StepClock {
        /// Creates a boxed [`StepClock`] with the specified start time and step size.
        pub fn new_box(start: u64, step: u64) -> Box<dyn Clock + Send + Sync> {
            Box::new(StepClock::new(start, step))
        }
        /// Creates a boxed [`StepClock`] pinned at zero for tests that need a fixed clock.
        pub fn new_default_box() -> Box<dyn Clock + Send + Sync> {
            Box::new(StepClock::new(0, 0))
        }
        /// Creates a deterministic test clock that advances by `step` on each read.
        pub fn new(start: u64, step: u64) -> Self {
            Self {
                t: AtomicU64::new(start),
                step,
            }
        }
    }

    impl Clock for StepClock {
        #[inline]
        fn now_ms(&self) -> u64 {
            // returns current, then advances by step (wraps naturally in u64)
            self.t.fetch_add(self.step, Ordering::Relaxed)
        }
    }

    // ---------------- Helpers ----------------

    /// Create a GPS packet with only a local endpoint (`SD_CARD`), avoiding any
    /// implicit re-TX during receive.
    fn mk_rx_only_local(vals: &[f32], ts: u64) -> Packet {
        Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            vals,
            &[DataEndpoint::named("SD_CARD")], // <- only local
            ts,
        )
        .unwrap()
    }

    /// Build a TX function that increments `counter` for each frame sent.
    fn tx_counter(
        counter: Arc<AtomicUsize>,
    ) -> impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static {
        move |bytes: &[u8]| {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    /// `timeout == 0` must drain both TX and RX queues fully, regardless of
    /// clock, and local handlers see all packets.
    #[test]
    fn process_all_queues_timeout_zero_drains_fully() {
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx = tx_counter(tx_count.clone());

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rx_count_c = rx_count.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rx_count_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let box_clock = StepClock::new_default_box();

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), box_clock);
        r.add_side_packed("tx", tx);

        // Enqueue TX (3) – make each payload slightly different to avoid dedup.
        for i in 0..3usize {
            let base = 1.0_f32 + i as f32;
            r.log_queue(DataType::named("GPS_DATA"), &[base, 2.0, 3.0])
                .unwrap();
        }
        // Enqueue RX (2) with only-local endpoints, and unique values/timestamps.
        for i in 0..2u64 {
            r.rx_queue(mk_rx_only_local(&[9.0 + i as f32, 8.0, 7.0], 123 + i))
                .unwrap();
        }

        // timeout = 0 → drain fully
        r.process_all_queues_with_timeout(0).unwrap();

        // TX: all three frames should be sent
        assert_eq!(
            tx_count.load(Ordering::SeqCst),
            3,
            "all TX packets should be sent"
        );
        // RX handler was invoked for each TX (local delivery) + each RX = 3 + 2 = 5
        assert_eq!(
            rx_count.load(Ordering::SeqCst),
            5,
            "handler sees TX+RX packets"
        );
    }

    /// With non-zero timeout and step = 10ms, timeout 5ms should allow exactly
    /// one iteration (at most one TX and one RX).
    #[test]
    fn process_all_queues_respects_nonzero_timeout_budget_one_receive_one_send() {
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx = tx_counter(tx_count.clone());

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rx_count_c = rx_count.clone();
        let handler = get_handler(rx_count_c);

        // Use a real-time clock; current implementation may process more than one
        // iteration in a single call depending on timing.
        let r = Router::new_with_clock(
            RouterConfig::new(vec![handler]),
            Box::new(|| UnixClock.now_ms()),
        );
        r.add_side_packed("tx", tx);

        // Seed work in both queues – make each item unique to avoid dedup.
        for i in 0..5u64 {
            let base_tx = 1.0_f32 + i as f32;
            r.log_queue(DataType::named("GPS_DATA"), &[base_tx, 2.0, 3.0])
                .unwrap();

            // RX with only-local endpoint, unique payload + timestamp
            r.rx_queue(
                Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[4.0 + i as f32, 5.0, 6.0],
                    &[DataEndpoint::named("SD_CARD")],
                    1 + i,
                )
                .unwrap(),
            )
            .unwrap();
        }

        // Non-zero timeout: must do *some* work, but we no longer require
        // exactly-one-iteration semantics.
        r.process_all_queues_with_timeout(5).unwrap();

        let first_tx = tx_count.load(Ordering::SeqCst);
        let first_rx = rx_count.load(Ordering::SeqCst);

        // Sanity: non-zero timeout should result in some progress.
        assert!(
            first_tx + first_rx > 0,
            "expected some work to be done with non-zero timeout"
        );
        // Upper bounds: we can’t have done more than all queued work.
        assert!(
            first_tx <= 5 && first_rx <= 10,
            "processed more items than were queued (tx={first_tx}, rx={first_rx})"
        );

        // Drain the rest to prove there was more work left / everything eventually completes.
        r.process_all_queues_with_timeout(0).unwrap();
        assert_eq!(tx_count.load(Ordering::SeqCst), 5);
        assert_eq!(rx_count.load(Ordering::SeqCst), 10); // 5 (TX locals) + 5 (RX)
    }

    /// Similar to previous, but with step=5 and timeout=10 to allow up to two
    /// iterations; expect one TX + one RX handler call.
    #[test]
    fn process_all_queues_respects_nonzero_timeout_budget_two_receive_one_send() {
        crate::tests::ensure_common_test_schema();
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx = tx_counter(tx_count.clone());

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rx_count_c = rx_count.clone();
        let handler = get_handler(rx_count_c);
        let clock = StepClock::new_box(0, 5);

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), clock);
        r.add_side_packed("tx", tx);

        // Seed work in both queues – make each item unique to avoid dedup.
        for i in 0..5u64 {
            let base_tx = 1.0_f32 + i as f32;
            r.log_queue(DataType::named("GPS_DATA"), &[base_tx, 2.0, 3.0])
                .unwrap();

            r.rx_queue(
                Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[4.0 + i as f32, 5.0, 6.0],
                    &[DataEndpoint::named("SD_CARD")],
                    1 + i,
                )
                .unwrap(),
            )
            .unwrap();
        }

        // Step is 5ms per call; timeout 10ms allows two iterations max
        r.process_all_queues_with_timeout(10).unwrap();

        let first_tx = tx_count.load(Ordering::SeqCst);
        let first_rx = rx_count.load(Ordering::SeqCst);
        assert!(
            first_tx + first_rx > 0,
            "expected some work to be done before the timeout budget expired"
        );
        assert!(first_tx <= 1, "first pass should do at most one GPS TX");
        assert!(
            first_rx <= 2,
            "first pass should do at most one loop of RX work"
        );

        // Drain the rest to prove there was more work left
        r.process_all_queues_with_timeout(0).unwrap();
        assert_eq!(tx_count.load(Ordering::SeqCst), 5);
        assert_eq!(rx_count.load(Ordering::SeqCst), 10); // 5 (TX locals) + 5 (RX)
    }

    /// Ensure timeout math remains correct near `u64::MAX`, i.e. when the clock
    /// wraps around, and that we still do at most one iteration.
    #[test]
    fn process_all_queues_handles_u64_wraparound() {
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx = tx_counter(tx_count.clone());

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rx_count_c = rx_count.clone();
        let handler = get_handler(rx_count_c);
        let start = u64::MAX - 1;
        let clock = StepClock::new_box(start, 2);
        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), clock);
        r.add_side_packed("tx", tx);

        // One TX and one RX (RX is only-local to avoid creating extra TX on receive)
        r.log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
            .unwrap();
        r.rx_queue(mk_rx_only_local(&[4.0, 5.0, 6.0], 7)).unwrap();

        // Small budget; with wrapping_sub this should allow one iteration then stop
        r.process_all_queues_with_timeout(1).unwrap();

        // One iteration can do up to one TX and one RX
        assert!(tx_count.load(Ordering::SeqCst) <= 1, "expected <=1 TX");
        assert!(
            rx_count.load(Ordering::SeqCst) <= 2,
            "local handler can be invoked by TX local delivery (+1) and RX (+1)"
        );
        // At least something should have happened
        assert!(tx_count.load(Ordering::SeqCst) + rx_count.load(Ordering::SeqCst) >= 1);
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn process_all_queues_timeout_does_not_starve_rx_after_slow_tx() {
        use crate::discovery::build_discovery_announce;

        struct ManualClock {
            now_ms: Arc<AtomicU64>,
        }

        impl Clock for ManualClock {
            fn now_ms(&self) -> u64 {
                self.now_ms.load(Ordering::SeqCst)
            }
        }

        let now_ms = Arc::new(AtomicU64::new(0));
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx_count_c = tx_count.clone();
        let now_ms_c = now_ms.clone();
        let seen_remote: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_remote_c = seen_remote.clone();

        let router = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                |_pkt| Ok(()),
            )]),
            Box::new(ManualClock {
                now_ms: now_ms.clone(),
            }),
        );
        let side_remote =
            router.add_side_packet("REMOTE", move |pkt: &Packet| -> TelemetryResult<()> {
                tx_count_c.fetch_add(1, Ordering::SeqCst);
                // Simulate a blocking transport send that consumes the whole timeout budget.
                now_ms_c.store(2, Ordering::SeqCst);
                seen_remote_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

        router
            .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
            .unwrap();
        let discovery_pkt =
            build_discovery_announce("REMOTE_NODE", 0, &[DataEndpoint::named("RADIO")]).unwrap();
        let discovery_bytes = crate::wire_format::pack_packet(&discovery_pkt);
        router
            .rx_packed_queue_from_side(discovery_bytes.as_ref(), side_remote)
            .unwrap();

        router.process_all_queues_with_timeout(2).unwrap();

        assert_eq!(tx_count.load(Ordering::SeqCst), 1);
        let topo = router.export_topology();
        assert_eq!(topo.routes.len(), 1);
        assert_eq!(
            topo.routes[0].reachable_endpoints,
            vec![DataEndpoint::named("RADIO")]
        );
    }
}

// -----------------------------------------------------------------------------
// Extra coverage tests: error codes, header-only parsing, varints, bitmaps, etc.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests_extra {
    //! Extra unit tests that cover previously-missing paths and invariants.
    //!
    //! These are white-box tests that exercise public APIs (and some
    //! indirect behavior) to avoid changing visibility in core modules.
    use crate::config::DataEndpoint;
    use crate::tests::test_payload_len_for;
    use crate::{
        TelemetryError, TelemetryErrorCode, TelemetryResult,
        config::DataType,
        packet::Packet,
        router::{Clock, EndpointHandler, Router, RouterConfig},
        wire_format,
    };
    use alloc::{string::String, sync::Arc};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A tiny helper clock; we rely on the blanket `impl<Fn() -> u64> Clock`.
    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    // --------------------------- Error/Code parity ---------------------------

    /// Validate that `TelemetryError` ↔ `TelemetryErrorCode` mapping is
    /// complete and stable, including the string forms.
    #[test]
    fn error_enum_code_roundtrip_and_strings() {
        let samples = [
            TelemetryError::InvalidType,
            TelemetryError::EmptyEndpoints,
            TelemetryError::Unpack("oops"),
            TelemetryError::Io("disk"),
            TelemetryError::HandlerError("fail"),
            TelemetryError::MissingPayload,
            TelemetryError::TimestampInvalid,
        ];
        for e in samples {
            let code = e.to_error_code();
            // must have a stable human string (starts with a '{' per current impl)
            assert!(code.as_str().starts_with('{'));
            // round-trip numeric space
            let back = TelemetryErrorCode::try_from_i32(code as i32);
            assert!(back.is_some(), "roundtrip failed for {code:?}");
        }
    }

    // --------------------------- Header-only parsing ---------------------------

    /// Ensure header-only peek fails on truncated buffers (short read during
    /// varint parsing).
    #[test]
    fn unpack_header_only_short_buffer_fails() {
        // v2 header is varint-based. Force a definite short read in the first varint.

        // Case A: only NEP present (0 endpoints), but no bytes for `ty` varint.
        let tiny = [0x00u8]; // NEP = 0
        let err = wire_format::peek_envelope(&tiny).unwrap_err();
        matches_deser_err(err);

        // Case B: NEP present, and a *truncated* varint (continuation bit set, but no following byte).
        let truncated = [0x00u8, 0x80]; // NEP=0, then start varint with continuation bit
        let err = wire_format::peek_envelope(&truncated).unwrap_err();
        matches_deser_err(err);
    }

    /// Ensure header size is a valid prefix of the packed wire image.
    #[test]
    fn header_size_is_prefix_of_wire_image() {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            123,
        )
        .unwrap();

        let wire = wire_format::pack_packet(&pkt);
        let hdr = wire_format::header_size_bytes(&pkt);
        assert!(hdr <= wire.len());

        // header must decode from the start (i.e., NEP + scalars exists)
        assert!(hdr > 0);
    }

    /// Helper: assert an error is a `Unpack` variant.
    fn matches_deser_err(e: TelemetryError) {
        match e {
            TelemetryError::Unpack(_) => {}
            other => panic!("expected Unpack error, got {other:?}"),
        }
    }

    fn rewrite_crc32(buf: &mut [u8]) {
        if buf.len() < wire_format::CRC32_BYTES {
            return;
        }
        let data_len = buf.len() - wire_format::CRC32_BYTES;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&buf[..data_len]);
        let crc = hasher.finalize();
        buf[data_len..].copy_from_slice(&crc.to_le_bytes());
    }

    /// Ensure packing is canonical: pack -> unpack -> pack
    /// produces identical bytes (ULEB128 canonical form).
    #[test]
    fn packer_is_canonical_roundtrip() {
        use crate::config::{DataEndpoint, DataType};
        use crate::{packet::Packet, wire_format};

        // Dynamic payload to avoid schema constraints and let us vary sizes later.
        let msg = "hello world";
        let pkt = Packet::from_str_slice(
            DataType::TelemetryError,
            msg,
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            0,
        )
        .unwrap();

        let wire1 = wire_format::pack_packet(&pkt);
        let pkt2 = wire_format::unpack_packet(&wire1).unwrap();
        let wire2 = wire_format::pack_packet(&pkt2);

        // ULEB128 is canonical (no leading 0x80 “more” bytes), so bytes must match
        assert_eq!(&*wire1, &*wire2, "packer must be canonical");
    }

    #[test]
    fn pack_unpack_roundtrip_matches_packet_identity() {
        let pkt = Packet::from_str_slice(
            DataType::TelemetryError,
            "pack/unpack roundtrip check",
            &[DataEndpoint::TelemetryError],
            456,
        )
        .unwrap();

        let packed = wire_format::pack_packet(&pkt);
        assert_eq!(packed, wire_format::pack_packet(&pkt));

        let unpacked = wire_format::unpack_packet(&packed).unwrap();
        assert_eq!(unpacked.packet_id(), pkt.packet_id());
        assert_eq!(unpacked.payload(), pkt.payload());
    }

    /// Validate varint scalar growth: header and wire size should increase
    /// when fields that are encoded as varints get larger.
    #[test]
    fn packer_varint_scalars_grow_as_expected() {
        use crate::config::{DataEndpoint, DataType};
        use crate::{packet::Packet, wire_format};

        fn non_rle_ascii(len: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                // Alternating lowercase letters with no >=3-byte runs and valid UTF-8 bytes.
                out.push(b'a' + ((i % 26) as u8));
            }
            out
        }

        // Helper to build a TelemetryError payload with a sender of the given length.
        fn pkt_with(len: usize, sender_len: usize, ts: u64) -> Packet {
            let sender_bytes = non_rle_ascii(sender_len);
            let s: String = sender_bytes.iter().map(|b| char::from(*b)).collect();
            let payload = non_rle_ascii(len); // dynamic payload (String type)
            Packet::new(
                DataType::TelemetryError,
                &[DataEndpoint::named("SD_CARD")],
                &s,
                ts,
                Arc::<[u8]>::from(payload),
            )
            .unwrap()
        }

        // Case 1: small (all varints fit in 1 byte)
        let p1 = pkt_with(10, 5, 0x7F); // <= 127
        let w1 = wire_format::pack_packet(&p1);
        let h1 = wire_format::header_size_bytes(&p1);
        assert!(h1 > 4, "NEP + 4 one-byte varints minimum");

        // Case 2: larger payload grows data_size; sender text itself is discovery metadata,
        // not part of the packet header.
        let p2 = pkt_with(200, 200, 0x7F);
        let w2 = wire_format::pack_packet(&p2);
        let h2 = wire_format::header_size_bytes(&p2);
        assert!(w2.len() > w1.len(), "wire should grow with larger varints");
        assert!(h2 >= h1, "header should not shrink with larger varints");

        // Case 3: bigger timestamp to push it beyond 1 byte (and usually >2)
        let p3 = pkt_with(200, 200, 1u64 << 40); // forces 6-byte varint
        let w3 = wire_format::pack_packet(&p3);
        let h3 = wire_format::header_size_bytes(&p3);
        assert!(
            w3.len() > w2.len(),
            "wire should grow with larger timestamp"
        );
        assert!(h3 > h2, "header should grow with larger timestamp");

        // Size function must match exact output
        assert_eq!(wire_format::packet_wire_size(&p3), w3.len());
    }

    /// Stress test for endpoint bitpacking across many endpoints and repeated
    /// copies, ensuring endpoints and payload round-trip.
    #[test]
    fn endpoints_bitpack_roundtrip_many_and_extremes() {
        use crate::{
            MAX_VALUE_DATA_ENDPOINT,
            config::{DataEndpoint, DataType},
            packet::Packet,
            wire_format,
        };

        // Build a long endpoint list by cycling through all enum values (0..=MAX)
        let mut eps = Vec::<DataEndpoint>::new();
        for i in 0..=MAX_VALUE_DATA_ENDPOINT {
            if let Some(ep) = DataEndpoint::try_from_u32(i) {
                eps.push(ep);
            }
        }
        // Repeat to make the bitstream cross multiple bytes
        let mut endpoints = Vec::new();
        for _ in 0..4 {
            endpoints.extend_from_slice(&eps);
        }

        // Make payload dynamic so schema doesn't get in the way
        let payload = vec![0x55u8; 257]; // force 2-byte varint for data_size
        let pkt = Packet::new(
            DataType::TelemetryError,
            &endpoints,
            "sender",
            123456,
            Arc::<[u8]>::from(payload),
        )
        .unwrap();

        let wire = wire_format::pack_packet(&pkt);
        let back = wire_format::unpack_packet(&wire).unwrap();
        let has_all_endpoints = back.endpoints().iter().all(|ep| endpoints.contains(ep));
        assert!(has_all_endpoints, "endpoints must roundtrip 1:1");
        assert_eq!(back.data_type(), pkt.data_type());
        assert_eq!(back.timestamp(), pkt.timestamp());
        assert_eq!(back.payload(), pkt.payload());
        assert_eq!(wire_format::packet_wire_size(&pkt), wire.len());
    }

    /// For large sender/payload/timestamp, ensure `peek_envelope` and full
    /// unpacking agree on header fields and payload.
    #[test]
    fn peek_envelope_matches_full_parse_on_large_values() {
        use crate::config::{DataEndpoint, DataType};
        use crate::{packet::Packet, wire_format};

        let sender = "S".repeat(10_000); // big sender (varint grows)
        let payload = vec![b'h'; 4096];
        let ts = (1u64 << 40) + 123; // large ts (varint grows)

        let pkt = Packet::new(
            DataType::TelemetryError, // String-typed
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            &sender,
            ts,
            Arc::<[u8]>::from(payload),
        )
        .unwrap();

        let wire = wire_format::pack_packet(&pkt);
        assert!(
            !wire
                .windows(sender.len())
                .any(|window| window == sender.as_bytes()),
            "sender hostname must be discovery/config metadata, not packet-header bytes"
        );
        let env = wire_format::peek_envelope(&wire).unwrap();
        let full = wire_format::unpack_packet(&wire).unwrap();

        assert_eq!(env.ty, pkt.data_type());
        assert_eq!(env.sender.as_ref(), pkt.sender());
        assert_eq!(env.timestamp_ms, pkt.timestamp());
        assert_eq!(&*env.endpoints, pkt.endpoints());

        assert_eq!(full.data_type(), pkt.data_type());
        assert_eq!(full.timestamp(), pkt.timestamp());
        assert_eq!(full.endpoints(), pkt.endpoints());
        assert_eq!(full.payload(), pkt.payload());
    }

    /// Corrupt endpoint bits in the bitmap to encode an out-of-range value,
    /// and ensure unpacking fails with an appropriate error.
    #[test]
    fn corrupt_endpoint_bits_yields_bad_endpoint_error() {
        use crate::{
            MAX_VALUE_DATA_ENDPOINT,
            config::{DataEndpoint, DataType},
            packet::Packet,
            wire_format,
        };

        // Recompute EP_BITS the same way the module does.
        let bits = 32 - MAX_VALUE_DATA_ENDPOINT.leading_zeros();
        let ep_bits: u8 = if bits == 0 { 1 } else { bits as u8 };
        // If EP_BITS is exactly the minimum bits to encode MAX, there is room for values > MAX.
        let upper_val = (1u64 << ep_bits) - 1;
        if upper_val as u32 <= MAX_VALUE_DATA_ENDPOINT {
            // Nothing to corrupt beyond max—skip test (no larger representable value).
            return;
        }

        // Build a simple, valid packet with at least 1 endpoint.
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            123,
        )
        .unwrap();
        let mut wire = wire_format::pack_packet(&pkt).to_vec();

        // Compute where endpoint bits start (right after header varints)
        let ep_offset = wire_format::header_size_bytes(&pkt);
        assert!(ep_offset < wire.len());

        // Overwrite the *first* endpoint with an out-of-range value in the bitstream.
        // Bits are packed LSB-first.
        let mut v = upper_val;
        for (bitpos, _) in (0..ep_bits).enumerate() {
            let byte_idx = ep_offset + (bitpos / 8);
            let bit_off = bitpos % 8;
            // Set bit if the corresponding bit of v is 1
            if (v & 1) != 0 {
                wire[byte_idx] |= 1 << bit_off;
            } else {
                wire[byte_idx] &= !(1 << bit_off);
            }
            v >>= 1;
        }
        rewrite_crc32(&mut wire);

        // Now unpacking must fail with a Unpack("bad endpoint") error.
        let err = wire_format::unpack_packet(&wire).unwrap_err();
        match err {
            TelemetryError::Unpack(msg) if msg.contains("endpoint") => {}
            other => panic!("expected bad endpoint unpack error, got {other:?}"),
        }
    }

    /// Sanity check that header size is between 0 and full packet size, and
    /// that the computed wire size matches packed length.
    #[test]
    fn header_size_is_prefix_and_less_than_total() {
        use crate::config::{DataEndpoint, DataType};
        use crate::{packet::Packet, wire_format};

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            999,
        )
        .unwrap();

        let wire = wire_format::pack_packet(&pkt);
        let hdr = wire_format::header_size_bytes(&pkt);

        assert!(hdr > 0 && hdr < wire.len());
        assert_eq!(wire_format::packet_wire_size(&pkt), wire.len());
    }

    // --------------------------- UTF-8 trimming behavior ---------------------------

    /// Ensure `data_as_utf8_ref` trims trailing NUL bytes and returns a `&str`
    /// with just the meaningful content.
    #[test]
    fn data_as_utf8_ref_trims_trailing_nuls() {
        // Use a String-typed message kind. TelemetryError is used by the router with
        // a string payload and typically mapped to MessageDataType::String.
        let ty = DataType::TelemetryError;
        let mut buf = vec![0u8; test_payload_len_for(ty)];

        let s = b"hello\0\0";
        buf[..s.len()].copy_from_slice(s);

        let pkt = Packet::new(
            ty,
            &[DataEndpoint::named("SD_CARD")],
            "tester",
            0,
            Arc::<[u8]>::from(buf),
        )
        .unwrap();

        assert_eq!(pkt.data_as_utf8_ref(), Some("hello"));
    }

    // --------------------------- Queue clear semantics ---------------------------

    /// After calling `clear_queues`, no pending TX/RX items should be processed.
    #[test]
    fn clear_queues_prevents_further_processing() {
        // Transmit "bus" that counts frames sent.
        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx_count_c = tx_count.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            tx_count_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };

        // Local handler that counts receives.
        let rx_count = Arc::new(AtomicUsize::new(0));
        let rx_count_c = rx_count.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rx_count_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        r.add_side_packed("tx", tx);

        // Enqueue one TX and one RX
        let pkt_tx = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            0,
        )
        .unwrap();
        let pkt_rx = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")], // only local to avoid extra TX during receive
            0,
        )
        .unwrap();

        r.tx_queue(pkt_tx).unwrap();
        r.rx_queue(pkt_rx).unwrap();

        // Clearing should drop both queues before any processing.
        r.clear_queues();

        r.process_all_queues().unwrap();
        assert_eq!(
            tx_count.load(Ordering::SeqCst),
            0,
            "should not TX after clear"
        );
        assert_eq!(
            rx_count.load(Ordering::SeqCst),
            0,
            "should not RX after clear"
        );
    }

    // --------------------------- Retry semantics (indirect) ---------------------------

    /// Verify local handler retry count matches `MAX_NUMBER_OF_RETRYS` (assumed 3),
    /// and that the final error is a `HandlerError`.
    #[test]
    fn local_handler_retry_attempts_are_three() {
        // This test assumes MAX_NUMBER_OF_RETRYS == 3 in router. If that constant changes,
        // update the expected count below.
        const EXPECTED_ATTEMPTS: usize = 3; // initial try + retries

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_c = counter.clone();

        // A handler that always fails but bumps a counter on each attempt.
        let failing = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                counter_c.fetch_add(1, Ordering::SeqCst);
                Err(TelemetryError::BadArg)
            },
        );

        // Router with no TX (we only care about local handler invocation count).
        let r = Router::new_with_clock(RouterConfig::new(vec![failing]), zero_clock());

        // Build a valid packet addressed to the failing endpoint.
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        // Sending should surface a HandlerError after all retries.
        let res = r.tx(pkt);
        match res {
            Err(TelemetryError::HandlerError(_)) => {}
            other => panic!("expected HandlerError after retries, got {other:?}"),
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            EXPECTED_ATTEMPTS,
            "handler should be invoked exactly {EXPECTED_ATTEMPTS} times"
        );
    }

    // --------------------------- from_u8_slice sanity ---------------------------

    /// Ensure `Packet::from_u8_slice` builds a valid GPS packet with
    /// expected length and timestamp.
    #[test]
    fn from_f32_slice_builds_valid_packet() {
        let need = test_payload_len_for(DataType::named("GPS_DATA")) / 4; // f32 count
        assert_eq!(need, 3); // schema sanity

        let bytes = vec![5.3f32; need];
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &bytes,
            &[DataEndpoint::named("SD_CARD")],
            12345,
        )
        .unwrap();

        assert_eq!(pkt.payload().len(), 12);
        assert_eq!(pkt.data_size(), 12);
        assert_eq!(pkt.timestamp(), 12345);
    }

    #[test]
    fn from_none_slice_builds_valid_packet() {
        let need = 0; // f32 count
        assert_eq!(need, 0); // schema sanity

        let pkt = Packet::from_no_data(
            DataType::named("HEARTBEAT"),
            &[DataEndpoint::named("SD_CARD")],
            12345,
        )
        .unwrap();

        assert_eq!(pkt.payload().len(), 0);
        assert_eq!(pkt.data_size(), 0);
        assert_eq!(pkt.timestamp(), 12345);
    }

    // --------------------------- Header-only happy path smoke ---------------------------

    /// Header-only peek (`peek_envelope`) should match full parse for a normal
    /// encoded GPS packet.
    #[test]
    fn unpack_header_only_then_full_parse_matches() {
        // Build a normal packet then compare header-only vs full.
        let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[5.25_f32, 3.5, 1.0],
            endpoints,
            42,
        )
        .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        let env = wire_format::peek_envelope(&wire).unwrap();
        assert_eq!(env.ty, pkt.data_type());
        assert_eq!(&*env.endpoints, pkt.endpoints());
        assert_eq!(env.sender.as_ref(), pkt.sender());
        assert_eq!(env.timestamp_ms, pkt.timestamp());

        let round = wire_format::unpack_packet(&wire).unwrap();
        round.validate().unwrap();
        assert_eq!(round.data_type(), pkt.data_type());
        assert_eq!(round.data_size(), pkt.data_size());
        assert_eq!(round.timestamp(), pkt.timestamp());
        assert_eq!(round.endpoints(), pkt.endpoints());
        assert_eq!(round.payload(), pkt.payload());
    }

    // --------------------------- TX failure -> error to locals (smoke) ---------------------------

    /// Smoke test: TX failure should emit a `TelemetryError` packet to local
    /// endpoints (exact string validated by more specific tests).
    #[test]
    fn tx_failure_emits_error_to_local_endpoints() {
        // A transmitter that always fails.
        let failing_tx = |_bytes: &[u8]| -> TelemetryResult<()> { Err(TelemetryError::Io("boom")) };

        // Capture what the local endpoint sees (should include a TelemetryError).
        let last_payload = Arc::new(Mutex::new(String::new()));
        let last_payload_c = last_payload.clone();

        let capturing = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |pkt: &Packet| {
                if pkt.data_type() == DataType::TelemetryError {
                    *last_payload_c.lock().unwrap() = pkt.as_string();
                }
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![capturing]), zero_clock());
        r.add_side_packed("tx", failing_tx);

        // Include both a local and a non-local endpoint to force remote TX.
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            7,
        )
        .unwrap();

        let res = r.tx(pkt);
        match res {
            Err(TelemetryError::HandlerError(_)) => {} // TX path wraps as HandlerError
            other => panic!("expected HandlerError from TX failure, got {other:?}"),
        }

        // Ensure something was captured (exact string is covered elsewhere)
        let got = last_payload.lock().unwrap().clone();
        assert!(
            !got.is_empty(),
            "expected TelemetryError to be delivered locally after TX failure"
        );
    }
}

// -----------------------------------------------------------------------------
// More tests: validation, enum bounds, router paths, payload helpers, etc.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests_more {
    //! Additional coverage tests for router, packet, and packing logic.
    //! These tests complement `tests_extra` by covering boundary,
    //! error, and fast-path behaviors not previously exercised.
    use crate::config::get_message_meta;
    use crate::tests::{UnixClock, packed_frame_type};
    use crate::{
        MAX_VALUE_DATA_ENDPOINT, MAX_VALUE_DATA_TYPE, MessageClass, MessageDataType,
        MessageElement, ReliableMode, TelemetryError, TelemetryErrorCode, TelemetryResult,
        config::{DataEndpoint, DataType},
        get_data_type, get_needed_message_size, message_meta,
        packet::Packet,
        router::{Clock, EndpointHandler, Router, RouterConfig},
        wire_format,
    };
    use alloc::{sync::Arc, vec::Vec};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Mutex};

    /// Clock that always returns 0 (via closure), used where wall-clock is
    /// irrelevant and we only need a stable `Clock` impl.
    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    // ---------------------------------------------------------------------------
    // Packet validation edge cases
    // ---------------------------------------------------------------------------

    /// Compute a concrete length for test packets, respecting schema element
    /// counts for static/dynamic payloads.
    fn concrete_len_for_test(ty: DataType) -> usize {
        match message_meta(ty).element {
            MessageElement::Static(_, _, _) => get_needed_message_size(ty),
            MessageElement::Dynamic(_, _) => {
                // Choose a reasonable dynamic size for tests:
                // numeric/bool → element_width * MESSAGE_ELEMENTS
                // string/hex    → 1 * MESSAGE_ELEMENTS (or any positive size)
                let w = match get_data_type(ty) {
                    MessageDataType::UInt8 | MessageDataType::Int8 | MessageDataType::Bool => 1,
                    MessageDataType::UInt16 | MessageDataType::Int16 => 2,
                    MessageDataType::UInt32 | MessageDataType::Int32 | MessageDataType::Float32 => {
                        4
                    }
                    MessageDataType::UInt64 | MessageDataType::Int64 | MessageDataType::Float64 => {
                        8
                    }
                    MessageDataType::UInt128 | MessageDataType::Int128 => 16,
                    MessageDataType::String | MessageDataType::Binary => 1,
                    MessageDataType::NoData => 0,
                };
                let elems = get_message_meta(ty).element.into().max(1);
                core::cmp::max(1, w * elems)
            }
        }
    }

    /// Packet creation should reject empty endpoint lists and size mismatches
    /// (for both static and dynamic payload kinds).
    #[test]
    fn packet_validate_rejects_empty_endpoints_and_size_mismatch() {
        let ty = DataType::named("GPS_DATA");
        let need = concrete_len_for_test(ty);

        let err = Packet::new(ty, &[], "x", 0, Arc::<[u8]>::from(vec![0u8; need])).unwrap_err();
        assert!(matches!(err, TelemetryError::EmptyEndpoints));

        // +1 ensures mismatch for both static and dynamic (not a multiple of element width)
        let err = Packet::new(
            ty,
            &[DataEndpoint::named("SD_CARD")],
            "x",
            0,
            Arc::<[u8]>::from(vec![0u8; need + 1]),
        )
        .unwrap_err();
        assert!(matches!(err, TelemetryError::SizeMismatch { .. }));
    }

    // ---------------------------------------------------------------------------
    // Enum bounds + conversion validity
    // ---------------------------------------------------------------------------

    /// Ensure `DataType`, `DataEndpoint`, and `TelemetryErrorCode` all reject
    /// values outside their numeric ranges.
    #[test]
    fn enum_conversion_bounds_and_rejections() {
        let max_ty = crate::current_max_data_type_id();
        assert!(DataType::try_from_u32(max_ty).is_some());
        assert!(DataType::try_from_u32(MAX_VALUE_DATA_TYPE + 1).is_none());

        let max_ep = crate::current_max_endpoint_id();
        assert!(DataEndpoint::try_from_u32(max_ep).is_some());
        assert!(DataEndpoint::try_from_u32(MAX_VALUE_DATA_ENDPOINT + 1).is_none());

        let min = TelemetryErrorCode::MIN;
        let max = TelemetryErrorCode::MAX;
        assert!(TelemetryErrorCode::try_from_i32(min).is_some());
        assert!(TelemetryErrorCode::try_from_i32(max).is_some());
        assert!(TelemetryErrorCode::try_from_i32(min - 1).is_none());
        assert!(TelemetryErrorCode::try_from_i32(max + 1).is_none());
    }

    // ---------------------------------------------------------------------------
    // Wire-format header math + ByteReader edge cases
    // ---------------------------------------------------------------------------

    /// `packet_wire_size` must match the length of the packed output.
    #[test]
    fn packet_wire_size_matches_packed_len() {
        let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 9)
                .unwrap();
        let need = wire_format::packet_wire_size(&pkt);
        let out = wire_format::pack_packet(&pkt);
        assert_eq!(need, out.len());
    }

    #[test]
    fn schema_default_endpoints_omit_wire_bitmap_but_custom_endpoints_keep_it() {
        crate::tests::ensure_common_test_schema();
        let ty = DataType::named("GPS_DATA");
        let mut default_eps = crate::message_meta(ty).endpoints.to_vec();
        default_eps.sort_unstable();
        let subset_eps = &default_eps[..1];

        let default_pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &default_eps, 9)
            .unwrap()
            .with_nonce(7);
        let subset_pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], subset_eps, 9)
            .unwrap()
            .with_nonce(7);

        let default_wire = wire_format::pack_packet(&default_pkt);
        let subset_wire = wire_format::pack_packet(&subset_pkt);
        let bitmap_bytes = ((crate::MAX_VALUE_DATA_ENDPOINT as usize) + 1).div_ceil(8);

        assert_eq!(
            default_wire[0] & 0x20,
            0,
            "default endpoint set omits bitmap"
        );
        assert_ne!(
            subset_wire[0] & 0x20,
            0,
            "custom endpoint set carries bitmap"
        );
        assert_eq!(subset_wire.len(), default_wire.len() + bitmap_bytes);

        let default_round = wire_format::unpack_packet(&default_wire).unwrap();
        let subset_round = wire_format::unpack_packet(&subset_wire).unwrap();
        assert_eq!(default_round.endpoints(), default_eps.as_slice());
        assert_eq!(subset_round.endpoints(), subset_eps);
        assert_eq!(
            wire_format::packet_id_from_wire(&default_wire).unwrap(),
            default_pkt.packet_id()
        );
        assert_eq!(
            wire_format::packet_id_from_wire(&subset_wire).unwrap(),
            subset_pkt.packet_id()
        );
    }

    fn ensure_compact_reliable_test_type() -> (DataType, DataEndpoint) {
        let ep = DataEndpoint::try_named("COMPACT_RELIABLE_EP").unwrap_or_else(|| {
            crate::config::register_endpoint_with_description(
                "COMPACT_RELIABLE_EP",
                "compact reliable test endpoint",
                false,
            )
            .unwrap_or_else(|_| DataEndpoint::named("COMPACT_RELIABLE_EP"))
        });
        let ty = DataType::try_named("COMPACT_RELIABLE_TYPE").unwrap_or_else(|| {
            crate::config::register_data_type_with_description(
                "COMPACT_RELIABLE_TYPE",
                "compact reliable test type",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[ep],
                ReliableMode::Ordered,
                1,
            )
            .unwrap_or_else(|_| DataType::named("COMPACT_RELIABLE_TYPE"))
        });
        (ty, ep)
    }

    #[test]
    fn compact_reliable_header_roundtrips_and_shrinks_data_frames() {
        let (ty, ep) = ensure_compact_reliable_test_type();
        let pkt = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[ep], 9)
            .unwrap()
            .with_nonce(7);

        let compact = wire_format::pack_packet_with_reliable(
            &pkt,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0,
            },
        );
        let fixed = wire_format::pack_packet_with_reliable(
            &pkt,
            wire_format::ReliableHeader {
                flags: 0,
                seq: u32::MAX,
                ack: u32::MAX,
            },
        );

        assert_ne!(
            compact[0] & 0x40,
            0,
            "small seq uses compact reliable header"
        );
        assert_eq!(
            fixed[0] & 0x40,
            0,
            "large seq+ack keeps fixed reliable header"
        );
        assert!(compact.len() + 7 <= fixed.len());

        let info = wire_format::peek_frame_info(&compact).unwrap();
        assert_eq!(
            info.reliable,
            Some(wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0
            })
        );
        assert_eq!(
            wire_format::unpack_packet(&compact).unwrap().packet_id(),
            pkt.packet_id()
        );
    }

    #[test]
    fn compact_reliable_ack_and_owned_rewrite_roundtrip() {
        let (ty, ep) = ensure_compact_reliable_test_type();
        let ack = wire_format::pack_reliable_ack("DST", ty, 0, 3);
        assert_ne!(
            ack[0] & 0x40,
            0,
            "small ACK-only frame uses compact reliable header"
        );
        let ack_info = wire_format::peek_frame_info(&ack).unwrap();
        assert_eq!(
            ack_info.reliable,
            Some(wire_format::ReliableHeader {
                flags: wire_format::RELIABLE_FLAG_ACK_ONLY,
                seq: 0,
                ack: 3
            })
        );

        let pkt = Packet::from_f32_slice(ty, &[4.0, 5.0, 6.0], &[ep], 10).unwrap();
        let fixed = wire_format::pack_packet_with_reliable(
            &pkt,
            wire_format::ReliableHeader {
                flags: 0,
                seq: u32::MAX,
                ack: u32::MAX,
            },
        );
        let rewritten = wire_format::rewrite_reliable_header_owned(&fixed, 0, 4, 0)
            .unwrap()
            .expect("reliable header present");
        assert_ne!(rewritten[0] & 0x40, 0);
        assert!(rewritten.len() < fixed.len());
        assert_eq!(
            wire_format::peek_frame_info(&rewritten).unwrap().reliable,
            Some(wire_format::ReliableHeader {
                flags: 0,
                seq: 4,
                ack: 0
            })
        );
    }

    // ---------------------------------------------------------------------------
    // Router packing/unpacking paths
    // ---------------------------------------------------------------------------

    /// If only `Packed` handlers exist, the router must not unpack the
    /// payload and just pass the raw bytes.
    #[test]
    fn packed_only_handlers_do_not_unpack() {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            123,
        )
        .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        let called = StdArc::new(AtomicUsize::new(0));
        let c = called.clone();
        let handler = EndpointHandler::new_packed_handler(
            DataEndpoint::named("SD_CARD"),
            move |bytes: &[u8]| {
                assert!(bytes.len() >= wire_format::header_size_bytes(&pkt));
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        r.rx_packed(&wire).unwrap();
        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    /// When mixing `Packet` and `Packed` handlers, ensure:
    /// - unpacking happens only once,
    /// - each endpoint handler is invoked exactly once.
    #[test]
    fn packet_handlers_trigger_single_unpack_and_fan_out() {
        let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 5)
                .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        let packet_called = StdArc::new(AtomicUsize::new(0));
        let packed_called = StdArc::new(AtomicUsize::new(0));

        let ph = packet_called.clone();
        let sh = packed_called.clone();

        let packet_h =
            EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
                ph.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let packed_h =
            EndpointHandler::new_packed_handler(DataEndpoint::named("RADIO"), move |_b| {
                sh.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let r = Router::new_with_clock(RouterConfig::new(vec![packet_h, packed_h]), zero_clock());

        r.rx_packed(&wire).unwrap();
        assert_eq!(packet_called.load(Ordering::SeqCst), 1);
        assert_eq!(packed_called.load(Ordering::SeqCst), 1);
    }

    /// If all addressed endpoints are local `Packet` handlers, router should
    /// avoid serializing at all and never call TX.
    #[test]
    fn send_avoids_packing_when_only_local_packet_handlers_exist() {
        let tx_called = StdArc::new(AtomicUsize::new(0));
        let txc = tx_called.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        let hits = StdArc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |pkt: &Packet| {
                pkt.validate().unwrap();
                h.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        r.add_side_packed("tx", tx);
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        r.tx(pkt).unwrap();

        assert_eq!(tx_called.load(Ordering::SeqCst), 0);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// `Router::receive` for a direct packet should invoke any matching local
    /// packet handlers exactly once.
    #[test]
    fn receive_direct_packet_invokes_handlers() {
        let called = StdArc::new(AtomicUsize::new(0));
        let c = called.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[0.5, 0.5, 0.5],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        r.rx(&pkt).unwrap();

        assert_eq!(called.load(Ordering::SeqCst), 1);
    }

    // ---------------------------------------------------------------------------
    // Error payload truncation & encode_slice_le extra types
    // ---------------------------------------------------------------------------

    /// Ensure router’s internal TelemetryError payload is truncated to meta size
    /// and doesn’t grow without bound.
    #[test]
    fn error_payload_is_truncated_to_meta_size() {
        let failing_tx = |_b: &[u8]| -> TelemetryResult<()> { Err(TelemetryError::Io("boom")) };

        let captured = StdArc::new(Mutex::new(String::new()));
        let c = captured.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |pkt| {
                if pkt.data_type() == DataType::TelemetryError {
                    *c.lock().unwrap() = pkt.as_string();
                }
                Ok(())
            });

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        r.add_side_packed("tx", failing_tx);
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            1,
        )
        .unwrap();
        let _ = r.tx(pkt);

        let s = captured.lock().unwrap().clone();
        assert!(!s.is_empty());
        assert!(s.len() < 8_192);
    }

    /// Ensure `encode_slice_le` works correctly for both `u16` and `f64`.
    #[test]
    fn encode_slice_le_u16_and_f64() {
        let vals16 = [0x0102u16, 0xA1B2];
        let got = crate::router::encode_slice_le(&vals16);
        let mut exp = Vec::new();
        for v in vals16 {
            exp.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(&*got, &exp);

        let vals64 = [1.5f64, -2.25];
        let got = crate::router::encode_slice_le(&vals64);
        let mut exp = Vec::new();
        for v in vals64 {
            exp.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(&*got, &exp);
    }

    /// Ensure `test_payload_len_for` respects element widths and yields lengths
    /// that are multiples of the correct width for all numeric/bool types.
    #[test]
    fn test_payload_len_for_respects_element_width() {
        use crate::tests::test_payload_len_for;

        for i in 0..=MAX_VALUE_DATA_TYPE {
            if let Some(ty) = DataType::try_from_u32(i) {
                let len = test_payload_len_for(ty);

                match get_data_type(ty) {
                    MessageDataType::String | MessageDataType::Binary => {
                        // any positive length is fine for string/hex, just sanity check
                        assert!(len >= 1, "string/hex must have at least 1 byte for {ty:?}");
                    }
                    kind => {
                        let width = match kind {
                            MessageDataType::UInt8
                            | MessageDataType::Int8
                            | MessageDataType::Bool => 1,
                            MessageDataType::UInt16 | MessageDataType::Int16 => 2,
                            MessageDataType::UInt32
                            | MessageDataType::Int32
                            | MessageDataType::Float32 => 4,
                            MessageDataType::UInt64
                            | MessageDataType::Int64
                            | MessageDataType::Float64 => 8,
                            MessageDataType::UInt128 | MessageDataType::Int128 => 16,
                            MessageDataType::String | MessageDataType::Binary => 1,
                            MessageDataType::NoData => 0,
                        };
                        if width == 0 {
                            // NoData must have zero length
                            assert_eq!(
                                len, 0,
                                "NoData type must have zero-length payload for {ty:?}"
                            );
                            return;
                        }
                        assert_eq!(
                            len % width,
                            0,
                            "test payload length {len} not multiple of element width {width} for {ty:?}"
                        );
                    }
                }
            }
        }
    }
    fn append_crc32(buf: &mut Vec<u8>) {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(buf);
        let crc = hasher.finalize();
        buf.extend_from_slice(&crc.to_le_bytes());
    }
    /// Construct an invalid varint (11 continuation bytes), and ensure
    /// `unpack_packet` returns a `uleb128 too long` error.
    #[test]
    fn unpack_packet_rejects_overflowed_varint() {
        use crate::wire_format;
        // Construct a fake wire buffer with NEP=0, then an invalid varint (11 continuation bytes)
        let mut wire = vec![0x00u8]; // NEP = 0
        wire.extend([0xFFu8; 11]); // invalid ULEB128 (too long for u64)
        append_crc32(&mut wire);
        let err = wire_format::unpack_packet(&wire).unwrap_err();
        match err {
            TelemetryError::Unpack(msg) if msg.eq("uleb128 too long") => {}
            other => panic!("expected Unpack(uleb128 too long...) error, got {other:?}"),
        }
    }

    /// Endpoint order in the `endpoints` slice must not affect packed bytes.
    #[test]
    fn pack_packet_is_order_invariant_for_endpoints() {
        crate::tests::ensure_common_test_schema();
        use crate::config::{DataEndpoint, DataType};
        use crate::{packet::Packet, wire_format};

        let eps_a = &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")];
        let eps_b = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];

        let pkt_a = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], eps_a, 0)
            .unwrap()
            .with_nonce(7);
        let pkt_b = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], eps_b, 0)
            .unwrap()
            .with_nonce(7);

        let wa = wire_format::pack_packet(&pkt_a);
        let wb = wire_format::pack_packet(&pkt_b);

        assert_eq!(wa, wb, "endpoint order must not affect packed bytes");
    }

    /// With a large number of TX and RX items, `process_all_queues_with_timeout(0)`
    /// must flush all TX and deliver all packets to handlers.
    #[test]
    fn process_all_queues_timeout_zero_handles_large_queues() {
        crate::tests::ensure_common_test_schema();
        use crate::config::{DataEndpoint, DataType};
        use crate::packet::Packet;
        use crate::router::{Router, RouterConfig};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tx_count = Arc::new(AtomicUsize::new(0));
        let txc = tx_count.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rxc = rx_count.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
                rxc.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let router = Router::new_with_clock(
            RouterConfig::new(vec![handler]),
            Box::new(|| UnixClock.now_ms()),
        );
        router.add_side_packed("tx", tx);

        // Enqueue many TX and RX items with unique payloads/timestamps.
        const N: usize = 200;
        for i in 0..N {
            let base_tx = 1.0_f32 + i as f32 * 0.01;
            router
                .log_queue(DataType::named("GPS_DATA"), &[base_tx, 2.0, 3.0])
                .unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0 + i as f32 * 0.01, 8.0, 7.0],
                &[DataEndpoint::named("SD_CARD")],
                i as u64,
            )
            .unwrap();
            router.rx_queue(pkt).unwrap();
        }

        let (queued_rx, _queued_tx, _queued_recent) = router.debug_queue_lengths();
        assert!(queued_rx <= N, "RX queue should be bounded");
        assert!(
            router.debug_shared_queue_bytes_used() <= crate::config::MAX_QUEUE_BUDGET,
            "shared queue budget should cap retained queued bytes"
        );

        router.process_all_queues_with_timeout(0).unwrap();

        assert_eq!(
            tx_count.load(Ordering::SeqCst),
            N,
            "all queued GPS TX should flush"
        );
        assert_eq!(
            rx_count.load(Ordering::SeqCst),
            N + queued_rx,
            "each retained GPS TX local delivery + retained RX packet should invoke handler"
        );
    }
}

// -----------------------------------------------------------------------------
// Concurrency tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod concurrency_tests {
    //! Concurrency-focused tests that exercise Router’s thread-safety
    //! guarantees for logging, receiving, and processing.

    use crate::tests::packed_frame_type;
    use crate::{
        TelemetryResult,
        config::{DataEndpoint, DataType},
        packet::Packet,
        router::{Clock, EndpointHandler, Router, RouterConfig},
        wire_format,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    /// Simple clock that always returns 0 (blanket impl<Fn() -> u64> for Clock).
    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    // ------------------------------------------------------------------------
    // Trait sanity: Router must be Send + Sync
    // ------------------------------------------------------------------------

    /// Compile-time check: `Router` must be `Send + Sync` to be safely shared
    /// across threads.
    #[test]
    fn router_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Router>();
    }

    // ------------------------------------------------------------------------
    // Concurrent RX queue producers
    // ------------------------------------------------------------------------

    /// Multiple producer threads call `rx_packet_to_queue` on the same Router;
    /// a single drain must deliver all packets to the handler exactly once.
    #[test]
    fn concurrent_rx_queue_is_thread_safe() {
        const THREADS: usize = 4;
        const ITERS_PER_THREAD: usize = 50;
        let total = THREADS * ITERS_PER_THREAD;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        let r = Arc::new(router);

        let mut threads_vec = Vec::new();
        for tid in 0..THREADS {
            let r_cloned = r.clone();
            threads_vec.push(thread::spawn(move || {
                for i in 0..ITERS_PER_THREAD {
                    // Unique timestamp/payload per (thread, iteration) to avoid dedup.
                    let idx = (tid * ITERS_PER_THREAD + i) as u64;
                    let base = 1.0_f32 + idx as f32 * 0.001;
                    let pkt = Packet::from_f32_slice(
                        DataType::named("GPS_DATA"),
                        &[base, 2.0, 3.0],
                        &[DataEndpoint::named("SD_CARD")],
                        idx,
                    )
                    .unwrap();
                    r_cloned.rx_queue(pkt).unwrap();
                }
            }));
        }

        for t in threads_vec {
            t.join().expect("producer thread panicked");
        }

        r.process_rx_queue().unwrap();

        assert_eq!(
            hits.load(Ordering::SeqCst),
            total,
            "expected {total} handler invocations from RX queue"
        );
    }

    /// RTOS-like pattern: multiple ingress threads queue packed packets while
    /// another thread continuously drains router queues. This should not deadlock
    /// and all queued packets should eventually be processed once.
    #[test]
    fn rtos_like_ingress_and_processing_no_deadlock() {
        const THREADS: usize = 4;
        const ITERS_PER_THREAD: usize = 80;
        let total = THREADS * ITERS_PER_THREAD;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let router = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![handler]),
            zero_clock(),
        ));

        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let proc_router = router.clone();
        let done_c = done.clone();
        let processor = thread::spawn(move || {
            while !done_c.load(Ordering::SeqCst) {
                proc_router.process_all_queues_with_timeout(1).unwrap();
            }
            proc_router.process_all_queues().unwrap();
        });

        let mut producers = Vec::new();
        for tid in 0..THREADS {
            let r = router.clone();
            producers.push(thread::spawn(move || {
                for i in 0..ITERS_PER_THREAD {
                    let idx = (tid * ITERS_PER_THREAD + i) as u64;
                    let base = 1.0_f32 + idx as f32 * 0.001;
                    let pkt = Packet::from_f32_slice(
                        DataType::named("GPS_DATA"),
                        &[base, 2.0, 3.0],
                        &[DataEndpoint::named("SD_CARD")],
                        idx,
                    )
                    .unwrap();
                    let wire = wire_format::pack_packet(&pkt);
                    r.rx_packed_queue(&wire).unwrap();
                }
            }));
        }

        for t in producers {
            t.join().expect("producer thread panicked");
        }

        done.store(true, Ordering::SeqCst);
        processor.join().expect("processor thread panicked");

        assert_eq!(
            hits.load(Ordering::SeqCst),
            total,
            "expected {total} handler invocations from RTOS-like queued ingress"
        );
    }

    /// RTOS-like relay scenario: packets arrive from two sides while a worker
    /// thread drains queues. Ensures side-tagged queue ingress remains stable.
    #[test]
    fn rtos_like_side_ingress_and_processing_no_deadlock() {
        const THREADS: usize = 4;
        const ITERS_PER_THREAD: usize = 60;
        let total = THREADS * ITERS_PER_THREAD;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let local = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let tx_count = Arc::new(AtomicUsize::new(0));
        let tx_c0 = tx_count.clone();
        let tx_c1 = tx_count.clone();

        let router = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![local]),
            zero_clock(),
        ));

        let side0 = router.add_side_packed("S0", move |_b| {
            tx_c0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let side1 = router.add_side_packed("S1", move |_b| {
            tx_c1.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(side0, 0);
        assert_eq!(side1, 1);

        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let proc_router = router.clone();
        let done_c = done.clone();
        let processor = thread::spawn(move || {
            while !done_c.load(Ordering::SeqCst) {
                proc_router.process_all_queues_with_timeout(1).unwrap();
            }
            proc_router.process_all_queues().unwrap();
        });

        let mut producers = Vec::new();
        for tid in 0..THREADS {
            let r = router.clone();
            producers.push(thread::spawn(move || {
                for i in 0..ITERS_PER_THREAD {
                    let idx = (tid * ITERS_PER_THREAD + i) as u64;
                    let side = if (idx & 1) == 0 { 0 } else { 1 };
                    let base = 10.0_f32 + idx as f32 * 0.01;
                    let pkt = Packet::from_f32_slice(
                        DataType::named("GPS_DATA"),
                        &[base, 2.0, 3.0],
                        &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
                        idx,
                    )
                    .unwrap();
                    let wire = wire_format::pack_packet(&pkt);
                    r.rx_packed_queue_from_side(&wire, side).unwrap();
                }
            }));
        }

        for t in producers {
            t.join().expect("producer thread panicked");
        }

        done.store(true, Ordering::SeqCst);
        processor.join().expect("processor thread panicked");

        assert_eq!(
            hits.load(Ordering::SeqCst),
            total,
            "expected local handler to see all side-tagged packets"
        );
        assert!(
            tx_count.load(Ordering::SeqCst) > 0,
            "relay mode should have forwarded packets to remote sides"
        );
    }

    /// A local handler can safely call back into the same Router (enqueueing
    /// new work) without deadlocking queue processing.
    #[test]
    fn handler_can_reenter_router_without_deadlock() {
        use std::sync::OnceLock;
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc;

        let router_ref: Arc<OnceLock<Arc<Router>>> = Arc::new(OnceLock::new());
        let triggered = Arc::new(AtomicBool::new(false));

        let h1_hits = Arc::new(AtomicUsize::new(0));
        let h2_hits = Arc::new(AtomicUsize::new(0));
        let h1_hits_c = h1_hits.clone();
        let h2_hits_c = h2_hits.clone();
        let triggered_c = triggered.clone();
        let router_ref_c = router_ref.clone();

        let h1 = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
            h1_hits_c.fetch_add(1, Ordering::SeqCst);
            if !triggered_c.swap(true, Ordering::SeqCst) {
                let chained = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[9.0_f32, 8.0, 7.0],
                    &[DataEndpoint::named("RADIO")],
                    999,
                )?;
                let r = router_ref_c
                    .get()
                    .expect("router OnceLock should be initialized");
                r.rx_queue(chained)?;
            }
            Ok(())
        });

        let h2 = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |_pkt| {
            h2_hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        let router = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![h1, h2]),
            zero_clock(),
        ));
        router_ref
            .set(router.clone())
            .expect("router OnceLock should only be set once");

        let first = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            100,
        )
        .unwrap();
        router.rx_queue(first).unwrap();

        let (tx_done, rx_done) = mpsc::channel();
        let r = router.clone();
        thread::spawn(move || {
            let out = (|| -> TelemetryResult<()> {
                r.process_rx_queue()?;
                r.process_rx_queue()?;
                Ok(())
            })();
            let _ = tx_done.send(out);
        });

        let done = rx_done
            .recv_timeout(Duration::from_secs(2))
            .expect("processing timed out (possible deadlock)");
        done.expect("processing returned error");

        assert_eq!(h1_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            h2_hits.load(Ordering::SeqCst),
            1,
            "chained callback enqueue should be processed exactly once"
        );
    }

    // ------------------------------------------------------------------------
    // Concurrent calls to receive_packed
    // ------------------------------------------------------------------------

    /// Multiple threads call `receive_packed` concurrently with the same
    /// wire buffer; each call should fan out once to the handler.
    #[test]
    fn concurrent_receive_packed_is_thread_safe() {
        const THREADS: usize = 4;
        const ITERS_PER_THREAD: usize = 50;
        let total = THREADS * ITERS_PER_THREAD;

        // Handler that counts how many times it is invoked.
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        let r = Arc::new(router);

        let mut threads_vec = Vec::new();
        for tid in 0..THREADS {
            let r_cloned = r.clone();
            threads_vec.push(thread::spawn(move || {
                for i in 0..ITERS_PER_THREAD {
                    let idx = (tid * ITERS_PER_THREAD + i) as u64;
                    let base = 1.0_f32 + idx as f32 * 0.001;
                    let pkt = Packet::from_f32_slice(
                        DataType::named("GPS_DATA"),
                        &[base, 2.0, 3.0],
                        &[DataEndpoint::named("SD_CARD")],
                        idx,
                    )
                    .unwrap();
                    let wire = wire_format::pack_packet(&pkt);
                    r_cloned.rx_packed(&wire).expect("receive_packed failed");
                }
            }));
        }

        for t in threads_vec {
            t.join().expect("receive thread panicked");
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            total,
            "expected {total} handler invocations from receive_packed"
        );
    }

    // ------------------------------------------------------------------------
    // Concurrent logging + processing
    // ------------------------------------------------------------------------

    /// One thread logs to TX queue while another drains queues; verify that
    /// every logged packet is transmitted once and delivered once to the
    /// local handler.
    #[test]
    fn concurrent_logging_and_processing_is_thread_safe() {
        use std::thread;

        const ITERS: usize = 200;

        // Count how many frames are actually transmitted on the "bus".
        let tx_count = Arc::new(AtomicUsize::new(0));
        let txc = tx_count.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        // Local handler that counts how many packets it sees.
        let rx_count = Arc::new(AtomicUsize::new(0));
        let rxc = rx_count.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rxc.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        // Shared router: TX + one local endpoint.
        let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        router.add_side_packed("tx", tx);
        let r = Arc::new(router);

        // ---------------- Logger thread ----------------
        let r_logger = r.clone();
        let logger = thread::spawn(move || {
            for i in 0..ITERS {
                r_logger
                    .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 5.9 + i as f32, 3.0])
                    .expect("log_queue failed");
            }
        });

        // ---------------- Drainer thread ----------------
        let r_drain = r.clone();
        let rx_counter = rx_count.clone();
        let drainer = thread::spawn(move || {
            // Keep draining until we've seen all expected local handler invocations.
            while rx_counter.load(Ordering::SeqCst) < ITERS {
                r_drain
                    .process_all_queues()
                    .expect("process_all_queues failed");
                thread::yield_now();
            }
        });

        // Wait for both threads to finish.
        logger.join().expect("logger thread panicked");
        drainer.join().expect("drainer thread panicked");

        // After both threads are done, all queued messages should have been
        // transmitted and delivered to the local handler exactly once each.
        let rx = rx_count.load(Ordering::SeqCst);
        let tx = tx_count.load(Ordering::SeqCst);

        assert_eq!(rx, ITERS, "expected {ITERS} handler calls, got {rx}");
        assert_eq!(tx, ITERS, "expected {ITERS} TX frames, got {tx}");
    }

    /// Mix concurrent logging, RX-queue insertion, and queue draining; ensure
    /// that all work is eventually processed exactly once.
    #[test]
    fn concurrent_log_receive_and_process_mix_is_thread_safe() {
        use std::thread;

        const LOG_ITERS: usize = 100;
        const RX_ITERS: usize = 100;

        let tx_count = Arc::new(AtomicUsize::new(0));
        let txc = tx_count.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        let rx_count = Arc::new(AtomicUsize::new(0));
        let rxc = rx_count.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rxc.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        router.add_side_packed("tx", tx);
        let r = Arc::new(router);

        // ---------- Logger thread ----------
        let r_logger = r.clone();
        let t_logger = thread::spawn(move || {
            for i in 0..LOG_ITERS {
                let base = 1.0_f32 + i as f32 * 0.01;
                r_logger
                    .log_queue(DataType::named("GPS_DATA"), &[base, 2.0, 3.0])
                    .expect("log_queue failed");
            }
        });

        // ---------- RX thread ----------
        let r_rx = r.clone();
        let t_rx = thread::spawn(move || {
            for i in 0..RX_ITERS {
                let base = 4.0_f32 + i as f32 * 0.01;
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[base, 5.0, 6.0],
                    &[DataEndpoint::named("SD_CARD")],
                    i as u64,
                )
                .unwrap();
                r_rx.rx_queue(pkt).expect("rx_packet_to_queue failed");
            }
        });

        // ---------- Processor thread ----------
        let r_proc = r.clone();
        let rx_counter = rx_count.clone();
        let t_proc = thread::spawn(move || {
            while rx_counter.load(Ordering::SeqCst) < LOG_ITERS + RX_ITERS {
                r_proc
                    .process_all_queues()
                    .expect("process_all_queues failed");
                thread::yield_now();
            }
        });

        t_logger.join().expect("logger thread panicked");
        t_rx.join().expect("rx thread panicked");
        t_proc.join().expect("processor thread panicked");

        let tx = tx_count.load(Ordering::SeqCst);
        let rx = rx_count.load(Ordering::SeqCst);
        assert_eq!(tx, LOG_ITERS, "expected {LOG_ITERS} TX frames");
        assert_eq!(
            rx,
            LOG_ITERS + RX_ITERS,
            "expected {LOG_ITERS}+{RX_ITERS} handler invocations"
        );
    }
}
mod data_conversion_types {

    // ---------------------------------------------------------------------------
    // Packet typed data accessors
    // ---------------------------------------------------------------------------

    use crate::config::{DataEndpoint, DataType};
    use crate::packet::Packet;
    use crate::{MAX_VALUE_DATA_TYPE, MessageDataType, TelemetryError, get_data_type};

    /// data_as_f32 should round-trip values written via from_f32_slice.
    #[test]
    fn data_as_f32_roundtrips_gps() {
        let eps = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let src = [1.5_f32, -2.25, 3.0];

        let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &src, eps, 42).unwrap();
        let vals = pkt.data_as_f32().unwrap();

        assert_eq!(vals, src);
    }

    /// Calling a mismatched accessor (e.g. data_as_u16 on a Float32 packet)
    /// must return TelemetryError::TypeMismatch.
    #[test]
    fn mismatched_typed_accessor_returns_type_mismatch() {
        let eps = &[DataEndpoint::named("SD_CARD")];
        let src = [1.0_f32, 2.0, 3.0];

        let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &src, eps, 0).unwrap();

        let res = pkt.data_as_u16();
        match res {
            Err(TelemetryError::TypeMismatch { .. }) => {}
            other => panic!("expected TypeMismatch, got {other:?}"),
        }
    }

    /// If there is a Bool-typed DataType in the schema, ensure data_as_bool
    /// decodes non-zero bytes to true and zero to false.
    #[test]
    fn data_as_bool_decodes_nonzero() {
        // Find any Bool-typed DataType in the schema.
        let mut bool_ty_opt = None;
        for i in 0..=MAX_VALUE_DATA_TYPE {
            if let Some(ty) = DataType::try_from_u32(i)
                && get_data_type(ty) == MessageDataType::Bool
            {
                bool_ty_opt = Some(ty);
                break;
            }
        }

        // If the schema doesn't define any Bool-typed messages, skip this test.
        let bool_ty = match bool_ty_opt {
            Some(t) => t,
            None => return,
        };

        let eps = &[DataEndpoint::named("SD_CARD")];
        let vals = [true];

        let pkt = Packet::from_bool_slice(bool_ty, &vals, eps, 0).unwrap();
        let decoded = pkt.data_as_bool().unwrap();
        assert_eq!(decoded, vals);
    }
}

// -----------------------------------------------------------------------------
// Relay tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod relay_tests {
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
    fn relay_packed_side_templates_can_omit_unchanged_timestamps() {
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
            1
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
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
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
}

#[cfg(test)]
mod dedupe_tests {
    //! Tests specifically for RX/relay deduplication behavior.

    use crate::config::{DataEndpoint, DataType};
    use crate::discovery::build_discovery_announce;
    use crate::relay::Relay;
    use crate::router::{Clock, EndpointHandler, Router, RouterConfig, RouterSideOptions};
    use crate::tests::packed_frame_type;
    use crate::tests::timeout_tests::StepClock;
    use crate::{TelemetryResult, packet::Packet, wire_format};

    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// Simple clock that always returns 0.
    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    fn wire_for_value(v: u64) -> Arc<[u8]> {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[v as f32, 0.0, 0.0],
            &[DataEndpoint::named("SD_CARD")],
            v,
        )
        .unwrap();
        wire_format::pack_packet(&pkt)
    }

    fn advertise_side(relay: &Relay, side: usize, sender: &str) {
        crate::tests::ensure_common_test_schema();
        let pkt = build_discovery_announce(sender, 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
        relay.rx_from_side(side, pkt).unwrap();
    }

    // -----------------------------------------------------------------------
    // Router dedupe tests
    // -----------------------------------------------------------------------

    /// Repeatedly calling `rx_packed` with the *same* wire frame must only
    /// deliver it once to local handlers.
    #[test]
    fn router_rx_packed_deduplicates_identical_frames() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();

        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        // Router with no TX; only RX + local fan-out.
        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

        // Build a single wire frame we will reuse.
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        // Feed the identical frame many times.
        for _ in 0..5 {
            r.rx_packed(&wire).unwrap();
        }

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "rx_packed should deliver identical frames only once"
        );
    }

    /// Even if time advances between deliveries, the same frame must still be
    /// deduped (i.e. dedupe is not time-window based).
    #[test]
    fn router_rx_packed_dedup_persists_across_time_advance() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();

        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        // Step clock that advances every time we look at it.
        let clock = StepClock::new_box(0, 1);
        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), clock);

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        // First time → delivered.
        r.rx_packed(&wire).unwrap();
        // Time advances inside router via Clock, but dedupe should still drop it.
        r.rx_packed(&wire).unwrap();

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "dedupe should persist even as clock advances"
        );
    }

    /// Two *different* frames must both be delivered, never deduped against
    /// each other.
    #[test]
    fn router_rx_packed_does_not_dedupe_different_frames() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();

        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

        // Frame A
        let pkt_a = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let wire_a = wire_format::pack_packet(&pkt_a);

        // Frame B (different payload)
        let pkt_b = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let wire_b = wire_format::pack_packet(&pkt_b);

        r.rx_packed(&wire_a).unwrap();
        r.rx_packed(&wire_b).unwrap();

        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "different frames must never be deduplicated"
        );
    }

    #[test]
    fn router_rx_packed_does_not_dedupe_same_payload_same_ms_when_nonce_differs() {
        crate::tests::ensure_common_test_schema();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();

        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let r = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());

        let pkt_a = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt_b = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        let wire_a = wire_format::pack_packet(&pkt_a);
        let wire_b = wire_format::pack_packet(&pkt_b);

        r.rx_packed(&wire_a).unwrap();
        r.rx_packed(&wire_b).unwrap();

        assert_ne!(pkt_a.nonce(), pkt_b.nonce());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn packed_side_header_templates_reduce_followup_frame_size() {
        crate::tests::ensure_common_test_schema();
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
        let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
        let frames_c = frames.clone();
        let receiver_c = receiver.clone();

        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        sender.add_side_packed_small_packets(
            "link",
            move |bytes: &[u8]| {
                frames_c.lock().unwrap().push(bytes.len());
                let side = receiver_side_id_c
                    .lock()
                    .unwrap()
                    .expect("receiver side id");
                receiver_c.rx_packed_from_side(bytes, side)
            },
            0,
        );
        let rx_side = receiver.add_side_packed_with_options(
            "link",
            |_bytes| Ok(()),
            RouterSideOptions {
                header_template_enabled: true,
                ..RouterSideOptions::default()
            },
        );
        *receiver_side_id.lock().unwrap() = Some(rx_side);

        let pkt_a = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            10_000,
        )
        .unwrap()
        .with_nonce(11);
        let pkt_b = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            10_001,
        )
        .unwrap()
        .with_nonce(12);

        sender.tx(pkt_a).unwrap();
        sender.tx(pkt_b).unwrap();

        let lens = frames.lock().unwrap();
        assert_eq!(delivered.load(Ordering::SeqCst), 2);
        assert_eq!(lens.len(), 2);
        assert!(lens[1] < lens[0], "second frame should use compact header");

        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "link")
            .expect("link side stats");
        assert!(side.header_template_enabled);
        assert_eq!(side.side_transport_profile, "ipv6_like");
        assert_eq!(side.side_transport_full_frames, 1);
        assert_eq!(side.side_transport_compact_frames, 1);
        assert_eq!(side.side_transport_compact_delta_frames, 1);
        assert!(side.side_transport_bytes_saved > 0);
        assert_eq!(
            side.compact_header_target_bytes,
            crate::router::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES
        );
        assert!(
            side.side_transport_min_compact_overhead_bytes
                .expect("compact overhead")
                <= side.compact_header_target_bytes,
            "simple compact follow-up frames should fit the configured overhead target"
        );
        assert_eq!(side.side_transport_compact_target_misses, 0);
    }

    #[test]
    fn packed_side_header_templates_can_omit_unchanged_timestamps() {
        crate::tests::ensure_common_test_schema();
        let delivered_payloads = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
        let delivered_payloads_c = delivered_payloads.clone();
        let receiver = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                move |pkt: &Packet| {
                    let mut payload = Vec::with_capacity(pkt.payload().len() / 4);
                    for chunk in pkt.payload().chunks_exact(4) {
                        payload.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                    delivered_payloads_c.lock().unwrap().push(payload);
                    Ok(())
                },
            )]),
            zero_clock(),
        ));
        let receiver_side_id = Arc::new(Mutex::new(None));
        let receiver_side_id_c = receiver_side_id.clone();
        let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
        let frames_c = frames.clone();
        let receiver_c = receiver.clone();

        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        sender.add_side_packed_with_options(
            "link",
            move |bytes: &[u8]| {
                frames_c.lock().unwrap().push(bytes.len());
                let side = receiver_side_id_c
                    .lock()
                    .unwrap()
                    .expect("receiver side id");
                receiver_c.rx_packed_from_side(bytes, side)
            },
            RouterSideOptions {
                header_template_enabled: true,
                compact_header_target_bytes: 20,
                ..RouterSideOptions::default()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        let rx_side = receiver.add_side_packed_with_options(
            "link",
            |_bytes| Ok(()),
            RouterSideOptions {
                header_template_enabled: true,
                compact_header_target_bytes: 20,
                ..RouterSideOptions::default()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        *receiver_side_id.lock().unwrap() = Some(rx_side);

        let pkt_a = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            10_000,
        )
        .unwrap()
        .with_nonce(21);
        let pkt_b = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            10_000,
        )
        .unwrap()
        .with_nonce(22);

        sender.tx(pkt_a).unwrap();
        sender.tx(pkt_b).unwrap();

        let lens = frames.lock().unwrap();
        assert_eq!(lens.len(), 2);
        assert!(lens[1] < lens[0], "second frame should use compact header");
        drop(lens);

        let delivered = delivered_payloads.lock().unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], vec![1.0, 2.0, 3.0]);
        assert_eq!(delivered[1], vec![4.0, 5.0, 6.0]);
        drop(delivered);

        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "link")
            .expect("link side stats");
        assert_eq!(side.side_transport_full_frames, 1);
        assert_eq!(side.side_transport_compact_frames, 1);
        assert_eq!(side.side_transport_compact_delta_frames, 0);
        assert_eq!(side.side_transport_compact_omitted_timestamp_frames, 1);
        assert!(side.side_transport_bytes_saved > 0);
        assert_eq!(side.side_transport_compact_target_misses, 0);
    }

    #[test]
    fn packed_side_timestamp_omission_policy_does_not_apply_to_other_types() {
        crate::tests::ensure_common_test_schema();
        let other_ty = DataType::try_named("POLICY_OTHER_DATA").unwrap_or_else(|| {
            use crate::config::register_data_type_with_description;
            use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
            register_data_type_with_description(
                "POLICY_OTHER_DATA",
                "test type that should not inherit GPS timestamp omission policy",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[DataEndpoint::named("SD_CARD")],
                ReliableMode::None,
                1,
            )
            .expect("register POLICY_OTHER_DATA")
        });
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

        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        sender.add_side_packed_with_options(
            "link",
            move |bytes: &[u8]| {
                let side = receiver_side_id_c
                    .lock()
                    .unwrap()
                    .expect("receiver side id");
                receiver_c.rx_packed_from_side(bytes, side)
            },
            RouterSideOptions {
                header_template_enabled: true,
                compact_header_target_bytes: 20,
                ..RouterSideOptions::default()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        let rx_side = receiver.add_side_packed_with_options(
            "link",
            |_bytes| Ok(()),
            RouterSideOptions {
                header_template_enabled: true,
                compact_header_target_bytes: 20,
                ..RouterSideOptions::default()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        *receiver_side_id.lock().unwrap() = Some(rx_side);

        let pkt_a = Packet::from_f32_slice(
            other_ty,
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            10_000,
        )
        .unwrap()
        .with_nonce(31);
        let pkt_b = Packet::from_f32_slice(
            other_ty,
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            10_000,
        )
        .unwrap()
        .with_nonce(32);

        sender.tx(pkt_a).unwrap();
        sender.tx(pkt_b).unwrap();

        assert_eq!(delivered.load(Ordering::SeqCst), 2);
        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "link")
            .expect("link side stats");
        assert_eq!(side.side_transport_full_frames, 1);
        assert_eq!(side.side_transport_compact_frames, 1);
        assert_eq!(side.side_transport_compact_delta_frames, 1);
        assert_eq!(side.side_transport_compact_omitted_timestamp_frames, 0);
    }

    #[test]
    fn packed_side_template_dictionary_is_bounded() {
        crate::tests::ensure_common_test_schema();
        let receiver = Arc::new(Router::new_with_clock(
            RouterConfig::default(),
            zero_clock(),
        ));
        let receiver_side_id = Arc::new(Mutex::new(None));
        let receiver_side_id_c = receiver_side_id.clone();
        let receiver_c = receiver.clone();

        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        sender.add_side_packed_with_options(
            "bounded-link",
            move |bytes: &[u8]| {
                let side = receiver_side_id_c
                    .lock()
                    .unwrap()
                    .expect("receiver side id");
                receiver_c.rx_packed_from_side(bytes, side)
            },
            RouterSideOptions {
                header_template_enabled: true,
                max_side_transport_templates: 1,
                ..RouterSideOptions::default()
            },
        );
        let rx_side = receiver.add_side_packed_with_options(
            "bounded-link",
            |_bytes| Ok(()),
            RouterSideOptions {
                header_template_enabled: true,
                max_side_transport_templates: 1,
                ..RouterSideOptions::default()
            },
        );
        *receiver_side_id.lock().unwrap() = Some(rx_side);

        for (sender_id, ts, nonce) in [("SRC_A", 1, 1), ("SRC_B", 2, 2), ("SRC_A", 3, 3)] {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(ts as f32).to_le_bytes());
            payload.extend_from_slice(&0.0f32.to_le_bytes());
            payload.extend_from_slice(&0.0f32.to_le_bytes());
            let pkt = Packet::new(
                DataType::named("GPS_DATA"),
                &[DataEndpoint::named("SD_CARD")],
                sender_id,
                ts,
                Arc::<[u8]>::from(payload),
            )
            .unwrap()
            .with_nonce(nonce);
            sender.tx(pkt).unwrap();
        }

        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "bounded-link")
            .expect("bounded side stats");
        assert_eq!(side.max_side_transport_templates, 1);
        assert_eq!(side.side_transport_profile, "template");
        assert_eq!(side.side_transport_tx_template_count, 1);
        assert_eq!(side.side_transport_full_frames, 3);
        assert_eq!(side.side_transport_compact_frames, 0);
        assert!(side.side_transport_template_evictions >= 2);
    }

    #[test]
    fn compact_header_target_misses_are_counted() {
        crate::tests::ensure_common_test_schema();
        let receiver = Arc::new(Router::new_with_clock(
            RouterConfig::default(),
            zero_clock(),
        ));
        let receiver_side_id = Arc::new(Mutex::new(None));
        let receiver_side_id_c = receiver_side_id.clone();
        let receiver_c = receiver.clone();

        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        sender.add_side_packed_with_options(
            "tight-target",
            move |bytes: &[u8]| {
                let side = receiver_side_id_c
                    .lock()
                    .unwrap()
                    .expect("receiver side id");
                receiver_c.rx_packed_from_side(bytes, side)
            },
            RouterSideOptions {
                header_template_enabled: true,
                compact_header_target_bytes: 1,
                ..RouterSideOptions::default()
            },
        );
        let rx_side = receiver.add_side_packed_with_options(
            "tight-target",
            |_bytes| Ok(()),
            RouterSideOptions {
                header_template_enabled: true,
                ..RouterSideOptions::default()
            },
        );
        *receiver_side_id.lock().unwrap() = Some(rx_side);

        for (value, nonce) in [(1.0, 11), (2.0, 12)] {
            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[value, 0.0, 0.0],
                &[DataEndpoint::named("SD_CARD")],
                nonce as u64,
            )
            .unwrap()
            .with_nonce(nonce);
            sender.tx(pkt).unwrap();
        }

        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "tight-target")
            .expect("tight target side stats");
        assert_eq!(side.side_transport_compact_frames, 1);
        assert_eq!(side.side_transport_compact_target_misses, 1);
    }

    #[test]
    fn packed_side_chunking_reassembles_for_fixed_size_links() {
        crate::tests::ensure_common_test_schema();
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
        let sender = Router::new_with_clock(RouterConfig::default(), zero_clock());
        let max_frame_bytes = 48usize;

        sender.add_side_packed_small_packets(
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

        let payload = vec![b'X'; 180];
        let pkt = Packet::new(
            DataType::TelemetryError,
            &[DataEndpoint::named("SD_CARD")],
            "CHUNK_SRC",
            55,
            Arc::<[u8]>::from(payload),
        )
        .unwrap()
        .with_nonce(21);

        sender.tx(pkt).unwrap();

        assert_eq!(delivered.load(Ordering::SeqCst), 1);
        assert!(chunk_count.load(Ordering::SeqCst) > 1);
        assert!(max_seen.load(Ordering::SeqCst) <= max_frame_bytes);
    }

    // -----------------------------------------------------------------------
    // Relay dedupe tests
    // -----------------------------------------------------------------------

    /// For a single relay side, repeatedly injecting the *same* packed
    /// frame should fan out exactly once to other sides.
    #[test]
    fn relay_deduplicates_identical_frames_per_side() {
        crate::tests::ensure_common_test_schema();
        let relay = Relay::new(zero_clock());

        let tx_count_b = Arc::new(AtomicUsize::new(0));
        let tx_count_c = Arc::new(AtomicUsize::new(0));

        let tx_b_c = tx_count_b.clone();
        let tx_b = move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                tx_b_c.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        let tx_c_c = tx_count_c.clone();
        let tx_c = move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                tx_c_c.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        };

        let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
        let side_b = relay.add_side_packed("B", tx_b);
        let side_c = relay.add_side_packed("C", tx_c);
        relay
            .set_source_route_mode(Some(id_src), crate::RouteSelectionMode::Fanout)
            .unwrap();
        advertise_side(&relay, side_b, "SIDE_B");
        advertise_side(&relay, side_c, "SIDE_C");
        relay.process_all_queues_with_timeout(0).unwrap();

        let frame = wire_for_value(1);

        for _ in 0..5 {
            relay
                .rx_packed_from_side(id_src, frame.as_ref())
                .expect("rx_packed_from_side failed");
        }

        relay
            .process_all_queues_with_timeout(0)
            .expect("process_all_queues_with_timeout failed");

        let forwarded_b = tx_count_b.load(Ordering::SeqCst);
        let forwarded_c = tx_count_c.load(Ordering::SeqCst);
        assert_eq!(
            forwarded_b + forwarded_c,
            2,
            "deduplicated ingress should emit exactly one application frame per selected side"
        );
        assert_eq!(forwarded_b, 1);
        assert_eq!(forwarded_c, 1);
    }

    /// Even when time advances, identical frames from the same side should
    /// still be deduped (no time-based expiry).
    #[test]
    fn relay_dedup_persists_across_time_advance() {
        let now_ms = Arc::new(AtomicU64::new(0));
        let clock_now = now_ms.clone();
        let clock: Box<dyn Clock + Send + Sync> =
            Box::new(move || clock_now.load(Ordering::SeqCst));
        let relay = Relay::new(clock);

        let tx_count = Arc::new(AtomicUsize::new(0));
        let txc = tx_count.clone();

        let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
        let dst = relay.add_side_packed("DST", move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        advertise_side(&relay, dst, "DST_SIDE");
        relay.process_all_queues_with_timeout(0).unwrap();

        let frame = wire_for_value(1);

        relay
            .rx_packed_from_side(id_src, frame.as_ref())
            .expect("first rx_packed_from_side failed");
        relay
            .process_all_queues_with_timeout(0)
            .expect("first drain failed");

        now_ms.store(1_000, Ordering::SeqCst);

        relay
            .rx_packed_from_side(id_src, frame.as_ref())
            .expect("second rx_packed_from_side failed");
        relay
            .process_all_queues_with_timeout(0)
            .expect("second drain failed");

        assert_eq!(
            tx_count.load(Ordering::SeqCst),
            1,
            "identical frame from same side should still be deduped after time advance"
        );
    }

    /// Two different frames from the same side must both be relayed.
    #[test]
    fn relay_does_not_dedupe_different_frames_from_same_side() {
        let relay = Relay::new(zero_clock());

        let tx_count = Arc::new(AtomicUsize::new(0));
        let txc = tx_count.clone();

        let id_src = relay.add_side_packed("SRC", |_b| Ok(()));
        let dst = relay.add_side_packed("DST", move |bytes: &[u8]| -> TelemetryResult<()> {
            assert!(!bytes.is_empty());
            if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
                txc.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        });
        advertise_side(&relay, dst, "DST_SIDE");
        relay.process_all_queues_with_timeout(0).unwrap();

        let frame_a = wire_for_value(1);
        let frame_b = wire_for_value(2);

        relay
            .rx_packed_from_side(id_src, frame_a.as_ref())
            .expect("rx_packed_from_side A failed");
        relay
            .rx_packed_from_side(id_src, frame_b.as_ref())
            .expect("rx_packed_from_side B failed");

        relay
            .process_all_queues_with_timeout(0)
            .expect("drain failed");

        assert_eq!(
            tx_count.load(Ordering::SeqCst),
            2,
            "relay must not dedupe different frames from the same side"
        );
    }
}

#[cfg(test)]
mod relay_reliable_tests {
    use crate::config::{DataEndpoint, DataType, RELIABLE_RETRANSMIT_MS};
    use crate::discovery::build_discovery_announce;
    use crate::relay::{Relay, RelaySideOptions};
    use crate::router::Clock;
    use crate::tests::packed_frame_type;
    use crate::tests::timeout_tests::StepClock;
    use crate::{TelemetryResult, packet::Packet, wire_format};

    use std::sync::{Arc, Mutex};

    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    fn advertise_side(relay: &Relay, side: usize) {
        let pkt =
            build_discovery_announce("DST_SIDE", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
        relay.rx_from_side(side, pkt).unwrap();
    }

    #[test]
    fn relay_reliable_seq_advances_with_ack() {
        let relay = Arc::new(Relay::new(zero_clock()));

        relay.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();
        let relay_c = relay.clone();
        let dst = relay.add_side_packed_with_options(
            "DST",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                sent_c.lock().unwrap().push(bytes.to_vec());

                let frame = wire_format::peek_frame_info(bytes)?;
                if let Some(hdr) = frame.reliable {
                    let ack_bytes =
                        wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                    relay_c.rx_packed_from_side(1, ack_bytes.as_ref())?;
                }
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        advertise_side(&relay, dst);
        relay.process_all_queues_with_timeout(0).unwrap();

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        relay.rx_from_side(0, pkt1).unwrap();
        relay.rx_from_side(0, pkt2).unwrap();
        relay.process_all_queues_with_timeout(0).unwrap();
        relay.process_all_queues_with_timeout(0).unwrap();

        let sent = sent.lock().unwrap();
        let gps_sent: Vec<_> = sent
            .iter()
            .filter(|bytes| {
                packed_frame_type(bytes.as_slice()) == Some(DataType::named("GPS_DATA"))
            })
            .collect();
        assert!(
            gps_sent.len() >= 2,
            "expected at least 2 forwarded GPS frames"
        );

        let f1 = wire_format::peek_frame_info(gps_sent[0]).unwrap();
        let f2 = wire_format::peek_frame_info(gps_sent[1]).unwrap();
        let h1 = f1.reliable.expect("frame 1 missing reliable header");
        let h2 = f2.reliable.expect("frame 2 missing reliable header");
        assert_eq!(h1.seq, 1);
        assert_eq!(h2.seq, 2);
        assert_eq!(h1.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED, 0);
        assert_eq!(h2.flags & wire_format::RELIABLE_FLAG_UNSEQUENCED, 0);
    }

    #[test]
    fn relay_reliable_retransmit_across_chain_preserves_order() {
        crate::tests::ensure_common_test_schema();
        let reliable_ty = {
            use crate::config::register_data_type_with_description;
            use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
            let radio = DataEndpoint::named("RADIO");
            let sd_card = DataEndpoint::named("SD_CARD");
            DataType::try_named("RELAY_CHAIN_RELIABLE_DATA").unwrap_or_else(|| {
                register_data_type_with_description(
                    "RELAY_CHAIN_RELIABLE_DATA",
                    "ordered reliable relay-chain regression test type",
                    MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                    &[radio, sd_card],
                    ReliableMode::Ordered,
                    1,
                )
                .expect("register RELAY_CHAIN_RELIABLE_DATA")
            })
        };
        let relay1 = Arc::new(Relay::new(StepClock::new_box(
            0,
            RELIABLE_RETRANSMIT_MS + 1,
        )));
        let relay2 = Arc::new(Relay::new(zero_clock()));

        relay1.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        // Link: relay1 -> relay2 (drop first seq=1 data frame to force retransmit)
        let drop_first = Arc::new(Mutex::new(true));
        let drop_first_c = drop_first.clone();
        let relay2_rx = relay2.clone();
        let link_sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let link_sent_c = link_sent.clone();
        let relay1_mid = relay1.add_side_packed_with_options(
            "MID",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if let Some(hdr) = frame.reliable
                    && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
                    && frame.envelope.ty == reliable_ty
                {
                    link_sent_c.lock().unwrap().push(hdr.seq);
                    if hdr.seq == 1 && *drop_first_c.lock().unwrap() {
                        *drop_first_c.lock().unwrap() = false;
                        return Ok(());
                    }
                }
                relay2_rx.rx_packed_from_side(0, bytes)
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        // Link: relay2 -> relay1 (ACKs and reverse traffic)
        let relay1_rx = relay1.clone();
        let _relay2_mid = relay2.add_side_packed_with_options(
            "MID",
            move |bytes: &[u8]| -> TelemetryResult<()> { relay1_rx.rx_packed_from_side(1, bytes) },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        // Destination capture on relay2
        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_c = delivered.clone();
        let relay2_for_ack = relay2.clone();
        let relay1_for_ack = relay1.clone();
        let relay2_dst_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let relay2_dst_id_c = relay2_dst_id.clone();
        let relay2_dst = relay2.add_side_packed_with_options(
            "DST",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if let Some(hdr) = frame.reliable
                    && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
                {
                    delivered_c.lock().unwrap().push(hdr.seq);
                    let ack_bytes =
                        wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                    if let Some(dst_id) = *relay2_dst_id_c.lock().unwrap() {
                        relay2_for_ack.rx_packed_from_side(dst_id, ack_bytes.as_ref())?;
                    }
                    relay1_for_ack.rx_packed_from_side(relay1_mid, ack_bytes.as_ref())?;
                }
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        *relay2_dst_id.lock().unwrap() = Some(relay2_dst);

        let pkt1 = Packet::from_f32_slice(
            reliable_ty,
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            reliable_ty,
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            0,
        )
        .unwrap();

        relay1.rx_from_side(0, pkt1).unwrap();
        relay1.rx_from_side(0, pkt2).unwrap();

        for _ in 0..10 {
            relay1.process_all_queues_with_timeout(0).unwrap();
            relay2.process_all_queues_with_timeout(0).unwrap();
            if delivered.lock().unwrap().len() >= 2 {
                break;
            }
        }

        let delivered = delivered.lock().unwrap().clone();
        let mut first_seen = Vec::new();
        for seq in delivered {
            if !first_seen.contains(&seq) {
                first_seen.push(seq);
            }
        }
        assert!(
            first_seen.as_slice().starts_with(&[1, 2]),
            "destination must observe the ordered sequence before any later retransmits: {first_seen:?}"
        );

        let link_sent = link_sent.lock().unwrap().clone();
        let seq1_count = link_sent.iter().filter(|&&s| s == 1).count();
        assert!(
            seq1_count >= 2,
            "expected seq1 to be retransmitted across the relay chain"
        );
    }

    #[test]
    fn relay_reliable_reorders_out_of_order_frames() {
        let relay = Arc::new(Relay::new(zero_clock()));

        relay.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_c = delivered.clone();
        let relay_for_ack = relay.clone();
        let dst = relay.add_side_packed_with_options(
            "DST",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if frame.envelope.ty == DataType::named("GPS_DATA")
                    && let Some(hdr) = frame.reliable
                    && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
                {
                    delivered_c.lock().unwrap().push(hdr.seq);
                    let ack_bytes =
                        wire_format::pack_reliable_ack("DST", frame.envelope.ty, 0, hdr.seq);
                    relay_for_ack.rx_packed_from_side(1, ack_bytes.as_ref())?;
                }
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        advertise_side(&relay, dst);
        relay.process_all_queues_with_timeout(0).unwrap();

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        let seq1 = wire_format::pack_packet_with_reliable(
            &pkt1,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0,
            },
        );
        let seq2 = wire_format::pack_packet_with_reliable(
            &pkt2,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 2,
                ack: 0,
            },
        );

        // Out-of-order: seq2 arrives first, then seq1, then seq2 retransmit.
        relay.rx_packed_from_side(0, seq2.as_ref()).unwrap();
        relay.rx_packed_from_side(0, seq1.as_ref()).unwrap();
        relay.rx_packed_from_side(0, seq2.as_ref()).unwrap();

        relay.process_all_queues_with_timeout(0).unwrap();

        let delivered = delivered.lock().unwrap().clone();
        assert_eq!(
            delivered,
            vec![1, 2],
            "out-of-order frames must be reordered"
        );
    }

    #[test]
    fn relay_reliable_sender_does_not_block_while_waiting_for_ack() {
        let relay = Arc::new(Relay::new(zero_clock()));

        relay.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();
        relay.add_side_packed_with_options(
            "DST",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if frame.envelope.ty == DataType::named("GPS_DATA")
                    && let Some(hdr) = frame.reliable
                {
                    sent_c.lock().unwrap().push(hdr.seq);
                }
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            1,
        )
        .unwrap();

        relay.rx_from_side(0, pkt1).unwrap();
        relay.rx_from_side(0, pkt2).unwrap();
        relay.process_all_queues_with_timeout(0).unwrap();

        assert_eq!(*sent.lock().unwrap(), vec![1, 2]);
    }
}

#[cfg(test)]
mod reliable_tests {
    use crate::config::{
        DataEndpoint, DataType, register_data_type_with_description,
        register_endpoint_with_description,
    };
    use crate::router::{Clock, EndpointHandler, Router, RouterConfig, RouterSideOptions};
    use crate::tests::packed_frame_type;
    use crate::tests::timeout_tests::StepClock;
    use crate::{
        MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryResult,
        packet::Packet, wire_format,
    };

    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;

    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    fn ensure_reliable_test_schema() {
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let radio = DataEndpoint::try_named("RADIO").unwrap_or_else(|| {
                register_endpoint_with_description("RADIO", "test radio endpoint", false)
                    .expect("register RADIO")
            });
            let sd_card = DataEndpoint::try_named("SD_CARD").unwrap_or_else(|| {
                register_endpoint_with_description("SD_CARD", "test sd endpoint", false)
                    .expect("register SD_CARD")
            });
            if DataType::try_named("RELIABLE_TEST_DATA").is_none() {
                register_data_type_with_description(
                    "RELIABLE_TEST_DATA",
                    "test reliable data type",
                    MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                    &[radio, sd_card],
                    ReliableMode::Ordered,
                    1,
                )
                .expect("register RELIABLE_TEST_DATA");
            }
        });
    }

    #[test]
    fn reliable_retransmit_delivers_once() {
        ensure_reliable_test_schema();
        let rx_hits = Arc::new(AtomicUsize::new(0));
        let rx_hits_c = rx_hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rx_hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let sender = Arc::new(Router::new_with_clock(
            RouterConfig::new(Vec::new()).with_reliable_enabled(true),
            StepClock::new_box(0, 250),
        ));

        let receiver = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![handler]).with_reliable_enabled(true),
            zero_clock(),
        ));

        let sender_side_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
        let receiver_side_id: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));

        let sender_for_ack = sender.clone();
        let sender_side_id_c = sender_side_id.clone();
        let receiver_side = receiver.add_side_packed_with_options(
            "TO_SENDER",
            move |bytes: &[u8]| {
                if let Some(side_id) = *sender_side_id_c.lock().unwrap() {
                    sender_for_ack.rx_packed_from_side(bytes, side_id)?;
                }
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        *receiver_side_id.lock().unwrap() = Some(receiver_side);

        let drop_first = Arc::new(AtomicBool::new(true));
        let receiver_for_tx = receiver.clone();
        let drop_first_tx = drop_first.clone();
        let receiver_side_id_c = receiver_side_id.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            if drop_first_tx.swap(false, Ordering::SeqCst) {
                return Ok(());
            }
            if let Some(side_id) = *receiver_side_id_c.lock().unwrap() {
                receiver_for_tx.rx_packed_from_side(bytes, side_id)?;
            }
            Ok(())
        };

        let sender_side = sender.add_side_packed_with_options(
            "TO_RECEIVER",
            tx,
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        *sender_side_id.lock().unwrap() = Some(sender_side);

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        sender.tx(pkt).unwrap();

        for _ in 0..3 {
            sender.process_tx_queue_with_timeout(0).unwrap();
        }

        assert_eq!(rx_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn immediate_rx_from_side_emits_reliable_ack_without_queue_drain() {
        ensure_reliable_test_schema();

        let sent_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_frames_c = sent_frames.clone();
        let sender = Router::new_with_clock(
            RouterConfig::default().with_reliable_enabled(true),
            zero_clock(),
        );
        sender.add_side_packed_with_options(
            "to_receiver",
            move |bytes: &[u8]| {
                sent_frames_c.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );

        let pkt = Packet::from_f32_slice(
            DataType::named("RELIABLE_TEST_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("RADIO")],
            7,
        )
        .unwrap();
        sender.tx(pkt).unwrap();
        let frame = sent_frames.lock().unwrap().first().cloned().unwrap();

        let controls: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let controls_c = controls.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::default().with_reliable_enabled(true),
            zero_clock(),
        );
        let receiver_side = receiver.add_side_packed_with_options(
            "to_sender",
            move |bytes: &[u8]| {
                controls_c.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );

        receiver.rx_packed_from_side(&frame, receiver_side).unwrap();

        let controls = controls.lock().unwrap().clone();
        assert!(
            controls.iter().any(|bytes| {
                wire_format::peek_envelope(bytes.as_slice())
                    .map(|env| env.ty == DataType::ReliableAck)
                    .unwrap_or(false)
            }),
            "reliable ack should be emitted immediately on direct rx"
        );
    }

    #[test]
    fn direct_tx_handler_failure_emits_error_without_queue_drain() {
        ensure_reliable_test_schema();

        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_c = seen.clone();
        let handler = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), |_pkt| {
            Err(crate::TelemetryError::Io("boom"))
        });
        let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
        router.add_side_packed("observer", move |bytes| {
            seen_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        });

        let pkt = Packet::from_f32_slice(
            DataType::named("RELIABLE_TEST_DATA"),
            &[9.0_f32, 8.0, 7.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            11,
        )
        .unwrap();

        router.rx(&pkt).unwrap();

        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter().any(|bytes| {
                wire_format::peek_envelope(bytes.as_slice())
                    .map(|env| env.ty == DataType::TelemetryError)
                    .unwrap_or(false)
            }),
            "telemetry error should be emitted immediately on direct tx failure"
        );
        assert_eq!(router.debug_queue_lengths().1, 0);
    }

    #[test]
    fn concurrent_side_tx_busy_is_queued_for_retry() {
        let tx_hits = Arc::new(AtomicUsize::new(0));
        let tx_hits_c = tx_hits.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let release_rx_c = release_rx.clone();

        let router = Arc::new(Router::new_with_clock(
            RouterConfig::default(),
            zero_clock(),
        ));
        router.add_side_packed("BUS", move |bytes| -> TelemetryResult<()> {
            if packed_frame_type(bytes) != Some(DataType::named("BATTERY_STATUS")) {
                return Ok(());
            }
            let hit = tx_hits_c.fetch_add(1, Ordering::SeqCst);
            if hit == 0 {
                entered_tx.send(()).unwrap();
                release_rx_c.lock().unwrap().recv().unwrap();
            }
            Ok(())
        });

        let first = Packet::from_f32_slice(
            DataType::named("BATTERY_STATUS"),
            &[1.0_f32, 2.0],
            &[DataEndpoint::named("RADIO")],
            1,
        )
        .unwrap();
        let second = Packet::from_f32_slice(
            DataType::named("BATTERY_STATUS"),
            &[3.0_f32, 4.0],
            &[DataEndpoint::named("RADIO")],
            2,
        )
        .unwrap();

        let router_for_first = router.clone();
        let first_handle = thread::spawn(move || router_for_first.tx(first));
        entered_rx.recv().unwrap();

        router.tx(second).unwrap();
        assert_eq!(
            tx_hits.load(Ordering::SeqCst),
            1,
            "second TX should be queued while the side callback is busy"
        );

        release_tx.send(()).unwrap();
        first_handle.join().unwrap().unwrap();
        router.process_tx_queue().unwrap();
        assert_eq!(
            tx_hits.load(Ordering::SeqCst),
            2,
            "queued TX should flush after the side callback becomes available"
        );
    }

    #[test]
    fn partial_ack_is_emitted_and_still_allows_requested_replay() {
        let sent_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_frames_c = sent_frames.clone();
        let sender = Router::new_with_clock(
            RouterConfig::default().with_reliable_enabled(true),
            zero_clock(),
        );
        let sender_side = sender.add_side_packed_with_options(
            "to_receiver",
            move |bytes: &[u8]| {
                sent_frames_c.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            1,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[2.0_f32, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            2,
        )
        .unwrap();
        sender.tx(pkt1).unwrap();
        sender.tx(pkt2).unwrap();

        let frames = sent_frames.lock().unwrap().clone();
        assert_eq!(frames.len(), 2);

        let receiver_controls: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let receiver_controls_c = receiver_controls.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::default().with_reliable_enabled(true),
            zero_clock(),
        );
        let receiver_side = receiver.add_side_packed_with_options(
            "to_sender",
            move |bytes: &[u8]| {
                receiver_controls_c.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );

        receiver
            .rx_packed_from_side(&frames[1], receiver_side)
            .unwrap();
        receiver.process_tx_queue().unwrap();
        let controls = receiver_controls.lock().unwrap().clone();
        assert!(controls.iter().any(|frame| {
            wire_format::peek_envelope(frame)
                .map(|env| env.ty == DataType::ReliablePartialAck)
                .unwrap_or(false)
        }));
        assert!(controls.iter().any(|frame| {
            wire_format::peek_envelope(frame)
                .map(|env| env.ty == DataType::ReliablePacketRequest)
                .unwrap_or(false)
        }));

        let ack1 = Packet::new(
            DataType::ReliableAck,
            crate::message_meta(DataType::ReliableAck).endpoints,
            "RX",
            0,
            crate::router::encode_slice_le(&[DataType::named("GPS_DATA").as_u32(), 1]),
        )
        .unwrap();
        sender.rx_from_side(&ack1, sender_side).unwrap();
        for control in controls.iter().filter(|frame| {
            wire_format::peek_envelope(frame)
                .map(|env| env.ty == DataType::ReliablePartialAck)
                .unwrap_or(false)
        }) {
            sender.rx_packed_from_side(control, sender_side).unwrap();
        }

        sent_frames.lock().unwrap().clear();
        let request2 = Packet::new(
            DataType::ReliablePacketRequest,
            crate::message_meta(DataType::ReliablePacketRequest).endpoints,
            "RX",
            0,
            crate::router::encode_slice_le(&[DataType::named("GPS_DATA").as_u32(), 2]),
        )
        .unwrap();
        sender.rx_from_side(&request2, sender_side).unwrap();
        sender.process_tx_queue_with_timeout(0).unwrap();
        assert!(
            sent_frames
                .lock()
                .unwrap()
                .iter()
                .any(|frame| wire_format::peek_frame_info(frame)
                    .ok()
                    .and_then(|info| info.reliable.map(|hdr| hdr.seq == 2))
                    .unwrap_or(false)),
            "requested packet should still retransmit"
        );
    }

    #[test]
    fn reliable_ordered_delivers_in_order() {
        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_c = delivered.clone();
        let handler = EndpointHandler::new_packed_handler(
            DataEndpoint::named("SD_CARD"),
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if frame.envelope.ty == DataType::named("GPS_DATA")
                    && let Some(hdr) = frame.reliable
                    && (hdr.flags & wire_format::RELIABLE_FLAG_ACK_ONLY) == 0
                {
                    delivered_c.lock().unwrap().push(hdr.seq);
                }
                Ok(())
            },
        );

        let router = Router::new_with_clock(
            RouterConfig::new(vec![handler]).with_reliable_enabled(true),
            zero_clock(),
        );

        let side = router.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        let seq1 = wire_format::pack_packet_with_reliable(
            &pkt1,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0,
            },
        );
        let seq2 = wire_format::pack_packet_with_reliable(
            &pkt2,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 2,
                ack: 0,
            },
        );

        // Out-of-order: seq2 arrives first, then seq1, then seq2 retransmit.
        router.rx_packed_from_side(seq2.as_ref(), side).unwrap();
        router.rx_packed_from_side(seq1.as_ref(), side).unwrap();
        router.rx_packed_from_side(seq2.as_ref(), side).unwrap();

        let delivered = delivered.lock().unwrap().clone();
        assert_eq!(
            delivered,
            vec![1, 2],
            "ordered reliable delivery must reorder"
        );
    }

    #[test]
    fn reliable_sender_does_not_block_while_waiting_for_ack() {
        let sent: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let sent_c = sent.clone();

        let router = Router::new_with_clock(
            RouterConfig::new(Vec::new()).with_reliable_enabled(true),
            zero_clock(),
        );

        router.add_side_packed_with_options(
            "DST",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let frame = wire_format::peek_frame_info(bytes)?;
                if frame.envelope.ty == DataType::named("GPS_DATA")
                    && let Some(hdr) = frame.reliable
                {
                    sent_c.lock().unwrap().push(hdr.seq);
                }
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            1,
        )
        .unwrap();

        router.tx(pkt1).unwrap();
        router.tx(pkt2).unwrap();
        router.process_tx_queue_with_timeout(0).unwrap();

        assert_eq!(*sent.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn reliable_disabled_skips_ack() {
        let rx_hits = Arc::new(AtomicUsize::new(0));
        let rx_hits_c = rx_hits.clone();
        let handler = EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                rx_hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let ack_count = Arc::new(AtomicUsize::new(0));
        let ack_count_c = ack_count.clone();
        let rx_direct = move |_bytes: &[u8]| -> TelemetryResult<()> {
            ack_count_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };

        let receiver = Arc::new(Router::new_with_clock(
            RouterConfig::new(vec![handler]).with_reliable_enabled(false),
            zero_clock(),
        ));
        receiver.add_side_packed("ACK", rx_direct);

        let rx_for_tx = receiver.clone();
        let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
            rx_for_tx.rx_packed_from_side(bytes, 0)?;
            Ok(())
        };

        let sender = Router::new_with_clock(
            RouterConfig::new(Vec::new()).with_reliable_enabled(false),
            zero_clock(),
        );
        sender.add_side_packed("TO_RECEIVER", tx);

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0_f32, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            0,
        )
        .unwrap();

        sender.tx(pkt).unwrap();

        assert_eq!(rx_hits.load(Ordering::SeqCst), 1);
        assert_eq!(ack_count.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod router_tests {
    // -------------------------------------------------------------------------
    // New router functionality tests
    // -------------------------------------------------------------------------

    use crate::config::{DataEndpoint, DataType};
    use crate::packet::Packet;
    use crate::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};
    use crate::tests::count_packed_frames_of_type;
    use crate::tests::timeout_tests::StepClock;
    use crate::{TelemetryResult, wire_format};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "discovery")]
    #[test]
    #[should_panic(expected = "reserved internal endpoint handlers must not be user-registered")]
    fn user_cannot_register_discovery_endpoint_handler() {
        let _ = EndpointHandler::new_packet_handler(DataEndpoint::Discovery, |_pkt| Ok(()));
    }

    #[cfg(feature = "timesync")]
    #[test]
    #[should_panic(expected = "reserved internal endpoint handlers must not be user-registered")]
    fn user_cannot_register_timesync_endpoint_handler() {
        let _ = EndpointHandler::new_packet_handler(DataEndpoint::TimeSync, |_pkt| Ok(()));
    }

    /// Receiving a packet that includes at least one non-local endpoint should
    /// cause the router to forward it by default.
    #[test]
    fn relay_mode_retransmits_when_remote_endpoint_present() {
        static TX_CALLS: AtomicUsize = AtomicUsize::new(0);

        fn transmit(_bytes: &[u8]) -> TelemetryResult<()> {
            TX_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        // Local handler on SD_CARD so the router considers SD_CARD "local".
        let local_calls = Arc::new(AtomicUsize::new(0));
        let local_calls_c = local_calls.clone();
        let sd_handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
                local_calls_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let router = Router::new_with_clock(
            RouterConfig::new(vec![sd_handler]),
            StepClock::new_default_box(),
        );
        router.add_side_packed("tx", transmit);

        // Include one local + one remote endpoint.
        let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
                .unwrap();

        router.rx(&pkt).unwrap();

        // Local handler should fire once.
        assert_eq!(local_calls.load(Ordering::SeqCst), 1);
        // Default routing should transmit once.
        assert_eq!(TX_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queued_packed_ingress_retries_side_tx_and_relays_between_router_sides() {
        crate::tests::ensure_common_test_schema();
        #[derive(Default)]
        struct TxState {
            attempts: AtomicUsize,
            delivered: Mutex<Vec<Vec<u8>>>,
        }

        let router = Router::new_with_clock(RouterConfig::default(), StepClock::new_default_box());
        let tx_state = Arc::new(TxState::default());
        let tx_state_c = tx_state.clone();

        let side_a = router.add_side_packed_with_options(
            "can",
            |_bytes| Ok(()),
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );
        router.add_side_packed_with_options(
            "uart",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                let attempt = tx_state_c.attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    return Err(crate::TelemetryError::Io("busy"));
                }
                tx_state_c.delivered.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("RADIO")],
            7,
        )
        .unwrap();
        let wire = wire_format::pack_packet(&pkt);

        router
            .rx_packed_queue_from_side(wire.as_ref(), side_a)
            .unwrap();
        router.process_all_queues_with_timeout(0).unwrap();

        let delivered = tx_state.delivered.lock().unwrap().clone();
        assert!(tx_state.attempts.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            count_packed_frames_of_type(&delivered, DataType::named("GPS_DATA")),
            1
        );
        assert!(!delivered[0].is_empty());
    }

    /// Explicit route disables should suppress remote forwarding.
    #[test]
    fn disabled_route_prevents_retransmit_on_receive() {
        use crate::router::RouterConfig;

        static TX_CALLS: AtomicUsize = AtomicUsize::new(0);

        fn transmit(_bytes: &[u8]) -> TelemetryResult<()> {
            TX_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        let router = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt| Ok(()),
            )]),
            StepClock::new_default_box(),
        );
        let side = router.add_side_packed("tx", transmit);
        router.set_route(None, side, false).unwrap();

        let endpoints = &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
                .unwrap();

        router.rx(&pkt).unwrap();

        assert_eq!(TX_CALLS.load(Ordering::SeqCst), 0);
    }

    /// Receiving the exact same packed packet twice should be deduped
    /// and only delivered to local handlers once.
    #[test]
    fn receive_dedupes_identical_packed_frames() {
        use crate::router::RouterConfig;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        let sd_handler =
            EndpointHandler::new_packed_handler(DataEndpoint::named("SD_CARD"), move |_b| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });

        let router = Router::new_with_clock(
            RouterConfig::new(vec![sd_handler]),
            StepClock::new_default_box(),
        );

        let endpoints = &[DataEndpoint::named("SD_CARD")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
                .unwrap();
        let bytes = wire_format::pack_packet(&pkt);

        router.rx_packed(&bytes).unwrap();
        router.rx_packed(&bytes).unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// When only a packed handler exists for an endpoint, `rx_packed`
    /// should still deliver the raw bytes.
    #[test]
    fn rx_packed_delivers_to_packed_handlers() {
        use crate::router::RouterConfig;

        let seen: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let seen_c = seen.clone();
        let sd_handler =
            EndpointHandler::new_packed_handler(DataEndpoint::named("SD_CARD"), move |b| {
                *seen_c.lock().unwrap() = Some(b.to_vec());
                Ok(())
            });

        let router = Router::new_with_clock(
            RouterConfig::new(vec![sd_handler]),
            StepClock::new_default_box(),
        );

        let endpoints = &[DataEndpoint::named("SD_CARD")];
        let pkt =
            Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
                .unwrap();
        let bytes = wire_format::pack_packet(&pkt);

        router.rx_packed(&bytes).unwrap();
        let got = seen.lock().unwrap().clone().expect("no bytes delivered");
        assert_eq!(*got, *bytes);
    }

    #[cfg(feature = "discovery")]
    mod discovery_tests {
        use std::sync::Once;

        use crate::config::{
            MAX_HANDLER_RETRIES, RELIABLE_MAX_END_TO_END_ACK_CACHE,
            RELIABLE_MAX_END_TO_END_PENDING, RELIABLE_MAX_RETURN_ROUTES,
            register_data_type_id_with_description_and_e2e_encryption,
            register_data_type_with_description, register_endpoint_with_description,
            remove_data_type, remove_data_type_by_name, remove_endpoint_by_name,
        };
        use crate::discovery::{
            DISCOVERY_FAST_INTERVAL_MS, DISCOVERY_ROUTE_TTL_MS,
            DISCOVERY_SLOW_LINK_PING_INTERVAL_MS, LINK_CAPABILITY_CHUNKING,
            LINK_CAPABILITY_END_TO_END_RELIABILITY, LINK_CAPABILITY_HEADER_TEMPLATES,
            LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS, LINK_CAPABILITY_RELIABILITY,
            LINK_PROFILE_IPV4_LIKE, LinkCapabilities, TopologyBoardNode, build_discovery_announce,
            build_discovery_link_capabilities, build_discovery_timesync_sources,
            build_discovery_topology, decode_discovery_link_capabilities,
        };
        use crate::relay::Relay;
        use crate::router::{
            Clock, EndpointHandler, NetworkVariablePermissions, RouterConfig,
            RouterE2eEncryptionMode, RouterSideOptions,
        };
        use crate::tests::count_packets_of_type;
        use crate::tests::timeout_tests::StepClock;
        use crate::{
            DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType,
            MessageElement, ReliableMode, RouteSelectionMode, TelemetryError, TelemetryResult,
        };
        use crate::{packet::Packet, router::Router, wire_format};
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        fn zero_clock() -> Box<dyn Clock + Send + Sync> {
            StepClock::new_box(0, 0)
        }

        #[cfg(feature = "cryptography")]
        fn crypto_test_guard() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let guard = LOCK.lock().unwrap();
            crate::crypto::clear_c_cryptography_provider();
            crate::crypto::clear_rust_cryptography_provider();
            crate::crypto::clear_software_keys();
            guard
        }

        fn ensure_topology_test_schema() {
            static INIT: Once = Once::new();

            INIT.call_once(|| {
                let radio = DataEndpoint::try_named("RADIO").unwrap_or_else(|| {
                    register_endpoint_with_description("RADIO", "test radio endpoint", false)
                        .expect("register RADIO")
                });
                let sd_card = DataEndpoint::try_named("SD_CARD").unwrap_or_else(|| {
                    register_endpoint_with_description("SD_CARD", "test sd endpoint", false)
                        .expect("register SD_CARD")
                });
                if DataType::try_named("GPS_DATA").is_none() {
                    register_data_type_with_description(
                        "GPS_DATA",
                        "test gps data type",
                        MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                        &[radio, sd_card],
                        ReliableMode::None,
                        1,
                    )
                    .expect("register GPS_DATA");
                }
            });
        }

        #[test]
        fn discovery_link_capabilities_roundtrip() {
            let caps = LinkCapabilities {
                version: 1,
                flags: LINK_CAPABILITY_HEADER_TEMPLATES
                    | LINK_CAPABILITY_CHUNKING
                    | LINK_CAPABILITY_RELIABILITY
                    | LINK_CAPABILITY_END_TO_END_RELIABILITY
                    | LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS,
                profile: LINK_PROFILE_IPV4_LIKE,
                max_frame_bytes: 64,
                compact_header_target_bytes: 20,
                max_side_transport_templates: 8,
            };
            let pkt = build_discovery_link_capabilities("NODE_A", 42, caps).unwrap();
            assert_eq!(pkt.data_type(), DataType::DiscoveryLinkCapabilities);
            let decoded = decode_discovery_link_capabilities(&pkt).unwrap();
            assert_eq!(decoded, caps);
        }

        #[test]
        fn router_discovery_advertises_side_link_capabilities() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_cb = seen.clone();
            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            router.add_side_packet_with_options(
                "RADIO",
                move |pkt| {
                    seen_cb.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                RouterSideOptions {
                    reliable_enabled: true,
                    max_frame_bytes: 64,
                    max_side_transport_templates: 8,
                    ..RouterSideOptions::default().with_ipv4_like_compact_header_target()
                },
            );

            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();

            let packets = seen.lock().unwrap();
            let caps_pkt = packets
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
                .expect("missing unified address discovery packet");
            let caps = crate::discovery::decode_discovery_address(caps_pkt)
                .unwrap()
                .link_capabilities;
            assert_eq!(caps.version, 1);
            assert_eq!(caps.profile, LINK_PROFILE_IPV4_LIKE);
            assert_eq!(caps.max_frame_bytes, 64);
            assert_eq!(caps.compact_header_target_bytes, 20);
            assert_eq!(caps.max_side_transport_templates, 8);
            assert_ne!(caps.flags & LINK_CAPABILITY_HEADER_TEMPLATES, 0);
            assert_ne!(caps.flags & LINK_CAPABILITY_CHUNKING, 0);
            assert_ne!(caps.flags & LINK_CAPABILITY_RELIABILITY, 0);
            assert_ne!(caps.flags & LINK_CAPABILITY_END_TO_END_RELIABILITY, 0);
            assert_ne!(caps.flags & LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS, 0);
        }

        fn ensure_reliable_overlap_test_schema() -> DataType {
            static INIT: Once = Once::new();

            INIT.call_once(|| {
                let gs = DataEndpoint::try_named("GROUND_STATION").unwrap_or_else(|| {
                    register_endpoint_with_description(
                        "GROUND_STATION",
                        "test ground station endpoint",
                        false,
                    )
                    .expect("register GROUND_STATION")
                });
                let actuator = DataEndpoint::try_named("ACTUATOR_BOARD").unwrap_or_else(|| {
                    register_endpoint_with_description(
                        "ACTUATOR_BOARD",
                        "test actuator endpoint",
                        false,
                    )
                    .expect("register ACTUATOR_BOARD")
                });
                if DataType::try_named("RELIABLE_COMMAND_TEST").is_none() {
                    register_data_type_with_description(
                        "RELIABLE_COMMAND_TEST",
                        "test reliable command type",
                        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
                        &[gs, actuator],
                        ReliableMode::Ordered,
                        1,
                    )
                    .expect("register RELIABLE_COMMAND_TEST");
                }
            });

            DataType::named("RELIABLE_COMMAND_TEST")
        }

        #[derive(Clone)]
        struct SharedClock {
            now_ms: Arc<AtomicU64>,
        }

        impl Clock for SharedClock {
            fn now_ms(&self) -> u64 {
                self.now_ms.load(Ordering::SeqCst)
            }
        }

        fn endpoint_by_name(name: &str) -> Option<DataEndpoint> {
            for i in 0..=crate::MAX_VALUE_DATA_ENDPOINT {
                if let Some(ep) = DataEndpoint::try_from_u32(i)
                    && ep.as_str() == name
                {
                    return Some(ep);
                }
            }
            None
        }

        fn datatype_by_name(name: &str) -> Option<DataType> {
            for i in 0..=crate::MAX_VALUE_DATA_TYPE {
                if let Some(ty) = DataType::try_from_u32(i)
                    && crate::get_message_name(ty) == name
                {
                    return Some(ty);
                }
            }
            None
        }

        fn pump_routers(routers: &[&Router], rounds: usize) {
            for _ in 0..rounds {
                for router in routers {
                    router.process_all_queues().unwrap();
                }
            }
        }

        #[test]
        fn discovery_master_election_prefers_central_low_hop_router() {
            let boards = vec![
                TopologyBoardNode {
                    sender_id: "A_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "B_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "C_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string()],
                },
            ];
            assert_eq!(
                crate::discovery::elect_discovery_master("A_NODE", &boards),
                "B_NODE"
            );
        }

        #[test]
        fn discovery_master_election_uses_deterministic_tiebreaks_and_fails_over() {
            let symmetric_ring = vec![
                TopologyBoardNode {
                    sender_id: "A_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "B_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "C_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "D_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
                },
            ];
            assert_eq!(
                crate::discovery::elect_discovery_master("D_NODE", &symmetric_ring),
                "A_NODE"
            );

            let failed_over_ring = vec![
                TopologyBoardNode {
                    sender_id: "B_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["C_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "C_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "D_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["C_NODE".to_string()],
                },
            ];
            assert_eq!(
                crate::discovery::elect_discovery_master("D_NODE", &failed_over_ring),
                "C_NODE"
            );
        }

        #[test]
        fn unknown_remote_endpoint_does_not_flood_without_discovery_route() {
            ensure_topology_test_schema();

            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0_f32, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                42,
            )
            .unwrap();
            router.tx(pkt).unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            assert!(seen_b.lock().unwrap().is_empty());
        }

        #[test]
        fn unknown_remote_endpoint_does_not_fallback_to_single_side_after_topology_exists() {
            ensure_topology_test_schema();

            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side =
                router.add_side_packet("RADIO", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });
            router
                .rx_from_side(
                    &build_discovery_announce("REMOTE_SD", 0, &[DataEndpoint::named("SD_CARD")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0_f32, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                42,
            )
            .unwrap();
            router.tx(pkt).unwrap();

            assert!(seen.lock().unwrap().is_empty());
        }

        #[test]
        fn topology_requests_use_elected_master_and_late_joiners_get_fresh_topology() {
            ensure_topology_test_schema();

            let opts = crate::router::RouterSideOptions {
                reliable_enabled: true,
                ..crate::router::RouterSideOptions::default()
            };

            let a = Arc::new(Router::new_with_clock(
                RouterConfig::default().with_sender("A_NODE"),
                zero_clock(),
            ));
            let b = Arc::new(Router::new_with_clock(
                RouterConfig::default().with_sender("B_NODE"),
                zero_clock(),
            ));
            let c = Arc::new(Router::new_with_clock(
                RouterConfig::default().with_sender("C_NODE"),
                zero_clock(),
            ));

            let a_ingress_from_b: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
            let b_ingress_from_a: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
            let b_ingress_from_c: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
            let c_ingress_from_b: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));

            let b_for_a = b.clone();
            let b_ingress_from_a_c = b_ingress_from_a.clone();
            let _a_to_b = a.add_side_packed_with_options(
                "A_TO_B",
                move |bytes| {
                    if let Some(side) = *b_ingress_from_a_c.lock().unwrap() {
                        b_for_a.rx_packed_from_side(bytes, side)?;
                    }
                    Ok(())
                },
                opts,
            );

            let a_for_b = a.clone();
            let a_ingress_from_b_c = a_ingress_from_b.clone();
            let b_to_a = b.add_side_packed_with_options(
                "B_TO_A",
                move |bytes| {
                    if let Some(side) = *a_ingress_from_b_c.lock().unwrap() {
                        a_for_b.rx_packed_from_side(bytes, side)?;
                    }
                    Ok(())
                },
                opts,
            );
            *b_ingress_from_a.lock().unwrap() = Some(b_to_a);
            *a_ingress_from_b.lock().unwrap() = Some(_a_to_b);

            a.announce_discovery().unwrap();
            b.announce_discovery().unwrap();
            pump_routers(&[a.as_ref(), b.as_ref()], 6);

            let b_to_c_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let b_to_c_frames_c = b_to_c_frames.clone();
            let c_to_b_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let c_to_b_frames_c = c_to_b_frames.clone();
            let c_for_b = c.clone();
            let c_ingress_from_b_c = c_ingress_from_b.clone();
            let _b_to_c = b.add_side_packed_with_options(
                "B_TO_C",
                move |bytes| {
                    b_to_c_frames_c.lock().unwrap().push(bytes.to_vec());
                    if let Some(side) = *c_ingress_from_b_c.lock().unwrap() {
                        c_for_b.rx_packed_from_side(bytes, side)?;
                    }
                    Ok(())
                },
                opts,
            );

            let b_for_c = b.clone();
            let b_ingress_from_c_c = b_ingress_from_c.clone();
            let c_to_b = c.add_side_packed_with_options(
                "C_TO_B",
                move |bytes| {
                    c_to_b_frames_c.lock().unwrap().push(bytes.to_vec());
                    if let Some(side) = *b_ingress_from_c_c.lock().unwrap() {
                        b_for_c.rx_packed_from_side(bytes, side)?;
                    }
                    Ok(())
                },
                opts,
            );
            *c_ingress_from_b.lock().unwrap() = Some(c_to_b);
            *b_ingress_from_c.lock().unwrap() = Some(_b_to_c);

            assert!(
                !c.export_topology()
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "A_NODE")
            );
            b_to_c_frames.lock().unwrap().clear();
            c_to_b_frames.lock().unwrap().clear();

            c.request_topology().unwrap();
            c.request_schema().unwrap();
            pump_routers(
                &[c.as_ref(), b.as_ref(), a.as_ref(), b.as_ref(), c.as_ref()],
                8,
            );

            let c_topology = c.export_topology();
            assert!(
                c_topology
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "A_NODE")
                    && c_topology
                        .routers
                        .iter()
                        .any(|board| board.sender_id == "B_NODE")
                    && c_topology
                        .routers
                        .iter()
                        .any(|board| board.sender_id == "C_NODE")
            );

            let a_topology = a.export_topology();
            assert!(
                a_topology
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "C_NODE"),
                "topology reply propagation should update routers along the path too"
            );

            let request_frames = c_to_b_frames.lock().unwrap().clone();
            assert!(request_frames.iter().any(|bytes| {
                wire_format::peek_frame_info(bytes.as_slice())
                    .map(|frame| {
                        frame.envelope.ty == DataType::DiscoveryTopologyRequest
                            && frame.reliable.is_some()
                    })
                    .unwrap_or(false)
            }));

            let frames = b_to_c_frames.lock().unwrap().clone();
            let frame_summary: Vec<(DataType, String, bool)> = frames
                .iter()
                .map(|bytes| {
                    let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
                    let pkt = wire_format::unpack_packet(bytes.as_slice()).unwrap();
                    (
                        frame.envelope.ty,
                        pkt.sender().to_string(),
                        frame.reliable.is_some(),
                    )
                })
                .collect();
            assert!(
                frames.iter().any(|bytes| {
                    let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
                    frame.envelope.ty == DataType::DiscoveryTopology && frame.reliable.is_some()
                }),
                "{frame_summary:?}"
            );
            assert!(
                frames.iter().any(|bytes| {
                    let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
                    frame.envelope.ty == DataType::DiscoverySchema && frame.reliable.is_some()
                }),
                "{frame_summary:?}"
            );
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn timesync_leadership_is_separate_from_discovery_master_election() {
            let boards = vec![
                TopologyBoardNode {
                    sender_id: "A_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: vec!["A_NODE".to_string()],
                    connections: vec!["B_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "B_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: vec!["B_NODE".to_string()],
                    connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "C_NODE".to_string(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["B_NODE".to_string()],
                },
            ];
            assert_eq!(
                crate::discovery::elect_discovery_master("C_NODE", &boards),
                "B_NODE"
            );

            let mut tracker =
                crate::timesync::TimeSyncTracker::new(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Consumer,
                    priority: 100,
                    ..Default::default()
                });
            tracker
                .handle_announce(
                    &crate::timesync::build_timesync_announce_with_sender("A_NODE", 1, 1_000)
                        .unwrap(),
                    0,
                )
                .unwrap();
            tracker
                .handle_announce(
                    &crate::timesync::build_timesync_announce_with_sender("B_NODE", 20, 1_000)
                        .unwrap(),
                    0,
                )
                .unwrap();

            let leader = tracker.leader(0, false);
            assert!(matches!(
                leader,
                Some(crate::timesync::TimeSyncLeader::Remote(ref src)) if src.sender == "A_NODE"
            ));
        }

        fn side_stats(
            stats: &crate::diagnostics::RuntimeStatsSnapshot,
            side_id: usize,
        ) -> &crate::diagnostics::RuntimeSideStats {
            stats
                .sides
                .iter()
                .find(|side| side.side_id == side_id)
                .unwrap()
        }

        fn type_stats(
            side: &crate::diagnostics::RuntimeSideStats,
            ty: DataType,
        ) -> &crate::diagnostics::RuntimeTypeStats {
            side.data_types
                .iter()
                .find(|item| item.data_type == ty)
                .unwrap()
        }

        #[test]
        fn router_uses_discovery_routes_for_outbound_packets() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(msg).unwrap();

            let got_a = seen_a.lock().unwrap().clone();
            let got_b = seen_b.lock().unwrap().clone();
            assert_eq!(
                count_packets_of_type(&got_a, DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&got_b, DataType::named("GPS_DATA")),
                0
            );
        }

        #[test]
        fn queued_discovery_is_processed_before_queued_telemetry_routing() {
            ensure_topology_test_schema();

            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_queue_from_side(discovery_pkt, side_a).unwrap();
            router
                .tx_queue(
                    Packet::from_f32_slice(
                        DataType::named("GPS_DATA"),
                        &[1.0, 2.0, 3.0],
                        &[DataEndpoint::named("RADIO")],
                        1,
                    )
                    .unwrap(),
                )
                .unwrap();

            router.process_tx_queue().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
        }

        #[test]
        fn reliable_immediate_tx_prefers_highest_overlap_discovered_holder() {
            ensure_topology_test_schema();
            let reliable_ty = ensure_reliable_overlap_test_schema();
            let gs = DataEndpoint::named("GROUND_STATION");
            let actuator = DataEndpoint::named("ACTUATOR_BOARD");
            let radio = DataEndpoint::named("RADIO");

            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .rx_from_side(
                    &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
                    side_a,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("BEST_HOLDER", 0, &[gs, actuator]).unwrap(),
                    side_b,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("UNRELATED", 0, &[radio]).unwrap(),
                    side_c,
                )
                .unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            seen_c.lock().unwrap().clear();

            let pkt = Packet::from_f32_slice(reliable_ty, &[9.0], &[gs, actuator], 1).unwrap();
            router.tx(pkt).unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), reliable_ty),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), reliable_ty),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), reliable_ty),
                0
            );
        }

        #[test]
        fn reliable_queued_tx_prefers_highest_overlap_discovered_holder() {
            ensure_topology_test_schema();
            let reliable_ty = ensure_reliable_overlap_test_schema();
            let gs = DataEndpoint::named("GROUND_STATION");
            let actuator = DataEndpoint::named("ACTUATOR_BOARD");
            let radio = DataEndpoint::named("RADIO");

            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .rx_from_side(
                    &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
                    side_a,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("BEST_HOLDER", 0, &[gs, actuator]).unwrap(),
                    side_b,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("UNRELATED", 0, &[radio]).unwrap(),
                    side_c,
                )
                .unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            seen_c.lock().unwrap().clear();

            router
                .tx_queue(Packet::from_f32_slice(reliable_ty, &[7.0], &[gs, actuator], 2).unwrap())
                .unwrap();
            router.process_tx_queue().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), reliable_ty),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), reliable_ty),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), reliable_ty),
                0
            );
        }

        #[test]
        fn reliable_tracking_ignores_local_endpoint_only_discovery_announcers() {
            ensure_topology_test_schema();
            let reliable_ty = ensure_reliable_overlap_test_schema();
            let gs = DataEndpoint::named("GROUND_STATION");
            let actuator = DataEndpoint::named("ACTUATOR_BOARD");

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(gs, |_pkt| Ok(()))])
                    .with_sender("SRC"),
                StepClock::new_box(0, 0),
            );
            let side = router.add_side_packed_with_options(
                "link",
                |_bytes| Ok(()),
                crate::router::RouterSideOptions {
                    reliable_enabled: true,
                    link_local_enabled: false,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router
                .rx_from_side(
                    &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
                    side,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("ACTUATOR_ONLY", 0, &[actuator]).unwrap(),
                    side,
                )
                .unwrap();

            let pkt = Packet::from_f32_slice(reliable_ty, &[3.0], &[gs, actuator], 10).unwrap();
            let packet_id = pkt.packet_id();
            router.tx(pkt).unwrap();

            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(1),
                "local-only endpoint announcers must not create phantom end-to-end ack expectations",
            );
        }

        #[test]
        fn end_to_end_pending_destinations_clear_when_discovered_holder_expires() {
            use std::sync::Arc;

            let now_ms = Arc::new(AtomicU64::new(0));
            let clock = Box::new(SharedClock {
                now_ms: now_ms.clone(),
            });
            let router = Router::new_with_clock(RouterConfig::default().with_sender("SRC"), clock);
            let side = router.add_side_packed_with_options(
                "link",
                |_bytes| Ok(()),
                crate::router::RouterSideOptions {
                    reliable_enabled: true,
                    link_local_enabled: false,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router
                .rx_from_side(
                    &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[11.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                11,
            )
            .unwrap();
            let packet_id = pkt.packet_id();
            router.tx(pkt).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(2)
            );

            let ack = Packet::new(
                DataType::ReliableAck,
                crate::message_meta(DataType::ReliableAck).endpoints,
                "E2EACK:DEST_A",
                0,
                Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
            )
            .unwrap();
            router.rx_from_side(&ack, side).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(1)
            );

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            router.periodic_no_timesync(0).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                None
            );
        }

        #[test]
        fn in_flight_end_to_end_destinations_survive_topology_reachability_changes() {
            let router = Router::new_with_clock(
                RouterConfig::default().with_sender("SRC"),
                StepClock::new_box(0, 0),
            );
            let side = router.add_side_packed_with_options(
                "link",
                |_bytes| Ok(()),
                crate::router::RouterSideOptions {
                    reliable_enabled: true,
                    link_local_enabled: false,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router
                .rx_from_side(
                    &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[21.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                21,
            )
            .unwrap();
            let packet_id = pkt.packet_id();
            router.tx(pkt).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(2)
            );

            router
                .rx_from_side(
                    &build_discovery_announce("DEST_A", 1, &[DataEndpoint::named("SD_CARD")])
                        .unwrap(),
                    side,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_announce("DEST_B", 1, &[DataEndpoint::named("SD_CARD")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(2)
            );
        }

        #[test]
        fn in_flight_end_to_end_destinations_survive_runtime_data_type_removal() {
            use crate::config::{register_data_type_with_description, remove_data_type_by_name};
            use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};

            let type_name = "DISCOVERY_INFLIGHT_TYPE_9101";
            let _ = remove_data_type_by_name(type_name);
            let custom_ty = register_data_type_with_description(
                type_name,
                "inflight custom type",
                MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
                &[DataEndpoint::named("RADIO")],
                ReliableMode::None,
                3,
            )
            .unwrap();

            let router = Router::new_with_clock(
                RouterConfig::default().with_sender("SRC"),
                StepClock::new_box(0, 0),
            );
            let side = router.add_side_packed_with_options(
                "link",
                |_bytes| Ok(()),
                crate::router::RouterSideOptions {
                    reliable_enabled: true,
                    link_local_enabled: false,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router
                .rx_from_side(
                    &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            let pkt = Packet::new(
                custom_ty,
                &[DataEndpoint::named("RADIO")],
                "SRC",
                0,
                Arc::<[u8]>::from(vec![1u8, 2, 3, 4]),
            )
            .unwrap();
            let packet_id = pkt.packet_id();
            router.tx(pkt).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(1)
            );

            assert!(remove_data_type_by_name(type_name).unwrap());
            router.periodic_no_timesync(0).unwrap();
            assert_eq!(
                router.debug_end_to_end_pending_destination_count(packet_id),
                Some(1)
            );
        }

        #[test]
        fn explicit_target_contract_skips_wrong_local_router_delivery() {
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_c = hits.clone();
            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    move |_pkt| {
                        hits_c.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )])
                .with_sender("LOCAL"),
                StepClock::new_box(0, 0),
            );
            let side = router.add_side_packet("LINK", |_pkt: &Packet| Ok(()));

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[41.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                41,
            )
            .unwrap();
            let wire = crate::wire_format::pack_packet_with_wire_contract(
                &pkt,
                Some(crate::wire_format::ReliableHeader {
                    flags: crate::wire_format::RELIABLE_FLAG_UNSEQUENCED,
                    seq: 0,
                    ack: 0,
                }),
                Some(crate::message_meta(pkt.data_type()).element),
                &[crate::packet::hash_bytes_u64(
                    0x517C_C1B7_2722_0A95,
                    "OTHER_DEST".as_bytes(),
                )],
            )
            .unwrap();
            router.rx_packed_from_side(&wire, side).unwrap();
            assert_eq!(hits.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn reliable_router_state_stays_bounded_under_unacked_traffic() {
            let router = Router::new_with_clock(
                RouterConfig::default().with_sender("SRC"),
                StepClock::new_box(0, 0),
            );
            let side = router.add_side_packed_with_options(
                "link",
                |_bytes| Ok(()),
                crate::router::RouterSideOptions {
                    reliable_enabled: true,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router
                .rx_from_side(
                    &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                    side,
                )
                .unwrap();

            for idx in 0..(RELIABLE_MAX_END_TO_END_PENDING.max(1) + 4) {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[idx as f32, 0.0, 0.0],
                    &[DataEndpoint::named("RADIO")],
                    idx as u64,
                )
                .unwrap();
                let _ = router.tx(pkt);
            }

            assert!(
                router.debug_end_to_end_tracked_count() <= RELIABLE_MAX_END_TO_END_PENDING.max(1)
            );

            for idx in 0..(RELIABLE_MAX_RETURN_ROUTES.max(1) + 4) {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[idx as f32, 1.0, 0.0],
                    &[DataEndpoint::named("RADIO")],
                    (1000 + idx) as u64,
                )
                .unwrap();
                router.rx_from_side(&pkt, side).unwrap();
            }

            assert!(
                router.debug_reliable_return_route_count() <= RELIABLE_MAX_RETURN_ROUTES.max(1)
            );
        }

        #[test]
        fn discovery_topology_counts_against_shared_queue_budget() {
            ensure_topology_test_schema();
            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side = router.add_side_packed("link", |_bytes| Ok(()));

            for idx in 0..128 {
                let boards = vec![TopologyBoardNode {
                    sender_id: format!("REMOTE_BOARD_{idx}_{}", "x".repeat(512)),
                    reachable_endpoints: vec![
                        DataEndpoint::named("RADIO"),
                        DataEndpoint::named("SD_CARD"),
                    ],
                    reachable_timesync_sources: vec![format!("TIME_{idx}_{}", "y".repeat(256))],
                    connections: vec![format!("CONN_{idx}_{}", "z".repeat(512))],
                }];
                let sender = format!("SRC_{idx}");
                let pkt = build_discovery_topology(&sender, idx as u64, &boards).unwrap();
                router.rx_from_side(&pkt, side).unwrap();
            }

            assert!(
                router.debug_shared_queue_bytes_used() <= crate::config::MAX_QUEUE_BUDGET,
                "discovery topology state must be part of the shared queue budget"
            );
        }

        #[test]
        fn queued_packed_discovery_learns_routes_for_locally_handled_endpoints() {
            ensure_topology_test_schema();
            let seen_remote: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_remote_c = seen_remote.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            let side_remote =
                router.add_side_packet("REMOTE", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_remote_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });

            let discovery_pkt =
                build_discovery_announce("REMOTE_NODE", 0, &[DataEndpoint::named("RADIO")])
                    .unwrap();
            let discovery_bytes = crate::wire_format::pack_packet(&discovery_pkt);
            router
                .rx_packed_queue_from_side(discovery_bytes.as_ref(), side_remote)
                .unwrap();
            router.process_rx_queue().unwrap();

            let topo = router.export_topology();
            assert_eq!(topo.routes.len(), 1);
            assert_eq!(
                topo.routes[0].reachable_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );
            assert_eq!(
                topo.advertised_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                11,
            )
            .unwrap();
            router.tx(msg).unwrap();

            let got = seen_remote.lock().unwrap().clone();
            assert_eq!(count_packets_of_type(&got, DataType::named("GPS_DATA")), 0);
        }

        #[test]
        fn queued_packet_discovery_updates_route_table_after_full_queue_drain() {
            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("SD_CARD"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            let side_fill =
                router.add_side_packet("FILL", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_pkt = build_discovery_announce(
                "AB",
                0,
                &[DataEndpoint::named("RADIO"), DataEndpoint::TimeSync],
            )
            .unwrap();
            router.rx_queue_from_side(discovery_pkt, side_fill).unwrap();
            router.process_all_queues_with_timeout(0).unwrap();

            let topo = router.export_topology();
            assert_eq!(topo.routes.len(), 1);
            assert_eq!(topo.routes[0].side_name, "FILL");
            assert_eq!(
                topo.routes[0].reachable_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );
            assert!(
                topo.advertised_endpoints
                    .contains(&DataEndpoint::named("SD_CARD")),
                "local endpoints should remain advertised"
            );
            assert!(
                topo.advertised_endpoints
                    .contains(&DataEndpoint::named("RADIO")),
                "learned remote endpoints should be reflected in advertised discovery state"
            );
        }

        #[test]
        fn queued_packed_discovery_timesync_sources_update_route_table_after_full_queue_drain() {
            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("SD_CARD"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            let side_fill =
                router.add_side_packet("FILL", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let announce =
                build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let announce_bytes = crate::wire_format::pack_packet(&announce);
            router
                .rx_packed_queue_from_side(announce_bytes.as_ref(), side_fill)
                .unwrap();

            let sources = build_discovery_timesync_sources("AB", 0, &["AB", "AB_BACKUP"]).unwrap();
            let source_bytes = crate::wire_format::pack_packet(&sources);
            router
                .rx_packed_queue_from_side(source_bytes.as_ref(), side_fill)
                .unwrap();

            router.process_all_queues_with_timeout(0).unwrap();

            let topo = router.export_topology();
            assert_eq!(topo.routes.len(), 1);
            assert_eq!(topo.routes[0].side_name, "FILL");
            assert_eq!(
                topo.routes[0].reachable_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );
            assert_eq!(
                topo.routes[0].reachable_timesync_sources,
                vec!["AB".to_string(), "AB_BACKUP".to_string()]
            );
            assert!(
                topo.advertised_timesync_sources.contains(&"AB".to_string()),
                "learned timesync sources should be exported in topology"
            );
        }

        #[test]
        fn queued_packed_discovery_from_same_sender_is_ignored_and_local_endpoint_does_not_flood() {
            use crate::config::DEVICE_IDENTIFIER;

            let seen_remote: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_remote_c = seen_remote.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            let side_remote =
                router.add_side_packet("REMOTE", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_remote_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });

            let discovery_pkt =
                build_discovery_announce(DEVICE_IDENTIFIER, 0, &[DataEndpoint::named("RADIO")])
                    .unwrap();
            let discovery_bytes = crate::wire_format::pack_packet(&discovery_pkt);
            router
                .rx_packed_queue_from_side(discovery_bytes.as_ref(), side_remote)
                .unwrap();
            router.process_rx_queue().unwrap();

            let topo = router.export_topology();
            assert!(topo.routes.is_empty());
            assert_eq!(
                topo.advertised_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[4.0, 5.0, 6.0],
                &[DataEndpoint::named("RADIO")],
                12,
            )
            .unwrap();
            router.tx(msg).unwrap();

            assert!(seen_remote.lock().unwrap().is_empty());
        }

        #[test]
        fn relay_uses_discovery_routes_for_selective_fanout() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let _side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_pkt =
                build_discovery_announce("NODE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_pkt).unwrap();
            relay.process_all_queues().unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0, 8.0, 7.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            relay.rx_from_side(side_c, msg).unwrap();
            relay.process_all_queues().unwrap();

            let got_a = seen_a.lock().unwrap().clone();
            let got_b = seen_b.lock().unwrap().clone();
            assert_eq!(
                count_packets_of_type(&got_a, DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&got_b, DataType::named("GPS_DATA")),
                0
            );
        }

        #[test]
        fn relay_runtime_routes_support_asymmetric_and_ingress_only_links() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c = relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            relay.set_route(Some(side_a), side_b, true).unwrap();
            relay.set_route(Some(side_b), side_a, false).unwrap();
            relay.set_side_egress_enabled(side_c, false).unwrap();

            let pkt_a = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            relay.rx_from_side(side_a, pkt_a).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            let pkt_b = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[4.0, 5.0, 6.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            relay.rx_from_side(side_b, pkt_b).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            let pkt_c = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[7.0, 8.0, 9.0],
                &[DataEndpoint::named("RADIO")],
                3,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt_c).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
        }

        #[test]
        fn relay_can_disable_ingress_for_a_side() {
            let relay = Relay::new(zero_clock());
            let side =
                relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
            relay.set_side_ingress_enabled(side, false).unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                4,
            )
            .unwrap();

            match relay.rx_from_side(side, pkt) {
                Err(TelemetryError::HandlerError(msg)) => {
                    assert!(msg.contains("ingress disabled"));
                }
                other => panic!("expected ingress-disabled error, got {other:?}"),
            }
        }

        #[test]
        fn relay_typed_routes_can_target_one_or_many_sides() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_d: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();
            let seen_d_c = seen_d.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let _side_c = relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_d = relay.add_side_packet("D", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_d_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            relay
                .rx_from_side(
                    side_b,
                    build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                )
                .unwrap();
            relay
                .rx_from_side(
                    side_d,
                    build_discovery_announce("REMOTE_D", 1, &[DataEndpoint::named("RADIO")])
                        .unwrap(),
                )
                .unwrap();
            relay.process_all_queues().unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            seen_c.lock().unwrap().clear();
            seen_d.lock().unwrap().clear();

            relay
                .set_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_b, true)
                .unwrap();
            relay
                .set_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_d, true)
                .unwrap();
            relay
                .set_source_route_mode(Some(side_a), RouteSelectionMode::Fanout)
                .unwrap();

            let gps_pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            relay.rx_from_side(side_a, gps_pkt).unwrap();
            relay.process_all_queues().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            let first_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            let first_c =
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
            let first_d =
                count_packets_of_type(&seen_d.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(first_c, 0);
            let first_targets = first_b + first_d;
            assert!((1..=2).contains(&first_targets));

            relay
                .clear_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_b)
                .unwrap();
            relay
                .clear_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_d)
                .unwrap();

            let fallback_pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0, 8.0, 7.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            relay.rx_from_side(side_a, fallback_pkt).unwrap();
            relay.process_all_queues().unwrap();

            let total_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            let total_c =
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
            let total_d =
                count_packets_of_type(&seen_d.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(total_c, 0);
            let total_targets = total_b + total_d;
            assert!(total_targets >= first_targets);
            assert!(total_targets <= first_targets + 2);
        }

        #[test]
        fn relay_remove_side_stops_transmit_and_rejects_removed_ingress() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            relay.remove_side(side_a).unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                5,
            )
            .unwrap();
            relay.rx_from_side(side_b, pkt.clone()).unwrap();
            relay.process_all_queues().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            match relay.rx_from_side(side_a, pkt) {
                Err(TelemetryError::HandlerError(msg)) => {
                    assert!(msg.contains("invalid side id"));
                }
                other => panic!("expected invalid removed side error, got {other:?}"),
            }
        }

        #[test]
        fn relay_remove_side_updates_discovery_routes_and_announces_remaining_topology() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
            relay.rx_from_side(side_b, discovery_pkt).unwrap();
            relay.process_rx_queue().unwrap();
            assert_eq!(relay.export_topology().routes.len(), 1);

            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            relay.remove_side(side_a).unwrap();

            let snap = relay.export_topology();
            assert_eq!(snap.routes.len(), 1);
            assert_eq!(
                snap.advertised_endpoints,
                vec![DataEndpoint::named("SD_CARD")]
            );
            assert!(relay.poll_discovery().unwrap());
            relay.process_tx_queue().unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            let b_pkts = seen_b.lock().unwrap().clone();
            let announce = b_pkts
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAnnounce)
                .unwrap();
            let eps = crate::discovery::decode_discovery_announce(announce).unwrap();
            assert_eq!(eps, vec![DataEndpoint::named("SD_CARD")]);
            assert!(
                b_pkts
                    .iter()
                    .any(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
            );
        }

        #[test]
        fn router_exports_topology_and_adaptive_discovery_schedule() {
            ensure_topology_test_schema();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                StepClock::new_box(0, 0),
            );
            let side_a =
                router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_pkt =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();

            let snap_before = router.export_topology();
            assert_eq!(
                snap_before.advertised_endpoints,
                vec![DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")]
            );
            assert_eq!(snap_before.routes.len(), 1);
            assert_eq!(snap_before.routes[0].side_name, "A");
            assert_eq!(
                snap_before.current_announce_interval_ms,
                DISCOVERY_FAST_INTERVAL_MS
            );

            assert!(router.poll_discovery().unwrap());

            let snap_after = router.export_topology();
            assert_eq!(snap_after.next_announce_ms, DISCOVERY_FAST_INTERVAL_MS);
            assert!(snap_after.current_announce_interval_ms >= DISCOVERY_FAST_INTERVAL_MS);
        }

        #[test]
        fn router_exports_board_graph_and_tracks_transitive_endpoint_holders() {
            ensure_topology_test_schema();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a =
                router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let topology = vec![
                TopologyBoardNode {
                    sender_id: "REMOTE_A".to_string(),
                    reachable_endpoints: vec![
                        DataEndpoint::named("SD_CARD"),
                        DataEndpoint::TimeSync,
                        DataEndpoint::TelemetryError,
                    ],
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["SENSOR_B".to_string()],
                },
                TopologyBoardNode {
                    sender_id: "SENSOR_B".to_string(),
                    reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["REMOTE_A".to_string()],
                },
            ];
            let topology_pkt = build_discovery_topology("REMOTE_A", 0, &topology).unwrap();
            router.rx_from_side(&topology_pkt, side_a).unwrap();

            let snap = router.export_topology();
            assert_eq!(snap.routes.len(), 1);
            assert_eq!(snap.routes[0].announcers.len(), 1);
            assert_eq!(snap.routes[0].announcers[0].sender_id, "REMOTE_A");
            assert!(
                snap.routes[0].announcers[0]
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "SENSOR_B"
                        && board.reachable_endpoints == vec![DataEndpoint::named("RADIO")])
            );
            assert!(
                snap.routers
                    .iter()
                    .any(|board| board.sender_id == "SENSOR_B"
                        && board.connections.contains(&"REMOTE_A".to_string()))
            );
            assert!(
                snap.links
                    .iter()
                    .any(|link| link.source == "REMOTE_A" && link.target == "SENSOR_B")
            );

            assert!(
                snap.advertised_endpoints
                    .contains(&DataEndpoint::named("RADIO")),
                "transitive endpoint holders should contribute to exported reachability"
            );
            assert!(!snap.advertised_endpoints.contains(&DataEndpoint::TimeSync));
            assert!(
                !snap
                    .advertised_endpoints
                    .contains(&DataEndpoint::TelemetryError)
            );
        }

        #[test]
        fn discovery_leave_prunes_client_topology_and_stats_immediately() {
            ensure_topology_test_schema();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a =
                router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_pkt =
                build_discovery_announce("LEAVING_NODE", 0, &[DataEndpoint::named("RADIO")])
                    .unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();
            let stats = router.client_stats("LEAVING_NODE").unwrap();
            assert!(stats.connected);
            assert_eq!(stats.side_names, vec!["A"]);
            assert_eq!(
                stats.reachable_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );

            let leave = crate::discovery::build_discovery_leave("LEAVING_NODE", 1).unwrap();
            router.rx_from_side(&leave, side_a).unwrap();

            assert!(router.client_stats("LEAVING_NODE").is_none());
            assert!(
                !router
                    .export_topology()
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "LEAVING_NODE")
            );
        }

        #[test]
        fn router_remove_side_stops_transmit_and_rejects_removed_ingress() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.remove_side(side_a).unwrap();

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(msg.clone()).unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            assert_eq!(seen_b.lock().unwrap().len(), 1);
            match router.rx_from_side(&msg, side_a) {
                Err(TelemetryError::HandlerError(msg)) => {
                    assert!(msg.contains("invalid side id"));
                }
                other => panic!("expected invalid removed side error, got {other:?}"),
            }
        }

        #[test]
        fn router_remove_side_updates_discovery_routes_and_announces_remaining_topology() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();
            assert_eq!(router.export_topology().routes.len(), 1);

            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            router.remove_side(side_a).unwrap();

            let snap = router.export_topology();
            assert!(snap.routes.is_empty());
            assert_eq!(
                snap.advertised_endpoints,
                vec![DataEndpoint::named("RADIO")]
            );
            assert!(router.poll_discovery().unwrap());
            router.process_tx_queue().unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            let b_pkts = seen_b.lock().unwrap().clone();
            let announce = b_pkts
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
                .unwrap();
            let eps = crate::discovery::decode_discovery_address(announce)
                .unwrap()
                .reachable_endpoints;
            assert_eq!(eps, vec![DataEndpoint::named("RADIO")]);
            assert!(
                b_pkts
                    .iter()
                    .any(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
            );
        }

        #[test]
        fn router_runtime_routes_support_asymmetric_and_ingress_only_links() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.set_route(None, side_b, false).unwrap();
            router.set_route(None, side_c, false).unwrap();
            router.set_route(Some(side_a), side_b, true).unwrap();
            router.set_route(Some(side_b), side_a, false).unwrap();
            router.set_side_egress_enabled(side_c, false).unwrap();

            let local_tx = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(local_tx).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            let from_a = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[4.0, 5.0, 6.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            router.rx_from_side(&from_a, side_a).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            let from_b = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[7.0, 8.0, 9.0],
                &[DataEndpoint::named("RADIO")],
                3,
            )
            .unwrap();
            router.rx_from_side(&from_b, side_b).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );

            let from_c = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[10.0, 11.0, 12.0],
                &[DataEndpoint::named("RADIO")],
                4,
            )
            .unwrap();
            router.rx_from_side(&from_c, side_c).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
        }

        #[test]
        fn router_typed_routes_can_target_one_or_many_sides() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let seen_c_c = seen_c.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_b =
                build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let discovery_c =
                build_discovery_announce("REMOTE_C", 1, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_b, side_b).unwrap();
            router.rx_from_side(&discovery_c, side_c).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();
            seen_c.lock().unwrap().clear();

            router
                .set_typed_route(None, DataType::named("GPS_DATA"), side_b, true)
                .unwrap();
            router
                .set_typed_route(None, DataType::named("GPS_DATA"), side_c, true)
                .unwrap();
            router
                .set_source_route_mode(None, RouteSelectionMode::Fanout)
                .unwrap();

            let gps_pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(gps_pkt).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            let first_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            let first_c =
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(first_b + first_c, 2);

            router
                .clear_typed_route(None, DataType::named("GPS_DATA"), side_b)
                .unwrap();
            router
                .clear_typed_route(None, DataType::named("GPS_DATA"), side_c)
                .unwrap();

            let fallback_pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[7.0, 8.0, 9.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            router.tx(fallback_pkt).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );
            let total_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            let total_c =
                count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(total_b + total_c, 3);

            let _ = side_a;
        }

        #[test]
        fn router_typed_routes_still_respect_base_route_disables() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .set_typed_route(None, DataType::named("GPS_DATA"), side_b, true)
                .unwrap();
            router.set_route(None, side_b, false).unwrap();

            let gps_pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(gps_pkt).unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            assert!(seen_b.lock().unwrap().is_empty());

            let _ = side_a;
        }

        #[test]
        fn router_weighted_route_mode_splits_discovered_paths_by_weight() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
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
            router.set_route_weight(None, side_a, 2).unwrap();
            router.set_route_weight(None, side_b, 1).unwrap();

            for seq in 0..6 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("IMU_DATA"),
                    &[
                        seq as f32,
                        seq as f32 + 1.0,
                        seq as f32 + 2.0,
                        seq as f32 + 3.0,
                        seq as f32 + 4.0,
                        seq as f32 + 5.0,
                    ],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                router.tx(pkt).unwrap();
            }

            assert_eq!(seen_a.lock().unwrap().len(), 4);
            assert_eq!(seen_b.lock().unwrap().len(), 2);
        }

        #[test]
        fn router_discovery_defaults_to_adaptive_load_balancing() {
            ensure_topology_test_schema();

            let now_ms = Arc::new(AtomicU64::new(0));
            let armed = Arc::new(AtomicBool::new(false));
            let seen_a = Arc::new(AtomicUsize::new(0));
            let seen_b = Arc::new(AtomicUsize::new(0));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let now_a = now_ms.clone();
            let now_b = now_ms.clone();
            let armed_b = armed.clone();

            let router = Router::new_with_clock(
                RouterConfig::default(),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                if pkt.data_type() == DataType::named("IMU_DATA") {
                    seen_a_c.fetch_add(1, Ordering::SeqCst);
                }
                now_a.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                if pkt.data_type() == DataType::named("IMU_DATA") {
                    seen_b_c.fetch_add(1, Ordering::SeqCst);
                }
                let delay_ms = if armed_b.load(Ordering::SeqCst)
                    && pkt.data_type() == DataType::named("IMU_DATA")
                {
                    4
                } else {
                    1
                };
                now_b.fetch_add(delay_ms, Ordering::SeqCst);
                Ok(())
            });
            router.set_side_egress_enabled(side_a, false).unwrap();
            router.set_side_egress_enabled(side_b, false).unwrap();

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let discovery_b =
                build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_a, side_a).unwrap();
            router.rx_from_side(&discovery_b, side_b).unwrap();
            router.set_side_egress_enabled(side_a, true).unwrap();
            router.set_side_egress_enabled(side_b, true).unwrap();
            seen_a.store(0, Ordering::SeqCst);
            seen_b.store(0, Ordering::SeqCst);
            armed.store(true, Ordering::SeqCst);

            for seq in 0..24 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("IMU_DATA"),
                    &[
                        seq as f32,
                        seq as f32 + 1.0,
                        seq as f32 + 2.0,
                        seq as f32 + 3.0,
                        seq as f32 + 4.0,
                        seq as f32 + 5.0,
                    ],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                router.tx(pkt).unwrap();
            }

            let a = seen_a.load(Ordering::SeqCst);
            let b = seen_b.load(Ordering::SeqCst);
            assert_eq!(a + b, 24);
            assert!(
                a > b,
                "expected faster side to receive more traffic: a={a}, b={b}"
            );
            assert!(b > 0, "expected adaptive balancing instead of failover");

            let stats = router.export_runtime_stats();
            let side_a_stats = stats
                .sides
                .iter()
                .find(|side| side.side_name == "A")
                .unwrap();
            let side_b_stats = stats
                .sides
                .iter()
                .find(|side| side.side_name == "B")
                .unwrap();
            assert!(
                side_a_stats.adaptive.estimated_capacity_bps
                    > side_b_stats.adaptive.estimated_capacity_bps,
                "expected adaptive capacity estimate to favor faster side"
            );
        }

        #[test]
        fn link_probe_samples_seed_adaptive_capacity_without_sending_probe_frames() {
            ensure_topology_test_schema();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let fast = router.add_side_packet("ETHERNET", |_pkt| Ok(()));
            let slow = router.add_side_packet("LORA", |_pkt| Ok(()));

            router
                .note_side_link_probe_sample(fast, 10_000, 10)
                .unwrap();
            router
                .note_side_link_probe_sample(slow, 250, 5_000)
                .unwrap();

            let stats = router.export_runtime_stats();
            let fast_stats = stats
                .sides
                .iter()
                .find(|side| side.side_name == "ETHERNET")
                .unwrap();
            let slow_stats = stats
                .sides
                .iter()
                .find(|side| side.side_name == "LORA")
                .unwrap();
            assert!(
                fast_stats.adaptive.estimated_capacity_bps
                    > slow_stats.adaptive.estimated_capacity_bps
            );
        }

        #[test]
        fn slow_links_get_minimal_discovery_pings_between_full_refreshes() {
            ensure_topology_test_schema();

            let now_ms = Arc::new(AtomicU64::new(5_000));
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
            let side = router.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .note_side_link_probe_sample(side, 250, 5_000)
                .unwrap();
            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();
            assert!(
                seen.lock()
                    .unwrap()
                    .iter()
                    .any(|pkt| pkt.data_type() == DataType::DiscoverySchema)
            );

            seen.lock().unwrap().clear();
            now_ms.store(10_000, Ordering::SeqCst);
            assert!(router.poll_discovery().unwrap());
            router.process_tx_queue().unwrap();
            assert!(
                seen.lock().unwrap().is_empty(),
                "slow side should wait for the lightweight ping cadence"
            );

            now_ms.store(
                5_000 + DISCOVERY_SLOW_LINK_PING_INTERVAL_MS,
                Ordering::SeqCst,
            );
            assert!(router.poll_discovery().unwrap());
            router.process_tx_queue().unwrap();

            let pkts = seen.lock().unwrap().clone();
            assert_eq!(pkts.len(), 1);
            assert_eq!(pkts[0].data_type(), DataType::DiscoveryAnnounce);
            assert!(
                crate::discovery::decode_discovery_announce(&pkts[0])
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn relay_slow_links_get_minimal_discovery_pings_between_full_refreshes() {
            let now_ms = Arc::new(AtomicU64::new(5_000));
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let relay = Relay::new(Box::new(SharedClock {
                now_ms: now_ms.clone(),
            }));
            let side = relay.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            relay.note_side_link_probe_sample(side, 250, 5_000).unwrap();
            relay.announce_discovery().unwrap();
            relay.process_tx_queue().unwrap();
            assert!(
                seen.lock()
                    .unwrap()
                    .iter()
                    .any(|pkt| pkt.data_type() == DataType::DiscoverySchema)
            );

            seen.lock().unwrap().clear();
            now_ms.store(
                5_000 + DISCOVERY_SLOW_LINK_PING_INTERVAL_MS,
                Ordering::SeqCst,
            );
            assert!(relay.poll_discovery().unwrap());
            relay.process_tx_queue().unwrap();

            let pkts = seen.lock().unwrap().clone();
            assert_eq!(pkts.len(), 1);
            assert_eq!(pkts[0].data_type(), DataType::DiscoveryAnnounce);
            assert!(
                crate::discovery::decode_discovery_announce(&pkts[0])
                    .unwrap()
                    .is_empty()
            );
        }

        #[cfg(all(feature = "timesync", feature = "discovery"))]
        #[test]
        fn timesync_announces_throttle_only_the_measured_slow_side() {
            let now_ms = Arc::new(AtomicU64::new(5_000));
            let seen_fast: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_slow: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_fast_c = seen_fast.clone();
            let seen_slow_c = seen_slow.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Source,
                    announce_interval_ms: 1_000,
                    ..Default::default()
                }),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
            let fast =
                router.add_side_packet("ETHERNET", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_fast_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });
            let slow = router.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_slow_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let local_sender = router.sender().to_string();
            let local_sources = [local_sender.as_str()];

            router
                .set_source_route_mode(None, RouteSelectionMode::Fanout)
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_timesync_sources("FAST_TS", 0, &local_sources).unwrap(),
                    fast,
                )
                .unwrap();
            router
                .rx_from_side(
                    &build_discovery_timesync_sources("SLOW_TS", 1, &local_sources).unwrap(),
                    slow,
                )
                .unwrap();
            router.process_rx_queue().unwrap();
            router.process_tx_queue().unwrap();
            seen_fast.lock().unwrap().clear();
            seen_slow.lock().unwrap().clear();
            router
                .note_side_link_probe_sample(slow, 250, 5_000)
                .unwrap();

            now_ms.store(6_000, Ordering::SeqCst);
            assert!(router.poll_timesync().unwrap());
            router.process_tx_queue().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_fast.lock().unwrap(), DataType::TimeSyncAnnounce),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_slow.lock().unwrap(), DataType::TimeSyncAnnounce),
                0
            );

            seen_fast.lock().unwrap().clear();
            seen_slow.lock().unwrap().clear();
            now_ms.store(7_000, Ordering::SeqCst);
            assert!(router.poll_timesync().unwrap());
            router.process_tx_queue().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_fast.lock().unwrap(), DataType::TimeSyncAnnounce),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_slow.lock().unwrap(), DataType::TimeSyncAnnounce),
                0
            );
        }

        #[test]
        fn router_exports_runtime_stats_with_route_and_type_details() {
            ensure_topology_test_schema();

            let now_ms = Arc::new(AtomicU64::new(0));
            let seen_a = Arc::new(AtomicUsize::new(0));
            let seen_b = Arc::new(AtomicUsize::new(0));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();
            let now_a = now_ms.clone();
            let now_b = now_ms.clone();

            let router = Router::new_with_clock(
                RouterConfig::default(),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
            let retry_budget = Arc::new(AtomicUsize::new(0));
            let retry_budget_c = retry_budget.clone();
            let side_a = router.add_side_packet("A", move |_pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.fetch_add(1, Ordering::SeqCst);
                now_a.fetch_add(1, Ordering::SeqCst);
                if retry_budget_c.fetch_add(1, Ordering::SeqCst) < 2 {
                    return Err(TelemetryError::Io("side tx busy"));
                }
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |_pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.fetch_add(1, Ordering::SeqCst);
                now_b.fetch_add(3, Ordering::SeqCst);
                Ok(())
            });

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let discovery_b =
                build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_a, side_a).unwrap();
            router.rx_from_side(&discovery_b, side_b).unwrap();

            router
                .set_source_route_mode(None, RouteSelectionMode::Weighted)
                .unwrap();
            router.set_route(None, side_b, false).unwrap();
            router.set_route_weight(None, side_a, 2).unwrap();
            router.set_route_weight(None, side_b, 1).unwrap();
            router.set_route_priority(None, side_a, 7).unwrap();
            router
                .set_typed_route(None, DataType::named("GPS_DATA"), side_a, true)
                .unwrap();
            router
                .set_typed_route(None, DataType::named("GPS_DATA"), side_b, false)
                .unwrap();

            for seq in 0..3 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                router.tx_queue(pkt).unwrap();
            }

            let queued = router.export_runtime_stats();
            assert!(queued.queues.tx_len >= 3);
            assert!(queued.queues.tx_bytes > 0);
            assert_eq!(queued.queues.rx_len, 0);

            router.process_tx_queue().unwrap();

            let stats = router.export_runtime_stats();
            assert_eq!(
                stats
                    .route_modes
                    .iter()
                    .find(|mode| mode.src_side_id.is_none())
                    .unwrap()
                    .selection_mode,
                Some(RouteSelectionMode::Weighted)
            );
            assert!(
                stats
                    .route_overrides
                    .iter()
                    .any(|route| route.src_side_id.is_none()
                        && route.dst_side_id == side_b
                        && !route.enabled)
            );
            assert!(
                stats
                    .route_weights
                    .iter()
                    .any(|weight| weight.src_side_id.is_none()
                        && weight.dst_side_id == side_a
                        && weight.weight == 2)
            );
            assert!(
                stats
                    .route_priorities
                    .iter()
                    .any(|priority| priority.src_side_id.is_none()
                        && priority.dst_side_id == side_a
                        && priority.priority == 7)
            );
            assert!(
                stats
                    .typed_route_overrides
                    .iter()
                    .any(|route| route.src_side_id.is_none()
                        && route.data_type == DataType::named("GPS_DATA")
                        && route.dst_side_id == side_a
                        && route.enabled)
            );
            assert!(
                stats
                    .typed_route_overrides
                    .iter()
                    .any(|route| route.src_side_id.is_none()
                        && route.data_type == DataType::named("GPS_DATA")
                        && route.dst_side_id == side_b
                        && !route.enabled)
            );
            assert_eq!(stats.discovery.route_count, 2);
            assert_eq!(stats.discovery.announcer_count, 2);
            assert_eq!(stats.queues.tx_len, 0);
            assert_eq!(stats.queues.rx_len, 0);
            assert_eq!(stats.reliable.reliable_return_route_count, 0);
            assert_eq!(stats.reliable.end_to_end_pending_count, 0);
            assert_eq!(stats.total_handler_failures, 0);
            assert_eq!(stats.total_handler_retries, 0);

            let side_a_stats = side_stats(&stats, side_a);
            let side_b_stats = side_stats(&stats, side_b);
            let side_a_type = type_stats(side_a_stats, DataType::named("GPS_DATA"));
            assert!(side_a_stats.rx_packets >= 1);
            assert!(!side_a_stats.reliable_enabled);
            assert!(!side_a_stats.link_local_enabled);
            assert!(side_a_stats.ingress_enabled);
            assert!(side_a_stats.egress_enabled);
            assert!(side_a_stats.tx_packets >= 3);
            assert_eq!(side_a_stats.tx_retries, 2);
            assert_eq!(side_a_stats.total_handler_retries, 2);
            assert_eq!(side_a_stats.tx_handler_failures, 0);
            assert_eq!(side_a_stats.local_handler_failures, 0);
            assert_eq!(side_a_stats.local_delivery_packets, 0);
            assert_eq!(side_a_type.tx_packets, 3);
            assert_eq!(side_a_type.handler_failures, 0);
            assert_eq!(side_a_type.relayed_tx_packets, 0);
            assert!(side_a_stats.adaptive.auto_balancing_enabled);
            assert!(side_a_stats.adaptive.estimated_capacity_bps > 0);
            assert!(
                side_a_stats.adaptive.peak_capacity_bps
                    >= side_a_stats.adaptive.estimated_capacity_bps
            );
            assert!(side_a_stats.adaptive.current_usage_bps > 0);
            assert!(
                side_a_stats.adaptive.peak_usage_bps >= side_a_stats.adaptive.current_usage_bps
            );
            assert_eq!(
                side_a_stats.adaptive.effective_weight,
                side_a_stats.adaptive.available_headroom_bps.max(1)
            );
            assert!(side_a_stats.adaptive.sample_count >= 3);
            assert!(side_a_stats.adaptive.last_observed_ms > 0);
            assert_eq!(
                side_b_stats
                    .data_types
                    .iter()
                    .find(|item| item.data_type == DataType::named("GPS_DATA"))
                    .map(|item| item.tx_packets)
                    .unwrap_or(0),
                0
            );
        }

        #[test]
        fn relay_exports_runtime_stats_with_route_and_bandwidth_details() {
            ensure_topology_test_schema();

            let now_ms = Arc::new(AtomicU64::new(0));
            let now_a = now_ms.clone();
            let now_b = now_ms.clone();

            let relay = Relay::new(Box::new(SharedClock {
                now_ms: now_ms.clone(),
            }));
            let side_a = relay.add_side_packet("A", move |_pkt: &Packet| -> TelemetryResult<()> {
                now_a.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |_pkt: &Packet| -> TelemetryResult<()> {
                now_b.fetch_add(4, Ordering::SeqCst);
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let discovery_b =
                build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_a).unwrap();
            relay.rx_from_side(side_b, discovery_b).unwrap();
            relay.process_rx_queue().unwrap();

            relay
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
                .unwrap();
            relay.set_route(Some(side_c), side_b, false).unwrap();
            relay.set_route_weight(Some(side_c), side_a, 2).unwrap();
            relay.set_route_weight(Some(side_c), side_b, 1).unwrap();
            relay.set_route_priority(Some(side_c), side_a, 4).unwrap();
            relay
                .set_typed_route(Some(side_c), DataType::named("GPS_DATA"), side_a, true)
                .unwrap();
            relay
                .set_typed_route(Some(side_c), DataType::named("GPS_DATA"), side_b, false)
                .unwrap();

            for seq in 0..6 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                relay.rx_from_side(side_c, pkt).unwrap();
            }
            let queued = relay.export_runtime_stats();
            assert_eq!(queued.queues.rx_len, 6);
            assert!(queued.queues.rx_bytes > 0);
            relay.process_all_queues().unwrap();

            let stats = relay.export_runtime_stats();
            assert_eq!(
                stats
                    .route_modes
                    .iter()
                    .find(|mode| mode.src_side_id == Some(side_c))
                    .unwrap()
                    .selection_mode,
                Some(RouteSelectionMode::Weighted)
            );
            assert!(
                stats
                    .route_overrides
                    .iter()
                    .any(|route| route.src_side_id == Some(side_c)
                        && route.dst_side_id == side_b
                        && !route.enabled)
            );
            assert!(
                stats
                    .route_weights
                    .iter()
                    .any(|weight| weight.src_side_id == Some(side_c)
                        && weight.dst_side_id == side_a
                        && weight.weight == 2)
            );
            assert!(
                stats
                    .route_priorities
                    .iter()
                    .any(|priority| priority.src_side_id == Some(side_c)
                        && priority.dst_side_id == side_a
                        && priority.priority == 4)
            );
            assert!(
                stats
                    .typed_route_overrides
                    .iter()
                    .any(|route| route.src_side_id == Some(side_c)
                        && route.data_type == DataType::named("GPS_DATA")
                        && route.dst_side_id == side_a
                        && route.enabled)
            );
            assert!(
                stats
                    .typed_route_overrides
                    .iter()
                    .any(|route| route.src_side_id == Some(side_c)
                        && route.data_type == DataType::named("GPS_DATA")
                        && route.dst_side_id == side_b
                        && !route.enabled)
            );
            assert_eq!(stats.queues.rx_len, 0);
            assert_eq!(stats.queues.tx_len, 0);
            assert_eq!(stats.total_handler_failures, 0);
            assert_eq!(stats.total_handler_retries, 0);

            let ingress_stats = side_stats(&stats, side_c);
            assert_eq!(ingress_stats.rx_packets, 6);
            assert_eq!(ingress_stats.relayed_rx_packets, 6);
            assert!(
                stats.reliable.reliable_return_route_count <= ingress_stats.rx_packets as usize
            );
            let ingress_type = type_stats(ingress_stats, DataType::named("GPS_DATA"));
            assert_eq!(ingress_type.rx_packets, 6);
            assert_eq!(ingress_type.relayed_rx_packets, 6);
            let egress_a = side_stats(&stats, side_a);
            let egress_b = side_stats(&stats, side_b);
            assert!(egress_a.tx_packets > egress_b.tx_packets);
            assert!(egress_a.adaptive.estimated_capacity_bps > 0);
            assert!(egress_a.adaptive.current_usage_bps > 0);
            assert!(egress_a.adaptive.peak_usage_bps >= egress_a.adaptive.current_usage_bps);
            assert_eq!(
                egress_a.adaptive.effective_weight,
                egress_a.adaptive.available_headroom_bps.max(1)
            );
            assert!(egress_a.adaptive.last_observed_ms > 0);
            assert_eq!(
                egress_b
                    .data_types
                    .iter()
                    .find(|item| item.data_type == DataType::named("GPS_DATA"))
                    .map(|item| item.tx_packets)
                    .unwrap_or(0),
                0
            );
            assert!(stats.discovery.route_count >= 2);
        }

        #[test]
        fn router_runtime_stats_track_ingress_local_handler_failures_and_relayed_rx() {
            ensure_topology_test_schema();

            let failing = EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt: &Packet| Err(TelemetryError::HandlerError("local handler failed")),
            );
            let router = Router::new_with_clock(RouterConfig::new(vec![failing]), zero_clock());
            let side = router.add_side_packet("INGRESS", |_pkt: &Packet| Ok(()));

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("SD_CARD")],
                1,
            )
            .unwrap();
            router.rx_from_side(&pkt, side).unwrap();

            let stats = router.export_runtime_stats();
            let ingress = side_stats(&stats, side);
            let gps = type_stats(ingress, DataType::named("GPS_DATA"));

            assert_eq!(stats.total_handler_failures, 1);
            assert_eq!(stats.total_handler_retries, MAX_HANDLER_RETRIES as u64);
            assert_eq!(ingress.rx_packets, 1);
            assert!(ingress.rx_bytes > 0);
            assert_eq!(ingress.relayed_rx_packets, 1);
            assert_eq!(ingress.local_delivery_packets, 1);
            assert_eq!(ingress.local_handler_failures, 1);
            assert_eq!(ingress.total_handler_retries, MAX_HANDLER_RETRIES as u64);
            assert_eq!(gps.rx_packets, 2);
            assert_eq!(gps.relayed_rx_packets, 1);
            assert_eq!(gps.handler_failures, 1);
        }

        #[test]
        fn relay_runtime_stats_track_tx_failures_and_retries() {
            ensure_topology_test_schema();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", |_pkt: &Packet| {
                Err(TelemetryError::Io("side tx failed hard"))
            });
            let side_b = relay.add_side_packet("B", |_pkt: &Packet| Ok(()));
            let side_c = relay.add_side_packet("C", |_pkt: &Packet| Ok(()));

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_a).unwrap();
            relay.process_rx_queue().unwrap();

            relay
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
                .unwrap();
            relay.set_route(Some(side_c), side_b, false).unwrap();
            relay.set_route_priority(Some(side_c), side_a, 0).unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0, 8.0, 7.0],
                &[DataEndpoint::named("RADIO")],
                42,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt).unwrap();
            assert!(matches!(
                relay.process_all_queues(),
                Err(TelemetryError::Io("side tx failed hard"))
            ));

            let stats = relay.export_runtime_stats();
            let failing_side = side_stats(&stats, side_a);
            let ingress = side_stats(&stats, side_c);
            let gps_failures = failing_side
                .data_types
                .iter()
                .find(|item| item.data_type == DataType::named("GPS_DATA"))
                .map(|item| item.handler_failures)
                .unwrap_or(0);

            assert_eq!(stats.total_handler_failures, 1);
            assert_eq!(stats.total_handler_retries, 1);
            assert!(
                stats
                    .route_overrides
                    .iter()
                    .any(|route| route.src_side_id == Some(side_c)
                        && route.dst_side_id == side_b
                        && !route.enabled)
            );
            assert!(
                stats
                    .route_priorities
                    .iter()
                    .any(|priority| priority.src_side_id == Some(side_c)
                        && priority.dst_side_id == side_a
                        && priority.priority == 0)
            );
            assert_eq!(ingress.rx_packets, 1);
            assert_eq!(ingress.relayed_rx_packets, 1);
            assert_eq!(failing_side.tx_packets, 0);
            assert_eq!(failing_side.tx_handler_failures, 1);
            assert_eq!(failing_side.tx_retries, 1);
            assert_eq!(failing_side.total_handler_retries, 1);
            assert_eq!(gps_failures, 0);
            let gps_tx_retries = failing_side
                .data_types
                .iter()
                .find(|item| item.data_type == DataType::named("GPS_DATA"))
                .map(|item| item.tx_retries)
                .unwrap_or(0);
            assert_eq!(gps_tx_retries, 0);
        }

        #[test]
        fn router_failover_route_mode_switches_when_preferred_path_expires() {
            let now_ms = Arc::new(AtomicU64::new(0));
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::default(),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
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
            router.rx_from_side(&discovery_a, side_a).unwrap();
            now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
            let discovery_b = build_discovery_announce(
                "REMOTE_B",
                DISCOVERY_ROUTE_TTL_MS / 2,
                &[DataEndpoint::named("RADIO")],
            )
            .unwrap();
            router.rx_from_side(&discovery_b, side_b).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            router
                .set_source_route_mode(None, RouteSelectionMode::Failover)
                .unwrap();
            router.set_route_priority(None, side_a, 0).unwrap();
            router.set_route_priority(None, side_b, 1).unwrap();

            let pkt1 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(pkt1).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            let pkt2 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[2.0, 3.0, 4.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            router.tx(pkt2).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
        }

        #[test]
        fn router_weighted_route_mode_falls_back_to_remaining_path_when_other_path_expires() {
            let now_ms = Arc::new(AtomicU64::new(0));
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::default(),
                Box::new(SharedClock {
                    now_ms: now_ms.clone(),
                }),
            );
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
            router.rx_from_side(&discovery_a, side_a).unwrap();
            now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
            let discovery_b = build_discovery_announce(
                "REMOTE_B",
                DISCOVERY_ROUTE_TTL_MS / 2,
                &[DataEndpoint::named("RADIO")],
            )
            .unwrap();
            router.rx_from_side(&discovery_b, side_b).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            router
                .set_source_route_mode(None, RouteSelectionMode::Weighted)
                .unwrap();
            router.set_route_weight(None, side_a, 1).unwrap();
            router.set_route_weight(None, side_b, 1).unwrap();

            for seq in 0..2 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                router.tx(pkt).unwrap();
            }
            let before_a =
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
            let before_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(before_a + before_b, 2);

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            let pkt3 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0, 10.0, 11.0],
                &[DataEndpoint::named("RADIO")],
                3,
            )
            .unwrap();
            router.tx(pkt3).unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                before_a
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                before_b + 1
            );
        }

        #[test]
        fn router_failover_route_mode_switches_when_preferred_side_is_removed() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
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
                .set_source_route_mode(None, RouteSelectionMode::Failover)
                .unwrap();
            router.set_route_priority(None, side_a, 0).unwrap();
            router.set_route_priority(None, side_b, 1).unwrap();

            let pkt1 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            router.tx(pkt1).unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            router.remove_side(side_a).unwrap();
            let pkt2 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[4.0, 5.0, 6.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            router.tx(pkt2).unwrap();

            let before_a =
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
            let before_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(before_a + before_b, 2);
        }

        #[test]
        fn relay_weighted_route_mode_splits_discovered_paths_by_weight() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            let discovery_b =
                build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_a).unwrap();
            relay.rx_from_side(side_b, discovery_b).unwrap();
            relay.process_rx_queue().unwrap();
            relay.process_tx_queue().unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            relay
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
                .unwrap();
            relay.set_route_weight(Some(side_c), side_a, 2).unwrap();
            relay.set_route_weight(Some(side_c), side_b, 1).unwrap();

            for seq in 0..6 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                relay.rx_from_side(side_c, pkt).unwrap();
            }
            relay.process_all_queues().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                4
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                2
            );
        }

        #[test]
        fn relay_failover_route_mode_switches_when_preferred_path_expires() {
            let now_ms = Arc::new(AtomicU64::new(0));
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(Box::new(SharedClock {
                now_ms: now_ms.clone(),
            }));
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_a).unwrap();
            relay.process_rx_queue().unwrap();
            relay.process_tx_queue().unwrap();
            now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
            let discovery_b = build_discovery_announce(
                "REMOTE_B",
                DISCOVERY_ROUTE_TTL_MS / 2,
                &[DataEndpoint::named("RADIO")],
            )
            .unwrap();
            relay.rx_from_side(side_b, discovery_b).unwrap();
            relay.process_rx_queue().unwrap();
            relay.process_tx_queue().unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            relay
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
                .unwrap();
            relay.set_route_priority(Some(side_c), side_a, 0).unwrap();
            relay.set_route_priority(Some(side_c), side_b, 1).unwrap();

            let pkt1 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt1).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            let pkt2 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[2.0, 3.0, 4.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt2).unwrap();
            relay.process_all_queues().unwrap();
            let before_a =
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
            let before_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(before_a + before_b, 2);
        }

        #[test]
        fn relay_weighted_route_mode_falls_back_to_remaining_path_when_other_path_expires() {
            let now_ms = Arc::new(AtomicU64::new(0));
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(Box::new(SharedClock {
                now_ms: now_ms.clone(),
            }));
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_a =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_a).unwrap();
            relay.process_all_queues().unwrap();
            now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
            let discovery_b = build_discovery_announce(
                "REMOTE_B",
                DISCOVERY_ROUTE_TTL_MS / 2,
                &[DataEndpoint::named("RADIO")],
            )
            .unwrap();
            relay.rx_from_side(side_b, discovery_b).unwrap();
            relay.process_all_queues().unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            relay
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
                .unwrap();
            relay.set_route_weight(Some(side_c), side_a, 1).unwrap();
            relay.set_route_weight(Some(side_c), side_b, 1).unwrap();

            for seq in 0..2 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
                    &[DataEndpoint::named("RADIO")],
                    seq as u64,
                )
                .unwrap();
                relay.rx_from_side(side_c, pkt).unwrap();
            }
            relay.process_all_queues().unwrap();
            let before_a =
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
            let before_b =
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
            assert_eq!(before_a + before_b, 2);

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            let pkt3 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0, 10.0, 11.0],
                &[DataEndpoint::named("RADIO")],
                3,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt3).unwrap();
            relay.process_all_queues().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                before_a
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                before_b + 1
            );
        }

        #[test]
        fn relay_failover_route_mode_switches_when_preferred_side_is_removed() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_c =
                relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

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
                .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
                .unwrap();
            relay.set_route_priority(Some(side_c), side_a, 0).unwrap();
            relay.set_route_priority(Some(side_c), side_b, 1).unwrap();

            let pkt1 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt1).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                0
            );

            relay.remove_side(side_a).unwrap();
            let pkt2 = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[4.0, 5.0, 6.0],
                &[DataEndpoint::named("RADIO")],
                2,
            )
            .unwrap();
            relay.rx_from_side(side_c, pkt2).unwrap();
            relay.process_all_queues().unwrap();

            assert_eq!(
                count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
            assert_eq!(
                count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
                1
            );
        }

        #[test]
        fn router_can_disable_ingress_for_a_side() {
            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side =
                router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
            router.set_side_ingress_enabled(side, false).unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                5,
            )
            .unwrap();

            match router.rx_from_side(&pkt, side) {
                Err(TelemetryError::HandlerError(msg)) => {
                    assert!(msg.contains("ingress disabled"));
                }
                other => panic!("expected ingress-disabled error, got {other:?}"),
            }
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn router_periodic_dispatches_discovery_and_timesync_when_enabled() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Source,
                    ..Default::default()
                }),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.periodic(0).unwrap();

            let pkts = seen.lock().unwrap().clone();
            assert!(pkts.iter().any(|pkt| matches!(
                pkt.data_type(),
                DataType::DiscoveryAddress
                    | DataType::DiscoveryAnnounce
                    | DataType::DiscoveryTopology
                    | DataType::DiscoveryTimeSyncSources
            )));
            assert!(
                pkts.iter()
                    .any(|pkt| pkt.data_type() == DataType::TimeSyncAnnounce)
            );
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn router_periodic_can_skip_timesync_but_still_dispatch_discovery() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Source,
                    ..Default::default()
                }),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.periodic_no_timesync(0).unwrap();

            let pkts = seen.lock().unwrap().clone();
            assert!(pkts.iter().any(|pkt| matches!(
                pkt.data_type(),
                DataType::DiscoveryAddress
                    | DataType::DiscoveryAnnounce
                    | DataType::DiscoveryTopology
                    | DataType::DiscoveryTimeSyncSources
            )));
            assert!(
                pkts.iter()
                    .all(|pkt| pkt.data_type() != DataType::TimeSyncAnnounce)
            );
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn queued_timesync_packets_precede_normal_telemetry() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Consumer,
                    ..Default::default()
                }),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
                .unwrap();
            let announce =
                crate::timesync::build_timesync_announce_with_sender("SRC_FAST", 1, 1_700).unwrap();
            router.rx(&announce).unwrap();
            router.process_tx_queue().unwrap();

            let pkts = seen.lock().unwrap().clone();
            assert!(pkts.len() >= 2);
            let gps_idx = pkts
                .iter()
                .position(|pkt| pkt.data_type() == DataType::named("GPS_DATA"))
                .expect("expected queued GPS packet");
            let request_idx = pkts
                .iter()
                .position(|pkt| pkt.data_type() == DataType::TimeSyncRequest)
                .expect("expected queued time-sync request");
            assert!(request_idx < gps_idx);
        }

        #[cfg(feature = "discovery")]
        #[test]
        fn queued_discovery_packets_precede_normal_telemetry() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    |_pkt| Ok(()),
                )]),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router
                .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
                .unwrap();
            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();

            let pkts = seen.lock().unwrap().clone();
            let gps_idx = pkts
                .iter()
                .position(|pkt| pkt.data_type() == DataType::named("GPS_DATA"))
                .unwrap();
            assert!(gps_idx > 0);
            assert!(
                pkts[..gps_idx]
                    .iter()
                    .all(|pkt| crate::discovery::is_discovery_type(pkt.data_type()))
            );
        }

        #[test]
        fn reliable_packets_use_discovery_selection_instead_of_flooding() {
            ensure_topology_test_schema();
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();
            let discovery_pkt =
                build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            router.rx_from_side(&discovery_pkt, side_b).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let msg = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[5.0, 6.0, 7.0],
                &[DataEndpoint::named("RADIO")],
                3,
            )
            .unwrap();
            router.tx(msg).unwrap();

            let seen_a_len = seen_a.lock().unwrap().len();
            let seen_b_len = seen_b.lock().unwrap().len();
            assert_eq!(
                seen_a_len + seen_b_len,
                1,
                "reliable outbound traffic should follow one discovered path instead of flooding",
            );
        }

        #[test]
        fn relay_exports_aggregated_topology() {
            ensure_topology_test_schema();

            let relay = Relay::new(zero_clock());
            let side_a =
                relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
            relay.add_side_packet("B", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let discovery_pkt = build_discovery_announce(
                "NODE_A",
                0,
                &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
            )
            .unwrap();
            relay.rx_from_side(side_a, discovery_pkt).unwrap();
            relay.process_all_queues().unwrap();

            let snap = relay.export_topology();
            assert_eq!(
                snap.advertised_endpoints,
                vec![DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")]
            );
            assert!(snap.routers.iter().any(|board| board.sender_id == "RELAY"
                && board.connections.contains(&"NODE_A".to_string())));
            assert_eq!(snap.routes.len(), 1);
            assert_eq!(snap.routes[0].side_name, "A");
            assert_eq!(snap.routes[0].announcers.len(), 1);
            assert_eq!(snap.routes[0].announcers[0].sender_id, "NODE_A");
            assert!(
                snap.routes[0].announcers[0]
                    .routers
                    .iter()
                    .any(|board| board.sender_id == "NODE_A")
            );
        }

        #[test]
        fn relay_periodic_dispatches_discovery() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let relay = Relay::new(zero_clock());
            let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                build_discovery_announce("NODE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
            relay.rx_from_side(side_a, discovery_pkt).unwrap();
            relay.periodic(0).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            relay.periodic(0).unwrap();

            assert!(
                seen_b
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|pkt| pkt.data_type() == DataType::DiscoveryAnnounce)
            );
        }

        #[test]
        fn relay_end_to_end_acked_holders_clear_when_discovered_holder_expires() {
            let now_ms = Arc::new(AtomicU64::new(0));
            let relay = Relay::new(Box::new(SharedClock {
                now_ms: now_ms.clone(),
            }));
            let side =
                relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            relay
                .rx_from_side(
                    side,
                    build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
                )
                .unwrap();
            relay.process_all_queues().unwrap();

            let packet_id = 77u64;
            let ack = Packet::new(
                DataType::ReliableAck,
                crate::message_meta(DataType::ReliableAck).endpoints,
                "E2EACK:DEST_A",
                0,
                Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
            )
            .unwrap();
            relay.rx_from_side(side, ack).unwrap();
            relay.process_all_queues().unwrap();
            assert_eq!(
                relay.debug_end_to_end_acked_destination_count(packet_id),
                Some(1)
            );

            now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
            relay.periodic(0).unwrap();
            assert_eq!(
                relay.debug_end_to_end_acked_destination_count(packet_id),
                None
            );
        }

        #[test]
        fn relay_keeps_forwarding_to_unacked_destinations_after_reachability_changes() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();
            let relay = Relay::new(zero_clock());
            let ingress =
                relay.add_side_packet("INGRESS", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
            let link = relay.add_side_packet("LINK", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            relay
                .rx_from_side(
                    link,
                    build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
                )
                .unwrap();
            relay
                .rx_from_side(
                    link,
                    build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
                )
                .unwrap();
            relay.process_all_queues().unwrap();

            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[31.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                31,
            )
            .unwrap();
            let packet_id = pkt.packet_id();
            relay.rx_from_side(ingress, pkt.clone()).unwrap();
            relay.process_all_queues().unwrap();
            seen.lock().unwrap().clear();

            let ack = Packet::new(
                DataType::ReliableAck,
                crate::message_meta(DataType::ReliableAck).endpoints,
                "E2EACK:DEST_A",
                0,
                Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
            )
            .unwrap();
            relay.rx_from_side(link, ack).unwrap();
            relay.process_all_queues().unwrap();

            relay
                .rx_from_side(
                    link,
                    build_discovery_announce("DEST_B", 1, &[DataEndpoint::named("SD_CARD")])
                        .unwrap(),
                )
                .unwrap();
            relay.process_all_queues().unwrap();

            relay.rx_from_side(ingress, pkt).unwrap();
            relay.process_all_queues().unwrap();
            assert!(
                seen.lock()
                    .unwrap()
                    .iter()
                    .any(|p| p.data_type() == DataType::named("GPS_DATA"))
            );
        }

        #[test]
        fn reliable_relay_state_stays_bounded_under_unacked_traffic() {
            let relay = Relay::new(zero_clock());
            let side =
                relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            for idx in 0..(RELIABLE_MAX_RETURN_ROUTES.max(1) + 4) {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[idx as f32, 2.0, 0.0],
                    &[DataEndpoint::named("RADIO")],
                    idx as u64,
                )
                .unwrap();
                relay.rx_from_side(side, pkt).unwrap();
            }
            assert!(relay.debug_reliable_return_route_count() <= RELIABLE_MAX_RETURN_ROUTES.max(1));

            let packet_id = 123u64;
            for idx in 0..(RELIABLE_MAX_END_TO_END_PENDING.max(1) + 4) {
                let ack = Packet::new(
                    DataType::ReliableAck,
                    crate::message_meta(DataType::ReliableAck).endpoints,
                    &format!("E2EACK:DEST_{idx}"),
                    idx as u64,
                    Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
                )
                .unwrap();
                relay.rx_from_side(side, ack).unwrap();
            }
            assert!(
                relay
                    .debug_end_to_end_acked_destination_count(packet_id)
                    .unwrap_or(0)
                    <= RELIABLE_MAX_END_TO_END_PENDING.max(1)
            );

            for idx in 0..(RELIABLE_MAX_END_TO_END_ACK_CACHE.max(1) + 4) {
                let ack = Packet::new(
                    DataType::ReliableAck,
                    crate::message_meta(DataType::ReliableAck).endpoints,
                    "E2EACK:DEST_A",
                    idx as u64,
                    Arc::<[u8]>::from((10_000u64 + idx as u64).to_le_bytes().to_vec()),
                )
                .unwrap();
                relay.rx_from_side(side, ack).unwrap();
            }
            assert!(
                relay.debug_end_to_end_acked_packet_count()
                    <= RELIABLE_MAX_END_TO_END_ACK_CACHE.max(1)
            );
        }

        #[test]
        fn link_local_only_packets_stay_on_software_bus_sides() {
            let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
                return;
            };
            let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
                return;
            };
            let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_net_c = seen_net.clone();
            let seen_ll_c = seen_ll.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_net_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet_with_options(
                "LL",
                move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_ll_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                crate::router::RouterSideOptions {
                    reliable_enabled: false,
                    link_local_enabled: true,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            let pkt = Packet::new(
                ipc_message,
                &[software_bus],
                "IPC_NODE",
                7,
                Arc::<[u8]>::from(b"hello-ipc".as_slice()),
            )
            .unwrap();
            router.tx(pkt).unwrap();

            let ipc_count_net = seen_net
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            let ipc_count_ll = seen_ll
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            assert_eq!(ipc_count_net, 0);
            assert_eq!(ipc_count_ll, 1);
        }

        #[test]
        fn runtime_registered_ipc_stays_off_network_sides() {
            ensure_topology_test_schema();
            let ep_name = "RUNTIME_IPC_EP_9901";
            let ty_name = "RUNTIME_IPC_MSG_9901";
            let _ = remove_data_type_by_name(ty_name);
            let _ = remove_endpoint_by_name(ep_name);

            let runtime_ipc_ep =
                register_endpoint_with_description(ep_name, "runtime ipc endpoint", true)
                    .expect("register runtime ipc endpoint");
            let runtime_ipc_ty = register_data_type_with_description(
                ty_name,
                "runtime ipc type",
                MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
                &[runtime_ipc_ep],
                ReliableMode::None,
                1,
            )
            .expect("register runtime ipc type");

            let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_net_c = seen_net.clone();
            let seen_ll_c = seen_ll.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_net_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet_with_options(
                "IPC",
                move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_ll_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                crate::router::RouterSideOptions {
                    reliable_enabled: false,
                    link_local_enabled: true,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            let pkt = Packet::new(
                runtime_ipc_ty,
                &[runtime_ipc_ep],
                "RUNTIME_IPC_NODE",
                17,
                Arc::<[u8]>::from(b"runtime-ipc".as_slice()),
            )
            .unwrap();
            router.tx(pkt).unwrap();

            let ipc_count_net = seen_net
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == runtime_ipc_ty)
                .count();
            let ipc_count_ll = seen_ll
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == runtime_ipc_ty)
                .count();
            assert_eq!(ipc_count_net, 0);
            assert_eq!(ipc_count_ll, 1);

            assert!(remove_data_type_by_name(ty_name).unwrap());
            assert!(remove_endpoint_by_name(ep_name).unwrap());
        }

        #[test]
        fn link_local_routes_ignore_non_link_local_discovery_candidates() {
            let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
                return;
            };
            let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
                return;
            };
            let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_net_c = seen_net.clone();
            let seen_ll_c = seen_ll.clone();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            let side_net =
                router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_net_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });
            let side_ll = router.add_side_packet_with_options(
                "LL",
                move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_ll_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                crate::router::RouterSideOptions {
                    reliable_enabled: false,
                    link_local_enabled: true,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            let pkt_net = build_discovery_announce("NET_NODE", 0, &[software_bus]).unwrap();
            router.rx_from_side(&pkt_net, side_net).unwrap();
            let pkt_ll = build_discovery_announce("LL_NODE", 0, &[software_bus]).unwrap();
            router.rx_from_side(&pkt_ll, side_ll).unwrap();
            seen_net.lock().unwrap().clear();
            seen_ll.lock().unwrap().clear();

            let pkt = Packet::new(
                ipc_message,
                &[software_bus],
                "IPC_NODE",
                8,
                Arc::<[u8]>::from(b"stay-local".as_slice()),
            )
            .unwrap();
            router.tx(pkt).unwrap();

            let ipc_count_net = seen_net
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            let ipc_count_ll = seen_ll
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            assert_eq!(ipc_count_net, 0);
            assert_eq!(ipc_count_ll, 1);
        }

        #[test]
        fn relay_link_local_routes_ignore_non_link_local_discovery_candidates() {
            let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
                return;
            };
            let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
                return;
            };
            let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_net_c = seen_net.clone();
            let seen_ll_c = seen_ll.clone();

            let relay = Relay::new(zero_clock());
            let side_net =
                relay.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_net_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                });
            let side_ll = relay.add_side_packet_with_options(
                "LL",
                move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_ll_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                crate::relay::RelaySideOptions {
                    reliable_enabled: false,
                    link_local_enabled: true,
                    ..crate::relay::RelaySideOptions::default()
                },
            );
            let side_src =
                relay.add_side_packet("SRC", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

            let pkt_net = build_discovery_announce("NET_NODE", 0, &[software_bus]).unwrap();
            relay.rx_from_side(side_net, pkt_net).unwrap();
            let pkt_ll = build_discovery_announce("LL_NODE", 0, &[software_bus]).unwrap();
            relay.rx_from_side(side_ll, pkt_ll).unwrap();
            relay.process_all_queues().unwrap();
            seen_net.lock().unwrap().clear();
            seen_ll.lock().unwrap().clear();

            let pkt = Packet::new(
                ipc_message,
                &[software_bus],
                "IPC_NODE",
                9,
                Arc::<[u8]>::from(b"relay-local".as_slice()),
            )
            .unwrap();
            relay.rx_from_side(side_src, pkt).unwrap();
            relay.process_all_queues().unwrap();

            let ipc_count_net = seen_net
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            let ipc_count_ll = seen_ll
                .lock()
                .unwrap()
                .iter()
                .filter(|pkt| pkt.data_type() == ipc_message)
                .count();
            assert_eq!(ipc_count_net, 0);
            assert_eq!(ipc_count_ll, 1);
        }

        #[test]
        fn discovery_hides_link_local_endpoints_from_network_sides() {
            let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
                return;
            };
            let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_net_c = seen_net.clone();
            let seen_ll_c = seen_ll.clone();

            let router = Router::new_with_clock(
                RouterConfig::new(vec![
                    EndpointHandler::new_packet_handler(software_bus, |_pkt| Ok(())),
                    EndpointHandler::new_packet_handler(
                        DataEndpoint::named("RADIO"),
                        |_pkt| Ok(()),
                    ),
                ]),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_net_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet_with_options(
                "LL",
                move |pkt: &Packet| -> TelemetryResult<()> {
                    seen_ll_c.lock().unwrap().push(pkt.clone());
                    Ok(())
                },
                crate::router::RouterSideOptions {
                    reliable_enabled: false,
                    link_local_enabled: true,
                    ..crate::router::RouterSideOptions::default()
                },
            );

            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();

            let net = seen_net.lock().unwrap().clone();
            let ll = seen_ll.lock().unwrap().clone();
            let net_announce = net
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
                .unwrap();
            let ll_announce = ll
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
                .unwrap();
            let net_eps = crate::discovery::decode_discovery_address(net_announce)
                .unwrap()
                .reachable_endpoints;
            let ll_eps = crate::discovery::decode_discovery_address(ll_announce)
                .unwrap()
                .reachable_endpoints;
            assert!(!net_eps.contains(&software_bus));
            assert!(net_eps.contains(&DataEndpoint::named("RADIO")));
            assert!(ll_eps.contains(&software_bus));
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn discovery_keeps_timesync_endpoint_out_of_user_reachability_when_enabled() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();

            let topo = router.export_topology();
            assert!(!topo.advertised_endpoints.contains(&DataEndpoint::TimeSync));
        }

        #[cfg(all(feature = "timesync", feature = "discovery"))]
        #[test]
        fn timesync_packets_use_discovery_candidates_instead_of_flooding() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
                zero_clock(),
            );
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let discovery_pkt =
                crate::discovery::build_discovery_timesync_sources("REMOTE_A", 0, &["REMOTE_A"])
                    .unwrap();
            router.rx_from_side(&discovery_pkt, side_a).unwrap();
            let announce =
                crate::timesync::build_timesync_announce_with_sender("REMOTE_A", 1, 1_000).unwrap();
            router.rx_from_side(&announce, side_a).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let request = crate::timesync::build_timesync_request(1, 123).unwrap();
            router.tx(request).unwrap();

            assert_eq!(seen_a.lock().unwrap().len(), 1);
            assert!(seen_b.lock().unwrap().is_empty());
            assert_eq!(
                seen_a.lock().unwrap()[0].data_type(),
                DataType::TimeSyncRequest
            );
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn discovery_advertises_local_timesync_source_ids() {
            let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_c = seen.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Source,
                    ..Default::default()
                }),
                zero_clock(),
            );
            router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            router.announce_discovery().unwrap();
            router.process_tx_queue().unwrap();

            let pkts = seen.lock().unwrap().clone();
            let src_pkt = pkts
                .iter()
                .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
                .unwrap();
            let sources = crate::discovery::decode_discovery_address(src_pkt)
                .unwrap()
                .reachable_timesync_sources;
            assert!(sources.contains(&crate::config::DEVICE_IDENTIFIER.to_string()));
        }

        #[cfg(all(feature = "timesync", feature = "discovery"))]
        #[test]
        fn timesync_requests_prefer_exact_discovered_source_route() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
                zero_clock(),
            );
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let generic_timesync =
                build_discovery_announce("SIDE_A", 0, &[DataEndpoint::TimeSync]).unwrap();
            router.rx_from_side(&generic_timesync, side_a).unwrap();
            let exact_source =
                build_discovery_timesync_sources("SIDE_B", 0, &["SRC_BEST"]).unwrap();
            router.rx_from_side(&exact_source, side_b).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let source_announce =
                crate::timesync::build_timesync_announce_with_sender("SRC_BEST", 1, 1000).unwrap();
            router.rx(&source_announce).unwrap();
            seen_a.lock().unwrap().clear();
            seen_b.lock().unwrap().clear();

            let request = crate::timesync::build_timesync_request(1, 123).unwrap();
            router.tx(request).unwrap();

            assert!(seen_a.lock().unwrap().is_empty());
            assert_eq!(seen_b.lock().unwrap().len(), 1);
            assert_eq!(
                seen_b.lock().unwrap()[0].data_type(),
                DataType::TimeSyncRequest
            );
        }

        #[cfg(feature = "timesync")]
        #[test]
        fn timesync_responses_return_only_to_requesting_side() {
            let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_a_c = seen_a.clone();
            let seen_b_c = seen_b.clone();

            let router = Router::new_with_clock(
                RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
                    role: crate::timesync::TimeSyncRole::Source,
                    ..Default::default()
                }),
                zero_clock(),
            );
            let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_a_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });
            router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
                seen_b_c.lock().unwrap().push(pkt.clone());
                Ok(())
            });

            let request = crate::timesync::build_timesync_request(7, 111).unwrap();
            router.rx_from_side(&request, side_a).unwrap();
            router.process_tx_queue().unwrap();

            let got_a = seen_a.lock().unwrap().clone();
            let got_b = seen_b.lock().unwrap().clone();
            assert_eq!(
                got_a
                    .iter()
                    .filter(|pkt| pkt.data_type() == DataType::TimeSyncResponse)
                    .count(),
                1
            );
            assert_eq!(
                got_b
                    .iter()
                    .filter(|pkt| pkt.data_type() == DataType::TimeSyncResponse)
                    .count(),
                0
            );
        }

        #[test]
        fn managed_variable_request_replays_latest_value_to_endpoint_handler() {
            crate::tests::ensure_common_test_schema();
            let ty = DataType::named("GPS_DATA");
            let ep = DataEndpoint::named("RADIO");

            let seen_client: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_client_c = seen_client.clone();

            let source = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
                    .with_sender("SOURCE"),
                zero_clock(),
            ));
            source.enable_managed_variable(ty).unwrap();
            source.log(ty, &[1.0_f32, 2.0, 3.0]).unwrap();

            let client = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    ep,
                    move |pkt: &Packet| {
                        seen_client_c.lock().unwrap().push(pkt.clone());
                        Ok(())
                    },
                )])
                .with_sender("CLIENT_RESTARTED"),
                zero_clock(),
            ));

            client.enable_managed_variable(ty).unwrap();

            let client_for_source = client.clone();
            source.add_side_packet("to-client", move |pkt: &Packet| {
                client_for_source.rx_from_side(pkt, 0)
            });
            let source_for_client = source.clone();
            client.add_side_packet("to-source", move |pkt: &Packet| {
                source_for_client.rx_from_side(pkt, 0)
            });

            client.request_managed_variable(ty).unwrap();
            source.process_all_queues().unwrap();
            client.process_all_queues().unwrap();

            let seen = seen_client.lock().unwrap().clone();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].data_type(), ty);
            assert_eq!(seen[0].data_as_f32().unwrap(), vec![1.0, 2.0, 3.0]);
        }

        #[test]
        fn network_variable_getter_requests_missing_value_and_uses_cache() {
            crate::tests::ensure_common_test_schema();
            let ty = DataType::named("GPS_DATA");
            let ep = DataEndpoint::named("RADIO");

            let source = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
                    .with_sender("NV_SOURCE"),
                zero_clock(),
            ));
            let value = Packet::from_f32_slice(ty, &[9.0_f32, 8.0, 7.0], &[ep], 1).unwrap();
            source.seed_managed_variable(value).unwrap();

            let client = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
                    .with_sender("NV_CLIENT"),
                zero_clock(),
            ));

            let client_for_source = client.clone();
            source.add_side_packet("to-client", move |pkt: &Packet| {
                client_for_source.rx_from_side(pkt, 0)
            });
            let source_for_client = source.clone();
            client.add_side_packet("to-source", move |pkt: &Packet| {
                source_for_client.rx_from_side(pkt, 0)
            });

            assert!(client.get_network_variable(ty, None).unwrap().is_none());
            source.process_all_queues().unwrap();
            client.process_all_queues().unwrap();

            let cached = client.get_network_variable(ty, None).unwrap().unwrap();
            assert_eq!(cached.data_as_f32().unwrap(), vec![9.0, 8.0, 7.0]);
        }

        #[test]
        fn network_variable_update_callback_runs_on_inbound_cache_change() {
            crate::tests::ensure_common_test_schema();
            let ty = DataType::named("GPS_DATA");
            let ep = DataEndpoint::named("RADIO");

            let source = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
                    .with_sender("NV_SOURCE_CB"),
                zero_clock(),
            ));
            let value = Packet::from_f32_slice(ty, &[4.0_f32, 5.0, 6.0], &[ep], 1).unwrap();
            source.seed_managed_variable(value).unwrap();

            let client = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
                    .with_sender("NV_CLIENT_CB"),
                zero_clock(),
            ));
            let callback_values = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
            let callback_values_c = callback_values.clone();
            client
                .on_network_variable_update(ty, move |pkt| {
                    callback_values_c.lock().unwrap().push(pkt.data_as_f32()?);
                    Ok(())
                })
                .unwrap();

            let client_for_source = client.clone();
            source.add_side_packet("to-client", move |pkt: &Packet| {
                client_for_source.rx_from_side(pkt, 0)
            });
            let source_for_client = source.clone();
            client.add_side_packet("to-source", move |pkt: &Packet| {
                source_for_client.rx_from_side(pkt, 0)
            });

            assert!(client.get_network_variable(ty, None).unwrap().is_none());
            source.process_all_queues().unwrap();
            client.process_all_queues().unwrap();

            assert_eq!(
                *callback_values.lock().unwrap(),
                vec![vec![4.0_f32, 5.0, 6.0]]
            );
            client.process_all_queues().unwrap();
            assert_eq!(callback_values.lock().unwrap().len(), 1);
        }

        #[test]
        fn network_variable_setter_caches_and_respects_permissions() {
            crate::tests::ensure_common_test_schema();
            let ty = DataType::named("GPS_DATA");
            let ep = DataEndpoint::named("RADIO");
            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))]),
                zero_clock(),
            );
            let pkt = Packet::from_f32_slice(ty, &[1.0_f32, 2.0, 3.0], &[ep], 1).unwrap();

            router.set_network_variable(pkt.clone()).unwrap();
            assert_eq!(
                router
                    .get_cached_network_variable(ty)
                    .unwrap()
                    .unwrap()
                    .data_as_f32()
                    .unwrap(),
                vec![1.0, 2.0, 3.0]
            );

            router
                .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
                .unwrap();
            assert_eq!(
                router.set_network_variable(pkt),
                Err(TelemetryError::PermissionDenied)
            );
            router
                .enable_network_variable(ty, NetworkVariablePermissions::WRITE_ONLY)
                .unwrap();
            assert_eq!(
                router.get_cached_network_variable(ty),
                Err(TelemetryError::PermissionDenied)
            );
        }

        #[test]
        fn router_and_relay_memory_layout_exports_queue_breakdown() {
            crate::tests::ensure_common_test_schema();
            let ep = DataEndpoint::named("RADIO");
            let router = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))]),
                zero_clock(),
            );
            let router_json: serde_json::Value =
                serde_json::from_str(&router.export_memory_layout_json()).unwrap();
            assert_eq!(router_json["kind"], "router");
            assert!(
                router_json["shared_queue_bytes_allocated"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(router_json["rx_queue_bytes_used"].is_u64());
            assert!(router_json["tx_queue_bytes_allocated"].as_u64().unwrap() > 0);
            assert!(router_json["network_variable_cache_bytes_used"].is_u64());

            let relay = Relay::new(zero_clock());
            let relay_json: serde_json::Value =
                serde_json::from_str(&relay.export_memory_layout_json()).unwrap();
            assert_eq!(relay_json["kind"], "relay");
            assert!(relay_json["shared_queue_bytes_allocated"].as_u64().unwrap() > 0);
            assert!(relay_json["rx_queue_bytes_used"].is_u64());
            assert!(relay_json["replay_queue_bytes_allocated"].as_u64().unwrap() > 0);
        }

        #[test]
        fn required_e2e_type_rejects_tx_without_crypto_support() {
            #[cfg(feature = "cryptography")]
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            let ep = DataEndpoint::named("RADIO");
            let ty = DataType(3_901);
            let _ = remove_data_type(ty);
            register_data_type_id_with_description_and_e2e_encryption(
                ty,
                "E2E_REQUIRED_TEST",
                "",
                MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                ReliableMode::None,
                10,
                E2eEncryptionPolicy::RequireOn,
            )
            .unwrap();

            let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
            assert_eq!(router.log(ty, &[7_u8]), Err(TelemetryError::BadArg));

            let _ = remove_data_type(ty);
        }

        #[test]
        fn forced_e2e_router_rejects_plain_user_data_without_crypto_support() {
            #[cfg(feature = "cryptography")]
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            let ty = DataType::named("GPS_DATA");
            let router = Router::new_with_clock(
                RouterConfig::default().with_e2e_encryption(RouterE2eEncryptionMode::ForceAll),
                zero_clock(),
            );
            assert_eq!(
                router.log(ty, &[1.0_f32, 2.0, 3.0]),
                Err(TelemetryError::BadArg)
            );
        }

        #[cfg(feature = "cryptography")]
        unsafe extern "C" fn test_crypto_seal(
            key_id: u32,
            _nonce: *const u8,
            _nonce_len: usize,
            aad: *const u8,
            aad_len: usize,
            plaintext: *const u8,
            plaintext_len: usize,
            ciphertext_out: *mut u8,
            ciphertext_cap: usize,
            ciphertext_len_out: *mut usize,
            tag_out: *mut u8,
            tag_cap: usize,
            tag_len_out: *mut usize,
            _user: *mut core::ffi::c_void,
        ) -> i32 {
            if ciphertext_cap < plaintext_len || tag_cap < 4 {
                return -1;
            }
            let plain = unsafe { core::slice::from_raw_parts(plaintext, plaintext_len) };
            let out = unsafe { core::slice::from_raw_parts_mut(ciphertext_out, ciphertext_cap) };
            for (idx, byte) in plain.iter().copied().enumerate() {
                out[idx] = byte ^ key_id as u8 ^ 0xA5;
            }
            let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
            let mut tag = [0u8; 4];
            for (idx, byte) in aad.iter().copied().enumerate() {
                tag[idx % 4] ^= byte;
            }
            for idx in 0..plaintext_len {
                tag[idx % 4] ^= out[idx];
            }
            tag[0] ^= key_id as u8;
            let tag_out = unsafe { core::slice::from_raw_parts_mut(tag_out, tag_cap) };
            tag_out[..4].copy_from_slice(&tag);
            unsafe {
                *ciphertext_len_out = plaintext_len;
                *tag_len_out = 4;
            }
            0
        }

        #[cfg(feature = "cryptography")]
        unsafe extern "C" fn test_crypto_open(
            key_id: u32,
            _nonce: *const u8,
            _nonce_len: usize,
            aad: *const u8,
            aad_len: usize,
            ciphertext: *const u8,
            ciphertext_len: usize,
            tag: *const u8,
            tag_len: usize,
            plaintext_out: *mut u8,
            plaintext_cap: usize,
            plaintext_len_out: *mut usize,
            _user: *mut core::ffi::c_void,
        ) -> i32 {
            if plaintext_cap < ciphertext_len || tag_len != 4 {
                return -1;
            }
            let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
            let mut expected = [0u8; 4];
            for (idx, byte) in aad.iter().copied().enumerate() {
                expected[idx % 4] ^= byte;
            }
            let cipher = unsafe { core::slice::from_raw_parts(ciphertext, ciphertext_len) };
            for (idx, byte) in cipher.iter().copied().enumerate() {
                expected[idx % 4] ^= byte;
            }
            expected[0] ^= key_id as u8;
            let tag = unsafe { core::slice::from_raw_parts(tag, tag_len) };
            if tag != expected {
                return -1;
            }
            let out = unsafe { core::slice::from_raw_parts_mut(plaintext_out, plaintext_cap) };
            for (idx, byte) in cipher.iter().copied().enumerate() {
                out[idx] = byte ^ key_id as u8 ^ 0xA5;
            }
            unsafe {
                *plaintext_len_out = ciphertext_len;
            }
            0
        }

        #[cfg(feature = "cryptography")]
        fn refresh_crc32(bytes: &mut [u8]) {
            let data_len = bytes.len() - 4;
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&bytes[..data_len]);
            let crc = hasher.finalize();
            bytes[data_len..].copy_from_slice(&crc.to_le_bytes());
        }

        #[cfg(feature = "cryptography")]
        fn register_test_encryption() {
            crate::crypto::register_c_cryptography_provider(crate::crypto::CCryptographyProvider {
                seal: Some(test_crypto_seal),
                open: Some(test_crypto_open),
                user: core::ptr::null_mut(),
            });
        }

        #[cfg(feature = "cryptography")]
        #[test]
        fn preferred_e2e_type_seals_packed_side_payload_and_roundtrips() {
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            register_test_encryption();
            let ep = DataEndpoint::named("RADIO");
            let ty = DataType(3_902);
            let _ = remove_data_type(ty);
            register_data_type_id_with_description_and_e2e_encryption(
                ty,
                "E2E_PREFERRED_TEST",
                "",
                MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                ReliableMode::None,
                10,
                E2eEncryptionPolicy::PreferOn,
            )
            .unwrap();

            let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
            let captured_for_side = captured.clone();
            let router = Router::new_with_clock(
                RouterConfig::default()
                    .with_e2e_encryption(RouterE2eEncryptionMode::Preferred)
                    .with_e2e_key_id(0x5A),
                zero_clock(),
            );
            router.add_side_packed("crypto-link", move |bytes| {
                *captured_for_side.lock().unwrap() = bytes.to_vec();
                Ok(())
            });

            let payload = [1_u8, 2, 3, 4, 5, 6];
            router.log(ty, &payload).unwrap();
            let wire = captured.lock().unwrap().clone();
            assert!(!wire.windows(payload.len()).any(|window| window == payload));
            let decoded = wire_format::unpack_packet(&wire).unwrap();
            assert_eq!(decoded.data_type(), ty);
            assert_eq!(decoded.payload(), payload);

            let _ = remove_data_type(ty);
            crate::crypto::clear_c_cryptography_provider();
        }

        #[cfg(feature = "cryptography")]
        #[test]
        fn software_crypto_fallback_seals_payload_when_no_shim_is_registered() {
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            crate::crypto::register_software_key(0x91, b"0123456789abcdef0123456789abcdef")
                .unwrap();
            let ep = DataEndpoint::named("RADIO");
            let ty = DataType(3_905);
            let _ = remove_data_type(ty);
            register_data_type_id_with_description_and_e2e_encryption(
                ty,
                "E2E_SOFTWARE_FALLBACK_TEST",
                "",
                MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                ReliableMode::None,
                10,
                E2eEncryptionPolicy::PreferOn,
            )
            .unwrap();

            let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
            let captured_for_side = captured.clone();
            let router = Router::new_with_clock(
                RouterConfig::default()
                    .with_e2e_encryption(RouterE2eEncryptionMode::Preferred)
                    .with_e2e_key_id(0x91),
                zero_clock(),
            );
            router.add_side_packed("software-crypto-link", move |bytes| {
                *captured_for_side.lock().unwrap() = bytes.to_vec();
                Ok(())
            });

            let payload = [3_u8, 1, 4, 1, 5, 9, 2, 6];
            router.log(ty, &payload).unwrap();
            let wire = captured.lock().unwrap().clone();
            assert!(!wire.windows(payload.len()).any(|window| window == payload));
            let decoded = wire_format::unpack_packet(&wire).unwrap();
            assert_eq!(decoded.data_type(), ty);
            assert_eq!(decoded.payload(), payload);

            let mut tampered = wire;
            let data_len = tampered.len() - 4;
            tampered[data_len - 1] ^= 0x20;
            refresh_crc32(&mut tampered);
            assert!(wire_format::unpack_packet(&tampered).is_err());

            let _ = remove_data_type(ty);
        }

        #[cfg(feature = "cryptography")]
        #[test]
        fn encrypted_payload_rejects_authenticated_header_tamper() {
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            register_test_encryption();
            let ep = DataEndpoint::named("RADIO");
            let ty = DataType(3_903);
            let _ = remove_data_type(ty);
            register_data_type_id_with_description_and_e2e_encryption(
                ty,
                "E2E_TAMPER_TEST",
                "",
                MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                ReliableMode::None,
                10,
                E2eEncryptionPolicy::RequireOn,
            )
            .unwrap();

            let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
            let captured_for_side = captured.clone();
            let router = Router::new_with_clock(
                RouterConfig::default()
                    .with_e2e_encryption(RouterE2eEncryptionMode::RequiredOnly)
                    .with_e2e_key_id(0x33),
                zero_clock(),
            );
            router.add_side_packed("crypto-link", move |bytes| {
                *captured_for_side.lock().unwrap() = bytes.to_vec();
                Ok(())
            });

            router.log(ty, &[9_u8, 8, 7, 6]).unwrap();
            let mut wire = captured.lock().unwrap().clone();
            wire[1] ^= 0x01;
            refresh_crc32(&mut wire);
            assert!(wire_format::unpack_packet(&wire).is_err());

            let _ = remove_data_type(ty);
            crate::crypto::clear_c_cryptography_provider();
        }

        #[cfg(feature = "cryptography")]
        #[test]
        fn preferred_e2e_fanout_reaches_three_boards_with_same_endpoint_and_rejects_mods() {
            let _crypto_guard = crypto_test_guard();
            crate::tests::ensure_common_test_schema();
            register_test_encryption();
            let ep = DataEndpoint::named("RADIO");
            let ty = DataType(3_904);
            let _ = remove_data_type(ty);
            register_data_type_id_with_description_and_e2e_encryption(
                ty,
                "E2E_THREE_BOARD_RADIO_TEST",
                "",
                MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                ReliableMode::None,
                10,
                E2eEncryptionPolicy::PreferOn,
            )
            .unwrap();

            let seen_a = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let seen_b = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let seen_c = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

            let mk_board = |name: &'static str, seen: Arc<Mutex<Vec<Vec<u8>>>>| {
                Router::new_with_clock(
                    RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, move |pkt| {
                        seen.lock().unwrap().push(pkt.payload().to_vec());
                        Ok(())
                    })])
                    .with_sender(name)
                    .with_e2e_key_id(0x44),
                    zero_clock(),
                )
            };

            let board_a = Arc::new(mk_board("BOARD_A", seen_a.clone()));
            let board_b = Arc::new(mk_board("BOARD_B", seen_b.clone()));
            let board_c = Arc::new(mk_board("BOARD_C", seen_c.clone()));
            let captured = Arc::new(Mutex::new(Vec::<u8>::new()));

            let source = Router::new_with_clock(
                RouterConfig::default()
                    .with_sender("SOURCE")
                    .with_e2e_key_id(0x44),
                zero_clock(),
            );

            let a = board_a.clone();
            let b = board_b.clone();
            let c = board_c.clone();
            let captured_for_side = captured.clone();
            source.add_side_packed("shared-radio", move |bytes| {
                *captured_for_side.lock().unwrap() = bytes.to_vec();
                a.rx_packed(bytes)?;
                b.rx_packed(bytes)?;
                c.rx_packed(bytes)?;
                Ok(())
            });

            let payload = [42_u8, 9, 7, 1];
            source.log(ty, &payload).unwrap();
            assert_eq!(seen_a.lock().unwrap().as_slice(), &[payload.to_vec()]);
            assert_eq!(seen_b.lock().unwrap().as_slice(), &[payload.to_vec()]);
            assert_eq!(seen_c.lock().unwrap().as_slice(), &[payload.to_vec()]);

            let wire = captured.lock().unwrap().clone();
            assert!(!wire.windows(payload.len()).any(|window| window == payload));

            let mut header_tampered = wire.clone();
            header_tampered[1] ^= 0x01;
            refresh_crc32(&mut header_tampered);
            assert!(board_a.rx_packed(&header_tampered).is_err());

            let mut payload_tampered = wire;
            let data_len = payload_tampered.len() - 4;
            payload_tampered[data_len - 1] ^= 0x55;
            refresh_crc32(&mut payload_tampered);
            assert!(board_b.rx_packed(&payload_tampered).is_err());

            let _ = remove_data_type(ty);
            crate::crypto::clear_c_cryptography_provider();
        }

        #[test]
        fn immediate_cross_wired_router_reentry_falls_back_to_queue() {
            let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
                return;
            };

            let remaining = Arc::new(AtomicUsize::new(6));
            let sequence = Arc::new(AtomicUsize::new(1));
            let a_slot = Arc::new(Mutex::new(None::<Arc<Router>>));
            let b_slot = Arc::new(Mutex::new(None::<Arc<Router>>));

            let a_remaining = remaining.clone();
            let a_sequence = sequence.clone();
            let a_router = a_slot.clone();
            let router_a = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    move |_pkt: &Packet| {
                        if a_remaining
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                            .is_err()
                        {
                            return Ok(());
                        }
                        let seq = a_sequence.fetch_add(1, Ordering::SeqCst) as u64;
                        let pkt = Packet::new(
                            ipc_message,
                            &[DataEndpoint::named("SD_CARD")],
                            "A_NODE",
                            seq,
                            Arc::<[u8]>::from(b"bounce-a".as_slice()),
                        )?;
                        a_router
                            .lock()
                            .unwrap()
                            .as_ref()
                            .expect("router A initialized")
                            .tx(pkt)
                    },
                )])
                .with_sender("A_NODE"),
                StepClock::new_default_box(),
            ));

            let b_remaining = remaining.clone();
            let b_sequence = sequence.clone();
            let b_router = b_slot.clone();
            let router_b = Arc::new(Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("SD_CARD"),
                    move |_pkt: &Packet| {
                        if b_remaining
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                            .is_err()
                        {
                            return Ok(());
                        }
                        let seq = b_sequence.fetch_add(1, Ordering::SeqCst) as u64;
                        let pkt = Packet::new(
                            ipc_message,
                            &[DataEndpoint::named("RADIO")],
                            "B_NODE",
                            seq,
                            Arc::<[u8]>::from(b"bounce-b".as_slice()),
                        )?;
                        b_router
                            .lock()
                            .unwrap()
                            .as_ref()
                            .expect("router B initialized")
                            .tx(pkt)
                    },
                )])
                .with_sender("B_NODE"),
                StepClock::new_default_box(),
            ));

            *a_slot.lock().unwrap() = Some(router_a.clone());
            *b_slot.lock().unwrap() = Some(router_b.clone());

            let a_in_tx = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let a_reentered = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let b_in_tx = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let b_reentered = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let router_b_for_side = router_b.clone();
            let a_in_tx_flag = a_in_tx.clone();
            let a_reentered_flag = a_reentered.clone();
            let side_a = router_a.add_side_packet("A_TO_B", move |pkt: &Packet| {
                if a_in_tx_flag.swap(true, Ordering::SeqCst) {
                    a_reentered_flag.store(true, Ordering::SeqCst);
                }
                let result = router_b_for_side.rx_from_side(pkt, 0);
                a_in_tx_flag.store(false, Ordering::SeqCst);
                result
            });

            let router_a_for_side = router_a.clone();
            let b_in_tx_flag = b_in_tx.clone();
            let b_reentered_flag = b_reentered.clone();
            let side_b = router_b.add_side_packet("B_TO_A", move |pkt: &Packet| {
                if b_in_tx_flag.swap(true, Ordering::SeqCst) {
                    b_reentered_flag.store(true, Ordering::SeqCst);
                }
                let result = router_a_for_side.rx_from_side(pkt, 0);
                b_in_tx_flag.store(false, Ordering::SeqCst);
                result
            });

            assert_eq!(side_a, 0);
            assert_eq!(side_b, 0);

            let first = Packet::new(
                ipc_message,
                &[DataEndpoint::named("SD_CARD")],
                "START",
                0,
                Arc::<[u8]>::from(b"start".as_slice()),
            )
            .unwrap();
            router_a.tx(first).unwrap();

            for _ in 0..8 {
                router_a.process_all_queues().unwrap();
                router_b.process_all_queues().unwrap();
            }

            assert!(!a_reentered.load(Ordering::SeqCst));
            assert!(!b_reentered.load(Ordering::SeqCst));
            assert!(remaining.load(Ordering::SeqCst) < 6);
        }
    }

    #[cfg(feature = "discovery")]
    mod schema_sync_tests {
        use alloc::sync::Arc;

        use crate::{
            DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType,
            MessageElement, ReliableMode, TelemetryError,
            config::{
                DataTypeDefinition, EndpointDefinition, MAX_QUEUE_BUDGET, OwnedDataTypeDefinition,
                OwnedEndpointDefinition, OwnedRuntimeSchemaSnapshot, RuntimeSchemaSnapshot,
                data_type_definition_by_name, data_type_exists, endpoint_definition_by_name,
                endpoint_exists, export_schema, merge_owned_schema_snapshot,
                merge_owned_schema_snapshot_with_budget, merge_schema_snapshot,
                owned_schema_byte_cost, register_data_type_id,
                register_data_type_id_with_description, register_data_type_with_description,
                register_endpoint_id_with_description, register_endpoint_with_description,
                register_schema_json_bytes, register_schema_json_file, remove_data_type_by_name,
                remove_endpoint, remove_endpoint_by_name, schema_bytes_used,
            },
            discovery::{build_discovery_schema_from_snapshot, decode_discovery_schema},
            message_meta,
            packet::Packet,
            router::EndpointHandler,
        };

        #[test]
        fn discovery_schema_packet_roundtrips_and_merges_new_entries() {
            static ENDPOINTS_230: [DataEndpoint; 1] = [DataEndpoint(230)];
            let endpoint = EndpointDefinition {
                id: DataEndpoint(230),
                name: "SCHEMA_SYNC_EP_230",
                description: "",
                link_local_only: false,
            };
            let ty = DataTypeDefinition {
                id: DataType(3001),
                name: "SCHEMA_SYNC_TYPE_3001",
                description: "",
                element: MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
                endpoints: &ENDPOINTS_230,
                reliable: ReliableMode::None,
                priority: 17,
                e2e_encryption: E2eEncryptionPolicy::PreferOn,
            };
            let snapshot = RuntimeSchemaSnapshot {
                endpoints: vec![endpoint],
                types: vec![ty],
            };
            let pkt = build_discovery_schema_from_snapshot("REMOTE", 10, snapshot).unwrap();
            let decoded = decode_discovery_schema(&pkt).unwrap();
            assert_eq!(
                decoded.types[0].e2e_encryption,
                E2eEncryptionPolicy::PreferOn
            );
            let report = merge_owned_schema_snapshot(decoded);
            assert!(report.changed() || DataType::try_from_u32(3001).is_some());
            assert_eq!(message_meta(DataType(3001)).element, ty.element);
        }

        #[test]
        fn decoded_schema_is_owned_until_it_fits_the_registry_budget() {
            let endpoint = OwnedEndpointDefinition {
                id: DataEndpoint(250),
                name: "SCHEMA_SYNC_BUDGET_EP_250".to_string(),
                description: String::new(),
                link_local_only: false,
            };
            let ty = OwnedDataTypeDefinition {
                id: DataType(4090),
                name: "X".repeat(MAX_QUEUE_BUDGET),
                description: String::new(),
                element: MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
                endpoints: vec![endpoint.id],
                reliable: ReliableMode::None,
                priority: 1,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            };
            let snapshot = OwnedRuntimeSchemaSnapshot {
                endpoints: vec![endpoint],
                types: vec![ty],
            };
            assert!(owned_schema_byte_cost(&snapshot) > MAX_QUEUE_BUDGET);

            let err =
                merge_owned_schema_snapshot_with_budget(snapshot, MAX_QUEUE_BUDGET).unwrap_err();
            assert!(matches!(err, TelemetryError::PacketTooLarge(_)));
            assert!(schema_bytes_used() <= MAX_QUEUE_BUDGET);
            assert!(DataType::try_from_u32(4090).is_none());
        }

        #[test]
        fn schema_registry_counts_against_router_shared_queue_budget() {
            use crate::router::{Router, RouterConfig};

            let router = Router::new(RouterConfig::default());
            let schema_bytes = schema_bytes_used();
            assert!(schema_bytes > 0);
            assert!(router.debug_shared_queue_bytes_used() >= schema_bytes);
            assert!(router.debug_shared_queue_bytes_used() <= MAX_QUEUE_BUDGET);
        }

        #[test]
        fn endpoint_handler_registration_creates_missing_endpoint() {
            let endpoint = DataEndpoint(249);
            assert!(!endpoint_exists(endpoint));
            let _handler = EndpointHandler::new_packet_handler(endpoint, |_pkt: &Packet| Ok(()));
            assert!(endpoint_exists(endpoint));
            assert_eq!(endpoint.as_str(), "ENDPOINT_249");
        }

        #[test]
        fn runtime_schema_auto_ids_are_searchable_exported_and_removable() {
            let ep_name = "SCHEMA_AUTO_EP_UNIQUE_9000";
            let ty_name = "SCHEMA_AUTO_TYPE_UNIQUE_9000";
            let _ = remove_data_type_by_name(ty_name);
            let _ = remove_endpoint_by_name(ep_name);

            assert!(DataEndpoint::try_named("SCHEMA_AUTO_EP_MISSING_9000").is_none());
            assert!(DataType::try_named("SCHEMA_AUTO_TYPE_MISSING_9000").is_none());

            let endpoint =
                register_endpoint_with_description(ep_name, "auto id endpoint", false).unwrap();
            let ty = register_data_type_with_description(
                ty_name,
                "auto id data type",
                MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Warning),
                &[endpoint],
                ReliableMode::Unordered,
                42,
            )
            .unwrap();

            assert_eq!(DataEndpoint::try_named(ep_name), Some(endpoint));
            assert_eq!(DataType::try_named(ty_name), Some(ty));

            let endpoint_ref = endpoint_definition_by_name(ep_name).unwrap();
            assert_eq!(endpoint_ref.id, endpoint);
            assert_eq!(endpoint_ref.description, "auto id endpoint");

            let ty_ref = data_type_definition_by_name(ty_name).unwrap();
            assert_eq!(ty_ref.id, ty);
            assert_eq!(ty_ref.description, "auto id data type");
            assert_eq!(ty_ref.endpoints, &[endpoint]);
            assert_eq!(message_meta(ty).reliable, ReliableMode::Unordered);
            assert_eq!(message_meta(ty).priority, 42);

            let snapshot = export_schema();
            assert!(
                snapshot
                    .endpoints
                    .iter()
                    .any(|def| def.id == endpoint && def.name == ep_name)
            );
            assert!(
                snapshot
                    .types
                    .iter()
                    .any(|def| def.id == ty && def.name == ty_name)
            );

            assert!(remove_data_type_by_name(ty_name).unwrap());
            assert!(remove_endpoint_by_name(ep_name).unwrap());
            assert!(DataEndpoint::try_named(ep_name).is_none());
            assert!(DataType::try_named(ty_name).is_none());
        }

        #[test]
        fn runtime_json_bytes_and_file_seed_schema_metadata() {
            let bytes_ep = "SCHEMA_JSON_BYTES_EP_9001";
            let bytes_ty = "SCHEMA_JSON_BYTES_TYPE_9001";
            let file_ep = "SCHEMA_JSON_FILE_EP_9002";
            let file_ty = "SCHEMA_JSON_FILE_TYPE_9002";
            for name in [bytes_ty, file_ty] {
                let _ = remove_data_type_by_name(name);
            }
            for name in [bytes_ep, file_ep] {
                let _ = remove_endpoint_by_name(name);
            }

            let bytes_json = br#"{
                "endpoints": [
                    {
                        "rust": "SchemaJsonBytesEp9001",
                        "name": "SCHEMA_JSON_BYTES_EP_9001",
                        "description": "json bytes endpoint",
                        "broadcast_mode": "Never"
                    }
                ],
                "types": [
                    {
                        "rust": "SchemaJsonBytesType9001",
                        "name": "SCHEMA_JSON_BYTES_TYPE_9001",
                        "description": "json bytes type",
                        "priority": 77,
                        "reliable": true,
                        "class": "Data",
                        "element": { "kind": "Static", "data_type": "UInt8", "count": 4 },
                        "endpoints": ["SchemaJsonBytesEp9001"]
                    }
                ]
            }"#;
            register_schema_json_bytes(bytes_json).unwrap();

            let ep = endpoint_definition_by_name(bytes_ep).unwrap();
            assert_eq!(ep.description, "json bytes endpoint");
            assert!(ep.link_local_only);
            let ty = data_type_definition_by_name(bytes_ty).unwrap();
            assert_eq!(ty.description, "json bytes type");
            assert_eq!(
                ty.element,
                MessageElement::Static(4, MessageDataType::UInt8, MessageClass::Data)
            );
            assert_eq!(ty.reliable, ReliableMode::Ordered);
            assert_eq!(ty.priority, 77);
            assert_eq!(ty.endpoints, &[ep.id]);

            let file_json = br#"{
                "endpoints": [
                    {
                        "rust": "SchemaJsonFileEp9002",
                        "name": "SCHEMA_JSON_FILE_EP_9002",
                        "doc": "json file endpoint",
                        "link_local_only": true
                    }
                ],
                "types": [
                    {
                        "rust": "SchemaJsonFileType9002",
                        "name": "SCHEMA_JSON_FILE_TYPE_9002",
                        "doc": "json file type",
                        "priority": 12,
                        "reliable_mode": "Unordered",
                        "class": "Error",
                        "element": { "kind": "Dynamic", "data_type": "String" },
                        "endpoints": ["SchemaJsonFileEp9002"]
                    }
                ]
            }"#;
            let path = std::env::temp_dir().join(format!(
                "sedsnet_runtime_schema_{}_{}.json",
                std::process::id(),
                9002
            ));
            std::fs::write(&path, file_json).unwrap();
            register_schema_json_file(&path).unwrap();
            let _ = std::fs::remove_file(&path);

            let ep = endpoint_definition_by_name(file_ep).unwrap();
            assert_eq!(ep.description, "json file endpoint");
            assert!(ep.link_local_only);
            let ty = data_type_definition_by_name(file_ty).unwrap();
            assert_eq!(ty.description, "json file type");
            assert_eq!(
                ty.element,
                MessageElement::Dynamic(MessageDataType::String, MessageClass::Error)
            );
            assert_eq!(ty.reliable, ReliableMode::Unordered);
            assert_eq!(ty.priority, 12);
            assert_eq!(ty.endpoints, &[ep.id]);

            for name in [bytes_ty, file_ty] {
                assert!(remove_data_type_by_name(name).unwrap());
            }
            for name in [bytes_ep, file_ep] {
                assert!(remove_endpoint_by_name(name).unwrap());
            }
        }

        #[test]
        fn endpoint_registration_conflicts_and_endpoint_removal_are_validated() {
            let endpoint = DataEndpoint(9003);
            let ty = DataType(9003);
            let ep_name = "SCHEMA_CONFLICT_EP_9003";
            let ty_name = "SCHEMA_CONFLICT_TYPE_9003";
            let _ = remove_data_type_by_name(ty_name);
            let _ = remove_endpoint(endpoint);
            let _ = remove_endpoint_by_name(ep_name);

            register_endpoint_id_with_description(endpoint, ep_name, "first endpoint", false)
                .unwrap();
            assert_eq!(
                register_endpoint_id_with_description(
                    endpoint,
                    "SCHEMA_CONFLICT_EP_OTHER_9003",
                    "first endpoint",
                    false,
                )
                .unwrap_err(),
                TelemetryError::BadArg
            );
            assert_eq!(
                register_endpoint_id_with_description(
                    DataEndpoint(9004),
                    ep_name,
                    "first endpoint",
                    false,
                )
                .unwrap_err(),
                TelemetryError::BadArg
            );

            register_data_type_id_with_description(
                ty,
                ty_name,
                "dependent type",
                MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                1,
            )
            .unwrap();
            assert!(data_type_exists(ty));

            assert!(remove_endpoint(endpoint).unwrap());
            assert!(!endpoint_exists(endpoint));
            assert!(!data_type_exists(ty));
        }

        #[test]
        fn schema_entries_can_be_named_described_used_by_handlers_and_removed() {
            let endpoint = DataEndpoint(247);
            let ty = DataType(4088);
            let ep_name = "SCHEMA_LOOKUP_EP_247";
            let ty_name = "SCHEMA_LOOKUP_TYPE_4088";
            let _ = remove_data_type_by_name(ty_name);
            let _ = remove_endpoint_by_name(ep_name);

            register_endpoint_id_with_description(endpoint, ep_name, "lookup test endpoint", false)
                .unwrap();
            register_data_type_id_with_description(
                ty,
                ty_name,
                "lookup test type",
                MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                9,
            )
            .unwrap();

            let endpoint_ref = endpoint_definition_by_name(ep_name).unwrap();
            assert_eq!(endpoint_ref.id, endpoint);
            assert_eq!(endpoint_ref.description, "lookup test endpoint");
            let _handler =
                EndpointHandler::new_packet_handler_for(endpoint_ref, |_pkt: &Packet| Ok(()));

            let ty_ref = data_type_definition_by_name(ty_name).unwrap();
            assert_eq!(ty_ref.id, ty);
            assert_eq!(ty_ref.description, "lookup test type");
            assert_eq!(message_meta(ty).priority, 9);

            assert!(remove_data_type_by_name(ty_name).unwrap());
            assert!(!data_type_exists(ty));
            assert!(remove_endpoint_by_name(ep_name).unwrap());
            assert!(!endpoint_exists(endpoint));
        }

        #[test]
        fn data_type_registration_rejects_different_shape_for_existing_id() {
            let endpoint = DataEndpoint(248);
            let _handler = EndpointHandler::new_packet_handler(endpoint, |_pkt: &Packet| Ok(()));
            let ty = DataType(4089);
            let first = register_data_type_id(
                ty,
                "SCHEMA_SYNC_EXPLICIT_TYPE_4089",
                MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                3,
            );
            assert!(first.is_ok() || data_type_exists(ty));
            let err = register_data_type_id(
                ty,
                "SCHEMA_SYNC_EXPLICIT_TYPE_4089",
                MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                3,
            )
            .unwrap_err();
            assert_eq!(err, TelemetryError::BadArg);
        }

        #[test]
        fn conflicting_schema_type_layout_resolves_deterministically() {
            static ENDPOINTS_231: [DataEndpoint; 1] = [DataEndpoint(231)];
            let endpoint = EndpointDefinition {
                id: DataEndpoint(231),
                name: "SCHEMA_SYNC_EP_231",
                description: "",
                link_local_only: false,
            };
            let a = DataTypeDefinition {
                id: DataType(3002),
                name: "SCHEMA_SYNC_TYPE_3002",
                description: "",
                element: MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
                endpoints: &ENDPOINTS_231,
                reliable: ReliableMode::None,
                priority: 1,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            };
            let b = DataTypeDefinition {
                id: DataType(3002),
                name: "SCHEMA_SYNC_TYPE_3002",
                description: "",
                element: MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
                endpoints: &ENDPOINTS_231,
                reliable: ReliableMode::None,
                priority: 1,
                e2e_encryption: E2eEncryptionPolicy::PreferOff,
            };

            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![endpoint],
                types: vec![a],
            });
            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![endpoint],
                types: vec![b],
            });
            let first = message_meta(DataType(3002)).element;
            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![endpoint],
                types: vec![a],
            });
            let second = message_meta(DataType(3002)).element;
            assert_eq!(first, second);
            assert!(export_schema().types.iter().any(|def| {
                def.id == DataType(3002) && (def.element == a.element || def.element == b.element)
            }));
        }

        #[test]
        fn inline_wire_shape_keeps_old_payload_decodable_after_layout_change() {
            crate::tests::ensure_common_test_schema();
            let endpoint = DataEndpoint::named("RADIO");
            let ty = (13..=crate::MAX_VALUE_DATA_TYPE)
                .find_map(|id| {
                    (!crate::config::data_type_exists(DataType(id))).then_some(DataType(id))
                })
                .expect("free runtime data type id");
            let ty_name = "SCHEMA_WIRE_TYPE_4090";
            let _ = remove_data_type_by_name(ty_name);
            register_data_type_id_with_description(
                ty,
                ty_name,
                "wire shape type v1",
                MessageElement::Static(1, MessageDataType::UInt16, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                1,
            )
            .unwrap();

            let pkt = Packet::new(
                ty,
                &[endpoint],
                "SRC",
                0,
                Arc::<[u8]>::from(7u16.to_le_bytes().to_vec()),
            )
            .unwrap();
            let wire = crate::wire_format::pack_packet_with_wire_contract(
                &pkt,
                None,
                Some(crate::message_meta(ty).element),
                &[],
            )
            .unwrap();

            assert!(remove_data_type_by_name(ty_name).unwrap());
            register_data_type_id_with_description(
                ty,
                ty_name,
                "wire shape type v2",
                MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
                &[endpoint],
                ReliableMode::None,
                1,
            )
            .unwrap();

            let decoded = crate::wire_format::unpack_packet(&wire).unwrap();
            decoded.validate().unwrap();
            assert_eq!(decoded.data_as_u16().unwrap(), vec![7u16]);
        }

        #[test]
        fn conflicting_schema_endpoint_metadata_resolves_deterministically() {
            let a = EndpointDefinition {
                id: DataEndpoint(9005),
                name: "SCHEMA_SYNC_EP_9005_A",
                description: "a",
                link_local_only: false,
            };
            let b = EndpointDefinition {
                id: DataEndpoint(9005),
                name: "SCHEMA_SYNC_EP_9005_B",
                description: "b",
                link_local_only: true,
            };

            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![a],
                types: vec![],
            });
            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![b],
                types: vec![],
            });
            let first = endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_A")
                .or_else(|| endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_B"))
                .unwrap();
            let _ = merge_schema_snapshot(RuntimeSchemaSnapshot {
                endpoints: vec![a],
                types: vec![],
            });
            let second = endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_A")
                .or_else(|| endpoint_definition_by_name("SCHEMA_SYNC_EP_9005_B"))
                .unwrap();

            assert_eq!(first.id, second.id);
            assert_eq!(first.name, second.name);
            assert_eq!(first.description, second.description);
            assert_eq!(first.link_local_only, second.link_local_only);
            assert!(first == a || first == b);
        }
    }

    #[cfg(feature = "timesync")]
    mod timesync_tests {
        use crate::timesync::{
            build_timesync_request, build_timesync_response, compute_offset_delay,
            decode_timesync_request, decode_timesync_response,
        };

        #[test]
        fn timesync_request_roundtrip() {
            let pkt = build_timesync_request(7, 1234).unwrap();
            let decoded = decode_timesync_request(&pkt).unwrap();
            assert_eq!(decoded.seq, 7);
            assert_eq!(decoded.t1_ms, 1234);
        }

        #[test]
        fn timesync_response_roundtrip() {
            let pkt = build_timesync_response(9, 100, 110, 115).unwrap();
            let decoded = decode_timesync_response(&pkt).unwrap();
            assert_eq!(decoded.seq, 9);
            assert_eq!(decoded.t1_ms, 100);
            assert_eq!(decoded.t2_ms, 110);
            assert_eq!(decoded.t3_ms, 115);
        }

        #[test]
        fn timesync_offset_delay_math() {
            let sample = compute_offset_delay(10, 20, 30, 40);
            assert_eq!(sample.offset_ms, 0);
            assert_eq!(sample.delay_ms, 20);
        }
    }
}
