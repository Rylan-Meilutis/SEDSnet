use crate::config::{STATIC_HEX_LENGTH, STATIC_STRING_LENGTH, get_message_meta};
mod error_display_tests;
use crate::get_needed_message_size;
use crate::packet::Packet;
use crate::relay::Relay;
use crate::router::{Clock, EndpointHandler, Router, RouterConfig};
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
mod compression_memory_tests;

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
        (RECENT_RX_QUEUE_BYTES.max(1) / size_of::<u64>()).max(1)
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

    let relay = Relay::new(Box::new(timeout_tests::StepClock::new(0, 0)));
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
        for chunk in pkt.payload().as_chunks::<4>().0 {
            vals.push(f32::from_le_bytes(*chunk));
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
mod tests2;

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

#[test]
fn router_and_relay_side_churn_reclaims_names_and_reuses_slots() {
    let router = Router::new(RouterConfig::default());
    let relay = Relay::new(timeout_tests::StepClock::new_default_box());
    let mut router_capacity = None;
    let mut relay_capacity = None;

    for index in 0..256 {
        let router_side = router.add_side_packed(format!("router-side-{index}"), |_| Ok(()));
        assert_eq!(router_side, 0);
        router.remove_side(router_side).unwrap();
        let router_storage = router.debug_side_storage();
        assert_eq!(router_storage.0, 0);
        if let Some(capacity) = router_capacity {
            assert_eq!(router_storage.1, capacity);
        } else {
            router_capacity = Some(router_storage.1);
        }

        let relay_side = relay.add_side_packed(format!("relay-side-{index}"), |_| Ok(()));
        assert_eq!(relay_side, 0);
        relay.remove_side(relay_side).unwrap();
        let relay_storage = relay.debug_side_storage();
        assert_eq!(relay_storage.0, 0);
        if let Some(capacity) = relay_capacity {
            assert_eq!(relay_storage.1, capacity);
        } else {
            relay_capacity = Some(relay_storage.1);
        }
    }

    assert!(router_capacity.is_some_and(|capacity| capacity > 0 && capacity <= 4));
    assert!(relay_capacity.is_some_and(|capacity| capacity > 0 && capacity <= 4));
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
mod p2p_address_tests;

// -----------------------------------------------------------------------------
// Error propagation & handler-failure tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod handler_failure_tests;

// -----------------------------------------------------------------------------
// Timeout and queue-draining behavior tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod timeout_tests;

// -----------------------------------------------------------------------------
// Extra coverage tests: error codes, header-only parsing, varints, bitmaps, etc.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests_extra;

// -----------------------------------------------------------------------------
// More tests: validation, enum bounds, router paths, payload helpers, etc.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests_more;

// -----------------------------------------------------------------------------
// Concurrency tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod concurrency_tests;
mod data_conversion_types;

// -----------------------------------------------------------------------------
// Relay tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod relay_tests;

#[cfg(test)]
mod dedupe_tests;

#[cfg(test)]
mod relay_reliable_tests;

#[cfg(test)]
mod reliable_tests;

#[cfg(test)]
mod router_tests;
#[test]
fn scheduler_reserves_discovery_and_shared_state_priority_bands() {
    let discovery = crate::scheduler_priority(DataType::DiscoveryAddress);
    let schema = crate::scheduler_priority(DataType::DiscoverySchema);
    let managed = crate::scheduler_priority(DataType::ManagedVariableValue);
    let timesync = crate::scheduler_priority(DataType::TimeSyncAnnounce);
    let user = crate::scheduler_priority(DataType::P2pMessage);

    assert_eq!(discovery, 255);
    assert_eq!(schema, managed);
    assert_eq!(managed, timesync);
    assert!(discovery > managed);
    assert!(managed > user);
}
