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

    let tx_fail = |_bytes: &[u8]| -> crate::TelemetryResult<()> { Err(TelemetryError::Io("boom")) };
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

#[test]
fn remote_only_tx_failure_is_bounded_and_not_reported_over_failed_side() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_c = attempts.clone();
    let router = Router::new_with_clock(RouterConfig::default(), StepClock::new_default_box());
    router.add_side_packed("failed", move |_bytes: &[u8]| {
        attempts_c.fetch_add(1, Ordering::SeqCst);
        Err(TelemetryError::Io("transport unavailable"))
    });

    let ty = pick_any_type();
    let packet = Packet::new(
        ty,
        &[DataEndpoint::named("RADIO")],
        "isolated_board",
        0,
        Arc::<[u8]>::from(payload_for(ty)),
    )
    .unwrap();

    assert!(router.tx(packet).is_err());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        crate::config::MAX_HANDLER_RETRIES,
        "a failed transport must not recursively transmit its own error report"
    );
}
