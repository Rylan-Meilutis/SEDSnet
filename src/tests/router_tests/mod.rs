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
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
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
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
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
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
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
    let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], endpoints, 0)
        .unwrap();
    let bytes = wire_format::pack_packet(&pkt);

    router.rx_packed(&bytes).unwrap();
    let got = seen.lock().unwrap().clone().expect("no bytes delivered");
    assert_eq!(*got, *bytes);
}

#[cfg(feature = "discovery")]
mod discovery_tests;

#[cfg(feature = "discovery")]
mod schema_sync_tests;

#[cfg(feature = "timesync")]
mod timesync_tests;
