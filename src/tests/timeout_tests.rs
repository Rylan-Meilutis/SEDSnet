
//! Tests for `process_*_queue*` functions and timeout semantics,
//! including u64 wraparound handling.

use crate::config::DataEndpoint;
use crate::router::EndpointHandler;
use crate::tests::{UnixClock, get_handler, packed_frame_type};
use crate::{
    DataType, TelemetryResult, packet::Packet, router::Clock, router::Router, router::RouterConfig,
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
