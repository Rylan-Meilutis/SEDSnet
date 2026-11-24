//! One side that refuses every frame ("side tx busy") must not hold back
//! another side's frames. Each TX pass has a wall-clock budget; on a slow
//! CPU it reaches only a few queued items, and re-offering the busy side's
//! backlog item by item used all of it, so a frame for an idle side queued
//! behind that backlog waited for seconds. The model below charges model
//! time for every refusal, as a slow CPU does, and counts model time.

use crate::config::{DataEndpoint, DataType, register_data_type_with_description};
use crate::packet::Packet;
use crate::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const PASS_BUDGET_MS: u32 = 3;
const CLOCK_READS_PER_MS: u64 = 5_000;

fn endpoint(name: &str) -> DataEndpoint {
    crate::tests::ensure_common_test_schema();
    DataEndpoint::try_named(name)
        .unwrap_or_else(|| crate::config::register_endpoint(name, false).unwrap())
}

fn test_type(name: &str, endpoint_name: &str, mode: ReliableMode, priority: u8) -> DataType {
    let endpoint = endpoint(endpoint_name);
    DataType::try_named(name).unwrap_or_else(|| {
        register_data_type_with_description(
            name,
            "side busy skip model",
            MessageElement::Static(2, MessageDataType::Float32, MessageClass::Data),
            &[endpoint],
            mode,
            priority,
        )
        .unwrap()
    })
}

type Offers = Arc<Mutex<Vec<(u64, Option<DataType>)>>>;

struct Model {
    router: Router,
    now: Arc<AtomicU64>,
    radio: usize,
    umbilical: usize,
    /// (model ms, type) of every frame offered to the busy radio.
    radio_offers: Offers,
    /// (model ms, type) of every frame the umbilical took.
    umbilical_frames: Offers,
}

/// A node with a radio that refuses everything, each refusal costing
/// `1 / refusals_per_ms` of model time, and an umbilical that takes
/// everything. Each side has a peer announcing one endpoint.
fn model(refusals_per_ms: u64, mode: ReliableMode) -> Model {
    model_accepting(refusals_per_ms, mode, None)
}

/// As `model`, but the radio takes frames of `accepted` (a side that refuses
/// one class of frame while it has room for another).
fn model_accepting(refusals_per_ms: u64, mode: ReliableMode, accepted: Option<DataType>) -> Model {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(1_000));
    let (clock, reads) = (now.clone(), AtomicU64::new(0));
    // All router work costs a little model time too (one millisecond per
    // CLOCK_READS_PER_MS clock reads), so a pass always ends.
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("SIDE_BUSY_HOST"),
        Box::new(move || {
            if reads.fetch_add(1, Ordering::Relaxed) % CLOCK_READS_PER_MS == CLOCK_READS_PER_MS - 1 {
                clock.fetch_add(1, Ordering::Relaxed);
            }
            clock.load(Ordering::Relaxed)
        }),
    );
    let reliable = !matches!(mode, ReliableMode::None);
    let radio_offers: Offers = Default::default();
    let (offers, cost, refusals) = (radio_offers.clone(), now.clone(), AtomicU64::new(0));
    let radio = router.add_side_packed_with_options(
        "radio",
        move |bytes: &[u8]| {
            let ty = crate::tests::packed_frame_type(bytes);
            offers.lock().unwrap().push((cost.load(Ordering::Relaxed), ty));
            if accepted.is_some() && ty == accepted {
                return Ok(());
            }
            if refusals.fetch_add(1, Ordering::Relaxed) % refusals_per_ms == refusals_per_ms - 1 {
                cost.fetch_add(1, Ordering::Relaxed);
            }
            Err(crate::TelemetryError::Io("side tx busy"))
        },
        RouterSideOptions { reliable_enabled: reliable, ..Default::default() },
    );
    let umbilical_frames: Offers = Default::default();
    let (frames, at) = (umbilical_frames.clone(), now.clone());
    let umbilical = router.add_side_packed_with_options(
        "umbilical",
        move |bytes: &[u8]| {
            frames
                .lock()
                .unwrap()
                .push((at.load(Ordering::Relaxed), crate::tests::packed_frame_type(bytes)));
            Ok(())
        },
        RouterSideOptions { reliable_enabled: reliable, ..Default::default() },
    );
    let m = Model { router, now, radio, umbilical, radio_offers, umbilical_frames };
    announce(&m, m.radio, "SIDE_BUSY_FC");
    announce(&m, m.umbilical, "SIDE_BUSY_AB");
    m
}

fn announce(m: &Model, side: usize, endpoint: &str) {
    let owner = Router::new(
        RouterConfig::new([EndpointHandler::new_packet_handler(self::endpoint(endpoint), |_| Ok(()))])
            .with_sender(endpoint),
    );
    let out = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let sink = out.clone();
    owner.add_side_packed_with_options(
        "uplink",
        move |bytes: &[u8]| {
            sink.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default(),
    );
    owner.announce_discovery().unwrap();
    owner.process_tx_queue().unwrap();
    for frame in out.lock().unwrap().drain(..) {
        let _ = m.router.rx_packed_from_side(&frame, side);
    }
    m.router.process_rx_queue_with_timeout(0).unwrap();
}

fn queue(m: &Model, ty: DataType, endpoint: &str, value: f32) {
    let packet = Packet::from_f32_slice(
        ty,
        &[value, 1.0],
        &[self::endpoint(endpoint)],
        m.now.load(Ordering::Relaxed),
    )
    .unwrap();
    m.router.tx_queue(packet).unwrap();
}

/// One worker iteration: a budgeted TX pass, then the worker's sleep.
fn pass(m: &Model, sleep_ms: u64) {
    let _ = m.router.process_tx_queue_with_timeout(PASS_BUDGET_MS);
    m.now.fetch_add(sleep_ms, Ordering::Relaxed);
}

fn arrived(m: &Model, ty: DataType) -> Option<u64> {
    m.umbilical_frames.lock().unwrap().iter().find(|(_, t)| *t == Some(ty)).map(|(at, _)| *at)
}

/// Model ms from queueing one umbilical frame behind `backlog` radio frames
/// (after the backlog has settled into refusals) until the umbilical takes
/// it, or None within `limit_ms`.
fn umbilical_latency(refusals_per_ms: u64, mode: ReliableMode, backlog: usize, limit_ms: u64) -> Option<u64> {
    let tag = match mode {
        ReliableMode::None => "PLAIN",
        ReliableMode::Ordered => "ORDERED",
        ReliableMode::Unordered => "UNORDERED",
    };
    let radio_ty = test_type(&format!("SIDE_BUSY_RADIO_{tag}"), "SIDE_BUSY_FC", mode, 10);
    let umbilical_ty = test_type(&format!("SIDE_BUSY_UMBILICAL_{tag}"), "SIDE_BUSY_AB", mode, 10);
    let m = model(refusals_per_ms, mode);
    for index in 0..backlog {
        queue(&m, radio_ty, "SIDE_BUSY_FC", index as f32);
    }
    for _ in 0..50 {
        pass(&m, 1);
    }
    let start = m.now.load(Ordering::Relaxed);
    queue(&m, umbilical_ty, "SIDE_BUSY_AB", 0.0);
    let offers_before = m.radio_offers.lock().unwrap().len();
    let mut passes = 0u32;
    while m.now.load(Ordering::Relaxed) - start < limit_ms {
        pass(&m, 1);
        passes += 1;
        if let Some(at) = arrived(&m, umbilical_ty) {
            return Some(at.saturating_sub(start));
        }
    }
    eprintln!(
        "{mode:?}: no umbilical frame after {passes} passes, {} radio offers, {} queued",
        m.radio_offers.lock().unwrap().len() - offers_before,
        m.router.state.lock().transmit_queue.len()
    );
    None
}

#[test]
fn a_refusing_side_does_not_starve_another_side_on_a_slow_cpu() {
    // Two refusals per model millisecond: a pass reaches about six items.
    for (mode, backlog) in [(ReliableMode::None, 200), (ReliableMode::Unordered, 24), (ReliableMode::Ordered, 24)] {
        let latency = umbilical_latency(2, mode, backlog, 1_000);
        eprintln!("{mode:?} backlog {backlog}: umbilical frame after {latency:?} model ms");
        assert!(
            latency.is_some_and(|ms| ms <= u64::from(PASS_BUDGET_MS) + 1),
            "{mode:?}: an umbilical frame waited behind refused radio frames: {latency:?} ms"
        );
    }
}

#[test]
fn a_side_refusing_one_frame_is_still_offered_the_next_of_its_priority() {
    // Refusal can depend on the frame (its size, its class), not only on the
    // side: a radio refusing a backlog of one type still takes another type
    // of the same priority, in the same pass, when nothing else waits.
    let refused = test_type("SIDE_BUSY_SAME_REFUSED", "SIDE_BUSY_FC", ReliableMode::None, 10);
    let taken = test_type("SIDE_BUSY_SAME_TAKEN", "SIDE_BUSY_FC", ReliableMode::None, 10);
    let m = model_accepting(1_000, ReliableMode::None, Some(taken));
    for index in 0..100 {
        queue(&m, refused, "SIDE_BUSY_FC", index as f32);
    }
    for _ in 0..10 {
        pass(&m, 1);
    }
    m.radio_offers.lock().unwrap().clear();
    queue(&m, taken, "SIDE_BUSY_FC", 0.0);
    pass(&m, 1);
    let offers = m.radio_offers.lock().unwrap().clone();
    assert!(offers.iter().any(|(_, ty)| *ty == Some(taken)), "{offers:?}");
}

#[test]
fn critical_frames_still_go_first_past_a_busy_side() {
    let radio_ty = test_type("SIDE_BUSY_PRIO_RADIO", "SIDE_BUSY_FC", ReliableMode::None, 10);
    let critical_radio = test_type("SIDE_BUSY_PRIO_RADIO_CRITICAL", "SIDE_BUSY_FC", ReliableMode::None, 250);
    let normal_umbilical = test_type("SIDE_BUSY_PRIO_UMBILICAL", "SIDE_BUSY_AB", ReliableMode::None, 10);
    let critical_umbilical = test_type("SIDE_BUSY_PRIO_UMBILICAL_CRITICAL", "SIDE_BUSY_AB", ReliableMode::None, 250);
    let m = model(2, ReliableMode::None);
    for index in 0..100 {
        queue(&m, radio_ty, "SIDE_BUSY_FC", index as f32);
    }
    for _ in 0..60 {
        pass(&m, 1);
    }
    // The radio has refused low-priority frames in every pass so far. A
    // critical frame for it is still offered in the next pass, before any
    // lower-priority frame for it, and the umbilical's frames both go in that
    // pass. (Their order follows the queue's priority burst: after eight
    // higher-priority picks one lower-priority frame takes a turn.)
    m.radio_offers.lock().unwrap().clear();
    queue(&m, normal_umbilical, "SIDE_BUSY_AB", 0.0);
    queue(&m, critical_umbilical, "SIDE_BUSY_AB", 0.0);
    queue(&m, critical_radio, "SIDE_BUSY_FC", 0.0);
    pass(&m, 1);
    let offers: Vec<_> = m
        .radio_offers
        .lock()
        .unwrap()
        .iter()
        .map(|(_, ty)| *ty)
        .filter(|ty| *ty == Some(radio_ty) || *ty == Some(critical_radio))
        .collect();
    assert_eq!(offers.first(), Some(&Some(critical_radio)), "{offers:?}");
    let frames: Vec<_> = m.umbilical_frames.lock().unwrap().iter().map(|(_, ty)| *ty).collect();
    assert!(frames.contains(&Some(critical_umbilical)) && frames.contains(&Some(normal_umbilical)), "{frames:?}");
}

#[test]
fn a_side_refusing_one_priority_is_still_offered_another() {
    // The radio refuses every high-priority frame but has room for a
    // low-priority one: that frame still goes out in the next pass.
    let refused = test_type("SIDE_BUSY_CLASS_REFUSED", "SIDE_BUSY_FC", ReliableMode::None, 200);
    let taken = test_type("SIDE_BUSY_CLASS_TAKEN", "SIDE_BUSY_FC", ReliableMode::None, 10);
    let m = model_accepting(2, ReliableMode::None, Some(taken));
    for index in 0..100 {
        queue(&m, refused, "SIDE_BUSY_FC", index as f32);
    }
    for _ in 0..60 {
        pass(&m, 1);
    }
    m.radio_offers.lock().unwrap().clear();
    queue(&m, taken, "SIDE_BUSY_FC", 0.0);
    pass(&m, 1);
    let offers = m.radio_offers.lock().unwrap().clone();
    assert!(offers.iter().any(|(_, ty)| *ty == Some(taken)), "{offers:?}");
}
