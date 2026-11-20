//! Queued reliable packets whose destination has no route must not be
//! re-dispatched on every queue call while the route stays absent. They park
//! until routing changes, then go out at once and in priority order.

use crate::config::{
    DataEndpoint, DataType, register_data_type_with_description, runtime_reliable_max_retries,
    runtime_reliable_retransmit_ms,
};
use crate::packet::Packet;
use crate::router::{
    EndpointHandler, Router, RouterConfig, RouterSideOptions, test_dispatch_counter,
};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PARKED: usize = 16;
const SIDE_A: usize = 0;
const SIDE_B: usize = 1;

fn test_type(name: &str, endpoint: &str, mode: ReliableMode, priority: u8) -> DataType {
    crate::tests::ensure_common_test_schema();
    DataType::try_named(name).unwrap_or_else(|| {
        register_data_type_with_description(
            name,
            "data addressed to a remote endpoint",
            MessageElement::Static(2, MessageDataType::Float32, MessageClass::Data),
            &[DataEndpoint::named(endpoint)],
            mode,
            priority,
        )
        .unwrap()
    })
}

type Frames = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

struct Harness {
    router: Router,
    now: Arc<AtomicU64>,
    frames: Frames,
}

/// A node with two links and no discovered routes: with more than one link,
/// nothing addressed to a remote endpoint is routable.
fn harness() -> Harness {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("PARK_NODE"),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    for index in [SIDE_A, SIDE_B] {
        let sink = frames.clone();
        let id = router.add_side_packed_with_options(
            ["side_a", "side_b"][index],
            move |bytes: &[u8]| {
                sink.lock().unwrap().push((index, bytes.to_vec()));
                Ok(())
            },
            RouterSideOptions::default(),
        );
        assert_eq!(id, index);
    }
    Harness { router, now, frames }
}

fn queue(h: &Harness, ty: DataType, endpoint: &str, count: usize, base: f32) {
    for index in 0..count {
        let packet = Packet::from_f32_slice(
            ty,
            &[base + index as f32, 1.0],
            &[DataEndpoint::named(endpoint)],
            h.now.load(Ordering::Relaxed),
        )
        .unwrap();
        h.router.tx_queue(packet).unwrap();
    }
}

/// Drive `drain_queues_with_timeout(1)` once per simulated millisecond and
/// return how many queued items were handed to dispatch.
fn idle_for(h: &Harness, ms: u64) -> u64 {
    test_dispatch_counter::take();
    for _ in 0..ms {
        h.now.fetch_add(1, Ordering::Relaxed);
        let _ = h.router.drain_queues_with_timeout(1);
    }
    test_dispatch_counter::take()
}

fn frames_of(h: &Harness, ty: DataType) -> Vec<(usize, Vec<u8>)> {
    h.frames
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, bytes)| crate::tests::packed_frame_type(bytes) == Some(ty))
        .cloned()
        .collect()
}

fn queued_of(h: &Harness, ty: DataType) -> usize {
    h.router
        .state
        .lock()
        .transmit_queue
        .iter()
        .filter(|item| item.accepted_type == ty.as_u32())
        .count()
}

/// A second router owning `endpoint`, linked to `side` of the harness. Its
/// discovery announcement gives the harness a route to that endpoint.
fn announce_owner(h: &Harness, side: usize, endpoint: &str) -> Arc<AtomicUsize> {
    let delivered = Arc::new(AtomicUsize::new(0));
    let hits = delivered.clone();
    let clock = h.now.clone();
    let owner = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            DataEndpoint::named(endpoint),
            move |_| {
                hits.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )])
        .with_sender("ENDPOINT_OWNER"),
        Box::new(move || clock.load(Ordering::Relaxed)),
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
        let _ = h.router.rx_packed_from_side(&frame, side);
    }
    delivered
}

fn has_route(h: &Harness) -> bool {
    !h.router.state.lock().discovery_routes.is_empty()
}

#[test]
fn unroutable_reliable_packets_cost_near_zero_dispatch_while_parked() {
    let ty = test_type("UNROUTABLE_PARK_IDLE", "RADIO", ReliableMode::Unordered, 10);
    let h = harness();
    queue(&h, ty, "RADIO", PARKED, 0.0);
    // Stay inside the delivery lifetime so expiry does not empty the queue.
    let lifetime = runtime_reliable_retransmit_ms()
        .saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
    let window = lifetime.saturating_sub(10).min(4_000);
    let dispatches = idle_for(&h, window);
    // Previously each parked packet was re-dispatched every millisecond:
    // PARKED * window dispatches. Now each is re-checked on a doubling
    // schedule capped at UNROUTABLE_RECHECK_MAX_MS.
    let per_packet_bound = 12 + window / crate::router::UNROUTABLE_RECHECK_MAX_MS;
    eprintln!(
        "{PARKED} parked unroutable packets: {dispatches} dispatches in {window} ms \
         (previously {})",
        PARKED as u64 * window
    );
    assert!(
        dispatches <= PARKED as u64 * per_packet_bound,
        "{dispatches} dispatches for {PARKED} parked packets over {window} ms"
    );
    assert_eq!(queued_of(&h, ty), PARKED, "parking must not drop packets");
    assert!(frames_of(&h, ty).is_empty());
}

#[test]
fn parked_unroutable_packets_go_out_as_soon_as_a_route_appears() {
    let ty = test_type("UNROUTABLE_PARK_WAKE", "RADIO", ReliableMode::Unordered, 10);
    let h = harness();
    queue(&h, ty, "RADIO", PARKED, 0.0);
    // Long enough for the fallback re-check to reach its cap.
    idle_for(&h, 1_500);
    assert!(frames_of(&h, ty).is_empty());
    h.now.fetch_add(3, Ordering::Relaxed); // Mid-interval, not on a re-check.
    let delivered = announce_owner(&h, SIDE_B, "RADIO");
    assert!(has_route(&h), "the owner's announcement must create a route");
    test_dispatch_counter::take();
    // Same millisecond: no time passes before the route is used.
    h.router.drain_queues_with_timeout(1).unwrap();
    let sent = frames_of(&h, ty);
    assert_eq!(sent.len(), PARKED, "every parked packet leaves at once");
    assert!(sent.iter().all(|(side, _)| *side == SIDE_B));
    assert_eq!(queued_of(&h, ty), 0);
    assert_eq!(delivered.load(Ordering::Relaxed), 0, "frames were captured, not delivered");
}

#[test]
fn parked_unroutable_packets_still_expire_on_time() {
    let ty = test_type("UNROUTABLE_PARK_EXPIRY", "RADIO", ReliableMode::Unordered, 10);
    let h = harness();
    queue(&h, ty, "RADIO", PARKED, 0.0);
    let lifetime = runtime_reliable_retransmit_ms()
        .saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
    // First dispatch parks them and starts the lifetime.
    idle_for(&h, 1);
    idle_for(&h, lifetime.saturating_sub(2));
    assert_eq!(queued_of(&h, ty), PARKED, "not expired before the lifetime");
    // Each expiry is reported as an error from the queue call that finds it,
    // which ends that call, so one packet expires per call, as before parking.
    idle_for(&h, 2);
    assert!(queued_of(&h, ty) < PARKED, "expiry starts at the lifetime, not a re-check later");
    idle_for(&h, PARKED as u64);
    assert_eq!(queued_of(&h, ty), 0);
    assert!(frames_of(&h, ty).is_empty());
}

#[test]
fn routable_traffic_flows_past_parked_unroutable_packets() {
    let parked = test_type("UNROUTABLE_PARK_MIXED", "SD_CARD", ReliableMode::Unordered, 10);
    let routable = test_type("UNROUTABLE_PARK_ROUTABLE", "RADIO", ReliableMode::None, 10);
    let h = harness();
    announce_owner(&h, SIDE_B, "RADIO");
    assert!(has_route(&h));
    queue(&h, parked, "SD_CARD", PARKED, 0.0);
    idle_for(&h, 50);
    h.frames.lock().unwrap().clear();
    const FLOW: u64 = 1_000;
    let mut dispatched = 0;
    for index in 0..FLOW {
        h.now.fetch_add(1, Ordering::Relaxed);
        queue(&h, routable, "RADIO", 1, index as f32);
        test_dispatch_counter::take();
        h.router.drain_queues_with_timeout(1).unwrap();
        dispatched += test_dispatch_counter::take();
        assert_eq!(
            frames_of(&h, routable).len() as u64,
            index + 1,
            "each routable packet leaves in the call that follows it"
        );
    }
    eprintln!("{FLOW} routable packets beside {PARKED} parked: {dispatched} dispatches");
    // Parked packets add only their bounded re-checks.
    assert!(dispatched <= FLOW + PARKED as u64 * 12, "{dispatched}");
    assert_eq!(queued_of(&h, parked), PARKED);
    assert!(frames_of(&h, parked).is_empty());
}

#[test]
fn parked_packets_keep_priority_order_once_routable() {
    let low = test_type("UNROUTABLE_PARK_LOW", "RADIO", ReliableMode::Unordered, 10);
    let high = test_type("UNROUTABLE_PARK_HIGH", "RADIO", ReliableMode::Unordered, 120);
    let h = harness();
    queue(&h, low, "RADIO", 4, 0.0);
    queue(&h, high, "RADIO", 4, 100.0);
    idle_for(&h, 700);
    announce_owner(&h, SIDE_B, "RADIO");
    h.router.drain_queues_with_timeout(1).unwrap();
    let order: Vec<_> = h
        .frames
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, bytes)| crate::tests::packed_frame_type(bytes))
        .filter(|ty| *ty == low || *ty == high)
        .collect();
    assert_eq!(order.len(), 8);
    // While parked, re-checking a lower-band packet with higher ones queued
    // owes that band one bounded fairness turn (unchanged queue policy). At
    // most that one turn precedes the higher band.
    let first_high = order.iter().position(|ty| *ty == high).unwrap();
    assert!(first_high <= 1, "{order:?}");
    assert!(order[first_high..first_high + 4].iter().all(|ty| *ty == high), "{order:?}");
    assert!(order[first_high + 4..].iter().all(|ty| *ty == low), "{order:?}");
}

/// The cached memory charge of discovered routes must always equal a fresh
/// recomputation: after learning, refreshing, liveness updates and expiry.
#[test]
fn cached_discovery_route_charge_tracks_every_change() {
    let h = harness();
    let check = |h: &Harness| {
        let st = h.router.state.lock();
        let fresh = st
            .discovery_routes
            .iter()
            .map(|(side, route)| crate::router::RouterInner::discovery_route_byte_cost(*side, route))
            .fold(0usize, usize::saturating_add);
        assert_eq!(st.discovery_routes.byte_cost(), fresh);
        st.discovery_routes.len()
    };
    assert_eq!(check(&h), 0);
    announce_owner(&h, SIDE_B, "RADIO");
    assert_eq!(check(&h), 1);
    announce_owner(&h, SIDE_A, "SD_CARD");
    assert_eq!(check(&h), 2);
    // Ordinary traffic from a known peer refreshes liveness only.
    idle_for(&h, 10);
    assert_eq!(check(&h), 2);
    // Expiry prunes both routes.
    h.now.fetch_add(crate::discovery::DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    let _ = h.router.periodic(0);
    assert_eq!(check(&h), 0);
}
