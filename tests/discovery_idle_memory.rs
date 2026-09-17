#![cfg(all(feature = "std", feature = "discovery"))]

use sedsnet::discovery::{DISCOVERY_ROUTE_TTL_MS, TopologyBoardNode, build_discovery_topology};
use sedsnet::relay::Relay;
use sedsnet::router::{Router, RouterConfig};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct CountingAllocator;
thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn measured(mut poll: impl FnMut()) -> usize {
    COUNT.with(|count| count.set(Some(0)));
    for _ in 0..1000 {
        poll();
    }
    COUNT.with(|count| count.replace(None).unwrap())
}

#[test]
fn unchanged_discovery_polling_does_not_allocate_or_lose_routes() {
    let endpoint =
        sedsnet::config::register_endpoint_with_description("SOAK_MEMORY", "soak test", false)
            .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let router_clock = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || router_clock.load(Ordering::Relaxed)),
    );
    let relay_clock = clock.clone();
    let relay = Relay::new(Box::new(move || relay_clock.load(Ordering::Relaxed)));
    let router_side = router.add_side_packet("can", |_pkt| Ok(()));
    let relay_side = relay.add_side_packet("can", |_pkt| Ok(()));
    let boards = (0..7)
        .map(|i| TopologyBoardNode {
            sender_id: format!("BOARD_{i}"),
            reachable_endpoints: vec![endpoint],
            reachable_timesync_sources: vec![format!("BOARD_{i}")],
            connections: vec!["BRIDGE".into()],
        })
        .collect::<Vec<_>>();
    let packet = build_discovery_topology("BRIDGE", 0, &boards).unwrap();
    router.rx_from_side(&packet, router_side).unwrap();
    relay.rx_from_side(relay_side, packet).unwrap();
    // Initial advertisements may allocate. Only idle maintenance is measured.
    for _ in 0..3 {
        router.poll_discovery().unwrap();
        relay.poll_discovery().unwrap();
        router.process_all_queues().unwrap();
        relay.process_all_queues().unwrap();
    }
    assert!(!router.export_topology().routes.is_empty());
    assert!(!relay.export_topology().routes.is_empty());
    let router_allocations = measured(|| {
        router.poll_discovery().unwrap();
    });
    let relay_allocations = measured(|| {
        relay.poll_discovery().unwrap();
    });
    assert_eq!(
        router_allocations, 0,
        "unchanged router discovery allocated"
    );
    assert_eq!(relay_allocations, 0, "unchanged relay discovery allocated");
    assert!(!router.export_topology().routes.is_empty());
    assert!(!relay.export_topology().routes.is_empty());
    clock.store(DISCOVERY_ROUTE_TTL_MS, Ordering::Relaxed);
    assert!(
        !router.export_topology().routes.is_empty(),
        "peer expired at the inclusive TTL boundary"
    );
    assert!(
        !relay.export_topology().routes.is_empty(),
        "peer expired at the inclusive TTL boundary"
    );
    clock.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    router.poll_discovery().unwrap();
    relay.poll_discovery().unwrap();
    assert!(
        router.export_topology().routes.is_empty(),
        "expired peer survived"
    );
    assert!(
        relay.export_topology().routes.is_empty(),
        "expired peer survived"
    );
}
