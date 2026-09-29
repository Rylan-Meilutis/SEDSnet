#![cfg(all(feature = "std", feature = "discovery"))]

use sedsnet::discovery::{DISCOVERY_ROUTE_TTL_MS, TopologyBoardNode, build_discovery_topology};
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

#[test]
fn repeated_variable_request_does_not_clone_learned_topology() {
    use sedsnet::discovery::build_managed_variable_request;
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let endpoint =
        sedsnet::config::register_endpoint_with_description("REFRESH_MEMORY", "", false).unwrap();
    let ty = sedsnet::config::register_data_type(
        "REFRESH_VALUE",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[endpoint],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let router_clock = clock.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(move || router_clock.load(Ordering::Relaxed)),
    );
    let side = router.add_side_packet("can", |_| Ok(()));
    let boards = (0..16)
        .map(|i| TopologyBoardNode {
            sender_id: format!("REFRESH_BOARD_{i}"),
            reachable_endpoints: vec![endpoint],
            reachable_timesync_sources: vec![format!("CLOCK_{i}")],
            connections: vec!["REFRESH_BRIDGE".into()],
        })
        .collect::<Vec<_>>();
    let topology = build_discovery_topology("REFRESH_BRIDGE", 0, &boards).unwrap();
    router.rx_from_side(&topology, side).unwrap();
    let first = build_managed_variable_request("CLIENT", 1, ty).unwrap();
    router.rx_from_side(&first, side).unwrap();
    router.process_all_queues().unwrap();
    clock.store(2, Ordering::Relaxed);
    let refresh = build_managed_variable_request("CLIENT", 2, ty).unwrap();
    COUNT.with(|count| count.set(Some(0)));
    router.rx_from_side(&refresh, side).unwrap();
    let allocations = COUNT.with(|count| count.replace(None).unwrap());
    eprintln!("refresh allocations: {allocations}");
    assert!(
        allocations < 50,
        "refresh cloned route storage: {allocations} allocations"
    );
    let route = router
        .export_topology()
        .routes
        .into_iter()
        .find(|route| route.side_id == side)
        .unwrap();
    assert!(route.reachable_network_variables.contains(&ty));
    assert!(route.announcers.iter().any(|peer| peer.routers.len() == 16));
    clock.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    router.poll_discovery().unwrap();
    assert!(
        router
            .export_topology()
            .routes
            .iter()
            .any(|route| route.reachable_network_variables.contains(&ty)),
        "refresh did not extend subscriber lease"
    );
}
