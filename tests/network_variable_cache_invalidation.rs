#![cfg(feature = "std")]

use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, NetworkVariablePermissions, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Meter;
thread_local! { static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) }; }
#[global_allocator]
static ALLOCATOR: Meter = Meter;
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| {
            if let Some(count) = n.get() {
                n.set(Some(count + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
fn no_allocations<T>(f: impl FnOnce() -> T) -> T {
    ALLOCATIONS.with(|n| n.set(Some(0)));
    let result = f();
    let count = ALLOCATIONS.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0, "cache retirement must not allocate");
    result
}
fn schema(name: &str) -> (DataType, DataEndpoint) {
    let ep = sedsnet::config::register_endpoint(name, false).unwrap();
    let ty = sedsnet::config::register_data_type(
        name,
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    (ty, ep)
}
fn packet(ty: DataType, ep: DataEndpoint, timestamp: u64, value: u8) -> Packet {
    Packet::new(ty, &[ep], "CACHE_WRITER", timestamp, Arc::from([value])).unwrap()
}

#[test]
fn selective_retirement_keeps_other_values_permissions_and_callback() {
    let (a, ep_a) = schema("CACHE_ONLY_SELECTIVE_A");
    let (b, ep_b) = schema("CACHE_ONLY_SELECTIVE_B");
    let node = Router::new(RouterConfig::new([
        EndpointHandler::new_packet_handler(ep_a, |_| Ok(())),
        EndpointHandler::new_packet_handler(ep_b, |_| Ok(())),
    ]));
    for ty in [a, b] {
        node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    node.on_network_variable_update(a, move |_| {
        observed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();
    let first = packet(a, ep_a, 11, 1);
    let other = packet(b, ep_b, 12, 2);
    node.seed_managed_variable(first.clone()).unwrap();
    node.seed_managed_variable(other.clone()).unwrap();
    assert!(no_allocations(|| node.invalidate_network_variable_cache(a)));
    assert!(node.cached_managed_variable(a).is_none());
    assert_eq!(node.cached_managed_variable(b), Some(other));
    assert!(!no_allocations(|| node.invalidate_network_variable_cache(a)));
    assert!(matches!(
        node.set_network_variable(first.clone()),
        Err(TelemetryError::PermissionDenied)
    ));
    node.rx(&first).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(node.cached_managed_variable(a), Some(first));
}

#[test]
fn clear_all_retires_every_observation_but_keeps_both_registrations() {
    let (a, ep_a) = schema("CACHE_ONLY_CLEAR_A");
    let (b, ep_b) = schema("CACHE_ONLY_CLEAR_B");
    let node = Router::new(RouterConfig::new([
        EndpointHandler::new_packet_handler(ep_a, |_| Ok(())),
        EndpointHandler::new_packet_handler(ep_b, |_| Ok(())),
    ]));
    let calls = Arc::new(AtomicUsize::new(0));
    for (ty, ep) in [(a, ep_a), (b, ep_b)] {
        node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        let observed = calls.clone();
        node.on_network_variable_update(ty, move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
        node.seed_managed_variable(packet(ty, ep, 10, 3)).unwrap();
    }
    assert_eq!(no_allocations(|| node.clear_network_variable_caches()), 2);
    assert_eq!(no_allocations(|| node.clear_network_variable_caches()), 0);
    assert!(node.cached_managed_variable(a).is_none());
    assert!(node.cached_managed_variable(b).is_none());
    for (ty, ep) in [(a, ep_a), (b, ep_b)] {
        let update = packet(ty, ep, 20, 4);
        assert!(matches!(
            node.set_network_variable(update.clone()),
            Err(TelemetryError::PermissionDenied)
        ));
        node.rx(&update).unwrap();
        assert_eq!(node.cached_managed_variable(ty), Some(update));
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn rejected_packed_value_can_reach_the_same_callback_again_without_rebinding() {
    let (ty, ep) = schema("CACHE_ONLY_PACKED_RETRY");
    let node = Arc::new(Router::new(RouterConfig::new([
        EndpointHandler::new_packet_handler(ep, |_| Ok(())),
    ])));
    node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let weak = Arc::downgrade(&node);
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    node.on_network_variable_update(ty, move |_| {
        if observed.fetch_add(1, Ordering::Relaxed) == 0 {
            assert!(
                weak.upgrade()
                    .unwrap()
                    .invalidate_network_variable_cache(ty)
            );
            return Err(TelemetryError::HandlerError("injected owner refusal"));
        }
        Ok(())
    })
    .unwrap();
    let side = node.add_side_packed("source", |_| Ok(()));
    let value = packet(ty, ep, 40, 5);
    let wire = sedsnet::wire_format::pack_packet(&value);
    assert!(node.rx_packed_from_side(wire.as_ref(), side).is_err());
    assert!(node.cached_managed_variable(ty).is_none());
    node.rx_packed_from_side(wire.as_ref(), side).unwrap();
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    assert_eq!(node.cached_managed_variable(ty), Some(value));
}

#[cfg(feature = "discovery")]
#[test]
fn actual_discovery_advertisements_keep_invalidated_variables_registered() {
    let (a, ep_a) = schema("CACHE_ONLY_ADVERTISEMENT_A");
    let (b, ep_b) = schema("CACHE_ONLY_ADVERTISEMENT_B");
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("CACHE_ADVERTISER"),
        Box::new(|| 1000),
    );
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = captured.clone();
    node.add_side_packet("peer", move |packet| {
        output.lock().unwrap().push(packet.clone());
        Ok(())
    });
    for (ty, ep) in [(a, ep_a), (b, ep_b)] {
        node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        node.seed_managed_variable(packet(ty, ep, 10, 1)).unwrap();
    }
    let advertise = || {
        captured.lock().unwrap().clear();
        node.announce_discovery().unwrap();
        node.process_all_queues().unwrap();
        let observations: Vec<_> = captured
            .lock()
            .unwrap()
            .iter()
            .filter_map(|packet| sedsnet::discovery::decode_discovery_address(packet).ok())
            .collect();
        assert!(
            !observations.is_empty(),
            "actual router must emit an address advertisement"
        );
        for observation in observations {
            assert!(observation.reachable_network_variables.contains(&a));
            assert!(observation.reachable_network_variables.contains(&b));
        }
    };
    advertise();
    assert!(node.invalidate_network_variable_cache(a));
    advertise();
    assert_eq!(node.clear_network_variable_caches(), 1);
    advertise();
}
