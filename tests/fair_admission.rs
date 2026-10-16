#![cfg(feature = "std")]
use sedsnet::packet::Packet;
use sedsnet::relay::Relay;
use sedsnet::router::{EndpointHandler, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Counted;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static BUDGET: AtomicUsize = AtomicUsize::new(usize::MAX);
static REFUSED: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe {
            System.dealloc(p, layout);
        }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, layout, size) };
        if !out.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(size, Ordering::Relaxed);
        }
        out
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;
extern "C" fn probe(additional: usize, _: usize, _: u32) -> bool {
    let allowed = LIVE
        .load(Ordering::Relaxed)
        .saturating_add(additional)
        .saturating_add(4096)
        <= BUDGET.load(Ordering::Relaxed);
    if !allowed {
        REFUSED.fetch_add(1, Ordering::Relaxed);
    }
    allowed
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe_v2(None);
    }
}
fn pressure(wire: &[u8]) -> Reset {
    // Require real reclamation while preserving the entire work estimate and
    // 4 KiB reserve. The system allocator remains unlimited for observation.
    BUDGET.store(
        LIVE.load(Ordering::Relaxed) + wire.len() * 3 + 2048 + 4096 - 1,
        Ordering::Relaxed,
    );
    sedsnet::memory_admission::set_probe_v2(Some(probe));
    Reset
}
#[test]
fn gateway_and_standalone_relay_reclaim_dominant_sender_before_refusing_valve_report() {
    let ep = sedsnet::config::register_endpoint("FAIR_BULK_DEST", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "FAIR_FLOAT_REPORT",
        "",
        MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let make = |sender: &str, tick: u64, value: f32| {
        sedsnet::wire_format::pack_packet(
            &Packet::new(
                ty,
                &[ep],
                sender,
                tick,
                Arc::<[u8]>::from(value.to_le_bytes()),
            )
            .unwrap(),
        )
    };
    let wires: Vec<_> = (0..10).map(|i| make("DAQ", i + 1, 1.0)).collect();
    let rare = make("VALVE", 11, 2.0);
    let incoming = make("VALVE", 12, 3.0);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let router = Router::new(RouterConfig::new([EndpointHandler::new_packet_handler(
        ep,
        move |p| {
            output.lock().unwrap().push(p.data_as_f32()?[0]);
            Ok(())
        },
    )]));
    let side = router.add_side_packed("can", |_| Ok(()));
    for wire in &wires {
        router.rx_packed_queue_from_side(wire, side).unwrap();
    }
    router.rx_packed_queue_from_side(&rare, side).unwrap();
    let before = router.export_runtime_stats().queues.rx_len;
    let heavy_incoming = make("DAQ", 13, 1.0);
    let reset = pressure(&heavy_incoming);
    let refused = router.rx_packed_queue_from_side(&heavy_incoming, side);
    drop(reset);
    assert!(
        refused.is_err(),
        "the dominant sender must not evict a smaller peer"
    );
    assert_eq!(router.export_runtime_stats().queues.rx_len, before);
    let reset = pressure(&incoming);
    router
        .rx_packed_queue_from_side(&incoming, side)
        .expect("low-rate valve report must reclaim queued DAQ bulk");
    drop(reset);
    assert_eq!(
        router.export_runtime_stats().queues.rx_len,
        before,
        "one old bulk item is replaced, not retained indefinitely"
    );
    router.process_all_queues().unwrap();
    let values = seen.lock().unwrap();
    assert_eq!(values.iter().filter(|v| **v == 1.0).count(), 9);
    assert!(
        values.contains(&2.0) && values.contains(&3.0),
        "both existing and fresh valve reports survive"
    );
    drop(values);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let relay = Relay::new(Box::new(|| 0));
    let input = relay.add_side_packed("can", |_| Ok(()));
    let output_side = relay.add_side_packet("pico", move |p| {
        if p.data_type() == ty {
            output.lock().unwrap().push(p.data_as_f32()?[0]);
        }
        Ok(())
    });
    relay.set_route(Some(input), output_side, true).unwrap();
    for wire in &wires {
        relay.rx_packed_from_side(input, wire).unwrap();
    }
    relay.rx_packed_from_side(input, &rare).unwrap();
    let before = relay.export_runtime_stats().queues.rx_len;
    let reset = pressure(&incoming);
    relay
        .rx_packed_from_side(input, &incoming)
        .expect("standalone relay must apply the same fair reclamation");
    drop(reset);
    assert_eq!(relay.export_runtime_stats().queues.rx_len, before);
    relay.process_all_queues().unwrap();
    let values = seen.lock().unwrap();
    assert_eq!(values.iter().filter(|v| **v == 1.0).count(), 9);
    assert!(values.contains(&2.0) && values.contains(&3.0));
    assert!(
        REFUSED.load(Ordering::Relaxed) >= 2,
        "both paths must actually hit memory refusal before recovering"
    );
}
