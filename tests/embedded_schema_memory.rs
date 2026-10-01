#![cfg(all(not(feature = "std"), feature = "discovery"))]
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
struct Counter;
thread_local! { static LARGE: Cell<Option<(usize,usize)>> = const { Cell::new(None) }; }
#[global_allocator]
static ALLOCATOR: Counter = Counter;
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = LARGE.try_with(|v| {
            if let Some((threshold, count)) = v.get() {
                if layout.size() >= threshold {
                    v.set(Some((threshold, count + 1)));
                }
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}
#[test]
fn embedded_schema_encodes_directly_into_one_large_allocation() {
    use sedsnet::discovery::{build_discovery_schema, decode_discovery_schema};
    let first = build_discovery_schema("GB", 1).unwrap();
    let payload_len = first.payload().len();
    assert!(payload_len > 256);
    LARGE.with(|v| v.set(Some((payload_len, 0))));
    let packet = build_discovery_schema("GB", 2).unwrap();
    let large = LARGE.with(|v| v.replace(None).unwrap().1);
    assert_eq!(
        large, 1,
        "schema retained duplicate full-size payload buffers"
    );
    assert_eq!(packet.payload(), first.payload());
    let decoded = decode_discovery_schema(&packet).unwrap();
    let expected = sedsnet::config::export_schema();
    assert_eq!(decoded.endpoints.len(), expected.endpoints.len());
    assert_eq!(decoded.types.len(), expected.types.len());
    // Deny headroom before any schema-sized allocation, then recover without
    // damaging the retained registry or leaving partial output behind.
    extern "C" fn deny(_: usize, _: usize) -> bool {
        false
    }
    sedsnet::memory_admission::set_probe(Some(deny));
    let rejected = build_discovery_schema("GB", 3);
    sedsnet::memory_admission::set_probe(None);
    assert!(matches!(
        rejected,
        Err(sedsnet::TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(
        build_discovery_schema("GB", 4).unwrap().payload(),
        first.payload()
    );
    for ty in expected.types {
        let actual = decoded
            .types
            .iter()
            .find(|entry| entry.id == ty.id)
            .unwrap();
        assert_eq!(actual.name, ty.name);
        assert_eq!(actual.element, ty.element);
        assert_eq!(actual.endpoints, ty.endpoints);
        assert_eq!(actual.reliable, ty.reliable);
    }
}
