use sedsnet::config::{
    DataEndpoint, DataType, RuntimeMemoryConfig, register_schema_json_bytes_with_budget,
    remove_data_type_by_name, remove_endpoint_by_name,
};
use sedsnet::packet::Packet;
use sedsnet::relay::{Relay, RelayConfig};
use sedsnet::router::{Router, RouterConfig};
use sedsnet::wire_format;

use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::{align_of, size_of};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const HEADER_WORDS: usize = 4;
const HEADER_RAW: usize = 1;
const HEADER_SIZE: usize = 2;
const HEADER_TOTAL: usize = 3;
const HEADER_ALIGN: usize = 4;

struct TrackingAllocator;

static LIVE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

#[inline]
fn align_up(address: usize, alignment: usize) -> usize {
    (address + (alignment - 1)) & !(alignment - 1)
}

fn update_peak(live: usize) {
    let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_BYTES.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let requested = layout.size().max(1);
        let alignment = layout.align().max(align_of::<usize>());
        let header_bytes = HEADER_WORDS * size_of::<usize>();
        let Some(total) = requested
            .checked_add(alignment)
            .and_then(|size| size.checked_add(header_bytes))
        else {
            return null_mut();
        };
        let Ok(raw_layout) = Layout::from_size_align(total, alignment) else {
            return null_mut();
        };
        let raw = unsafe { System.alloc(raw_layout) };
        if raw.is_null() {
            return null_mut();
        }

        let aligned = align_up(raw as usize + header_bytes, alignment) as *mut u8;
        let header = aligned as *mut usize;
        unsafe {
            *header.sub(HEADER_RAW) = raw as usize;
            *header.sub(HEADER_SIZE) = requested;
            *header.sub(HEADER_TOTAL) = total;
            *header.sub(HEADER_ALIGN) = alignment;
        }

        LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        let live = LIVE_BYTES.fetch_add(requested, Ordering::Relaxed) + requested;
        update_peak(live);
        aligned
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let header = ptr as *mut usize;
        let raw = unsafe { *header.sub(HEADER_RAW) as *mut u8 };
        let requested = unsafe { *header.sub(HEADER_SIZE) };
        let total = unsafe { *header.sub(HEADER_TOTAL) };
        let alignment = unsafe { *header.sub(HEADER_ALIGN) };

        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(requested, Ordering::Relaxed);
        let raw_layout = Layout::from_size_align(total, alignment).expect("stored layout");
        unsafe { System.dealloc(raw, raw_layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size.max(1), old_layout.align()) else {
            return null_mut();
        };
        let replacement = unsafe { self.alloc(new_layout) };
        if replacement.is_null() {
            return null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, replacement, old_layout.size().min(new_size));
            self.dealloc(ptr, old_layout);
        }
        replacement
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeapSnapshot {
    allocations: usize,
    bytes: usize,
}

fn heap_snapshot() -> HeapSnapshot {
    HeapSnapshot {
        allocations: LIVE_ALLOCATIONS.load(Ordering::Relaxed),
        bytes: LIVE_BYTES.load(Ordering::Relaxed),
    }
}

const LIFECYCLE_SCHEMA: &[u8] = br#"{
    "endpoints": [{
        "rust": "MemoryLifecycleEndpoint",
        "name": "MEMORY_LIFECYCLE_ENDPOINT",
        "description": "temporary allocator lifecycle endpoint"
    }],
    "types": [{
        "rust": "MemoryLifecycleType",
        "name": "MEMORY_LIFECYCLE_TYPE",
        "description": "temporary allocator lifecycle type",
        "class": "Data",
        "element": {"kind": "Dynamic", "data_type": "Binary"},
        "endpoints": ["MemoryLifecycleEndpoint"]
    }]
}"#;

const INVALID_LIFECYCLE_SCHEMA: &[u8] = br#"{
    "endpoints": [{
        "rust": "MemoryFailedEndpoint",
        "name": "MEMORY_FAILED_ENDPOINT",
        "description": "must be reclaimed during rollback"
    }],
    "types": [{
        "rust": "MemoryFailedType",
        "name": "MEMORY_FAILED_TYPE",
        "class": "InvalidClass",
        "element": {"kind": "Dynamic", "data_type": "Binary"},
        "endpoints": ["MemoryFailedEndpoint"]
    }]
}"#;

fn register_lifecycle_schema() {
    register_schema_json_bytes_with_budget(LIFECYCLE_SCHEMA, 256 * 1024).unwrap();
}

fn remove_lifecycle_schema() {
    assert!(remove_data_type_by_name("MEMORY_LIFECYCLE_TYPE").unwrap());
    assert!(remove_endpoint_by_name("MEMORY_LIFECYCLE_ENDPOINT").unwrap());
}

fn exercise_failed_schema_rollbacks() {
    for _ in 0..16 {
        assert!(
            register_schema_json_bytes_with_budget(INVALID_LIFECYCLE_SCHEMA, 256 * 1024).is_err()
        );
        assert!(
            register_schema_json_bytes_with_budget(LIFECYCLE_SCHEMA, 1).is_err(),
            "a schema larger than the retained-memory budget must be rejected"
        );
    }
}

fn exercise_router_and_relay_lifecycle() {
    let memory = RuntimeMemoryConfig::new(16 * 1024, 8, 256, 1.5).unwrap();
    let data_type = DataType::TelemetryError;
    let endpoint = DataEndpoint::TelemetryError;
    let payload = Arc::<[u8]>::from(&b"bounded-memory-lifecycle"[..]);

    let router = Router::new(RouterConfig::default().with_memory_config(memory).unwrap());
    let router_side = router.add_side_packed("reused-link", |_bytes| Ok(()));
    for timestamp in 0..48 {
        let packet = Packet::new(
            data_type,
            &[endpoint],
            "MEMORY_TEST",
            timestamp,
            payload.clone(),
        )
        .unwrap();
        router.rx_queue_from_side(packet, router_side).unwrap();
    }
    router.clear_queues();
    router.remove_side(router_side).unwrap();
    for _ in 0..64 {
        let side = router.add_side_packed("reused-link", |_bytes| Ok(()));
        router.remove_side(side).unwrap();
    }
    drop(router);

    let relay = Relay::new_with_config(
        RelayConfig::default().with_memory_config(memory).unwrap(),
        Box::new(|| 0),
    );
    let relay_side = relay.add_side_packed("reused-link", |_bytes| Ok(()));
    for timestamp in 0..48 {
        let packet = Packet::new(
            data_type,
            &[endpoint],
            "MEMORY_TEST",
            timestamp,
            payload.clone(),
        )
        .unwrap();
        relay.rx_from_side(relay_side, packet).unwrap();
    }
    relay.clear_queues();
    relay.remove_side(relay_side).unwrap();
    for _ in 0..64 {
        let side = relay.add_side_packed("reused-link", |_bytes| Ok(()));
        relay.remove_side(side).unwrap();
    }
    drop(relay);

    for timestamp in 0..64 {
        let packet = Packet::new(
            data_type,
            &[endpoint],
            "MEMORY_TEST",
            timestamp,
            payload.clone(),
        )
        .unwrap();
        let packed = wire_format::pack_packet(&packet);
        let unpacked = wire_format::unpack_packet(&packed).unwrap();
        assert_eq!(unpacked.payload(), payload.as_ref());
    }
}

fn exercise_full_lifecycle() {
    exercise_failed_schema_rollbacks();
    register_lifecycle_schema();
    exercise_router_and_relay_lifecycle();
    remove_lifecycle_schema();
}

#[test]
fn repeated_runtime_churn_returns_all_temporary_allocations() {
    // Initialize process-wide schema and any one-time library state before the
    // baseline. Warm-up also lets reusable global registry vectors reach their
    // steady-state capacity; that capacity belongs to the registry, not a leak.
    for _ in 0..3 {
        exercise_full_lifecycle();
    }

    let baseline = heap_snapshot();
    PEAK_BYTES.store(baseline.bytes, Ordering::Relaxed);

    for cycle in 0..64 {
        exercise_full_lifecycle();
        assert_eq!(
            heap_snapshot(),
            baseline,
            "temporary allocations remained live after lifecycle cycle {cycle}"
        );
    }

    let peak = PEAK_BYTES.load(Ordering::Relaxed);
    assert!(
        peak.saturating_sub(baseline.bytes) <= 256 * 1024,
        "lifecycle transient heap use exceeded the embedded-oriented bound: baseline={} peak={peak}",
        baseline.bytes,
    );
}
