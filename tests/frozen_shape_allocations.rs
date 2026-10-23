use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
fn record() {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            ALLOCATIONS.with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(p, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[test]
fn unknown_type_with_frozen_wire_shape_validates_without_fallback_allocations() {
    // A self-describing v4 frame for a type absent from this node's registry.
    // Its frozen UInt8[8] shape must work while runtime schema is incomplete.
    const WIRE: &[u8] = &[
        140, 1, 129, 128, 252, 255, 7, 8, 1, 1, 133, 184, 224, 176, 2, 202, 1, 12, 3, 66, 8, 1, 34,
        17, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 249, 109, 220, 29,
    ];
    let packet = sedsnet::wire_format::unpack_packet(WIRE).unwrap();
    assert_eq!(packet.payload(), &[0, 1, 2, 3, 4, 5, 6, 7]);
    ALLOCATIONS.with(|n| n.set(0));
    TRACK.with(|track| track.set(true));
    for _ in 0..64 {
        std::hint::black_box(&packet).validate().unwrap();
    }
    TRACK.with(|track| track.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    assert_eq!(
        allocations, 0,
        "a frozen shape must not allocate UNKNOWN_TYPE metadata on each validation"
    );
}
