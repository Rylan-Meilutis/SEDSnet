#![cfg(all(feature = "std", not(feature = "compression")))]
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
struct Counter;
thread_local! { static LARGE: Cell<Option<usize>> = const { Cell::new(None) }; }
#[global_allocator]
static ALLOCATOR: Counter = Counter;
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= 3000 {
            let _ = LARGE.try_with(|n| {
                if let Some(v) = n.get() {
                    n.set(Some(v + 1));
                }
            });
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[test]
fn schema_packing_allocates_only_one_frame_sized_buffer() {
    // Incompressible, schema-sized data reproduces the failed embedded allocation.
    let mut state = 0x12345678u32;
    let payload: Arc<[u8]> = (0..3600)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>()
        .into();
    let packet = Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        "GB",
        1_790_705_000_000,
        payload.clone(),
    )
    .unwrap();
    LARGE.with(|n| n.set(Some(0)));
    let packed = sedsnet::wire_format::pack_packet(&packet);
    let allocations = LARGE.with(|n| n.replace(None).unwrap());
    assert_eq!(
        allocations, 1,
        "packing retained duplicate full-frame buffers"
    );
    let decoded = sedsnet::wire_format::unpack_packet(&packed).unwrap();
    assert_eq!(decoded.payload(), payload.as_ref());
}
