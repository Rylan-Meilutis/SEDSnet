#![cfg(feature = "std")]
use sedsnet::{
    TelemetryError,
    config::{DataEndpoint, DataType},
    packet::Packet,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
const PAYLOAD_LEN: usize = 3600;
thread_local! { static LARGE: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
#[global_allocator]
static ALLOCATOR: Counter = Counter;
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= PAYLOAD_LEN {
            let _ = LARGE.try_with(|v| {
                if let Some(n) = v.get() {
                    v.set(Some(n + 1));
                }
            });
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe(None);
    }
}
extern "C" fn deny_large(_: usize, largest: usize) -> bool {
    largest < 1024
}
#[test]
fn decoded_payload_is_refused_before_large_allocation_and_can_retry() {
    let mut state = 42u32;
    let random: Vec<u8> = (0..PAYLOAD_LEN)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    // Exercise plain and compressible frames; with compression disabled both
    // are plain. Direct decode also covers completed side reassembly, where
    // the original fragment ingress checks cannot account for the full copy.
    for payload in [random, vec![0; PAYLOAD_LEN]] {
        let packet = Packet::new(
            DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "PEER",
            1,
            Arc::from(payload.as_slice()),
        )
        .unwrap();
        let wire = sedsnet::wire_format::pack_packet(&packet);
        let _reset = Reset;
        sedsnet::memory_admission::set_probe(Some(deny_large));
        LARGE.with(|v| v.set(Some(0)));
        let rejected = sedsnet::wire_format::unpack_packet(&wire);
        let allocations = LARGE.with(|v| v.replace(None).unwrap());
        sedsnet::memory_admission::set_probe(None);
        assert!(matches!(
            rejected,
            Err(TelemetryError::Io("memory pressure"))
        ));
        assert_eq!(allocations, 0, "payload allocated before admission refusal");
        assert_eq!(
            sedsnet::wire_format::unpack_packet(&wire)
                .unwrap()
                .payload(),
            payload
        );
    }
}
