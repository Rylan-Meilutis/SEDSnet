#![cfg(all(feature = "std", not(feature = "compression")))]
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
thread_local! { static CHUNK: Cell<Option<usize>> = const { Cell::new(None) }; }
thread_local! { static CHUNK_LIVE: Cell<Option<(usize, usize)>> = const { Cell::new(None) }; }
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
        if (1000..=1050).contains(&layout.size()) {
            let _ = CHUNK_LIVE.try_with(|n| {
                if let Some((live, peak)) = n.get() {
                    n.set(Some((live + 1, peak.max(live + 1))));
                }
            });
            let _ = CHUNK.try_with(|n| {
                if let Some(v) = n.get() {
                    n.set(Some(v + 1));
                }
            });
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if (1000..=1050).contains(&layout.size()) {
            let _ = CHUNK_LIVE.try_with(|n| {
                if let Some((live, peak)) = n.get() {
                    n.set(Some((live - 1, peak)));
                }
            });
        }
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

#[test]
fn schema_chunks_do_not_allocate_body_and_wrapper_copies() {
    use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    router.add_side_packed_with_options(
        "uart",
        |frame| {
            assert!(frame.len() <= 1024);
            assert_eq!(&frame[..4], b"SDT\x03");
            let n = frame.len() - 4;
            assert_eq!(
                crc32fast::hash(&frame[..n]),
                u32::from_le_bytes(frame[n..].try_into().unwrap())
            );
            Ok(())
        },
        RouterSideOptions {
            header_template_enabled: false,
            max_frame_bytes: 1024,
            ..Default::default()
        },
    );
    let packet = Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        "GB",
        1,
        Arc::from(vec![0x5au8; 3600]),
    )
    .unwrap();
    LARGE.with(|n| n.set(Some(0)));
    CHUNK.with(|n| n.set(Some(0)));
    CHUNK_LIVE.with(|n| n.set(Some((0, 0))));
    router.tx(packet).unwrap();
    let large = LARGE.with(|n| n.replace(None).unwrap());
    assert_eq!(large, 0, "chunked schema allocated a duplicate full frame");
    let count = CHUNK.with(|n| n.replace(None).unwrap());
    let (live, peak) = CHUNK_LIVE.with(|n| n.replace(None).unwrap());
    assert_eq!(live, 0);
    assert_eq!(peak, 1, "all outgoing chunks were retained at once");
    assert_eq!(
        count, 3,
        "each full chunk must allocate only its final shared frame"
    );
}
