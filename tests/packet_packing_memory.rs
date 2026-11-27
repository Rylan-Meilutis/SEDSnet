//! Allocation bounds for packing and chunking INCOMPRESSIBLE payloads.
//! Compression is always built in; for these payloads the packer keeps the
//! uncompressed form, so the frame must still be built without extra
//! full-size copies.
#![cfg(feature = "std")]
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
thread_local! { static CHUNK: Cell<Option<usize>> = const { Cell::new(None) }; }
thread_local! { static CHUNK_LIVE: Cell<Option<(usize, usize)>> = const { Cell::new(None) }; }
struct Counter;
thread_local! { static LARGE: Cell<Option<usize>> = const { Cell::new(None) }; }
thread_local! { static LARGE_LIVE: Cell<Option<(usize, usize)>> = const { Cell::new(None) }; }
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
            let _ = LARGE_LIVE.try_with(|n| {
                if let Some((live, peak)) = n.get() {
                    n.set(Some((live + 1, peak.max(live + 1))));
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
        if layout.size() >= 3000 {
            let _ = LARGE_LIVE.try_with(|n| {
                if let Some((live, peak)) = n.get() {
                    n.set(Some((live.saturating_sub(1), peak)));
                }
            });
        }
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
/// Xorshift bytes: zstd cannot shrink them, so packing keeps them raw.
fn incompressible(len: usize, mut state: u32) -> Arc<[u8]> {
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>()
        .into()
}

/// A frame that kept its payload raw is longer than the payload itself.
fn assert_stays_uncompressed(payload: &Arc<[u8]>) {
    let packet = Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        "GB",
        1,
        payload.clone(),
    )
    .unwrap();
    let packed = sedsnet::wire_format::pack_packet(&packet);
    assert!(packed.len() > payload.len(), "fixture payload must be incompressible");
}

#[test]
fn schema_packing_allocates_only_one_frame_sized_buffer() {
    // Incompressible, schema-sized data reproduces the failed embedded allocation.
    let payload = incompressible(3600, 0x12345678);
    assert_stays_uncompressed(&payload);
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
            // Chunks carry no CRC: the reassembled frame is checked.
            assert_eq!(frame[0], 0x61);
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
        {
            let payload = incompressible(3600, 0x5a5a_1234);
            assert_stays_uncompressed(&payload);
            payload
        },
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

/// A compression-eligible user type: the packer tries zstd, finds no gain and
/// keeps the raw payload. Discovery types above skip the attempt entirely.
fn user_binary_type(name: &str) -> (DataType, DataEndpoint) {
    use sedsnet::config::{register_data_type_with_description, register_endpoint_with_description};
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let ep = register_endpoint_with_description(&format!("{name}_SINK"), "", false).unwrap();
    let ty = register_data_type_with_description(
        name,
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    (ty, ep)
}

#[test]
fn incompressible_user_payload_packing_allocates_only_one_frame_sized_buffer() {
    let (ty, ep) = user_binary_type("INCOMPRESSIBLE_PACK");
    let payload = incompressible(3600, 0x7777_1234);
    let packet = Packet::new(ty, &[ep], "GB", 1_790_705_000_000, payload.clone()).unwrap();
    LARGE.with(|n| n.set(Some(0)));
    LARGE_LIVE.with(|n| n.set(Some((0, 0))));
    let packed = sedsnet::wire_format::pack_packet(&packet);
    let allocations = LARGE.with(|n| n.replace(None).unwrap());
    let (live, peak) = LARGE_LIVE.with(|n| n.replace(None).unwrap());
    assert!(packed.len() > payload.len(), "fixture payload must be incompressible");
    // Measured: the compression attempt borrows one payload-sized output
    // buffer and frees it when zstd finds no gain, then the frame is built.
    // Discovery types (above) skip the attempt and allocate only the frame.
    assert_eq!(allocations, 2, "compression attempt scratch plus the frame");
    assert_eq!(peak, 1, "the failed compression scratch outlived the attempt");
    assert_eq!(live, 1, "only the packed frame stays allocated");
    let decoded = sedsnet::wire_format::unpack_packet(&packed).unwrap();
    assert_eq!(decoded.payload(), payload.as_ref());
}

#[test]
fn incompressible_user_payload_chunks_do_not_allocate_body_and_wrapper_copies() {
    use sedsnet::router::{Router, RouterConfig, RouterSideOptions};
    let (ty, ep) = user_binary_type("INCOMPRESSIBLE_CHUNK");
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let output = sent.clone();
    router.add_side_packed_with_options(
        "uart",
        move |frame| {
            assert!(frame.len() <= 1024);
            output.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        },
        RouterSideOptions {
            header_template_enabled: false,
            max_frame_bytes: 1024,
            ..Default::default()
        },
    );
    let payload = incompressible(3600, 0x5151_2468);
    let packet = Packet::new(ty, &[ep], "GB", 1, payload).unwrap();
    LARGE.with(|n| n.set(Some(0)));
    CHUNK.with(|n| n.set(Some(0)));
    CHUNK_LIVE.with(|n| n.set(Some((0, 0))));
    router.tx(packet).unwrap();
    let large = LARGE.with(|n| n.replace(None).unwrap());
    let count = CHUNK.with(|n| n.replace(None).unwrap());
    let (live, peak) = CHUNK_LIVE.with(|n| n.replace(None).unwrap());
    assert!(sent.load(std::sync::atomic::Ordering::Relaxed) >= 4, "frame was not chunked out");
    assert_eq!(live, 0);
    assert_eq!(peak, 1, "all outgoing chunks were retained at once");
    assert_eq!(count, 3, "each full chunk must allocate only its final shared frame");
    assert!(large <= 1, "chunked payload allocated duplicate full frames: {large}");
}
