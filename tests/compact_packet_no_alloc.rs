#![cfg(all(feature = "std", feature = "compact-packet-store"))]
use sedsnet::packet_store::PacketStore;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
thread_local! {static COUNT:Cell<Option<usize>>=const {Cell::new(None)};}
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[test]
fn store_pin_clone_read_compact_and_release_allocate_nothing() {
    let store = PacketStore::new(4096, 32, 4096).unwrap();
    COUNT.with(|c| c.set(Some(0)));
    for byte in 0..100 {
        let a = store.store(&[byte; 128]).unwrap();
        let b = store.store(&[byte; 128]).unwrap();
        let shared = b.clone();
        drop(a);
        let pin = shared.pin().unwrap();
        store.compact();
        assert_eq!(&*pin, &[byte; 128]);
        drop(pin);
        let mut field = [0; 4];
        shared.read_range(12, &mut field).unwrap();
        assert_eq!(field, [byte; 4]);
        drop(shared);
        drop(b);
    }
    let count = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(count, 0);
    assert_eq!(store.stats().live_bytes, 0);
}

#[cfg(feature = "compact-packet-compression")]
#[test]
fn fixed_codec_and_chunk_scratch_never_allocate_after_startup() {
    use sedsnet::packet_store::{BoundedPacketCodec, PacketCodec};
    let required = PacketCodec::memory_requirements(128).unwrap();
    COUNT.with(|c| c.set(Some(0)));
    assert!(BoundedPacketCodec::new(128, required.total_bytes - 1).is_err());
    let count = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(count, 0, "budget rejection must happen before allocation");
    let mut codec = BoundedPacketCodec::new(128, required.total_bytes).unwrap();
    let reserved = codec.reserved_bytes();
    let store = PacketStore::new(8192, 16, 8192).unwrap();
    // Packet size is much larger than both scratch buffers; reads cross chunks.
    let mut data = [0u8; 4096];
    COUNT.with(|c| c.set(Some(0)));
    for len in [1, 127, 128, 129, 255, 256, 511, 1024, 4096] {
        for (i, x) in data.iter_mut().enumerate() {
            *x = (i / 128) as u8;
        }
        let h = codec.store(&store, &data[..len]).unwrap();
        let mut field = [0; 12];
        let offset = len.saturating_sub(field.len());
        let n = len.min(field.len());
        codec.read_range(&h, offset, &mut field[..n]).unwrap();
        assert_eq!(&field[..n], &data[offset..offset + n]);
        assert_eq!(codec.reserved_bytes(), reserved);
        assert!(h.stored_len() <= len);
        drop(h);
        // Poorly compressible content must also leave the fixed buffers alone.
        let mut state = 0x12345678u32;
        for x in &mut data {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *x = state as u8;
        }
        let h = codec.store(&store, &data[..len]).unwrap();
        codec.read_range(&h, offset, &mut field[..n]).unwrap();
        assert_eq!(&field[..n], &data[offset..offset + n]);
        assert_eq!(codec.reserved_bytes(), reserved);
        assert!(h.stored_len() <= len);
    }
    let count = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(count, 0);
    assert_eq!(store.stats().live_bytes, 0);
}
