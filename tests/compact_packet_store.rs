#![cfg(feature = "compact-packet-store")]
use sedsnet::packet_store::{PacketStore, set_default_store};
#[test]
fn compaction_preserves_pinned_and_shared_handles() {
    let store = PacketStore::new(100, 10, usize::MAX).unwrap();
    let a = store.store(&[1; 20]).unwrap();
    let b = store.store(&[2; 20]).unwrap();
    let c = store.store(&[3; 20]).unwrap();
    let d = store.store(&[4; 20]).unwrap();
    let shared = c.clone();
    let pin = b.pin().unwrap();
    let address = pin.as_ptr();
    drop(a);
    drop(d);
    store.compact();
    assert_eq!(pin.as_ptr(), address);
    assert_eq!(&*pin, &[2; 20]);
    drop(pin);
    store.compact();
    assert_eq!(&*shared.pin().unwrap(), &[3; 20]);
    let e = store.store(&[5; 50]).unwrap();
    assert_eq!(&*e.pin().unwrap(), &[5; 50]);
    assert!(store.stats().moves > 0);
    drop(c);
    drop(shared);
    drop(b);
    drop(e);
    assert_eq!(store.stats().live_bytes, 0);
}
#[test]
fn large_buffers_are_barriers_and_exhaustion_does_not_corrupt() {
    let store = PacketStore::new(100, 8, 20).unwrap();
    let a = store.store(&[1; 20]).unwrap();
    let b = store.store(&[2; 40]).unwrap();
    let c = store.store(&[3; 20]).unwrap();
    let address = b.pin().unwrap().as_ptr();
    drop(a);
    store.compact();
    assert_eq!(b.pin().unwrap().as_ptr(), address);
    assert!(store.store(&[9; 30]).is_err());
    assert_eq!(&*c.pin().unwrap(), &[3; 20]);
    assert_eq!(store.stats().rejected, 1);
    drop(b);
    let d = store.store(&[4; 70]).unwrap();
    assert_eq!(d.len(), 70);
}
#[test]
fn handle_table_and_ranges_are_bounded() {
    let store = PacketStore::new(64, 1, 64).unwrap();
    let h = store.store(&[1, 2, 3, 4]).unwrap();
    assert!(store.store(&[5]).is_err());
    let mut out = [0; 2];
    h.read_range(1, &mut out).unwrap();
    assert_eq!(out, [2, 3]);
    assert!(h.read_range(usize::MAX, &mut out).is_err());
    let empty = store.store(&[]).unwrap();
    assert!(empty.pin().unwrap().is_empty());
    drop(h);
    assert!(store.store(&[5]).is_ok());
}
#[test]
fn pins_survive_concurrent_compaction_and_default_replacement() {
    let store = PacketStore::new(256, 16, 256).unwrap();
    let h = store.store(&[7; 40]).unwrap();
    let pin = h.pin().unwrap();
    let other = store.clone();
    let thread = std::thread::spawn(move || {
        for _ in 0..1000 {
            let h = other.store(&[3; 20]).unwrap();
            other.compact();
            drop(h);
        }
    });
    for _ in 0..1000 {
        assert_eq!(&*pin, &[7; 40]);
    }
    thread.join().unwrap();
    assert_eq!(&*pin, &[7; 40]);
}
#[cfg(feature = "compact-packet-compression")]
#[test]
fn compression_saves_total_bytes_and_decodes_only_intersecting_chunks() {
    use sedsnet::packet_store::PacketCodec;
    let store = PacketStore::new(8192, 16, 8192).unwrap();
    let mut codec = PacketCodec::new(128, usize::MAX).unwrap();
    let mut data = [0u8; 2048];
    for (i, x) in data.iter_mut().enumerate() {
        *x = (i / 128) as u8;
    }
    let mut encoded = [0; 2048];
    let h = codec.store(&store, &data, &mut encoded).unwrap();
    assert!(h.is_compressed());
    assert!(h.stored_len() < h.len());
    let occupied = store.stats().live_bytes;
    let mut field = [0; 12];
    let mut scratch = [0; 128];
    codec.read_range(&h, 124, &mut field, &mut scratch).unwrap();
    assert_eq!(field, data[124..136]);
    assert_eq!(codec.decoded_chunks(), 2);
    assert_eq!(store.stats().live_bytes, occupied);
    assert!(h.pin().is_err());
    // Incompressible tiny values cannot amortize headers. No expansion is stored.
    let plain = codec
        .store(&store, &[1, 9, 8, 7, 6, 5, 4, 3], &mut encoded)
        .unwrap();
    assert!(!plain.is_compressed());
    assert_eq!(plain.stored_len(), 8);
    assert!(codec.read_range(&h, 0, &mut field, &mut []).is_err());
    let mut tail = [0; 4];
    codec.read_range(&h, 2044, &mut tail, &mut scratch).unwrap();
    assert_eq!(tail, [15; 4]);
}

#[cfg(feature = "compact-packet-compression")]
#[test]
fn codec_requires_an_explicit_workspace_budget() {
    use sedsnet::packet_store::PacketCodec;
    assert!(PacketCodec::new(128, 0).is_err());
    let mut codec = PacketCodec::new(128, usize::MAX).unwrap();
    let workspace = codec.workspace_bytes();
    let store = PacketStore::new(4096, 8, 4096).unwrap();
    let mut encode = [0; 1024];
    let mut decode = [0; 128];
    for byte in 0..16 {
        let data = [byte; 1024];
        let h = codec.store(&store, &data, &mut encode).unwrap();
        let mut field = [0; 4];
        codec.read_range(&h, 80, &mut field, &mut decode).unwrap();
        assert_eq!(field, [byte; 4]);
        assert_eq!(codec.workspace_bytes(), workspace);
    }
}

#[test]
fn allocation_compacts_automatically_after_pins_are_released() {
    let store = PacketStore::new(64, 8, 64).unwrap();
    let a = store.store(&[1; 16]).unwrap();
    let b = store.store(&[2; 16]).unwrap();
    let c = store.store(&[3; 16]).unwrap();
    let d = store.store(&[4; 16]).unwrap();
    let pin = b.pin().unwrap();
    drop(a);
    drop(c);
    assert!(store.store(&[5; 28]).is_err());
    assert_eq!(&*pin, &[2; 16]);
    drop(pin);
    let e = store.store(&[5; 28]).unwrap();
    assert_eq!(&*d.pin().unwrap(), &[4; 16]);
    assert_eq!(&*e.pin().unwrap(), &[5; 28]);
    assert!(store.stats().moves > 0);
}
#[test]
fn randomized_reuse_compaction_and_pinning_preserve_every_live_payload() {
    let store = PacketStore::new(1024, 32, 100).unwrap();
    let mut live = Vec::new();
    let mut rng = 7u32;
    for _ in 0..3000 {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        if rng % 3 == 0 && !live.is_empty() {
            let index = rng as usize % live.len();
            live.swap_remove(index);
        } else {
            let len = 1 + (rng as usize % 120);
            let expected = vec![rng as u8; len];
            if let Ok(h) = store.store(&expected) {
                live.push((h, expected));
            }
        }
        if rng % 5 == 0 {
            store.compact();
        }
        for (h, expected) in &live {
            let pin = h.pin().unwrap();
            store.compact();
            assert_eq!(&*pin, expected);
        }
    }
    drop(live);
    assert_eq!(store.stats().live_bytes, 0);
    assert_eq!(store.stats().live_handles, 0);
}
#[cfg(feature = "compact-packet-compression")]
#[test]
fn consuming_packet_releases_original_payload_and_reads_a_field_without_a_cache() {
    use sedsnet::{
        config::{DataEndpoint, DataType},
        packet::Packet,
        packet_store::PacketCodec,
    };
    use std::sync::Arc;
    let store = PacketStore::new(8192, 32, 8192).unwrap();
    let original: Arc<[u8]> = Arc::from([b'A'; 4096]);
    let packet = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::TelemetryError],
        "FIELD",
        123,
        original.clone(),
    )
    .unwrap();
    let mut codec = PacketCodec::new(128, usize::MAX).unwrap();
    let mut encoded = [0; 4096];
    let packet = packet
        .into_stored_compressed(&store, &mut codec, &mut encoded)
        .unwrap();
    assert_eq!(Arc::strong_count(&original), 1);
    assert_eq!(packet.sender(), "FIELD");
    assert!(packet.payload_is_compressed());
    let occupied = store.stats().live_bytes;
    let mut field = [0; 4];
    let mut scratch = [0; 128];
    packet
        .read_payload_range_with_codec(&mut codec, 900, &mut field, &mut scratch)
        .unwrap();
    assert_eq!(field, [b'A'; 4]);
    assert_eq!(store.stats().live_bytes, occupied);
    assert!(occupied < 4096);
    drop(packet);
    assert_eq!(store.stats().live_bytes, 0);
}

#[test]
fn shared_owners_use_one_arena_allocation() {
    use std::sync::Arc;
    let store = PacketStore::new(256, 8, 256).unwrap();
    let original: Arc<[u8]> = Arc::from([7; 100]);
    let a = store.store_shared(&original).unwrap();
    let b = store.store_shared(&original).unwrap();
    assert_eq!(store.stats().live_handles, 1);
    assert_eq!(store.stats().live_bytes, 100);
    drop(original);
    let pin = a.pin().unwrap();
    drop(a);
    store.compact();
    assert_eq!(&*b.pin().unwrap(), &[7; 100]);
    drop(pin);
    drop(b);
    assert_eq!(store.stats().live_bytes, 0);
}
#[test]
fn router_raw_queue_uses_arena_and_dispatches_after_default_replacement() {
    use sedsnet::{
        MessageClass, MessageDataType, MessageElement, ReliableMode,
        config::{register_data_type_with_description, register_endpoint_with_description},
        packet::Packet,
        router::{Router, RouterConfig},
    };
    use std::sync::{Arc, Mutex};
    let ep = register_endpoint_with_description("ARENA_SINK", "", false).unwrap();
    let ty = register_data_type_with_description(
        "ARENA_VALUE",
        "",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        50,
    )
    .unwrap();
    let store = PacketStore::new(65536, 128, 65536).unwrap();
    set_default_store(Some(store.clone()));
    let frames = Arc::new(Mutex::new(Vec::new()));
    let received = frames.clone();
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    router.add_side_packed("wire", move |bytes| {
        received.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });
    let packet = Packet::new(ty, &[ep], "ARENA", 1, Arc::from([9; 1000])).unwrap();
    let raw = sedsnet::wire_format::pack_packet(&packet);
    router.tx_packed_queue(raw.clone()).unwrap();
    assert!(store.stats().live_bytes >= raw.len());
    set_default_store(None);
    store.compact();
    router.process_tx_queue().unwrap();
    let frames = frames.lock().unwrap();
    let delivered = frames
        .iter()
        .find_map(|bytes| {
            sedsnet::wire_format::unpack_packet(bytes)
                .ok()
                .filter(|p| p.data_type() == ty)
        })
        .expect("queued application packet delivered");
    assert_eq!(delivered.payload(), &[9; 1000]);
    drop(frames);
    drop(router);
    assert_eq!(store.stats().live_bytes, 0);
}

#[test]
fn concurrent_shared_parking_coalesces_atomically() {
    use std::sync::{Arc, Barrier};
    let store = PacketStore::new(4096, 16, 4096).unwrap();
    let source: Arc<[u8]> = Arc::from([5; 1000]);
    let barrier = Arc::new(Barrier::new(4));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        let source = source.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store.store_shared(&source).unwrap()
        }));
    }
    let handles = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(store.stats().live_handles, 1);
    assert_eq!(store.stats().live_bytes, 1000);
    for h in &handles {
        assert_eq!(&*h.pin().unwrap(), &[5; 1000]);
    }
    drop(handles);
    assert_eq!(store.stats().live_bytes, 0);
}

#[cfg(feature = "compact-packet-compression")]
#[test]
fn bounded_codec_budget_and_chunk_scratch_cover_large_mixed_packets() {
    use sedsnet::packet_store::{BoundedPacketCodec, PacketCodec};
    let required = PacketCodec::memory_requirements(128).unwrap();
    assert_eq!(required.decode_scratch_bytes, 128);
    assert!(required.encode_scratch_bytes < 256);
    assert!(PacketCodec::memory_requirements(0).is_err());
    assert!(PacketCodec::new(128, required.workspace_bytes - 1).is_err());
    assert!(BoundedPacketCodec::new(128, required.total_bytes - 1).is_err());
    let mut codec = BoundedPacketCodec::new(128, required.total_bytes).unwrap();
    assert_eq!(codec.reserved_bytes(), required.total_bytes);
    let store = PacketStore::new(16384, 8, 16384).unwrap();
    let mut data = [0u8; 8192];
    let mut state = 0x98765432u32;
    for (i, x) in data.iter_mut().enumerate() {
        if i / 128 % 2 == 0 {
            *x = (i / 128) as u8;
        } else {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *x = state as u8;
        }
    }
    let h = codec.store(&store, &data).unwrap();
    assert!(h.is_compressed());
    assert!(h.stored_len() < data.len());
    let live = store.stats().live_bytes;
    let mut field = [0; 12];
    codec.read_range(&h, 124, &mut field).unwrap();
    assert_eq!(field, data[124..136]);
    // One compressed chunk and one plain chunk, no unrelated decompressions.
    assert_eq!(codec.decoded_chunks(), 1);
    // Walk every byte with a small field buffer, including mixed chunk boundaries.
    for offset in (0..data.len()).step_by(field.len()) {
        let n = field.len().min(data.len() - offset);
        codec.read_range(&h, offset, &mut field[..n]).unwrap();
        assert_eq!(&field[..n], &data[offset..offset + n]);
    }
    assert_eq!(store.stats().live_bytes, live);
    assert_eq!(codec.reserved_bytes(), required.total_bytes);
    assert!(codec.read_range(&h, usize::MAX, &mut field).is_err());
}

#[cfg(feature = "compact-packet-compression")]
#[test]
fn bounded_packet_conversion_releases_original_and_has_no_decode_cache() {
    use sedsnet::{
        config::{DataEndpoint, DataType},
        packet::Packet,
        packet_store::{BoundedPacketCodec, PacketCodec},
    };
    use std::sync::Arc;
    let memory = PacketCodec::memory_requirements(128).unwrap();
    let mut codec = BoundedPacketCodec::new(128, memory.total_bytes).unwrap();
    let store = PacketStore::new(8192, 8, 8192).unwrap();
    let original: Arc<[u8]> = Arc::from([b'A'; 4096]);
    let packet = Packet::new(
        DataType::TelemetryError,
        &[DataEndpoint::TelemetryError],
        "BOUNDED",
        123,
        original.clone(),
    )
    .unwrap();
    let packet = packet.into_stored_bounded(&store, &mut codec).unwrap();
    assert_eq!(Arc::strong_count(&original), 1);
    let occupied = store.stats().live_bytes;
    assert!(packet.payload_is_compressed());
    let mut field = [0; 12];
    packet
        .read_payload_range_bounded(&mut codec, 124, &mut field)
        .unwrap();
    assert_eq!(field, [b'A'; 12]);
    assert_eq!(codec.decoded_chunks(), 2);
    assert_eq!(codec.reserved_bytes(), memory.total_bytes);
    assert_eq!(store.stats().live_bytes, occupied);
    drop(packet);
    assert_eq!(store.stats().live_bytes, 0);
}

#[cfg(feature = "compact-packet-compression")]
#[test]
#[ignore = "ten-minute wall-clock codec/arena pressure soak; run explicitly"]
fn bounded_codec_pressure_soak() {
    use sedsnet::packet_store::{BoundedPacketCodec, PacketCodec};
    use std::{
        collections::VecDeque,
        time::{Duration, Instant},
    };
    let seconds = std::env::var("SEDSNET_CODEC_SOAK_SECONDS")
        .ok()
        .map(|v| v.parse::<u64>().expect("valid soak seconds"))
        .unwrap_or(600);
    assert!(seconds > 0);
    let required = PacketCodec::memory_requirements(128).unwrap();
    let mut codec = BoundedPacketCodec::new(128, required.total_bytes).unwrap();
    let store = PacketStore::new(131072, 128, 512).unwrap();
    let anchor = store.store(&[0xa5; 256]).unwrap();
    let pin = anchor.pin().unwrap();
    let address = pin.as_ptr();
    let mut pending = VecDeque::with_capacity(32);
    let mut input = [0; 4096];
    let mut field = [0; 12];
    let byte_at = |seed: u64, offset: usize| -> u8 {
        if seed % 4 != 0 && offset / 128 % 2 == 0 {
            (seed + (offset / 128) as u64) as u8
        } else {
            let mut x = seed
                .wrapping_add(offset as u64)
                .wrapping_mul(0x9e3779b97f4a7c15);
            x ^= x >> 29;
            x = x.wrapping_mul(0xbf58476d1ce4e5b9);
            (x >> 32) as u8
        }
    };
    let started = Instant::now();
    let mut rounds = 0u64;
    let mut report_at = Duration::from_secs(30);
    while started.elapsed() < Duration::from_secs(seconds) {
        if pending.len() == 32 {
            pending.pop_front();
        }
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = byte_at(rounds, i);
        }
        let h = codec.store(&store, &input).unwrap();
        assert!(
            h.stored_len() <= input.len(),
            "compression expanded retained memory"
        );
        pending.push_back((h, rounds));
        for (h, seed) in &pending {
            let offset = ((*seed as usize * 127) % (input.len() - field.len()))
                .min(input.len() - field.len());
            let before = store.stats().live_bytes;
            codec.read_range(h, offset, &mut field).unwrap();
            for (i, byte) in field.iter().enumerate() {
                assert_eq!(*byte, byte_at(*seed, offset + i));
            }
            assert_eq!(
                store.stats().live_bytes,
                before,
                "field read retained a full decode"
            );
        }
        if rounds % 64 == 0 {
            // Refuse a request larger than the whole arena without corrupting
            // retained payloads or losing a pinned address, then keep draining.
            assert!(store.store(&[0; 131073]).is_err());
            store.compact();
        }
        assert_eq!(pin.as_ptr(), address);
        assert_eq!(&*pin, &[0xa5; 256]);
        assert_eq!(codec.reserved_bytes(), required.total_bytes);
        rounds += 1;
        if started.elapsed() >= report_at {
            eprintln!(
                "codec soak: {} seconds, {rounds} rounds, stats={:?}",
                started.elapsed().as_secs(),
                store.stats()
            );
            report_at += Duration::from_secs(30);
        }
    }
    drop(pending);
    drop(pin);
    drop(anchor);
    assert_eq!(store.stats().live_bytes, 0);
    assert_eq!(store.stats().live_handles, 0);
    eprintln!(
        "codec soak PASS: {} seconds, {rounds} rounds, workspace={} bytes, stats={:?}",
        started.elapsed().as_secs(),
        required.total_bytes,
        store.stats()
    );
}
