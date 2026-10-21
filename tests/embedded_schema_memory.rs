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
    // Exercise the actual no_std decoder, not hosted sender/schema caches.
    // Only the retained numeric sender alias and final endpoints need storage;
    // the small payload and absent frozen targets need no allocations.
    let ty = sedsnet::config::DataType::named("GPS_DATA");
    let meta = sedsnet::config::data_type_definition(ty).unwrap();
    let scalar =
        sedsnet::packet::Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &meta.endpoints, 123)
            .unwrap();
    let wire = sedsnet::wire_format::pack_packet(&scalar);
    sedsnet::wire_format::unpack_packet(&wire).unwrap();
    LARGE.with(|v| v.set(Some((0, 0))));
    let decoded = sedsnet::wire_format::unpack_packet(&wire).unwrap();
    let allocations = LARGE.with(|v| v.replace(None).unwrap().1);
    assert_eq!(
        allocations, 2,
        "embedded small decoder allocated temporary metadata/payload storage"
    );
    assert_eq!(decoded.payload(), scalar.payload());
    assert_eq!(decoded.packet_id(), scalar.packet_id());
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
    // An already-known schema requires no full decoder workspace. Reject that
    // headroom while still permitting small control bookkeeping on both paths.
    static LARGE_ADMISSIONS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    extern "C" fn control_only(additional: usize, _: usize) -> bool {
        if additional > 1024 {
            // An unrelated periodic announcement may probe its fixed 8 KiB
            // workspace; only the payload-sized schema decoder is forbidden.
            if additional > 8192 {
                LARGE_ADMISSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            false
        } else {
            true
        }
    }
    let router = sedsnet::router::Router::new_with_clock(
        sedsnet::router::RouterConfig::new(vec![]),
        Box::new(|| 0),
    );
    let router_side = router.add_side_packet("known-schema", |_| Ok(()));
    let relay = sedsnet::relay::Relay::new(Box::new(|| 0));
    let relay_side = relay.add_side_packet("known-schema", |_| Ok(()));
    relay.rx_from_side(relay_side, first.clone()).unwrap();
    sedsnet::memory_admission::set_probe(Some(control_only));
    let router_result = router.rx_from_side(&first, router_side);
    let relay_result = relay.process_rx_queue();
    sedsnet::memory_admission::set_probe(None);
    router_result.unwrap();
    relay_result.unwrap();
    assert_eq!(
        LARGE_ADMISSIONS.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "known schema unnecessarily required full decoder headroom"
    );
    // The hardware capture refused a packed schema before reaching the
    // decoded-Packet fast path. Exercise raw and actual full side wrappers
    // with no payload-sized headroom; neither may clone the known snapshot.
    let tuning = sedsnet::config::runtime_tuning_config();
    sedsnet::config::set_runtime_tuning_config(sedsnet::config::RuntimeTuningConfig {
        payload_compress_threshold: usize::MAX,
        ..tuning
    })
    .unwrap();
    let raw = sedsnet::wire_format::pack_packet(&first);
    let sequenced = sedsnet::wire_format::pack_packet_with_reliable(
        &first,
        sedsnet::wire_format::ReliableHeader {
            flags: 0,
            seq: 1,
            ack: 0,
        },
    );
    let piggyback = sedsnet::wire_format::pack_packet_with_reliable(
        &first,
        sedsnet::wire_format::ReliableHeader {
            flags: sedsnet::wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 1,
        },
    );
    let mut unknown_payload = first.payload().to_vec();
    assert!(unknown_payload.len() > 12 && !expected.endpoints.is_empty());
    unknown_payload[8..12].copy_from_slice(&(u32::MAX - 7).to_le_bytes());
    let unknown = sedsnet::packet::Packet::new(
        first.data_type(),
        first.endpoints(),
        "GB",
        9,
        std::sync::Arc::from(unknown_payload),
    )
    .unwrap();
    let unknown = sedsnet::wire_format::pack_packet(&unknown);
    sedsnet::config::set_runtime_tuning_config(tuning).unwrap();
    let wrapped_router_side = router.add_side_packed_with_options(
        "known-full-schema",
        |_| Ok(()),
        sedsnet::router::RouterSideOptions {
            header_template_enabled: true,
            ..Default::default()
        },
    );
    let wrapped_relay_side = relay.add_side_packed_with_options(
        "known-full-schema",
        |_| Ok(()),
        sedsnet::relay::RelaySideOptions {
            header_template_enabled: true,
            ..Default::default()
        },
    );
    let mut full = b"SDT\x01\x01".to_vec();
    full.extend_from_slice(&raw);
    full.extend_from_slice(&crc32fast::hash(&full).to_le_bytes());
    let mut corrupt = raw.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut truncated = raw[..raw.len() - 5].to_vec();
    truncated.extend_from_slice(&crc32fast::hash(&truncated).to_le_bytes());
    let mut compressed = raw[..raw.len() - 4].to_vec();
    compressed[0] |= 1;
    compressed.extend_from_slice(&crc32fast::hash(&compressed).to_le_bytes());
    LARGE.with(|v| v.set(Some((payload_len, 0))));
    sedsnet::memory_admission::set_probe(Some(control_only));
    // Reliable sequencing and piggyback receipts must never be bypassed.
    for frame in [&sequenced, &piggyback] {
        assert!(matches!(
            router.rx_packed_from_side(frame, router_side),
            Err(sedsnet::TelemetryError::Io("memory pressure"))
        ));
        assert!(matches!(
            relay.rx_packed_from_side(relay_side, frame),
            Err(sedsnet::TelemetryError::Io("memory pressure"))
        ));
    }
    let raw_router = router.rx_packed_from_side(&raw, router_side);
    let raw_relay = relay.rx_packed_from_side(relay_side, &raw);
    let full_router = router.rx_packed_from_side(&full, wrapped_router_side);
    let full_relay = relay.rx_packed_from_side(wrapped_relay_side, &full);
    assert!(router.rx_packed_from_side(&corrupt, router_side).is_err());
    assert!(relay.rx_packed_from_side(relay_side, &corrupt).is_err());
    assert!(router.rx_packed_from_side(&truncated, router_side).is_err());
    assert!(relay.rx_packed_from_side(relay_side, &truncated).is_err());
    // A compression flag must not interpret compressed bytes as a no-op
    // schema. It retains ordinary allocation admission and decode semantics.
    assert!(matches!(
        router.rx_packed_from_side(&compressed, router_side),
        Err(sedsnet::TelemetryError::Io("memory pressure"))
    ));
    assert!(matches!(
        relay.rx_packed_from_side(relay_side, &compressed),
        Err(sedsnet::TelemetryError::Io("memory pressure"))
    ));
    // A genuinely new definition still needs merge/decode headroom. The
    // optimization must never falsely acknowledge an unknown schema.
    assert!(matches!(
        router.rx_packed_from_side(&unknown, router_side),
        Err(sedsnet::TelemetryError::Io("memory pressure"))
    ));
    assert!(matches!(
        relay.rx_packed_from_side(relay_side, &unknown),
        Err(sedsnet::TelemetryError::Io("memory pressure"))
    ));
    sedsnet::memory_admission::set_probe(None);
    let packed_copies = LARGE.with(|v| v.replace(None).unwrap().1);
    raw_router.unwrap();
    raw_relay.unwrap();
    full_router.unwrap();
    full_relay.unwrap();
    assert_eq!(
        packed_copies, 0,
        "known packed schema cloned its payload before admission"
    );
    // Duplicate fragments must reuse their retained payload rather than copy
    // it into another allocation and immediately discard that copy.
    let mut chunk = b"SDT\x03".to_vec();
    chunk.extend_from_slice(&123u32.to_le_bytes());
    chunk.extend_from_slice(&0u16.to_le_bytes());
    chunk.extend_from_slice(&2u16.to_le_bytes());
    chunk.extend_from_slice(&[0x5a; 128]);
    chunk.extend_from_slice(&crc32fast::hash(&chunk).to_le_bytes());
    router.rx_packed_from_side(&chunk, router_side).unwrap();
    relay.rx_packed_from_side(relay_side, &chunk).unwrap();
    LARGE.with(|v| v.set(Some((128, 0))));
    let router_duplicate = router.rx_packed_from_side(&chunk, router_side);
    let relay_duplicate = relay.rx_packed_from_side(relay_side, &chunk);
    let copies = LARGE.with(|v| v.replace(None).unwrap().1);
    router_duplicate.unwrap();
    relay_duplicate.unwrap();
    assert_eq!(copies, 0, "duplicate chunks allocated another payload copy");
}

#[test]
fn embedded_named_id_lookup_uses_retained_schema_storage() {
    // Exercise every compiled ID, including reserved endpoint IDs 200–202.
    // Generated endpoint IDs start at 100; they do not share the built-in
    // type-ID range. Unknown IDs must not alias a neighboring table entry.
    let schema = sedsnet::config::export_schema();
    for def in &schema.endpoints {
        assert!(
            sedsnet::config::endpoint_exists(def.id),
            "missing {}",
            def.name
        );
        assert_eq!(sedsnet::config::endpoint_definition(def.id).unwrap(), *def);
    }
    for def in &schema.types {
        assert!(
            sedsnet::config::data_type_exists(def.id),
            "missing {}",
            def.name
        );
        assert_eq!(sedsnet::config::data_type_definition(def.id).unwrap(), *def);
    }
    assert!(!sedsnet::config::endpoint_exists(
        sedsnet::config::DataEndpoint(u32::MAX)
    ));
    assert!(!sedsnet::config::data_type_exists(
        sedsnet::config::DataType(u32::MAX)
    ));
    assert_eq!(
        sedsnet::config::schema_bytes_used(),
        0,
        "flash schema must not consume the runtime RAM budget"
    );
    let ty = sedsnet::config::DataType::named("GPS_DATA");
    let def = sedsnet::config::data_type_definition(ty).unwrap();
    let ep = def.endpoints[0];
    let endpoint = sedsnet::config::endpoint_definition(ep).unwrap();
    LARGE.with(|v| v.set(Some((0, 0))));
    for _ in 0..1000 {
        assert_eq!(sedsnet::config::DataType::try_named("GPS_DATA"), Some(ty));
        assert_eq!(
            sedsnet::config::DataEndpoint::try_named(&endpoint.name),
            Some(ep)
        );
        assert_eq!(
            sedsnet::config::DataType::try_named("ID_LOOKUP_MISSING"),
            None
        );
    }
    let allocations = LARGE.with(|v| v.replace(None).unwrap().1);
    assert_eq!(
        allocations, 0,
        "embedded ID lookup copied static schema definitions"
    );
}

#[test]
fn embedded_scheduling_metadata_follows_replaced_runtime_definitions() {
    use sedsnet::config::{
        DataEndpoint, DataType, OwnedDataTypeDefinition, OwnedRuntimeSchemaSnapshot,
        merge_owned_schema_snapshot_with_budget,
    };
    let ty = DataType::identity("LIVE_EMBEDDED_DELIVERY_META");
    assert_eq!(sedsnet::message_priority(ty), 0);
    assert_eq!(sedsnet::reliable_mode(ty), sedsnet::ReliableMode::None);
    merge_owned_schema_snapshot_with_budget(
        OwnedRuntimeSchemaSnapshot {
            endpoints: vec![],
            types: vec![OwnedDataTypeDefinition {
                id: ty,
                name: "LIVE_EMBEDDED_DELIVERY_META".into(),
                description: String::new(),
                element: sedsnet::MessageElement::Static(
                    1,
                    sedsnet::MessageDataType::UInt8,
                    sedsnet::MessageClass::Data,
                ),
                endpoints: vec![DataEndpoint::Discovery],
                reliable: sedsnet::ReliableMode::Unordered,
                priority: 123,
                e2e_encryption: sedsnet::E2eEncryptionPolicy::PreferOff,
            }],
        },
        usize::MAX,
    )
    .unwrap();
    assert_eq!(sedsnet::message_priority(ty), 123);
    assert_eq!(sedsnet::reliable_mode(ty), sedsnet::ReliableMode::Unordered);

    for (mode, priority) in [
        (sedsnet::ReliableMode::Unordered, 231),
        (sedsnet::ReliableMode::Ordered, 241),
        (sedsnet::ReliableMode::None, 0),
    ] {
        let mut definition = sedsnet::config::data_type_definition(ty).unwrap();
        definition.reliable = mode;
        definition.priority = priority;
        sedsnet::config::merge_owned_schema_snapshot_with_budget(
            sedsnet::config::OwnedRuntimeSchemaSnapshot {
                endpoints: vec![],
                types: vec![definition],
            },
            usize::MAX,
        )
        .unwrap();
        // Conflicting wire contracts use the deterministic merge winner.
        // The fast accessors must reflect that current winner, never a cache.
        let current = sedsnet::config::data_type_definition(ty).unwrap();
        assert_eq!(sedsnet::reliable_mode(ty), current.reliable);
        assert_eq!(
            sedsnet::is_reliable_type(ty),
            current.reliable != sedsnet::ReliableMode::None
        );
        assert_eq!(sedsnet::message_priority(ty), current.priority);
        if mode == sedsnet::ReliableMode::Unordered && priority == 231 {
            assert_eq!(current.priority, 231);
        }
    }
}
