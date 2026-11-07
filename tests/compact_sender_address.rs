#![cfg(feature = "std")]
//! Public API contracts; generic test schema/names, no application board IDs.
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{DataEndpoint, DataType, register_data_type_id, register_endpoint_id},
    packet::{Packet, sender_address_u32},
    wire_format::{pack_packet, peek_envelope, unpack_packet},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{Arc, OnceLock},
};

thread_local! { static ALLOCS: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|count| {
            if let Some(value) = count.get() {
                count.set(Some(value + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
}

fn register_schema() {
    static SCHEMA: OnceLock<()> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let target = DataEndpoint(180);
        register_endpoint_id(target, "SENDER_API_TEST_TARGET", false).unwrap();
        register_data_type_id(
            DataType(180),
            "SENDER_API_TEST_VALUE",
            MessageElement::Static(8, MessageDataType::UInt8, MessageClass::Data),
            &[target],
            ReliableMode::None,
            0,
        )
        .unwrap();
    });
}

fn packet(sender: &str) -> Packet {
    register_schema();
    Packet::new_with_nonce(
        DataType(180),
        &[DataEndpoint(180)],
        sender,
        200,
        9,
        Arc::from([1u8, 2, 3, 4, 5, 6, 7, 8]),
    )
    .unwrap()
}

#[test]
fn public_function_preserves_literal_and_numeric_alias_contract() {
    // Fixed pre-existing function outputs, not a second hash implementation.
    for (name, expected) in [
        ("sender-api-alpha", 980_322_278),
        ("sender-api-beta", 2_508_323_153),
        ("", 1_266_620_901),
        ("sensor-µ", 3_321_715_545),
        ("@addr:0", 0),
        ("@addr:17", 17),
        ("@addr:00017", 17),
        ("@addr:+17", 17),
        ("@addr:4294967295", u32::MAX),
    ] {
        assert_eq!(sender_address_u32(name), expected, "{name:?}");
    }
}

#[test]
fn public_identity_matches_actual_canonical_header_and_alias_packet_id() {
    let named = packet("sender-api-wire-contract");
    let compact = sender_address_u32(named.sender());
    let numeric = packet(&format!("@addr:{compact}"));
    let named_wire = pack_packet(&named);
    let numeric_wire = pack_packet(&numeric);
    assert_eq!(peek_envelope(&named_wire).unwrap().source_address, compact);
    assert_eq!(numeric.packet_id(), named.packet_id());
    assert_eq!(numeric_wire, named_wire);
    for malformed in [
        "@addr:",
        "@addr:-1",
        "@addr:4294967296",
        "@addr: 17",
        "@addr:17 ",
        "@ADDR:17",
    ] {
        let wire = pack_packet(&packet(malformed));
        assert_eq!(
            peek_envelope(&wire).unwrap().source_address,
            sender_address_u32(malformed)
        );
        assert_ne!(sender_address_u32(malformed), 0);
    }
}

#[cfg(feature = "discovery")]
#[test]
fn compact_wire_identity_is_not_assigned_node_address_or_route_discovery() {
    use sedsnet::router::{Router, RouterConfig};
    let name = "sender-api-assigned-namespace";
    let router = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname(name)
            .with_static_address(101),
        Box::new(|| 1),
    );
    let before = router.address_book();
    let queued_before = router.has_queued_work();
    let compact = sender_address_u32(name);
    assert_eq!(router.current_address(), 101);
    assert_ne!(compact, 101);
    assert_eq!(
        peek_envelope(&pack_packet(&packet(name)))
            .unwrap()
            .source_address,
        compact
    );
    assert_eq!(router.address_book(), before);
    assert_eq!(router.has_queued_work(), queued_before);
}

#[test]
fn pure_identity_allocates_nothing_for_names_aliases_and_malformed_text() {
    let names = [
        "sender-api-no-allocation",
        "@addr:17",
        "@addr:-1",
        "sensor-µ",
        "",
    ];
    ALLOCS.with(|count| count.set(Some(0)));
    let mut combined = 0;
    for _ in 0..1000 {
        for name in names {
            combined ^= std::hint::black_box(sender_address_u32(name));
        }
    }
    std::hint::black_box(combined);
    let count = ALLOCS.with(|count| count.replace(None)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn helper_does_not_populate_wire_cache_but_actual_pack_does() {
    const NAME: &str = "sender-api-pure-cache-causal";
    const PRODUCER: &str = "SEDS_SENDER_API_CACHE_PRODUCER";
    if let Some(path) = std::env::var_os(PRODUCER) {
        // A separate actual SDK process creates canonical bytes; this parent
        // never packs NAME until the final explicit positive control below.
        std::fs::write(path, pack_packet(&packet(NAME))).unwrap();
        return;
    }
    // Schema metadata only: do not pack NAME or populate the wire-name cache.
    register_schema();
    let path = std::env::temp_dir().join(format!("sender-api-wire-{}.bin", std::process::id()));
    assert!(!path.exists());
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "helper_does_not_populate_wire_cache_but_actual_pack_does",
            "--test-threads=1",
        ])
        .env(PRODUCER, &path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "separate canonical pack producer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    let wire = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let actual_source = peek_envelope(&wire).unwrap().source_address;
    let unresolved = format!("@addr:{actual_source}");
    assert_eq!(unpack_packet(&wire).unwrap().sender(), unresolved);
    assert_eq!(sender_address_u32(NAME), actual_source);
    assert_eq!(
        unpack_packet(&wire).unwrap().sender(),
        unresolved,
        "pure helper must not learn a sender name"
    );
    let packed = pack_packet(&packet(NAME));
    assert_eq!(packed.as_ref(), wire.as_slice());
    assert_eq!(
        unpack_packet(&wire).unwrap().sender(),
        NAME,
        "packing is the actual cache-populating positive control"
    );
}
