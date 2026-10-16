#![cfg(feature = "std")]
use sedsnet::packet::Packet;
use sedsnet::router::{NetworkVariablePermissions, Router, RouterConfig};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::Arc;

// A separate test process owns the global allocator probe.
#[test]
fn low_schema_priority_managed_control_retains_bounded_reserved_admission() {
    let endpoints = ["FLIGHT", "STORAGE", "GROUND"]
        .map(|name| sedsnet::config::register_endpoint(name, false).unwrap());
    let ty = sedsnet::config::register_data_type_with_description(
        "MANAGED_LOW_PRIORITY_ADMISSION",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &endpoints,
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let router = Router::new(RouterConfig::new([]).with_sender("GATEWAY"));
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let side = router.add_side_packed("uart", |_| Ok(()));
    let wire = sedsnet::wire_format::pack_packet(
        &Packet::new(ty, &endpoints, "GS", 1, Arc::<[u8]>::from([1])).unwrap(),
    );
    // Allocate queue backing before the pressure event, as in the warmed gateway.
    router.rx_packed_queue_from_side(&wire, side).unwrap();
    router.clear_queues();
    let ordinary = Router::new(RouterConfig::new([]).with_sender("ORDINARY"));
    let ordinary_side = ordinary.add_side_packed("uart", |_| Ok(()));
    ordinary
        .rx_packed_queue_from_side(&wire, ordinary_side)
        .unwrap();
    ordinary.clear_queues();
    extern "C" fn bounded_control_only(additional: usize, largest: usize, kind: u32) -> bool {
        kind == sedsnet::memory_admission::WORK_SMALL_PROTECTED
            && (2048..=2432).contains(&additional)
            && largest <= 160
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            sedsnet::memory_admission::set_probe_v2(None);
        }
    }
    let _reset = Reset;
    sedsnet::memory_admission::set_probe_v2(Some(bounded_control_only));
    router.rx_packed_queue_from_side(&wire, side).expect(
        "managed controls retain their complete bounded estimate but use reserved headroom",
    );
    assert!(
        ordinary
            .rx_packed_queue_from_side(&wire, ordinary_side)
            .is_err(),
        "a low-priority type without a registered managed role cannot borrow the control reserve"
    );
    let mut corrupt = wire.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        router.rx_packed_queue_from_side(&corrupt, side).is_err(),
        "reserved admission does not bypass CRC validation"
    );
}
