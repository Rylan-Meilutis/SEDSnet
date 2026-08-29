#![cfg(not(feature = "std"))]

use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::packet::Packet;
use sedsnet::router::{Router, RouterConfig};

use std::sync::Arc;
use std::sync::Mutex;

// The no_std library delegates synchronization to the platform. This test is
// single-threaded, so no-op host shims are sufficient to execute that path.
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}

#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
fn immutable_embedded_router_ignores_remote_schema_without_decoding_it() {
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let side = router.add_side_packed("embedded-link", |_bytes| Ok(()));

    // This is intentionally not a valid discovery-schema encoding. Immutable
    // no_std nodes cannot merge remote schemas, so they must accept and discard
    // the already-framed packet without allocating a decoded snapshot.
    let payload = Arc::<[u8]>::from(vec![0xA5; 128 * 1024]);
    let packet = Packet::new(
        DataType::DiscoverySchema,
        &[DataEndpoint::Discovery],
        "REMOTE_NODE",
        1,
        payload.clone(),
    )
    .unwrap();
    let payload_owners = Arc::strong_count(&payload);

    router.rx_from_side(&packet, side).unwrap();

    assert_eq!(Arc::strong_count(&payload), payload_owners);
}

#[test]
fn immutable_embedded_router_does_not_advertise_unused_schema_frames() {
    let router = Router::new_with_clock(RouterConfig::default(), Box::new(|| 0));
    let frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let captured = frames.clone();
    router.add_side_packed("embedded-link", move |bytes| {
        captured.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let frames = frames.lock().unwrap();
    assert!(!frames.is_empty());
    assert!(frames.iter().all(|bytes| {
        sedsnet::wire_format::unpack_packet(bytes)
            .map(|packet| packet.data_type() != DataType::DiscoverySchema)
            .unwrap_or(true)
    }));
}
