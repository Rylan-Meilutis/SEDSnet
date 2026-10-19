#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    config::{DataEndpoint, DataType},
    discovery,
    packet::Packet,
    relay::{Relay, RelayConfig},
    router::{Router, RouterConfig},
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
static LOCK: Mutex<()> = Mutex::new(());
static PROTECTED: AtomicUsize = AtomicUsize::new(0);
extern "C" fn probe(additional: usize, _: usize, kind: u32) -> bool {
    if kind == sedsnet::memory_admission::WORK_SMALL_PROTECTED {
        PROTECTED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        !(2048..=2432).contains(&additional)
    }
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe_v2(None);
    }
}
fn requests() -> Vec<Packet> {
    vec![
        discovery::build_discovery_topology_request("GS", 1).unwrap(),
        discovery::build_discovery_schema_request("GS", 1).unwrap(),
    ]
}
#[test]
fn empty_discovery_requests_reach_router_and_relay_under_control_only_headroom() {
    let _lock = LOCK.lock().unwrap();
    let _reset = Reset;
    let router = Router::new(RouterConfig::default().with_sender("GB"));
    let rs = router.add_side_packed("uart", |_| Ok(()));
    let relay = Relay::new_with_config(RelayConfig::default().with_sender("RF"), Box::new(|| 1));
    let ls = relay.add_side_packed("radio", |_| Ok(()));
    for packet in requests() {
        let wire = sedsnet::wire_format::pack_packet(&packet);
        sedsnet::memory_admission::set_probe_v2(Some(probe));
        PROTECTED.store(0, Ordering::Relaxed);
        router
            .rx_packed_queue_from_side(&wire, rs)
            .expect("restart request must enter router");
        relay
            .rx_packed_from_side(ls, &wire)
            .expect("restart request must enter relay");
        sedsnet::wire_format::unpack_packet(&wire)
            .expect("request decode must retain its admission class");
        assert!(PROTECTED.load(Ordering::Relaxed) >= 3);
        sedsnet::memory_admission::set_probe_v2(None);
        router.drain_queues_with_timeout(0).unwrap();
        relay.drain_queues_with_timeout(0).unwrap();
    }
}
#[test]
fn nonempty_wrong_endpoint_and_corrupt_requests_cannot_use_control_reserve() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let router = Router::new(RouterConfig::default().with_sender("GB"));
    let side = router.add_side_packed("uart", |_| Ok(()));
    let other = sedsnet::config::register_endpoint("OTHER_REQUEST_DESTINATION", false).unwrap();
    let mut invalid = Vec::new();
    for request in requests() {
        invalid.push(sedsnet::wire_format::pack_packet(
            &Packet::new(
                request.data_type(),
                &[DataEndpoint::Discovery],
                "GS",
                1,
                vec![1].into(),
            )
            .unwrap(),
        ));
        invalid.push(sedsnet::wire_format::pack_packet(
            &Packet::new(
                request.data_type(),
                &[other],
                "GS",
                1,
                Vec::<u8>::new().into(),
            )
            .unwrap(),
        ));
        let mut corrupt = sedsnet::wire_format::pack_packet(&request).to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        invalid.push(corrupt.into());
    }
    invalid.push(sedsnet::wire_format::pack_packet(
        &Packet::new(
            DataType::DiscoveryTopology,
            &[DataEndpoint::Discovery],
            "GS",
            1,
            Vec::<u8>::new().into(),
        )
        .unwrap(),
    ));
    sedsnet::memory_admission::set_probe_v2(Some(probe));
    for wire in invalid {
        PROTECTED.store(0, Ordering::Relaxed);
        assert!(router.rx_packed_queue_from_side(&wire, side).is_err());
        assert_eq!(PROTECTED.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn legacy_probe_retains_full_ingress_estimate_for_discovery_requests() {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    extern "C" fn legacy(additional: usize, _: usize) -> bool {
        additional < 2048
    }
    let router = Router::new(RouterConfig::default().with_sender("GB"));
    let side = router.add_side_packed("uart", |_| Ok(()));
    sedsnet::memory_admission::set_probe(Some(legacy));
    for request in requests() {
        let wire = sedsnet::wire_format::pack_packet(&request);
        assert!(router.rx_packed_queue_from_side(&wire, side).is_err());
    }
}
