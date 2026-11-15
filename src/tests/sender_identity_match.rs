use super::*;

fn learn(receiver: &Router, name: &str, address: u32) {
    let packets = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = packets.clone();
    let producer = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname(name)
            .with_static_address(address),
        Box::new(|| 1),
    );
    producer.add_side_packet("wire", move |packet| {
        capture.lock().unwrap().push(packet.clone());
        Ok(())
    });
    producer.announce_discovery().unwrap();
    producer.process_all_queues_with_timeout(0).unwrap();
    let side = receiver.add_side_packet(name, |_| Ok(()));
    for packet in packets.lock().unwrap().iter() {
        receiver.rx_from_side(packet, side).unwrap();
    }
    receiver.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(receiver.resolve_hostname(name).unwrap().address, address);
}
#[test]
fn sender_match_named_invalid_unknown_and_discovered_aliases() {
    let receiver = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname("identity-receiver")
            .with_static_address(5000),
        Box::new(|| 1),
    );
    let name = "identity-source";
    let compact = format!("@addr:{}", sender_address_u32(name));
    assert!(receiver.sender_matches_hostname(name, name));
    assert!(
        !receiver.sender_matches_hostname(&compact, name),
        "a deterministic hash alone must never establish identity"
    );
    for source in [
        "",
        "other-source",
        "@addr:",
        "@addr:+101",
        "@addr:-1",
        "@addr: 101",
        "@addr:101 ",
        "@addr:4294967296",
        "@addr:abc",
        "@addr:0",
        "@addr:unknown",
        "identity-source\0",
    ] {
        assert!(
            !receiver.sender_matches_hostname(source, name),
            "{source:?}"
        );
    }
    assert!(!receiver.sender_matches_hostname(name, ""));
    assert!(!receiver.sender_matches_hostname("@addr:101", "@addr:101"));
    learn(&receiver, name, 101);
    assert!(receiver.sender_matches_hostname(&compact, name));
    assert!(receiver.sender_matches_hostname("@addr:101", name));
    assert!(!receiver.sender_matches_hostname("@addr:102", name));
    assert!(!receiver.sender_matches_hostname(&compact, "other-source"));
    assert!(!receiver.sender_matches_hostname("identity-source", "IDENTITY-SOURCE"));
}
#[test]
fn sender_match_compact_collisions_fail_closed_while_assigned_owners_match() {
    let receiver = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname("identity-collision-receiver")
            .with_static_address(5000),
        Box::new(|| 1),
    );
    let a = "identity-collision-51666";
    let b = "identity-collision-117548";
    assert_eq!(sender_address_u32(a), 2711038533);
    assert_eq!(sender_address_u32(a), sender_address_u32(b));
    learn(&receiver, a, 101);
    assert!(receiver.sender_matches_hostname("@addr:2711038533", a));
    learn(&receiver, b, 102);
    assert!(!receiver.sender_matches_hostname("@addr:2711038533", a));
    assert!(!receiver.sender_matches_hostname("@addr:2711038533", b));
    assert!(receiver.sender_matches_hostname("@addr:101", a));
    assert!(receiver.sender_matches_hostname("@addr:102", b));
    assert!(!receiver.sender_matches_hostname("@addr:101", b));
    assert!(!receiver.sender_matches_hostname("@addr:102", a));
    // The existing assigned-address namespace stays authoritative.
    let assigned = "identity-explicit-address-owner";
    learn(&receiver, assigned, 2711038533);
    assert!(receiver.sender_matches_hostname("@addr:2711038533", assigned));
    assert!(!receiver.sender_matches_hostname("@addr:2711038533", a));
    assert!(!receiver.sender_matches_hostname("@addr:2711038533", b));
}
#[test]
fn sender_match_retained_bridge_connections_without_address_advertisement() {
    let receiver = Router::new_with_clock(
        RouterConfig::new([]).with_hostname("identity-bridge-receiver"),
        Box::new(|| 1),
    );
    let name = "identity-far-source";
    let alias = format!("@addr:{}", sender_address_u32(name));
    assert!(!receiver.sender_matches_hostname(&alias, name));
    let topology = crate::discovery::build_discovery_topology(
        "identity-bridge",
        1,
        &[crate::discovery::TopologyBoardNode {
            sender_id: "identity-bridge".into(),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec![name.into()],
        }],
    )
    .unwrap();
    let side = receiver.add_side_packet("bridge", |_| Ok(()));
    receiver.rx_from_side(&topology, side).unwrap();
    receiver.process_all_queues_with_timeout(0).unwrap();
    assert!(receiver.sender_matches_hostname(&alias, name));
}

/// A board behind a relay that never learned a station's address (an empty
/// address book) still identifies the station by the station predicate,
/// while the general name match stays fail-closed.
#[test]
fn station_match_identifies_a_station_a_board_never_learned() {
    let fc = Router::new_with_clock(RouterConfig::new([]).with_hostname("FC"), Box::new(|| 1_000));
    let rrls = format!("@addr:{}", sender_address_u32("RRLS"));
    assert!(fc.address_book().iter().all(|entry| entry.hostname.as_ref() != "RRLS"));
    assert!(fc.sender_matches_station(&rrls, "RRLS"));
    assert!(!fc.sender_matches_hostname(&rrls, "RRLS"), "the general rule is unchanged");
    assert!(!fc.sender_matches_station(&rrls, "GS"));
    assert!(fc.sender_matches_station("RRLS", "RRLS"), "a full-name sender, as before");
    for bad in ["", "@addr:", "@addr:abc", "@addr:4294967296", "RRLS\0"] {
        assert!(!fc.sender_matches_station(bad, "RRLS"), "{bad:?}");
    }
    assert!(!fc.sender_matches_station(&rrls, ""));
    assert!(!fc.sender_matches_station(&rrls, &rrls));
}

/// The station predicate fails closed when another name the receiver knows
/// has the same compact identity, and an assigned address still decides.
#[test]
fn station_match_refuses_a_compact_identity_another_known_name_shares() {
    let receiver = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname("identity-station-receiver")
            .with_static_address(5000),
        Box::new(|| 1),
    );
    // A known colliding pair (sender_match_compact_collisions_fail_closed_while_assigned_owners_match).
    let station = "identity-collision-51666";
    let other = "identity-collision-117548";
    let compact = format!("@addr:{}", sender_address_u32(station));
    assert_eq!(sender_address_u32(station), sender_address_u32(other));
    assert!(receiver.sender_matches_station(&compact, station), "nothing known: the station's own identity");
    learn(&receiver, other, 102);
    assert!(!receiver.sender_matches_station(&compact, station), "another known name shares it: refused");
    assert!(receiver.sender_matches_station(&compact, other), "the known name itself, no other known name shares it");
    learn(&receiver, "identity-explicit-address-owner", sender_address_u32(station));
    assert!(!receiver.sender_matches_station(&compact, station), "an assigned address decides alone");
}
