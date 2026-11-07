#![cfg(all(feature = "std", feature = "discovery"))]
//! Public preparation/delivery contracts. All names and schema IDs are generic.
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode,
    config::{DataEndpoint, DataType, register_data_type_id, register_endpoint_id},
    discovery,
    packet::Packet,
    router::{
        EndpointHandler, MAX_PREPARED_TARGET_RECIPIENTS, PrepareTargetedPacketErrorKind as Kind,
        Router, RouterConfig,
    },
    wire_format::{pack_packet, unpack_packet},
};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

const ENDPOINT: DataEndpoint = DataEndpoint(181);
const TYPE: DataType = DataType(181);
fn schema() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        register_endpoint_id(ENDPOINT, "FROZEN_TARGET_TEST_ENDPOINT", false).unwrap();
        register_data_type_id(
            TYPE,
            "FROZEN_TARGET_TEST_VALUE",
            MessageElement::Static(4, MessageDataType::UInt8, MessageClass::Data),
            &[ENDPOINT],
            ReliableMode::None,
            0,
        )
        .unwrap();
    });
}
fn packet() -> Packet {
    schema();
    Packet::new_with_nonce(
        TYPE,
        &[ENDPOINT],
        "cohort-source",
        123456,
        77,
        Arc::from([2u8, 4, 6, 8]),
    )
    .unwrap()
}
fn source() -> (Router, usize, Arc<AtomicUsize>) {
    schema();
    let reads = Arc::new(AtomicUsize::new(0));
    let capture = reads.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("cohort-source"),
        Box::new(move || {
            capture.fetch_add(1, Ordering::SeqCst);
            1000
        }),
    );
    let side = router.add_side_packed("shared-link", |_| Ok(()));
    for name in ["cohort-alpha", "cohort-beta", "cohort-gamma"] {
        announce(&router, side, name);
    }
    (router, side, reads)
}
fn announce(router: &Router, side: usize, name: &str) {
    router
        .rx_from_side(
            &discovery::build_discovery_announce(name, 1000, &[ENDPOINT]).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues().unwrap();
}
fn peer(name: &str) -> (Router, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let output = calls.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            ENDPOINT,
            move |packet| {
                assert_eq!(packet.data_type(), TYPE);
                assert_eq!(packet.timestamp(), 123456);
                output.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )])
        .with_sender(name),
        Box::new(|| 1000),
    );
    (router, calls)
}

#[test]
fn preparation_preserves_packet_identity_and_has_no_clock_or_queue_effect() {
    let (router, _, reads) = source();
    let original = packet();
    let id = original.packet_id();
    let before = reads.load(Ordering::SeqCst);
    let queued = router.has_queued_work();
    let prepared = router
        .prepare_targeted_packet(original.clone(), &["cohort-beta", "cohort-alpha"])
        .unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), before);
    assert_eq!(router.has_queued_work(), queued);
    assert_eq!(prepared.packet().packet_id(), id);
    assert_eq!(prepared.packet().sender(), original.sender());
    assert_eq!(prepared.packet().timestamp(), original.timestamp());
    assert_eq!(prepared.packet().nonce(), original.nonce());
    assert_eq!(prepared.packet().payload(), original.payload());
    assert_eq!(prepared.packet().endpoints(), original.endpoints());
    assert_eq!(
        prepared
            .recipients()
            .iter()
            .map(|r| r.hostname())
            .collect::<Vec<_>>(),
        ["cohort-beta", "cohort-alpha"]
    );
    for recipient in prepared.recipients() {
        assert_eq!(recipient.assigned_address(), None);
        assert_eq!(recipient.birth_ms(), None);
        assert_eq!(recipient.owner_hash(), None);
    }
    assert_ne!(
        prepared.recipients()[0].wire_target_symbol(),
        prepared.recipients()[1].wire_target_symbol()
    );
    let decoded = unpack_packet(&pack_packet(prepared.packet())).unwrap();
    assert_eq!(decoded.packet_id(), id);
}

#[test]
fn refusals_retain_exact_original_and_never_fall_back_to_multicast() {
    let (router, _, _) = source();
    for (names, expected) in [
        (vec![], Kind::InvalidRecipients),
        (vec![""], Kind::InvalidRecipients),
        (vec!["@addr:17"], Kind::InvalidRecipients),
        (vec!["cohort-missing"], Kind::UnknownRecipient),
        (
            vec!["cohort-alpha", "cohort-alpha"],
            Kind::DuplicateRecipient,
        ),
        (
            vec!["cohort-alpha"; MAX_PREPARED_TARGET_RECIPIENTS + 1],
            Kind::TooManyRecipients,
        ),
    ] {
        let original = packet();
        let failure = router
            .prepare_targeted_packet(original.clone(), &names)
            .unwrap_err();
        assert_eq!(failure.reason(), expected);
        assert_eq!(failure.into_packet(), original);
    }
}

#[test]
fn identical_cohort_is_wire_idempotent_and_conflicting_cohorts_are_refused() {
    let (router, _, _) = source();
    let frozen = router
        .prepare_targeted_packet(packet(), &["cohort-alpha", "cohort-beta"])
        .unwrap()
        .into_packet();
    let before = pack_packet(&frozen);
    let same = router
        .prepare_targeted_packet(frozen.clone(), &["cohort-beta", "cohort-alpha"])
        .unwrap();
    assert_eq!(pack_packet(same.packet()), before);
    for names in [
        &["cohort-alpha"][..],
        &["cohort-alpha", "cohort-gamma"][..],
        &["cohort-alpha", "cohort-beta", "cohort-gamma"][..],
    ] {
        let failure = router
            .prepare_targeted_packet(frozen.clone(), names)
            .unwrap_err();
        assert_eq!(failure.reason(), Kind::ConflictingContract);
        assert_eq!(failure.into_packet(), frozen);
    }
}

#[test]
fn shared_endpoint_three_peers_retry_and_changed_discovery_keep_original_cohort() {
    let (router, side, _) = source();
    let frozen = router
        .prepare_targeted_packet(packet(), &["cohort-alpha"])
        .unwrap();
    let wire = pack_packet(frozen.packet());
    // A newly learned holder does not become part of the frozen packet.
    announce(&router, side, "cohort-late");
    let peers = [
        peer("cohort-alpha"),
        peer("cohort-beta"),
        peer("cohort-gamma"),
        peer("cohort-late"),
    ];
    for _ in 0..2 {
        for (receiver, _) in &peers {
            receiver.rx_packed(&wire).unwrap();
        }
    }
    assert_eq!(peers[0].1.load(Ordering::SeqCst), 1);
    for (_, count) in &peers[1..] {
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
    assert_eq!(pack_packet(frozen.packet()), wire);
}

#[test]
fn address_book_metadata_is_actual_optional_identity_not_compact_source_alias() {
    let (router, side, _) = source();
    let advertisement = discovery::AddressAdvertisement {
        hostname: "cohort-alpha".into(),
        address: 101,
        requested_address: 101,
        mode: 2,
        state: 1,
        birth_ms: 41,
        owner_hash: 43,
        reachable_endpoints: vec![ENDPOINT],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: discovery::LINK_PROFILE_CANONICAL,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    router
        .rx_from_side(
            &discovery::build_discovery_address("cohort-alpha", 1000, &advertisement).unwrap(),
            side,
        )
        .unwrap();
    router.process_all_queues().unwrap();
    let prepared = router
        .prepare_targeted_packet(packet(), &["cohort-alpha"])
        .unwrap();
    let recipient = &prepared.recipients()[0];
    assert_eq!(recipient.assigned_address(), Some(101));
    assert_eq!(recipient.birth_ms(), Some(41));
    assert_eq!(recipient.owner_hash(), Some(43));
    assert_ne!(recipient.wire_target_symbol(), 101);
}

#[test]
fn actual_relay_preserves_frozen_contract_before_three_peer_local_handlers() {
    use sedsnet::relay::Relay;
    use std::sync::Mutex;
    let (router, _, _) = source();
    let frozen = router
        .prepare_targeted_packet(packet(), &["cohort-alpha", "cohort-beta"])
        .unwrap();
    let id = frozen.packet().packet_id();
    let relay = Relay::new(Box::new(|| 1000));
    let ingress = relay.add_side_packed("producer", |_| Ok(()));
    let wires = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let capture = wires.clone();
    let egress = relay.add_side_packed("shared-endpoint", move |bytes| {
        if sedsnet::wire_format::packet_id_from_wire(bytes).is_ok_and(|candidate| candidate == id) {
            capture.lock().unwrap().push(bytes.to_vec());
        }
        Ok(())
    });
    for name in ["cohort-alpha", "cohort-beta", "cohort-gamma"] {
        relay
            .rx_from_side(
                egress,
                discovery::build_discovery_announce(name, 1000, &[ENDPOINT]).unwrap(),
            )
            .unwrap();
        relay.process_all_queues().unwrap();
    }
    let input = pack_packet(frozen.packet());
    relay.rx_packed_from_side(ingress, &input).unwrap();
    relay.process_all_queues().unwrap();
    let frames = wires.lock().unwrap();
    assert!(!frames.is_empty());
    let peers = [
        peer("cohort-alpha"),
        peer("cohort-beta"),
        peer("cohort-gamma"),
    ];
    for wire in frames.iter() {
        assert_eq!(unpack_packet(wire).unwrap().packet_id(), id);
        for (receiver, _) in &peers {
            receiver.rx_packed(wire).unwrap();
        }
    }
    assert_eq!(peers[0].1.load(Ordering::SeqCst), 1);
    assert_eq!(peers[1].1.load(Ordering::SeqCst), 1);
    assert_eq!(peers[2].1.load(Ordering::SeqCst), 0);
}
