use std::sync::Once;

use crate::config::{
    MAX_HANDLER_RETRIES, RELIABLE_MAX_END_TO_END_ACK_CACHE, RELIABLE_MAX_END_TO_END_PENDING,
    RELIABLE_MAX_RETURN_ROUTES, RuntimeMemoryConfig,
    register_data_type_id_with_description_and_e2e_encryption, register_data_type_with_description,
    register_endpoint_with_description, remove_data_type, remove_data_type_by_name,
    remove_endpoint_by_name,
};
use crate::discovery::{
    DISCOVERY_FAST_INTERVAL_MS, DISCOVERY_ROUTE_TTL_MS, DISCOVERY_SLOW_LINK_PING_INTERVAL_MS,
    LINK_CAPABILITY_CHUNKING, LINK_CAPABILITY_END_TO_END_RELIABILITY,
    LINK_CAPABILITY_HEADER_TEMPLATES, LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS,
    LINK_CAPABILITY_RELIABILITY, LINK_PROFILE_IPV4_LIKE, LinkCapabilities, TopologyBoardNode,
    build_discovery_announce, build_discovery_link_capabilities, build_discovery_timesync_sources,
    build_discovery_topology, decode_discovery_link_capabilities,
};
use crate::relay::{Relay, RelaySideOptions};
use crate::router::{
    Clock, EndpointHandler, NetworkVariablePermissions, RouterConfig, RouterE2eEncryptionMode,
    RouterSideOptions,
};
use crate::tests::count_packets_of_type;
use crate::tests::timeout_tests::StepClock;
use crate::{
    DataEndpoint, DataType, E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement,
    ReliableMode, RouteSelectionMode, TelemetryError, TelemetryResult,
};
use crate::{packet::Packet, router::Router, wire_format};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    StepClock::new_box(0, 0)
}

#[test]
fn compact_discovery_sender_reuses_hostname_learned_from_address_packet() {
    ensure_topology_test_schema();
    let emitted: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let emitted_tx = emitted.clone();
    let source = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )])
        .with_hostname("GB"),
        zero_clock(),
    );
    source.add_side_packet("wire", move |pkt: &Packet| {
        emitted_tx.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    source.announce_discovery().unwrap();
    source.process_all_queues().unwrap();

    let address = emitted
        .lock()
        .unwrap()
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .cloned()
        .expect("source did not emit an address advertisement");
    let wire_sender = format!("@addr:{}", crate::packet::sender_address_u32("GB"));
    let compact_address = Packet::new(
        address.data_type(),
        address.endpoints(),
        &wire_sender,
        address.timestamp(),
        address.payload().to_vec().into(),
    )
    .unwrap();

    let relay = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let ingress = relay.add_side_packet("ingress", |_pkt: &Packet| Ok(()));
    relay.rx_from_side(&compact_address, ingress).unwrap();
    relay.process_all_queues().unwrap();
    let resolved = relay
        .resolve_address(crate::packet::sender_address_u32("GB"))
        .expect("compact wire address should resolve through the learned hostname");
    assert_eq!(resolved.hostname.as_ref(), "GB");
    let compact_announce =
        build_discovery_announce(&wire_sender, 1, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(&compact_announce, ingress).unwrap();
    relay.process_all_queues().unwrap();

    let topology = relay.export_topology();
    let route = topology
        .routes
        .iter()
        .find(|route| route.side_id == ingress)
        .unwrap();
    assert_eq!(route.announcers.len(), 1);
    assert_eq!(route.announcers[0].sender_id, "GB");
    assert!(
        route
            .reachable_endpoints
            .contains(&DataEndpoint::named("RADIO"))
    );
}

#[test]
fn compact_topology_identifies_sender_by_embedded_board_name() {
    ensure_topology_test_schema();
    let wire_sender = format!("@addr:{}", crate::packet::sender_address_u32("RF"));
    let topology_packet = build_discovery_topology(
        &wire_sender,
        1,
        &[
            TopologyBoardNode {
                sender_id: "RF".to_owned(),
                reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                reachable_timesync_sources: Vec::new(),
                connections: vec!["PB".to_owned(), "FC".to_owned()],
            },
            TopologyBoardNode {
                sender_id: "PB".to_owned(),
                reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                reachable_timesync_sources: Vec::new(),
                connections: vec!["RF".to_owned()],
            },
        ],
    )
    .unwrap();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let ingress = router.add_side_packet("radio", |_pkt: &Packet| Ok(()));
    router.rx_from_side(&topology_packet, ingress).unwrap();
    router.process_all_queues().unwrap();

    let topology = router.export_topology();
    let route = topology
        .routes
        .iter()
        .find(|route| route.side_id == ingress)
        .unwrap();
    assert_eq!(route.announcers.len(), 1);
    assert_eq!(route.announcers[0].sender_id, "RF");
    assert!(
        route.announcers[0]
            .routers
            .iter()
            .any(|board| board.sender_id == "RF")
    );
    let remote = router
        .resolve_address(crate::packet::sender_address_u32("PB"))
        .expect("topology-only compact sender should resolve");
    assert_eq!(remote.hostname.as_ref(), "PB");
}

#[cfg(feature = "cryptography")]
fn crypto_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let guard = LOCK.lock().unwrap();
    crate::crypto::clear_c_cryptography_provider();
    crate::crypto::clear_rust_cryptography_provider();
    crate::crypto::clear_software_keys();
    guard
}

fn ensure_topology_test_schema() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let radio = DataEndpoint::try_named("RADIO").unwrap_or_else(|| {
            register_endpoint_with_description("RADIO", "test radio endpoint", false)
                .expect("register RADIO")
        });
        let sd_card = DataEndpoint::try_named("SD_CARD").unwrap_or_else(|| {
            register_endpoint_with_description("SD_CARD", "test sd endpoint", false)
                .expect("register SD_CARD")
        });
        if DataType::try_named("GPS_DATA").is_none() {
            register_data_type_with_description(
                "GPS_DATA",
                "test gps data type",
                MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                &[radio, sd_card],
                ReliableMode::None,
                1,
            )
            .expect("register GPS_DATA");
        }
    });
}

#[test]
fn discovery_link_capabilities_roundtrip() {
    let caps = LinkCapabilities {
        version: 1,
        flags: LINK_CAPABILITY_HEADER_TEMPLATES
            | LINK_CAPABILITY_CHUNKING
            | LINK_CAPABILITY_RELIABILITY
            | LINK_CAPABILITY_END_TO_END_RELIABILITY
            | LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS,
        profile: LINK_PROFILE_IPV4_LIKE,
        max_frame_bytes: 64,
        compact_header_target_bytes: 20,
        max_side_transport_templates: 8,
    };
    let pkt = build_discovery_link_capabilities("NODE_A", 42, caps).unwrap();
    assert_eq!(pkt.data_type(), DataType::DiscoveryLinkCapabilities);
    let decoded = decode_discovery_link_capabilities(&pkt).unwrap();
    assert_eq!(decoded, caps);
}

#[test]
fn router_discovery_advertises_side_link_capabilities() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    router.add_side_packet_with_options(
        "RADIO",
        move |pkt| {
            seen_cb.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            max_frame_bytes: 64,
            max_side_transport_templates: 8,
            ..RouterSideOptions::default().with_ipv4_like_compact_header_target()
        },
    );

    router.announce_discovery().unwrap();
    router.process_all_queues().unwrap();

    let packets = seen.lock().unwrap();
    let caps_pkt = packets
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .expect("missing unified address discovery packet");
    let caps = crate::discovery::decode_discovery_address(caps_pkt)
        .unwrap()
        .link_capabilities;
    assert_eq!(caps.version, 1);
    assert_eq!(caps.profile, LINK_PROFILE_IPV4_LIKE);
    assert_eq!(caps.max_frame_bytes, 64);
    assert_eq!(caps.compact_header_target_bytes, 20);
    assert_eq!(caps.max_side_transport_templates, 8);
    assert_ne!(caps.flags & LINK_CAPABILITY_HEADER_TEMPLATES, 0);
    assert_ne!(caps.flags & LINK_CAPABILITY_CHUNKING, 0);
    assert_ne!(caps.flags & LINK_CAPABILITY_RELIABILITY, 0);
    assert_ne!(caps.flags & LINK_CAPABILITY_END_TO_END_RELIABILITY, 0);
    assert_ne!(caps.flags & LINK_CAPABILITY_OMIT_UNCHANGED_TIMESTAMPS, 0);
}

fn ensure_reliable_overlap_test_schema() -> DataType {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let gs = DataEndpoint::try_named("GROUND_STATION").unwrap_or_else(|| {
            register_endpoint_with_description(
                "GROUND_STATION",
                "test ground station endpoint",
                false,
            )
            .expect("register GROUND_STATION")
        });
        let actuator = DataEndpoint::try_named("ACTUATOR_BOARD").unwrap_or_else(|| {
            register_endpoint_with_description("ACTUATOR_BOARD", "test actuator endpoint", false)
                .expect("register ACTUATOR_BOARD")
        });
        if DataType::try_named("RELIABLE_COMMAND_TEST").is_none() {
            register_data_type_with_description(
                "RELIABLE_COMMAND_TEST",
                "test reliable command type",
                MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
                &[gs, actuator],
                ReliableMode::Ordered,
                1,
            )
            .expect("register RELIABLE_COMMAND_TEST");
        }
    });

    DataType::named("RELIABLE_COMMAND_TEST")
}

fn ensure_managed_variable_test_schema() -> DataType {
    ensure_reliable_overlap_test_schema();
    let actuator = DataEndpoint::named("ACTUATOR_BOARD");
    if DataType::try_named("MANAGED_VARIABLE_TEST").is_none() {
        register_data_type_with_description(
            "MANAGED_VARIABLE_TEST",
            "non-hop-reliable managed variable used to verify end-to-end ACK routing",
            MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data),
            &[actuator],
            ReliableMode::None,
            1,
        )
        .expect("register MANAGED_VARIABLE_TEST");
    }
    DataType::named("MANAGED_VARIABLE_TEST")
}

#[derive(Clone)]
struct SharedClock {
    now_ms: Arc<AtomicU64>,
}

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

fn endpoint_by_name(name: &str) -> Option<DataEndpoint> {
    for i in 0..=crate::MAX_VALUE_DATA_ENDPOINT {
        if let Some(ep) = DataEndpoint::try_from_u32(i)
            && ep.as_str().as_ref() == name
        {
            return Some(ep);
        }
    }
    None
}

fn datatype_by_name(name: &str) -> Option<DataType> {
    for i in 0..=crate::MAX_VALUE_DATA_TYPE {
        if let Some(ty) = DataType::try_from_u32(i)
            && crate::get_message_name(ty).as_ref() == name
        {
            return Some(ty);
        }
    }
    None
}

fn pump_routers(routers: &[&Router], rounds: usize) {
    for _ in 0..rounds {
        for router in routers {
            router.process_all_queues().unwrap();
        }
    }
}

#[test]
fn discovery_master_election_prefers_central_low_hop_router() {
    let boards = vec![
        TopologyBoardNode {
            sender_id: "A_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "B_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "C_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string()],
        },
    ];
    assert_eq!(
        crate::discovery::elect_discovery_master("A_NODE", &boards),
        "B_NODE"
    );
}

#[test]
fn preferred_discovery_master_restart_request_gets_adjacent_snapshot() {
    ensure_topology_test_schema();
    let emitted: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let emitted_tx = emitted.clone();
    let gateway = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("GB")
            .with_preferred_discovery_master("GS"),
        zero_clock(),
    );
    let side = gateway.add_side_packet("pico_i2c", move |pkt: &Packet| {
        emitted_tx.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let request = crate::discovery::build_discovery_topology_request("GS", 1).unwrap();
    gateway.rx_from_side(&request, side).unwrap();
    gateway.process_all_queues().unwrap();

    assert_eq!(gateway.preferred_discovery_master().as_deref(), Some("GS"));
    assert!(
        emitted
            .lock()
            .unwrap()
            .iter()
            .any(|pkt| { pkt.data_type() == DataType::DiscoveryTopology && pkt.sender() == "GB" })
    );
}

#[test]
fn missing_preferred_discovery_master_falls_back_to_normal_election() {
    ensure_topology_test_schema();
    let emitted: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let emitted_tx = emitted.clone();
    let gateway = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("GB")
            .with_preferred_discovery_master("GS"),
        zero_clock(),
    );
    let side = gateway.add_side_packet("isolated", move |pkt: &Packet| {
        emitted_tx.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let request = crate::discovery::build_discovery_topology_request("CLIENT", 1).unwrap();
    gateway.rx_from_side(&request, side).unwrap();
    gateway.process_all_queues().unwrap();

    assert!(
        emitted
            .lock()
            .unwrap()
            .iter()
            .any(|pkt| { pkt.data_type() == DataType::DiscoveryTopology && pkt.sender() == "GB" })
    );
}

#[test]
fn topology_recovery_request_is_answered_on_ingress_without_master_identity() {
    ensure_topology_test_schema();
    let returned = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let unrelated = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let gateway = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("GB")
            .with_preferred_discovery_master("GS"),
        zero_clock(),
    );
    let out = returned.clone();
    let host = gateway.add_side_packet("pico", move |p| {
        out.lock().unwrap().push(p.clone());
        Ok(())
    });
    let out = unrelated.clone();
    let can = gateway.add_side_packet("can", move |p| {
        out.lock().unwrap().push(p.clone());
        Ok(())
    });
    let topology = build_discovery_topology(
        "VB",
        0,
        &[TopologyBoardNode {
            sender_id: "VB".into(),
            reachable_endpoints: vec![DataEndpoint::named("RADIO")],
            reachable_timesync_sources: vec![],
            connections: vec!["GS".into()],
        }],
    )
    .unwrap();
    gateway.rx_from_side(&topology, can).unwrap();
    gateway.announce_discovery().unwrap();
    gateway.process_all_queues().unwrap();
    returned.lock().unwrap().clear();
    unrelated.lock().unwrap().clear();

    // The incumbent master is known, but this recovering neighbor's identity
    // advertisement was lost. A request cannot depend on already knowing it.
    let request = crate::discovery::build_discovery_topology_request("@addr:1234567", 1).unwrap();
    gateway.rx_from_side(&request, host).unwrap();
    gateway.process_all_queues().unwrap();
    let packets = returned.lock().unwrap();
    let response = packets
        .iter()
        .find(|p| p.data_type() == DataType::DiscoveryTopology)
        .expect("adjacent router must answer recovery even when it is not master");
    let update = crate::discovery::decode_discovery_topology_update(response).unwrap();
    assert!(
        !update.incremental,
        "a restarted receiver needs the full baseline"
    );
    assert!(update.boards.iter().any(|b| b.sender_id == "VB"));
    assert!(
        !unrelated
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.data_type() == DataType::DiscoveryTopology),
        "recovery response must not flood the CAN side"
    );
}

#[test]
fn compact_sender_resolves_from_bridge_connection_only_topology() {
    let topology_packet = build_discovery_topology(
        "GB",
        1,
        &[TopologyBoardNode {
            sender_id: "GB".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["AB".to_string(), "DAQ".to_string(), "VB".to_string()],
        }],
    )
    .unwrap();

    let router = Router::new_with_clock(RouterConfig::default().with_hostname("GS"), zero_clock());
    let ingress = router.add_side_packet("pico_i2c", |_pkt: &Packet| Ok(()));
    router.rx_from_side(&topology_packet, ingress).unwrap();
    router.process_all_queues().unwrap();

    for sender in ["AB", "DAQ", "VB"] {
        let address = crate::packet::sender_address_u32(sender);
        let resolved = router
            .resolve_address(address)
            .unwrap_or_else(|| panic!("missing compact identity for {sender}"));
        assert_eq!(resolved.hostname.as_ref(), sender);
    }
}

#[test]
fn missing_topology_baseline_retries_bounded_recovery_until_full_snapshot_arrives() {
    ensure_topology_test_schema();
    let sent = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let out = sent.clone();
    let source = Router::new_with_clock(RouterConfig::default().with_sender("GB"), zero_clock());
    source.add_side_packet("pico", move |p| {
        out.lock().unwrap().push(p.clone());
        Ok(())
    });
    let can = source.add_side_packet("can", |_| Ok(()));
    source
        .rx_from_side(
            &build_discovery_topology(
                "VB",
                0,
                &[TopologyBoardNode {
                    sender_id: "VB".into(),
                    reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                    reachable_timesync_sources: vec![],
                    connections: vec!["AB".into(), "DAQ".into()],
                }],
            )
            .unwrap(),
            can,
        )
        .unwrap();
    source.announce_discovery().unwrap();
    source.process_all_queues().unwrap();
    let packets = sent.lock().unwrap();
    let address = packets
        .iter()
        .find(|p| p.data_type() == DataType::DiscoveryAddress)
        .unwrap()
        .clone();
    let full = packets
        .iter()
        .find(|p| p.data_type() == DataType::DiscoveryTopology)
        .unwrap()
        .clone();
    drop(packets);

    let now_ms = Arc::new(AtomicU64::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let relay_requests = Arc::new(AtomicUsize::new(0));
    let receiver = Router::new_with_clock(
        RouterConfig::default().with_sender("GS"),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let out = requests.clone();
    let side = receiver.add_side_packet("pico", move |p| {
        if p.data_type() == DataType::DiscoveryTopologyRequest {
            out.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    let out = relay_requests.clone();
    let relay_side = relay.add_side_packet("pico", move |p| {
        if p.data_type() == DataType::DiscoveryTopologyRequest {
            out.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    // Drop the initial full topology but deliver the aggregate address. The
    // bridge is alive; its downstream identities are not yet a valid baseline.
    receiver.rx_from_side(&address, side).unwrap();
    relay.rx_from_side(relay_side, address).unwrap();
    relay.process_all_queues().unwrap();
    receiver.poll_discovery().unwrap();
    relay.poll_discovery().unwrap();
    for expected in [1, 2] {
        now_ms.store(1_000 + (expected as u64 - 1) * 5_000, Ordering::SeqCst);
        receiver.poll_discovery().unwrap();
        relay.poll_discovery().unwrap();
        receiver.process_all_queues().unwrap();
        relay.process_all_queues().unwrap();
        assert_eq!(
            requests.load(Ordering::SeqCst),
            expected,
            "router must repair missing baseline"
        );
        assert_eq!(
            relay_requests.load(Ordering::SeqCst),
            expected,
            "relay must repair missing baseline"
        );
        for _ in 0..10 {
            receiver.poll_discovery().unwrap();
            relay.poll_discovery().unwrap();
            receiver.process_all_queues().unwrap();
            relay.process_all_queues().unwrap();
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            expected,
            "polling must not flood requests"
        );
        assert_eq!(relay_requests.load(Ordering::SeqCst), expected);
    }
    receiver.rx_from_side(&full, side).unwrap();
    relay.rx_from_side(relay_side, full).unwrap();
    relay.process_all_queues().unwrap();
    now_ms.store(11_000, Ordering::SeqCst);
    receiver.poll_discovery().unwrap();
    relay.poll_discovery().unwrap();
    receiver.process_all_queues().unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "recovery must stop after full snapshot"
    );
    assert_eq!(relay_requests.load(Ordering::SeqCst), 2);
    for board in ["VB", "AB", "DAQ"] {
        let address = crate::packet::sender_address_u32(board);
        assert_eq!(
            receiver.resolve_address(address).unwrap().hostname.as_ref(),
            board,
            "recovery must restore downstream packet attribution, not just bridge liveness"
        );
    }
}

#[test]
fn relay_answers_recovery_request_with_full_ingress_snapshot() {
    ensure_topology_test_schema();
    let returned = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let unrelated = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let relay = Relay::new(zero_clock());
    let out = returned.clone();
    let host = relay.add_side_packet("pico", move |p| {
        out.lock().unwrap().push(p.clone());
        Ok(())
    });
    let out = unrelated.clone();
    let can = relay.add_side_packet("can", move |p| {
        out.lock().unwrap().push(p.clone());
        Ok(())
    });
    relay
        .rx_from_side(
            can,
            build_discovery_topology(
                "VB",
                0,
                &[TopologyBoardNode {
                    sender_id: "VB".into(),
                    reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }],
            )
            .unwrap(),
        )
        .unwrap();
    relay.announce_discovery().unwrap();
    // Drain both the queued ingress and its normal incremental announcements
    // before observing traffic caused by the explicit recovery request.
    for _ in 0..8 {
        relay.process_all_queues().unwrap();
    }
    returned.lock().unwrap().clear();
    unrelated.lock().unwrap().clear();
    relay
        .rx_from_side(
            host,
            crate::discovery::build_discovery_topology_request("GS", 1).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();
    let packets = returned.lock().unwrap();
    let reply = packets
        .iter()
        .find(|p| p.data_type() == DataType::DiscoveryTopology)
        .unwrap();
    let update = crate::discovery::decode_discovery_topology_update(reply).unwrap();
    assert!(!update.incremental);
    assert!(update.boards.iter().any(|b| b.sender_id == "VB"));
    assert!(
        !unrelated
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.data_type() == DataType::DiscoveryTopology)
    );
}

#[test]
fn relay_discovery_keeps_downstream_nodes_behind_the_bridge() {
    ensure_topology_test_schema();
    let sent = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let out = sent.clone();
    let relay = Relay::new(zero_clock());
    relay.set_sender("GB");
    relay.add_side_packet("pico", move |p| { out.lock().unwrap().push(p.clone()); Ok(()) });
    let can = relay.add_side_packet("can", |_| Ok(()));
    relay.rx_from_side(can, build_discovery_topology("VB", 0, &[TopologyBoardNode {
        sender_id: "VB".into(), reachable_endpoints: vec![DataEndpoint::named("RADIO")],
        reachable_timesync_sources: vec![], connections: vec![],
    }]).unwrap()).unwrap();
    for _ in 0..8 { relay.process_all_queues().unwrap(); }
    let packets = sent.lock().unwrap();
    assert!(!packets.iter().any(|p| p.data_type() == DataType::DiscoveryTopology && p.sender() == "VB"),
        "forwarding a downstream advertisement makes it falsely appear directly attached");
    assert!(packets.iter().filter(|p| p.data_type() == DataType::DiscoveryTopology && p.sender() == "GB")
        .any(|p| crate::discovery::decode_discovery_topology_update(p).unwrap().boards.iter().any(|b| b.sender_id == "VB")),
        "the bridge must advertise its retained downstream topology instead");
}

#[test]
fn discovery_master_election_uses_deterministic_tiebreaks_and_fails_over() {
    let symmetric_ring = vec![
        TopologyBoardNode {
            sender_id: "A_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "B_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "C_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "D_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
        },
    ];
    assert_eq!(
        crate::discovery::elect_discovery_master("D_NODE", &symmetric_ring),
        "A_NODE"
    );

    let failed_over_ring = vec![
        TopologyBoardNode {
            sender_id: "B_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["C_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "C_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string(), "D_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "D_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["C_NODE".to_string()],
        },
    ];
    assert_eq!(
        crate::discovery::elect_discovery_master("D_NODE", &failed_over_ring),
        "C_NODE"
    );
}

#[test]
fn unknown_remote_endpoint_does_not_flood_without_discovery_route() {
    ensure_topology_test_schema();

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        42,
    )
    .unwrap();
    assert!(router.tx(pkt).is_err());

    assert!(seen_a.lock().unwrap().is_empty());
    assert!(seen_b.lock().unwrap().is_empty());
}

#[test]
fn unknown_remote_endpoint_does_not_fallback_to_single_side_after_topology_exists() {
    ensure_topology_test_schema();

    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("RADIO", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router
        .rx_from_side(
            &build_discovery_announce("REMOTE_SD", 0, &[DataEndpoint::named("SD_CARD")]).unwrap(),
            side,
        )
        .unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        42,
    )
    .unwrap();
    assert!(router.tx(pkt).is_err());

    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn discovered_endpoint_routes_reliably_back_across_a_two_sided_gateway() {
    ensure_topology_test_schema();
    let reliable_ty = ensure_reliable_overlap_test_schema();
    let gs_endpoint = DataEndpoint::named("GROUND_STATION");
    let delivered: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_c = delivered.clone();

    let gs = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            gs_endpoint,
            move |pkt| {
                delivered_c.lock().unwrap().push(pkt.clone());
                Ok(())
            },
        )])
        .with_sender("GS"),
        zero_clock(),
    ));
    // Gateway also owns this schema endpoint locally. The frozen
    // destination contract must still identify it as an intermediate
    // hop and continue toward GroundStation.
    let gateway = Arc::new(Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(gs_endpoint, |_| Ok(()))])
            .with_sender("GW"),
        zero_clock(),
    ));
    let valve = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("VB"),
        zero_clock(),
    ));

    let gs_from_gateway = Arc::new(Mutex::new(None));
    let gateway_from_gs = Arc::new(Mutex::new(None));
    let gateway_from_valve = Arc::new(Mutex::new(None));
    let valve_from_gateway = Arc::new(Mutex::new(None));
    let opts = RouterSideOptions {
        reliable_enabled: true,
        ..RouterSideOptions::default()
    };
    let best_effort_opts = RouterSideOptions {
        reliable_enabled: false,
        ..RouterSideOptions::default()
    };

    let gateway_c = gateway.clone();
    let gateway_from_gs_c = gateway_from_gs.clone();
    let gs_side = gs.add_side_packed_with_options(
        "GS_TO_GW",
        move |bytes| {
            if let Some(side) = *gateway_from_gs_c.lock().unwrap() {
                gateway_c.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );
    let gs_c = gs.clone();
    let gs_from_gateway_c = gs_from_gateway.clone();
    let gateway_uplink = gateway.add_side_packed_with_options(
        "GW_TO_GS",
        move |bytes| {
            if let Some(side) = *gs_from_gateway_c.lock().unwrap() {
                gs_c.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        best_effort_opts,
    );
    *gs_from_gateway.lock().unwrap() = Some(gs_side);
    *gateway_from_gs.lock().unwrap() = Some(gateway_uplink);

    let valve_c = valve.clone();
    let valve_from_gateway_c = valve_from_gateway.clone();
    let gateway_downlink = gateway.add_side_packed_with_options(
        "GW_TO_VB",
        move |bytes| {
            if let Some(side) = *valve_from_gateway_c.lock().unwrap() {
                valve_c.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );
    let gateway_c = gateway.clone();
    let gateway_from_valve_c = gateway_from_valve.clone();
    let valve_side = valve.add_side_packed_with_options(
        "VB_TO_GW",
        move |bytes| {
            if let Some(side) = *gateway_from_valve_c.lock().unwrap() {
                gateway_c.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );
    *valve_from_gateway.lock().unwrap() = Some(valve_side);
    *gateway_from_valve.lock().unwrap() = Some(gateway_downlink);

    gs.announce_discovery().unwrap();
    gateway.announce_discovery().unwrap();
    valve.announce_discovery().unwrap();
    pump_routers(&[gs.as_ref(), gateway.as_ref(), valve.as_ref()], 24);

    let valve_topology = valve.export_topology();
    assert!(
        valve_topology
            .routes
            .iter()
            .any(|route| { route.reachable_endpoints.contains(&gs_endpoint) }),
        "Valve must discover the GroundStation endpoint through Gateway"
    );

    valve
        .tx(Packet::from_f32_slice(reliable_ty, &[1.0], &[gs_endpoint], 10).unwrap())
        .unwrap();
    pump_routers(&[valve.as_ref(), gateway.as_ref(), gs.as_ref()], 24);
    assert_eq!(delivered.lock().unwrap().len(), 1);
}

#[test]
fn managed_variable_reaches_every_owner_behind_a_two_sided_router() {
    ensure_topology_test_schema();
    // Network variables use their frozen destination contract for end-to-end delivery;
    // they do not need to consume hop-reliable sequencing state on every transport.
    let ty = ensure_managed_variable_test_schema();
    // A network variable's schema endpoint is descriptive metadata;
    // ownership is advertised independently through discovery.  No
    // board registers this endpoint as a normal packet handler.
    let endpoint = DataEndpoint::named("SD_CARD");
    let gs = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("GS"),
        zero_clock(),
    ));
    let rf = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("RF"),
        zero_clock(),
    ));
    let power = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("PB"),
        zero_clock(),
    ));
    let flight = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("FC"),
        zero_clock(),
    ));

    let observed = |router: &Arc<Router>| {
        let values = Arc::new(Mutex::new(Vec::new()));
        let values_c = values.clone();
        router
            .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        router
            .on_network_variable_update(ty, move |packet| {
                values_c.lock().unwrap().push(packet.data_as_f32()?[0]);
                Ok(())
            })
            .unwrap();
        values
    };
    let rf_values = observed(&rf);
    let power_values = observed(&power);
    let flight_values = observed(&flight);
    gs.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    assert!(
        !rf.export_topology()
            .advertised_endpoints
            .contains(&endpoint),
        "managed-variable metadata endpoints must not become local endpoint claims",
    );

    let reliable = RouterSideOptions {
        reliable_enabled: true,
        ..RouterSideOptions::default()
    };
    let best_effort = RouterSideOptions {
        reliable_enabled: false,
        ..RouterSideOptions::default()
    };
    let gs_c = gs.clone();
    rf.add_side_packed_with_options(
        "radio",
        move |bytes| gs_c.rx_packed_from_side(bytes, 0),
        reliable,
    );
    let power_c = power.clone();
    let flight_c = flight.clone();
    rf.add_side_packed_with_options(
        "can",
        move |bytes| {
            power_c.rx_packed_from_side(bytes, 0)?;
            flight_c.rx_packed_from_side(bytes, 0)
        },
        best_effort,
    );
    let rf_c = rf.clone();
    let _gs_radio = gs.add_side_packed_with_options(
        "radio",
        move |bytes| rf_c.rx_packed_from_side(bytes, 0),
        reliable,
    );
    let rf_c = rf.clone();
    let flight_c = flight.clone();
    power.add_side_packed_with_options(
        "can",
        move |bytes| {
            rf_c.rx_packed_from_side(bytes, 1)?;
            flight_c.rx_packed_from_side(bytes, 0)
        },
        best_effort,
    );
    let rf_c = rf.clone();
    let power_c = power.clone();
    flight.add_side_packed_with_options(
        "can",
        move |bytes| {
            rf_c.rx_packed_from_side(bytes, 1)?;
            power_c.rx_packed_from_side(bytes, 0)
        },
        best_effort,
    );

    for router in [&gs, &rf, &power, &flight] {
        router.announce_discovery().unwrap();
    }
    pump_routers(
        &[gs.as_ref(), rf.as_ref(), power.as_ref(), flight.as_ref()],
        96,
    );
    // RF has now learned the two CAN-side owners; publish its
    // aggregate split-horizon snapshot back across the radio side.
    rf.announce_discovery().unwrap();
    pump_routers(
        &[gs.as_ref(), rf.as_ref(), power.as_ref(), flight.as_ref()],
        96,
    );
    // Managed-variable subscriptions advertise their type-specific ownership without a
    // conventional endpoint callback. Discovery must identify all three replicas without
    // turning the message's delivery endpoints into false local endpoint claims.
    // Queue a complete control burst before servicing any router. Real GroundStation
    // startup publishes several managed variables together; serializing each publish
    // behind its ACKs hid packet-id/return-route bugs under concurrent traffic.
    for (index, value) in [1.0_f32, 0.0, 1.0].into_iter().enumerate() {
        let packet = Packet::from_f32_slice(ty, &[value], &[endpoint], 100 + index as u64)
            .unwrap()
            .with_nonce(index as u16 + 1);
        gs.set_network_variable(packet).unwrap();
    }
    pump_routers(
        &[gs.as_ref(), rf.as_ref(), power.as_ref(), flight.as_ref()],
        256,
    );
    assert_eq!(
        gs.export_runtime_stats()
            .reliable
            .end_to_end_pending_destination_count,
        0,
        "managed-variable callbacks must ACK every targeted owner in a control burst",
    );

    let expected = vec![1.0_f32, 0.0, 1.0];
    assert_eq!(*rf_values.lock().unwrap(), expected);
    assert_eq!(*power_values.lock().unwrap(), expected);
    assert_eq!(*flight_values.lock().unwrap(), expected);
}

#[test]
fn address_summary_does_not_replace_detailed_endpoint_ownership() {
    ensure_topology_test_schema();
    let endpoint = DataEndpoint::named("SD_CARD");
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("gateway-link", |_| Ok(()));
    let summary = crate::discovery::AddressAdvertisement {
        hostname: "GB".into(),
        address: 42,
        requested_address: 0,
        mode: crate::discovery::ADDRESS_MODE_DYNAMIC,
        state: crate::discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 42,
        reachable_endpoints: vec![endpoint],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: crate::discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: crate::discovery::LINK_PROFILE_CANONICAL,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    let address = crate::discovery::build_discovery_address("GB", 2, &summary).unwrap();
    router.rx_from_side(&address, side).unwrap();

    let summarized_route = &router.export_topology().routes[0];
    assert_eq!(summarized_route.reachable_endpoints, vec![endpoint]);
    assert!(
        summarized_route.announcers[0].routers.is_empty(),
        "an aggregate address summary must select the link without inventing an owner",
    );

    let topology = build_discovery_topology(
        "GB",
        3,
        &[
            TopologyBoardNode {
                sender_id: "GB".into(),
                reachable_endpoints: vec![],
                reachable_timesync_sources: vec![],
                connections: vec!["GS".into()],
            },
            TopologyBoardNode {
                sender_id: "GS".into(),
                reachable_endpoints: vec![endpoint],
                reachable_timesync_sources: vec![],
                connections: vec!["GB".into()],
            },
        ],
    )
    .unwrap();
    router.rx_from_side(&topology, side).unwrap();

    let route = &router.export_topology().routes[0].announcers[0];
    let gateway = route
        .routers
        .iter()
        .find(|board| board.sender_id == "GB")
        .expect("gateway topology node");
    let groundstation = route
        .routers
        .iter()
        .find(|board| board.sender_id == "GS")
        .expect("groundstation topology node");
    assert!(gateway.reachable_endpoints.is_empty());
    assert_eq!(groundstation.reachable_endpoints, vec![endpoint]);
}

#[test]
fn minimal_discovery_ping_preserves_ownership_until_explicit_withdrawal() {
    ensure_topology_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("gs", |_| Ok(()));
    let relay = Relay::new(zero_clock());
    let relay_side = relay.add_side_packet("gs", |_| Ok(()));
    for endpoints in [vec![endpoint], vec![]] {
        let topology = build_discovery_topology(
            "GS",
            1,
            &[TopologyBoardNode {
                sender_id: "GS".into(),
                reachable_endpoints: endpoints.clone(),
                reachable_timesync_sources: vec![],
                connections: vec![],
            }],
        )
        .unwrap();
        router.rx_from_side(&topology, side).unwrap();
        relay.rx_from_side(relay_side, topology).unwrap();
        let ping = build_discovery_announce("GS", 2, &[]).unwrap();
        router.rx_from_side(&ping, side).unwrap();
        relay.rx_from_side(relay_side, ping).unwrap();
        relay.process_all_queues().unwrap();
        for snapshot in [router.export_topology(), relay.export_topology()] {
            let board = snapshot.routes[0].announcers[0]
                .routers
                .iter()
                .find(|board| board.sender_id == "GS")
                .unwrap();
            assert_eq!(
                board.reachable_endpoints, endpoints,
                "empty keepalive must not erase ownership; explicit topology must still withdraw it"
            );
        }
    }
}

#[test]
fn topology_requests_use_elected_master_and_late_joiners_get_fresh_topology() {
    ensure_topology_test_schema();

    let opts = RouterSideOptions {
        reliable_enabled: true,
        ..RouterSideOptions::default()
    };

    let a = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("A_NODE"),
        zero_clock(),
    ));
    let b = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("B_NODE"),
        zero_clock(),
    ));
    let c = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("C_NODE"),
        zero_clock(),
    ));

    let a_ingress_from_b: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let b_ingress_from_a: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let b_ingress_from_c: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let c_ingress_from_b: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));

    let b_for_a = b.clone();
    let b_ingress_from_a_c = b_ingress_from_a.clone();
    let _a_to_b = a.add_side_packed_with_options(
        "A_TO_B",
        move |bytes| {
            if let Some(side) = *b_ingress_from_a_c.lock().unwrap() {
                b_for_a.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );

    let a_for_b = a.clone();
    let a_ingress_from_b_c = a_ingress_from_b.clone();
    let b_to_a = b.add_side_packed_with_options(
        "B_TO_A",
        move |bytes| {
            if let Some(side) = *a_ingress_from_b_c.lock().unwrap() {
                a_for_b.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );
    *b_ingress_from_a.lock().unwrap() = Some(b_to_a);
    *a_ingress_from_b.lock().unwrap() = Some(_a_to_b);

    a.announce_discovery().unwrap();
    b.announce_discovery().unwrap();
    pump_routers(&[a.as_ref(), b.as_ref()], 6);

    let b_to_c_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let b_to_c_frames_c = b_to_c_frames.clone();
    let c_to_b_frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let c_to_b_frames_c = c_to_b_frames.clone();
    let c_for_b = c.clone();
    let c_ingress_from_b_c = c_ingress_from_b.clone();
    let _b_to_c = b.add_side_packed_with_options(
        "B_TO_C",
        move |bytes| {
            b_to_c_frames_c.lock().unwrap().push(bytes.to_vec());
            if let Some(side) = *c_ingress_from_b_c.lock().unwrap() {
                c_for_b.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );

    let b_for_c = b.clone();
    let b_ingress_from_c_c = b_ingress_from_c.clone();
    let c_to_b = c.add_side_packed_with_options(
        "C_TO_B",
        move |bytes| {
            c_to_b_frames_c.lock().unwrap().push(bytes.to_vec());
            if let Some(side) = *b_ingress_from_c_c.lock().unwrap() {
                b_for_c.rx_packed_from_side(bytes, side)?;
            }
            Ok(())
        },
        opts,
    );
    *c_ingress_from_b.lock().unwrap() = Some(c_to_b);
    *b_ingress_from_c.lock().unwrap() = Some(_b_to_c);

    assert!(
        !c.export_topology()
            .routers
            .iter()
            .any(|board| board.sender_id == "A_NODE")
    );
    b_to_c_frames.lock().unwrap().clear();
    c_to_b_frames.lock().unwrap().clear();

    c.request_topology().unwrap();
    c.request_schema().unwrap();
    pump_routers(
        &[c.as_ref(), b.as_ref(), a.as_ref(), b.as_ref(), c.as_ref()],
        8,
    );

    let c_topology = c.export_topology();
    assert!(
        c_topology
            .routers
            .iter()
            .any(|board| board.sender_id == "A_NODE")
            && c_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "B_NODE")
            && c_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "C_NODE")
    );

    let a_topology = a.export_topology();
    assert!(
        a_topology
            .routers
            .iter()
            .any(|board| board.sender_id == "C_NODE"),
        "topology reply propagation should update routers along the path too"
    );

    let request_frames = c_to_b_frames.lock().unwrap().clone();
    assert!(request_frames.iter().any(|bytes| {
        wire_format::peek_frame_info(bytes.as_slice())
            .map(|frame| {
                frame.envelope.ty == DataType::DiscoveryTopologyRequest && frame.reliable.is_some()
            })
            .unwrap_or(false)
    }));

    let frames = b_to_c_frames.lock().unwrap().clone();
    let frame_summary: Vec<(DataType, String, bool)> = frames
        .iter()
        .map(|bytes| {
            let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
            let pkt = wire_format::unpack_packet(bytes.as_slice()).unwrap();
            (
                frame.envelope.ty,
                pkt.sender().to_string(),
                frame.reliable.is_some(),
            )
        })
        .collect();
    assert!(
        frames.iter().any(|bytes| {
            let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
            frame.envelope.ty == DataType::DiscoveryTopology && frame.reliable.is_some()
        }),
        "{frame_summary:?}"
    );
    assert!(
        frames.iter().any(|bytes| {
            let frame = wire_format::peek_frame_info(bytes.as_slice()).unwrap();
            frame.envelope.ty == DataType::DiscoverySchema && frame.reliable.is_some()
        }),
        "{frame_summary:?}"
    );
}

#[cfg(feature = "timesync")]
#[test]
fn timesync_leadership_is_separate_from_discovery_master_election() {
    let boards = vec![
        TopologyBoardNode {
            sender_id: "A_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: vec!["A_NODE".to_string()],
            connections: vec!["B_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "B_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: vec!["B_NODE".to_string()],
            connections: vec!["A_NODE".to_string(), "C_NODE".to_string()],
        },
        TopologyBoardNode {
            sender_id: "C_NODE".to_string(),
            reachable_endpoints: Vec::new(),
            reachable_timesync_sources: Vec::new(),
            connections: vec!["B_NODE".to_string()],
        },
    ];
    assert_eq!(
        crate::discovery::elect_discovery_master("C_NODE", &boards),
        "B_NODE"
    );

    let mut tracker = crate::timesync::TimeSyncTracker::new(crate::timesync::TimeSyncConfig {
        role: crate::timesync::TimeSyncRole::Consumer,
        priority: 100,
        ..Default::default()
    });
    tracker
        .handle_announce(
            &crate::timesync::build_timesync_announce_with_sender("A_NODE", 1, 1_000).unwrap(),
            0,
        )
        .unwrap();
    tracker
        .handle_announce(
            &crate::timesync::build_timesync_announce_with_sender("B_NODE", 20, 1_000).unwrap(),
            0,
        )
        .unwrap();

    let leader = tracker.leader(0, false);
    assert!(matches!(
        leader,
        Some(crate::timesync::TimeSyncLeader::Remote(ref src)) if src.sender == "A_NODE"
    ));
}

fn side_stats(
    stats: &crate::diagnostics::RuntimeStatsSnapshot,
    side_id: usize,
) -> &crate::diagnostics::RuntimeSideStats {
    stats
        .sides
        .iter()
        .find(|side| side.side_id == side_id)
        .unwrap()
}

fn type_stats(
    side: &crate::diagnostics::RuntimeSideStats,
    ty: DataType,
) -> &crate::diagnostics::RuntimeTypeStats {
    side.data_types
        .iter()
        .find(|item| item.data_type == ty)
        .unwrap()
}

#[test]
fn router_uses_discovery_routes_for_outbound_packets() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(msg).unwrap();

    let got_a = seen_a.lock().unwrap().clone();
    let got_b = seen_b.lock().unwrap().clone();
    assert_eq!(
        count_packets_of_type(&got_a, DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&got_b, DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn router_prefers_direct_topology_path_over_reflected_route() {
    ensure_topology_test_schema();
    let direct_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let reflected_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let direct_seen_c = direct_seen.clone();
    let reflected_seen_c = reflected_seen.clone();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let direct = router.add_side_packet("UMBILICAL", move |packet| {
        direct_seen_c.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let reflected = router.add_side_packet("ROCKET", move |packet| {
        reflected_seen_c.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let endpoint = DataEndpoint::named("RADIO");

    for (side, announcer, boards) in [
        (
            direct,
            "GATEWAY",
            vec![
                TopologyBoardNode {
                    sender_id: "GATEWAY".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["VALVE".into()],
                },
                TopologyBoardNode {
                    sender_id: "VALVE".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GATEWAY".into()],
                },
            ],
        ),
        (
            reflected,
            "RF",
            vec![
                TopologyBoardNode {
                    sender_id: "RF".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GROUND".into()],
                },
                TopologyBoardNode {
                    sender_id: "GROUND".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into(), "GATEWAY".into()],
                },
                TopologyBoardNode {
                    sender_id: "GATEWAY".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GROUND".into(), "VALVE".into()],
                },
                TopologyBoardNode {
                    sender_id: "VALVE".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GATEWAY".into()],
                },
            ],
        ),
    ] {
        router
            .rx_from_side(
                &build_discovery_announce(announcer, 1, &[endpoint]).unwrap(),
                side,
            )
            .unwrap();
        router
            .rx_from_side(
                &build_discovery_topology(announcer, 2, &boards).unwrap(),
                side,
            )
            .unwrap();
    }
    direct_seen.lock().unwrap().clear();
    reflected_seen.lock().unwrap().clear();

    router
        .tx(Packet::new(
            DataType::named("GPS_DATA"),
            &[endpoint],
            "GROUND",
            3,
            Arc::from([0u8; 12]),
        )
        .unwrap())
        .unwrap();

    assert_eq!(
        count_packets_of_type(&direct_seen.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&reflected_seen.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn discovery_uses_split_horizon_for_reachable_endpoints() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .rx_from_side(
            &build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            side_a,
        )
        .unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    router.announce_discovery().unwrap();
    router.process_all_queues().unwrap();

    let decode_address = |packets: &Arc<Mutex<Vec<Packet>>>| {
        let guard = packets.lock().unwrap();
        let packet = guard
            .iter()
            .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
            .unwrap();
        crate::discovery::decode_discovery_address(packet).unwrap()
    };
    assert!(
        !decode_address(&seen_a)
            .reachable_endpoints
            .contains(&DataEndpoint::named("RADIO"))
    );
    assert!(
        decode_address(&seen_b)
            .reachable_endpoints
            .contains(&DataEndpoint::named("RADIO"))
    );
}

#[test]
fn discovery_advertisements_are_republished_hop_by_hop() {
    ensure_topology_test_schema();
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b_c = seen_b.clone();
    let router =
        Router::new_with_clock(RouterConfig::default().with_sender("BRIDGE"), zero_clock());
    let side_a = router.add_side_packet("A", |_packet| Ok(()));
    router.add_side_packet("B", move |packet| {
        seen_b_c.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let remote_topology = vec![TopologyBoardNode {
        sender_id: "REMOTE_A".into(),
        reachable_endpoints: vec![DataEndpoint::named("RADIO")],
        reachable_timesync_sources: vec![],
        connections: vec![],
    }];

    router
        .rx_from_side(
            &build_discovery_topology("REMOTE_A", 1, &remote_topology).unwrap(),
            side_a,
        )
        .unwrap();
    assert!(
        seen_b.lock().unwrap().iter().all(|packet| {
            packet.data_type() != DataType::DiscoveryTopology || packet.sender() != "REMOTE_A"
        }),
        "an original remote advertisement must not be reflected as adjacent"
    );

    router.announce_discovery().unwrap();
    router.process_all_queues().unwrap();
    let seen = seen_b.lock().unwrap();
    let aggregate = seen
        .iter()
        .find(|packet| packet.data_type() == DataType::DiscoveryTopology)
        .expect("bridge did not publish its aggregate topology");
    assert_eq!(aggregate.sender(), "BRIDGE");
    assert!(
        crate::discovery::decode_discovery_topology(aggregate)
            .unwrap()
            .iter()
            .any(|board| board.sender_id == "REMOTE_A")
    );
}

#[test]
fn discovered_network_variable_owner_avoids_endpoint_fanout() {
    ensure_topology_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");

    let owner_announcements: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let owner_announcements_c = owner_announcements.clone();
    let owner = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_| Ok(()))])
            .with_sender("OWNER"),
        zero_clock(),
    );
    owner.enable_managed_variable(ty).unwrap();
    owner.add_side_packet("uplink", move |pkt: &Packet| {
        owner_announcements_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    owner.announce_discovery().unwrap();
    owner.process_all_queues().unwrap();

    let non_owner_announcements: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let non_owner_announcements_c = non_owner_announcements.clone();
    let non_owner = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_| Ok(()))])
            .with_sender("NON_OWNER"),
        zero_clock(),
    );
    non_owner.add_side_packet("uplink", move |pkt: &Packet| {
        non_owner_announcements_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    non_owner.announce_discovery().unwrap();
    non_owner.process_all_queues().unwrap();

    let owner_tx: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let other_tx: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let owner_tx_c = owner_tx.clone();
    let other_tx_c = other_tx.clone();
    let source = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let owner_side = source.add_side_packet("owner", move |pkt: &Packet| {
        owner_tx_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let other_side = source.add_side_packet("other", move |pkt: &Packet| {
        other_tx_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    for packet in owner_announcements.lock().unwrap().iter() {
        source.rx_from_side(packet, owner_side).unwrap();
    }
    for packet in non_owner_announcements.lock().unwrap().iter() {
        source.rx_from_side(packet, other_side).unwrap();
    }
    owner_tx.lock().unwrap().clear();
    other_tx.lock().unwrap().clear();

    source.enable_managed_variable(ty).unwrap();
    source
        .set_network_variable(Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[ep], 1).unwrap())
        .unwrap();
    assert_eq!(count_packets_of_type(&owner_tx.lock().unwrap(), ty), 1);
    assert_eq!(count_packets_of_type(&other_tx.lock().unwrap(), ty), 0);
}

#[test]
fn queued_discovery_is_processed_before_queued_telemetry_routing() {
    ensure_topology_test_schema();

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_queue_from_side(discovery_pkt, side_a).unwrap();
    router
        .tx_queue(
            Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("RADIO")],
                1,
            )
            .unwrap(),
        )
        .unwrap();

    router.process_tx_queue().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn reliable_immediate_tx_prefers_highest_overlap_discovered_holder() {
    ensure_topology_test_schema();
    let reliable_ty = ensure_reliable_overlap_test_schema();
    let gs = DataEndpoint::named("GROUND_STATION");
    let actuator = DataEndpoint::named("ACTUATOR_BOARD");
    let radio = DataEndpoint::named("RADIO");

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .rx_from_side(
            &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
            side_a,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("BEST_HOLDER", 0, &[gs, actuator]).unwrap(),
            side_b,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("UNRELATED", 0, &[radio]).unwrap(),
            side_c,
        )
        .unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    seen_c.lock().unwrap().clear();

    let pkt = Packet::from_f32_slice(reliable_ty, &[9.0], &[gs, actuator], 1).unwrap();
    router.tx(pkt).unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), reliable_ty),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), reliable_ty),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), reliable_ty),
        0
    );
}

#[test]
fn reliable_queued_tx_prefers_highest_overlap_discovered_holder() {
    ensure_topology_test_schema();
    let reliable_ty = ensure_reliable_overlap_test_schema();
    let gs = DataEndpoint::named("GROUND_STATION");
    let actuator = DataEndpoint::named("ACTUATOR_BOARD");
    let radio = DataEndpoint::named("RADIO");

    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .rx_from_side(
            &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
            side_a,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("BEST_HOLDER", 0, &[gs, actuator]).unwrap(),
            side_b,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("UNRELATED", 0, &[radio]).unwrap(),
            side_c,
        )
        .unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    seen_c.lock().unwrap().clear();

    router
        .tx_queue(Packet::from_f32_slice(reliable_ty, &[7.0], &[gs, actuator], 2).unwrap())
        .unwrap();
    router.process_tx_queue().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), reliable_ty),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), reliable_ty),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), reliable_ty),
        0
    );
}

#[test]
fn reliable_tracking_ignores_local_endpoint_only_discovery_announcers() {
    ensure_topology_test_schema();
    let reliable_ty = ensure_reliable_overlap_test_schema();
    let gs = DataEndpoint::named("GROUND_STATION");
    let actuator = DataEndpoint::named("ACTUATOR_BOARD");

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(gs, |_pkt| Ok(()))])
            .with_sender("SRC"),
        StepClock::new_box(0, 0),
    );
    let side = router.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );

    router
        .rx_from_side(
            &build_discovery_announce("GS_ONLY", 0, &[gs]).unwrap(),
            side,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("ACTUATOR_ONLY", 0, &[actuator]).unwrap(),
            side,
        )
        .unwrap();

    let pkt = Packet::from_f32_slice(reliable_ty, &[3.0], &[gs, actuator], 10).unwrap();
    let packet_id = pkt.packet_id();
    router.tx(pkt).unwrap();

    assert_eq!(
        router.debug_end_to_end_pending_destination_count(packet_id),
        Some(1),
        "local-only endpoint announcers must not create phantom end-to-end ack expectations",
    );
}

#[test]
fn reliable_command_re_resolves_at_an_aggregated_discovery_next_hop() {
    ensure_topology_test_schema();
    let reliable_ty = ensure_reliable_overlap_test_schema();
    let gs = DataEndpoint::named("GROUND_STATION");
    let actuator = DataEndpoint::named("ACTUATOR_BOARD");

    let source_to_gateway: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let source_wire = source_to_gateway.clone();
    let delivered_wire = delivered.clone();

    let source = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(gs, |_pkt| Ok(()))])
            .with_sender("GS"),
        zero_clock(),
    );
    let gateway = Router::new_with_clock(RouterConfig::default().with_sender("GW"), zero_clock());
    let source_side = source.add_side_packed("gateway", move |bytes: &[u8]| {
        source_wire.lock().unwrap().push(bytes.to_vec());
        Ok(())
    });
    let gateway_uplink = gateway.add_side_packed("source", |_bytes: &[u8]| Ok(()));
    let gateway_child = gateway.add_side_packet("child", move |pkt: &Packet| {
        delivered_wire.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    source
        .rx_from_side(
            &build_discovery_announce("GW", 0, &[actuator]).unwrap(),
            source_side,
        )
        .unwrap();
    let child_address = crate::discovery::AddressAdvertisement {
        hostname: "AB".into(),
        address: 42,
        requested_address: 0,
        mode: crate::discovery::ADDRESS_MODE_DYNAMIC,
        state: crate::discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 42,
        reachable_endpoints: vec![actuator],
        reachable_network_variables: vec![],
        reachable_timesync_sources: vec![],
        link_capabilities: crate::discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: crate::discovery::LINK_PROFILE_CANONICAL,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    gateway
        .rx_from_side(
            &crate::discovery::build_discovery_address("AB", 0, &child_address).unwrap(),
            gateway_child,
        )
        .unwrap();
    source_to_gateway.lock().unwrap().clear();
    delivered.lock().unwrap().clear();

    source
        .tx(Packet::from_f32_slice(reliable_ty, &[1.0], &[gs, actuator], 1).unwrap())
        .unwrap();
    for frame in source_to_gateway.lock().unwrap().drain(..) {
        gateway.rx_packed_from_side(&frame, gateway_uplink).unwrap();
    }

    assert_eq!(
        count_packets_of_type(&delivered.lock().unwrap(), reliable_ty),
        1
    );
}

#[test]
fn end_to_end_expiry_clears_unordered_but_does_not_ack_ordered_data() {
    use std::sync::Arc;

    ensure_topology_test_schema();
    for mode in [crate::ReliableMode::Ordered, crate::ReliableMode::Unordered] {
        let ty = crate::config::register_data_type_with_description(
            if mode == crate::ReliableMode::Ordered {
                "ORDERED_EXPIRY"
            } else {
                "UNORDERED_EXPIRY"
            },
            "expiry reliability fixture",
            crate::MessageElement::Static(
                3,
                crate::MessageDataType::Float32,
                crate::MessageClass::Data,
            ),
            &[DataEndpoint::named("RADIO")],
            mode,
            1,
        )
        .unwrap();

        let now_ms = Arc::new(AtomicU64::new(0));
        let clock = Box::new(SharedClock {
            now_ms: now_ms.clone(),
        });
        let router = Router::new_with_clock(RouterConfig::default().with_sender("SRC"), clock);
        let side = router.add_side_packed_with_options(
            "link",
            |_bytes| Ok(()),
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        router
            .rx_from_side(
                &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
                side,
            )
            .unwrap();
        router
            .rx_from_side(
                &build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
                side,
            )
            .unwrap();

        let pkt =
            Packet::from_f32_slice(ty, &[11.0, 0.0, 0.0], &[DataEndpoint::named("RADIO")], 11)
                .unwrap();
        let packet_id = pkt.packet_id();
        router.tx(pkt).unwrap();
        assert_eq!(
            router.debug_end_to_end_pending_destination_count(packet_id),
            Some(2)
        );

        let ack = Packet::new(
            DataType::ReliableAck,
            &crate::message_meta(DataType::ReliableAck).endpoints,
            "E2EACK:DEST_A",
            0,
            Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
        )
        .unwrap();
        router.rx_from_side(&ack, side).unwrap();
        assert_eq!(
            router.debug_end_to_end_pending_destination_count(packet_id),
            Some(1)
        );

        now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
        router.periodic_no_timesync(0).unwrap();
        assert_eq!(
            router.debug_end_to_end_pending_destination_count(packet_id),
            if mode == crate::ReliableMode::Ordered {
                Some(1)
            } else {
                None
            }
        );
    }
}

#[test]
fn in_flight_end_to_end_destinations_survive_topology_reachability_changes() {
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("SRC"),
        StepClock::new_box(0, 0),
    );
    let side = router.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );

    router
        .rx_from_side(
            &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            side,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            side,
        )
        .unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[21.0, 0.0, 0.0],
        &[DataEndpoint::named("RADIO")],
        21,
    )
    .unwrap();
    let packet_id = pkt.packet_id();
    router.tx(pkt).unwrap();
    assert_eq!(
        router.debug_end_to_end_pending_destination_count(packet_id),
        Some(2)
    );

    router
        .rx_from_side(
            &build_discovery_announce("DEST_A", 1, &[DataEndpoint::named("SD_CARD")]).unwrap(),
            side,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("DEST_B", 1, &[DataEndpoint::named("SD_CARD")]).unwrap(),
            side,
        )
        .unwrap();

    assert_eq!(
        router.debug_end_to_end_pending_destination_count(packet_id),
        Some(2)
    );
}

#[test]
fn in_flight_end_to_end_destinations_survive_runtime_data_type_removal() {
    use crate::config::{register_data_type_with_description, remove_data_type_by_name};
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};

    let type_name = "DISCOVERY_INFLIGHT_TYPE_9101";
    let _ = remove_data_type_by_name(type_name);
    let custom_ty = register_data_type_with_description(
        type_name,
        "inflight custom type",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[DataEndpoint::named("RADIO")],
        ReliableMode::None,
        3,
    )
    .unwrap();

    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("SRC"),
        StepClock::new_box(0, 0),
    );
    let side = router.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        },
    );

    router
        .rx_from_side(
            &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            side,
        )
        .unwrap();

    let pkt = Packet::new(
        custom_ty,
        &[DataEndpoint::named("RADIO")],
        "SRC",
        0,
        Arc::<[u8]>::from(vec![1u8, 2, 3, 4]),
    )
    .unwrap();
    let packet_id = pkt.packet_id();
    router.tx(pkt).unwrap();
    assert_eq!(
        router.debug_end_to_end_pending_destination_count(packet_id),
        Some(1)
    );

    assert!(remove_data_type_by_name(type_name).unwrap());
    router.periodic_no_timesync(0).unwrap();
    assert_eq!(
        router.debug_end_to_end_pending_destination_count(packet_id),
        Some(1)
    );
}

#[test]
fn explicit_target_contract_skips_wrong_local_router_delivery() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            move |_pkt| {
                hits_c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )])
        .with_sender("LOCAL"),
        StepClock::new_box(0, 0),
    );
    let side = router.add_side_packet("LINK", |_pkt: &Packet| Ok(()));

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[41.0, 0.0, 0.0],
        &[DataEndpoint::named("RADIO")],
        41,
    )
    .unwrap();
    let wire = wire_format::pack_packet_with_wire_contract(
        &pkt,
        Some(wire_format::ReliableHeader {
            flags: wire_format::RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        }),
        Some(crate::message_meta(pkt.data_type()).element),
        &[crate::packet::hash_bytes_u64(
            0x517C_C1B7_2722_0A95,
            "OTHER_DEST".as_bytes(),
        )],
    )
    .unwrap();
    router.rx_packed_from_side(&wire, side).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn reliable_router_state_stays_bounded_under_unacked_traffic() {
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("SRC"),
        StepClock::new_box(0, 0),
    );
    let side = router.add_side_packed_with_options(
        "link",
        |_bytes| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    router
        .rx_from_side(
            &build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            side,
        )
        .unwrap();

    for idx in 0..(RELIABLE_MAX_END_TO_END_PENDING.max(1) + 4) {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[idx as f32, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            idx as u64,
        )
        .unwrap();
        let _ = router.tx(pkt);
    }

    assert!(router.debug_end_to_end_tracked_count() <= RELIABLE_MAX_END_TO_END_PENDING.max(1));

    for idx in 0..(RELIABLE_MAX_RETURN_ROUTES.max(1) + 4) {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[idx as f32, 1.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            (1000 + idx) as u64,
        )
        .unwrap();
        router.rx_from_side(&pkt, side).unwrap();
    }

    assert!(router.debug_reliable_return_route_count() <= RELIABLE_MAX_RETURN_ROUTES.max(1));
}

#[test]
fn discovery_topology_counts_against_shared_queue_budget() {
    ensure_topology_test_schema();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packed("link", |_bytes| Ok(()));

    for idx in 0..128 {
        let boards = vec![TopologyBoardNode {
            sender_id: format!("REMOTE_BOARD_{idx}_{}", "x".repeat(512)),
            reachable_endpoints: vec![DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
            reachable_timesync_sources: vec![format!("TIME_{idx}_{}", "y".repeat(256))],
            connections: vec![format!("CONN_{idx}_{}", "z".repeat(512))],
        }];
        let sender = format!("SRC_{idx}");
        let pkt = build_discovery_topology(&sender, idx as u64, &boards).unwrap();
        router.rx_from_side(&pkt, side).unwrap();
    }

    assert!(
        router.debug_shared_queue_bytes_used() <= crate::config::MAX_QUEUE_BUDGET,
        "discovery topology state must be part of the shared queue budget"
    );
}

#[test]
fn multi_node_memory_exhaustion_keeps_runtime_pools_bounded() {
    ensure_topology_test_schema();
    let budget = 24 * 1024usize;
    let memory = RuntimeMemoryConfig::new(budget, 16, 512, 1.5).unwrap();
    let ep = DataEndpoint::named("RADIO");
    let mut nodes = Vec::new();
    let mut max_discovery_seen = Vec::new();

    for idx in 0..6usize {
        let cfg = RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_hostname(format!("MEM_NODE_{idx}"))
            .with_memory_config(memory)
            .unwrap();
        let router = Router::new_with_clock(cfg, zero_clock());
        let side = router.add_side_packed("mesh", |_bytes| Ok(()));
        nodes.push((format!("node-{idx}"), router, side));
        max_discovery_seen.push(0u64);
    }

    fn assert_pool(label: &str, router: &Router, budget: usize, queued_inputs: u64) {
        let json: serde_json::Value =
            serde_json::from_str(&router.export_memory_layout_json()).unwrap();
        let used = json["shared_queue_bytes_used"].as_u64().unwrap();
        let allocated = json["shared_queue_bytes_allocated"].as_u64().unwrap();
        assert_eq!(
            allocated, budget as u64,
            "{label}: runtime memory pool changed unexpectedly"
        );
        assert!(
            used <= allocated,
            "{label}: shared queue budget exceeded: used={used} allocated={allocated} layout={json}"
        );
        assert!(
            json["discovery_bytes_used"].as_u64().unwrap() <= allocated,
            "{label}: discovery state exceeded pool: layout={json}"
        );
        assert!(
            json["rx_queue_bytes_used"].as_u64().unwrap()
                + json["tx_queue_bytes_used"].as_u64().unwrap()
                <= allocated,
            "{label}: queued packet state exceeded pool: layout={json}"
        );

        if queued_inputs > 128 {
            let retained =
                json["rx_queue_len"].as_u64().unwrap() + json["tx_queue_len"].as_u64().unwrap();
            assert!(
                retained < queued_inputs,
                "{label}: low memory pool did not evict queued work: retained={retained} inputs={queued_inputs} layout={json}"
            );
        }
    }

    fn discovery_bytes(router: &Router) -> u64 {
        let json: serde_json::Value =
            serde_json::from_str(&router.export_memory_layout_json()).unwrap();
        json["discovery_bytes_used"].as_u64().unwrap()
    }

    let mut queued_inputs = 0u64;
    for round in 0..180u64 {
        let topology = (0..4)
            .map(|slot| TopologyBoardNode {
                sender_id: format!(
                    "REMOTE_{round}_{slot}_{}",
                    "n".repeat(48 + (slot * 8) as usize)
                ),
                reachable_endpoints: vec![DataEndpoint::named("RADIO")],
                reachable_timesync_sources: vec![format!("TIME_{round}_{slot}_{}", "t".repeat(32))],
                connections: vec![format!("LINK_{round}_{slot}_{}", "c".repeat(64))],
            })
            .collect::<Vec<_>>();
        let topology_pkt =
            build_discovery_topology(&format!("DISCOVERY_SRC_{round}"), round, &topology).unwrap();

        for (idx, (label, router, side)) in nodes.iter().enumerate() {
            router.rx_from_side(&topology_pkt, *side).unwrap();
            max_discovery_seen[idx] = max_discovery_seen[idx].max(discovery_bytes(router));
            let queued = router.log_queue_ts(
                DataType::named("GPS_DATA"),
                round * 10 + idx as u64,
                &[round as f32, idx as f32, (round + idx as u64) as f32],
            );
            assert!(
                queued.is_ok(),
                "{label}: telemetry admission failed at round {round}: {queued:?}; layout={}",
                router.export_memory_layout_json()
            );
            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[idx as f32, round as f32, 42.0],
                &[DataEndpoint::named("RADIO")],
                10_000 + round * 10 + idx as u64,
            )
            .unwrap();
            router.rx_queue(pkt).unwrap();
            queued_inputs += 2;

            if round % 15 == 0 {
                assert_pool(label, router, budget, queued_inputs);
            }
        }
    }

    for (idx, (label, router, _side)) in nodes.iter().enumerate() {
        assert_pool(label, router, budget, queued_inputs);
        assert!(
            max_discovery_seen[idx] > 0,
            "{label}: pressure test did not add any discovered node state"
        );
    }
}

#[test]
fn queued_packed_discovery_learns_routes_for_locally_handled_endpoints() {
    ensure_topology_test_schema();
    let seen_remote: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_remote_c = seen_remote.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side_remote =
        router.add_side_packet("REMOTE", move |pkt: &Packet| -> TelemetryResult<()> {
            seen_remote_c.lock().unwrap().push(pkt.clone());
            Ok(())
        });

    let discovery_pkt =
        build_discovery_announce("REMOTE_NODE", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_bytes = wire_format::pack_packet(&discovery_pkt);
    router
        .rx_packed_queue_from_side(discovery_bytes.as_ref(), side_remote)
        .unwrap();
    router.process_rx_queue().unwrap();

    let topo = router.export_topology();
    assert_eq!(topo.routes.len(), 1);
    assert_eq!(
        topo.routes[0].reachable_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );
    assert_eq!(
        topo.advertised_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        11,
    )
    .unwrap();
    router.tx(msg).unwrap();

    let got = seen_remote.lock().unwrap().clone();
    assert_eq!(count_packets_of_type(&got, DataType::named("GPS_DATA")), 0);
}

#[test]
fn queued_packet_discovery_updates_route_table_after_full_queue_drain() {
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side_fill =
        router.add_side_packet("FILL", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_pkt = build_discovery_announce(
        "AB",
        0,
        &[DataEndpoint::named("RADIO"), DataEndpoint::TimeSync],
    )
    .unwrap();
    router.rx_queue_from_side(discovery_pkt, side_fill).unwrap();
    router.process_all_queues_with_timeout(0).unwrap();

    let topo = router.export_topology();
    assert_eq!(topo.routes.len(), 1);
    assert_eq!(topo.routes[0].side_name, "FILL");
    assert_eq!(
        topo.routes[0].reachable_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );
    assert!(
        topo.advertised_endpoints
            .contains(&DataEndpoint::named("SD_CARD")),
        "local endpoints should remain advertised"
    );
    assert!(
        topo.advertised_endpoints
            .contains(&DataEndpoint::named("RADIO")),
        "learned remote endpoints should be reflected in advertised discovery state"
    );
}

#[test]
fn queued_packed_discovery_timesync_sources_update_route_table_after_full_queue_drain() {
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side_fill =
        router.add_side_packet("FILL", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let announce = build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let announce_bytes = wire_format::pack_packet(&announce);
    router
        .rx_packed_queue_from_side(announce_bytes.as_ref(), side_fill)
        .unwrap();

    let sources = build_discovery_timesync_sources("AB", 0, &["AB", "AB_BACKUP"]).unwrap();
    let source_bytes = wire_format::pack_packet(&sources);
    router
        .rx_packed_queue_from_side(source_bytes.as_ref(), side_fill)
        .unwrap();

    router.process_all_queues_with_timeout(0).unwrap();

    let topo = router.export_topology();
    assert_eq!(topo.routes.len(), 1);
    assert_eq!(topo.routes[0].side_name, "FILL");
    assert_eq!(
        topo.routes[0].reachable_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );
    assert_eq!(
        topo.routes[0].reachable_timesync_sources,
        vec!["AB".to_string(), "AB_BACKUP".to_string()]
    );
    assert!(
        topo.advertised_timesync_sources.contains(&"AB".to_string()),
        "learned timesync sources should be exported in topology"
    );
}

#[test]
fn queued_packed_discovery_from_same_sender_is_ignored_and_local_endpoint_does_not_flood() {
    use crate::config::DEVICE_IDENTIFIER;

    let seen_remote: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_remote_c = seen_remote.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side_remote =
        router.add_side_packet("REMOTE", move |pkt: &Packet| -> TelemetryResult<()> {
            seen_remote_c.lock().unwrap().push(pkt.clone());
            Ok(())
        });

    let discovery_pkt =
        build_discovery_announce(DEVICE_IDENTIFIER, 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_bytes = wire_format::pack_packet(&discovery_pkt);
    router
        .rx_packed_queue_from_side(discovery_bytes.as_ref(), side_remote)
        .unwrap();
    router.process_rx_queue().unwrap();

    let topo = router.export_topology();
    assert!(topo.routes.is_empty());
    assert_eq!(
        topo.advertised_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        12,
    )
    .unwrap();
    router.tx(msg).unwrap();

    assert!(seen_remote.lock().unwrap().is_empty());
}

#[test]
fn relay_uses_discovery_routes_for_selective_fanout() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let _side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_pkt =
        build_discovery_announce("NODE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_pkt).unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[9.0, 8.0, 7.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(side_c, msg).unwrap();
    relay.process_all_queues().unwrap();

    let got_a = seen_a.lock().unwrap().clone();
    let got_b = seen_b.lock().unwrap().clone();
    assert_eq!(
        count_packets_of_type(&got_a, DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&got_b, DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn relay_advertises_only_remote_routes_on_each_side() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet_with_options(
        "A",
        move |pkt: &Packet| {
            seen_a_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: false,
            ..RelaySideOptions::default()
        },
    );
    let side_b = relay.add_side_packet_with_options(
        "B",
        move |pkt: &Packet| {
            seen_b_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: false,
            ..RelaySideOptions::default()
        },
    );

    relay
        .rx_from_side(
            side_a,
            build_discovery_announce("NODE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay
        .rx_from_side(
            side_b,
            build_discovery_announce("NODE_B", 0, &[DataEndpoint::named("SD_CARD")]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay.announce_discovery().unwrap();
    relay.process_all_queues().unwrap();
    let endpoints_on = |packets: &Vec<Packet>| {
        packets
            .iter()
            .find(|pkt| pkt.data_type() == DataType::DiscoveryAnnounce)
            .map(|pkt| crate::discovery::decode_discovery_announce(pkt).unwrap())
            .expect("relay did not advertise an endpoint summary")
    };
    let to_a = endpoints_on(&seen_a.lock().unwrap());
    let to_b = endpoints_on(&seen_b.lock().unwrap());
    assert_eq!(to_a, vec![DataEndpoint::named("SD_CARD")]);
    assert_eq!(to_b, vec![DataEndpoint::named("RADIO")]);
}

#[test]
fn relay_runtime_routes_support_asymmetric_and_ingress_only_links() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    relay.set_route(Some(side_a), side_b, true).unwrap();
    relay.set_route(Some(side_b), side_a, false).unwrap();
    relay.set_side_egress_enabled(side_c, false).unwrap();

    let pkt_a = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    relay.rx_from_side(side_a, pkt_a).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    let pkt_b = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(side_b, pkt_b).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    let pkt_c = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[7.0, 8.0, 9.0],
        &[DataEndpoint::named("RADIO")],
        3,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt_c).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn relay_can_disable_ingress_for_a_side() {
    let relay = Relay::new(zero_clock());
    let side = relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
    relay.set_side_ingress_enabled(side, false).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        4,
    )
    .unwrap();

    match relay.rx_from_side(side, pkt) {
        Err(TelemetryError::HandlerError(msg)) => {
            assert!(msg.contains("ingress disabled"));
        }
        other => panic!("expected ingress-disabled error, got {other:?}"),
    }
}

#[test]
fn relay_typed_routes_can_target_one_or_many_sides() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_d: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();
    let seen_d_c = seen_d.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let _side_c = relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_d = relay.add_side_packet("D", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_d_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    relay
        .rx_from_side(
            side_b,
            build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay
        .rx_from_side(
            side_d,
            build_discovery_announce("REMOTE_D", 1, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    seen_c.lock().unwrap().clear();
    seen_d.lock().unwrap().clear();

    relay
        .set_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_b, true)
        .unwrap();
    relay
        .set_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_d, true)
        .unwrap();
    relay
        .set_source_route_mode(Some(side_a), RouteSelectionMode::Fanout)
        .unwrap();

    let gps_pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    relay.rx_from_side(side_a, gps_pkt).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    let first_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    let first_c = count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
    let first_d = count_packets_of_type(&seen_d.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(first_c, 0);
    let first_targets = first_b + first_d;
    assert!((1..=2).contains(&first_targets));

    relay
        .clear_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_b)
        .unwrap();
    relay
        .clear_typed_route(Some(side_a), DataType::named("GPS_DATA"), side_d)
        .unwrap();

    let fallback_pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[9.0, 8.0, 7.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(side_a, fallback_pkt).unwrap();
    relay.process_all_queues().unwrap();

    let total_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    let total_c = count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
    let total_d = count_packets_of_type(&seen_d.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(total_c, 0);
    let total_targets = total_b + total_d;
    assert!(total_targets >= first_targets);
    assert!(total_targets <= first_targets + 2);
}

#[test]
fn relay_remove_side_stops_transmit_and_rejects_removed_ingress() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    relay.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    relay.remove_side(side_a).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        5,
    )
    .unwrap();
    relay.rx_from_side(side_b, pkt.clone()).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    match relay.rx_from_side(side_a, pkt) {
        Err(TelemetryError::HandlerError(msg)) => {
            assert!(msg.contains("invalid side id"));
        }
        other => panic!("expected invalid removed side error, got {other:?}"),
    }
}

#[test]
fn relay_remove_side_updates_discovery_routes_and_announces_remaining_topology() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
    relay.rx_from_side(side_b, discovery_pkt).unwrap();
    relay.process_rx_queue().unwrap();
    assert_eq!(relay.export_topology().routes.len(), 1);

    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    relay.remove_side(side_a).unwrap();

    let snap = relay.export_topology();
    assert_eq!(snap.routes.len(), 1);
    assert_eq!(
        snap.advertised_endpoints,
        vec![DataEndpoint::named("SD_CARD")]
    );
    assert!(relay.poll_discovery().unwrap());
    relay.process_all_queues().unwrap();

    assert!(seen_a.lock().unwrap().is_empty());
    let b_pkts = seen_b.lock().unwrap().clone();
    let announce = b_pkts
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAnnounce)
        .unwrap();
    let eps = crate::discovery::decode_discovery_announce(announce).unwrap();
    assert!(
        eps.is_empty(),
        "a relay must not reflect a route learned from the only remaining side back to it"
    );
    assert!(
        b_pkts
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
    );
}

#[test]
fn router_exports_topology_and_adaptive_discovery_schedule() {
    ensure_topology_test_schema();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        StepClock::new_box(0, 0),
    );
    let side_a = router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_pkt =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();

    let snap_before = router.export_topology();
    assert_eq!(
        snap_before.advertised_endpoints,
        vec![DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")]
    );
    assert_eq!(snap_before.routes.len(), 1);
    assert_eq!(snap_before.routes[0].side_name, "A");
    assert_eq!(
        snap_before.current_announce_interval_ms,
        DISCOVERY_FAST_INTERVAL_MS
    );

    assert!(router.poll_discovery().unwrap());

    let snap_after = router.export_topology();
    assert_eq!(snap_after.next_announce_ms, DISCOVERY_FAST_INTERVAL_MS);
    assert!(snap_after.current_announce_interval_ms >= DISCOVERY_FAST_INTERVAL_MS);
}

#[test]
fn router_does_not_stack_periodic_discovery_behind_an_unacked_snapshot() {
    ensure_topology_test_schema();
    let now_ms = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let sent_cb = sent.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    router.add_side_packed_with_options(
        "radio",
        move |bytes| {
            sent_cb.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    assert!(router.poll_discovery().unwrap());
    router.process_all_queues().unwrap();
    let first_count = sent.lock().unwrap().len();
    assert!(first_count > 0);

    now_ms.store(DISCOVERY_FAST_INTERVAL_MS, Ordering::SeqCst);
    assert!(!router.poll_discovery().unwrap());
}

#[test]
fn router_unacked_discovery_blocks_only_the_affected_side() {
    ensure_topology_test_schema();
    let now_ms = Arc::new(AtomicU64::new(0));
    let reliable_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let best_effort_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let reliable_seen_c = reliable_seen.clone();
    let best_effort_seen_c = best_effort_seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    router.add_side_packed_with_options(
        "reliable_radio",
        move |bytes| {
            reliable_seen_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    router.add_side_packed_with_options(
        "best_effort_umbilical",
        move |bytes| {
            best_effort_seen_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default(),
    );

    assert!(router.poll_discovery().unwrap());
    router.process_all_queues().unwrap();
    let reliable_first = reliable_seen.lock().unwrap().len();
    let best_effort_first = best_effort_seen.lock().unwrap().len();
    assert!(reliable_first > 0);
    assert!(best_effort_first > 0);

    now_ms.store(DISCOVERY_FAST_INTERVAL_MS, Ordering::SeqCst);
    assert!(router.poll_discovery().unwrap());
    // Drain only the newly queued snapshot; do not turn this routing
    // assertion into a reliable-retransmit timing test.
    now_ms.store(0, Ordering::SeqCst);
    router.process_tx_queue().unwrap();
    assert_eq!(reliable_seen.lock().unwrap().len(), reliable_first);
    assert!(best_effort_seen.lock().unwrap().len() > best_effort_first);
}

#[test]
fn relay_does_not_stack_periodic_discovery_behind_an_unacked_snapshot() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let sent_cb = sent.clone();
    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    relay.add_side_packed_with_options(
        "radio",
        move |bytes| {
            sent_cb.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            ..RelaySideOptions::default()
        },
    );

    assert!(relay.poll_discovery().unwrap());
    relay.process_all_queues().unwrap();
    let first_count = sent.lock().unwrap().len();
    assert!(first_count > 0);

    now_ms.store(DISCOVERY_FAST_INTERVAL_MS, Ordering::SeqCst);
    assert!(!relay.poll_discovery().unwrap());
}

#[test]
fn relay_unacked_discovery_blocks_only_the_affected_side() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let reliable_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let best_effort_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let reliable_seen_c = reliable_seen.clone();
    let best_effort_seen_c = best_effort_seen.clone();
    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    relay.add_side_packed_with_options(
        "reliable_radio",
        move |bytes| {
            reliable_seen_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RelaySideOptions {
            reliable_enabled: true,
            ..RelaySideOptions::default()
        },
    );
    relay.add_side_packed_with_options(
        "best_effort_umbilical",
        move |bytes| {
            best_effort_seen_c.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RelaySideOptions::default(),
    );

    assert!(relay.poll_discovery().unwrap());
    relay.process_all_queues().unwrap();
    let reliable_first = reliable_seen.lock().unwrap().len();
    let best_effort_first = best_effort_seen.lock().unwrap().len();
    assert!(reliable_first > 0);
    assert!(best_effort_first > 0);

    now_ms.store(DISCOVERY_FAST_INTERVAL_MS, Ordering::SeqCst);
    assert!(relay.poll_discovery().unwrap());
    now_ms.store(0, Ordering::SeqCst);
    relay.process_tx_queue().unwrap();
    assert_eq!(reliable_seen.lock().unwrap().len(), reliable_first);
    assert!(best_effort_seen.lock().unwrap().len() > best_effort_first);
}

#[test]
fn router_exports_board_graph_and_tracks_transitive_endpoint_holders() {
    ensure_topology_test_schema();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let topology = vec![
        TopologyBoardNode {
            sender_id: "REMOTE_A".to_string(),
            reachable_endpoints: vec![
                DataEndpoint::named("SD_CARD"),
                DataEndpoint::TimeSync,
                DataEndpoint::TelemetryError,
            ],
            reachable_timesync_sources: Vec::new(),
            connections: vec!["SENSOR_B".to_string()],
        },
        TopologyBoardNode {
            sender_id: "SENSOR_B".to_string(),
            reachable_endpoints: vec![DataEndpoint::named("RADIO")],
            reachable_timesync_sources: Vec::new(),
            connections: vec!["REMOTE_A".to_string()],
        },
    ];
    let topology_pkt = build_discovery_topology("REMOTE_A", 0, &topology).unwrap();
    router.rx_from_side(&topology_pkt, side_a).unwrap();

    let snap = router.export_topology();
    assert_eq!(snap.routes.len(), 1);
    assert_eq!(snap.routes[0].announcers.len(), 1);
    assert_eq!(snap.routes[0].announcers[0].sender_id, "REMOTE_A");
    assert!(
        snap.routes[0].announcers[0]
            .routers
            .iter()
            .any(|board| board.sender_id == "SENSOR_B"
                && board.reachable_endpoints == vec![DataEndpoint::named("RADIO")])
    );
    assert!(
        snap.routers
            .iter()
            .any(|board| board.sender_id == "SENSOR_B"
                && board.connections.contains(&"REMOTE_A".to_string()))
    );
    assert!(
        snap.links
            .iter()
            .any(|link| link.source == "REMOTE_A" && link.target == "SENSOR_B")
    );

    assert!(
        snap.advertised_endpoints
            .contains(&DataEndpoint::named("RADIO")),
        "transitive endpoint holders should contribute to exported reachability"
    );
    assert!(!snap.advertised_endpoints.contains(&DataEndpoint::TimeSync));
    assert!(
        !snap
            .advertised_endpoints
            .contains(&DataEndpoint::TelemetryError)
    );
}

#[test]
fn discovery_leave_prunes_client_topology_and_stats_immediately() {
    ensure_topology_test_schema();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_pkt =
        build_discovery_announce("LEAVING_NODE", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();
    let stats = router.client_stats("LEAVING_NODE").unwrap();
    assert!(stats.connected);
    assert_eq!(stats.side_names, vec!["A"]);
    assert_eq!(
        stats.reachable_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );

    let leave = crate::discovery::build_discovery_leave("LEAVING_NODE", 1).unwrap();
    router.rx_from_side(&leave, side_a).unwrap();

    assert!(router.client_stats("LEAVING_NODE").is_none());
    assert!(
        !router
            .export_topology()
            .routers
            .iter()
            .any(|board| board.sender_id == "LEAVING_NODE")
    );
}

#[test]
fn router_remove_side_stops_transmit_and_rejects_removed_ingress() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.remove_side(side_a).unwrap();

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(msg.clone()).unwrap();

    assert!(seen_a.lock().unwrap().is_empty());
    assert_eq!(seen_b.lock().unwrap().len(), 1);
    match router.rx_from_side(&msg, side_a) {
        Err(TelemetryError::HandlerError(msg)) => {
            assert!(msg.contains("invalid side id"));
        }
        other => panic!("expected invalid removed side error, got {other:?}"),
    }
}

#[test]
fn router_remove_side_updates_discovery_routes_and_announces_remaining_topology() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("SD_CARD")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();
    assert_eq!(router.export_topology().routes.len(), 1);

    // Publish the addition first so the remaining side has a precise
    // baseline from which to emit a removal delta.
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();

    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    router.remove_side(side_a).unwrap();

    let snap = router.export_topology();
    assert!(snap.routes.is_empty());
    assert_eq!(
        snap.advertised_endpoints,
        vec![DataEndpoint::named("RADIO")]
    );
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();

    assert!(seen_a.lock().unwrap().is_empty());
    let b_pkts = seen_b.lock().unwrap().clone();
    let announce = b_pkts
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .unwrap();
    let eps = crate::discovery::decode_discovery_address(announce)
        .unwrap()
        .reachable_endpoints;
    assert_eq!(eps, vec![DataEndpoint::named("RADIO")]);
    let update = b_pkts
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
        .map(crate::discovery::decode_discovery_topology_update)
        .transpose()
        .unwrap()
        .expect("removal must emit an incremental topology update");
    assert!(update.incremental);
    assert!(update.removed.iter().any(|sender| sender == "REMOTE_A"));
}

#[test]
fn router_can_suppress_detailed_topology_on_a_constrained_side() {
    ensure_topology_test_schema();
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    let side = router.add_side_packet("constrained", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router
        .set_typed_route(None, DataType::DiscoveryTopology, side, false)
        .unwrap();

    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();

    let packets = seen.lock().unwrap();
    assert!(
        packets
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
    );
    assert!(
        !packets
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
    );
}

#[test]
fn router_runtime_routes_support_asymmetric_and_ingress_only_links() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.set_route(None, side_b, false).unwrap();
    router.set_route(None, side_c, false).unwrap();
    router.set_route(Some(side_a), side_b, true).unwrap();
    router.set_route(Some(side_b), side_a, false).unwrap();
    router.set_side_egress_enabled(side_c, false).unwrap();

    let local_tx = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(local_tx).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    let from_a = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    router.rx_from_side(&from_a, side_a).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    let from_b = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[7.0, 8.0, 9.0],
        &[DataEndpoint::named("RADIO")],
        3,
    )
    .unwrap();
    router.rx_from_side(&from_b, side_b).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );

    let from_c = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[10.0, 11.0, 12.0],
        &[DataEndpoint::named("RADIO")],
        4,
    )
    .unwrap();
    router.rx_from_side(&from_c, side_c).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
}

#[test]
fn router_typed_routes_can_target_one_or_many_sides() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let seen_c_c = seen_c.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = router.add_side_packet("C", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_b =
        build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_c =
        build_discovery_announce("REMOTE_C", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    router.rx_from_side(&discovery_c, side_c).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    seen_c.lock().unwrap().clear();

    router
        .set_typed_route(None, DataType::named("GPS_DATA"), side_b, true)
        .unwrap();
    router
        .set_typed_route(None, DataType::named("GPS_DATA"), side_c, true)
        .unwrap();
    router
        .set_source_route_mode(None, RouteSelectionMode::Fanout)
        .unwrap();

    let gps_pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(gps_pkt).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    let first_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    let first_c = count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(first_b + first_c, 2);

    router
        .clear_typed_route(None, DataType::named("GPS_DATA"), side_b)
        .unwrap();
    router
        .clear_typed_route(None, DataType::named("GPS_DATA"), side_c)
        .unwrap();

    let fallback_pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[7.0, 8.0, 9.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    router.tx(fallback_pkt).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );
    let total_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    let total_c = count_packets_of_type(&seen_c.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(
        total_b + total_c,
        4,
        "an explicit fanout policy remains active after typed routes are cleared"
    );

    let _ = side_a;
}

#[test]
fn network_variables_reach_all_discovered_owner_segments() {
    ensure_topology_test_schema();
    let ty = DataType::named("GPS_DATA");
    let endpoint = DataEndpoint::named("RADIO");
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_cb = seen_a.clone();
    let seen_b_cb = seen_b.clone();
    let owner_announcements = |sender: &'static str| {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_cb = captured.clone();
        let owner = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(endpoint, |_| {
                Ok(())
            })])
            .with_sender(sender),
            zero_clock(),
        );
        owner.enable_managed_variable(ty).unwrap();
        owner.add_side_packet("uplink", move |packet| {
            captured_cb.lock().unwrap().push(packet.clone());
            Ok(())
        });
        owner.announce_discovery().unwrap();
        owner.process_all_queues().unwrap();
        captured.lock().unwrap().clone()
    };
    let router = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    let side_a = router.add_side_packet("rocket", move |packet| {
        seen_a_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("fill", move |packet| {
        seen_b_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    for packet in owner_announcements("RF") {
        router.rx_from_side(&packet, side_a).unwrap();
    }
    for packet in owner_announcements("GATEWAY") {
        router.rx_from_side(&packet, side_b).unwrap();
    }
    router
        .rx_from_side(
            &build_discovery_topology(
                "RF",
                1,
                &[TopologyBoardNode {
                    sender_id: "RF".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec![],
                }],
            )
            .unwrap(),
            side_a,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_topology(
                "GATEWAY",
                1,
                &[
                    TopologyBoardNode {
                        sender_id: "GATEWAY".into(),
                        reachable_endpoints: vec![],
                        reachable_timesync_sources: vec![],
                        connections: vec!["FILL_OWNER".into()],
                    },
                    TopologyBoardNode {
                        sender_id: "FILL_OWNER".into(),
                        reachable_endpoints: vec![endpoint],
                        reachable_timesync_sources: vec![],
                        connections: vec!["GATEWAY".into()],
                    },
                ],
            )
            .unwrap(),
            side_b,
        )
        .unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    router
        .set_source_route_mode(None, RouteSelectionMode::Fanout)
        .unwrap();
    let variable = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[endpoint], 2).unwrap();
    router.set_network_variable(variable).unwrap();
    assert_eq!(count_packets_of_type(&seen_a.lock().unwrap(), ty), 1);
    assert_eq!(count_packets_of_type(&seen_b.lock().unwrap(), ty), 1);

    router.clear_source_route_mode(None).unwrap();
    let adaptive = Packet::from_f32_slice(ty, &[4.0, 5.0, 6.0], &[endpoint], 3).unwrap();
    router.set_network_variable(adaptive).unwrap();
    let total = count_packets_of_type(&seen_a.lock().unwrap(), ty)
        + count_packets_of_type(&seen_b.lock().unwrap(), ty);
    assert_eq!(
        total, 4,
        "discovered network-variable owners on independent segments must all receive state"
    );
}

#[test]
fn detailed_endpoint_topology_cannot_narrow_managed_variable_segments() {
    ensure_topology_test_schema();
    let ty = ensure_managed_variable_test_schema();
    let endpoint = DataEndpoint::named("SD_CARD");
    let rocket_seen = Arc::new(Mutex::new(Vec::new()));
    let fill_seen = Arc::new(Mutex::new(Vec::new()));
    let rocket_seen_cb = rocket_seen.clone();
    let fill_seen_cb = fill_seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_reliable_enabled(true),
        zero_clock(),
    );
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    let rocket = router.add_side_packet("rocket", move |packet| {
        rocket_seen_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });
    let fill = router.add_side_packet("fill", move |packet| {
        fill_seen_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });

    let owner_address = |sender: &str, address: u32| {
        crate::discovery::build_discovery_address(
            sender,
            address as u64,
            &crate::discovery::AddressAdvertisement {
                hostname: sender.into(),
                address,
                requested_address: address,
                mode: crate::discovery::ADDRESS_MODE_STATIC,
                state: crate::discovery::ADDRESS_STATE_APPROVED,
                birth_ms: 0,
                owner_hash: address as u64,
                reachable_endpoints: vec![],
                reachable_network_variables: vec![ty],
                reachable_timesync_sources: vec![],
                link_capabilities: crate::discovery::LinkCapabilities {
                    version: 1,
                    flags: 0,
                    profile: crate::discovery::LINK_PROFILE_CANONICAL,
                    max_frame_bytes: 0,
                    compact_header_target_bytes: 0,
                    max_side_transport_templates: 0,
                },
            },
        )
        .unwrap()
    };
    router
        .rx_from_side(&owner_address("RF", 1), rocket)
        .unwrap();
    router.rx_from_side(&owner_address("GB", 2), fill).unwrap();

    // Only the fill segment advertises FLIGHT_STATE as an ordinary
    // endpoint. That endpoint detail must not erase the independent
    // managed-variable owner learned on the rocket segment.
    router
        .rx_from_side(
            &build_discovery_topology(
                "RF",
                3,
                &[TopologyBoardNode {
                    sender_id: "FC".into(),
                    reachable_endpoints: vec![],
                    reachable_timesync_sources: vec![],
                    connections: vec!["RF".into()],
                }],
            )
            .unwrap(),
            rocket,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_topology(
                "GB",
                4,
                &[TopologyBoardNode {
                    sender_id: "VB".into(),
                    reachable_endpoints: vec![endpoint],
                    reachable_timesync_sources: vec![],
                    connections: vec!["GB".into()],
                }],
            )
            .unwrap(),
            fill,
        )
        .unwrap();
    rocket_seen.lock().unwrap().clear();
    fill_seen.lock().unwrap().clear();

    for (nonce, value) in [(1, 1.0_f32), (2, 0.0), (3, 1.0)] {
        router
            .set_network_variable(
                Packet::from_f32_slice(ty, &[value], &[endpoint], nonce)
                    .unwrap()
                    .with_nonce(nonce as u16),
            )
            .unwrap();
        router.process_all_queues().unwrap();
    }
    assert_eq!(count_packets_of_type(&rocket_seen.lock().unwrap(), ty), 3);
    assert_eq!(count_packets_of_type(&fill_seen.lock().unwrap(), ty), 3);
}

#[test]
fn explicit_ingress_fanout_crosses_both_router_egress_sides() {
    ensure_topology_test_schema();
    let ty = DataType::named("GPS_DATA");
    let endpoint = DataEndpoint::named("RADIO");
    let seen_left = Arc::new(AtomicUsize::new(0));
    let seen_right = Arc::new(AtomicUsize::new(0));
    let left_cb = seen_left.clone();
    let right_cb = seen_right.clone();
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let ingress = router.add_side_packet("can", |_packet| Ok(()));
    let left = router.add_side_packet("radio-a", move |packet| {
        if packet.data_type() == ty {
            left_cb.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    let right = router.add_side_packet("radio-b", move |packet| {
        if packet.data_type() == ty {
            right_cb.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    });
    router
        .rx_from_side(
            &build_discovery_announce("LEFT", 1, &[endpoint]).unwrap(),
            left,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_announce("RIGHT", 1, &[endpoint]).unwrap(),
            right,
        )
        .unwrap();
    router
        .set_source_route_mode(Some(ingress), RouteSelectionMode::Fanout)
        .unwrap();
    let packet = Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[endpoint], 2).unwrap();
    router.rx_from_side(&packet, ingress).unwrap();
    assert_eq!(seen_left.load(Ordering::SeqCst), 1);
    assert_eq!(seen_right.load(Ordering::SeqCst), 1);
}

#[test]
fn router_typed_routes_still_respect_base_route_disables() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .set_typed_route(None, DataType::named("GPS_DATA"), side_b, true)
        .unwrap();
    router.set_route(None, side_b, false).unwrap();

    let gps_pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    assert!(router.tx(gps_pkt).is_err());

    assert!(seen_a.lock().unwrap().is_empty());
    assert!(seen_b.lock().unwrap().is_empty());

    let _ = side_a;
}

#[test]
fn router_weighted_route_mode_splits_discovered_paths_by_weight() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    router.set_route_weight(None, side_a, 2).unwrap();
    router.set_route_weight(None, side_b, 1).unwrap();

    for seq in 0..6 {
        let pkt = Packet::from_f32_slice(
            DataType::named("IMU_DATA"),
            &[
                seq as f32,
                seq as f32 + 1.0,
                seq as f32 + 2.0,
                seq as f32 + 3.0,
                seq as f32 + 4.0,
                seq as f32 + 5.0,
            ],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        router.tx(pkt).unwrap();
    }

    assert_eq!(seen_a.lock().unwrap().len(), 4);
    assert_eq!(seen_b.lock().unwrap().len(), 2);
}

#[test]
fn router_discovery_defaults_to_adaptive_load_balancing() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(0));
    let armed = Arc::new(AtomicBool::new(false));
    let seen_a = Arc::new(AtomicUsize::new(0));
    let seen_b = Arc::new(AtomicUsize::new(0));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let now_a = now_ms.clone();
    let now_b = now_ms.clone();
    let armed_b = armed.clone();

    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        if pkt.data_type() == DataType::named("IMU_DATA") {
            seen_a_c.fetch_add(1, Ordering::SeqCst);
        }
        now_a.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        if pkt.data_type() == DataType::named("IMU_DATA") {
            seen_b_c.fetch_add(1, Ordering::SeqCst);
        }
        let delay_ms =
            if armed_b.load(Ordering::SeqCst) && pkt.data_type() == DataType::named("IMU_DATA") {
                4
            } else {
                1
            };
        now_b.fetch_add(delay_ms, Ordering::SeqCst);
        Ok(())
    });
    router.set_side_egress_enabled(side_a, false).unwrap();
    router.set_side_egress_enabled(side_b, false).unwrap();

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    router.set_side_egress_enabled(side_a, true).unwrap();
    router.set_side_egress_enabled(side_b, true).unwrap();
    seen_a.store(0, Ordering::SeqCst);
    seen_b.store(0, Ordering::SeqCst);
    armed.store(true, Ordering::SeqCst);

    for seq in 0..24 {
        let pkt = Packet::from_f32_slice(
            DataType::named("IMU_DATA"),
            &[
                seq as f32,
                seq as f32 + 1.0,
                seq as f32 + 2.0,
                seq as f32 + 3.0,
                seq as f32 + 4.0,
                seq as f32 + 5.0,
            ],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        router.tx(pkt).unwrap();
    }

    let a = seen_a.load(Ordering::SeqCst);
    let b = seen_b.load(Ordering::SeqCst);
    assert_eq!(a + b, 24);
    assert!(
        a > b,
        "expected faster side to receive more traffic: a={a}, b={b}"
    );
    assert!(b > 0, "expected adaptive balancing instead of failover");

    let stats = router.export_runtime_stats();
    let side_a_stats = stats
        .sides
        .iter()
        .find(|side| side.side_name == "A")
        .unwrap();
    let side_b_stats = stats
        .sides
        .iter()
        .find(|side| side.side_name == "B")
        .unwrap();
    assert!(
        side_a_stats.adaptive.estimated_capacity_bps > side_b_stats.adaptive.estimated_capacity_bps,
        "expected adaptive capacity estimate to favor faster side"
    );
}

#[test]
fn link_probe_samples_seed_adaptive_capacity_without_sending_probe_frames() {
    ensure_topology_test_schema();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let fast = router.add_side_packet("ETHERNET", |_pkt| Ok(()));
    let slow = router.add_side_packet("LORA", |_pkt| Ok(()));

    router
        .note_side_link_probe_sample(fast, 10_000, 10)
        .unwrap();
    router
        .note_side_link_probe_sample(slow, 250, 5_000)
        .unwrap();

    let stats = router.export_runtime_stats();
    let fast_stats = stats
        .sides
        .iter()
        .find(|side| side.side_name == "ETHERNET")
        .unwrap();
    let slow_stats = stats
        .sides
        .iter()
        .find(|side| side.side_name == "LORA")
        .unwrap();
    assert!(
        fast_stats.adaptive.estimated_capacity_bps > slow_stats.adaptive.estimated_capacity_bps
    );
}

#[test]
fn slow_links_get_minimal_discovery_pings_between_full_refreshes() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(5_000));
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let side = router.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .note_side_link_probe_sample(side, 250, 5_000)
        .unwrap();
    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoverySchema)
    );

    seen.lock().unwrap().clear();
    now_ms.store(10_000, Ordering::SeqCst);
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();
    assert!(
        seen.lock().unwrap().is_empty(),
        "slow side should wait for the lightweight ping cadence"
    );

    now_ms.store(
        5_000 + DISCOVERY_SLOW_LINK_PING_INTERVAL_MS,
        Ordering::SeqCst,
    );
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();

    let pkts = seen.lock().unwrap().clone();
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].data_type(), DataType::DiscoveryAnnounce);
    assert!(
        crate::discovery::decode_discovery_announce(&pkts[0])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn topology_change_sends_only_incremental_route_summary_on_slow_link() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(5_000));
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )])
        .with_sender("BRIDGE"),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let slow = router.add_side_packet("SLOW_UPLINK", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let ingress = router.add_side_packet("LOCAL_BUS", |_pkt| Ok(()));
    router
        .note_side_link_probe_sample(slow, 250, 5_000)
        .unwrap();

    // Consume the initial full advertisement. A topology change must
    // update routes immediately without repeating that full graph.
    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();
    let initial_packets = seen.lock().unwrap().clone();
    let initial_wire_bytes: usize = initial_packets
        .iter()
        .map(|packet| crate::wire_format::pack_packet(packet).len())
        .sum();
    seen.lock().unwrap().clear();

    now_ms.store(10_000, Ordering::SeqCst);
    router
        .rx_from_side(
            &build_discovery_announce("REMOTE_SD", 10_000, &[DataEndpoint::named("SD_CARD")])
                .unwrap(),
            ingress,
        )
        .unwrap();

    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();
    let packets = seen.lock().unwrap().clone();
    let topology_updates: Vec<_> = packets
        .iter()
        .filter(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
        .map(|pkt| crate::discovery::decode_discovery_topology_update(pkt).unwrap())
        .collect();
    assert!(
        topology_updates.iter().all(|update| update.incremental),
        "a route addition must not resend the full topology graph"
    );
    assert!(
        !packets
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoverySchema),
        "a route addition must not resend the schema"
    );
    let incremental_wire_bytes: usize = packets
        .iter()
        .map(|packet| crate::wire_format::pack_packet(packet).len())
        .sum();
    assert!(
        incremental_wire_bytes < initial_wire_bytes,
        "incremental update ({incremental_wire_bytes} B) must be smaller than full discovery ({initial_wire_bytes} B)"
    );
    let address = packets
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .expect("topology change must emit an immediate route summary");
    assert!(
        crate::discovery::decode_discovery_address(address)
            .unwrap()
            .reachable_endpoints
            .contains(&DataEndpoint::named("SD_CARD")),
        "the new transitive endpoint must be advertised immediately"
    );

    // Repeat the same idempotent delta a small, bounded number of
    // times. Losing one discovery control frame must not postpone
    // convergence until the 120-second full repair snapshot.
    let mut retry_at_ms = 10_250;
    let mut retry_interval_ms = 500;
    for _retry in 1..crate::discovery::DISCOVERY_INCREMENTAL_RETRY_COUNT {
        seen.lock().unwrap().clear();
        now_ms.store(retry_at_ms, Ordering::SeqCst);
        assert!(router.poll_discovery().unwrap());
        router.process_tx_queue().unwrap();
        let retry_packets = seen.lock().unwrap().clone();
        let update = retry_packets
            .iter()
            .find(|pkt| pkt.data_type() == DataType::DiscoveryTopology)
            .map(crate::discovery::decode_discovery_topology_update)
            .transpose()
            .unwrap()
            .expect("bounded retry must repeat the topology delta");
        assert!(update.incremental);
        assert!(
            update
                .boards
                .iter()
                .any(|board| board.sender_id == "REMOTE_SD")
        );
        retry_at_ms += retry_interval_ms;
        retry_interval_ms *= 2;
    }

    seen.lock().unwrap().clear();
    now_ms.store(retry_at_ms, Ordering::SeqCst);
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();
    assert!(
        seen.lock().unwrap().is_empty(),
        "bounded delta retries must stop on a slow link"
    );
}

#[test]
fn enabling_network_variable_forces_fresh_slow_link_advertisement() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(5_000));
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("VARIABLE_NODE"),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let slow = router.add_side_packet("SLOW_UPLINK", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router
        .note_side_link_probe_sample(slow, 250, 5_000)
        .unwrap();

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();
    seen.lock().unwrap().clear();

    now_ms.store(10_000, Ordering::SeqCst);
    router
        .enable_network_variable(
            DataType::named("GPS_DATA"),
            crate::router::NetworkVariablePermissions::READ_ONLY,
        )
        .unwrap();
    assert!(router.poll_discovery().unwrap());
    router.process_tx_queue().unwrap();

    let packets = seen.lock().unwrap().clone();
    assert!(
        !packets
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoveryTopology),
        "network-variable registration must not restart full discovery"
    );
    let address = packets
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .expect("network-variable registration must bypass slow full-summary deadline");
    let advertised = crate::discovery::decode_discovery_address(address).unwrap();
    assert!(
        advertised
            .reachable_network_variables
            .contains(&DataType::named("GPS_DATA"))
    );
}

#[test]
fn newly_discovered_variable_owner_gets_only_the_cached_latest_value() {
    ensure_topology_test_schema();

    let ty = DataType::named("GPS_DATA");
    let endpoint = DataEndpoint::named("RADIO");
    let owner_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let unrelated_seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let owner_seen_c = owner_seen.clone();
    let unrelated_seen_c = unrelated_seen.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("VARIABLE_WRITER"),
        zero_clock(),
    );
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE)
        .unwrap();
    let owner_side = router.add_side_packet("owner", move |pkt: &Packet| {
        owner_seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("unrelated", move |pkt: &Packet| {
        unrelated_seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    // With no discovered remote owner, updates remain local instead
    // of being broadcast to every side. Only the latest value matters.
    router
        .set_network_variable(Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[endpoint], 1).unwrap())
        .unwrap();
    router
        .set_network_variable(Packet::from_f32_slice(ty, &[4.0, 5.0, 6.0], &[endpoint], 2).unwrap())
        .unwrap();
    router.process_all_queues().unwrap();
    assert!(
        owner_seen
            .lock()
            .unwrap()
            .iter()
            .all(|pkt| pkt.data_type() != ty)
    );
    assert!(
        unrelated_seen
            .lock()
            .unwrap()
            .iter()
            .all(|pkt| pkt.data_type() != ty)
    );

    let address = crate::discovery::AddressAdvertisement {
        hostname: "VARIABLE_READER".into(),
        address: 42,
        requested_address: 0,
        mode: crate::discovery::ADDRESS_MODE_DYNAMIC,
        state: crate::discovery::ADDRESS_STATE_APPROVED,
        birth_ms: 0,
        owner_hash: 42,
        reachable_endpoints: Vec::new(),
        reachable_network_variables: vec![ty],
        reachable_timesync_sources: Vec::new(),
        link_capabilities: crate::discovery::LinkCapabilities {
            version: 1,
            flags: 0,
            profile: crate::discovery::LINK_PROFILE_CANONICAL,
            max_frame_bytes: 0,
            compact_header_target_bytes: 0,
            max_side_transport_templates: 0,
        },
    };
    let advertisement =
        crate::discovery::build_discovery_address("VARIABLE_READER", 3, &address).unwrap();
    router.rx_from_side(&advertisement, owner_side).unwrap();
    router.process_all_queues().unwrap();

    let owner_values: Vec<Vec<f32>> = owner_seen
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ty)
        .map(|pkt| pkt.data_as_f32().unwrap())
        .collect();
    assert_eq!(owner_values, vec![vec![4.0, 5.0, 6.0]]);
    assert!(
        unrelated_seen
            .lock()
            .unwrap()
            .iter()
            .all(|pkt| pkt.data_type() != ty),
        "owner discovery must not fan the cached value out to unrelated sides"
    );

    // Repeating the same idempotent advertisement must not replay the
    // value again; only an actual ownership addition triggers it.
    router.rx_from_side(&advertisement, owner_side).unwrap();
    router.process_all_queues().unwrap();
    assert_eq!(
        owner_seen
            .lock()
            .unwrap()
            .iter()
            .filter(|pkt| pkt.data_type() == ty)
            .count(),
        1
    );
}

#[test]
fn relay_slow_links_get_minimal_discovery_pings_between_full_refreshes() {
    let now_ms = Arc::new(AtomicU64::new(5_000));
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let side = relay.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    relay.note_side_link_probe_sample(side, 250, 5_000).unwrap();
    relay.announce_discovery().unwrap();
    relay.process_tx_queue().unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoverySchema)
    );

    seen.lock().unwrap().clear();
    now_ms.store(
        5_000 + DISCOVERY_SLOW_LINK_PING_INTERVAL_MS,
        Ordering::SeqCst,
    );
    assert!(relay.poll_discovery().unwrap());
    relay.process_tx_queue().unwrap();

    let pkts = seen.lock().unwrap().clone();
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].data_type(), DataType::DiscoveryAnnounce);
    assert!(
        crate::discovery::decode_discovery_announce(&pkts[0])
            .unwrap()
            .is_empty()
    );
}

#[cfg(all(feature = "timesync", feature = "discovery"))]
#[test]
fn timesync_announces_throttle_only_the_measured_slow_side() {
    let now_ms = Arc::new(AtomicU64::new(5_000));
    let seen_fast: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_slow: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_fast_c = seen_fast.clone();
    let seen_slow_c = seen_slow.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Source,
            announce_interval_ms: 1_000,
            ..Default::default()
        }),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let fast = router.add_side_packet("ETHERNET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_fast_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let slow = router.add_side_packet("LORA", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_slow_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let local_sender = router.sender().to_string();
    let local_sources = [local_sender.as_str()];

    router
        .set_source_route_mode(None, RouteSelectionMode::Fanout)
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_timesync_sources("FAST_TS", 0, &local_sources).unwrap(),
            fast,
        )
        .unwrap();
    router
        .rx_from_side(
            &build_discovery_timesync_sources("SLOW_TS", 1, &local_sources).unwrap(),
            slow,
        )
        .unwrap();
    router.process_rx_queue().unwrap();
    router.process_tx_queue().unwrap();
    seen_fast.lock().unwrap().clear();
    seen_slow.lock().unwrap().clear();
    router
        .note_side_link_probe_sample(slow, 250, 5_000)
        .unwrap();

    now_ms.store(6_000, Ordering::SeqCst);
    assert!(router.poll_timesync().unwrap());
    router.process_tx_queue().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_fast.lock().unwrap(), DataType::TimeSyncAnnounce),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_slow.lock().unwrap(), DataType::TimeSyncAnnounce),
        0
    );

    seen_fast.lock().unwrap().clear();
    seen_slow.lock().unwrap().clear();
    now_ms.store(7_000, Ordering::SeqCst);
    assert!(router.poll_timesync().unwrap());
    router.process_tx_queue().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_fast.lock().unwrap(), DataType::TimeSyncAnnounce),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_slow.lock().unwrap(), DataType::TimeSyncAnnounce),
        0
    );
}

#[test]
fn router_exports_runtime_stats_with_route_and_type_details() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(0));
    let seen_a = Arc::new(AtomicUsize::new(0));
    let seen_b = Arc::new(AtomicUsize::new(0));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let now_a = now_ms.clone();
    let now_b = now_ms.clone();

    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let retry_budget = Arc::new(AtomicUsize::new(0));
    let retry_budget_c = retry_budget.clone();
    let side_a = router.add_side_packet("A", move |_pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.fetch_add(1, Ordering::SeqCst);
        now_a.fetch_add(1, Ordering::SeqCst);
        if retry_budget_c.fetch_add(1, Ordering::SeqCst) < 2 {
            return Err(TelemetryError::Io("side tx busy"));
        }
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |_pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.fetch_add(1, Ordering::SeqCst);
        now_b.fetch_add(3, Ordering::SeqCst);
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();

    router
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    router.set_route(None, side_b, false).unwrap();
    router.set_route_weight(None, side_a, 2).unwrap();
    router.set_route_weight(None, side_b, 1).unwrap();
    router.set_route_priority(None, side_a, 7).unwrap();
    router
        .set_typed_route(None, DataType::named("GPS_DATA"), side_a, true)
        .unwrap();
    router
        .set_typed_route(None, DataType::named("GPS_DATA"), side_b, false)
        .unwrap();

    for seq in 0..3 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        router.tx_queue(pkt).unwrap();
    }

    let queued = router.export_runtime_stats();
    assert!(queued.queues.tx_len >= 3);
    assert!(queued.queues.tx_bytes > 0);
    assert_eq!(queued.queues.rx_len, 0);

    router.process_tx_queue().unwrap();

    let stats = router.export_runtime_stats();
    assert_eq!(
        stats
            .route_modes
            .iter()
            .find(|mode| mode.src_side_id.is_none())
            .unwrap()
            .selection_mode,
        Some(RouteSelectionMode::Weighted)
    );
    assert!(
        stats
            .route_overrides
            .iter()
            .any(|route| route.src_side_id.is_none()
                && route.dst_side_id == side_b
                && !route.enabled)
    );
    assert!(
        stats
            .route_weights
            .iter()
            .any(|weight| weight.src_side_id.is_none()
                && weight.dst_side_id == side_a
                && weight.weight == 2)
    );
    assert!(
        stats
            .route_priorities
            .iter()
            .any(|priority| priority.src_side_id.is_none()
                && priority.dst_side_id == side_a
                && priority.priority == 7)
    );
    assert!(
        stats
            .typed_route_overrides
            .iter()
            .any(|route| route.src_side_id.is_none()
                && route.data_type == DataType::named("GPS_DATA")
                && route.dst_side_id == side_a
                && route.enabled)
    );
    assert!(
        stats
            .typed_route_overrides
            .iter()
            .any(|route| route.src_side_id.is_none()
                && route.data_type == DataType::named("GPS_DATA")
                && route.dst_side_id == side_b
                && !route.enabled)
    );
    assert_eq!(stats.discovery.route_count, 2);
    assert_eq!(stats.discovery.announcer_count, 2);
    assert_eq!(stats.queues.tx_len, 0);
    assert_eq!(stats.queues.rx_len, 0);
    assert_eq!(stats.reliable.reliable_return_route_count, 0);
    assert_eq!(stats.reliable.end_to_end_pending_count, 0);
    assert_eq!(stats.total_handler_failures, 0);
    assert_eq!(stats.total_handler_retries, 0);

    let side_a_stats = side_stats(&stats, side_a);
    let side_b_stats = side_stats(&stats, side_b);
    let side_a_type = type_stats(side_a_stats, DataType::named("GPS_DATA"));
    assert!(side_a_stats.rx_packets >= 1);
    assert!(!side_a_stats.reliable_enabled);
    assert!(!side_a_stats.link_local_enabled);
    assert!(side_a_stats.ingress_enabled);
    assert!(side_a_stats.egress_enabled);
    assert!(side_a_stats.tx_packets >= 3);
    assert_eq!(side_a_stats.tx_retries, 2);
    assert_eq!(side_a_stats.total_handler_retries, 2);
    assert_eq!(side_a_stats.tx_handler_failures, 0);
    assert_eq!(side_a_stats.local_handler_failures, 0);
    assert_eq!(side_a_stats.local_delivery_packets, 0);
    assert_eq!(side_a_type.tx_packets, 3);
    assert_eq!(side_a_type.handler_failures, 0);
    assert_eq!(side_a_type.relayed_tx_packets, 0);
    assert!(side_a_stats.adaptive.auto_balancing_enabled);
    assert!(side_a_stats.adaptive.estimated_capacity_bps > 0);
    assert!(
        side_a_stats.adaptive.peak_capacity_bps >= side_a_stats.adaptive.estimated_capacity_bps
    );
    assert!(side_a_stats.adaptive.current_usage_bps > 0);
    assert!(side_a_stats.adaptive.peak_usage_bps >= side_a_stats.adaptive.current_usage_bps);
    assert_eq!(
        side_a_stats.adaptive.effective_weight,
        side_a_stats.adaptive.available_headroom_bps.max(1)
    );
    assert!(side_a_stats.adaptive.sample_count >= 3);
    assert!(side_a_stats.adaptive.last_observed_ms > 0);
    assert_eq!(
        side_b_stats
            .data_types
            .iter()
            .find(|item| item.data_type == DataType::named("GPS_DATA"))
            .map(|item| item.tx_packets)
            .unwrap_or(0),
        0
    );
}

#[test]
fn relay_exports_runtime_stats_with_route_and_bandwidth_details() {
    ensure_topology_test_schema();

    let now_ms = Arc::new(AtomicU64::new(0));
    let now_a = now_ms.clone();
    let now_b = now_ms.clone();

    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let side_a = relay.add_side_packet("A", move |_pkt: &Packet| -> TelemetryResult<()> {
        now_a.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |_pkt: &Packet| -> TelemetryResult<()> {
        now_b.fetch_add(4, Ordering::SeqCst);
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_rx_queue().unwrap();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
        .unwrap();
    relay.set_route(Some(side_c), side_b, false).unwrap();
    relay.set_route_weight(Some(side_c), side_a, 2).unwrap();
    relay.set_route_weight(Some(side_c), side_b, 1).unwrap();
    relay.set_route_priority(Some(side_c), side_a, 4).unwrap();
    relay
        .set_typed_route(Some(side_c), DataType::named("GPS_DATA"), side_a, true)
        .unwrap();
    relay
        .set_typed_route(Some(side_c), DataType::named("GPS_DATA"), side_b, false)
        .unwrap();

    for seq in 0..6 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        relay.rx_from_side(side_c, pkt).unwrap();
    }
    let queued = relay.export_runtime_stats();
    assert_eq!(queued.queues.rx_len, 6);
    assert!(queued.queues.rx_bytes > 0);
    relay.process_all_queues().unwrap();

    let stats = relay.export_runtime_stats();
    assert_eq!(
        stats
            .route_modes
            .iter()
            .find(|mode| mode.src_side_id == Some(side_c))
            .unwrap()
            .selection_mode,
        Some(RouteSelectionMode::Weighted)
    );
    assert!(
        stats
            .route_overrides
            .iter()
            .any(|route| route.src_side_id == Some(side_c)
                && route.dst_side_id == side_b
                && !route.enabled)
    );
    assert!(
        stats
            .route_weights
            .iter()
            .any(|weight| weight.src_side_id == Some(side_c)
                && weight.dst_side_id == side_a
                && weight.weight == 2)
    );
    assert!(
        stats
            .route_priorities
            .iter()
            .any(|priority| priority.src_side_id == Some(side_c)
                && priority.dst_side_id == side_a
                && priority.priority == 4)
    );
    assert!(
        stats
            .typed_route_overrides
            .iter()
            .any(|route| route.src_side_id == Some(side_c)
                && route.data_type == DataType::named("GPS_DATA")
                && route.dst_side_id == side_a
                && route.enabled)
    );
    assert!(
        stats
            .typed_route_overrides
            .iter()
            .any(|route| route.src_side_id == Some(side_c)
                && route.data_type == DataType::named("GPS_DATA")
                && route.dst_side_id == side_b
                && !route.enabled)
    );
    assert_eq!(stats.queues.rx_len, 0);
    assert_eq!(stats.queues.tx_len, 0);
    assert_eq!(stats.total_handler_failures, 0);
    assert_eq!(stats.total_handler_retries, 0);

    let ingress_stats = side_stats(&stats, side_c);
    assert_eq!(ingress_stats.rx_packets, 6);
    assert_eq!(ingress_stats.relayed_rx_packets, 6);
    assert!(stats.reliable.reliable_return_route_count <= ingress_stats.rx_packets as usize);
    let ingress_type = type_stats(ingress_stats, DataType::named("GPS_DATA"));
    assert_eq!(ingress_type.rx_packets, 6);
    assert_eq!(ingress_type.relayed_rx_packets, 6);
    let egress_a = side_stats(&stats, side_a);
    let egress_b = side_stats(&stats, side_b);
    assert!(egress_a.tx_packets > egress_b.tx_packets);
    assert!(egress_a.adaptive.estimated_capacity_bps > 0);
    assert!(egress_a.adaptive.current_usage_bps > 0);
    assert!(egress_a.adaptive.peak_usage_bps >= egress_a.adaptive.current_usage_bps);
    assert_eq!(
        egress_a.adaptive.effective_weight,
        egress_a.adaptive.available_headroom_bps.max(1)
    );
    assert!(egress_a.adaptive.last_observed_ms > 0);
    assert_eq!(
        egress_b
            .data_types
            .iter()
            .find(|item| item.data_type == DataType::named("GPS_DATA"))
            .map(|item| item.tx_packets)
            .unwrap_or(0),
        0
    );
    assert!(stats.discovery.route_count >= 2);
}

#[test]
fn router_runtime_stats_track_ingress_local_handler_failures_and_relayed_rx() {
    ensure_topology_test_schema();

    let failing =
        EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), |_pkt: &Packet| {
            Err(TelemetryError::HandlerError("local handler failed"))
        });
    let router = Router::new_with_clock(RouterConfig::new(vec![failing]), zero_clock());
    let side = router.add_side_packet("INGRESS", |_pkt: &Packet| Ok(()));

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        1,
    )
    .unwrap();
    router.rx_from_side(&pkt, side).unwrap();

    let stats = router.export_runtime_stats();
    let ingress = side_stats(&stats, side);
    let gps = type_stats(ingress, DataType::named("GPS_DATA"));

    assert_eq!(stats.total_handler_failures, 1);
    assert_eq!(stats.total_handler_retries, MAX_HANDLER_RETRIES as u64);
    assert_eq!(ingress.rx_packets, 1);
    assert!(ingress.rx_bytes > 0);
    assert_eq!(ingress.relayed_rx_packets, 1);
    assert_eq!(ingress.local_delivery_packets, 1);
    assert_eq!(ingress.local_handler_failures, 1);
    assert_eq!(ingress.total_handler_retries, MAX_HANDLER_RETRIES as u64);
    assert_eq!(gps.rx_packets, 2);
    assert_eq!(gps.relayed_rx_packets, 1);
    assert_eq!(gps.handler_failures, 1);
}

#[test]
fn relay_runtime_stats_track_tx_failures_and_retries() {
    ensure_topology_test_schema();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", |_pkt: &Packet| {
        Err(TelemetryError::Io("side tx failed hard"))
    });
    let side_b = relay.add_side_packet("B", |_pkt: &Packet| Ok(()));
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| Ok(()));

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.process_rx_queue().unwrap();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
        .unwrap();
    relay.set_route(Some(side_c), side_b, false).unwrap();
    relay.set_route_priority(Some(side_c), side_a, 0).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[9.0, 8.0, 7.0],
        &[DataEndpoint::named("RADIO")],
        42,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt).unwrap();
    assert!(matches!(
        relay.process_all_queues(),
        Err(TelemetryError::Io("side tx failed hard"))
    ));

    let stats = relay.export_runtime_stats();
    let failing_side = side_stats(&stats, side_a);
    let ingress = side_stats(&stats, side_c);
    let gps_failures = failing_side
        .data_types
        .iter()
        .find(|item| item.data_type == DataType::named("GPS_DATA"))
        .map(|item| item.handler_failures)
        .unwrap_or(0);

    assert_eq!(stats.total_handler_failures, 1);
    assert_eq!(stats.total_handler_retries, 1);
    assert!(
        stats
            .route_overrides
            .iter()
            .any(|route| route.src_side_id == Some(side_c)
                && route.dst_side_id == side_b
                && !route.enabled)
    );
    assert!(
        stats
            .route_priorities
            .iter()
            .any(|priority| priority.src_side_id == Some(side_c)
                && priority.dst_side_id == side_a
                && priority.priority == 0)
    );
    assert_eq!(ingress.rx_packets, 1);
    assert_eq!(ingress.relayed_rx_packets, 1);
    assert_eq!(failing_side.tx_packets, 0);
    assert_eq!(failing_side.tx_handler_failures, 1);
    assert_eq!(failing_side.tx_retries, 1);
    assert_eq!(failing_side.total_handler_retries, 1);
    assert_eq!(gps_failures, 0);
    let gps_tx_retries = failing_side
        .data_types
        .iter()
        .find(|item| item.data_type == DataType::named("GPS_DATA"))
        .map(|item| item.tx_retries)
        .unwrap_or(0);
    assert_eq!(gps_tx_retries, 0);
}

#[test]
fn router_failover_route_mode_switches_when_preferred_path_expires() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
    let discovery_b = build_discovery_announce(
        "REMOTE_B",
        DISCOVERY_ROUTE_TTL_MS / 2,
        &[DataEndpoint::named("RADIO")],
    )
    .unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .set_source_route_mode(None, RouteSelectionMode::Failover)
        .unwrap();
    router.set_route_priority(None, side_a, 0).unwrap();
    router.set_route_priority(None, side_b, 1).unwrap();

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(pkt1).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[2.0, 3.0, 4.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    router.tx(pkt2).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
}

#[test]
fn router_weighted_route_mode_falls_back_to_remaining_path_when_other_path_expires() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::default(),
        Box::new(SharedClock {
            now_ms: now_ms.clone(),
        }),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
    let discovery_b = build_discovery_announce(
        "REMOTE_B",
        DISCOVERY_ROUTE_TTL_MS / 2,
        &[DataEndpoint::named("RADIO")],
    )
    .unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    router.set_route_weight(None, side_a, 1).unwrap();
    router.set_route_weight(None, side_b, 1).unwrap();

    for seq in 0..2 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        router.tx(pkt).unwrap();
    }
    let before_a = count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
    let before_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(before_a + before_b, 2);

    now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
    let pkt3 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[9.0, 10.0, 11.0],
        &[DataEndpoint::named("RADIO")],
        3,
    )
    .unwrap();
    router.tx(pkt3).unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        before_a
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        before_b + 1
    );
}

#[test]
fn router_failover_route_mode_switches_when_preferred_side_is_removed() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_a, side_a).unwrap();
    router.rx_from_side(&discovery_b, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    router
        .set_source_route_mode(None, RouteSelectionMode::Failover)
        .unwrap();
    router.set_route_priority(None, side_a, 0).unwrap();
    router.set_route_priority(None, side_b, 1).unwrap();

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    router.tx(pkt1).unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    router.remove_side(side_a).unwrap();
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    router.tx(pkt2).unwrap();

    let before_a = count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
    let before_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(before_a + before_b, 2);
}

#[test]
fn relay_weighted_route_mode_splits_discovered_paths_by_weight() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_rx_queue().unwrap();
    relay.process_tx_queue().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
        .unwrap();
    relay.set_route_weight(Some(side_c), side_a, 2).unwrap();
    relay.set_route_weight(Some(side_c), side_b, 1).unwrap();

    for seq in 0..6 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        relay.rx_from_side(side_c, pkt).unwrap();
    }
    relay.process_all_queues().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        4
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        2
    );
}

#[test]
fn relay_failover_route_mode_switches_when_preferred_path_expires() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.process_rx_queue().unwrap();
    relay.process_tx_queue().unwrap();
    now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
    let discovery_b = build_discovery_announce(
        "REMOTE_B",
        DISCOVERY_ROUTE_TTL_MS / 2,
        &[DataEndpoint::named("RADIO")],
    )
    .unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_rx_queue().unwrap();
    relay.process_tx_queue().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
        .unwrap();
    relay.set_route_priority(Some(side_c), side_a, 0).unwrap();
    relay.set_route_priority(Some(side_c), side_b, 1).unwrap();

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt1).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[2.0, 3.0, 4.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt2).unwrap();
    relay.process_all_queues().unwrap();
    let before_a = count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
    let before_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(before_a + before_b, 2);
}

#[test]
fn relay_weighted_route_mode_falls_back_to_remaining_path_when_other_path_expires() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.process_all_queues().unwrap();
    now_ms.store(DISCOVERY_ROUTE_TTL_MS / 2, Ordering::SeqCst);
    let discovery_b = build_discovery_announce(
        "REMOTE_B",
        DISCOVERY_ROUTE_TTL_MS / 2,
        &[DataEndpoint::named("RADIO")],
    )
    .unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Weighted)
        .unwrap();
    relay.set_route_weight(Some(side_c), side_a, 1).unwrap();
    relay.set_route_weight(Some(side_c), side_b, 1).unwrap();

    for seq in 0..2 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[seq as f32, seq as f32 + 1.0, seq as f32 + 2.0],
            &[DataEndpoint::named("RADIO")],
            seq as u64,
        )
        .unwrap();
        relay.rx_from_side(side_c, pkt).unwrap();
    }
    relay.process_all_queues().unwrap();
    let before_a = count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA"));
    let before_b = count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA"));
    assert_eq!(before_a + before_b, 2);

    now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
    let pkt3 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[9.0, 10.0, 11.0],
        &[DataEndpoint::named("RADIO")],
        3,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt3).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        before_a
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        before_b + 1
    );
}

#[test]
fn relay_failover_route_mode_switches_when_preferred_side_is_removed() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_c = relay.add_side_packet("C", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_a =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    let discovery_b =
        build_discovery_announce("REMOTE_B", 1, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_a).unwrap();
    relay.rx_from_side(side_b, discovery_b).unwrap();
    relay.process_all_queues().unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay
        .set_source_route_mode(Some(side_c), RouteSelectionMode::Failover)
        .unwrap();
    relay.set_route_priority(Some(side_c), side_a, 0).unwrap();
    relay.set_route_priority(Some(side_c), side_b, 1).unwrap();

    let pkt1 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        1,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt1).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        0
    );

    relay.remove_side(side_a).unwrap();
    let pkt2 = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[4.0, 5.0, 6.0],
        &[DataEndpoint::named("RADIO")],
        2,
    )
    .unwrap();
    relay.rx_from_side(side_c, pkt2).unwrap();
    relay.process_all_queues().unwrap();

    assert_eq!(
        count_packets_of_type(&seen_a.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::named("GPS_DATA")),
        1
    );
}

#[test]
fn router_can_disable_ingress_for_a_side() {
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
    router.set_side_ingress_enabled(side, false).unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0, 2.0, 3.0],
        &[DataEndpoint::named("RADIO")],
        5,
    )
    .unwrap();

    match router.rx_from_side(&pkt, side) {
        Err(TelemetryError::HandlerError(msg)) => {
            assert!(msg.contains("ingress disabled"));
        }
        other => panic!("expected ingress-disabled error, got {other:?}"),
    }
}

#[cfg(feature = "timesync")]
#[test]
fn router_periodic_dispatches_discovery_and_timesync_when_enabled() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Source,
            ..Default::default()
        }),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.periodic(0).unwrap();

    let pkts = seen.lock().unwrap().clone();
    assert!(pkts.iter().any(|pkt| matches!(
        pkt.data_type(),
        DataType::DiscoveryAddress
            | DataType::DiscoveryAnnounce
            | DataType::DiscoveryTopology
            | DataType::DiscoveryTimeSyncSources
    )));
    assert!(
        pkts.iter()
            .any(|pkt| pkt.data_type() == DataType::TimeSyncAnnounce)
    );
}

#[cfg(feature = "timesync")]
#[test]
fn router_periodic_can_skip_timesync_but_still_dispatch_discovery() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Source,
            ..Default::default()
        }),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.periodic_no_timesync(0).unwrap();

    let pkts = seen.lock().unwrap().clone();
    assert!(pkts.iter().any(|pkt| matches!(
        pkt.data_type(),
        DataType::DiscoveryAddress
            | DataType::DiscoveryAnnounce
            | DataType::DiscoveryTopology
            | DataType::DiscoveryTimeSyncSources
    )));
    assert!(
        pkts.iter()
            .all(|pkt| pkt.data_type() != DataType::TimeSyncAnnounce)
    );
}

#[cfg(feature = "timesync")]
#[test]
fn queued_timesync_packets_precede_normal_telemetry() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Consumer,
            ..Default::default()
        }),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
        .unwrap();
    let announce =
        crate::timesync::build_timesync_announce_with_sender("SRC_FAST", 1, 1_700).unwrap();
    router.rx(&announce).unwrap();
    router.process_tx_queue().unwrap();

    let pkts = seen.lock().unwrap().clone();
    assert!(pkts.len() >= 2);
    let gps_idx = pkts
        .iter()
        .position(|pkt| pkt.data_type() == DataType::named("GPS_DATA"))
        .expect("expected queued GPS packet");
    let request_idx = pkts
        .iter()
        .position(|pkt| pkt.data_type() == DataType::TimeSyncRequest)
        .expect("expected queued time-sync request");
    assert!(request_idx < gps_idx);
}

#[cfg(feature = "discovery")]
#[test]
fn queued_discovery_packets_precede_normal_telemetry() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            |_pkt| Ok(()),
        )]),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router
        .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 2.0, 3.0])
        .unwrap();
    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let pkts = seen.lock().unwrap().clone();
    let gps_idx = pkts
        .iter()
        .position(|pkt| pkt.data_type() == DataType::named("GPS_DATA"))
        .unwrap();
    assert!(gps_idx > 0);
    assert!(
        pkts[..gps_idx]
            .iter()
            .all(|pkt| crate::discovery::is_discovery_type(pkt.data_type()))
    );
}

#[test]
fn reliable_packets_use_discovery_selection_instead_of_flooding() {
    ensure_topology_test_schema();
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("REMOTE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();
    let discovery_pkt =
        build_discovery_announce("REMOTE_B", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    router.rx_from_side(&discovery_pkt, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let msg = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[5.0, 6.0, 7.0],
        &[DataEndpoint::named("RADIO")],
        3,
    )
    .unwrap();
    router.tx(msg).unwrap();

    let seen_a_len = seen_a.lock().unwrap().len();
    let seen_b_len = seen_b.lock().unwrap().len();
    assert_eq!(
        seen_a_len + seen_b_len,
        1,
        "reliable outbound traffic should follow one discovered path instead of flooding",
    );
}

#[test]
fn relay_exports_aggregated_topology() {
    ensure_topology_test_schema();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
    relay.add_side_packet("B", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let discovery_pkt = build_discovery_announce(
        "NODE_A",
        0,
        &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
    )
    .unwrap();
    relay.rx_from_side(side_a, discovery_pkt).unwrap();
    relay.process_all_queues().unwrap();

    let snap = relay.export_topology();
    assert_eq!(
        snap.advertised_endpoints,
        vec![DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")]
    );
    assert!(snap.routers.iter().any(
        |board| board.sender_id == "RELAY" && board.connections.contains(&"NODE_A".to_string())
    ));
    assert_eq!(snap.routes.len(), 1);
    assert_eq!(snap.routes[0].side_name, "A");
    assert_eq!(snap.routes[0].announcers.len(), 1);
    assert_eq!(snap.routes[0].announcers[0].sender_id, "NODE_A");
    assert!(
        snap.routes[0].announcers[0]
            .routers
            .iter()
            .any(|board| board.sender_id == "NODE_A")
    );
}

#[test]
fn relay_periodic_dispatches_discovery() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let relay = Relay::new(zero_clock());
    let side_a = relay.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    relay.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt =
        build_discovery_announce("NODE_A", 0, &[DataEndpoint::named("RADIO")]).unwrap();
    relay.rx_from_side(side_a, discovery_pkt).unwrap();
    relay.periodic(0).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    relay.periodic(0).unwrap();

    assert!(
        seen_b
            .lock()
            .unwrap()
            .iter()
            .any(|pkt| pkt.data_type() == DataType::DiscoveryAnnounce)
    );
}

#[test]
fn relay_end_to_end_acked_holders_clear_when_discovered_holder_expires() {
    let now_ms = Arc::new(AtomicU64::new(0));
    let relay = Relay::new(Box::new(SharedClock {
        now_ms: now_ms.clone(),
    }));
    let side = relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    relay
        .rx_from_side(
            side,
            build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();

    let packet_id = 77u64;
    let ack = Packet::new(
        DataType::ReliableAck,
        &crate::message_meta(DataType::ReliableAck).endpoints,
        "E2EACK:DEST_A",
        0,
        Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
    )
    .unwrap();
    relay.rx_from_side(side, ack).unwrap();
    relay.process_all_queues().unwrap();
    assert_eq!(
        relay.debug_end_to_end_acked_destination_count(packet_id),
        Some(1)
    );

    now_ms.store(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::SeqCst);
    relay.periodic(0).unwrap();
    assert_eq!(
        relay.debug_end_to_end_acked_destination_count(packet_id),
        None
    );
}

#[test]
fn relay_keeps_forwarding_to_unacked_destinations_after_reachability_changes() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();
    let relay = Relay::new(zero_clock());
    let ingress =
        relay.add_side_packet("INGRESS", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });
    let link = relay.add_side_packet("LINK", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    relay
        .rx_from_side(
            link,
            build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay
        .rx_from_side(
            link,
            build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();

    let pkt = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[31.0, 0.0, 0.0],
        &[DataEndpoint::named("RADIO")],
        31,
    )
    .unwrap();
    let packet_id = pkt.packet_id();
    relay.rx_from_side(ingress, pkt.clone()).unwrap();
    relay.process_all_queues().unwrap();
    seen.lock().unwrap().clear();

    let ack = Packet::new(
        DataType::ReliableAck,
        &crate::message_meta(DataType::ReliableAck).endpoints,
        "E2EACK:DEST_A",
        0,
        Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
    )
    .unwrap();
    relay.rx_from_side(link, ack).unwrap();
    relay.process_all_queues().unwrap();

    relay
        .rx_from_side(
            link,
            build_discovery_announce("DEST_B", 1, &[DataEndpoint::named("SD_CARD")]).unwrap(),
        )
        .unwrap();
    relay.process_all_queues().unwrap();

    relay.rx_from_side(ingress, pkt).unwrap();
    relay.process_all_queues().unwrap();
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|p| p.data_type() == DataType::named("GPS_DATA"))
    );
}

#[test]
fn reliable_relay_state_stays_bounded_under_unacked_traffic() {
    let relay = Relay::new(zero_clock());
    let side = relay.add_side_packet("A", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    for idx in 0..(RELIABLE_MAX_RETURN_ROUTES.max(1) + 4) {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[idx as f32, 2.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            idx as u64,
        )
        .unwrap();
        relay.rx_from_side(side, pkt).unwrap();
    }
    assert!(relay.debug_reliable_return_route_count() <= RELIABLE_MAX_RETURN_ROUTES.max(1));

    let packet_id = 123u64;
    for idx in 0..(RELIABLE_MAX_END_TO_END_PENDING.max(1) + 4) {
        let ack = Packet::new(
            DataType::ReliableAck,
            &crate::message_meta(DataType::ReliableAck).endpoints,
            &format!("E2EACK:DEST_{idx}"),
            idx as u64,
            Arc::<[u8]>::from(packet_id.to_le_bytes().to_vec()),
        )
        .unwrap();
        relay.rx_from_side(side, ack).unwrap();
    }
    assert!(
        relay
            .debug_end_to_end_acked_destination_count(packet_id)
            .unwrap_or(0)
            <= RELIABLE_MAX_END_TO_END_PENDING.max(1)
    );

    for idx in 0..(RELIABLE_MAX_END_TO_END_ACK_CACHE.max(1) + 4) {
        let ack = Packet::new(
            DataType::ReliableAck,
            &crate::message_meta(DataType::ReliableAck).endpoints,
            "E2EACK:DEST_A",
            idx as u64,
            Arc::<[u8]>::from((10_000u64 + idx as u64).to_le_bytes().to_vec()),
        )
        .unwrap();
        relay.rx_from_side(side, ack).unwrap();
    }
    assert!(
        relay.debug_end_to_end_acked_packet_count() <= RELIABLE_MAX_END_TO_END_ACK_CACHE.max(1)
    );
}

#[test]
fn link_local_only_packets_stay_on_software_bus_sides() {
    let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
        return;
    };
    let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
        return;
    };
    let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_net_c = seen_net.clone();
    let seen_ll_c = seen_ll.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_net_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet_with_options(
        "LL",
        move |pkt: &Packet| -> TelemetryResult<()> {
            seen_ll_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    let pkt = Packet::new(
        ipc_message,
        &[software_bus],
        "IPC_NODE",
        7,
        Arc::<[u8]>::from(b"hello-ipc".as_slice()),
    )
    .unwrap();
    router.tx(pkt).unwrap();

    let ipc_count_net = seen_net
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    let ipc_count_ll = seen_ll
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    assert_eq!(ipc_count_net, 0);
    assert_eq!(ipc_count_ll, 1);
}

#[test]
fn runtime_registered_ipc_stays_off_network_sides() {
    ensure_topology_test_schema();
    let ep_name = "RUNTIME_IPC_EP_9901";
    let ty_name = "RUNTIME_IPC_MSG_9901";
    let _ = remove_data_type_by_name(ty_name);
    let _ = remove_endpoint_by_name(ep_name);

    let runtime_ipc_ep = register_endpoint_with_description(ep_name, "runtime ipc endpoint", true)
        .expect("register runtime ipc endpoint");
    let runtime_ipc_ty = register_data_type_with_description(
        ty_name,
        "runtime ipc type",
        MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
        &[runtime_ipc_ep],
        ReliableMode::None,
        1,
    )
    .expect("register runtime ipc type");

    let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_net_c = seen_net.clone();
    let seen_ll_c = seen_ll.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_net_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet_with_options(
        "IPC",
        move |pkt: &Packet| -> TelemetryResult<()> {
            seen_ll_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    let pkt = Packet::new(
        runtime_ipc_ty,
        &[runtime_ipc_ep],
        "RUNTIME_IPC_NODE",
        17,
        Arc::<[u8]>::from(b"runtime-ipc".as_slice()),
    )
    .unwrap();
    router.tx(pkt).unwrap();

    let ipc_count_net = seen_net
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == runtime_ipc_ty)
        .count();
    let ipc_count_ll = seen_ll
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == runtime_ipc_ty)
        .count();
    assert_eq!(ipc_count_net, 0);
    assert_eq!(ipc_count_ll, 1);

    assert!(remove_data_type_by_name(ty_name).unwrap());
    assert!(remove_endpoint_by_name(ep_name).unwrap());
}

#[test]
fn link_local_routes_ignore_non_link_local_discovery_candidates() {
    let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
        return;
    };
    let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
        return;
    };
    let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_net_c = seen_net.clone();
    let seen_ll_c = seen_ll.clone();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side_net = router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_net_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_ll = router.add_side_packet_with_options(
        "LL",
        move |pkt: &Packet| -> TelemetryResult<()> {
            seen_ll_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    let pkt_net = build_discovery_announce("NET_NODE", 0, &[software_bus]).unwrap();
    router.rx_from_side(&pkt_net, side_net).unwrap();
    let pkt_ll = build_discovery_announce("LL_NODE", 0, &[software_bus]).unwrap();
    router.rx_from_side(&pkt_ll, side_ll).unwrap();
    seen_net.lock().unwrap().clear();
    seen_ll.lock().unwrap().clear();

    let pkt = Packet::new(
        ipc_message,
        &[software_bus],
        "IPC_NODE",
        8,
        Arc::<[u8]>::from(b"stay-local".as_slice()),
    )
    .unwrap();
    router.tx(pkt).unwrap();

    let ipc_count_net = seen_net
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    let ipc_count_ll = seen_ll
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    assert_eq!(ipc_count_net, 0);
    assert_eq!(ipc_count_ll, 1);
}

#[test]
fn relay_link_local_routes_ignore_non_link_local_discovery_candidates() {
    let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
        return;
    };
    let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
        return;
    };
    let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_net_c = seen_net.clone();
    let seen_ll_c = seen_ll.clone();

    let relay = Relay::new(zero_clock());
    let side_net = relay.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_net_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_ll = relay.add_side_packet_with_options(
        "LL",
        move |pkt: &Packet| -> TelemetryResult<()> {
            seen_ll_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        crate::relay::RelaySideOptions {
            reliable_enabled: false,
            link_local_enabled: true,
            ..crate::relay::RelaySideOptions::default()
        },
    );
    let side_src = relay.add_side_packet("SRC", |_pkt: &Packet| -> TelemetryResult<()> { Ok(()) });

    let pkt_net = build_discovery_announce("NET_NODE", 0, &[software_bus]).unwrap();
    relay.rx_from_side(side_net, pkt_net).unwrap();
    let pkt_ll = build_discovery_announce("LL_NODE", 0, &[software_bus]).unwrap();
    relay.rx_from_side(side_ll, pkt_ll).unwrap();
    relay.process_all_queues().unwrap();
    seen_net.lock().unwrap().clear();
    seen_ll.lock().unwrap().clear();

    let pkt = Packet::new(
        ipc_message,
        &[software_bus],
        "IPC_NODE",
        9,
        Arc::<[u8]>::from(b"relay-local".as_slice()),
    )
    .unwrap();
    relay.rx_from_side(side_src, pkt).unwrap();
    relay.process_all_queues().unwrap();

    let ipc_count_net = seen_net
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    let ipc_count_ll = seen_ll
        .lock()
        .unwrap()
        .iter()
        .filter(|pkt| pkt.data_type() == ipc_message)
        .count();
    assert_eq!(ipc_count_net, 0);
    assert_eq!(ipc_count_ll, 1);
}

#[test]
fn discovery_hides_link_local_endpoints_from_network_sides() {
    let Some(software_bus) = endpoint_by_name("SOFTWARE_BUS") else {
        return;
    };
    let seen_net: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_ll: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_net_c = seen_net.clone();
    let seen_ll_c = seen_ll.clone();

    let router = Router::new_with_clock(
        RouterConfig::new(vec![
            EndpointHandler::new_packet_handler(software_bus, |_pkt| Ok(())),
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), |_pkt| Ok(())),
        ]),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_net_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet_with_options(
        "LL",
        move |pkt: &Packet| -> TelemetryResult<()> {
            seen_ll_c.lock().unwrap().push(pkt.clone());
            Ok(())
        },
        RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: true,
            ..RouterSideOptions::default()
        },
    );

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let net = seen_net.lock().unwrap().clone();
    let ll = seen_ll.lock().unwrap().clone();
    let net_announce = net
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .unwrap();
    let ll_announce = ll
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .unwrap();
    let net_eps = crate::discovery::decode_discovery_address(net_announce)
        .unwrap()
        .reachable_endpoints;
    let ll_eps = crate::discovery::decode_discovery_address(ll_announce)
        .unwrap()
        .reachable_endpoints;
    assert!(!net_eps.contains(&software_bus));
    assert!(net_eps.contains(&DataEndpoint::named("RADIO")));
    assert!(ll_eps.contains(&software_bus));
}

#[cfg(feature = "timesync")]
#[test]
fn discovery_keeps_timesync_endpoint_out_of_user_reachability_when_enabled() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let topo = router.export_topology();
    assert!(!topo.advertised_endpoints.contains(&DataEndpoint::TimeSync));
}

#[cfg(all(feature = "timesync", feature = "discovery"))]
#[test]
fn timesync_packets_use_discovery_candidates_instead_of_flooding() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
        zero_clock(),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let discovery_pkt = build_discovery_timesync_sources("REMOTE_A", 0, &["REMOTE_A"]).unwrap();
    router.rx_from_side(&discovery_pkt, side_a).unwrap();
    let announce =
        crate::timesync::build_timesync_announce_with_sender("REMOTE_A", 1, 1_000).unwrap();
    router.rx_from_side(&announce, side_a).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let request = crate::timesync::build_timesync_request(1, 123).unwrap();
    router.tx(request).unwrap();

    assert_eq!(seen_a.lock().unwrap().len(), 1);
    assert!(seen_b.lock().unwrap().is_empty());
    assert_eq!(
        seen_a.lock().unwrap()[0].data_type(),
        DataType::TimeSyncRequest
    );
}

#[cfg(all(feature = "timesync", feature = "discovery"))]
#[test]
fn timesync_announcements_propagate_away_from_the_source() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();
    let relay = Router::new_with_clock(RouterConfig::default().with_sender("RELAY"), zero_clock());
    let side_a = relay.add_side_packet("source", move |packet: &Packet| {
        seen_a_c.lock().unwrap().push(packet.clone());
        Ok(())
    });
    relay.add_side_packet("downstream", move |packet: &Packet| {
        seen_b_c.lock().unwrap().push(packet.clone());
        Ok(())
    });

    let announce = crate::timesync::build_timesync_announce_with_sender("RF", 1, 1_000).unwrap();
    relay.rx_from_side(&announce, side_a).unwrap();

    assert!(seen_a.lock().unwrap().is_empty());
    assert_eq!(
        count_packets_of_type(&seen_b.lock().unwrap(), DataType::TimeSyncAnnounce),
        1,
    );
}

#[cfg(feature = "timesync")]
#[test]
fn discovery_advertises_local_timesync_source_ids() {
    let seen: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Source,
            ..Default::default()
        }),
        zero_clock(),
    );
    router.add_side_packet("NET", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    router.announce_discovery().unwrap();
    router.process_tx_queue().unwrap();

    let pkts = seen.lock().unwrap().clone();
    let src_pkt = pkts
        .iter()
        .find(|pkt| pkt.data_type() == DataType::DiscoveryAddress)
        .unwrap();
    let sources = crate::discovery::decode_discovery_address(src_pkt)
        .unwrap()
        .reachable_timesync_sources;
    assert!(sources.contains(&crate::config::DEVICE_IDENTIFIER.to_string()));
}

#[cfg(all(feature = "timesync", feature = "discovery"))]
#[test]
fn timesync_requests_prefer_exact_discovered_source_route() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig::default()),
        zero_clock(),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let side_b = router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let generic_timesync =
        build_discovery_announce("SIDE_A", 0, &[DataEndpoint::TimeSync]).unwrap();
    router.rx_from_side(&generic_timesync, side_a).unwrap();
    let exact_source = build_discovery_timesync_sources("SIDE_B", 0, &["SRC_BEST"]).unwrap();
    router.rx_from_side(&exact_source, side_b).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let source_announce =
        crate::timesync::build_timesync_announce_with_sender("SRC_BEST", 1, 1000).unwrap();
    router.rx(&source_announce).unwrap();
    seen_a.lock().unwrap().clear();
    seen_b.lock().unwrap().clear();

    let request = crate::timesync::build_timesync_request(1, 123).unwrap();
    router.tx(request).unwrap();

    assert!(seen_a.lock().unwrap().is_empty());
    assert_eq!(seen_b.lock().unwrap().len(), 1);
    assert_eq!(
        seen_b.lock().unwrap()[0].data_type(),
        DataType::TimeSyncRequest
    );
}

#[cfg(feature = "timesync")]
#[test]
fn timesync_responses_return_only_to_requesting_side() {
    let seen_a: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_b: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_a_c = seen_a.clone();
    let seen_b_c = seen_b.clone();

    let router = Router::new_with_clock(
        RouterConfig::default().with_timesync(crate::timesync::TimeSyncConfig {
            role: crate::timesync::TimeSyncRole::Source,
            ..Default::default()
        }),
        zero_clock(),
    );
    let side_a = router.add_side_packet("A", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_a_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    router.add_side_packet("B", move |pkt: &Packet| -> TelemetryResult<()> {
        seen_b_c.lock().unwrap().push(pkt.clone());
        Ok(())
    });

    let request = crate::timesync::build_timesync_request(7, 111).unwrap();
    router.rx_from_side(&request, side_a).unwrap();
    router.process_tx_queue().unwrap();

    let got_a = seen_a.lock().unwrap().clone();
    let got_b = seen_b.lock().unwrap().clone();
    assert_eq!(
        got_a
            .iter()
            .filter(|pkt| pkt.data_type() == DataType::TimeSyncResponse)
            .count(),
        1
    );
    assert_eq!(
        got_b
            .iter()
            .filter(|pkt| pkt.data_type() == DataType::TimeSyncResponse)
            .count(),
        0
    );
}

#[test]
fn managed_variable_request_replays_latest_value_to_endpoint_handler() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");

    let seen_client: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_client_c = seen_client.clone();

    let source = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_sender("SOURCE"),
        zero_clock(),
    ));
    source.enable_managed_variable(ty).unwrap();
    source.log(ty, &[1.0_f32, 2.0, 3.0]).unwrap();

    let client = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            ep,
            move |pkt: &Packet| {
                seen_client_c.lock().unwrap().push(pkt.clone());
                Ok(())
            },
        )])
        .with_sender("CLIENT_RESTARTED"),
        zero_clock(),
    ));

    client.enable_managed_variable(ty).unwrap();

    let client_for_source = client.clone();
    source.add_side_packet("to-client", move |pkt: &Packet| {
        client_for_source.rx_from_side(pkt, 0)
    });
    let source_for_client = source.clone();
    client.add_side_packet("to-source", move |pkt: &Packet| {
        source_for_client.rx_from_side(pkt, 0)
    });

    client.request_managed_variable(ty).unwrap();
    source.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    let seen = seen_client.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].data_type(), ty);
    assert_eq!(seen[0].data_as_f32().unwrap(), vec![1.0, 2.0, 3.0]);
}

#[test]
fn read_only_variable_replica_relays_refresh_request() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let forwarded: Arc<Mutex<Vec<Packet>>> = Arc::new(Mutex::new(Vec::new()));
    let forwarded_cb = forwarded.clone();
    let bridge = Router::new_with_clock(
        RouterConfig::default().with_sender("READ_ONLY_BRIDGE"),
        zero_clock(),
    );
    bridge
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    bridge
        .seed_managed_variable(
            Packet::from_f32_slice(ty, &[1.0_f32, 2.0, 3.0], &[DataEndpoint::named("RADIO")], 0)
                .unwrap(),
        )
        .unwrap();
    let ingress = bridge.add_side_packet("client", |_packet| Ok(()));
    bridge.add_side_packet("owner", move |packet| {
        forwarded_cb.lock().unwrap().push(packet.clone());
        Ok(())
    });

    let request = crate::discovery::build_managed_variable_request("CLIENT", 1, ty).unwrap();
    bridge.rx_from_side(&request, ingress).unwrap();
    bridge.process_all_queues().unwrap();

    assert!(forwarded.lock().unwrap().iter().any(|packet| {
        packet.data_type() == DataType::ManagedVariableRequest
            && crate::discovery::decode_managed_variable_request(packet) == Ok(ty)
    }));
    let topology = bridge.export_topology();
    let client_route = topology
        .routes
        .iter()
        .find(|route| route.side_id == ingress)
        .expect("request ingress becomes a discovered subscriber route");
    assert!(client_route.reachable_network_variables.contains(&ty));
    assert!(client_route.announcers.is_empty());
}

#[test]
fn network_variable_getter_requests_missing_value_and_uses_cache() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");

    let source = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_sender("NV_SOURCE"),
        zero_clock(),
    ));
    let value = Packet::from_f32_slice(ty, &[9.0_f32, 8.0, 7.0], &[ep], 1).unwrap();
    source.seed_managed_variable(value).unwrap();

    let client = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_sender("NV_CLIENT"),
        zero_clock(),
    ));

    let client_for_source = client.clone();
    source.add_side_packet("to-client", move |pkt: &Packet| {
        client_for_source.rx_from_side(pkt, 0)
    });
    let source_for_client = source.clone();
    client.add_side_packet("to-source", move |pkt: &Packet| {
        source_for_client.rx_from_side(pkt, 0)
    });

    assert!(client.get_network_variable(ty, None).unwrap().is_none());
    source.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    let cached = client.get_network_variable(ty, None).unwrap().unwrap();
    assert_eq!(cached.data_as_f32().unwrap(), vec![9.0, 8.0, 7.0]);
}

#[test]
fn network_variable_update_callback_runs_on_inbound_cache_change() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");

    let source = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_sender("NV_SOURCE_CB"),
        zero_clock(),
    ));
    let value = Packet::from_f32_slice(ty, &[4.0_f32, 5.0, 6.0], &[ep], 1).unwrap();
    source.seed_managed_variable(value).unwrap();

    let client = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_sender("NV_CLIENT_CB"),
        zero_clock(),
    ));
    let callback_values = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
    let callback_values_c = callback_values.clone();
    client
        .on_network_variable_update(ty, move |pkt| {
            callback_values_c.lock().unwrap().push(pkt.data_as_f32()?);
            Ok(())
        })
        .unwrap();

    let client_for_source = client.clone();
    source.add_side_packet("to-client", move |pkt: &Packet| {
        client_for_source.rx_from_side(pkt, 0)
    });
    let source_for_client = source.clone();
    client.add_side_packet("to-source", move |pkt: &Packet| {
        source_for_client.rx_from_side(pkt, 0)
    });

    assert!(client.get_network_variable(ty, None).unwrap().is_none());
    source.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    assert_eq!(
        *callback_values.lock().unwrap(),
        vec![vec![4.0_f32, 5.0, 6.0]]
    );
    client.process_all_queues().unwrap();
    assert_eq!(callback_values.lock().unwrap().len(), 1);
}

#[test]
fn network_variable_rejects_an_out_of_order_older_update() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("wire", |_pkt| Ok(()));
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let observed = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
    let observed_c = observed.clone();
    router
        .on_network_variable_update(ty, move |pkt| {
            observed_c.lock().unwrap().push(pkt.data_as_f32()?);
            Ok(())
        })
        .unwrap();

    let newest = Packet::from_f32_slice(ty, &[1.0, 1.0, 1.0], &[ep], 200)
        .unwrap()
        .with_nonce(3);
    let older = Packet::from_f32_slice(ty, &[0.0, 0.0, 0.0], &[ep], 100)
        .unwrap()
        .with_nonce(2);
    router.rx_from_side(&newest, side).unwrap();
    router.rx_from_side(&older, side).unwrap();

    assert_eq!(
        router
            .get_cached_network_variable(ty)
            .unwrap()
            .unwrap()
            .data_as_f32()
            .unwrap(),
        vec![1.0, 1.0, 1.0]
    );
    assert_eq!(*observed.lock().unwrap(), vec![vec![1.0, 1.0, 1.0]]);
}

#[test]
fn network_variable_accepts_rapid_same_timestamp_updates() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packet("wire", |_pkt| Ok(()));
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();

    let first = Packet::from_f32_slice(ty, &[1.0, 1.0, 1.0], &[ep], 0)
        .unwrap()
        .with_nonce(u16::MAX);
    let second = Packet::from_f32_slice(ty, &[0.0, 0.0, 0.0], &[ep], 0)
        .unwrap()
        .with_nonce(1);
    router.rx_from_side(&first, side).unwrap();
    router.rx_from_side(&second, side).unwrap();

    assert_eq!(
        router
            .get_cached_network_variable(ty)
            .unwrap()
            .unwrap()
            .data_as_f32()
            .unwrap(),
        vec![0.0, 0.0, 0.0]
    );
}

#[test]
fn compact_sender_alias_cannot_roll_back_a_newer_managed_value() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    let side = router.add_side_packed("wire", |_bytes| Ok(()));
    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();

    let newest = Packet::new(
        ty,
        &[ep],
        "GROUND_STATION",
        200,
        Arc::from([1.0_f32, 1.0, 1.0].map(f32::to_le_bytes).concat()),
    )
    .unwrap();
    router.seed_managed_variable(newest).unwrap();

    let stale = Packet::new(
        ty,
        &[ep],
        "GROUND_STATION",
        100,
        Arc::from([0.0_f32, 0.0, 0.0].map(f32::to_le_bytes).concat()),
    )
    .unwrap();
    let stale_wire = crate::wire_format::pack_packet(&stale);
    router.rx_packed_from_side(&stale_wire, side).unwrap();

    assert_eq!(
        router
            .get_cached_network_variable(ty)
            .unwrap()
            .unwrap()
            .data_as_f32()
            .unwrap(),
        vec![1.0, 1.0, 1.0]
    );
}

#[test]
fn network_variable_setter_caches_and_respects_permissions() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))]),
        zero_clock(),
    );
    let pkt = Packet::from_f32_slice(ty, &[1.0_f32, 2.0, 3.0], &[ep], 1).unwrap();

    router.set_network_variable(pkt.clone()).unwrap();
    assert_eq!(
        router
            .get_cached_network_variable(ty)
            .unwrap()
            .unwrap()
            .data_as_f32()
            .unwrap(),
        vec![1.0, 2.0, 3.0]
    );

    router
        .enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    assert_eq!(
        router.set_network_variable(pkt),
        Err(TelemetryError::PermissionDenied)
    );
    router
        .enable_network_variable(ty, NetworkVariablePermissions::WRITE_ONLY)
        .unwrap();
    assert_eq!(
        router.get_cached_network_variable(ty),
        Err(TelemetryError::PermissionDenied)
    );
}

#[test]
fn reentrant_network_variable_update_precedes_ordinary_user_queue() {
    use std::sync::Weak;
    use std::sync::atomic::AtomicBool;

    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let router_slot = Arc::new(Mutex::new(Weak::<Router>::new()));
    let seen = Arc::new(Mutex::new(Vec::<Vec<f32>>::new()));
    let injected = Arc::new(AtomicBool::new(false));

    let router = Arc::new(Router::new_with_clock(
        RouterConfig::default().with_sender("NV_PRIORITY"),
        zero_clock(),
    ));
    *router_slot.lock().unwrap() = Arc::downgrade(&router);

    let router_slot_c = router_slot.clone();
    let seen_c = seen.clone();
    let injected_c = injected.clone();
    router.add_side_packet("wire", move |pkt: &Packet| {
        if pkt.data_type() == ty {
            seen_c.lock().unwrap().push(pkt.data_as_f32()?);
            if !injected_c.swap(true, Ordering::SeqCst) {
                router_slot_c
                    .lock()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .set_network_variable(Packet::from_f32_slice(
                        ty,
                        &[4.0, 5.0, 6.0],
                        &[ep],
                        2,
                    )?)?;
            }
        }
        Ok(())
    });

    router
        .tx(Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[ep], 1).unwrap())
        .unwrap();
    seen.lock().unwrap().clear();
    router
        .tx_queue(Packet::from_f32_slice(ty, &[7.0, 8.0, 9.0], &[ep], 3).unwrap())
        .unwrap();
    router.process_all_queues().unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![vec![4.0, 5.0, 6.0], vec![7.0, 8.0, 9.0]]
    );
}

#[test]
fn compact_transport_callback_preserves_network_variable_priority() {
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let ep = DataEndpoint::named("RADIO");
    let priorities = Arc::new(Mutex::new(Vec::<u8>::new()));
    let priorities_c = priorities.clone();
    let router = Router::new_with_clock(
        RouterConfig::default().with_sender("NV_WIRE_PRIORITY"),
        zero_clock(),
    );
    router.add_side_packed_with_priority_and_options(
        "wire",
        move |_frame, priority| {
            priorities_c.lock().unwrap().push(priority);
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(24),
    );

    router
        .set_network_variable(Packet::from_f32_slice(ty, &[1.0, 2.0, 3.0], &[ep], 1).unwrap())
        .unwrap();

    let priorities = priorities.lock().unwrap();
    assert!(
        priorities.len() > 1,
        "test packet should use transport chunks"
    );
    assert!(priorities.iter().all(|priority| *priority == 254));
}

#[test]
fn router_and_relay_memory_layout_exports_queue_breakdown() {
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    let memory = crate::config::RuntimeMemoryConfig::new(4096, 8, 512, 2.0).unwrap();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_memory_config(memory)
            .unwrap(),
        zero_clock(),
    );
    let router_json: serde_json::Value =
        serde_json::from_str(&router.export_memory_layout_json()).unwrap();
    assert_eq!(router_json["kind"], "router");
    assert_eq!(router_json["shared_queue_bytes_allocated"], 4096);
    assert!(
        router_json["shared_queue_bytes_allocated"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(router_json["rx_queue_bytes_used"].is_u64());
    assert!(router_json["tx_queue_bytes_allocated"].as_u64().unwrap() > 0);
    assert!(router_json["network_variable_cache_bytes_used"].is_u64());
    assert_eq!(router_json["recent_rx_bytes_allocated"], 64);

    let relay_cfg = crate::relay::RelayConfig::default()
        .with_memory_config(memory)
        .unwrap();
    let relay = Relay::new_with_config(relay_cfg, zero_clock());
    let relay_json: serde_json::Value =
        serde_json::from_str(&relay.export_memory_layout_json()).unwrap();
    assert_eq!(relay_json["kind"], "relay");
    assert_eq!(relay_json["shared_queue_bytes_allocated"], 4096);
    assert!(relay_json["shared_queue_bytes_allocated"].as_u64().unwrap() > 0);
    assert!(relay_json["rx_queue_bytes_used"].is_u64());
    assert!(relay_json["replay_queue_bytes_allocated"].as_u64().unwrap() > 0);
    assert_eq!(relay_json["recent_rx_bytes_allocated"], 64);
}

#[test]
fn router_runtime_memory_budget_caps_queued_state() {
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    // Leave room for the initial discovery snapshot, then verify that
    // sustained user traffic remains within the shared pool.
    let memory = crate::config::RuntimeMemoryConfig::new(16_384, 8, 512, 1.5).unwrap();
    let router = Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, |_pkt| Ok(()))])
            .with_memory_config(memory)
            .unwrap(),
        zero_clock(),
    );
    router.add_side_packed("budget-link", |_bytes| Ok(()));

    for idx in 0..300u64 {
        router
            .log_queue_ts(
                DataType::named("GPS_DATA"),
                idx,
                &[idx as f32, 2.0_f32, 3.0_f32],
            )
            .unwrap();
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[9.0_f32, 8.0_f32, idx as f32],
            &[DataEndpoint::named("SD_CARD")],
            idx + 10_000,
        )
        .unwrap();
        router.rx_queue(pkt).unwrap();
    }

    let json: serde_json::Value =
        serde_json::from_str(&router.export_memory_layout_json()).unwrap();
    let used = json["shared_queue_bytes_used"].as_u64().unwrap();
    let allocated = json["shared_queue_bytes_allocated"].as_u64().unwrap();
    assert_eq!(allocated, 16_384);
    assert!(
        used <= allocated,
        "router queued state exceeded runtime memory budget: used={used} allocated={allocated}"
    );
    assert!(router.debug_shared_queue_bytes_used() <= 16_384);
    assert!(
        json["rx_queue_len"].as_u64().unwrap() + json["tx_queue_len"].as_u64().unwrap() < 600,
        "low budget should evict older queued work instead of growing without bound"
    );
}

#[test]
fn relay_runtime_memory_budget_caps_queued_state() {
    crate::tests::ensure_common_test_schema();
    let memory = crate::config::RuntimeMemoryConfig::new(8192, 8, 512, 1.5).unwrap();
    let relay_cfg = crate::relay::RelayConfig::default()
        .with_memory_config(memory)
        .unwrap();
    let relay = Relay::new_with_config(relay_cfg, zero_clock());
    let side_a = relay.add_side_packet("A", |_pkt| Ok(()));
    relay.add_side_packet("B", |_pkt| Ok(()));

    for idx in 0..400u64 {
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[idx as f32, 4.0_f32, 5.0_f32],
            &[DataEndpoint::named("RADIO")],
            idx,
        )
        .unwrap();
        relay.rx_from_side(side_a, pkt).unwrap();
    }

    let json: serde_json::Value = serde_json::from_str(&relay.export_memory_layout_json()).unwrap();
    let used = json["shared_queue_bytes_used"].as_u64().unwrap();
    let allocated = json["shared_queue_bytes_allocated"].as_u64().unwrap();
    assert_eq!(allocated, 8192);
    assert!(
        used <= allocated,
        "relay queued state exceeded runtime memory budget: used={used} allocated={allocated}"
    );
    assert!(
        json["rx_queue_len"].as_u64().unwrap() < 400,
        "low budget should evict older relay RX work instead of growing without bound"
    );
}

#[test]
fn required_e2e_type_rejects_tx_without_crypto_support() {
    #[cfg(feature = "cryptography")]
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType(3_901);
    let _ = remove_data_type(ty);
    register_data_type_id_with_description_and_e2e_encryption(
        ty,
        "E2E_REQUIRED_TEST",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
        E2eEncryptionPolicy::RequireOn,
    )
    .unwrap();

    let router = Router::new_with_clock(RouterConfig::default(), zero_clock());
    assert_eq!(router.log(ty, &[7_u8]), Err(TelemetryError::BadArg));

    let _ = remove_data_type(ty);
}

#[test]
fn forced_e2e_router_rejects_plain_user_data_without_crypto_support() {
    #[cfg(feature = "cryptography")]
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    let ty = DataType::named("GPS_DATA");
    let router = Router::new_with_clock(
        RouterConfig::default().with_e2e_encryption(RouterE2eEncryptionMode::ForceAll),
        zero_clock(),
    );
    assert_eq!(
        router.log(ty, &[1.0_f32, 2.0, 3.0]),
        Err(TelemetryError::BadArg)
    );
}

#[cfg(feature = "cryptography")]
unsafe extern "C" fn test_crypto_seal(
    key_id: u32,
    _nonce: *const u8,
    _nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_cap: usize,
    ciphertext_len_out: *mut usize,
    tag_out: *mut u8,
    tag_cap: usize,
    tag_len_out: *mut usize,
    _user: *mut core::ffi::c_void,
) -> i32 {
    if ciphertext_cap < plaintext_len || tag_cap < 4 {
        return -1;
    }
    let plain = unsafe { core::slice::from_raw_parts(plaintext, plaintext_len) };
    let out = unsafe { core::slice::from_raw_parts_mut(ciphertext_out, ciphertext_cap) };
    for (idx, byte) in plain.iter().copied().enumerate() {
        out[idx] = byte ^ key_id as u8 ^ 0xA5;
    }
    let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
    let mut tag = [0u8; 4];
    for (idx, byte) in aad.iter().copied().enumerate() {
        tag[idx % 4] ^= byte;
    }
    for idx in 0..plaintext_len {
        tag[idx % 4] ^= out[idx];
    }
    tag[0] ^= key_id as u8;
    let tag_out = unsafe { core::slice::from_raw_parts_mut(tag_out, tag_cap) };
    tag_out[..4].copy_from_slice(&tag);
    unsafe {
        *ciphertext_len_out = plaintext_len;
        *tag_len_out = 4;
    }
    0
}

#[cfg(feature = "cryptography")]
unsafe extern "C" fn test_crypto_open(
    key_id: u32,
    _nonce: *const u8,
    _nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    tag_len: usize,
    plaintext_out: *mut u8,
    plaintext_cap: usize,
    plaintext_len_out: *mut usize,
    _user: *mut core::ffi::c_void,
) -> i32 {
    if plaintext_cap < ciphertext_len || tag_len != 4 {
        return -1;
    }
    let aad = unsafe { core::slice::from_raw_parts(aad, aad_len) };
    let mut expected = [0u8; 4];
    for (idx, byte) in aad.iter().copied().enumerate() {
        expected[idx % 4] ^= byte;
    }
    let cipher = unsafe { core::slice::from_raw_parts(ciphertext, ciphertext_len) };
    for (idx, byte) in cipher.iter().copied().enumerate() {
        expected[idx % 4] ^= byte;
    }
    expected[0] ^= key_id as u8;
    let tag = unsafe { core::slice::from_raw_parts(tag, tag_len) };
    if tag != expected {
        return -1;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(plaintext_out, plaintext_cap) };
    for (idx, byte) in cipher.iter().copied().enumerate() {
        out[idx] = byte ^ key_id as u8 ^ 0xA5;
    }
    unsafe {
        *plaintext_len_out = ciphertext_len;
    }
    0
}

#[cfg(feature = "cryptography")]
fn refresh_crc32(bytes: &mut [u8]) {
    let data_len = bytes.len() - 4;
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..data_len]);
    let crc = hasher.finalize();
    bytes[data_len..].copy_from_slice(&crc.to_le_bytes());
}

#[cfg(feature = "cryptography")]
fn register_test_encryption() {
    crate::crypto::register_c_cryptography_provider(crate::crypto::CCryptographyProvider {
        seal: Some(test_crypto_seal),
        open: Some(test_crypto_open),
        user: core::ptr::null_mut(),
    });
}

#[cfg(feature = "cryptography")]
#[test]
fn preferred_e2e_type_seals_packed_side_payload_and_roundtrips() {
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    register_test_encryption();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType(3_902);
    let _ = remove_data_type(ty);
    register_data_type_id_with_description_and_e2e_encryption(
        ty,
        "E2E_PREFERRED_TEST",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
        E2eEncryptionPolicy::PreferOn,
    )
    .unwrap();

    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured_for_side = captured.clone();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_e2e_encryption(RouterE2eEncryptionMode::Preferred)
            .with_e2e_key_id(0x5A),
        zero_clock(),
    );
    router.add_side_packed("crypto-link", move |bytes| {
        *captured_for_side.lock().unwrap() = bytes.to_vec();
        Ok(())
    });

    let payload = [1_u8, 2, 3, 4, 5, 6];
    router.log(ty, &payload).unwrap();
    let wire = captured.lock().unwrap().clone();
    assert!(!wire.windows(payload.len()).any(|window| window == payload));
    let decoded = wire_format::unpack_packet(&wire).unwrap();
    assert_eq!(decoded.data_type(), ty);
    assert_eq!(decoded.payload(), payload);

    let _ = remove_data_type(ty);
    crate::crypto::clear_c_cryptography_provider();
}

#[cfg(feature = "cryptography")]
#[test]
fn software_crypto_fallback_seals_payload_when_no_shim_is_registered() {
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    crate::crypto::register_software_key(0x91, b"0123456789abcdef0123456789abcdef").unwrap();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType(3_905);
    let _ = remove_data_type(ty);
    register_data_type_id_with_description_and_e2e_encryption(
        ty,
        "E2E_SOFTWARE_FALLBACK_TEST",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
        E2eEncryptionPolicy::PreferOn,
    )
    .unwrap();

    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured_for_side = captured.clone();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_e2e_encryption(RouterE2eEncryptionMode::Preferred)
            .with_e2e_key_id(0x91),
        zero_clock(),
    );
    router.add_side_packed("software-crypto-link", move |bytes| {
        *captured_for_side.lock().unwrap() = bytes.to_vec();
        Ok(())
    });

    let payload = [3_u8, 1, 4, 1, 5, 9, 2, 6];
    router.log(ty, &payload).unwrap();
    let wire = captured.lock().unwrap().clone();
    assert!(!wire.windows(payload.len()).any(|window| window == payload));
    let decoded = wire_format::unpack_packet(&wire).unwrap();
    assert_eq!(decoded.data_type(), ty);
    assert_eq!(decoded.payload(), payload);

    let mut tampered = wire;
    let data_len = tampered.len() - 4;
    tampered[data_len - 1] ^= 0x20;
    refresh_crc32(&mut tampered);
    assert!(wire_format::unpack_packet(&tampered).is_err());

    let _ = remove_data_type(ty);
}

#[cfg(feature = "cryptography")]
#[test]
fn encrypted_payload_rejects_authenticated_header_tamper() {
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    register_test_encryption();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType(3_903);
    let _ = remove_data_type(ty);
    register_data_type_id_with_description_and_e2e_encryption(
        ty,
        "E2E_TAMPER_TEST",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
        E2eEncryptionPolicy::RequireOn,
    )
    .unwrap();

    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let captured_for_side = captured.clone();
    let router = Router::new_with_clock(
        RouterConfig::default()
            .with_e2e_encryption(RouterE2eEncryptionMode::RequiredOnly)
            .with_e2e_key_id(0x33),
        zero_clock(),
    );
    router.add_side_packed("crypto-link", move |bytes| {
        *captured_for_side.lock().unwrap() = bytes.to_vec();
        Ok(())
    });

    router.log(ty, &[9_u8, 8, 7, 6]).unwrap();
    let mut wire = captured.lock().unwrap().clone();
    wire[1] ^= 0x01;
    refresh_crc32(&mut wire);
    assert!(wire_format::unpack_packet(&wire).is_err());

    let _ = remove_data_type(ty);
    crate::crypto::clear_c_cryptography_provider();
}

#[cfg(feature = "cryptography")]
#[test]
fn preferred_e2e_fanout_reaches_three_boards_with_same_endpoint_and_rejects_mods() {
    let _crypto_guard = crypto_test_guard();
    crate::tests::ensure_common_test_schema();
    register_test_encryption();
    let ep = DataEndpoint::named("RADIO");
    let ty = DataType(3_904);
    let _ = remove_data_type(ty);
    register_data_type_id_with_description_and_e2e_encryption(
        ty,
        "E2E_THREE_BOARD_RADIO_TEST",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        10,
        E2eEncryptionPolicy::PreferOn,
    )
    .unwrap();

    let seen_a = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let seen_b = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let seen_c = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

    let mk_board = |name: &'static str, seen: Arc<Mutex<Vec<Vec<u8>>>>| {
        Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(ep, move |pkt| {
                seen.lock().unwrap().push(pkt.payload().to_vec());
                Ok(())
            })])
            .with_sender(name)
            .with_e2e_key_id(0x44),
            zero_clock(),
        )
    };

    let board_a = Arc::new(mk_board("BOARD_A", seen_a.clone()));
    let board_b = Arc::new(mk_board("BOARD_B", seen_b.clone()));
    let board_c = Arc::new(mk_board("BOARD_C", seen_c.clone()));
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));

    let source = Router::new_with_clock(
        RouterConfig::default()
            .with_sender("SOURCE")
            .with_e2e_key_id(0x44),
        zero_clock(),
    );

    let a = board_a.clone();
    let b = board_b.clone();
    let c = board_c.clone();
    let captured_for_side = captured.clone();
    source.add_side_packed("shared-radio", move |bytes| {
        *captured_for_side.lock().unwrap() = bytes.to_vec();
        a.rx_packed(bytes)?;
        b.rx_packed(bytes)?;
        c.rx_packed(bytes)?;
        Ok(())
    });

    let payload = [42_u8, 9, 7, 1];
    source.log(ty, &payload).unwrap();
    assert_eq!(seen_a.lock().unwrap().as_slice(), &[payload.to_vec()]);
    assert_eq!(seen_b.lock().unwrap().as_slice(), &[payload.to_vec()]);
    assert_eq!(seen_c.lock().unwrap().as_slice(), &[payload.to_vec()]);

    let wire = captured.lock().unwrap().clone();
    assert!(!wire.windows(payload.len()).any(|window| window == payload));

    let mut header_tampered = wire.clone();
    header_tampered[1] ^= 0x01;
    refresh_crc32(&mut header_tampered);
    assert!(board_a.rx_packed(&header_tampered).is_err());

    let mut payload_tampered = wire;
    let data_len = payload_tampered.len() - 4;
    payload_tampered[data_len - 1] ^= 0x55;
    refresh_crc32(&mut payload_tampered);
    assert!(board_b.rx_packed(&payload_tampered).is_err());

    let _ = remove_data_type(ty);
    crate::crypto::clear_c_cryptography_provider();
}

#[test]
fn immediate_cross_wired_router_reentry_falls_back_to_queue() {
    let Some(ipc_message) = datatype_by_name("IPC_MESSAGE") else {
        return;
    };

    let remaining = Arc::new(AtomicUsize::new(6));
    let sequence = Arc::new(AtomicUsize::new(1));
    let a_slot = Arc::new(Mutex::new(None::<Arc<Router>>));
    let b_slot = Arc::new(Mutex::new(None::<Arc<Router>>));

    let a_remaining = remaining.clone();
    let a_sequence = sequence.clone();
    let a_router = a_slot.clone();
    let router_a = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("RADIO"),
            move |_pkt: &Packet| {
                if a_remaining
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_err()
                {
                    return Ok(());
                }
                let seq = a_sequence.fetch_add(1, Ordering::SeqCst) as u64;
                let pkt = Packet::new(
                    ipc_message,
                    &[DataEndpoint::named("SD_CARD")],
                    "A_NODE",
                    seq,
                    Arc::<[u8]>::from(b"bounce-a".as_slice()),
                )?;
                a_router
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("router A initialized")
                    .tx(pkt)
            },
        )])
        .with_sender("A_NODE"),
        StepClock::new_default_box(),
    ));

    let b_remaining = remaining.clone();
    let b_sequence = sequence.clone();
    let b_router = b_slot.clone();
    let router_b = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![EndpointHandler::new_packet_handler(
            DataEndpoint::named("SD_CARD"),
            move |_pkt: &Packet| {
                if b_remaining
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_err()
                {
                    return Ok(());
                }
                let seq = b_sequence.fetch_add(1, Ordering::SeqCst) as u64;
                let pkt = Packet::new(
                    ipc_message,
                    &[DataEndpoint::named("RADIO")],
                    "B_NODE",
                    seq,
                    Arc::<[u8]>::from(b"bounce-b".as_slice()),
                )?;
                b_router
                    .lock()
                    .unwrap()
                    .as_ref()
                    .expect("router B initialized")
                    .tx(pkt)
            },
        )])
        .with_sender("B_NODE"),
        StepClock::new_default_box(),
    ));

    *a_slot.lock().unwrap() = Some(router_a.clone());
    *b_slot.lock().unwrap() = Some(router_b.clone());

    let a_in_tx = Arc::new(AtomicBool::new(false));
    let a_reentered = Arc::new(AtomicBool::new(false));
    let b_in_tx = Arc::new(AtomicBool::new(false));
    let b_reentered = Arc::new(AtomicBool::new(false));

    let router_b_for_side = router_b.clone();
    let a_in_tx_flag = a_in_tx.clone();
    let a_reentered_flag = a_reentered.clone();
    let side_a = router_a.add_side_packet("A_TO_B", move |pkt: &Packet| {
        if a_in_tx_flag.swap(true, Ordering::SeqCst) {
            a_reentered_flag.store(true, Ordering::SeqCst);
        }
        let result = router_b_for_side.rx_from_side(pkt, 0);
        a_in_tx_flag.store(false, Ordering::SeqCst);
        result
    });

    let router_a_for_side = router_a.clone();
    let b_in_tx_flag = b_in_tx.clone();
    let b_reentered_flag = b_reentered.clone();
    let side_b = router_b.add_side_packet("B_TO_A", move |pkt: &Packet| {
        if b_in_tx_flag.swap(true, Ordering::SeqCst) {
            b_reentered_flag.store(true, Ordering::SeqCst);
        }
        let result = router_a_for_side.rx_from_side(pkt, 0);
        b_in_tx_flag.store(false, Ordering::SeqCst);
        result
    });

    assert_eq!(side_a, 0);
    assert_eq!(side_b, 0);

    let first = Packet::new(
        ipc_message,
        &[DataEndpoint::named("SD_CARD")],
        "START",
        0,
        Arc::<[u8]>::from(b"start".as_slice()),
    )
    .unwrap();
    router_a.tx(first).unwrap();

    for _ in 0..8 {
        router_a.process_all_queues().unwrap();
        router_b.process_all_queues().unwrap();
    }

    assert!(!a_reentered.load(Ordering::SeqCst));
    assert!(!b_reentered.load(Ordering::SeqCst));
    assert!(remaining.load(Ordering::SeqCst) < 6);
}
