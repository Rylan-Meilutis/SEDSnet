use super::*;
use std::sync::Mutex;

#[derive(Clone, Debug)]
struct Observed {
    kind: P2pStreamEventKind,
    address: u32,
    payload: Vec<u8>,
}
struct Fixture {
    r: Router,
    side: RouterSideId,
    events: Arc<Mutex<Vec<Observed>>>,
}
impl Fixture {
    fn new() -> Self {
        let r = Router::new_with_clock(
            RouterConfig::new([]).with_sender("TOPO_SOURCE"),
            Box::new(|| 0),
        );
        let side = r.add_side_packed("bridge", |_| Ok(()));
        let board = discovery::TopologyBoardNode {
            sender_id: "TOPO_BRIDGE".into(),
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec!["TOPO_LEAF".into()],
        };
        r.rx_from_side(
            &discovery::build_discovery_topology("TOPO_BRIDGE", 0, &[board]).unwrap(),
            side,
        )
        .unwrap();
        r.process_all_queues().unwrap();
        assert!(
            !r.address_book()
                .iter()
                .any(|p| p.hostname.as_ref() == "TOPO_LEAF")
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let output = events.clone();
        r.bind_p2p_stream_port(91, move |e| {
            output.lock().unwrap().push(Observed {
                kind: e.kind,
                address: e.peer_address,
                payload: e.payload.to_vec(),
            });
            Ok(())
        })
        .unwrap();
        Self { r, side, events }
    }
    fn open(&self) -> u32 {
        self.r
            .open_p2p_stream_to_hostname("TOPO_LEAF", 90, 91)
            .unwrap()
    }
    fn emit(
        &self,
        identity: (&str, &str, u32),
        ports: (u16, u16),
        flags: u8,
        ids: (u32, u32),
        body: &[u8],
    ) {
        let (sender, name, address) = identity;
        let stream = Router::encode_p2p_stream_payload(flags, ids.0, ids.1, 0, body).unwrap();
        let outer =
            Router::encode_p2p_payload(name, address, ports.0, ports.1, stream.as_ref()).unwrap();
        let packet = Packet::new(
            DataType::P2pMessage,
            &[DataEndpoint::Discovery],
            sender,
            0,
            Arc::from(outer.as_ref()),
        )
        .unwrap();
        let wire = wire_format::pack_packet(&packet);
        self.r.rx_packed_from_side(&wire, self.side).unwrap();
    }
    fn known(&self, address: u32) {
        let peer = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("TOPO_LEAF")
                .with_static_address(address),
            Box::new(|| 0),
        );
        let ad = peer.local_address_advertisement(
            vec![],
            vec![],
            vec![],
            discovery::LinkCapabilities {
                version: 1,
                flags: 0,
                profile: 0,
                max_frame_bytes: 0,
                compact_header_target_bytes: 0,
                max_side_transport_templates: 0,
            },
            0,
        );
        let staged = Router::prepare_address_record(&self.r.state.lock(), &ad, 0).unwrap();
        self.r.ingest_prepared_address(ad, staged).unwrap();
    }
    fn session(&self, id: u32) -> (u32, bool, u32, bool) {
        let st = self.r.state.lock();
        let s = &st.local_services.as_ref().unwrap().p2p_stream_sessions[&id];
        (
            s.peer_address,
            s.peer_address_bound,
            s.peer_stream_id,
            s.connected,
        )
    }
    fn revision(&self) -> u64 {
        self.r.state.lock().p2p_revision
    }
}
#[test]
fn topology_binding_provisional_early_data_then_synack_binds_zero_and_never_rebinds() {
    let f = Fixture::new();
    let id = f.open();
    let compact = sender_address_u32("TOPO_LEAF");
    assert_eq!(f.session(id), (compact, false, 0, false));
    // The existing actual codec permits declared node address0. It is not a
    // source-stream-ID sentinel and must survive first address binding.
    let outer = Router::encode_p2p_payload("TOPO_LEAF", 0, 90, 91, b"codec0").unwrap();
    assert_eq!(
        Router::decode_p2p_payload(outer.as_ref())
            .unwrap()
            .source_address,
        0
    );
    f.emit(
        ("TOPO_LEAF", "TOPO_LEAF", 0),
        (90, 91),
        P2P_STREAM_DATA,
        (7, id),
        b"early",
    );
    assert_eq!(f.session(id), (compact, false, 0, false));
    {
        let events = f.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, P2pStreamEventKind::Data);
        assert_eq!(events[0].address, 0);
        assert_eq!(events[0].payload, b"early");
    }
    f.emit(
        ("TOPO_LEAF", "TOPO_LEAF", 0),
        (90, 91),
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        (7, id),
        b"",
    );
    assert_eq!(f.session(id), (0, true, 7, true));
    let revision = f.revision();
    let count = f.events.lock().unwrap().len();
    for flags in [
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        P2P_STREAM_DATA,
        P2P_STREAM_FIN,
        P2P_STREAM_RST,
    ] {
        f.emit(("TOPO_LEAF", "TOPO_LEAF", 1), (90, 91), flags, (7, id), b"");
        assert_eq!(f.revision(), revision);
        assert_eq!(f.events.lock().unwrap().len(), count);
        assert_eq!(f.session(id), (0, true, 7, true));
    }
    f.emit(
        ("TOPO_LEAF", "TOPO_LEAF", 0),
        (90, 91),
        P2P_STREAM_DATA,
        (7, id),
        b"bound",
    );
    assert_eq!(f.events.lock().unwrap().last().unwrap().payload, b"bound");
}
#[test]
fn topology_binding_provisional_mismatches_are_inert_and_known_book_constrains_first_ack() {
    let f = Fixture::new();
    let id = f.open();
    let before = f.session(id);
    let rev = f.revision();
    for (sender, name, ports, ids) in [
        ("OTHER", "TOPO_LEAF", (90, 91), (7, id)),
        ("OTHER", "OTHER", (90, 91), (7, id)),
        ("TOPO_LEAF", "TOPO_LEAF", (92, 91), (7, id)),
        ("TOPO_LEAF", "TOPO_LEAF", (90, 92), (7, id)),
        ("TOPO_LEAF", "TOPO_LEAF", (90, 91), (7, id + 1)),
        ("TOPO_LEAF", "TOPO_LEAF", (90, 91), (0, id)),
    ] {
        f.emit(
            (sender, name, 77),
            ports,
            P2P_STREAM_SYN | P2P_STREAM_ACK,
            ids,
            b"",
        );
        assert_eq!(f.session(id), before);
        assert_eq!(f.revision(), rev);
        assert!(f.events.lock().unwrap().is_empty());
    }
    f.known(77);
    let rev = f.revision();
    f.emit(
        ("TOPO_LEAF", "TOPO_LEAF", 78),
        (90, 91),
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        (7, id),
        b"",
    );
    assert_eq!(f.session(id), before);
    assert_eq!(f.revision(), rev);
    assert!(f.events.lock().unwrap().is_empty());
    f.emit(
        ("TOPO_LEAF", "TOPO_LEAF", 77),
        (90, 91),
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        (7, id),
        b"",
    );
    assert_eq!(f.session(id), (77, true, 7, true));
}
#[test]
fn topology_binding_stale_assigned_target_never_becomes_provisional_before_allocation() {
    let f = Fixture::new();
    f.known(77);
    let old = f.r.resolve_hostname("TOPO_LEAF").unwrap();
    f.known(78);
    let before = {
        let st = f.r.state.lock();
        let s = st.local_services.as_ref().unwrap();
        (
            st.p2p_revision,
            s.next_p2p_stream_id,
            s.p2p_stream_sessions.len(),
        )
    };
    assert!(matches!(
        f.r.open_p2p_stream_to_entry(old, 90, 91),
        Err(TelemetryError::Io("p2p target identity changed"))
    ));
    let after = {
        let st = f.r.state.lock();
        let s = st.local_services.as_ref().unwrap();
        (
            st.p2p_revision,
            s.next_p2p_stream_id,
            s.p2p_stream_sessions.len(),
        )
    };
    assert_eq!(before, after);
}
#[test]
fn topology_binding_compact_alias_accepts_only_current_unique_topology_name() {
    let f = Fixture::new();
    let id = f.open();
    let alias = format!("@addr:{}", sender_address_u32("TOPO_LEAF"));
    assert!(f.r.sender_matches_hostname(&alias, "TOPO_LEAF"));
    let rev = f.revision();
    f.emit(
        ("@addr:0", "TOPO_LEAF", 77),
        (90, 91),
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        (7, id),
        b"",
    );
    assert_eq!(f.revision(), rev);
    assert_eq!(f.session(id).2, 0);
    f.emit(
        (&alias, "TOPO_LEAF", 77),
        (90, 91),
        P2P_STREAM_SYN | P2P_STREAM_ACK,
        (7, id),
        b"",
    );
    assert_eq!(f.session(id), (77, true, 7, true));
}
