//! Actual published runtime and SDK encoders; no application frame clone.
use super::*;
use std::sync::Mutex;
#[derive(Clone, Debug)]
struct Seen {
    kind: P2pStreamEventKind,
    id: u32,
    peer: String,
    source: u32,
    data: Vec<u8>,
}
type WireQueue = Arc<Mutex<Vec<(usize, usize, Vec<u8>)>>>;
pub(super) struct Mesh {
    pub(super) nodes: Vec<Router>,
    pub(super) wire: WireQueue,
    server: Arc<Mutex<Vec<Seen>>>,
    client: Arc<Mutex<Vec<Seen>>>,
}
impl Mesh {
    pub(super) fn new() -> Self {
        Self::new_with_reliable(true)
    }
    pub(super) fn new_with_reliable(reliable: bool) -> Self {
        let nodes: Vec<_> = ["CLIENT_A", "SERVICE_B", "CLIENT_C"]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                Router::new_with_clock(
                    RouterConfig::new([])
                        .with_sender(*n)
                        .with_static_address(31 + i as u32)
                        .with_reliable_enabled(reliable),
                    Box::new(|| 10000),
                )
            })
            .collect();
        let wire = Arc::new(Mutex::new(Vec::new()));
        for (left, right) in [(0, 1), (0, 2), (1, 2)] {
            let destination = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
            let slot = destination.clone();
            let queue = wire.clone();
            let a = nodes[left].add_side_packed(format!("{left}-{right}"), move |w| {
                queue.lock().unwrap().push((
                    right,
                    slot.load(core::sync::atomic::Ordering::SeqCst),
                    w.to_vec(),
                ));
                Ok(())
            });
            let queue = wire.clone();
            let b = nodes[right].add_side_packed(format!("{right}-{left}"), move |w| {
                queue.lock().unwrap().push((left, a, w.to_vec()));
                Ok(())
            });
            destination.store(b, core::sync::atomic::Ordering::SeqCst);
        }
        let server = Arc::new(Mutex::new(Vec::new()));
        let output = server.clone();
        nodes[1]
            .bind_p2p_stream_port(90, move |e| {
                output.lock().unwrap().push(Seen {
                    kind: e.kind,
                    id: e.stream_id,
                    peer: e.peer_hostname.into(),
                    source: e.peer_stream_id,
                    data: e.payload.to_vec(),
                });
                Ok(())
            })
            .unwrap();
        let client = Arc::new(Mutex::new(Vec::new()));
        let output = client.clone();
        nodes[0]
            .bind_p2p_stream_port(91, move |e| {
                output.lock().unwrap().push(Seen {
                    kind: e.kind,
                    id: e.stream_id,
                    peer: e.peer_hostname.into(),
                    source: e.peer_stream_id,
                    data: e.payload.to_vec(),
                });
                Ok(())
            })
            .unwrap();
        let m = Self {
            nodes,
            wire,
            server,
            client,
        };
        for n in &m.nodes {
            n.announce_discovery().unwrap();
        }
        m.pump();
        m
    }
    pub(super) fn pump(&self) {
        for _ in 0..30 {
            for n in &self.nodes {
                n.process_all_queues_with_timeout(0).unwrap();
            }
            let pending = { std::mem::take(&mut *self.wire.lock().unwrap()) };
            for (to, side, w) in pending {
                assert_ne!(side, usize::MAX);
                self.nodes[to].rx_packed_from_side(&w, side).unwrap();
            }
        }
    }
}
#[test]
fn published_p2p_tuple_binding_control() {
    if let Ok(case) = std::env::var("SEDSNET_P2P_CAUSAL_CASE") {
        run_binding_control(&case);
    } else {
        for case in [
            "data_foreign",
            "fin_foreign",
            "rst_foreign",
            "wrong_source_port",
            "wrong_destination_port",
            "wrong_source_stream",
            "synack_foreign",
            "synack_wrong_ports",
            "synack_existing_rebind",
            "zero_destination_uses_full_tuple",
            "positive_bound_data",
            "early_client_data_before_synack",
            "early_server_data_before_synack",
        ] {
            run_binding_control(case);
        }
    }
}
fn run_binding_control(case: &str) {
    let m = if case == "early_server_data_before_synack" {
        Mesh::new_with_reliable(false)
    } else {
        Mesh::new()
    };
    let a = m.nodes[0]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    if case == "early_client_data_before_synack" {
        assert_eq!(
            m.nodes[0]
                .state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .p2p_stream_sessions[&a]
                .peer_stream_id,
            0
        );
        m.nodes[0].send_p2p_stream(a, b"early-client").unwrap();
        m.pump();
        assert!(m.server.lock().unwrap().iter().any(|e| e.peer == "CLIENT_A"
            && e.kind == P2pStreamEventKind::Data
            && e.data == b"early-client"));
        println!("valid early CLIENT DATA from actual open before SYNACK preserved");
        return;
    }
    if case == "early_server_data_before_synack" {
        let pending = { std::mem::take(&mut *m.wire.lock().unwrap()) };
        for (to, side, wire) in pending {
            m.nodes[to].rx_packed_from_side(&wire, side).unwrap();
        }
        let server = m
            .server
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.kind == P2pStreamEventKind::Accepted && e.peer == "CLIENT_A")
            .unwrap()
            .id;
        assert_eq!(
            m.nodes[0]
                .state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .p2p_stream_sessions[&a]
                .peer_stream_id,
            0
        );
        m.nodes[1].send_p2p_stream(server, b"early-server").unwrap();
        let pending = { std::mem::take(&mut *m.wire.lock().unwrap()) };
        let mut held = Vec::new();
        let mut delivered = false;
        for (to, side, wire) in pending {
            let data = wire_format::unpack_packet(&wire)
                .ok()
                .filter(|p| p.data_type() == DataType::P2pMessage)
                .and_then(|p| {
                    let message = Router::decode_p2p_payload(p.payload()).ok()?;
                    Some(
                        Router::decode_p2p_stream_payload(message.payload)
                            .ok()??
                            .flags
                            & P2P_STREAM_DATA
                            != 0,
                    )
                })
                .unwrap_or(false);
            if to == 0 && data {
                m.nodes[to].rx_packed_from_side(&wire, side).unwrap();
                delivered = true;
            } else {
                held.push((to, side, wire));
            }
        }
        assert!(
            delivered,
            "actual no-hop-reliability profile must deliver held-server DATA independently of SYNACK"
        );
        assert_eq!(
            m.nodes[0]
                .state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .p2p_stream_sessions[&a]
                .peer_stream_id,
            0,
            "early DATA does not learn/rebind unknown peer stream"
        );
        assert!(
            m.client
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.peer == "SERVICE_B"
                    && e.kind == P2pStreamEventKind::Data
                    && e.data == b"early-server")
        );
        assert!(
            !m.client
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.kind == P2pStreamEventKind::Connected)
        );
        m.wire.lock().unwrap().extend(held);
        m.pump();
        assert_ne!(
            m.nodes[0]
                .state
                .lock()
                .local_services
                .as_ref()
                .unwrap()
                .p2p_stream_sessions[&a]
                .peer_stream_id,
            0
        );
        println!(
            "valid early SERVER DATA before held SYNACK preserved; peer0 never inferred from DATA"
        );
        return;
    }
    m.pump();
    let c = m.nodes[2]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    m.pump();
    assert_eq!(
        a, c,
        "independent clients genuinely collide in local stream ID"
    );
    let victim = m
        .server
        .lock()
        .unwrap()
        .iter()
        .find(|e| e.kind == P2pStreamEventKind::Accepted && e.peer == "CLIENT_A")
        .unwrap()
        .id;
    let own = m
        .server
        .lock()
        .unwrap()
        .iter()
        .find(|e| e.kind == P2pStreamEventKind::Accepted && e.peer == "CLIENT_C")
        .unwrap()
        .id;
    assert_ne!(victim, own);
    m.server.lock().unwrap().clear();
    m.client.lock().unwrap().clear();
    let before = m.nodes[0]
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .p2p_stream_sessions[&a]
        .peer_stream_id;
    let (mut actor, mut target, mut dst_port, mut src_port, mut source, mut destination, mut flags) =
        (2, "SERVICE_B", 90, 91, c, victim, P2P_STREAM_DATA);
    match case {
        "data_foreign" => {}
        "fin_foreign" => flags = P2P_STREAM_FIN,
        "rst_foreign" => flags = P2P_STREAM_RST,
        "wrong_source_port" => {
            actor = 0;
            src_port = 92
        }
        "wrong_destination_port" => {
            actor = 0;
            dst_port = 92
        }
        "wrong_source_stream" => {
            actor = 0;
            source = a + 77
        }
        "synack_foreign" => {
            target = "CLIENT_A";
            dst_port = 91;
            src_port = 90;
            destination = a;
            source = c + 77;
            flags = P2P_STREAM_SYN | P2P_STREAM_ACK
        }
        "synack_wrong_ports" => {
            actor = 1;
            target = "CLIENT_A";
            dst_port = 92;
            src_port = 93;
            destination = a;
            source = victim;
            flags = P2P_STREAM_SYN | P2P_STREAM_ACK
        }
        "synack_existing_rebind" => {
            actor = 1;
            target = "CLIENT_A";
            dst_port = 91;
            src_port = 90;
            destination = a;
            source = victim + 77;
            flags = P2P_STREAM_SYN | P2P_STREAM_ACK
        }
        "zero_destination_uses_full_tuple" => destination = 0,
        "positive_bound_data" => {
            actor = 0;
            source = a
        }
        _ => panic!("unknown case"),
    }
    let frame =
        Router::encode_p2p_stream_payload(flags, source, destination, 1, b"probe-origin").unwrap();
    m.nodes[actor]
        .send_p2p_to_hostname(target, dst_port, src_port, frame.as_ref())
        .unwrap();
    m.pump();
    let server = m.server.lock().unwrap().clone();
    let client = m.client.lock().unwrap().clone();
    let after = m.nodes[0]
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .p2p_stream_sessions[&a]
        .peer_stream_id;
    let present = m.nodes[1]
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .p2p_stream_sessions
        .contains_key(&victim);
    println!(
        "case={case} actual_actor={actor} real_client_collision={a} victim={victim} server={server:?} client={client:?} peer_before={before} peer_after={after} victim_present={present}"
    );
    if case == "positive_bound_data" {
        assert!(server.iter().any(|e| e.id == victim
            && e.peer == "CLIENT_A"
            && e.kind == P2pStreamEventKind::Data
            && e.source == a
            && e.data == b"probe-origin"));
    } else if case == "zero_destination_uses_full_tuple" {
        assert!(!server.iter().any(|e| e.id == victim));
        assert!(server.iter().any(|e| e.id == own && e.peer == "CLIENT_C"));
    } else {
        assert!(
            server.iter().all(|e| e.id != victim),
            "foreign/wrong tuple reached stored victim callback"
        );
        assert!(
            client.is_empty(),
            "foreign/wrong SYNACK emitted stored-peer callback"
        );
        assert_eq!(before, after, "SYNACK rebound established peer");
        assert!(present, "foreign FIN/RST removed legitimate session");
    }
}
