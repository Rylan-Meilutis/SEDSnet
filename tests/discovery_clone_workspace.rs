#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    TelemetryResult,
    discovery::{self, TopologyBoardNode},
    packet::Packet,
    relay::{Relay, RelayConfig},
    router::{Router, RouterConfig},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
    },
};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}
struct Meter;
#[global_allocator]
static ALLOCATOR: Meter = Meter;
fn charge(bytes: isize) {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = LIVE.try_with(|v| {
            let n = v.get() + bytes;
            v.set(n);
            let _ = PEAK.try_with(|p| p.set(p.get().max(n)));
        });
        if bytes > 0 {
            let _ = LARGEST.try_with(|v| v.set(v.get().max(bytes as usize)));
        }
    }
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            charge(layout.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        charge(-(layout.size() as isize));
        unsafe { System.dealloc(p, layout) }
    }
}
static LOCK: Mutex<()> = Mutex::new(());
static ENFORCE: AtomicBool = AtomicBool::new(false);
static CEILING: AtomicIsize = AtomicIsize::new(isize::MAX);
static DECLARED: AtomicUsize = AtomicUsize::new(0);
static DECLARED_LARGEST: AtomicUsize = AtomicUsize::new(0);
extern "C" fn probe(additional: usize, largest: usize) -> bool {
    DECLARED.fetch_max(additional, Ordering::Relaxed);
    DECLARED_LARGEST.fetch_max(largest, Ordering::Relaxed);
    !ENFORCE.load(Ordering::Relaxed)
        || LIVE.with(Cell::get).saturating_add(additional as isize)
            <= CEILING.load(Ordering::Relaxed)
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        sedsnet::memory_admission::set_probe(None);
        TRACK.with(|v| v.set(false));
        ENFORCE.store(false, Ordering::Relaxed);
    }
}
#[derive(Clone, Copy, Debug)]
enum Kind {
    Router,
    Relay,
}
enum Bridge {
    Router(Box<Router>),
    Relay(Box<Relay>),
}
impl Bridge {
    fn receive(&self, wire: &[u8]) -> TelemetryResult<()> {
        match self {
            Self::Router(n) => n.rx_packed_from_side(wire, 0),
            Self::Relay(n) => n.rx_packed_from_side(0, wire),
        }
    }
    fn drain(&self) -> TelemetryResult<()> {
        match self {
            Self::Router(n) => n.drain_queues_with_timeout(0),
            Self::Relay(n) => n.drain_queues_with_timeout(0),
        }
    }
    fn topology(&self) -> discovery::TopologySnapshot {
        match self {
            Self::Router(n) => n.export_topology(),
            Self::Relay(n) => n.export_topology(),
        }
    }
}
fn bridge(kind: Kind) -> Bridge {
    match kind {
        Kind::Router => {
            let n = Router::new_with_clock(
                RouterConfig::default()
                    .with_sender("GB")
                    .with_preferred_discovery_master("GS"),
                Box::new(|| 0),
            );
            assert_eq!(n.add_side_packed("can", |_| Ok(())), 0);
            n.add_side_packed("uart", |_| Ok(()));
            Bridge::Router(Box::new(n))
        }
        Kind::Relay => {
            let n =
                Relay::new_with_config(RelayConfig::default().with_sender("GB"), Box::new(|| 0));
            assert_eq!(n.add_side_packed("can", |_| Ok(())), 0);
            n.add_side_packed("uart", |_| Ok(()));
            Bridge::Relay(Box::new(n))
        }
    }
}
fn install(n: &Bridge, sender: &str, graph: &[TopologyBoardNode]) {
    let packet = discovery::build_discovery_topology(sender, 0, graph).unwrap();
    n.receive(&sedsnet::wire_format::pack_packet(&packet))
        .unwrap();
    n.drain().unwrap();
}
fn run_measured(
    n: &Bridge,
    packet: &Packet,
    limit: Option<isize>,
) -> (TelemetryResult<()>, isize, usize, usize, usize) {
    let wire = sedsnet::wire_format::pack_packet(packet);
    let before = LIVE.with(Cell::get);
    PEAK.with(|v| v.set(before));
    LARGEST.with(|v| v.set(0));
    DECLARED.store(0, Ordering::Relaxed);
    DECLARED_LARGEST.store(0, Ordering::Relaxed);
    ENFORCE.store(limit.is_some(), Ordering::Relaxed);
    CEILING.store(
        before.saturating_add(limit.unwrap_or(isize::MAX / 2)),
        Ordering::Relaxed,
    );
    sedsnet::memory_admission::set_probe(Some(probe));
    let result = n.receive(&wire).and_then(|_| n.drain());
    sedsnet::memory_admission::set_probe(None);
    ENFORCE.store(false, Ordering::Relaxed);
    (
        result,
        PEAK.with(Cell::get) - before,
        DECLARED.load(Ordering::Relaxed),
        LARGEST.with(Cell::get),
        DECLARED_LARGEST.load(Ordering::Relaxed),
    )
}
fn setup(kind: Kind, rich: bool) -> (Bridge, Vec<TopologyBoardNode>) {
    let ep = sedsnet::config::register_endpoint_with_description(
        &format!("CLONE_WORK_{kind:?}_{rich}"),
        "",
        false,
    )
    .unwrap();
    LIVE.with(|v| v.set(0));
    TRACK.with(|v| v.set(true));
    let n = bridge(kind);
    let names = if rich {
        vec!["AB", "DAQ", "VB", "GB", "FC", "PB", "RF"]
    } else {
        vec!["AB", "DAQ", "VB"]
    };
    let graph = names
        .iter()
        .map(|name| TopologyBoardNode {
            sender_id: (*name).into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: if rich {
                vec!["UTC".into(), "GPS".into()]
            } else {
                vec![]
            },
            connections: if rich {
                names
                    .iter()
                    .filter(|peer| *peer != name)
                    .map(|peer| (*peer).to_string())
                    .collect()
            } else {
                vec!["GB".into()]
            },
        })
        .collect::<Vec<_>>();
    let peers = if rich {
        vec!["AB", "DAQ", "VB", "FC", "PB", "RF"]
    } else {
        vec!["AB", "DAQ", "VB"]
    };
    for peer in peers {
        install(&n, peer, &graph);
    }
    (n, graph)
}
fn changed(graph: &[TopologyBoardNode], edge: &str) -> TopologyBoardNode {
    let mut node = graph[0].clone();
    node.connections = vec![edge.into()];
    node
}
fn assert_node(n: &Bridge, peer: &str, id: &str, connections: &[&str]) {
    let view = n.topology();
    let sender = view
        .routes
        .iter()
        .find(|r| r.side_id == 0)
        .unwrap()
        .announcers
        .iter()
        .find(|p| p.sender_id == peer)
        .unwrap();
    let node = sender.routers.iter().find(|b| b.sender_id == id).unwrap();
    assert_eq!(node.connections, connections);
}
fn small_case(kind: Kind) {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let (n, graph) = setup(kind, false);
    let before = n.topology().routes;
    let packet =
        discovery::build_discovery_topology_delta("AB", 1, &[changed(&graph, "NEW_EDGE")], &[])
            .unwrap();
    assert!(packet.payload().len() <= 128);
    let (result, peak, declared, largest, declared_largest) = run_measured(&n, &packet, Some(8192));
    result.unwrap();
    assert!(peak <= 8192);
    assert!(peak as usize <= declared);
    assert!(largest <= declared_largest);
    assert_node(&n, "AB", "AB", &["NEW_EDGE"]);
    let after = n.topology();
    for peer in ["DAQ", "VB"] {
        let prior = before
            .iter()
            .find(|r| r.side_id == 0)
            .unwrap()
            .announcers
            .iter()
            .find(|p| p.sender_id == peer)
            .unwrap();
        let current = after
            .routes
            .iter()
            .find(|r| r.side_id == 0)
            .unwrap()
            .announcers
            .iter()
            .find(|p| p.sender_id == peer)
            .unwrap();
        assert_eq!(
            current.routers, prior.routers,
            "another peer's graph changed"
        );
    }
    // New owners, oversized updates and malformed bodies do not inherit a
    // previously known peer's bounded metadata operation.
    let stable = n.topology().routes;
    let unknown =
        discovery::build_discovery_topology_delta("UNKNOWN", 2, &[changed(&graph, "OTHER")], &[])
            .unwrap();
    assert!(run_measured(&n, &unknown, Some(8192)).0.is_err());
    assert_eq!(n.topology().routes, stable);
    let mut large_node = changed(&graph, "OTHER");
    large_node.connections = vec!["x".repeat(1024)];
    let large = discovery::build_discovery_topology_delta("AB", 3, &[large_node], &[]).unwrap();
    assert!(large.payload().len() > 128);
    assert!(run_measured(&n, &large, Some(8192)).0.is_err());
    assert_eq!(n.topology().routes, stable);
    let malformed = Packet::new(
        sedsnet::config::DataType::DiscoveryTopology,
        &[sedsnet::config::DataEndpoint::Discovery],
        "AB",
        4,
        std::sync::Arc::<[u8]>::from([0xff]),
    )
    .unwrap();
    assert!(run_measured(&n, &malformed, Some(8192)).0.is_err());
    assert_eq!(n.topology().routes, stable);
}
fn peak_case(kind: Kind) {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    let (n, graph) = setup(kind, true);
    let packet =
        discovery::build_discovery_topology_delta("AB", 1, &[changed(&graph, "NEW_EDGE")], &[])
            .unwrap();
    let (result, peak, declared, largest, declared_largest) = run_measured(&n, &packet, None);
    result.unwrap();
    eprintln!(
        "{kind:?}: {peak} requested bytes peak, {declared} declared, largest {largest}/{declared_largest}"
    );
    assert!(
        peak as usize <= declared,
        "topology transaction allocated {peak} bytes after declaring only {declared}"
    );
    assert!(largest <= declared_largest);
    assert_node(&n, "AB", "AB", &["NEW_EDGE"]);
}
fn replace_case(kind: Kind) {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _reset = Reset;
    LIVE.with(|v| v.set(0));
    TRACK.with(|v| v.set(true));
    let n = bridge(kind);
    let graph = (0..100)
        .map(|i| TopologyBoardNode {
            sender_id: if i == 0 {
                "AB".into()
            } else {
                format!("NODE{i:03}")
            },
            reachable_endpoints: vec![],
            reachable_timesync_sources: vec![],
            connections: vec!["GB".into()],
        })
        .collect::<Vec<_>>();
    install(&n, "AB", &graph);
    let replacement = TopologyBoardNode {
        sender_id: "AB".into(),
        reachable_endpoints: vec![],
        reachable_timesync_sources: vec![],
        connections: vec!["GS".into()],
    };
    let packet = discovery::build_discovery_topology("AB", 1, &[replacement]).unwrap();
    let (result, peak, declared, largest, declared_largest) = run_measured(&n, &packet, Some(8192));
    result.unwrap();
    assert!(peak <= 8192);
    assert!(peak as usize <= declared);
    assert!(largest <= declared_largest);
    let view = n.topology();
    let sender = &view
        .routes
        .iter()
        .find(|r| r.side_id == 0)
        .unwrap()
        .announcers[0];
    assert_eq!(sender.sender_id, "AB");
    assert_eq!(sender.routers.len(), 1);
    assert_node(&n, "AB", "AB", &["GS"]);
}
#[test]
fn router_known_update_fits_and_preserves_other_peers() {
    small_case(Kind::Router);
}
#[test]
fn relay_known_update_fits_and_preserves_other_peers() {
    small_case(Kind::Relay);
}
#[test]
fn router_declares_all_transaction_work() {
    peak_case(Kind::Router);
}
#[test]
fn relay_declares_all_transaction_work() {
    peak_case(Kind::Relay);
}
#[test]
fn router_replaces_large_catalog_without_cloning_it() {
    replace_case(Kind::Router);
}
#[test]
fn relay_replaces_large_catalog_without_cloning_it() {
    replace_case(Kind::Relay);
}
