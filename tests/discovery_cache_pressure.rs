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
        Arc, Mutex,
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
    },
};
thread_local! {
    static TRACK: Cell<bool> = const {Cell::new(false)};
    static LIVE: Cell<isize> = const {Cell::new(0)};
    static PEAK: Cell<isize> = const {Cell::new(0)};
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
static MAX_WORK: AtomicUsize = AtomicUsize::new(0);
extern "C" fn probe(additional: usize, _largest: usize) -> bool {
    MAX_WORK.fetch_max(additional, Ordering::Relaxed);
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
enum Bridge {
    Router(Box<Router>),
    Relay(Box<Relay>),
}
impl Bridge {
    fn receive(&self, p: Packet, side: usize) -> TelemetryResult<()> {
        match self {
            Self::Router(n) => n.rx_from_side(&p, side),
            Self::Relay(n) => n.rx_from_side(side, p),
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
#[test]
fn router_rebuilds_full_baseline_after_releasing_obsolete_delta_copy() {
    check(false);
}
#[test]
fn relay_rebuilds_full_baseline_after_releasing_obsolete_delta_copy() {
    check(true);
}
fn check(relay: bool) {
    let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let _reset = Reset;
    // The remote receiver is outside the board's pool. Preallocate capture
    // buffers before metering; the physical callback only copies wire bytes.
    let captures = Arc::new(Mutex::new((
        0usize,
        (0..64)
            .map(|_| Vec::<u8>::with_capacity(65536))
            .collect::<Vec<_>>(),
    )));
    LIVE.with(|v| v.set(0));
    PEAK.with(|v| v.set(0));
    TRACK.with(|v| v.set(true));
    let sink = captures.clone();
    let output = move |bytes: &[u8]| {
        let mut captured = sink.lock().unwrap();
        let index = captured.0;
        let buffer = &mut captured.1[index];
        assert!(bytes.len() <= buffer.capacity());
        buffer.clear();
        buffer.extend_from_slice(bytes);
        captured.0 += 1;
        Ok(())
    };
    let (bridge, ingress, egress) = if relay {
        let n = Relay::new_with_config(RelayConfig::default().with_sender("GB"), Box::new(|| 0));
        let a = n.add_side_packed("can", |_| Ok(()));
        let b = n.add_side_packed("uart", output);
        (Bridge::Relay(Box::new(n)), a, b)
    } else {
        let n = Router::new_with_clock(
            RouterConfig::default()
                .with_sender("GB")
                .with_preferred_discovery_master("GS"),
            Box::new(|| 0),
        );
        let a = n.add_side_packed("can", |_| Ok(()));
        let b = n.add_side_packed("uart", output);
        (Bridge::Router(Box::new(n)), a, b)
    };
    let ep = sedsnet::config::register_endpoint_with_description(
        if relay {
            "CACHE_RELAY_DEST"
        } else {
            "CACHE_ROUTER_DEST"
        },
        "",
        false,
    )
    .unwrap();
    let graph = ["AB", "DAQ", "VB"]
        .into_iter()
        .map(|name| TopologyBoardNode {
            sender_id: name.into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: (0..16)
                .map(|i| format!("EDGE_{i}_{}", "x".repeat(96)))
                .collect(),
        })
        .collect::<Vec<_>>();
    bridge
        .receive(
            discovery::build_discovery_topology("CAN_PEER", 0, &graph).unwrap(),
            ingress,
        )
        .unwrap();
    bridge.drain().unwrap();
    // Record the unchanged recovery operation's conservative working estimate.
    MAX_WORK.store(0, Ordering::Relaxed);
    sedsnet::memory_admission::set_probe(Some(probe));
    bridge
        .receive(
            discovery::build_discovery_topology_request("GS", 1).unwrap(),
            egress,
        )
        .unwrap();
    bridge.drain().unwrap();
    sedsnet::memory_admission::set_probe(None);
    assert!(captured_names(&captures).iter().any(|n| n == "VB"));
    captures.lock().unwrap().0 = 0;
    sedsnet::memory_admission::set_probe(Some(probe));
    let baseline = bridge.topology();
    let work = MAX_WORK.load(Ordering::Relaxed);
    assert!(work > 1024);
    let before = LIVE.with(Cell::get);
    // Full recovery fits once the obsolete delta baseline has yielded at least
    // 512 bytes. This is a real allocation ledger, not a callback into SEDSnet.
    let ceiling = before + work as isize - 512;
    CEILING.store(ceiling, Ordering::Relaxed);
    ENFORCE.store(true, Ordering::Relaxed);
    PEAK.with(|v| v.set(before));
    let result = bridge
        .receive(
            discovery::build_discovery_topology_request("GS", 2).unwrap(),
            egress,
        )
        .and_then(|_| bridge.drain());
    let peak = PEAK.with(Cell::get);
    sedsnet::memory_admission::set_probe(None);
    TRACK.with(|v| v.set(false));
    result.unwrap();
    let got = captured_names(&captures);
    for name in ["AB", "DAQ", "VB", "GB"] {
        assert!(got.iter().any(|n| n == name), "missing {name}; got {got:?}");
    }
    assert!(
        peak <= ceiling,
        "materialized recovery used {peak} bytes with {ceiling} available"
    );
    assert_eq!(
        bridge.topology().routes,
        baseline.routes,
        "recovery discarded live routes"
    );
}

fn captured_names(captures: &Mutex<(usize, Vec<Vec<u8>>)>) -> Vec<String> {
    let captured = captures.lock().unwrap();
    captured.1[..captured.0]
        .iter()
        .flat_map(|bytes| {
            let packet = sedsnet::wire_format::unpack_packet(bytes).unwrap();
            if packet.data_type() == sedsnet::config::DataType::DiscoveryTopology {
                discovery::decode_discovery_topology(&packet)
                    .unwrap()
                    .into_iter()
                    .map(|node| node.sender_id)
                    .collect()
            } else {
                Vec::new()
            }
        })
        .collect()
}
