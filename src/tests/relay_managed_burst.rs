//! A burst of writes to one ordered managed variable relayed by a two-sided
//! router onto a shared bus must reach every node behind it, whatever the
//! spacing between writes.
//!
//! Topology: WRITER <-link-> RELAY <-bus-> {A, B, C}. Only the writer may
//! write; every other node applies the variable through its update callback.
use super::*;
use crate::router::Clock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct SimClock(Arc<AtomicU64>);
impl Clock for SimClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

const WRITER: usize = 0;
const RELAY: usize = 1;
const NAMES: [&str; 5] = ["WRITER", "RELAY", "A", "B", "C"];
const STEP_MS: u64 = 10;

type Outbox = Arc<Mutex<Vec<Vec<u8>>>>;

struct Side {
    node: usize,
    id: RouterSideId,
    out: Outbox,
    peers: Vec<usize>,
}

struct Sim {
    now: Arc<AtomicU64>,
    nodes: Vec<Router>,
    sides: Vec<Side>,
    ty: DataType,
    ep: DataEndpoint,
    /// Values each node's update callback saw, in order.
    applied: Vec<Arc<Mutex<Vec<u8>>>>,
    /// Bus frames of the managed type the relay sent.
    relayed: usize,
    /// Side indices whose transmissions are lost (a node that went quiet).
    mute: Vec<usize>,
}

fn schema() -> (DataType, DataEndpoint) {
    crate::tests::ensure_common_test_schema();
    let ep = crate::config::register_endpoint("RELAY_BURST_EP", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "RELAY_BURST_STATE",
        "ordered managed state for the relay burst sim",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
    (ty, ep)
}

fn side_options(max_frame_bytes: usize, templates: usize) -> RouterSideOptions {
    crate::binding_options::router_side_options_for_profile(
        false,
        crate::router::SideTransportProfile::Ipv6Like,
        max_frame_bytes,
        0,
        templates,
    )
}

impl Sim {
    fn new() -> Self {
        let (ty, ep) = schema();
        let now = Arc::new(AtomicU64::new(1_000));
        let mut nodes = Vec::new();
        let mut applied = Vec::new();
        for (i, name) in NAMES.iter().enumerate() {
            let node = Router::new_with_clock(
                RouterConfig::new(Vec::new()).with_sender(*name),
                Box::new(SimClock(now.clone())),
            );
            let perm = if i == WRITER {
                NetworkVariablePermissions::READ_WRITE
            } else {
                NetworkVariablePermissions::READ_ONLY
            };
            node.enable_network_variable(ty, perm).unwrap();
            let seen: Arc<Mutex<Vec<u8>>> = Arc::default();
            let s = seen.clone();
            node.on_network_variable_update(ty, move |p| {
                s.lock().unwrap().push(p.payload()[0]);
                Ok(())
            })
            .unwrap();
            nodes.push(node);
            applied.push(seen);
        }
        let mut sim = Self { now, nodes, sides: Vec::new(), ty, ep, applied, relayed: 0, mute: Vec::new() };
        // Neither hop runs hop-by-hop receipts: delivery is end to end, as on
        // a gateway between a polled serial link and a CAN FD bus.
        for (node, name, opts) in [
            (WRITER, "link", side_options(1024, 16)),
            (RELAY, "link", side_options(1024, 16)),
            (RELAY, "bus", side_options(128, 32)),
            (2, "bus", side_options(128, 32)),
            (3, "bus", side_options(128, 32)),
            (4, "bus", side_options(128, 32)),
        ] {
            let out: Outbox = Arc::default();
            let tx = out.clone();
            let id = sim.nodes[node].add_side_packed_with_options(
                name,
                move |b: &[u8]| {
                    tx.lock().unwrap().push(b.to_vec());
                    Ok(())
                },
                opts,
            );
            sim.sides.push(Side { node, id, out, peers: Vec::new() });
        }
        sim.sides[0].peers = vec![1];
        sim.sides[1].peers = vec![0];
        sim.sides[2].peers = vec![3, 4, 5];
        sim.sides[3].peers = vec![2, 4, 5];
        sim.sides[4].peers = vec![2, 3, 5];
        sim.sides[5].peers = vec![2, 3, 4];
        sim
    }

    fn deliver(&mut self) {
        for from in 0..self.sides.len() {
            let frames = std::mem::take(&mut *self.sides[from].out.lock().unwrap());
            for b in frames {
                if self.mute.contains(&from) {
                    continue;
                }
                if from == 2
                    && wire_format::peek_routing_envelope(&b).is_ok_and(|e| e.ty == self.ty)
                {
                    self.relayed += 1;
                }
                for to in self.sides[from].peers.clone() {
                    let (node, id) = (self.sides[to].node, self.sides[to].id);
                    let _ = self.nodes[node].rx_packed_from_side(&b, id);
                }
            }
        }
    }

    fn step(&mut self) {
        self.now.fetch_add(STEP_MS, Ordering::SeqCst);
        for node in &self.nodes {
            let _ = node.periodic(0);
        }
        self.deliver();
        for node in &self.nodes {
            let _ = node.process_all_queues();
        }
        self.deliver();
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms / STEP_MS {
            self.step();
        }
    }

    fn bootstrap(&mut self) {
        for node in &self.nodes {
            node.announce_discovery().unwrap();
        }
        self.run(3_000);
    }

    fn write(&mut self, value: u8) {
        let ts = self.now.load(Ordering::SeqCst);
        let pkt = Packet::new(self.ty, &[self.ep], NAMES[WRITER], ts, Arc::<[u8]>::from([value]))
            .unwrap();
        self.nodes[WRITER].set_network_variable(pkt).unwrap();
    }

    fn value(&self, node: usize) -> Option<u8> {
        self.nodes[node].cached_managed_variable(self.ty).map(|p| p.payload()[0])
    }

    fn applied(&self, node: usize) -> Vec<u8> {
        self.applied[node].lock().unwrap().clone()
    }
}

/// Eight writes, `spacing_ms` apart, with distinct values; afterwards every
/// node behind the relay has applied all of them, in order.
fn burst(spacing_ms: u64) {
    burst_values(spacing_ms, &(1..=8).collect::<Vec<u8>>());
}

fn burst_values(spacing_ms: u64, values: &[u8]) {
    let values = values.to_vec();
    let mut sim = Sim::new();
    sim.bootstrap();
    for (i, v) in values.iter().enumerate() {
        sim.write(*v);
        if i + 1 < values.len() {
            sim.run(spacing_ms);
        }
    }
    sim.run(10_000);
    let report: Vec<_> = (1..NAMES.len()).map(|n| (NAMES[n], sim.applied(n))).collect();
    for (node, name) in NAMES.iter().enumerate().skip(1) {
        assert_eq!(sim.value(node), values.last().copied(), "{name} ends on the last write: {report:?}");
        assert_eq!(sim.applied(node), values, "{name} applied every write in order: {report:?} (relayed {})", sim.relayed);
    }
}

#[test]
fn burst_one_second_apart_reaches_every_bus_node() {
    burst(1_000);
}

#[test]
fn burst_hundred_ms_apart_reaches_every_bus_node() {
    burst(100);
}

#[test]
fn burst_five_seconds_apart_reaches_every_bus_node() {
    burst(5_000);
}

/// Repeated writes of one value (fresh stamps) and then a different one.
#[test]
fn repeated_value_burst_one_second_apart_reaches_every_bus_node() {
    burst_values(1_000, &[2, 2, 2, 2, 2, 2, 2, 1]);
}

/// One bus node stops answering (its receipts never arrive). The relay
/// acknowledged each write upstream when it accepted it, so the writer can
/// neither see nor repair a loss behind the relay; every write must still
/// reach the nodes that do answer, in order. Before the fix each exhaustion of
/// the quiet node's head frame discarded the writes queued behind it: A and B
/// applied 1, 3, 5, 7.
fn burst_with_quiet_node(spacing_ms: u64) {
    let mut sim = Sim::new();
    sim.bootstrap();
    sim.mute = vec![5];
    let writer_before = sim.nodes[WRITER].export_runtime_stats().reliable.exhausted;
    let values: Vec<u8> = (1..=8).collect();
    for (i, v) in values.iter().enumerate() {
        sim.write(*v);
        if i + 1 < values.len() {
            sim.run(spacing_ms);
        }
    }
    // At most two exhaustion windows (default 200 ms x 8 retries) after the
    // last write: the one it may queue behind and its own.
    sim.run(4_000);
    let report: Vec<_> = (1..NAMES.len()).map(|n| (NAMES[n], sim.applied(n))).collect();
    for node in [2, 3] {
        assert_eq!(sim.applied(node), values, "{} applied every write in order: {report:?}", NAMES[node]);
    }
    // The quiet node hears the bus (only its own frames are lost) and ends on
    // the last write too, whatever it missed of the tracked retries.
    assert_eq!(sim.value(4), Some(8), "{report:?}");
    let relay = sim.nodes[RELAY].export_runtime_stats().reliable.exhausted;
    assert!(relay.end_to_end_ordered > 0, "the relay owns the quiet node's exhaustion: {relay:?}");
    assert!(relay.silent_owner_retired_ordered > 0, "and retires it from the queued writes: {relay:?}");
    assert_eq!(
        sim.nodes[WRITER].export_runtime_stats().reliable.exhausted,
        writer_before,
        "nothing is exhausted at the writer"
    );
}

#[test]
fn burst_one_second_apart_with_a_quiet_bus_node_reaches_the_others() {
    burst_with_quiet_node(1_000);
}

#[test]
fn burst_hundred_ms_apart_with_a_quiet_bus_node_reaches_the_others() {
    burst_with_quiet_node(100);
}
