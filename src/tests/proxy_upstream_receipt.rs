//! A segment proxy (a frozen owner with no local endpoint handler and a
//! downstream route) acknowledges its upstream as soon as it has accepted the
//! write and owns downstream delivery itself. A dead downstream owner is the
//! proxy's exhaustion, never the publisher's.
//!
//! Topology: GS <-umbilical-> FC <-CAN bus-> {RF, PB}; RF <-radio-> RRLS.
//! One ordered managed variable; every board applies it via its update
//! callback only (no endpoint handler anywhere).
use super::*;
use crate::router::Clock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct SimClock(Arc<AtomicU64>);
impl Clock for SimClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

const GS: usize = 0;
const FC: usize = 1;
const RF: usize = 2;
const PB: usize = 3;
const RR: usize = 4;
const NAMES: [&str; 5] = ["GS", "FC", "RF", "PB", "RRLS"];

type Outbox = Arc<Mutex<Vec<Vec<u8>>>>;

struct Side {
    node: usize,
    id: RouterSideId,
    out: Outbox,
    /// Indices into `Sim::sides` this side's frames reach.
    peers: Vec<usize>,
}

struct Sim {
    now: Arc<AtomicU64>,
    nodes: Vec<Router>,
    sides: Vec<Side>,
    ty: DataType,
    ep: DataEndpoint,
    applied: Vec<Arc<AtomicUsize>>,
    /// Drop everything the RRLS transmits (a listening station).
    rrls_mute: bool,
    /// Drop the GS's receipts on the umbilical.
    gs_acks_lost: bool,
    /// Every delivered frame: (from side index, to side index, bytes).
    log: Vec<(usize, usize, Vec<u8>)>,
}

const UMB_GS: usize = 0;
const UMB_FC: usize = 1;
const CAN_FC: usize = 2;
const CAN_RF: usize = 3;
const CAN_PB: usize = 4;
const RADIO_RF: usize = 5;
const RADIO_RR: usize = 6;

fn schema() -> (DataType, DataEndpoint) {
    crate::tests::ensure_common_test_schema();
    let ep = crate::config::register_endpoint("PROXY_RECEIPT_EP", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "PROXY_RECEIPT_STATE",
        "ordered managed state for the proxy receipt sim",
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
    (ty, ep)
}

impl Sim {
    fn new(gs_writer: bool) -> Self {
        let (ty, ep) = schema();
        let now = Arc::new(AtomicU64::new(1_000));
        let mut nodes = Vec::new();
        let mut applied = Vec::new();
        for (i, name) in NAMES.iter().enumerate() {
            let node = Router::new_with_clock(
                RouterConfig::new([]).with_sender(*name),
                Box::new(SimClock(now.clone())),
            );
            let perm = if i == GS && gs_writer {
                NetworkVariablePermissions::READ_WRITE
            } else {
                NetworkVariablePermissions::READ_ONLY
            };
            node.enable_network_variable(ty, perm).unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let c = count.clone();
            node.on_network_variable_update(ty, move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
            nodes.push(node);
            applied.push(count);
        }
        let mut sim = Self {
            now,
            nodes,
            sides: Vec::new(),
            ty,
            ep,
            applied,
            rrls_mute: false,
            gs_acks_lost: false,
            log: Vec::new(),
        };
        for (node, name) in [
            (GS, "umbilical"),
            (FC, "umbilical"),
            (FC, "can"),
            (RF, "can"),
            (PB, "can"),
            (RF, "radio"),
            (RR, "radio"),
        ] {
            let out: Outbox = Arc::default();
            let tx = out.clone();
            let id = sim.nodes[node].add_side_packed(name, move |b: &[u8]| {
                tx.lock().unwrap().push(b.to_vec());
                Ok(())
            });
            sim.sides.push(Side { node, id, out, peers: Vec::new() });
        }
        sim.sides[UMB_GS].peers = vec![UMB_FC];
        sim.sides[UMB_FC].peers = vec![UMB_GS];
        sim.sides[CAN_FC].peers = vec![CAN_RF, CAN_PB];
        sim.sides[CAN_RF].peers = vec![CAN_FC, CAN_PB];
        sim.sides[CAN_PB].peers = vec![CAN_FC, CAN_RF];
        sim.sides[RADIO_RF].peers = vec![RADIO_RR];
        sim.sides[RADIO_RR].peers = vec![RADIO_RF];
        sim
    }

    fn is_ack(bytes: &[u8]) -> bool {
        wire_format::peek_routing_envelope(bytes).is_ok_and(|e| e.ty == DataType::ReliableAck)
    }

    fn deliver(&mut self) {
        for from in 0..self.sides.len() {
            let frames = std::mem::take(&mut *self.sides[from].out.lock().unwrap());
            for b in frames {
                if self.sides[from].node == RR && self.rrls_mute {
                    continue;
                }
                if from == UMB_GS && self.gs_acks_lost && Self::is_ack(&b) {
                    continue;
                }
                for to in self.sides[from].peers.clone() {
                    let (node, id) = (self.sides[to].node, self.sides[to].id);
                    let _ = self.nodes[node].rx_packed_from_side(&b, id);
                    self.log.push((from, to, b.clone()));
                }
            }
        }
    }

    fn step(&mut self) {
        self.now.fetch_add(50, Ordering::SeqCst);
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
        for _ in 0..ms / 50 {
            self.step();
        }
    }

    fn bootstrap(&mut self) {
        for node in &self.nodes {
            node.announce_discovery().unwrap();
        }
        self.run(3_000);
    }

    fn packet(&self, node: usize, timestamp: u64, value: u8) -> Packet {
        Packet::new(self.ty, &[self.ep], NAMES[node], timestamp, Arc::<[u8]>::from([value])).unwrap()
    }

    fn pending(&self, node: usize) -> Vec<(u64, Vec<&'static str>)> {
        self.nodes[node]
            .export_reliable_pending_stats()
            .into_iter()
            .filter(|p| p.data_type == self.ty)
            .map(|p| {
                let owners = p
                    .pending_destinations
                    .iter()
                    .map(|h| {
                        NAMES
                            .iter()
                            .copied()
                            .find(|n| Router::sender_hash(n) == *h)
                            .unwrap_or("?")
                    })
                    .collect();
                (p.packet_id, owners)
            })
            .collect()
    }

    fn exhausted(&self, node: usize) -> crate::diagnostics::ReliableExhaustionCounts {
        self.nodes[node].export_runtime_stats().reliable.exhausted
    }

    fn gave_up(&self, node: usize) -> u64 {
        let c = self.exhausted(node);
        c.end_to_end_ordered
            + c.end_to_end_unordered
            + c.silent_owner_retired_ordered
            + c.silent_owner_retired_unordered
    }

    fn value(&self, node: usize) -> Option<u8> {
        self.nodes[node].cached_managed_variable(self.ty).map(|p| p.payload()[0])
    }

    /// Receipts for `packet_id` sent out of side `from`.
    fn acks_from(&self, from: usize, packet_id: u64) -> usize {
        self.log
            .iter()
            .filter(|(f, _, b)| {
                *f == from
                    && Self::is_ack(b)
                    && wire_format::unpack_packet(b)
                        .is_ok_and(|p| p.payload() == packet_id.to_le_bytes())
            })
            .count()
    }

    /// The first data frame of the managed type sent out of side `from`.
    fn first_data_from(&self, from: usize) -> Option<Vec<u8>> {
        self.log.iter().find_map(|(f, _, b)| {
            (*f == from
                && wire_format::peek_routing_envelope(b).is_ok_and(|e| e.ty == self.ty))
            .then(|| b.clone())
        })
    }
}

/// Case A: a listening RRLS (transmits nothing) is still advertised as an
/// owner. The GS's write completes once every reachable board applied it; RF
/// owns the RRLS delivery and gives it up itself.
#[test]
fn silent_downstream_owner_is_the_proxys_exhaustion_not_the_publishers() {
    let mut sim = Sim::new(true);
    sim.bootstrap();
    sim.rrls_mute = true;
    let before = [sim.gave_up(GS), sim.gave_up(FC), sim.gave_up(RF)];
    sim.nodes[GS].set_network_variable(sim.packet(GS, 5_000, 15)).unwrap();
    // Well within the GS's own retry budget (8 x 200 ms).
    sim.run(600);
    for node in [FC, RF, PB, RR] {
        assert_eq!(sim.value(node), Some(15), "{} applied the write", NAMES[node]);
    }
    assert!(sim.pending(GS).is_empty(), "GS write completes: {:?}", sim.pending(GS));
    assert!(sim.pending(FC).is_empty(), "FC segment completes: {:?}", sim.pending(FC));
    assert!(
        sim.pending(RF).iter().any(|(_, owners)| owners.contains(&"RRLS")),
        "RF owns the silent RRLS delivery: {:?}",
        sim.pending(RF)
    );
    sim.run(6_000);
    assert!(sim.pending(RF).is_empty(), "RF gave the RRLS up: {:?}", sim.pending(RF));
    assert_eq!(sim.gave_up(GS), before[0], "no exhaustion at the publisher");
    assert_eq!(sim.gave_up(FC), before[1], "no exhaustion at FC");
    assert!(sim.gave_up(RF) > before[2], "RF counts the dead downstream owner: {:?}", sim.exhausted(RF));
    assert_eq!(sim.applied[GS].load(Ordering::SeqCst), 0, "a writer is not re-applied");
}

/// Case B: the GS's receipts are lost on the umbilical. The RRLS's write
/// completes at the RRLS; FC owns the GS delivery and its failure.
#[test]
fn lost_upstream_receipts_are_the_segment_proxys_failure_not_the_publishers() {
    let mut sim = Sim::new(false);
    sim.bootstrap();
    sim.gs_acks_lost = true;
    let before = [sim.gave_up(RR), sim.gave_up(RF), sim.gave_up(FC)];
    sim.nodes[RR].tx(sim.packet(RR, 6_000, 15)).unwrap();
    sim.run(600);
    for node in [GS, FC, RF, PB] {
        assert_eq!(sim.value(node), Some(15), "{} applied the write", NAMES[node]);
    }
    assert!(sim.pending(RR).is_empty(), "RRLS write completes: {:?}", sim.pending(RR));
    assert!(sim.pending(RF).is_empty(), "RF segment completes: {:?}", sim.pending(RF));
    assert!(
        sim.pending(FC).iter().any(|(_, owners)| owners.contains(&"GS")),
        "FC owns the GS delivery: {:?}",
        sim.pending(FC)
    );
    sim.run(6_000);
    assert!(sim.pending(FC).is_empty(), "FC gave the GS up: {:?}", sim.pending(FC));
    assert_eq!(sim.gave_up(RR), before[0], "no exhaustion at the publisher");
    assert_eq!(sim.gave_up(RF), before[1], "no exhaustion at RF");
    assert!(sim.gave_up(FC) > before[2], "FC counts the lost GS receipts: {:?}", sim.exhausted(FC));
}

/// A duplicate of an upstream packet the proxy already acknowledged, arriving
/// again on its original side, gets the receipt again: while the downstream
/// contract is still pending, and after it completed.
#[test]
fn duplicate_on_the_original_side_is_acknowledged_again() {
    let mut sim = Sim::new(true);
    sim.bootstrap();
    sim.rrls_mute = true;
    sim.nodes[GS].set_network_variable(sim.packet(GS, 5_000, 15)).unwrap();
    sim.run(600);

    // RF: its RRLS delivery is still pending.
    let frame = sim.first_data_from(CAN_FC).expect("FC forwarded the write on CAN");
    let id = wire_format::packet_id_from_wire(&frame).unwrap();
    assert!(!sim.pending(RF).is_empty(), "RF still owns the RRLS delivery");
    let acks = sim.acks_from(CAN_RF, id);
    assert!(acks >= 1, "RF acknowledged FC");
    sim.nodes[RF].rx_packed_from_side(&frame, sim.sides[CAN_RF].id).unwrap();
    let _ = sim.nodes[RF].process_all_queues();
    sim.deliver();
    assert!(sim.acks_from(CAN_RF, id) > acks, "RF re-acknowledges a pending duplicate");

    // FC: its CAN segment completed.
    let frame = sim.first_data_from(UMB_GS).expect("GS sent the write");
    let id = wire_format::packet_id_from_wire(&frame).unwrap();
    assert!(sim.pending(FC).is_empty());
    sim.run(400);
    let acks = sim.acks_from(UMB_FC, id);
    assert!(acks >= 1, "FC acknowledged GS");
    sim.nodes[FC].rx_packed_from_side(&frame, sim.sides[UMB_FC].id).unwrap();
    let _ = sim.nodes[FC].process_all_queues();
    sim.deliver();
    assert!(sim.acks_from(UMB_FC, id) > acks, "FC re-acknowledges a completed duplicate");
    // The duplicate recreated no downstream child contract.
    assert!(sim.pending(FC).is_empty(), "{:?}", sim.pending(FC));
}
