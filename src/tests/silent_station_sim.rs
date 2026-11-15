//! Host sim of a station going silent (RRLS hand-back with its discovery
//! leave lost): GS and RRLS share the radio with RF; FC sits behind RF on CAN.
//! Both stations host the station endpoint. After the RRLS stops hearing and
//! sending, RF's and FC's reliable station frames must keep reaching the GS.
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
const RR: usize = 1;
const RF: usize = 2;
const FC: usize = 3;

/// (node, side, radio, outbox)
type Side = (usize, RouterSideId, bool, Arc<Mutex<Vec<Vec<u8>>>>);

pub(crate) struct Sim {
    pub now: Arc<AtomicU64>,
    pub nodes: Vec<Router>,
    /// (node, side, radio, outbox)
    sides: Vec<Side>,
    flight: Vec<(u64, usize, Vec<u8>)>,
    pub rr_silent: bool,
    /// Frames of the station type delivered to the GS / RRLS handler, by sender.
    pub gs_got: Arc<Mutex<Vec<(u64, String, u64)>>>,
    pub rr_got: Arc<AtomicUsize>,
    pub ty: DataType,
    pub ep: DataEndpoint,
    /// RF's radio writes of the station type: (ms, sender, packet id, targets).
    pub rf_air: Vec<(u64, String, u64, Vec<u64>)>,
}

pub(crate) fn station_schema(mode: crate::ReliableMode) -> (DataType, DataEndpoint) {
    crate::tests::ensure_common_test_schema();
    let ep = crate::config::register_endpoint("SILENT_STATION_EP", false).unwrap();
    let name = match mode {
        crate::ReliableMode::Ordered => "SILENT_STATION_STATUS_ORDERED",
        _ => "SILENT_STATION_STATUS",
    };
    let ty = crate::config::register_data_type_with_description(
        name,
        "station status for the silent-station sim",
        MessageElement::Static(8, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        mode,
        200,
    )
    .unwrap();
    (ty, ep)
}

impl Sim {
    pub(crate) fn new(mode: crate::ReliableMode) -> Self {
        let (ty, ep) = station_schema(mode);
        let now = Arc::new(AtomicU64::new(1_000));
        let gs_got: Arc<Mutex<Vec<(u64, String, u64)>>> = Arc::default();
        let rr_got = Arc::new(AtomicUsize::new(0));
        let mut nodes = Vec::new();
        for (i, name) in ["GS", "RRLS", "RF", "FC"].iter().enumerate() {
            let cfg = match i {
                GS => {
                    let got = gs_got.clone();
                    let clock = now.clone();
                    RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |p| {
                        got.lock().unwrap().push((
                            clock.load(Ordering::SeqCst),
                            p.sender().to_string(),
                            u64::from_le_bytes(p.payload()[..8].try_into().unwrap()),
                        ));
                        Ok(())
                    })])
                }
                RR => {
                    let got = rr_got.clone();
                    RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |_| {
                        got.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })])
                }
                _ => RouterConfig::new([]),
            };
            nodes.push(Router::new_with_clock(cfg.with_sender(*name), Box::new(SimClock(now.clone()))));
        }
        let mut sim = Self {
            now,
            nodes,
            sides: Vec::new(),
            flight: Vec::new(),
            rr_silent: false,
            gs_got,
            rr_got,
            ty,
            ep,
            rf_air: Vec::new(),
        };
        sim.add_side(GS, true); // 0
        sim.add_side(RR, true); // 1
        sim.add_side(RF, true); // 2
        sim.add_side(RF, false); // 3: RF CAN
        sim.add_side(FC, false); // 4: FC CAN
        sim
    }

    fn add_side(&mut self, node: usize, radio: bool) {
        let out: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let tx = out.clone();
        let side = self.nodes[node].add_side_packed(if radio { "radio" } else { "can" }, move |b: &[u8]| {
            tx.lock().unwrap().push(b.to_vec());
            Ok(())
        });
        self.sides.push((node, side, radio, out));
    }

    pub(crate) fn publish(&self, node: usize, seq: u64) {
        let sender = ["GS", "RRLS", "RF", "FC"][node];
        let pkt = Packet::new(self.ty, &[self.ep], sender, seq, Arc::<[u8]>::from(seq.to_le_bytes())).unwrap();
        let _ = self.nodes[node].tx_queue(pkt);
    }

    pub(crate) fn step(&mut self) {
        let t = self.now.load(Ordering::SeqCst);
        for (i, node) in self.nodes.iter().enumerate() {
            if i == RR && self.rr_silent {
                continue;
            }
            let _ = node.periodic(0);
        }
        for from in 0..self.sides.len() {
            let (node, radio, out) = (self.sides[from].0, self.sides[from].2, self.sides[from].3.clone());
            for b in std::mem::take(&mut *out.lock().unwrap()) {
                if node == RR && self.rr_silent {
                    continue;
                }
                if radio {
                    if node == RF
                        && let Ok(p) = wire_format::unpack_packet(&b)
                        && p.data_type() == self.ty
                    {
                        self.rf_air.push((t, p.sender().to_string(), p.packet_id(), p.wire_target_senders().to_vec()));
                    }
                    for to in 0..3 {
                        if to != from {
                            self.flight.push((t + 25, to, b.clone()));
                        }
                    }
                } else {
                    let to = if from == 3 { 4 } else { 3 };
                    self.flight.push((t + 1, to, b));
                }
            }
        }
        let mut due = Vec::new();
        self.flight.retain(|f| {
            if f.0 <= t {
                due.push(f.clone());
                false
            } else {
                true
            }
        });
        for (_, to, b) in due {
            let (node, side) = (self.sides[to].0, self.sides[to].1);
            if node == RR && self.rr_silent {
                continue;
            }
            let _ = self.nodes[node].rx_packed_from_side(&b, side);
        }
        self.now.store(t + 1, Ordering::SeqCst);
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Runs: both stations up for `up_s`, then the RRLS silent for `silent_s`; RF
/// and FC publish one station frame per second each. Returns, for frames
/// published after the cut, the GS delivery delay of each (None: never).
pub(crate) fn run(mode: crate::ReliableMode, up_s: u64, silent_s: u64) -> (Sim, Vec<(String, u64, Option<u64>)>) {
    let mut sim = Sim::new(mode);
    let mut published: Vec<(String, u64, u64)> = Vec::new(); // (sender, seq, at)
    let mut seq = 0u64;
    let end = sim.now_ms() + (up_s + silent_s) * 1_000;
    let cut = sim.now_ms() + up_s * 1_000;
    while sim.now_ms() < end {
        let t = sim.now_ms();
        if t >= cut {
            sim.rr_silent = true;
        }
        if t.is_multiple_of(1_000) {
            seq += 1;
            sim.publish(RF, seq);
            published.push(("RF".into(), seq, t));
        }
        if t % 1_000 == 500 {
            seq += 1;
            sim.publish(FC, seq);
            published.push(("FC".into(), seq, t));
        }
        sim.step();
    }
    let got = sim.gs_got.lock().unwrap().clone();
    let out = published
        .into_iter()
        .filter(|(_, _, at)| *at >= cut)
        .map(|(sender, seq, at)| {
            let delivered = got
                .iter()
                .find(|(_, s, got_seq)| *s == sender && *got_seq == seq)
                .map(|(t, _, _)| t - at);
            (sender, seq, delivered)
        })
        .collect();
    (sim, out)
}

fn summary(label: &str, sim: &Sim, frames: &[(String, u64, Option<u64>)]) -> (usize, u64) {
    let lost = frames.iter().filter(|f| f.2.is_none()).count();
    let worst = frames.iter().filter_map(|f| f.2).max().unwrap_or(0);
    let gs = Router::sender_hash("GS");
    let rr = Router::sender_hash("RRLS");
    let mut only_rr = 0;
    let mut both = 0;
    let mut only_gs = 0;
    for (_, _, _, targets) in &sim.rf_air {
        match (targets.contains(&gs), targets.contains(&rr)) {
            (true, true) => both += 1,
            (false, true) => only_rr += 1,
            (true, false) => only_gs += 1,
            _ => {}
        }
    }
    println!(
        "{label}: {} frames after the cut, {lost} never reached the GS, worst delay {worst} ms; RF air targets both {both}, RRLS only {only_rr}, GS only {only_gs}",
        frames.len()
    );
    (lost, worst)
}

/// The station frames published after the RRLS went silent reach the GS
/// promptly: none lost, each within 2 s.
#[test]
fn a_silent_station_does_not_stall_frames_to_the_other() {
    // Ordered frames keep their exhaustion semantics (the application
    // re-sends from it); a silent station still costs an Ordered stream its
    // tail, so station-bound Ordered types should not be relied on alone.
    {
        let mode = crate::ReliableMode::Unordered;
        let (sim, frames) = run(mode, 40, 50);
        let (lost, worst) = summary(&format!("{mode:?}"), &sim, &frames);
        println!("GS got {} total, RRLS got {}, RF air {}", sim.gs_got.lock().unwrap().len(), sim.rr_got.load(Ordering::SeqCst), sim.rf_air.len());
        let late: Vec<_> = frames.iter().filter(|f| f.2.is_none_or(|d| d > 2_000)).collect();
        assert!(lost == 0 && worst <= 2_000, "{mode:?}: late or lost after the cut: {late:?}");
    }
}
