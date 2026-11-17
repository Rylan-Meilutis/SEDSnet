//! Large network time steps: convergence through relays and lossy links, the
//! time-base epoch, and ordering of station-time-stamped state across a step.
//!
//! Field fault (2026-11-16): a station's network clock was 3 h 49 min off.
//! The operator's correction was slewed at 5% (76 h to converge), followers
//! (3% frequency range) lagged by seconds, and after a step back boards and
//! the managed FLIGHT_STATE cache refused every later command because it was
//! stamped "older" than the last one applied.
use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::router::{NetworkVariablePermissions, Router, RouterConfig, RouterSideId};
use crate::timesync::{
    NetworkStampAge, PartialNetworkTime, TimeSyncConfig, TimeSyncRole, TimeSyncStepReason,
};
use crate::timesync_discipline::SyncState;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Real UTC at the start of the simulation.
const UTC: u64 = 1_793_000_000_000;
const HOUR: u64 = 3_600_000;
/// The station's stale clock in the field: 3 h 49 min behind.
const FIELD_OFFSET: u64 = 3 * HOUR + 49 * 60_000;
/// Simulation tick, ms.
const TICK: u64 = 1;

type Wire = Arc<Mutex<Vec<Vec<u8>>>>;
/// Every frame a node put on a link: (from node, bytes).
type Tap = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

struct Rng(u64);
impl Rng {
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[derive(Clone, Copy)]
struct LinkSpec {
    delay_ms: u64,
    loss: f64,
}

const CAN: LinkSpec = LinkSpec { delay_ms: 1, loss: 0.0 };
const WIFI: LinkSpec = LinkSpec { delay_ms: 3, loss: 0.0 };

struct Link {
    a: usize,
    b: usize,
    side_a: RouterSideId,
    side_b: RouterSideId,
    a_out: Wire,
    b_out: Wire,
    spec: LinkSpec,
    up: bool,
}

struct Net {
    now: Arc<AtomicU64>,
    names: Vec<&'static str>,
    cfgs: Vec<TimeSyncConfig>,
    nodes: Vec<Router>,
    links: Vec<Link>,
    /// (deliver at ms, link, toward b, bytes)
    flight: Vec<(u64, usize, bool, Vec<u8>)>,
    rng: Rng,
    tapped: Tap,
}

fn station() -> TimeSyncConfig {
    TimeSyncConfig {
        role: TimeSyncRole::Source,
        priority: 50,
        ..Default::default()
    }
}

fn board() -> TimeSyncConfig {
    TimeSyncConfig::default()
}

fn router(name: &'static str, cfg: TimeSyncConfig, now: &Arc<AtomicU64>) -> Router {
    let read = now.clone();
    Router::new_with_clock(
        RouterConfig::default().with_sender(name).with_timesync(cfg),
        Box::new(move || read.load(Ordering::SeqCst)),
    )
}

impl Net {
    fn new(nodes: &[(&'static str, TimeSyncConfig)], seed: u64) -> Self {
        // Every board has run for a while.
        let now = Arc::new(AtomicU64::new(60_000));
        Self {
            names: nodes.iter().map(|(n, _)| *n).collect(),
            cfgs: nodes.iter().map(|(_, c)| *c).collect(),
            nodes: nodes.iter().map(|(n, c)| router(n, *c, &now)).collect(),
            now,
            links: Vec::new(),
            flight: Vec::new(),
            rng: Rng(seed | 1),
            tapped: Arc::default(),
        }
    }

    fn side(&self, node: usize, peer: usize, out: &Wire) -> RouterSideId {
        let tx = out.clone();
        let tap = self.tapped.clone();
        self.nodes[node].add_side_packed(format!("to{peer}"), move |bytes: &[u8]| {
            tx.lock().unwrap().push(bytes.to_vec());
            tap.lock().unwrap().push((node, bytes.to_vec()));
            Ok(())
        })
    }

    fn link(&mut self, a: usize, b: usize, spec: LinkSpec) -> usize {
        let (a_out, b_out): (Wire, Wire) = (Arc::default(), Arc::default());
        let side_a = self.side(a, b, &a_out);
        let side_b = self.side(b, a, &b_out);
        // Both ends know the link's physical minimum (a true lower bound):
        // exchanges that crossed directly prove a tight bound.
        let min_ns = (spec.delay_ms.saturating_sub(1) * 1_000_000) as u32;
        self.nodes[a].set_side_timesync_min_delay(side_a, min_ns);
        self.nodes[b].set_side_timesync_min_delay(side_b, min_ns);
        self.links.push(Link { a, b, side_a, side_b, a_out, b_out, spec, up: true });
        self.links.len() - 1
    }

    /// Replaces a node with a freshly started router (a station restart): no
    /// time, epoch 0, the same links.
    fn restart(&mut self, node: usize) {
        self.nodes[node] = router(self.names[node], self.cfgs[node], &self.now);
        for i in 0..self.links.len() {
            let (a, b) = (self.links[i].a, self.links[i].b);
            let min_ns = (self.links[i].spec.delay_ms.saturating_sub(1) * 1_000_000) as u32;
            if a == node {
                let out = self.links[i].a_out.clone();
                self.links[i].side_a = self.side(node, b, &out);
                self.nodes[node].set_side_timesync_min_delay(self.links[i].side_a, min_ns);
            } else if b == node {
                let out = self.links[i].b_out.clone();
                self.links[i].side_b = self.side(node, a, &out);
                self.nodes[node].set_side_timesync_min_delay(self.links[i].side_b, min_ns);
            }
        }
    }

    fn mono(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn collect(&mut self) {
        let now = self.mono();
        for i in 0..self.links.len() {
            for toward_b in [true, false] {
                let out = if toward_b { &self.links[i].a_out } else { &self.links[i].b_out };
                let frames = std::mem::take(&mut *out.lock().unwrap());
                let spec = self.links[i].spec;
                for bytes in frames {
                    if !self.links[i].up || self.rng.unit() < spec.loss {
                        continue;
                    }
                    self.flight.push((now + spec.delay_ms, i, toward_b, bytes));
                }
            }
        }
    }

    fn tick(&mut self) {
        for node in &self.nodes {
            let _ = node.periodic(0);
        }
        for _ in 0..3 {
            self.collect();
            let now = self.mono();
            let mut due = Vec::new();
            self.flight.retain(|f| {
                if f.0 <= now {
                    due.push(f.clone());
                    false
                } else {
                    true
                }
            });
            for (_, link, toward_b, bytes) in due {
                let l = &self.links[link];
                let (to, side) = if toward_b { (l.b, l.side_b) } else { (l.a, l.side_a) };
                let _ = self.nodes[to].rx_packed_from_side(&bytes, side);
            }
            for node in &self.nodes {
                let _ = node.drain_queues_with_timeout(0);
            }
        }
        self.now.fetch_add(TICK, Ordering::SeqCst);
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms / TICK {
            self.tick();
        }
    }

    /// Network time of `node` minus the station's, ms.
    fn offset_ms(&self, node: usize) -> Option<i64> {
        let station = self.nodes[0].network_time_ms()? as i64;
        Some(self.nodes[node].network_time_ms()? as i64 - station)
    }

    fn all_within(&self, nodes: &[usize], ms: u64) -> bool {
        nodes
            .iter()
            .all(|&n| self.offset_ms(n).is_some_and(|o| o.unsigned_abs() <= ms))
    }

    /// Runs until every listed node is within `ms` of the station; elapsed ms.
    fn converge(&mut self, nodes: &[usize], ms: u64, limit_ms: u64) -> u64 {
        let start = self.mono();
        while self.mono() - start <= limit_ms {
            if self.all_within(nodes, ms) {
                return self.mono() - start;
            }
            self.tick();
        }
        panic!(
            "no convergence within {limit_ms} ms: offsets {:?}",
            nodes.iter().map(|&n| (self.names[n], self.offset_ms(n))).collect::<Vec<_>>()
        );
    }

    /// The station operator (or its host clock) sets UTC.
    fn station_sets(&self, unix_ms: u64) {
        self.nodes[0]
            .try_set_local_network_time(PartialNetworkTime::from_unix_ms(unix_ms))
            .unwrap();
    }

    fn epochs(&self) -> Vec<u16> {
        self.nodes.iter().map(|n| n.network_time_epoch()).collect()
    }
}

/// GS --Wi-Fi-- GATEWAY --CAN-- ACTUATOR, and GS --radio-- RF --CAN-- FC.
/// The actuator and the flight computer are each one relay away.
const GS: usize = 0;
const GW: usize = 1;
const AB: usize = 2;
const RF: usize = 3;
const FC: usize = 4;
const BOARDS: [usize; 4] = [GW, AB, RF, FC];

fn field_net(radio_loss: f64, seed: u64) -> Net {
    let mut net = Net::new(
        &[("GS", station()), ("GATEWAY", board()), ("ACTUATOR", board()), ("RF", board()), ("FC", board())],
        seed,
    );
    net.link(GS, GW, WIFI);
    net.link(GW, AB, CAN);
    net.link(GS, RF, LinkSpec { delay_ms: 25, loss: radio_loss });
    net.link(RF, FC, CAN);
    net
}

/// A station that booted with a stale clock: the whole network follows it.
fn synced_on_stale_station(radio_loss: f64, seed: u64) -> Net {
    let mut net = field_net(radio_loss, seed);
    net.station_sets(UTC + net.mono() - FIELD_OFFSET);
    net.converge(&BOARDS, 5, 30_000);
    net.run(20_000);
    net
}

fn assert_locked_together(net: &Net, label: &str) {
    for &n in &BOARDS {
        let st = net.nodes[n].timesync_status().unwrap();
        assert_eq!(st.state, SyncState::Locked, "{label}: {} {st:?}", net.names[n]);
        assert!(
            net.offset_ms(n).unwrap().unsigned_abs() <= 5,
            "{label}: {} off by {:?} ms",
            net.names[n],
            net.offset_ms(n)
        );
        assert!(!st.holding);
    }
    let epochs = net.epochs();
    assert!(epochs.iter().all(|&e| e == epochs[0]), "{label}: epochs {epochs:?}");
}

/// The field fault both ways (+3 h 49 min, then -4 h), clean and with 30% loss
/// on the radio: every board, including those behind a relay, follows the
/// station within seconds; nobody is left seconds-to-hours apart.
#[test]
fn hours_long_station_steps_converge_network_wide_in_seconds() {
    for (loss, limit_ms) in [(0.0, 5_000), (0.3, 15_000)] {
        for seed in [1u64, 0x5eed] {
            let label = format!("loss {loss} seed {seed}");
            let mut net = synced_on_stale_station(loss, seed);
            assert_locked_together(&net, &label);
            assert_eq!(net.epochs(), vec![0; 5], "{label}: no step yet");

            // The operator sets real UTC: 3 h 49 min forward.
            net.station_sets(UTC + net.mono());
            let station = net.nodes[GS].timesync_status().unwrap();
            let step = station.last_step.unwrap();
            assert_eq!(step.reason, TimeSyncStepReason::LocalSource, "{label}");
            assert!(step.delta_ns.abs_diff(FIELD_OFFSET as i64 * 1_000_000) < 50_000_000, "{label}: {step:?}");
            assert_eq!((step.from_epoch, step.to_epoch), (0, 1), "{label}");
            let coarse = net.converge(&BOARDS, 50, 3_000);
            let took = coarse + net.converge(&BOARDS, 2, limit_ms);
            println!("{label}: +{FIELD_OFFSET} ms step: every board within 50 ms after {coarse} ms, 2 ms after {took} ms");
            net.run(30_000);
            assert_locked_together(&net, &label);
            assert_eq!(net.epochs(), vec![1; 5], "{label}");
            for &n in &BOARDS {
                let st = net.nodes[n].timesync_status().unwrap();
                assert_eq!(st.last_step.unwrap().reason, TimeSyncStepReason::SourceEpoch, "{label}");
            }

            // And four hours back (a wrong correction undone).
            net.station_sets(UTC + net.mono() - 4 * HOUR);
            let coarse = net.converge(&BOARDS, 50, 3_000);
            let took = coarse + net.converge(&BOARDS, 2, limit_ms);
            println!("{label}: -4 h step: every board within 50 ms after {coarse} ms, 2 ms after {took} ms");
            net.run(30_000);
            assert_locked_together(&net, &label);
            assert_eq!(net.epochs(), vec![2; 5], "{label}");
        }
    }
}

/// Below the step threshold a correction is slewed at the reference rate,
/// which followers track as a frequency change: they stay locked and within
/// milliseconds of the station the whole time, and no epoch starts. Above it,
/// the station steps. With steps inhibited (flight), even hours are slewed
/// and the network still stays together.
#[test]
fn slew_below_the_step_threshold_step_above_and_inhibited_steps_slew() {
    let mut net = synced_on_stale_station(0.3, 7);
    // 900 ms off: slewed at 20 ppm.
    net.station_sets(net.nodes[GS].network_time_ms().unwrap() + 900);
    let st = net.nodes[GS].timesync_status().unwrap();
    assert_eq!(st.steps, 0, "{st:?}");
    let gs_before = net.nodes[GS].network_time_ms().unwrap();
    let mut worst = 0u64;
    for _ in 0..60 {
        net.run(1_000);
        for &n in &BOARDS {
            worst = worst.max(net.offset_ms(n).unwrap().unsigned_abs());
        }
    }
    let gs_after = net.nodes[GS].network_time_ms().unwrap();
    // 60 s at 20 ppm moves the station 1.2 ms beyond real time, no more.
    let slewed = (gs_after - gs_before) as i64 - 60_000;
    assert!((1..=2).contains(&slewed), "slewed {slewed} ms in 60 s");
    assert!(worst <= 3, "a board fell {worst} ms behind the slewing station");
    assert_locked_together(&net, "while slewing");
    assert_eq!(net.epochs(), vec![0; 5]);

    // 1100 ms off: stepped, a new epoch.
    let gs_now = net.nodes[GS].network_time_ms().unwrap();
    net.station_sets(gs_now + 1_100);
    let st = net.nodes[GS].timesync_status().unwrap();
    assert_eq!(st.epoch, 1);
    assert!(st.last_step.unwrap().delta_ns.abs_diff(1_100_000_000) < 20_000_000);
    net.converge(&BOARDS, 20, 10_000);
    net.run(20_000);
    assert_locked_together(&net, "after the 1.1 s step");

    // Flight: steps inhibited. Four hours are slewed; the network stays together.
    net.nodes[GS].set_timesync_steps_allowed(false);
    let gs_now = net.nodes[GS].network_time_ms().unwrap();
    net.station_sets(gs_now + 4 * HOUR);
    assert!(!net.nodes[GS].step_local_network_time_ns(((gs_now + 4 * HOUR) * 1_000_000) as i64));
    let mut worst = 0u64;
    for _ in 0..60 {
        net.run(1_000);
        for &n in &BOARDS {
            worst = worst.max(net.offset_ms(n).unwrap().unsigned_abs());
        }
    }
    assert!(worst <= 3, "a board fell {worst} ms behind");
    assert_eq!(net.epochs(), vec![1; 5]);
    let st = net.nodes[GS].timesync_status().unwrap();
    assert!(!st.steps_allowed);
    assert!(st.offset_ns > 3 * HOUR as i64 * 1_000_000, "the rest is still being slewed: {st:?}");
}

/// The step threshold is configurable: a station configured with 5 s slews a
/// 3 s correction and steps a 6 s one.
#[test]
fn step_threshold_is_configurable() {
    let cfg = TimeSyncConfig { step_threshold_ms: 5_000, ..station() };
    let now = Arc::new(AtomicU64::new(1_000));
    let gs = router("GS", cfg, &now);
    gs.try_set_local_network_time(PartialNetworkTime::from_unix_ms(UTC)).unwrap();
    gs.try_set_local_network_time(PartialNetworkTime::from_unix_ms(UTC + 3_000)).unwrap();
    assert_eq!(gs.network_time_epoch(), 0);
    assert_eq!(gs.network_time_ms(), Some(UTC));
    gs.try_set_local_network_time(PartialNetworkTime::from_unix_ms(UTC + 6_000)).unwrap();
    assert_eq!(gs.network_time_epoch(), 1);
    assert_eq!(gs.network_time_ms(), Some(UTC + 6_000));
}

// ---------------------------------------------------------------------------
// Ordering across a step: the managed FLIGHT_STATE cache.
// ---------------------------------------------------------------------------

const IDLE: u8 = 1;
const LAUNCH: u8 = 3;
const ABORT: u8 = 15;

fn flight_state() -> (DataType, DataEndpoint) {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "TS_EPOCH_FLIGHT_STATE",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        16,
    )
    .unwrap();
    (ty, endpoint)
}

fn cached(router: &Router, ty: DataType) -> Option<u8> {
    router.cached_managed_variable(ty).map(|p| p.payload()[0])
}

/// The station writes a state stamped with its network time, as the GS does.
fn station_writes(net: &Net, ty: DataType, ep: DataEndpoint, value: u8) -> Packet {
    let (ms, _) = net.nodes[GS].network_time_ms_with_epoch().unwrap();
    let pkt = Packet::new(ty, &[ep], "GS", ms, Arc::<[u8]>::from([value])).unwrap();
    net.nodes[GS].set_network_variable(pkt.clone()).unwrap();
    net.nodes[GS].own_network_variable(ty).unwrap_or(pkt)
}

/// After a 4 h step back, a write made after the step reaches every board and
/// supersedes the pre-step state (before: refused for 4 h as "older"); a late
/// copy of the pre-step Launch never re-applies; Abort always gets through.
#[test]
fn managed_state_orders_across_a_backward_step_and_refuses_pre_step_replays() {
    let (ty, ep) = flight_state();
    let mut net = synced_on_stale_station(0.0, 3);
    net.nodes[GS].enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE).unwrap();
    for &n in &BOARDS {
        net.nodes[n].enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY).unwrap();
    }
    // The station's clock is ahead this time: corrected 4 h back.
    let ahead = net.nodes[GS].network_time_ms().unwrap() + 4 * HOUR;
    net.station_sets(ahead);
    net.converge(&BOARDS, 20, 5_000);
    net.run(5_000);
    let launch = station_writes(&net, ty, ep, LAUNCH);
    net.run(1_000);
    for &n in &[AB, FC] {
        assert_eq!(cached(&net.nodes[n], ty), Some(LAUNCH));
    }
    let launch_epoch = launch.time_epoch();
    assert_eq!(launch_epoch, 1);

    let now = net.nodes[GS].network_time_ms().unwrap();
    net.station_sets(now - 4 * HOUR);
    net.converge(&BOARDS, 20, 5_000);
    let idle = station_writes(&net, ty, ep, IDLE);
    assert!(idle.timestamp() < launch.timestamp(), "the later write is stamped hours earlier");
    assert_eq!(idle.time_epoch(), 2);
    assert_eq!(cached(&net.nodes[GS], ty), Some(IDLE), "the writer's own cache took its write");
    net.run(1_000);
    for &n in &[GW, AB, RF, FC] {
        assert_eq!(cached(&net.nodes[n], ty), Some(IDLE), "{}", net.names[n]);
    }

    // A stale copy of the pre-step Launch (a late relay retransmission; a new
    // nonce so receipt dedupe cannot be what stops it) arrives everywhere.
    let replay = Packet::new_with_nonce(ty, &[ep], "GS", launch.timestamp(), launch.nonce() ^ 0x55, Arc::<[u8]>::from([LAUNCH]))
        .unwrap()
        .with_time_epoch(launch_epoch);
    for &n in &[AB, FC] {
        let bytes = crate::wire_format::pack_packet(&replay);
        let side = net.links.iter().find(|l| l.b == n).unwrap().side_b;
        net.nodes[n].rx_packed_from_side(&bytes, side).unwrap();
        net.nodes[n].drain_queues_with_timeout(0).unwrap();
        assert_eq!(cached(&net.nodes[n], ty), Some(IDLE), "{}: the pre-step Launch re-applied", net.names[n]);
    }

    // Abort, written after the step, always gets through.
    station_writes(&net, ty, ep, ABORT);
    net.run(1_000);
    for &n in &BOARDS {
        assert_eq!(cached(&net.nodes[n], ty), Some(ABORT), "{}", net.names[n]);
    }
}

/// A board judges a command's freshness through `network_stamp_age_ms`: a
/// command stamped 2 s before a 4 h step back is 2 s old (not 4 h in the
/// future), a stamp from a newer epoch than the board's clock is reported as
/// such, and stamps older than the remembered steps are stale.
#[test]
fn stamp_age_translates_across_remembered_steps() {
    let mut net = synced_on_stale_station(0.3, 11);
    let (before, epoch0) = net.nodes[GS].network_time_ms_with_epoch().unwrap();
    net.run(2_000);
    net.station_sets(net.nodes[GS].network_time_ms().unwrap() - 4 * HOUR);
    net.converge(&BOARDS, 20, 10_000);
    for &n in &BOARDS {
        match net.nodes[n].network_stamp_age_ms(epoch0, before) {
            NetworkStampAge::Age(age) => assert!(
                (2_000..=12_500).contains(&age),
                "{}: a 2 s old command aged {age} ms",
                net.names[n]
            ),
            other => panic!("{}: {other:?}", net.names[n]),
        }
        let (now, epoch) = net.nodes[GS].network_time_ms_with_epoch().unwrap();
        match net.nodes[n].network_stamp_age_ms(epoch, now) {
            NetworkStampAge::Age(age) => assert!(age.abs() <= 20, "{}: {age}", net.names[n]),
            other => panic!("{other:?}"),
        }
        assert!(matches!(net.nodes[n].network_stamp_age_ms(epoch + 1, now), NetworkStampAge::NewerEpoch { .. }));
    }
    // Five more steps: the first is no longer remembered.
    for _ in 0..5 {
        net.station_sets(net.nodes[GS].network_time_ms().unwrap() + 2 * HOUR);
        net.converge(&BOARDS, 20, 10_000);
    }
    assert_eq!(net.nodes[FC].network_stamp_age_ms(epoch0, before), NetworkStampAge::OlderEpoch);
}

/// A station restarts (epoch 0) while the boards are in epoch 1. Its own
/// clock agrees with the network: it adopts the network's epoch from the
/// first requests, the boards never step, and its writes are accepted. A
/// restart with a clock 10 s off names a newer epoch and the boards follow.
#[test]
fn restarted_station_adopts_the_network_epoch() {
    let (ty, ep) = flight_state();
    let mut net = synced_on_stale_station(0.0, 5);
    net.station_sets(UTC + net.mono());
    net.converge(&BOARDS, 20, 5_000);
    net.run(10_000);
    assert_eq!(net.epochs(), vec![1; 5]);
    for &n in &BOARDS {
        net.nodes[n].enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY).unwrap();
    }
    let steps: Vec<u32> = BOARDS.iter().map(|&n| net.nodes[n].timesync_status().unwrap().steps).collect();

    net.restart(GS);
    net.nodes[GS].enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE).unwrap();
    net.station_sets(UTC + net.mono());
    assert_eq!(net.nodes[GS].network_time_epoch(), 0);
    net.run(3_000);
    assert_eq!(net.epochs(), vec![1; 5], "the station adopted the network's epoch");
    let after: Vec<u32> = BOARDS.iter().map(|&n| net.nodes[n].timesync_status().unwrap().steps).collect();
    assert_eq!(steps, after, "no board stepped");
    station_writes(&net, ty, ep, IDLE);
    net.run(1_000);
    for &n in &BOARDS {
        assert_eq!(cached(&net.nodes[n], ty), Some(IDLE));
    }

    net.restart(GS);
    net.station_sets(UTC + net.mono() + 10_000);
    net.run(3_000);
    assert_eq!(net.nodes[GS].network_time_epoch(), 2, "a different base under a newer epoch");
    net.converge(&BOARDS, 20, 10_000);
    net.run(20_000);
    assert_locked_together(&net, "after the second restart");
    assert_eq!(net.epochs(), vec![2; 5]);
}

/// The radio is down while both sides step on their own: the station 4 h
/// back (epoch 1), and RF, leading the vehicle meanwhile, onto its own time
/// (also epoch 1, a different base). When the radio returns RF must not step
/// back inside epoch 1 (its later stamps would sort before its earlier ones):
/// it names epoch 2, the station adopts a newer epoch from RF's requests, and
/// RF and FC step onto the station's time in that epoch.
#[test]
fn partitioned_steps_under_one_epoch_number_reconcile() {
    let mut net = Net::new(
        &[
            ("GS", station()),
            ("RF", TimeSyncConfig { role: TimeSyncRole::Auto, priority: 60, ..board() }),
            ("FC", board()),
        ],
        9,
    );
    let radio = net.link(0, 1, LinkSpec { delay_ms: 25, loss: 0.2 });
    net.link(1, 2, CAN);
    net.station_sets(UTC + net.mono());
    net.converge(&[1, 2], 5, 30_000);
    net.run(10_000);
    net.links[radio].up = false;
    net.run(8_000);
    net.station_sets(UTC + net.mono() - 4 * HOUR);
    assert_eq!(net.nodes[0].network_time_epoch(), 1);
    // RF leads the vehicle now and gets a local fix of its own.
    net.nodes[1]
        .try_set_local_network_time(PartialNetworkTime::from_unix_ms(UTC + net.mono() + 30_000))
        .unwrap();
    net.run(5_000);
    assert_eq!(net.nodes[1].network_time_epoch(), 1);
    assert!(net.offset_ms(2).unwrap() > 3 * HOUR as i64, "FC follows RF's base");

    net.links[radio].up = true;
    net.converge(&[1, 2], 20, 15_000);
    net.run(20_000);
    let epochs = net.epochs();
    assert!(epochs.iter().all(|&e| e == epochs[0] && e >= 3), "epochs {epochs:?}");
    for n in [1, 2] {
        let st = net.nodes[n].timesync_status().unwrap();
        assert_eq!(st.state, SyncState::Locked, "{st:?}");
        assert!(net.offset_ms(n).unwrap().unsigned_abs() <= 5);
    }
}

/// A board that hears a packet from a newer epoch asks its source at once
/// instead of waiting for its (relaxed) request interval.
#[test]
fn a_newer_epoch_on_any_packet_triggers_a_prompt_request() {
    let (ty, ep) = flight_state();
    let mut net = synced_on_stale_station(0.0, 13);
    net.run(30_000);
    let st = net.nodes[GW].timesync_status().unwrap();
    assert_eq!(st.newest_seen_epoch, 0);
    let gw_requested = |net: &Net| {
        net.tapped.lock().unwrap().iter().any(|(from, bytes)| {
            *from == GW
                && crate::wire_format::unpack_packet(bytes)
                    .is_ok_and(|p| p.data_type() == DataType::TimeSyncRequest)
        })
    };
    // Start right after a quiet tick: the relaxed interval is seconds long.
    loop {
        net.tapped.lock().unwrap().clear();
        net.tick();
        if !gw_requested(&net) {
            break;
        }
    }
    net.tapped.lock().unwrap().clear();
    let telemetry = Packet::new(ty, &[ep], "SOMEONE", UTC, Arc::<[u8]>::from([0])).unwrap().with_time_epoch(4);
    let side = net.links[1].side_a;
    net.nodes[GW].rx_packed_from_side(&crate::wire_format::pack_packet(&telemetry), side).unwrap();
    net.nodes[GW].drain_queues_with_timeout(0).unwrap();
    assert_eq!(net.nodes[GW].timesync_status().unwrap().newest_seen_epoch, 4);
    net.tick();
    assert!(gw_requested(&net), "no prompt request");
}


// ---------------------------------------------------------------------------
// Scenario matrix (SEDSnet 6): sources, restarts, relays, authority,
// sequences, repeated steps and the step policy.
// ---------------------------------------------------------------------------

/// Every node's own packets (time sync included) must order by
/// `(epoch, timestamp)` in the order it sent them: no node ever steps back
/// inside an epoch. Checks every frame tapped since the net was built.
fn assert_senders_ordered(net: &Net, label: &str) {
    let tapped = net.tapped.lock().unwrap();
    for (node, name) in net.names.iter().enumerate() {
        let mut last: Option<(u16, u64)> = None;
        for (from, bytes) in tapped.iter() {
            if *from != node {
                continue;
            }
            let Ok(pkt) = crate::wire_format::unpack_packet(bytes) else {
                continue;
            };
            if pkt.sender() != *name {
                continue;
            }
            let stamp = (pkt.time_epoch(), pkt.timestamp());
            if let Some(prev) = last {
                assert!(
                    stamp >= prev || pkt.timestamp() < crate::timesync::TIMESYNC_UTC_FLOOR_MS,
                    "{label}: {name} sent {stamp:?} after {prev:?} ({:?})",
                    pkt.data_type()
                );
            }
            if pkt.timestamp() >= crate::timesync::TIMESYNC_UTC_FLOOR_MS {
                last = Some(stamp);
            }
        }
    }
}

/// Seconds to hours, forward and back, from each kind of local source the
/// leading station has: an operator/client set (`try_set_local_network_time`)
/// and a host/NTP correction fed as a named source (`update_network_time_source`).
/// Every follower, including those one relay away, converges within one or
/// two exchanges (under 2 s on clean links), and each step starts exactly one
/// new epoch.
#[test]
fn jumps_of_seconds_to_hours_from_operator_and_host_sources_converge() {
    let mut net = synced_on_stale_station(0.0, 21);
    let mut epoch = 0u16;
    let jumps: [i64; 8] = [2_000, -2_000, 90_000, -90_000, 6 * HOUR as i64, -6 * HOUR as i64, 1_500, -(13_700_000)];
    for (i, jump) in jumps.iter().enumerate() {
        let target = (net.nodes[GS].network_time_ms().unwrap() as i64 + jump) as u64;
        if i % 2 == 0 {
            net.station_sets(target);
        } else {
            net.nodes[GS].update_network_time_source("host-ntp", 10, PartialNetworkTime::from_unix_ms(target), None);
        }
        epoch += 1;
        assert_eq!(net.nodes[GS].network_time_epoch(), epoch, "jump {jump}");
        let took = net.converge(&BOARDS, 50, 2_000);
        println!("jump {jump} ms: every board within 50 ms after {took} ms");
        net.run(3_000);
        assert_eq!(net.epochs(), vec![epoch; 5], "jump {jump}");
    }
    net.run(20_000);
    assert_locked_together(&net, "after the jump series");
    assert_senders_ordered(&net, "jump series");
}

/// RF leads the AV bay from its GPS (station out of reach). A GPS fix that
/// jumps (a wrong cold-start fix corrected, either way) steps RF and FC
/// follows within two exchanges. When the station is heard again, its better
/// priority (50 vs RF's 70) wins deterministically, and RF and FC re-anchor
/// onto the station's time base whatever the two clocks' epochs were.
#[test]
fn gps_source_jumps_and_station_authority_on_merge() {
    let rf_cfg = TimeSyncConfig { role: TimeSyncRole::Source, priority: 70, ..board() };
    let mut net = Net::new(&[("GS", station()), ("RF", rf_cfg), ("FC", board())], 31);
    let radio = net.link(0, 1, LinkSpec { delay_ms: 45, loss: 0.2 });
    net.link(1, 2, CAN);
    net.links[radio].up = false;
    net.station_sets(UTC + net.mono());
    let gps = |net: &Net, off: i64| {
        net.nodes[1].try_set_local_network_time(PartialNetworkTime::from_unix_ms((UTC as i64 + net.mono() as i64 + off) as u64)).unwrap()
    };
    gps(&net, 0);
    let fc_off = |net: &Net| net.nodes[2].network_time_ms().unwrap() as i64 - net.nodes[1].network_time_ms().unwrap() as i64;
    net.run(15_000);
    assert!(fc_off(&net).abs() <= 5, "FC follows RF's GPS: {}", fc_off(&net));
    for off in [2 * HOUR as i64, -(3 * HOUR as i64), 4_000, 0] {
        gps(&net, off);
        let start = net.mono();
        while fc_off(&net).abs() > 50 {
            assert!(net.mono() - start < 2_000, "FC did not follow a GPS jump of {off} ms: {}", fc_off(&net));
            net.tick();
        }
        net.run(2_000);
    }
    let rf_epoch = net.nodes[1].network_time_epoch();
    assert!(rf_epoch >= 3, "each GPS jump stepped RF: epoch {rf_epoch}");
    // The station returns: it outranks RF, which (and FC) follow it.
    net.links[radio].up = true;
    net.converge(&[1, 2], 20, 20_000);
    net.run(20_000);
    for n in [1, 2] {
        let st = net.nodes[n].timesync_status().unwrap();
        assert_eq!(st.state, SyncState::Locked, "{st:?}");
        assert!(!st.is_reference, "{} must follow the station", net.names[n]);
        assert!(net.offset_ms(n).unwrap().unsigned_abs() <= 5);
    }
    assert!(net.nodes[0].timesync_status().unwrap().is_reference);
    let epochs = net.epochs();
    assert!(epochs.iter().all(|&e| e == epochs[0]), "epochs {epochs:?}");
    assert_senders_ordered(&net, "gps and merge");
}

/// Two would-be sources: the GS (priority 50) and an RRLS (60), each with its
/// own host clock 400 ms apart, both reaching RF. The GS leads; the RRLS
/// follows it. When the GS goes silent the RRLS takes over without any
/// follower stepping; when the GS returns it leads again, again without steps.
#[test]
fn two_sources_have_a_deterministic_authority_and_hand_over_without_steps() {
    let rrls_cfg = TimeSyncConfig { role: TimeSyncRole::Source, priority: 60, ..board() };
    let mut net = Net::new(&[("GS", station()), ("RRLS", rrls_cfg), ("RF", board()), ("FC", board())], 41);
    let gs_radio = net.link(0, 2, LinkSpec { delay_ms: 45, loss: 0.1 });
    net.link(1, 2, LinkSpec { delay_ms: 45, loss: 0.1 });
    net.link(2, 3, CAN);
    net.station_sets(UTC + net.mono());
    net.nodes[1].try_set_local_network_time(PartialNetworkTime::from_unix_ms(UTC + net.mono() + 400)).unwrap();
    net.converge(&[1, 2, 3], 10, 30_000);
    net.run(20_000);
    let rf = net.nodes[2].timesync_status().unwrap();
    assert!(!rf.is_reference);
    assert!(net.nodes[0].timesync_status().unwrap().is_reference, "the GS leads");
    assert!(!net.nodes[1].timesync_status().unwrap().is_reference, "the RRLS follows the GS");
    assert!(net.offset_ms(1).unwrap().unsigned_abs() <= 10, "RRLS follows: {:?}", net.offset_ms(1));
    let steps = |net: &Net| [2usize, 3].map(|n| net.nodes[n].timesync_status().unwrap().steps);
    let before = steps(&net);
    let epochs_before = net.epochs();
    // GS silent: the RRLS takes over after the source timeout.
    net.links[gs_radio].up = false;
    net.run(20_000);
    assert!(net.nodes[1].timesync_status().unwrap().is_reference, "the RRLS leads during the outage");
    assert_eq!(steps(&net), before, "no follower stepped at the hand-over");
    for n in [2, 3] {
        assert_eq!(net.nodes[n].timesync_status().unwrap().state, SyncState::Locked);
    }
    // GS back: it leads again.
    net.links[gs_radio].up = true;
    net.run(20_000);
    assert!(net.nodes[0].timesync_status().unwrap().is_reference);
    assert!(!net.nodes[1].timesync_status().unwrap().is_reference);
    assert_eq!(steps(&net), before, "no follower stepped when the GS returned");
    assert_eq!(net.epochs(), epochs_before);
    for n in [1, 2, 3] {
        assert!(net.offset_ms(n).unwrap().unsigned_abs() <= 10, "{}: {:?}", net.names[n], net.offset_ms(n));
    }
}

/// A board restarts (no time, epoch 0) after the network stepped twice, and a
/// node joins late: both adopt the network's epoch and time within seconds.
#[test]
fn board_restart_and_late_joiner_adopt_the_network_epoch() {
    let mut net = synced_on_stale_station(0.3, 51);
    net.station_sets(UTC + net.mono());
    net.converge(&BOARDS, 20, 5_000);
    net.station_sets(net.nodes[GS].network_time_ms().unwrap() - 4 * HOUR);
    net.converge(&BOARDS, 20, 5_000);
    assert_eq!(net.epochs(), vec![2; 5]);
    net.restart(AB);
    assert_eq!(net.nodes[AB].network_time_epoch(), 0);
    net.converge(&[AB], 20, 5_000);
    net.restart(FC);
    net.converge(&[FC], 20, 10_000);
    assert_eq!(net.epochs(), vec![2; 5]);
    // A late joiner behind the gateway.
    let late = net.nodes.len();
    net.names.push("LATE");
    net.cfgs.push(board());
    let r = router("LATE", board(), &net.now);
    net.nodes.push(r);
    net.link(GW, late, CAN);
    net.converge(&[late], 20, 5_000);
    net.run(10_000);
    assert_eq!(net.nodes[late].network_time_epoch(), 2);
    assert_eq!(net.nodes[late].timesync_status().unwrap().state, SyncState::Locked);
}

/// A step through the RF relay hop over a radio with ~45 ms air packets and
/// 0%, 25% and 50% loss: RF and FC (behind RF) follow within seconds, and stay
/// locked afterwards.
#[test]
fn relay_hop_over_a_lossy_radio_follows_steps() {
    for (loss, limit_ms) in [(0.0, 2_000), (0.25, 6_000), (0.5, 20_000)] {
        let mut net = Net::new(&[("GS", station()), ("RF", board()), ("FC", board())], 61);
        net.link(0, 1, LinkSpec { delay_ms: 45, loss });
        net.link(1, 2, CAN);
        net.station_sets(UTC + net.mono() - FIELD_OFFSET);
        net.converge(&[1, 2], 5, 60_000);
        net.run(20_000);
        for jump in [FIELD_OFFSET as i64, -(4 * HOUR as i64)] {
            let target = (net.nodes[0].network_time_ms().unwrap() as i64 + jump) as u64;
            net.station_sets(target);
            let took = net.converge(&[1, 2], 50, limit_ms);
            println!("loss {loss}: {jump} ms step followed through the relay within 50 ms after {took} ms");
            // Afterwards every reading stays within 50 ms and inside the
            // node's own reported error bound; below 50% loss both lock.
            for _ in 0..20 {
                net.run(1_000);
                for n in [1, 2] {
                    let st = net.nodes[n].timesync_status().unwrap();
                    let off = net.offset_ms(n).unwrap().unsigned_abs();
                    assert!(off <= 50, "loss {loss}: {} off by {off} ms", net.names[n]);
                    assert!(off * 1_000_000 <= st.error_bound_ns.saturating_add(1_000_000), "loss {loss}: bound dishonest {st:?} off {off}");
                    assert_eq!(st.epoch, net.nodes[0].network_time_epoch());
                }
            }
            if loss < 0.5 {
                for n in [1, 2] {
                    let st = net.nodes[n].timesync_status().unwrap();
                    assert_eq!(st.state, SyncState::Locked, "loss {loss}: {st:?}");
                    assert!(net.offset_ms(n).unwrap().unsigned_abs() <= 5, "loss {loss}");
                }
            }
        }
        assert_senders_ordered(&net, &format!("relay loss {loss}"));
    }
}

/// Repeated steps in quick succession (2 s apart, alternating directions,
/// 1.5 s to 3 h): the network ends in one epoch, locked together, and no node
/// ever sent a stamp that orders before an earlier one of its own.
#[test]
fn repeated_steps_settle_in_one_epoch_with_ordered_stamps() {
    let mut net = synced_on_stale_station(0.2, 71);
    for jump in [1_500i64, -3 * HOUR as i64, 2 * HOUR as i64, -5_000, 3 * HOUR as i64, -1_200] {
        let target = (net.nodes[GS].network_time_ms().unwrap() as i64 + jump) as u64;
        net.station_sets(target);
        net.run(2_000);
    }
    net.converge(&BOARDS, 20, 10_000);
    net.run(30_000);
    assert_locked_together(&net, "after repeated steps");
    assert_eq!(net.nodes[GS].network_time_epoch(), 6);
    assert_senders_ordered(&net, "repeated steps");
}

/// A command sequence in progress (one GS command every 100 ms, each judged by
/// the receiving boards with a 5 s / 1 s validity window as AB judges an AUX
/// QD) while the station steps 4 h back and then 3 h 49 min forward: no
/// command is refused, before, during or after either step; a copy of a
/// pre-step command delivered 6 s later is refused.
#[test]
fn command_windows_hold_through_steps_during_an_active_sequence() {
    let mut net = synced_on_stale_station(0.0, 81);
    let mut refused = Vec::new();
    let mut late_copies = Vec::new();
    for i in 0..200u64 {
        if i == 50 {
            net.station_sets(net.nodes[GS].network_time_ms().unwrap() - 4 * HOUR);
        }
        if i == 120 {
            net.station_sets(net.nodes[GS].network_time_ms().unwrap() + FIELD_OFFSET);
        }
        let (ts, epoch) = net.nodes[GS].network_time_ms_with_epoch().unwrap();
        if i == 45 || i == 115 {
            late_copies.push((i, epoch, ts));
        }
        net.run(30); // transit through the gateway
        for &n in &[GW, AB, RF, FC] {
            if !net.nodes[n].network_stamp_is_fresh(epoch, ts, 5_000, 1_000) {
                refused.push((i, net.names[n], net.nodes[n].network_stamp_age_ms(epoch, ts)));
            }
        }
        net.run(70);
    }
    assert!(refused.is_empty(), "refused commands: {refused:?}");
    net.run(6_000);
    for (i, epoch, ts) in late_copies {
        for &n in &[AB, FC] {
            assert!(
                !net.nodes[n].network_stamp_is_fresh(epoch, ts, 5_000, 1_000),
                "{}: a copy of command {i} delivered seconds after a step passed: {:?}",
                net.names[n],
                net.nodes[n].network_stamp_age_ms(epoch, ts)
            );
        }
    }
}

/// The step policy. Inhibited (flight), a 4 h correction is slewed; when
/// steps are allowed again the next local-source update steps. A station
/// restarted while steps are inhibited, with a host clock 10 s off the
/// network's, joins the network's time base: no follower steps; once steps
/// are allowed its host time steps the network as usual.
#[test]
fn step_policy_inhibited_then_allowed_and_a_restarted_station_joins_in_flight() {
    let mut net = synced_on_stale_station(0.1, 91);
    net.station_sets(UTC + net.mono());
    net.converge(&BOARDS, 20, 5_000);
    net.run(10_000);
    assert_eq!(net.epochs(), vec![1; 5]);
    net.nodes[GS].set_timesync_steps_allowed(false);
    net.station_sets(net.nodes[GS].network_time_ms().unwrap() + 4 * HOUR);
    net.run(5_000);
    assert_eq!(net.epochs(), vec![1; 5], "inhibited: no step");
    assert_locked_together(&net, "slewing in flight");
    net.nodes[GS].set_timesync_steps_allowed(true);
    // The host refresh feeds the same (still 4 h away) time: now it steps.
    net.station_sets(net.nodes[GS].network_time_ms().unwrap() + 4 * HOUR);
    assert_eq!(net.nodes[GS].network_time_epoch(), 2);
    net.converge(&BOARDS, 20, 5_000);
    net.run(10_000);
    assert_locked_together(&net, "stepped once allowed");

    let steps = |net: &Net| BOARDS.map(|n| net.nodes[n].timesync_status().unwrap().steps);
    let before = steps(&net);
    let network_now = net.nodes[GW].network_time_ms().unwrap();
    net.restart(GS);
    net.nodes[GS].set_timesync_steps_allowed(false);
    net.station_sets(network_now + 10_000);
    net.run(5_000);
    let st = net.nodes[GS].timesync_status().unwrap();
    assert_eq!(st.epoch, 2, "joined the network's epoch: {st:?}");
    assert_eq!(st.last_step.unwrap().reason, TimeSyncStepReason::Joined);
    assert_eq!(steps(&net), before, "no follower stepped for the restarted station");
    net.converge(&BOARDS, 20, 5_000);
    net.run(10_000);
    assert_locked_together(&net, "after the station joined");
    net.nodes[GS].set_timesync_steps_allowed(true);
    let host = net.nodes[GS].network_time_ms().unwrap() + 10_000;
    net.station_sets(host);
    assert_eq!(net.nodes[GS].network_time_epoch(), 3);
    net.converge(&BOARDS, 20, 5_000);
    net.run(10_000);
    assert_locked_together(&net, "after the station's host time stepped the network");
}

/// Every node restarts at once (a whole-stack power cycle). The actuator
/// persisted a replay floor stamped in epoch 3 and raises its epoch to it at
/// boot: the network settles in an epoch at or above 3, so the station's next
/// command orders after the floor, while the floor still refuses anything
/// stamped before it.
#[test]
fn a_persisted_epoch_raises_the_network_after_a_whole_stack_restart() {
    let mut net = synced_on_stale_station(0.0, 101);
    for _ in 0..3 {
        net.station_sets(net.nodes[GS].network_time_ms().unwrap() + 2 * HOUR);
        net.converge(&BOARDS, 20, 5_000);
    }
    let floor = net.nodes[GS].network_time_ms_with_epoch().map(|(ms, e)| (e, ms)).unwrap();
    assert_eq!(floor.0, 3);
    for n in 0..net.nodes.len() {
        net.restart(n);
    }
    assert_eq!(net.nodes[AB].raise_network_time_epoch(floor.0), 3);
    // The station's host clock is earlier than the floor's stamp.
    net.station_sets(floor.1 - HOUR);
    net.converge(&BOARDS, 20, 10_000);
    net.run(20_000);
    assert_locked_together(&net, "after the whole-stack restart");
    let (ms, epoch) = net.nodes[GS].network_time_ms_with_epoch().unwrap();
    assert!(epoch >= 3, "network epoch {epoch}");
    assert_eq!(crate::timesync::compare_network_stamps((epoch, ms), floor), std::cmp::Ordering::Greater);
    assert_eq!(
        crate::timesync::compare_network_stamps((floor.0, floor.1 - 1), floor),
        std::cmp::Ordering::Less
    );
}

/// Freshness verdicts and packet identity across epochs.
#[test]
fn stamp_freshness_verdicts_and_identity_across_epochs() {
    use NetworkStampAge::*;
    assert!(Age(0).is_fresh(5_000, 1_000));
    assert!(Age(5_000).is_fresh(5_000, 1_000));
    assert!(!Age(5_001).is_fresh(5_000, 1_000));
    assert!(Age(-1_000).is_fresh(5_000, 1_000));
    assert!(!Age(-1_001).is_fresh(5_000, 1_000));
    assert!(NewerEpoch { since_ms: 0 }.is_fresh(5_000, 0));
    assert!(!NewerEpoch { since_ms: 5_001 }.is_fresh(5_000, 0));
    assert!(!OlderEpoch.is_fresh(u64::MAX, u64::MAX));
    assert!(!NoTime.is_fresh(u64::MAX, u64::MAX));
    // The same stamp and nonce in another epoch is another packet: receipt
    // dedupe never mistakes a post-step packet for a pre-step one.
    let (ty, ep) = flight_state();
    let a = Packet::new_with_nonce(ty, &[ep], "GS", UTC, 7, Arc::<[u8]>::from([1u8])).unwrap();
    let b = a.clone().with_time_epoch(1);
    assert_ne!(a.packet_id(), b.packet_id());
    assert_eq!(a.packet_id(), a.clone().with_time_epoch(0).packet_id());
}


/// A board that cannot sync at all (its only source is gone before it ever
/// got time) still judges station commands from the stamps it hears: a fresh
/// command passes, a stale one and one from before a step it never followed
/// do not, and a newer epoch re-anchors the estimate (a step back included).
#[test]
fn a_board_that_cannot_sync_judges_commands_from_heard_stamps() {
    let (ty, ep) = flight_state();
    let now = Arc::new(AtomicU64::new(10_000));
    let board_router = router("LONELY", TimeSyncConfig::default(), &now);
    let side = board_router.add_side_packed("gs", |_| Ok(()));
    assert_eq!(board_router.network_stamp_age_ms(0, UTC), NetworkStampAge::NoTime);
    let hear = |epoch: u16, ms: u64| {
        let pkt = Packet::new(ty, &[ep], "GS", ms, Arc::<[u8]>::from([1u8])).unwrap().with_time_epoch(epoch);
        board_router.rx_packed_from_side(&crate::wire_format::pack_packet(&pkt), side).unwrap();
        let _ = board_router.drain_queues_with_timeout(0);
    };
    hear(2, UTC);
    assert!(board_router.network_time_ms().is_none_or(|ms| ms < crate::timesync::TIMESYNC_UTC_FLOOR_MS));
    now.fetch_add(3_000, Ordering::SeqCst);
    assert_eq!(board_router.network_stamp_age_ms(2, UTC + 2_500), NetworkStampAge::Age(500));
    assert!(board_router.network_stamp_is_fresh(2, UTC + 2_500, 15_000, 1_000));
    assert!(!board_router.network_stamp_is_fresh(2, UTC - 20_000, 15_000, 1_000));
    assert_eq!(board_router.network_stamp_age_ms(1, UTC), NetworkStampAge::OlderEpoch);
    // A step back four hours in epoch 3 re-anchors the estimate.
    hear(3, UTC - 4 * HOUR);
    assert!(board_router.network_stamp_is_fresh(3, UTC - 4 * HOUR, 15_000, 1_000));
    assert!(!board_router.network_stamp_is_fresh(2, UTC + 3_000, 15_000, 1_000));
    // An older-epoch packet never moves it back.
    hear(2, UTC + 10_000);
    assert!(board_router.network_stamp_is_fresh(3, UTC - 4 * HOUR, 15_000, 1_000));
}

/// Epoch 0 can be stated explicitly: a packet built with a stamp saved before
/// the network's first step keeps epoch 0 when sent after it, while a packet
/// whose epoch was never stated is stamped with the router's current epoch.
#[test]
fn a_stated_epoch_zero_is_kept_and_an_unstated_one_is_filled_in() {
    let (ty, ep) = flight_state();
    let net = {
        let mut net = synced_on_stale_station(0.0, 111);
        net.station_sets(UTC + net.mono());
        net.converge(&BOARDS, 20, 5_000);
        net
    };
    assert_eq!(net.nodes[GS].network_time_epoch(), 1);
    let sent = |mut pkt: Packet| {
        net.nodes[GS].stamp_origin_epoch(&mut pkt);
        crate::wire_format::unpack_packet(&crate::wire_format::pack_packet(&pkt)).ok().map(|p| p.time_epoch())
    };
    let base = Packet::new(ty, &[ep], "GS", UTC, Arc::<[u8]>::from([1u8])).unwrap();
    assert!(!base.time_epoch_stated());
    assert_eq!(sent(base.clone()), Some(1), "unstated: the router's epoch");
    let stated = base.clone().with_time_epoch(0);
    assert!(stated.time_epoch_stated());
    assert_eq!(stated, base, "stating the epoch is not part of equality");
    assert_eq!(sent(stated), Some(0), "stated 0 is kept");
}

/// A board's time sync response is its largest time sync frame (four 64-bit
/// words). Board CAN fragments carry 55 bytes, so the canonical frame must
/// stay within 55 bytes once the network has stepped (the epoch rides in the
/// frame): an epoch-only contract costs two bytes below epoch 128 and time
/// sync nonces at most two. Receipt IDs stay distinct.
#[test]
fn a_time_sync_response_fits_one_board_can_fragment_after_steps() {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(60_000));
    let gw = router("GATEWAY", board(), &now);
    let words = [u64::MAX >> 1, u64::MAX >> 2, u64::MAX >> 3, u64::MAX >> 4];
    let mut ids = std::collections::BTreeSet::new();
    for epoch in [0u16, 1, 2, 63, 127] {
        for seq in 0..64u64 {
            let mut w = words;
            w[0] ^= seq;
            let pkt = gw.timesync_packet(DataType::TimeSyncResponse, &w, UTC + 3 * HOUR, epoch).unwrap();
            assert!((1..=16_383).contains(&pkt.nonce()));
            let frame = crate::wire_format::pack_packet(&pkt);
            assert!(frame.len() <= 55, "epoch {epoch}: {} bytes", frame.len());
            let back = crate::wire_format::unpack_packet(&frame).unwrap();
            assert_eq!(back.time_epoch(), epoch);
            assert!(ids.insert(back.packet_id()), "receipt IDs stay distinct");
        }
    }
    // One byte more from epoch 128 on.
    let pkt = gw.timesync_packet(DataType::TimeSyncResponse, &words, UTC + 3 * HOUR, 128).unwrap();
    assert!(crate::wire_format::pack_packet(&pkt).len() <= 56);
}
