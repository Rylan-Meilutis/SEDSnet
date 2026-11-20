//! Instruction counts for one relay hop: an ordinary frame received on one
//! side and forwarded out of another, through the queued RX/TX path.
//!
//! The relay has three links: `upstream` and `aux` peers on 128-byte buses
//! and `downstream` on a 1 KiB serial link. All links use the IPv6-like
//! side-transport profile with header templates; routes are learned through
//! discovery with time sync enabled, and the schema carries a catalog of
//! extra types, as a node that learned its peers' schemas would. Only the
//! relay's work is counted: queueing the received frame and draining its
//! queues until the forwarded frame leaves.
//!
//! On Linux the counts come from the user-space retired-instruction counter
//! (`perf_event_open`, no kernel work counted). Elsewhere, or when the
//! counter is unavailable, wall-clock time is reported instead.
//!
//! Run: `cargo bench --bench dispatch_instructions --features <features>`.
//! Set `SEDSNET_BENCH_FRAMES` to change the number of measured frames.

mod support;

use sedsnet::config::{
    DataEndpoint, DataType, data_type_definition_by_name, endpoint_definition_by_name,
    register_data_type_with_description, register_endpoint_with_description,
};
use sedsnet::packet::Packet;
use sedsnet::router::{
    Clock, EndpointHandler, Router, RouterConfig, RouterSideOptions, SideTransportProfile,
};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Builds without `std` (the embedded profile) lock through these C hooks.
// This harness is single threaded, so they do nothing; the lock count is
// reported because a board's RTOS lock costs extra on every call.
#[cfg(not(feature = "std"))]
static LOCKS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_lock() {
    LOCKS.fetch_add(1, Ordering::Relaxed);
}
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_unlock() {}

fn lock_count() -> u64 {
    #[cfg(not(feature = "std"))]
    {
        LOCKS.load(Ordering::Relaxed)
    }
    #[cfg(feature = "std")]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// User-space instruction counter
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod counter {
    use core::ffi::{c_int, c_long, c_ulong, c_void};
    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    }
    const SYS_PERF_EVENT_OPEN: c_long = 298;
    const PERF_EVENT_IOC_ENABLE: c_ulong = 0x2400;
    const PERF_EVENT_IOC_DISABLE: c_ulong = 0x2401;

    pub struct Instructions(c_int);

    impl Instructions {
        pub fn open() -> Option<Self> {
            // struct perf_event_attr, PERF_ATTR_SIZE_VER5 (112 bytes).
            let mut attr = [0u64; 14];
            attr[0] = 112u64 << 32; // type = PERF_TYPE_HARDWARE (0), size
            attr[1] = 1; // config = PERF_COUNT_HW_INSTRUCTIONS
            // flags: disabled | exclude_kernel | exclude_hv
            attr[5] = 1 | (1 << 5) | (1 << 6);
            let fd = unsafe { syscall(SYS_PERF_EVENT_OPEN, attr.as_ptr(), 0i32, -1i32, -1i32, 0u64) };
            (fd >= 0).then_some(Self(fd as c_int))
        }
        fn value(&self) -> u64 {
            let mut buf = [0u8; 8];
            let n = unsafe { read(self.0, buf.as_mut_ptr().cast(), 8) };
            assert_eq!(n, 8, "perf counter read");
            u64::from_ne_bytes(buf)
        }
        pub fn start(&self) -> u64 {
            unsafe { ioctl(self.0, PERF_EVENT_IOC_ENABLE, 0) };
            self.value()
        }
        pub fn stop(&self, start: u64) -> u64 {
            unsafe { ioctl(self.0, PERF_EVENT_IOC_DISABLE, 0) };
            self.value() - start
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod counter {
    pub struct Instructions;
    impl Instructions {
        pub fn open() -> Option<Self> {
            None
        }
        pub fn start(&self) -> u64 {
            0
        }
        pub fn stop(&self, _start: u64) -> u64 {
            0
        }
    }
}

enum Meter {
    Instructions(counter::Instructions),
    Nanos,
}

impl Meter {
    fn new() -> Self {
        counter::Instructions::open().map_or(Meter::Nanos, Meter::Instructions)
    }
    fn unit(&self) -> &'static str {
        match self {
            Meter::Instructions(_) => "instructions",
            Meter::Nanos => "ns (instruction counter unavailable)",
        }
    }
    fn measure<R>(&self, f: impl FnOnce() -> R) -> (R, u64) {
        match self {
            Meter::Instructions(counter) => {
                let start = counter.start();
                let result = std::hint::black_box(f());
                (result, counter.stop(start))
            }
            Meter::Nanos => {
                let start = std::time::Instant::now();
                let result = std::hint::black_box(f());
                (result, start.elapsed().as_nanos() as u64)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

type Wire = Arc<Mutex<Vec<Vec<u8>>>>;

const SAMPLE_TYPE: &str = "BENCH_FORWARD_SAMPLE";
const SINK_ENDPOINT: &str = "BENCH_FORWARD_SINK";
const RELIABLE_TYPE: &str = "BENCH_FORWARD_RELIABLE";
const AUX_ENDPOINT: &str = "BENCH_AUX_SINK";
/// Example size of a learned schema catalog.
const CATALOG_TYPES: usize = 32;

fn register_schema() {
    support::initialize_schema();
    if endpoint_definition_by_name(SINK_ENDPOINT).is_none() {
        register_endpoint_with_description(SINK_ENDPOINT, "bench downstream sink", false).unwrap();
    }
    if endpoint_definition_by_name(AUX_ENDPOINT).is_none() {
        register_endpoint_with_description(AUX_ENDPOINT, "bench side sink", false).unwrap();
    }
    for index in 0..CATALOG_TYPES {
        let name = format!("BENCH_CATALOG_{index}");
        if data_type_definition_by_name(&name).is_none() {
            register_data_type_with_description(
                &name,
                "bench catalog type",
                MessageElement::Static(2, MessageDataType::UInt16, MessageClass::Data),
                &[DataEndpoint::named(AUX_ENDPOINT)],
                ReliableMode::None,
                10,
            )
            .unwrap();
        }
    }
    let sink = DataEndpoint::named(SINK_ENDPOINT);
    for (name, mode) in [(SAMPLE_TYPE, ReliableMode::None), (RELIABLE_TYPE, ReliableMode::Unordered)] {
        if data_type_definition_by_name(name).is_none() {
            // Example payload: four 32-bit samples, a typical small sensor frame.
            register_data_type_with_description(
                name,
                "bench forwarded sample",
                MessageElement::Static(4, MessageDataType::Float32, MessageClass::Data),
                &[sink],
                mode,
                40,
            )
            .unwrap();
        }
    }
}

fn link_options(max_frame_bytes: usize, templates: usize) -> RouterSideOptions {
    RouterSideOptions {
        reliable_enabled: false,
        link_local_enabled: false,
        header_template_enabled: true,
        max_frame_bytes,
        compact_header_target_bytes: sedsnet::router::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES,
        max_side_transport_templates: templates,
        side_transport_profile: SideTransportProfile::Ipv6Like,
        ..RouterSideOptions::default()
    }
}

// Clock reads are counted: on a board each one is an application callback.
static CLOCK_READS: AtomicU64 = AtomicU64::new(0);

fn clock(now: &Arc<AtomicU64>) -> Box<dyn Clock + Send + Sync> {
    let now = now.clone();
    Box::new(move || {
        CLOCK_READS.fetch_add(1, Ordering::Relaxed);
        now.load(Ordering::Relaxed)
    })
}

fn config(name: &str, handlers: Vec<EndpointHandler>) -> RouterConfig {
    let cfg = RouterConfig::new(handlers).with_sender(name);
    #[cfg(feature = "timesync")]
    let cfg = cfg.with_timesync(sedsnet::timesync::TimeSyncConfig::default());
    cfg
}

struct Network {
    now: Arc<AtomicU64>,
    upstream: Router,
    relay: Router,
    downstream: Router,
    aux: Router,
    relay_in: usize,
    relay_out: usize,
    relay_aux: usize,
    up_in: usize,
    down_in: usize,
    aux_in: usize,
    // Frames each router emitted, keyed by the receiving end.
    to_relay_from_up: Wire,
    to_relay_from_down: Wire,
    to_relay_from_aux: Wire,
    to_up: Wire,
    to_down: Wire,
    to_aux: Wire,
    delivered: Arc<AtomicUsize>,
}

fn capture(wire: &Wire) -> impl Fn(&[u8], u8) -> sedsnet::TelemetryResult<()> + Send + Sync + 'static {
    let wire = wire.clone();
    move |bytes: &[u8], _priority: u8| {
        wire.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

impl Network {
    fn new() -> Self {
        register_schema();
        let now = Arc::new(AtomicU64::new(1_700_000_000_000));
        let delivered = Arc::new(AtomicUsize::new(0));
        let hits = delivered.clone();
        let upstream = Router::new_with_clock(config("BENCH_UPSTREAM", Vec::new()), clock(&now));
        // Example budget: a 16 KiB shared queue budget, as on a small MCU.
        let relay = Router::new_with_clock(
            config("BENCH_RELAY", Vec::new())
                .with_memory_config(sedsnet::config::RuntimeMemoryConfig {
                    max_queue_budget: 16 * 1024,
                    ..Default::default()
                })
                .unwrap(),
            clock(&now),
        );
        let downstream = Router::new_with_clock(
            config(
                "BENCH_DOWNSTREAM",
                vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named(SINK_ENDPOINT),
                    move |_| {
                        hits.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    },
                )],
            ),
            clock(&now),
        );
        let aux = Router::new_with_clock(
            config(
                "BENCH_AUX",
                vec![EndpointHandler::new_packet_handler(DataEndpoint::named(AUX_ENDPOINT), |_| {
                    Ok(())
                })],
            ),
            clock(&now),
        );
        let wires: [Wire; 6] = Default::default();
        let [to_relay_from_up, to_relay_from_down, to_relay_from_aux, to_up, to_down, to_aux] =
            wires;
        // Example link sizes: a 128-byte fragmenting bus and a 1 KiB serial link.
        let up_in = upstream.add_side_packed_with_priority_and_options(
            "bus",
            capture(&to_relay_from_up),
            link_options(128, 32),
        );
        let relay_in =
            relay.add_side_packed_with_priority_and_options("bus", capture(&to_up), link_options(128, 32));
        let relay_out = relay.add_side_packed_with_priority_and_options(
            "serial",
            capture(&to_down),
            link_options(1024, 16),
        );
        let down_in = downstream.add_side_packed_with_priority_and_options(
            "serial",
            capture(&to_relay_from_down),
            link_options(1024, 16),
        );
        let relay_aux =
            relay.add_side_packed_with_priority_and_options("aux", capture(&to_aux), link_options(128, 32));
        let aux_in =
            aux.add_side_packed_with_priority_and_options("aux", capture(&to_relay_from_aux), link_options(128, 32));
        let net = Self {
            now,
            upstream,
            relay,
            downstream,
            aux,
            relay_in,
            relay_out,
            relay_aux,
            up_in,
            down_in,
            aux_in,
            to_relay_from_up,
            to_relay_from_down,
            to_relay_from_aux,
            to_up,
            to_down,
            to_aux,
            delivered,
        };
        net.converge();
        net
    }

    fn take(wire: &Wire) -> Vec<Vec<u8>> {
        core::mem::take(&mut *wire.lock().unwrap())
    }

    /// Exchange pending frames among all routers until quiet.
    fn pump(&self) {
        for _ in 0..64 {
            let mut moved = false;
            for frame in Self::take(&self.to_relay_from_up) {
                moved = true;
                let _ = self.relay.rx_packed_queue_from_side(&frame, self.relay_in);
            }
            for frame in Self::take(&self.to_relay_from_down) {
                moved = true;
                let _ = self.relay.rx_packed_queue_from_side(&frame, self.relay_out);
            }
            for frame in Self::take(&self.to_up) {
                moved = true;
                let _ = self.upstream.rx_packed_queue_from_side(&frame, self.up_in);
            }
            for frame in Self::take(&self.to_down) {
                moved = true;
                let _ = self.downstream.rx_packed_queue_from_side(&frame, self.down_in);
            }
            for frame in Self::take(&self.to_relay_from_aux) {
                moved = true;
                let _ = self.relay.rx_packed_queue_from_side(&frame, self.relay_aux);
            }
            for frame in Self::take(&self.to_aux) {
                moved = true;
                let _ = self.aux.rx_packed_queue_from_side(&frame, self.aux_in);
            }
            for router in self.routers() {
                let _ = router.drain_queues_with_timeout(0);
            }
            if !moved {
                return;
            }
        }
    }

    fn converge(&self) {
        for _ in 0..40 {
            self.now.fetch_add(50, Ordering::Relaxed);
            for router in self.routers() {
                let _ = router.announce_discovery();
                let _ = router.periodic(0);
            }
            self.pump();
        }
    }

    /// Background maintenance between measured frames (not counted).
    fn maintain(&self) {
        for router in self.routers() {
            let _ = router.periodic(0);
        }
        self.pump();
    }

    fn routers(&self) -> [&Router; 4] {
        [&self.upstream, &self.relay, &self.downstream, &self.aux]
    }

    fn sample(&self, ty: &str, index: u64) -> Packet {
        let v = index as f32;
        Packet::from_f32_slice(
            DataType::named(ty),
            &[v, v + 0.5, v + 1.0, v + 1.5],
            &[DataEndpoint::named(SINK_ENDPOINT)],
            self.now.load(Ordering::Relaxed),
        )
        .unwrap()
    }
}

struct Result {
    frames: u64,
    locks: u64,
    clock_reads: u64,
    rx_enqueue: u64,
    drain: u64,
    forwarded: u64,
    bus_fragments: u64,
    idle_drain: u64,
}

fn forward(meter: &Meter, ty: &str, frames: u64) -> Result {
    let net = Network::new();
    let mut result =
        Result { frames: 0, locks: 0, clock_reads: 0, rx_enqueue: 0, drain: 0, forwarded: 0, bus_fragments: 0, idle_drain: 0 };
    let warmup = 64;
    let delivered_before = net.delivered.load(Ordering::Relaxed);
    for index in 0..warmup + frames {
        net.now.fetch_add(1, Ordering::Relaxed);
        if index % 50 == 0 {
            net.maintain();
        }
        net.upstream.tx(net.sample(ty, index)).unwrap();
        let inbound = Network::take(&net.to_relay_from_up);
        let measured = index >= warmup;
        let locks = lock_count();
        let clock_reads = CLOCK_READS.load(Ordering::Relaxed);
        let ((), rx) = meter.measure(|| {
            for frame in &inbound {
                net.relay.rx_packed_queue_from_side(frame, net.relay_in).unwrap();
            }
        });
        let ((), drain) = meter.measure(|| net.relay.drain_queues_with_timeout(0).unwrap());
        let outbound = net.to_down.lock().unwrap().len() as u64;
        if measured {
            result.frames += 1;
            result.locks += lock_count() - locks;
            result.clock_reads += CLOCK_READS.load(Ordering::Relaxed) - clock_reads;
            result.rx_enqueue += rx;
            result.drain += drain;
            result.forwarded += outbound;
            result.bus_fragments += inbound.len() as u64;
        }
        net.pump();
    }
    // Queue service with nothing queued: the fixed cost of one call.
    let mut idle = 0;
    for _ in 0..frames {
        net.now.fetch_add(1, Ordering::Relaxed);
        idle += meter.measure(|| net.relay.drain_queues_with_timeout(0).unwrap()).1;
    }
    result.idle_drain = idle / frames.max(1);
    let delivered = net.delivered.load(Ordering::Relaxed) - delivered_before;
    assert!(
        delivered as u64 >= frames,
        "downstream received {delivered} of {} frames",
        warmup + frames
    );
    result
}

/// Frames keep arriving while the relay does not drain: once the shared
/// queue budget is full, every admission has to select a victim. Returns the
/// mean cost of a saturated admission.
fn saturated_admission(meter: &Meter, frames: u64) -> u64 {
    let net = Network::new();
    let mut total = 0;
    let mut measured = 0;
    for index in 0..frames + 1_000 {
        net.now.fetch_add(1, Ordering::Relaxed);
        net.upstream.tx(net.sample(SAMPLE_TYPE, index)).unwrap();
        for frame in Network::take(&net.to_relay_from_up) {
            let (_, cost) = meter.measure(|| net.relay.rx_packed_queue_from_side(&frame, net.relay_in));
            if index >= 1_000 {
                total += cost;
                measured += 1;
            }
        }
        // The relay's own outbound queue is not serviced; peers still drain.
        Network::take(&net.to_up);
    }
    total / measured.max(1)
}

/// The relay holds `parked` reliable packets addressed to an endpoint no
/// route reaches. Count the queue-service work per simulated millisecond.
fn unroutable_idle(meter: &Meter, parked: usize, ms: u64) -> (u64, u64) {
    register_schema();
    let now = Arc::new(AtomicU64::new(1_700_000_000_000));
    let relay = Router::new_with_clock(config("BENCH_ISOLATED", Vec::new()), clock(&now));
    let sink: Wire = Default::default();
    relay.add_side_packed_with_priority_and_options("bus", capture(&sink), link_options(128, 32));
    relay.add_side_packed_with_priority_and_options("serial", capture(&sink), link_options(1024, 16));
    for index in 0..parked {
        let v = index as f32;
        let packet = Packet::from_f32_slice(
            DataType::named(RELIABLE_TYPE),
            &[v, v, v, v],
            &[DataEndpoint::named(SINK_ENDPOINT)],
            now.load(Ordering::Relaxed),
        )
        .unwrap();
        relay.tx_queue(packet).unwrap();
    }
    // Let the first dispatches park everything, then measure steady state.
    for _ in 0..1000 {
        now.fetch_add(1, Ordering::Relaxed);
        let _ = relay.drain_queues_with_timeout(1);
    }
    let mut total = 0;
    for _ in 0..ms {
        now.fetch_add(1, Ordering::Relaxed);
        let (_, cost) = meter.measure(|| relay.drain_queues_with_timeout(1));
        total += cost;
    }
    (total, ms)
}

fn main() {
    // Ignore criterion/libtest arguments such as `--bench`.
    let frames: u64 = std::env::var("SEDSNET_BENCH_FRAMES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let meter = Meter::new();
    let unit = meter.unit();
    println!("dispatch_instructions: unit = {unit}");
    for (label, ty) in [("best-effort", SAMPLE_TYPE), ("reliable", RELIABLE_TYPE)] {
        let r = forward(&meter, ty, frames);
        let per = |v: u64| v / r.frames.max(1);
        println!(
            "forward {label:<11} frames={} bus_fragments/frame={:.2} forwarded={} \
             rx_enqueue/frame={} drain/frame={} total/frame={} core_locks/frame={:.1} clock_reads/frame={:.1} idle_drain/call={}",
            r.frames,
            r.bus_fragments as f64 / r.frames as f64,
            r.forwarded,
            per(r.rx_enqueue),
            per(r.drain),
            per(r.rx_enqueue + r.drain),
            r.locks as f64 / r.frames as f64,
            r.clock_reads as f64 / r.frames as f64,
            r.idle_drain,
        );
    }
    println!(
        "saturated rx admission (16 KiB budget full): {unit}/frame = {}",
        saturated_admission(&meter, frames.min(2_000))
    );
    let (total, ms) = unroutable_idle(&meter, 16, 2_000);
    println!(
        "unroutable idle: 16 parked reliable packets, {unit}/ms of queue service = {}",
        total / ms
    );
}
