//! Cached route plans (`Router::remote_side_plan_with_selection`) across the
//! routing changes that must retire them: route expiry and revival, side
//! policy, new sides and schema changes. Under test, every cached plan is
//! re-derived the full way and must match (`verify_cached_route_plan`), so
//! this checks both that the cache serves frames and that it never serves a
//! stale plan.

use crate::config::{DataEndpoint, DataType, register_data_type_with_description};
use crate::discovery::DISCOVERY_ROUTE_TTL_MS;
use crate::packet::Packet;
use crate::router::{
    EndpointHandler, Router, RouterConfig, RouterSideOptions, route_plan_test_counter,
};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const SINK: &str = "ROUTE_PLAN_CACHE_SINK";

type Wire = Arc<Mutex<Vec<Vec<u8>>>>;

fn capture(wire: &Wire) -> impl Fn(&[u8]) -> crate::TelemetryResult<()> + Send + Sync + 'static {
    let wire = wire.clone();
    move |bytes: &[u8]| {
        wire.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

struct Net {
    now: Arc<AtomicU64>,
    relay: Router,
    peer: Router,
    relay_in: usize,
    relay_out: usize,
    peer_side: usize,
    to_peer: Wire,
    to_relay: Wire,
    to_in: Wire,
    delivered: Arc<AtomicUsize>,
}

impl Net {
    fn new() -> Self {
        crate::tests::ensure_common_test_schema();
        let sink = DataEndpoint::try_named(SINK).unwrap_or_else(|| {
            crate::config::register_endpoint_with_description(SINK, "cache sink", false).unwrap()
        });
        let now = Arc::new(AtomicU64::new(1_700_000_000_000));
        let clock = |now: &Arc<AtomicU64>| {
            let now = now.clone();
            Box::new(move || now.load(Ordering::Relaxed))
        };
        let delivered = Arc::new(AtomicUsize::new(0));
        let hits = delivered.clone();
        let relay = Router::new_with_clock(RouterConfig::new([]).with_sender("PLAN_RELAY"), clock(&now));
        let peer = Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(sink, move |_| {
                hits.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })])
            .with_sender("PLAN_PEER"),
            clock(&now),
        );
        let [to_peer, to_relay, to_in]: [Wire; 3] = Default::default();
        let opts = || RouterSideOptions { reliable_enabled: false, ..RouterSideOptions::default() };
        let relay_in = relay.add_side_packed_with_options("in", capture(&to_in), opts());
        let relay_out = relay.add_side_packed_with_options("out", capture(&to_peer), opts());
        // A second idle link: without a discovered route nothing is routable.
        relay.add_side_packed_with_options("idle", capture(&to_in), opts());
        let peer_side = peer.add_side_packed_with_options("up", capture(&to_relay), opts());
        let net = Self { now, relay, peer, relay_in, relay_out, peer_side, to_peer, to_relay, to_in, delivered };
        net.announce();
        net
    }

    fn pump(&self) {
        for _ in 0..32 {
            let to_peer = core::mem::take(&mut *self.to_peer.lock().unwrap());
            let to_relay = core::mem::take(&mut *self.to_relay.lock().unwrap());
            self.to_in.lock().unwrap().clear();
            if to_peer.is_empty() && to_relay.is_empty() {
                return;
            }
            for frame in to_peer {
                let _ = self.peer.rx_packed_queue_from_side(&frame, self.peer_side);
            }
            for frame in to_relay {
                let _ = self.relay.rx_packed_queue_from_side(&frame, self.relay_out);
            }
            let _ = self.peer.drain_queues_with_timeout(0);
            let _ = self.relay.drain_queues_with_timeout(0);
        }
    }

    /// Exchange discovery until the relay knows the peer's endpoint.
    fn announce(&self) {
        for _ in 0..6 {
            self.now.fetch_add(50, Ordering::Relaxed);
            let _ = self.peer.announce_discovery();
            let _ = self.relay.announce_discovery();
            let _ = self.peer.periodic(0);
            let _ = self.relay.periodic(0);
            self.pump();
        }
    }

    /// Forward `count` frames from the relay's `in` side; returns deliveries.
    fn forward(&self, ty: DataType, count: usize) -> usize {
        self.forward_via(ty, count, true)
    }

    /// `forward`, received immediately instead of queued: no queue pass (and
    /// so no route pruning) runs before the frame is routed.
    fn forward_immediate(&self, ty: DataType, count: usize) -> usize {
        self.forward_via(ty, count, false)
    }

    fn forward_via(&self, ty: DataType, count: usize, queued: bool) -> usize {
        let before = self.delivered.load(Ordering::Relaxed);
        let source = Router::new_with_clock(
            RouterConfig::new([]).with_sender("PLAN_SOURCE"),
            {
                let now = self.now.clone();
                Box::new(move || now.load(Ordering::Relaxed))
            },
        );
        let wire: Wire = Default::default();
        source.add_side_packed_with_options(
            "bus",
            capture(&wire),
            RouterSideOptions { reliable_enabled: false, ..RouterSideOptions::default() },
        );
        for index in 0..count {
            self.now.fetch_add(1, Ordering::Relaxed);
            let v = index as f32;
            source
                .tx(Packet::from_f32_slice(ty, &[v, v], &[DataEndpoint::named(SINK)], self.now.load(Ordering::Relaxed)).unwrap())
                .unwrap();
            for frame in core::mem::take(&mut *wire.lock().unwrap()) {
                let _ = if queued {
                    self.relay.rx_packed_queue_from_side(&frame, self.relay_in)
                } else {
                    self.relay.rx_packed_from_side(&frame, self.relay_in)
                };
            }
            let _ = self.relay.drain_queues_with_timeout(0);
            self.pump();
        }
        self.delivered.load(Ordering::Relaxed) - before
    }
}

fn bulk_type(name: &str) -> DataType {
    DataType::try_named(name).unwrap_or_else(|| {
        register_data_type_with_description(
            name,
            "cached plan traffic",
            MessageElement::Static(2, MessageDataType::Float32, MessageClass::Data),
            &[DataEndpoint::named(SINK)],
            ReliableMode::None,
            20,
        )
        .unwrap()
    })
}

#[test]
fn cached_route_plans_follow_expiry_revival_policy_and_topology() {
    let net = Net::new();
    let ty = bulk_type("ROUTE_PLAN_CACHE_BULK");
    let verified = route_plan_test_counter::verified();

    // A learned route: the plan is cached and every reuse re-derives equal.
    assert_eq!(net.forward(ty, 20), 20);
    assert!(route_plan_test_counter::verified() > verified + 10, "cached plans were not used");

    // The route expires with time alone: no cached plan may outlive it, even
    // before a queue pass prunes the route.
    assert_eq!(net.forward_immediate(ty, 5), 5);
    net.now.fetch_add(DISCOVERY_ROUTE_TTL_MS + 1, Ordering::Relaxed);
    let verified = route_plan_test_counter::verified();
    let before = net.delivered.load(Ordering::Relaxed);
    let wire: Wire = Default::default();
    let source = Router::new_with_clock(RouterConfig::new([]).with_sender("PLAN_SOURCE"), {
        let now = net.now.clone();
        Box::new(move || now.load(Ordering::Relaxed))
    });
    source.add_side_packed_with_options(
        "bus",
        capture(&wire),
        RouterSideOptions { reliable_enabled: false, ..RouterSideOptions::default() },
    );
    source
        .tx(Packet::from_f32_slice(ty, &[1.0, 2.0], &[DataEndpoint::named(SINK)], net.now.load(Ordering::Relaxed)).unwrap())
        .unwrap();
    for frame in core::mem::take(&mut *wire.lock().unwrap()) {
        let _ = net.relay.rx_packed_from_side(&frame, net.relay_in);
    }
    assert!(net.to_peer.lock().unwrap().is_empty(), "an expired route still carried a frame");
    assert_eq!(route_plan_test_counter::verified(), verified, "an expired plan was served");
    net.pump();
    assert_eq!(net.delivered.load(Ordering::Relaxed), before);
    assert_eq!(net.forward(ty, 5), 0);

    // Rediscovery revives it.
    net.announce();
    assert_eq!(net.forward(ty, 5), 5);

    // Side and route policy retire cached plans.
    net.relay.set_side_egress_enabled(net.relay_out, false).unwrap();
    assert_eq!(net.forward(ty, 3), 0);
    net.relay.set_side_egress_enabled(net.relay_out, true).unwrap();
    assert_eq!(net.forward(ty, 3), 3);
    net.relay.set_route(Some(net.relay_in), net.relay_out, false).unwrap();
    assert_eq!(net.forward(ty, 3), 0);
    net.relay.clear_route(Some(net.relay_in), net.relay_out).unwrap();
    assert_eq!(net.forward(ty, 3), 3);

    // A new side and a schema change.
    let aux: Wire = Default::default();
    net.relay.add_side_packed_with_options(
        "aux",
        capture(&aux),
        RouterSideOptions { reliable_enabled: false, ..RouterSideOptions::default() },
    );
    assert_eq!(net.forward(ty, 3), 3);
    let _ = bulk_type("ROUTE_PLAN_CACHE_LATE_TYPE");
    assert_eq!(net.forward(ty, 3), 3);
}

#[test]
fn cached_route_plans_serve_reliable_types_and_follow_sender_renames() {
    let net = Net::new();
    let ty = DataType::try_named("ROUTE_PLAN_CACHE_RELIABLE").unwrap_or_else(|| {
        register_data_type_with_description(
            "ROUTE_PLAN_CACHE_RELIABLE",
            "cached plan reliable traffic",
            MessageElement::Static(2, MessageDataType::Float32, MessageClass::Data),
            &[DataEndpoint::named(SINK)],
            ReliableMode::Unordered,
            20,
        )
        .unwrap()
    });
    // Reliable types are keyed too (their receipt state checked per packet);
    // every served plan is re-derived and must match.
    let verified = route_plan_test_counter::verified();
    assert_eq!(net.forward(ty, 10), 10);
    assert!(route_plan_test_counter::verified() > verified, "reliable plans were not cached");

    // Renaming the relay retires plans that depend on its own name.
    net.relay.set_sender("PLAN_RELAY_RENAMED");
    net.announce();
    assert_eq!(net.forward(ty, 5), 5);
    assert_eq!(net.forward(bulk_type("ROUTE_PLAN_CACHE_BULK"), 5), 5);
}
