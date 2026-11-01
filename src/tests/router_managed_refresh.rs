use crate as sedsnet;
use sedsnet::config::{DataEndpoint, DataType};
use sedsnet::router::{
    NetworkVariablePermissions, Router, RouterConfig, RouterSideId, RouterSideOptions,
};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
type Wire = Arc<Mutex<Vec<Vec<u8>>>>;
#[derive(Clone, Debug)]
struct PriorityFrame {
    from: usize,
    to: usize,
    priority: u8,
    len: usize,
    sdt: bool,
}
struct Link {
    from: usize,
    to: usize,
    side: RouterSideId,
    wire: Wire,
    blocked: Arc<AtomicBool>,
}
struct Fixture {
    routers: Vec<Arc<Router>>,
    links: Vec<Link>,
    clock: Arc<AtomicU64>,
    rejected: Arc<AtomicBool>,
    callbacks: Arc<AtomicU64>,
    ty: DataType,
    ep: DataEndpoint,
    name: &'static str,
    errors: u32,
    frames: Vec<(usize, usize, Vec<u8>)>,
    observer_callbacks: Vec<Arc<AtomicU64>>,
    priorities: Arc<Mutex<Vec<PriorityFrame>>>,
}
fn describe(ty: DataType, case: &str, event: &str, at: u64, from: usize, to: usize, bytes: &[u8]) {
    if let Ok(info) = sedsnet::wire_format::peek_frame_info(bytes)
        && (info.envelope.ty == ty || info.envelope.ty == DataType::ManagedVariableRequest)
    {
        let p = sedsnet::wire_format::unpack_packet(bytes).unwrap();
        println!(
            "{{\"case\":\"{case}\",\"event\":\"{event}\",\"clock\":{at},\"from\":{from},\"to\":{to},\"type\":{},\"sender\":\"{}\",\"packet_id\":{},\"timestamp\":{},\"endpoints\":{:?},\"targets\":{:?},\"payload\":{:?},\"reliable\":\"{:?}\"}}",
            p.data_type().as_u32(),
            p.sender(),
            p.packet_id(),
            p.timestamp(),
            info.envelope
                .endpoints
                .iter()
                .map(|x| x.as_u32())
                .collect::<Vec<_>>(),
            info.envelope.target_senders,
            &p.payload()[..p.payload().len().min(16)],
            info.reliable
        );
    }
}
impl Fixture {
    fn new(
        name: &'static str,
        edges: &[(usize, usize)],
        reject_initial: bool,
        ty: DataType,
        ep: DataEndpoint,
    ) -> Self {
        let clock = Arc::new(AtomicU64::new(0));
        let routers: Vec<_> = (0..(edges.iter().flat_map(|(a, b)| [*a, *b]).max().unwrap() + 1))
            .map(|i| {
                let c = clock.clone();
                Arc::new(Router::new_with_clock(
                    RouterConfig::new([sedsnet::router::EndpointHandler::new_packet_handler(
                        churn_schema().0,
                        |_| Ok(()),
                    )])
                    .with_sender(if i == 0 {
                        "writer".to_owned()
                    } else {
                        format!("refresh-node-{i}")
                    }),
                    Box::new(move || c.load(Ordering::Relaxed)),
                ))
            })
            .collect();
        for (i, r) in routers.iter().enumerate() {
            r.enable_network_variable(
                ty,
                if i == 0 {
                    NetworkVariablePermissions::READ_WRITE
                } else {
                    NetworkVariablePermissions::READ_ONLY
                },
            )
            .unwrap();
        }
        let rejected = Arc::new(AtomicBool::new(reject_initial));
        let callbacks = Arc::new(AtomicU64::new(0));
        let weak = Arc::downgrade(routers.last().unwrap());
        let reject = rejected.clone();
        let count = callbacks.clone();
        routers
            .last()
            .unwrap()
            .on_network_variable_update(ty, move |_packet| {
                count.fetch_add(1, Ordering::Relaxed);
                if reject.swap(false, Ordering::SeqCst) {
                    assert!(
                        weak.upgrade()
                            .unwrap()
                            .invalidate_network_variable_cache(ty)
                    );
                    return Err(sedsnet::TelemetryError::Io("expected callback rejection"));
                }
                Ok(())
            })
            .unwrap();
        let observer_callbacks: Vec<_> = (0..routers.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();
        for (i, r) in routers.iter().enumerate().take(routers.len() - 1) {
            let count = observer_callbacks[i].clone();
            r.on_network_variable_update(ty, move |_| {
                count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .unwrap();
        }
        let opts = RouterSideOptions::default().with_small_packet_transport(192);
        let priorities = Arc::new(Mutex::new(Vec::new()));
        let mut links = Vec::new();
        let mut adjacent = Vec::new();
        for &(left, right) in edges {
            let a: Wire = Arc::default();
            let b: Wire = Arc::default();
            let a_busy = Arc::new(AtomicBool::new(false));
            let b_busy = Arc::new(AtomicBool::new(false));
            let busy = a_busy.clone();
            let record = priorities.clone();
            let out = a.clone();
            let ls = routers[left].add_side_packed_with_priority_and_options(
                "forward",
                move |bytes, priority| {
                    record.lock().unwrap().push(PriorityFrame {
                        from: left,
                        to: right,
                        priority,
                        len: bytes.len(),
                        sdt: bytes.starts_with(b"SDT"),
                    });
                    if busy.load(Ordering::Relaxed)
                        && (bytes.starts_with(b"SDT")
                            || sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty))
                    {
                        return Err(sedsnet::TelemetryError::Io("side tx busy"));
                    }
                    out.lock().unwrap().push(bytes.to_vec());
                    Ok(())
                },
                opts.clone(),
            );
            let busy = b_busy.clone();
            let record = priorities.clone();
            let out = b.clone();
            let rs = routers[right].add_side_packed_with_priority_and_options(
                "return",
                move |bytes, priority| {
                    record.lock().unwrap().push(PriorityFrame {
                        from: right,
                        to: left,
                        priority,
                        len: bytes.len(),
                        sdt: bytes.starts_with(b"SDT"),
                    });
                    if busy.load(Ordering::Relaxed)
                        && (bytes.starts_with(b"SDT")
                            || sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty))
                    {
                        return Err(sedsnet::TelemetryError::Io("side tx busy"));
                    }
                    out.lock().unwrap().push(bytes.to_vec());
                    Ok(())
                },
                opts.clone(),
            );
            links.push(Link {
                from: left,
                to: right,
                side: rs,
                wire: a,
                blocked: a_busy,
            });
            links.push(Link {
                from: right,
                to: left,
                side: ls,
                wire: b,
                blocked: b_busy,
            });
            adjacent.push((left, right, ls, rs));
        }
        for (left, right, ls, rs) in adjacent {
            for (src, dst, side) in [(left, right, rs), (right, left, ls)] {
                let address = routers[src].current_address();
                let hostname = routers[src].sender();
                let ad = sedsnet::discovery::AddressAdvertisement {
                    hostname: hostname.to_string(),
                    address,
                    requested_address: address,
                    mode: 2,
                    state: 1,
                    birth_ms: 1,
                    owner_hash: u64::from(address),
                    reachable_endpoints: vec![churn_schema().0],
                    reachable_network_variables: vec![ty],
                    reachable_timesync_sources: vec![],
                    link_capabilities: opts.link_capabilities(),
                };
                routers[dst]
                    .rx_from_side(
                        &sedsnet::discovery::build_discovery_address(hostname.as_ref(), 1, &ad)
                            .unwrap(),
                        side,
                    )
                    .unwrap();
            }
        }
        let mut f = Self {
            routers,
            links,
            clock,
            rejected,
            callbacks,
            ty,
            ep,
            name,
            errors: 0,
            frames: Vec::new(),
            observer_callbacks,
            priorities,
        };
        f.pump(0, 100);
        f
    }
    fn pump(&mut self, start: u64, count: u64) {
        for now in start..start + count {
            self.clock.store(now, Ordering::Relaxed);
            for (i, r) in self.routers.iter().enumerate() {
                if let Err(e) = r.process_all_queues_with_timeout(0) {
                    self.errors += 1;
                    eprintln!("{} process_error router{i} at{now}: {e:?}", self.name);
                }
            }
            for l in &self.links {
                for bytes in std::mem::take(&mut *l.wire.lock().unwrap()) {
                    describe(self.ty, self.name, "wire", now, l.from, l.to, &bytes);
                    if sedsnet::wire_format::peek_envelope(&bytes).is_ok_and(|e| {
                        e.ty == self.ty
                            || e.ty == DataType::ManagedVariableRequest
                            || e.ty == DataType::ReliableAck
                    }) {
                        self.frames.push((l.from, l.to, bytes.clone()));
                    }
                    if let Err(e) = self.routers[l.to].rx_packed_from_side(&bytes, l.side) {
                        self.errors += 1;
                        eprintln!("{} RX_error {}->{} at{now}: {e:?}", self.name, l.from, l.to);
                    }
                }
            }
        }
    }
    fn publish(&self, revision: u16, value: u8) {
        let now = self.clock.load(Ordering::Relaxed);
        let packet = sedsnet::packet::Packet::new(
            self.ty,
            &[self.ep],
            "writer",
            now,
            Arc::<[u8]>::from([value]),
        )
        .unwrap()
        .with_nonce(revision);
        println!(
            "{{\"case\":\"{}\",\"event\":\"publish\",\"packet_id\":{},\"timestamp\":{now},\"revision_nonce\":{revision},\"value\":{value}}}",
            self.name,
            packet.packet_id()
        );
        self.routers[0].set_network_variable(packet).unwrap();
    }
    fn snapshots(&self, event: &str) {
        for (i, r) in self.routers.iter().enumerate() {
            match r.cached_managed_variable(self.ty) {
                Some(p) => println!(
                    "{{\"case\":\"{}\",\"event\":\"{event}\",\"router\":{i},\"value\":{:?},\"sender\":\"{}\",\"timestamp\":{},\"packet_id\":{},\"pending_owner\":{}}}",
                    self.name,
                    p.payload(),
                    p.sender(),
                    p.timestamp(),
                    p.packet_id(),
                    r.has_pending_reliable_tx_type(self.ty)
                ),
                None => println!(
                    "{{\"case\":\"{}\",\"event\":\"{event}\",\"router\":{i},\"value\":null,\"pending_owner\":{}}}",
                    self.name,
                    r.has_pending_reliable_tx_type(self.ty)
                ),
            }
        }
    }
}

fn schema() -> (DataType, DataEndpoint) {
    static SCHEMA: std::sync::OnceLock<(DataType, DataEndpoint)> = std::sync::OnceLock::new();
    *SCHEMA.get_or_init(|| {
        crate::tests::ensure_common_test_schema();
        let ep = crate::config::register_endpoint("GENERIC_REFRESH_TEST_ENDPOINT", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "GENERIC_REFRESH_TEST_VALUE",
            "Generic managed-cache refresh regression",
            MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
            &[ep],
            ReliableMode::Ordered,
            16,
        )
        .unwrap();
        (ty, ep)
    })
}
fn committed(name: &'static str, edges: &[(usize, usize)], reject: bool) -> Fixture {
    let (ty, ep) = schema();
    let mut f = Fixture::new(name, edges, reject, ty, ep);
    f.publish(1, 1);
    f.pump(100, 300);
    f.snapshots("committed");
    let original = f.routers[0].cached_managed_variable(ty).unwrap();
    for r in &f.routers {
        let value = r.cached_managed_variable(ty).unwrap();
        assert_eq!(value.packet_id(), original.packet_id());
        assert_eq!(value.timestamp(), 99);
        assert_eq!(value.payload(), [1]);
        assert!(!r.has_pending_reliable_tx_type(ty));
    }
    assert!(!f.rejected.load(Ordering::Relaxed));
    f
}
fn invalidate_request_and_assert(f: &mut Fixture) {
    let target = f.routers.len() - 1;
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    assert!(f.routers[target].invalidate_network_variable_cache(f.ty));
    assert!(
        f.routers[target]
            .get_network_variable(f.ty, None)
            .unwrap()
            .is_none()
    );
    let now = f.clock.load(Ordering::Relaxed) + 1;
    f.pump(now, 5000);
    f.snapshots("after_request");
    let value = f.routers[target].cached_managed_variable(f.ty).expect(
        "an explicit refresh must restore a committed generic managed value through proxies",
    );
    assert_eq!(
        value.packet_id(),
        original.packet_id(),
        "source identity/revision preserved"
    );
    assert_eq!(value.timestamp(), original.timestamp());
    assert_eq!(value.sender(), original.sender());
    assert_eq!(value.payload(), original.payload());
}
#[test]
fn generic_managed_refresh_direct() {
    let mut f = committed("direct", &[(0, 1)], false);
    invalidate_request_and_assert(&mut f);
    assert_eq!(f.errors, 0);
}
#[test]
fn generic_managed_refresh_proxy() {
    let mut f = committed("proxy", &[(0, 1), (1, 2)], false);
    invalidate_request_and_assert(&mut f);
    assert_eq!(f.errors, 0);
}
#[test]
fn generic_managed_refresh_branch() {
    let mut f = committed("branch", &[(0, 1), (1, 2), (1, 3)], false);
    let untouched = f.routers[2].cached_managed_variable(f.ty).unwrap();
    invalidate_request_and_assert(&mut f);
    assert_eq!(
        f.routers[2].cached_managed_variable(f.ty).unwrap(),
        untouched
    );
    assert_eq!(f.errors, 0);
}
#[test]
fn generic_managed_refresh_multihop() {
    let mut f = committed("multihop", &[(0, 1), (1, 2), (2, 3)], false);
    invalidate_request_and_assert(&mut f);
    assert_eq!(f.errors, 0);
}
#[test]
fn generic_managed_rejected_callback_invalidation_retries() {
    for (name, edges) in [
        ("direct_reject", vec![(0, 1)]),
        ("proxy_reject", vec![(0, 1), (1, 2)]),
    ] {
        let f = committed(name, &edges, true);
        assert_eq!(f.errors, 1);
        assert_eq!(f.callbacks.load(Ordering::Relaxed), 2);
    }
}
#[test]
fn generic_managed_fresh_revision_crosses_completed_proxy() {
    let mut f = committed("fresh", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    f.publish(2, 2);
    f.pump(400, 300);
    for r in &f.routers {
        let value = r.cached_managed_variable(f.ty).unwrap();
        assert_ne!(value.packet_id(), original.packet_id());
        assert_eq!(value.timestamp(), 399);
        assert_eq!(value.payload(), [2]);
        assert!(!r.has_pending_reliable_tx_type(f.ty));
    }
}

fn hops(f: &Fixture, packet_id: u64) -> usize {
    let state = f.routers[1].state.lock();
    state
        .transmit_queue
        .iter()
        .filter(|queued| {
            matches!(&queued.item, super::RouterTxItem::ToSide { data, .. }
            if Router::item_data_type(data).ok()==Some(f.ty) && Router::get_hash(data)==packet_id)
        })
        .count()
}
fn pending_grants(f: &Fixture) -> usize {
    f.routers[1]
        .state
        .lock()
        .discovery_routes
        .values()
        .flat_map(|route| &route.requested_network_variables)
        .filter(|request| request.ty == f.ty && request.refresh_pending)
        .count()
}
fn initial_ack(f: &Fixture, id: u64) -> Vec<u8> {
    f.frames
        .iter()
        .find_map(|(from, to, bytes)| {
            if *from != 2 || *to != 1 {
                return None;
            }
            let packet = crate::wire_format::unpack_packet(bytes).ok()?;
            (packet.data_type() == DataType::ReliableAck && packet.payload() == id.to_le_bytes())
                .then(|| bytes.clone())
        })
        .expect("initial leaf delivery must have a real old owner receipt")
}
#[test]
fn generic_managed_refresh_hop_survives_old_ack_and_transport_refusal() {
    let mut f = committed("old_ack_busy", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    let old_ack = initial_ack(&f, original.packet_id());
    let ingress = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
    assert!(
        f.routers[2]
            .get_network_variable(f.ty, None)
            .unwrap()
            .is_none()
    );
    f.pump(400, 3);
    assert_eq!(
        hops(&f, original.packet_id()),
        1,
        "reply must have actual shared-budget queue ownership before its transport callback"
    );
    assert_eq!(
        pending_grants(&f),
        0,
        "grant consumed only after hop admission"
    );
    assert!(
        !f.routers[1]
            .state
            .lock()
            .end_to_end_reliable_tx
            .values()
            .any(|owner| Router::item_data_type(&owner.data).ok() == Some(f.ty)),
        "no fabricated new frozen reader cohort"
    );
    f.routers[1].rx_packed_from_side(&old_ack, ingress).unwrap();
    assert_eq!(
        hops(&f, original.packet_id()),
        1,
        "old final ACK cannot retire a new ToSide hop"
    );
    f.links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .blocked
        .store(true, Ordering::Relaxed);
    f.pump(403, 3);
    assert!(f.routers[2].cached_managed_variable(f.ty).is_none());
    assert_eq!(
        hops(&f, original.packet_id()),
        1,
        "busy callback retains its exact original observation"
    );
    f.routers[1].rx_packed_from_side(&old_ack, ingress).unwrap();
    assert_eq!(hops(&f, original.packet_id()), 1);
    f.links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .blocked
        .store(false, Ordering::Relaxed);
    f.pump(406, 200);
    let restored = f.routers[2].cached_managed_variable(f.ty).unwrap();
    assert_eq!(restored.packet_id(), original.packet_id());
    assert_eq!(restored.timestamp(), 99);
    assert_eq!(hops(&f, original.packet_id()), 0);
    assert!(!f.routers[1].can_write_managed_variable(f.ty));
    assert!(!f.routers[2].can_write_managed_variable(f.ty));
}
#[test]
fn generic_managed_refresh_no_get_does_not_bypass_completed_duplicate() {
    let mut f = committed("no_get", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
    let upstream = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let packet = crate::wire_format::pack_packet(&original);
    f.routers[1].rx_packed_from_side(&packet, upstream).unwrap();
    f.pump(400, 200);
    assert!(f.routers[2].cached_managed_variable(f.ty).is_none());
    assert_eq!(hops(&f, original.packet_id()), 0);
}
#[test]
fn generic_managed_refresh_duplicate_request_and_observation_are_bounded() {
    let mut f = committed("repeated", &[(0, 1), (1, 2)], false);
    invalidate_request_and_assert(&mut f);
    let before = f.callbacks.load(Ordering::Relaxed);
    let request = f
        .frames
        .iter()
        .find_map(|(from, to, b)| {
            (*from == 2
                && *to == 1
                && crate::wire_format::peek_envelope(b)
                    .is_ok_and(|e| e.ty == DataType::ManagedVariableRequest))
            .then(|| b.clone())
        })
        .unwrap();
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    let value = crate::wire_format::pack_packet(&original);
    let down = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    let up = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let before_frames = f
        .frames
        .iter()
        .filter(|(from, to, b)| {
            *from == 1
                && *to == 2
                && crate::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty)
        })
        .count();
    for _ in 0..32 {
        f.routers[1].rx_packed_from_side(&request, down).unwrap();
        f.routers[1].rx_packed_from_side(&value, up).unwrap();
    }
    f.pump(5400, 200);
    assert_eq!(pending_grants(&f), 0);
    assert_eq!(hops(&f, original.packet_id()), 0);
    assert_eq!(f.callbacks.load(Ordering::Relaxed), before);
    assert_eq!(
        f.frames
            .iter()
            .filter(|(from, to, b)| *from == 1
                && *to == 2
                && crate::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty))
            .count(),
        before_frames,
        "replayed request IDs cannot mint more hop sends"
    );
}
#[test]
fn generic_managed_refresh_grant_cancels_on_different_revision() {
    let mut f = committed("changed", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
    f.routers[2].get_network_variable(f.ty, None).unwrap();
    f.pump(400, 2);
    assert_eq!(pending_grants(&f), 1);
    let upstream = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let newer = crate::packet::Packet::new(f.ty, &[f.ep], "writer", 401, Arc::<[u8]>::from([2]))
        .unwrap()
        .with_nonce(2);
    f.routers[1].rx_from_side(&newer, upstream).unwrap();
    assert_eq!(
        pending_grants(&f),
        0,
        "new revision invalidates, never counts as the owed unchanged response"
    );
    f.routers[1]
        .rx_packed_from_side(&crate::wire_format::pack_packet(&original), upstream)
        .unwrap();
    assert_eq!(hops(&f, original.packet_id()), 0);
    f.pump(402, 200);
    assert_eq!(
        f.routers[2]
            .cached_managed_variable(f.ty)
            .unwrap()
            .payload(),
        [2]
    );
}

#[test]
fn generic_managed_refresh_shared_admission_refusal_keeps_grant() {
    let mut f = committed("shared_refusal", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
    f.routers[2].get_network_variable(f.ty, None).unwrap();
    f.pump(400, 2);
    assert_eq!(pending_grants(&f), 1);
    // Fault injection at the exact shared-admission boundary; no public budget
    // policy is changed by production code or relaxed by this test.
    let limit = {
        let mut state = f.routers[1].state.lock();
        let old = state.memory.max_queue_budget;
        state.memory.max_queue_budget = 0;
        old
    };
    f.pump(402, 1);
    f.routers[1].state.lock().memory.max_queue_budget = limit;
    assert_eq!(f.errors, 1);
    assert_eq!(pending_grants(&f), 1);
    assert_eq!(hops(&f, original.packet_id()), 0);
    let (_, _, reply) = f
        .frames
        .iter()
        .find(|(from, to, b)| {
            *from == 0
                && *to == 1
                && crate::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty)
                && crate::wire_format::peek_envelope(b)
                    .unwrap()
                    .target_senders
                    .is_empty()
        })
        .cloned()
        .unwrap();
    let upstream = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    f.routers[1].rx_packed_from_side(&reply, upstream).unwrap();
    assert_eq!(hops(&f, original.packet_id()), 1);
    assert_eq!(pending_grants(&f), 0);
    f.pump(403, 200);
    assert_eq!(
        f.routers[2]
            .cached_managed_variable(f.ty)
            .unwrap()
            .packet_id(),
        original.packet_id()
    );
}
#[test]
fn generic_managed_refresh_wrong_ingress_does_not_consume_grant() {
    let mut f = committed("wrong_ingress", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
    f.routers[2].get_network_variable(f.ty, None).unwrap();
    f.pump(400, 2);
    assert_eq!(pending_grants(&f), 1);
    let downstream = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    f.routers[1]
        .rx_packed_from_side(&crate::wire_format::pack_packet(&original), downstream)
        .unwrap();
    assert_eq!(pending_grants(&f), 1);
    assert_eq!(hops(&f, original.packet_id()), 0);
    f.pump(402, 200);
    assert_eq!(
        f.routers[2]
            .cached_managed_variable(f.ty)
            .unwrap()
            .packet_id(),
        original.packet_id()
    );
}
#[test]
fn generic_managed_refresh_lease_and_clock_backstep_cannot_rearm() {
    for rollback in [false, true] {
        let mut f = committed("expired", &[(0, 1), (1, 2)], false);
        let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
        assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
        f.routers[2].get_network_variable(f.ty, None).unwrap();
        f.pump(400, 2);
        assert_eq!(pending_grants(&f), 1);
        f.clock.store(
            if rollback {
                398
            } else {
                401 + super::DISCOVERY_ROUTE_TTL_MS + 1
            },
            Ordering::Relaxed,
        );
        let upstream = f
            .links
            .iter()
            .find(|l| l.from == 0 && l.to == 1)
            .unwrap()
            .side;
        f.routers[1]
            .rx_packed_from_side(&crate::wire_format::pack_packet(&original), upstream)
            .unwrap();
        assert_eq!(pending_grants(&f), 0);
        assert_eq!(hops(&f, original.packet_id()), 0);
    }
}

#[test]
fn generic_managed_refresh_same_source_identity_does_not_reapply_warm_observers() {
    let mut f = committed("observers", &[(0, 1), (1, 2), (1, 3)], false);
    let before: Vec<_> = f
        .observer_callbacks
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .collect();
    invalidate_request_and_assert(&mut f);
    let after: Vec<_> = f
        .observer_callbacks
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .collect();
    assert_eq!(
        after, before,
        "source packet unchanged; transport recipient metadata is not a new application value"
    );
}

#[test]
fn generic_managed_subscription_reserve_refusal_is_transactional() {
    static REFUSE: AtomicBool = AtomicBool::new(false);
    extern "C" fn probe(additional: usize, largest: usize) -> bool {
        !(REFUSE.load(Ordering::Relaxed)
            && additional == largest
            && largest == std::mem::size_of::<super::ManagedVariableSubscription>())
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
            REFUSE.store(false, Ordering::Relaxed);
        }
    }
    let _reset = Reset;
    let mut route = super::DiscoverySideState::default();
    crate::memory_admission::set_probe(Some(probe));
    REFUSE.store(true, Ordering::Relaxed);
    assert!(matches!(
        super::reserve_managed_subscriptions(&mut route.requested_network_variables, 1),
        Err(crate::TelemetryError::Io("memory pressure"))
    ));
    assert!(route.requested_network_variables.is_empty());
    assert_eq!(route.requested_network_variables.capacity(), 0);
    REFUSE.store(false, Ordering::Relaxed);
    super::reserve_managed_subscriptions(&mut route.requested_network_variables, 1).unwrap();
    route
        .requested_network_variables
        .push(super::ManagedVariableSubscription {
            last_seen_ms: 400,
            next_refresh_ms: 0,
            request_id: 7,
            value_id: 8,
            upstream: 0,
            ty: schema().0,
            requester: 1,
            writer: 2,
            refresh_pending: true,
        });
    let original = route.clone();
    let pointer = route.requested_network_variables.as_ptr();
    REFUSE.store(true, Ordering::Relaxed);
    assert!(matches!(
        route.try_clone(),
        Err(crate::TelemetryError::Io("memory pressure"))
    ));
    assert_eq!(route, original);
    assert_eq!(route.requested_network_variables.as_ptr(), pointer);
}

#[test]
fn generic_managed_refresh_cycle_is_bounded_and_keeps_warm_observers() {
    let mut f = committed("cycle", &[(0, 1), (1, 2), (2, 3)], false);
    // Warm every cache and finish the original frozen cohort first. A cold
    // cyclic owner-cohort diagnostic is retained externally; it is a distinct
    // existing delivery question, not refresh admission or loop amplification.
    add_warm_link(&mut f, 3, 1);
    f.pump(400, 100);
    let before: Vec<_> = f
        .observer_callbacks
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .collect();
    let frames = f.frames.len();
    invalidate_request_and_assert(&mut f);
    assert_eq!(
        f.observer_callbacks
            .iter()
            .map(|n| n.load(Ordering::Relaxed))
            .collect::<Vec<_>>(),
        before
    );
    let transmissions = f.frames[frames..]
        .iter()
        .filter(|(_, _, b)| crate::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty))
        .count();
    assert!(
        transmissions <= f.routers.len(),
        "one explicit GET may authorize at most one reply hop per visited router, observed {transmissions}"
    );
    assert!(
        f.routers
            .iter()
            .all(|r| !r.has_pending_reliable_tx_type(f.ty))
    );
}

fn add_warm_link(f: &mut Fixture, left: usize, right: usize) {
    let opts = RouterSideOptions::default().with_small_packet_transport(192);
    let a: Wire = Arc::default();
    let b: Wire = Arc::default();
    let out = a.clone();
    let ls = f.routers[left].add_side_packed_with_options(
        "warm-loop",
        move |bytes| {
            out.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        opts.clone(),
    );
    let out = b.clone();
    let rs = f.routers[right].add_side_packed_with_options(
        "warm-loop",
        move |bytes| {
            out.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        opts.clone(),
    );
    f.links.push(Link {
        from: left,
        to: right,
        side: rs,
        wire: a,
        blocked: Arc::new(AtomicBool::new(false)),
    });
    f.links.push(Link {
        from: right,
        to: left,
        side: ls,
        wire: b,
        blocked: Arc::new(AtomicBool::new(false)),
    });
    for (src, dst, side) in [(left, right, rs), (right, left, ls)] {
        let address = f.routers[src].current_address();
        let hostname = f.routers[src].sender();
        let ad = sedsnet::discovery::AddressAdvertisement {
            hostname: hostname.to_string(),
            address,
            requested_address: address,
            mode: 2,
            state: 1,
            birth_ms: 1,
            owner_hash: u64::from(address),
            reachable_endpoints: vec![churn_schema().0],
            reachable_network_variables: vec![f.ty],
            reachable_timesync_sources: vec![],
            link_capabilities: opts.link_capabilities(),
        };
        f.routers[dst]
            .rx_from_side(
                &sedsnet::discovery::build_discovery_address(hostname.as_ref(), 399, &ad).unwrap(),
                side,
            )
            .unwrap();
    }
}

#[test]
fn generic_managed_refresh_side_lifecycle_cancels_old_grant() {
    for remove in [false, true] {
        let mut f = committed("side_lifecycle", &[(0, 1), (1, 2)], false);
        let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
        assert!(f.routers[2].invalidate_network_variable_cache(f.ty));
        f.routers[2].get_network_variable(f.ty, None).unwrap();
        f.pump(400, 2);
        assert_eq!(pending_grants(&f), 1);
        let upstream = f
            .links
            .iter()
            .find(|l| l.from == 0 && l.to == 1)
            .unwrap()
            .side;
        if remove {
            f.routers[1].remove_side(upstream).unwrap();
            let replacement = f.routers[1].add_side_packed("replacement", |_| Ok(()));
            assert_eq!(replacement, upstream);
        } else {
            f.routers[1]
                .set_side_ingress_enabled(upstream, false)
                .unwrap();
            f.routers[1]
                .set_side_ingress_enabled(upstream, true)
                .unwrap();
        }
        assert_eq!(pending_grants(&f), 0);
        f.routers[1]
            .rx_packed_from_side(&crate::wire_format::pack_packet(&original), upstream)
            .unwrap();
        assert_eq!(hops(&f, original.packet_id()), 0);
    }
}

#[test]
fn generic_managed_warm_get_renews_without_row_allocation() {
    static REFUSE: AtomicBool = AtomicBool::new(false);
    extern "C" fn probe(additional: usize, largest: usize) -> bool {
        !(REFUSE.load(Ordering::Relaxed)
            && additional == largest
            && largest == std::mem::size_of::<super::ManagedVariableSubscription>())
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
            REFUSE.store(false, Ordering::Relaxed);
        }
    }
    let mut f = committed("warm_renew", &[(0, 1), (1, 2)], false);
    invalidate_request_and_assert(&mut f);
    let down = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    let pointer = f.routers[1].state.lock().discovery_routes[&down]
        .requested_network_variables
        .as_ptr();
    let request = sedsnet::discovery::build_managed_variable_request("refresh-node-2", 5399, f.ty)
        .unwrap()
        .with_nonce(144);
    {
        let _reset = Reset;
        crate::memory_admission::set_probe(Some(probe));
        REFUSE.store(true, Ordering::Relaxed);
        f.routers[1].rx_from_side(&request, down).unwrap();
    }
    let state = f.routers[1].state.lock();
    let rows = &state.discovery_routes[&down].requested_network_variables;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.as_ptr(), pointer);
    assert_eq!(rows[0].request_id, request.packet_id());
    assert!(rows[0].refresh_pending);
}

fn churn_schema() -> (DataEndpoint, DataType, DataType) {
    static SCHEMA: std::sync::OnceLock<(DataEndpoint, DataType, DataType)> =
        std::sync::OnceLock::new();
    *SCHEMA.get_or_init(|| {
        crate::tests::ensure_common_test_schema();
        let ep = crate::config::register_endpoint("GENERIC_REFRESH_CHURN_ENDPOINT", false).unwrap();
        let make = |name, mode| {
            crate::config::register_data_type_with_description(
                name,
                "Distinct unrelated traffic for real bounded-cache eviction",
                MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
                &[ep],
                mode,
                1,
            )
            .unwrap()
        };
        (
            ep,
            make("GENERIC_REFRESH_CHURN_BEST_EFFORT", ReliableMode::None),
            make("GENERIC_REFRESH_CHURN_RELIABLE", ReliableMode::Ordered),
        )
    })
}
fn churn(f: &mut Fixture, reliable: bool, count: usize, first: u64) {
    let (ep, best, ordered) = churn_schema();
    let ty = if reliable { ordered } else { best };
    let upstream = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    for i in 0..count {
        let packet = crate::packet::Packet::new(
            ty,
            &[ep],
            "unrelated",
            first + i as u64,
            Arc::<[u8]>::from([0]),
        )
        .unwrap()
        .with_nonce((i as u16).wrapping_add(1));
        f.routers[1].rx_from_side(&packet, upstream).unwrap();
        f.routers[1].process_all_queues_with_timeout(0).unwrap();
    }
}
#[test]
fn generic_managed_refresh_consumed_get_survives_recent_id_eviction() {
    let mut f = committed("evicted_get", &[(0, 1), (1, 2)], false);
    invalidate_request_and_assert(&mut f);
    let request = f
        .frames
        .iter()
        .find_map(|(a, b, bytes)| {
            (*a == 2
                && *b == 1
                && crate::wire_format::peek_envelope(bytes)
                    .is_ok_and(|e| e.ty == DataType::ManagedVariableRequest))
            .then(|| bytes.clone())
        })
        .unwrap();
    let request_id = crate::wire_format::packet_id_from_wire(&request).unwrap();
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    let capacity = f.routers[1].state.lock().memory.max_recent_rx_ids;
    churn(&mut f, false, capacity + 16, 10_000);
    assert!(!f.routers[1].state.lock().recent_rx.contains(&request_id));
    let down = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    let up = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    f.routers[1].rx_packed_from_side(&request, down).unwrap();
    assert_eq!(
        pending_grants(&f),
        0,
        "same consumed request cannot rearm after real recent-ID eviction"
    );
    f.routers[1]
        .rx_packed_from_side(&crate::wire_format::pack_packet(&original), up)
        .unwrap();
    assert_eq!(hops(&f, original.packet_id()), 0);
}
#[test]
fn generic_managed_refresh_stable_value_survives_return_route_eviction() {
    let mut f = committed("quiet", &[(0, 1), (1, 2)], false);
    let original = f.routers[0].cached_managed_variable(f.ty).unwrap();
    let count = crate::config::runtime_reliable_max_return_routes() + 1;
    assert!(count < f.routers[1].state.lock().memory.max_recent_rx_ids);
    churn(&mut f, true, count, 20_000);
    {
        let state = f.routers[1].state.lock();
        assert!(
            !state
                .reliable_return_routes
                .contains_key(&original.packet_id()),
            "real bounded route insertion must evict stable value ACK path"
        );
        assert!(
            state.recent_rx.contains(&original.packet_id()),
            "keep value recent to isolate proxy refresh rather than new original delivery"
        );
        assert!(
            state
                .local_services
                .as_ref()
                .unwrap()
                .managed_variable_latest[&f.ty.as_u32()]
                .upstream
                .is_some()
        );
    }
    invalidate_request_and_assert(&mut f);
    assert_eq!(
        f.routers[2]
            .cached_managed_variable(f.ty)
            .unwrap()
            .timestamp(),
        99
    );
}

#[test]
fn generic_managed_refresh_alternating_old_gets_have_independent_cooldown() {
    let mut f = committed("alternating", &[(0, 1), (1, 2)], false);
    invalidate_request_and_assert(&mut f);
    let request_a = f
        .frames
        .iter()
        .find_map(|(a, b, bytes)| {
            (*a == 2
                && *b == 1
                && crate::wire_format::peek_envelope(bytes)
                    .is_ok_and(|e| e.ty == DataType::ManagedVariableRequest))
            .then(|| bytes.clone())
        })
        .unwrap();
    f.routers[2].invalidate_network_variable_cache(f.ty);
    f.routers[2].get_network_variable(f.ty, None).unwrap();
    f.pump(5400, 100);
    let request_b = f
        .frames
        .iter()
        .rev()
        .find_map(|(a, b, bytes)| {
            (*a == 2
                && *b == 1
                && crate::wire_format::peek_envelope(bytes)
                    .is_ok_and(|e| e.ty == DataType::ManagedVariableRequest))
            .then(|| bytes.clone())
        })
        .unwrap();
    assert_ne!(request_a, request_b);
    let value = f.routers[0].cached_managed_variable(f.ty).unwrap();
    let raw = crate::wire_format::pack_packet(&value);
    let down = f
        .links
        .iter()
        .find(|l| l.from == 2 && l.to == 1)
        .unwrap()
        .side;
    let up = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let count = f.routers[1].state.lock().memory.max_recent_rx_ids + 16;
    let deadline = f.routers[1].state.lock().discovery_routes[&down].requested_network_variables[0]
        .next_refresh_ms;
    assert!(f.clock.load(Ordering::Relaxed) < deadline);
    for (i, request) in [&request_a, &request_b]
        .into_iter()
        .cycle()
        .take(16)
        .enumerate()
    {
        churn(&mut f, false, count, 30_000 + i as u64 * 1000);
        f.routers[1].rx_packed_from_side(request, down).unwrap();
        f.routers[1].rx_packed_from_side(&raw, up).unwrap();
        assert_eq!(hops(&f, value.packet_id()), 0);
    }
    assert_eq!(
        f.routers[1].state.lock().discovery_routes[&down].requested_network_variables[0]
            .next_refresh_ms,
        deadline,
        "lease renewals never slide the independent cooldown"
    );
    // Continuous arrivals did not impose a quiet-gap requirement. At the
    // deadline exactly one different old GET may authorize one observation.
    f.clock.store(deadline, Ordering::Relaxed);
    churn(&mut f, false, count, 60_000);
    f.routers[1].rx_packed_from_side(&request_a, down).unwrap();
    assert_eq!(pending_grants(&f), 1);
    f.routers[1].rx_packed_from_side(&raw, up).unwrap();
    assert_eq!(hops(&f, value.packet_id()), 1);
    assert_eq!(pending_grants(&f), 0);
    let next = f.routers[1].state.lock().discovery_routes[&down].requested_network_variables[0]
        .next_refresh_ms;
    assert_eq!(
        next,
        deadline + crate::config::runtime_reliable_retransmit_ms()
    );
}

#[test]
fn generic_managed_refresh_large_low_priority_keeps_writer_policy_and_control_progress() {
    let (_, ep) = schema();
    let ty = crate::config::register_data_type_with_description(
        "GENERIC_REFRESH_LARGE_LOW",
        "Large low schema-priority managed observation",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        1,
    )
    .unwrap();
    let control_ep = churn_schema().0;
    let control_ty = crate::config::register_data_type_with_description(
        "GENERIC_REFRESH_INTERACTIVE_CONTROL",
        "Independent reliable small control during bulk refusal",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[control_ep],
        ReliableMode::Ordered,
        200,
    )
    .unwrap();
    let mut f = Fixture::new("large_low", &[(0, 1), (1, 2)], false, ty, ep);
    let mut noise = 0x1357_2468u32;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 17;
            noise ^= noise << 5;
            noise as u8
        })
        .collect();
    let value =
        crate::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from(payload.clone()))
            .unwrap()
            .with_nonce(1);
    let id = value.packet_id();
    f.routers[0].set_network_variable(value.clone()).unwrap();
    f.pump(100, 300);
    for r in &f.routers {
        assert_eq!(r.cached_managed_variable(ty).unwrap().payload(), payload);
        assert!(!r.has_pending_reliable_tx_type(ty));
    }
    assert!(!crate::small_frozen_control(ty, 1, None));
    let raw = crate::wire_format::pack_packet(&value);
    let original = super::RouterItem::Packed(crate::shared_bytes::convert(raw));
    let writer_priority = f.routers[0].item_service_priority(&original).unwrap();
    assert_eq!(
        f.routers[1].item_service_priority(&original).unwrap(),
        writer_priority
    );
    assert!(
        Router::item_type_priority(&original).unwrap().1 < 200,
        "large original is not a small interactive control"
    );
    f.routers[2].invalidate_network_variable_cache(ty);
    f.routers[2].get_network_variable(ty, None).unwrap();
    f.pump(400, 3);
    assert_eq!(hops(&f, id), 1);
    {
        let state = f.routers[1].state.lock();
        let queued=state.transmit_queue.iter().find(|q|matches!(&q.item,super::RouterTxItem::ToSide{data,..}if Router::get_hash(data)==id)).unwrap();
        assert_eq!(
            queued.priority, writer_priority,
            "new hop follows actual writer original-item service policy"
        );
        assert!(
            state.transmit_queue.bytes_used() >= payload.len(),
            "full logical observation is charged, not only its first chunk"
        );
    }
    f.links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .blocked
        .store(true, Ordering::Relaxed);
    f.pump(403, 3);
    let source = f.routers[1].sender();
    let target = Router::sender_hash(f.routers[2].sender().as_ref());
    let control = crate::packet::Packet::new_with_wire_contract(
        control_ty,
        &[control_ep],
        source.as_ref(),
        405,
        77,
        Arc::<[u8]>::from([1]),
        None,
        Arc::<[u64]>::from([target]),
    )
    .unwrap();
    let control_id = control.packet_id();
    f.routers[1].tx_queue(control).unwrap();
    f.pump(406, 30);
    let receipt = f.frames.iter().any(|(from, to, bytes)| {
        if *from != 2 || *to != 1 {
            return false;
        }
        let Ok(packet) = crate::wire_format::unpack_packet(bytes) else {
            return false;
        };
        packet.data_type() == DataType::ReliableAck
            && packet.payload() == control_id.to_le_bytes()
            && crate::wire_format::peek_envelope(bytes)
                .is_ok_and(|envelope| envelope.target_senders.first() == Some(&target))
    });
    assert!(
        receipt,
        "genuine independent control reaches its leaf and returns that frozen owner's exact-ID receipt while bulk stays refused"
    );
    {
        let state = f.routers[1].state.lock();
        assert!(!state.end_to_end_reliable_tx.contains_key(&control_id));
        assert!(
            !state
                .transmit_queue
                .iter()
                .any(|queued| match &queued.item {
                    super::RouterTxItem::Broadcast(data)
                    | super::RouterTxItem::ToSide { data, .. } =>
                        Router::get_hash(data) == control_id,
                    super::RouterTxItem::EndToEndReplay { packet_id } => *packet_id == control_id,
                    super::RouterTxItem::ReliableReplay { ty: found, .. } => *found == control_ty,
                })
        );
    }
    assert!(f.routers[2].cached_managed_variable(ty).is_none());
    assert_eq!(hops(&f, id), 1);
    // A later explicit GET cannot create a second queued copy while the
    // unchanged first hop is still retained by the busy transport.
    f.routers[2].get_network_variable(ty, None).unwrap();
    f.pump(503, 5);
    assert_eq!(hops(&f, id), 1);
    assert_eq!(pending_grants(&f), 0);
    f.links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .blocked
        .store(false, Ordering::Relaxed);
    f.pump(508, 300);
    let received = f.routers[2].cached_managed_variable(ty).unwrap();
    assert_eq!(received.payload(), payload);
    assert_eq!(received.packet_id(), id);
    assert_eq!(received.timestamp(), 99);
    assert_eq!(hops(&f, id), 0);
    let priorities = f.priorities.lock().unwrap();
    assert!(
        priorities
            .iter()
            .any(|x| x.from == 0 && x.to == 1 && x.sdt && x.priority == writer_priority)
    );
    assert!(
        priorities
            .iter()
            .any(|x| x.from == 1 && x.to == 2 && x.sdt && x.priority == writer_priority)
    );
    assert!(
        priorities.iter().filter(|x| x.sdt).all(|x| x.len <= 192),
        "large observation keeps actual SDT bounds; opaque chunks do not become canonical interactive frames"
    );
}

#[test]
fn generic_managed_refresh_actual_native_layout_and_queue_charge() {
    struct OldCacheEntry {
        packet: crate::packet::Packet,
        sender_address: u32,
        cached_at_ms: u64,
    }
    let (ty, ep) = schema();
    let packet =
        crate::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from([1])).unwrap();
    let old = OldCacheEntry {
        packet: packet.clone(),
        sender_address: 1,
        cached_at_ms: 3,
    };
    assert_eq!(old.packet.timestamp(), 99);
    assert_eq!(old.sender_address, 1);
    assert_eq!(old.cached_at_ms, 3);
    let current = super::ManagedVariableCacheEntry {
        packet,
        sender_address: 1,
        cached_at_ms: 3,
        upstream: None,
    };
    assert_eq!(current.packet.timestamp(), 99);
    let old_size = std::mem::size_of::<OldCacheEntry>();
    let new_size = std::mem::size_of::<super::ManagedVariableCacheEntry>();
    let field = std::mem::size_of::<Option<core::num::NonZeroUsize>>();
    assert!(new_size >= old_size && new_size - old_size <= field);
    let mut route = super::DiscoverySideState::default();
    let before = super::RouterInner::discovery_route_byte_cost(0, &route);
    super::reserve_managed_subscriptions(&mut route.requested_network_variables, 1).unwrap();
    route
        .requested_network_variables
        .push(super::ManagedVariableSubscription {
            last_seen_ms: 1,
            next_refresh_ms: 0,
            request_id: 2,
            value_id: 3,
            upstream: 0,
            ty,
            requester: 4,
            writer: 5,
            refresh_pending: true,
        });
    assert_eq!(
        route.requested_network_variables.len(),
        route.requested_network_variables.capacity()
    );
    let row = std::mem::size_of::<super::ManagedVariableSubscription>();
    assert_eq!(
        super::RouterInner::discovery_route_byte_cost(0, &route) - before,
        row
    );
    eprintln!(
        "LAYOUT old_cached_entry={old_size} new_cached_entry={new_size} upstream_field={field} old_request_row={} new_request_row={row} request_capacity={} exact_charged_growth={row}",
        std::mem::size_of::<(DataType, u64)>(),
        route.requested_network_variables.capacity()
    );
}

#[cfg(feature = "compact-packet-store")]
#[test]
fn generic_managed_refresh_compact_arena_has_no_repeated_pin_or_handle_growth() {
    struct Restore(Option<Arc<crate::packet_store::PacketStore>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::packet_store::set_default_store(self.0.take());
        }
    }
    let _restore = Restore(crate::packet_store::default_store());
    // Same dedicated shared-process arena size as existing compact router
    // regressions. This measures retention, not any MCU's heap headroom.
    let store = crate::packet_store::PacketStore::new(32768, 512, 512).unwrap();
    crate::packet_store::set_default_store(Some(store.clone()));
    let (_, ep) = schema();
    let ty = crate::config::register_data_type_with_description(
        "GENERIC_REFRESH_COMPACT_LARGE",
        "Actual arena retention under repeated observed-value refresh",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let mut f = Fixture::new("arena", &[(0, 1), (1, 2)], false, ty, ep);
    let mut noise = 0x7351_2468u32;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 17;
            noise ^= noise << 5;
            noise as u8
        })
        .collect();
    let packet =
        crate::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from(payload.clone()))
            .unwrap()
            .with_nonce(17);
    let id = packet.packet_id();
    f.routers[0].set_network_variable(packet).unwrap();
    f.pump(100, 300);
    let mut baseline = None;
    for round in 0..17 {
        assert!(f.routers[2].invalidate_network_variable_cache(ty));
        assert!(
            f.routers[2]
                .get_network_variable(ty, None)
                .unwrap()
                .is_none()
        );
        let start = f.clock.load(Ordering::Relaxed) + 1;
        // Stop before the proxy transport callback. Require a real parked
        // queued value, so an idle zero-arena result cannot pass vacuously.
        f.pump(start, 3);
        let owned = store.stats();
        assert!(owned.live_bytes >= payload.len() && owned.live_handles > 0);
        assert_eq!(hops(&f, id), 1);
        let inspected = store.stats();
        for _ in 0..32 {
            assert_eq!(hops(&f, id), 1);
            let again = store.stats();
            assert_eq!(
                (again.live_bytes, again.live_handles, again.pinned_bytes),
                (
                    inspected.live_bytes,
                    inspected.live_handles,
                    inspected.pinned_bytes
                ),
                "repeated inspection of an owned large Packed hop cannot add pins or materializations"
            );
        }
        f.pump(
            start + 3,
            crate::config::runtime_reliable_retransmit_ms() + 5,
        );
        {
            let value = f.routers[2].cached_managed_variable(ty).unwrap();
            assert_eq!(value.packet_id(), id);
            assert_eq!(value.timestamp(), 99);
            assert_eq!(value.payload(), payload);
        }
        let stats = store.stats();
        if let Some((bytes, handles, pins)) = baseline {
            assert_eq!(
                (stats.live_bytes, stats.live_handles, stats.pinned_bytes),
                (bytes, handles, pins),
                "round{round}: repeated hashing/refresh cannot accumulate retained materializations/pins"
            );
        } else {
            baseline = Some((stats.live_bytes, stats.live_handles, stats.pinned_bytes));
        }
    }
    let steady = store.stats();
    drop(f);
    let final_stats = store.stats();
    assert_eq!(
        (
            final_stats.live_bytes,
            final_stats.live_handles,
            final_stats.pinned_bytes
        ),
        (0, 0, 0)
    );
    eprintln!("COMPACT_RETAINED steady={steady:?} after_drop={final_stats:?}");
}

#[test]
fn generic_managed_refresh_known_queued_hop_must_not_claim_abort() {
    let (_, ep) = schema();
    let ty = crate::config::register_data_type_with_description(
        "GENERIC_REFRESH_LARGE_LOW",
        "Large low schema-priority managed observation",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        1,
    )
    .unwrap();
    let control_ep = churn_schema().0;
    let control_ty = crate::config::register_data_type_with_description(
        "ABORT",
        "Diagnostic application Stop ownership",
        MessageElement::Dynamic(MessageDataType::String, MessageClass::Error),
        &[control_ep],
        ReliableMode::Unordered,
        0,
    )
    .unwrap();
    let mut f = Fixture::new("large_low", &[(0, 1), (1, 2)], false, ty, ep);
    let mut noise = 0x1357_2468u32;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            noise ^= noise << 13;
            noise ^= noise >> 17;
            noise ^= noise << 5;
            noise as u8
        })
        .collect();
    let value =
        crate::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from(payload.clone()))
            .unwrap()
            .with_nonce(1);
    let id = value.packet_id();
    f.routers[0].set_network_variable(value.clone()).unwrap();
    f.pump(100, 300);
    for r in &f.routers {
        assert_eq!(r.cached_managed_variable(ty).unwrap().payload(), payload);
        assert!(!r.has_pending_reliable_tx_type(ty));
    }
    assert!(!crate::small_frozen_control(ty, 1, None));
    let raw = crate::wire_format::pack_packet(&value);
    let original = super::RouterItem::Packed(crate::shared_bytes::convert(raw));
    let writer_priority = f.routers[0].item_service_priority(&original).unwrap();
    assert_eq!(
        f.routers[1].item_service_priority(&original).unwrap(),
        writer_priority
    );
    assert!(
        Router::item_type_priority(&original).unwrap().1 < 200,
        "large original is not a small interactive control"
    );
    assert!(
        !f.routers[1].has_pending_reliable_tx_type(control_ty),
        "settled baseline has no Stop ownership"
    );
    f.routers[2].invalidate_network_variable_cache(ty);
    f.routers[2].get_network_variable(ty, None).unwrap();
    f.pump(400, 3);
    assert_eq!(hops(&f, id), 1);
    {
        let state = f.routers[1].state.lock();
        let queued=state.transmit_queue.iter().find(|q|matches!(&q.item,super::RouterTxItem::ToSide{data,..}if Router::get_hash(data)==id)).unwrap();
        assert_eq!(
            queued.priority, writer_priority,
            "new hop follows actual writer original-item service policy"
        );
        assert!(
            state.transmit_queue.bytes_used() >= payload.len(),
            "full logical observation is charged, not only its first chunk"
        );
    }
    f.links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .blocked
        .store(true, Ordering::Relaxed);
    f.pump(403, 3);
    let node = &f.routers[1];
    let mut unknown_packed = Vec::new();
    let queue;
    {
        let state = node.state.lock();
        queue = state
            .transmit_queue
            .iter()
            .map(|queued| match &queued.item {
                super::RouterTxItem::Broadcast(data) | super::RouterTxItem::ToSide { data, .. } => {
                    let packet_id = Router::get_hash(data);
                    let logical = Router::item_data_type(data).unwrap();
                    assert_ne!(logical, control_ty);
                    if queued.accepted_type == 0 && matches!(data, super::RouterItem::Packed(_)) {
                        unknown_packed.push(packet_id);
                    }
                    (
                        packet_id,
                        logical.as_u32(),
                        queued.accepted_type,
                        format!("{:?}", queued.delivery_state),
                    )
                }
                super::RouterTxItem::EndToEndReplay { .. }
                | super::RouterTxItem::ReliableReplay { .. } => {
                    panic!("fixture unexpectedly contains a retry marker")
                }
            })
            .collect::<Vec<_>>();
        assert!(
            state.end_to_end_reliable_tx.is_empty(),
            "retained-owner wildcard is not the cause"
        );
        assert!(
            state
                .reliable_tx
                .iter()
                .all(|((_, found), owner)| *found != control_ty.as_u32() || owner.sent.is_empty())
        );
    }
    assert!(
        unknown_packed.is_empty(),
        "known refresh hop must carry cached type before parking"
    );
    assert_eq!(
        queue,
        vec![(id, ty.as_u32(), ty.as_u32(), "Untracked".to_string())]
    );
    assert_eq!(
        node.active_queued_tx.load(Ordering::Acquire),
        0,
        "no active dispatch wildcard is involved"
    );
    let pending = node.has_pending_reliable_tx_type(control_ty);
    eprintln!(
        "REFRESH_QUEUED_TYPE_CAUSAL: refresh_id={id} refresh_type={} stop_type={} queue={queue:?} active_dispatch=0 end_to_end_owners=0 actual_stop_owners=0 stop_pending={pending}",
        ty.as_u32(),
        control_ty.as_u32()
    );
    assert!(
        !pending,
        "known non-Stop managed refresh must not masquerade as pending ABORT"
    );

    // Positive control: a genuine queued application Stop remains visible.
    let stop = crate::packet::Packet::new_with_nonce(
        control_ty,
        &[control_ep],
        "writer",
        405,
        2,
        Arc::from(&b"stop"[..]),
    )
    .unwrap();
    let stop_id = stop.packet_id();
    node.tx_packed_queue(crate::wire_format::pack_packet(&stop))
        .unwrap();
    {
        let state = node.state.lock();
        assert!(
            state.transmit_queue.iter().any(|queued| {
                matches!(&queued.item, super::RouterTxItem::Broadcast(data)
                if Router::get_hash(data) == stop_id
                    && Router::item_data_type(data).is_ok_and(|ty| ty == control_ty))
                    && queued.accepted_type == control_ty.as_u32()
            }),
            "exact Stop packet must have a queued logical owner"
        );
    }
    assert!(node.has_pending_reliable_tx_type(control_ty));
    eprintln!(
        "REFRESH_QUEUED_STOP_CONTROL: exact_stop_id={stop_id} stop_type={} pending=true",
        control_ty.as_u32()
    );
}
