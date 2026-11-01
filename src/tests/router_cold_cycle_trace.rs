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
    endpoint_reject: Arc<AtomicBool>,
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
            p.payload(),
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
        Self::new_with_endpoint_failure(name, edges, reject_initial, ty, ep, false)
    }

    fn new_with_endpoint_failure(
        name: &'static str,
        edges: &[(usize, usize)],
        reject_initial: bool,
        ty: DataType,
        ep: DataEndpoint,
        endpoint_failure: bool,
    ) -> Self {
        let clock = Arc::new(AtomicU64::new(0));
        let endpoint_reject = Arc::new(AtomicBool::new(endpoint_failure));
        let routers: Vec<_> = (0..(edges.iter().flat_map(|(a, b)| [*a, *b]).max().unwrap() + 1))
            .map(|i| {
                let c = clock.clone();
                Arc::new(Router::new_with_clock(
                    RouterConfig::new(if endpoint_failure && i == 1 {
                        let reject = endpoint_reject.clone();
                        vec![super::EndpointHandler::new_packet_handler(ep, move |_| {
                            if reject.load(Ordering::Relaxed) {
                                Err(sedsnet::TelemetryError::Io("endpoint refused"))
                            } else {
                                Ok(())
                            }
                        })]
                    } else {
                        vec![]
                    })
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
        let mut links = Vec::new();
        let mut adjacent = Vec::new();
        for &(left, right) in edges {
            let a: Wire = Arc::default();
            let b: Wire = Arc::default();
            let a_busy = Arc::new(AtomicBool::new(false));
            let b_busy = Arc::new(AtomicBool::new(false));
            let busy = a_busy.clone();
            let out = a.clone();
            let ls = routers[left].add_side_packed_with_options(
                "forward",
                move |bytes| {
                    if busy.load(Ordering::Relaxed)
                        && sedsnet::wire_format::peek_envelope(bytes)
                            .is_ok_and(|e| e.ty == ty || e.ty == DataType::ReliableAck)
                    {
                        return Err(sedsnet::TelemetryError::Io("side tx busy"));
                    }
                    out.lock().unwrap().push(bytes.to_vec());
                    Ok(())
                },
                opts.clone(),
            );
            let busy = b_busy.clone();
            let out = b.clone();
            let rs = routers[right].add_side_packed_with_options(
                "return",
                move |bytes| {
                    if busy.load(Ordering::Relaxed)
                        && sedsnet::wire_format::peek_envelope(bytes)
                            .is_ok_and(|e| e.ty == ty || e.ty == DataType::ReliableAck)
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
                    reachable_endpoints: vec![],
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
            endpoint_reject,
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

    fn audit(&self, now: u64, label: &str) {
        for (i, r) in self.routers.iter().enumerate() {
            let st = r.state.lock();
            for (id, owner) in &st.end_to_end_reliable_tx {
                eprintln!(
                    "OWNERS at={now} label={label} node={i} id={id} pending={:?} waiting={} retries={} route={:?}",
                    owner.pending_destinations,
                    owner.waiting_for_predecessor,
                    owner.retries,
                    st.reliable_return_routes.get(id)
                );
            }
        }
        eprintln!(
            "CALLBACKS at={now} observer={:?} target={}",
            self.observer_callbacks
                .iter()
                .map(|x| x.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.callbacks.load(Ordering::Relaxed)
        );
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

#[test]
fn cold_cycle_owned_dependency_trace() {
    let ep = sedsnet::config::register_endpoint("GENERIC_CYCLE_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_CYCLE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let mut f = Fixture::new(
        "cold_cycle",
        &[(0, 1), (1, 2), (2, 3), (3, 1)],
        false,
        ty,
        ep,
    );
    for (i, r) in f.routers.iter().enumerate() {
        eprintln!(
            "IDENTITY node={i} sender={} hash={}",
            r.sender(),
            Router::sender_hash(r.sender().as_ref())
        );
    }
    assert!(!f.rejected.load(Ordering::Relaxed));
    f.publish(1, 1);
    f.pump(100, 1);
    f.audit(100, "first physical round");
    f.pump(101, 1);
    f.audit(101, "second physical round");
    f.pump(102, 398);
    f.audit(499, "400ms later");
    f.snapshots("diagnostic");
    assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
    assert!(
        f.routers
            .iter()
            .all(|r| r.cached_managed_variable(ty).is_some())
    );
    assert!(
        f.routers
            .iter()
            .all(|r| !r.has_pending_reliable_tx_type(ty))
    );
    assert_eq!(f.errors, 0);
}

fn cycle_fixture(edges: &[(usize, usize)]) -> Fixture {
    let ep = sedsnet::config::register_endpoint("GENERIC_CYCLE_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_CYCLE_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    Fixture::new("cycle_control", edges, false, ty, ep)
}
fn owner_id(f: &Fixture) -> u64 {
    f.routers[0]
        .cached_managed_variable(f.ty)
        .unwrap()
        .packet_id()
}
fn ack_count(f: &Fixture, node: usize, id: u64) -> usize {
    f.routers[node]
        .state
        .lock()
        .transmit_queue
        .iter()
        .filter(|q| match &q.item {
            super::RouterTxItem::ToSide { data, .. } => match data {
                super::RouterItem::Packet(p) => {
                    p.data_type() == DataType::ReliableAck && p.payload() == id.to_le_bytes()
                }
                super::RouterItem::Packed(b) => {
                    sedsnet::wire_format::unpack_packet(b).is_ok_and(|p| {
                        p.data_type() == DataType::ReliableAck && p.payload() == id.to_le_bytes()
                    })
                }
            },
            _ => false,
        })
        .count()
}
#[test]
fn cycle_missing_leaf_never_gets_false_root_completion() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1), (2, 4)]);
    f.links
        .iter()
        .find(|l| l.from == 2 && l.to == 4)
        .unwrap()
        .blocked
        .store(true, Ordering::Relaxed);
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 500);
    assert!(
        f.routers[0]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id)
    );
    assert!(
        f.routers[2]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id)
    );
    assert!(f.routers[4].cached_managed_variable(f.ty).is_none());
}
#[test]
fn cycle_callback_rejection_cannot_close_backedge() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let weak = Arc::downgrade(&f.routers[1]);
    let ty = f.ty;
    f.routers[1]
        .on_network_variable_update(f.ty, move |_| {
            weak.upgrade()
                .unwrap()
                .invalidate_network_variable_cache(ty);
            Err(sedsnet::TelemetryError::Io("local refused"))
        })
        .unwrap();
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 1);
    let st = f.routers[1].state.lock();
    let route = st.reliable_return_routes.get(&id).unwrap();
    assert!(!route.local_admission_completed);
    assert!(!route.delivery_completed);
    drop(st);
    assert_eq!(ack_count(&f, 1, id), 0);
    assert!(
        f.routers[0]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id)
    );
    f.pump(101, 400);
    assert!(f.errors > 0);
    assert!(
        !f.frames.iter().any(|(a, _, b)| *a == 1
            && sedsnet::wire_format::unpack_packet(b).is_ok_and(|p| p.data_type()
                == DataType::ReliableAck
                && p.payload() == id.to_le_bytes())),
        "a refused callback must never emit a completion receipt"
    );
}
#[test]
fn cycle_edge_receipt_refusal_duplicates_and_parent_are_bounded() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let held = f.links.remove(
        f.links
            .iter()
            .position(|l| l.from == 3 && l.to == 1)
            .unwrap(),
    );
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 1);
    let body = std::mem::take(&mut *held.wire.lock().unwrap())
        .into_iter()
        .find(|b| sedsnet::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty))
        .unwrap();
    let parent = f.routers[1]
        .state
        .lock()
        .reliable_return_routes
        .get(&id)
        .unwrap()
        .side;
    let limit = {
        let mut st = f.routers[1].state.lock();
        let b = st.memory.max_queue_budget;
        st.memory.max_queue_budget = 0;
        b
    };
    assert!(f.routers[1].rx_packed_from_side(&body, held.side).is_err());
    assert_eq!(ack_count(&f, 1, id), 0);
    f.routers[1].state.lock().memory.max_queue_budget = limit;
    for _ in 0..32 {
        f.routers[1].rx_packed_from_side(&body, held.side).unwrap();
    }
    assert_eq!(ack_count(&f, 1, id), 1);
    let first = f
        .frames
        .iter()
        .find(|(a, b, x)| {
            *a == 0 && *b == 1 && sedsnet::wire_format::peek_envelope(x).is_ok_and(|e| e.ty == f.ty)
        })
        .unwrap()
        .2
        .clone();
    for _ in 0..32 {
        f.routers[1].rx_packed_from_side(&first, parent).unwrap();
    }
    assert_eq!(ack_count(&f, 1, id), 1);
    {
        let st = f.routers[1].state.lock();
        let route = st.reliable_return_routes.get(&id).unwrap();
        assert_eq!(route.side, parent);
        assert!(!route.delivery_completed);
        assert_eq!(
            st.end_to_end_reliable_tx
                .get(&id)
                .unwrap()
                .pending_destinations
                .len(),
            2
        );
    }
    let busy = f
        .links
        .iter()
        .find(|l| l.from == 1 && l.to == 3)
        .unwrap()
        .blocked
        .clone();
    busy.store(true, Ordering::Relaxed);
    f.links.push(held);
    f.pump(101, 10);
    assert!(
        f.routers[0]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id)
    );
    assert_eq!(
        ack_count(&f, 1, id),
        1,
        "physical refusal must retain exactly one edge receipt"
    );
    let due = 100 + super::runtime_reliable_retransmit_ms();
    f.clock.store(due, Ordering::Relaxed);
    let echo = body.clone();
    let src = f
        .links
        .iter()
        .find(|l| l.from == 3 && l.to == 1)
        .unwrap()
        .side;
    for _ in 0..32 {
        f.routers[1].rx_packed_from_side(&echo, src).unwrap();
    }
    assert_eq!(
        ack_count(&f, 1, id),
        1,
        "a due duplicate cannot stack behind a physically refused receipt"
    );
    busy.store(false, Ordering::Relaxed);
    f.pump(due + 1, 499 - due);
    assert!(
        f.routers
            .iter()
            .all(|r| !r.has_pending_reliable_tx_type(f.ty))
    );
}
#[test]
fn cycle_reversed_arrival_order_still_completes_within_500ms() {
    for reverse in [true, false] {
        let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
        if reverse {
            f.links.reverse();
        } else {
            f.links.rotate_left(3);
        }
        f.publish(1, 1);
        f.pump(100, 500);
        assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
        assert_eq!(f.errors, 0);
        assert!(
            f.routers
                .iter()
                .all(|r| !r.has_pending_reliable_tx_type(f.ty))
        );
    }
}

#[test]
fn cycle_normal_endpoint_rejection_never_acknowledges() {
    let seed = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let (ty, ep) = (seed.ty, seed.ep);
    drop(seed);
    let mut f = Fixture::new_with_endpoint_failure(
        "endpoint_refused",
        &[(0, 1), (1, 2), (2, 3), (3, 1)],
        false,
        ty,
        ep,
        true,
    );
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 1);
    assert!(
        !f.routers[1]
            .state
            .lock()
            .reliable_return_routes
            .get(&id)
            .unwrap()
            .local_admission_completed
    );
    f.pump(101, 400);
    assert!(f.errors > 0);
    assert!(!f.frames.iter().any(|(a, _, b)| *a == 1
        && sedsnet::wire_format::unpack_packet(b).is_ok_and(|p| p.data_type()
            == DataType::ReliableAck
            && p.payload() == id.to_le_bytes())));
}
#[test]
fn cycle_disabled_nonparent_egress_does_not_consume_receipt() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let held = f.links.remove(
        f.links
            .iter()
            .position(|l| l.from == 3 && l.to == 1)
            .unwrap(),
    );
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 1);
    let body = std::mem::take(&mut *held.wire.lock().unwrap())
        .into_iter()
        .find(|b| sedsnet::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty))
        .unwrap();
    let parent = f.routers[1]
        .state
        .lock()
        .reliable_return_routes
        .get(&id)
        .unwrap()
        .side;
    f.routers[1]
        .set_side_egress_enabled(held.side, false)
        .unwrap();
    f.routers[1].rx_packed_from_side(&body, held.side).unwrap();
    {
        let st = f.routers[1].state.lock();
        let route = st.reliable_return_routes.get(&id).unwrap();
        assert_eq!(route.side, parent);
        assert!(!route.delivery_completed);
    }
    f.routers[1]
        .set_side_egress_enabled(held.side, true)
        .unwrap();
    f.routers[1].rx_packed_from_side(&body, held.side).unwrap();
    assert_eq!(ack_count(&f, 1, id), 1);
    f.links.push(held);
    f.pump(101, 399);
    assert!(
        f.routers
            .iter()
            .all(|r| !r.has_pending_reliable_tx_type(f.ty))
    );
}
#[test]
fn cycle_concurrent_uncommitted_nv_callback_is_not_acceptance() {
    let f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let node = f.routers[1].clone();
    let ty = f.ty;
    let weak = Arc::downgrade(&node);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let first = AtomicBool::new(true);
    node.on_network_variable_update(ty, move |_| {
        if first.swap(false, Ordering::Relaxed) {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            weak.upgrade()
                .unwrap()
                .invalidate_network_variable_cache(ty);
            return Err(sedsnet::TelemetryError::Io("held validation rejected"));
        }
        Ok(())
    })
    .unwrap();
    let packet = sedsnet::packet::Packet::new(ty, &[f.ep], "writer", 99, Arc::<[u8]>::from([1]))
        .unwrap()
        .with_nonce(41);
    let id = packet.packet_id();
    let target = Router::sender_hash(node.sender().as_ref());
    let data = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(packet), &[target])
        .unwrap();
    let wire = match data {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    let parent = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let alternate = f
        .links
        .iter()
        .find(|l| l.from == 3 && l.to == 1)
        .unwrap()
        .side;
    let worker = node.clone();
    let first_wire = wire.clone();
    let join = std::thread::spawn(move || worker.rx_packed_from_side(&first_wire, parent));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let duplicate = node.rx_packed_from_side(&wire, alternate);
    let accepted = node
        .state
        .lock()
        .reliable_return_routes
        .get(&id)
        .is_some_and(|route| route.local_admission_completed);
    let stop_ep = sedsnet::config::register_endpoint("GENERIC_CYCLE_STOP_ENDPOINT", false).unwrap();
    let stop_ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_CYCLE_STOP",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[stop_ep],
        ReliableMode::Ordered,
        200,
    )
    .unwrap();
    node.enable_network_variable(stop_ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let stop_count = Arc::new(AtomicU64::new(0));
    let count = stop_count.clone();
    node.on_network_variable_update(stop_ty, move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();
    let stop =
        sedsnet::packet::Packet::new(stop_ty, &[stop_ep], "writer", 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(42);
    let (stop_tx, stop_rx) = std::sync::mpsc::sync_channel(1);
    let stop_node = node.clone();
    let stop_join =
        std::thread::spawn(move || stop_tx.send(stop_node.rx_from_side(&stop, parent)).unwrap());
    let stop_result = stop_rx.recv_timeout(std::time::Duration::from_secs(2));
    // Fill beyond the return-route cap while the callback is held: its admission
    // row is pinned, all unrelated fixture leases retire immediately.
    let token = node
        .state
        .lock()
        .reliable_return_routes
        .get(&id)
        .unwrap()
        .local_admission_token;
    for extra in 1..super::runtime_reliable_max_return_routes() + 17 {
        assert!(node.note_reliable_return_route(parent, id.wrapping_add(extra as u64)));
    }
    {
        let state = node.state.lock();
        assert_eq!(
            state
                .reliable_return_routes
                .get(&id)
                .unwrap()
                .local_admission_token,
            token
        );
        assert!(state.reliable_return_routes.len() <= super::runtime_reliable_max_return_routes());
    }
    release_tx.send(()).unwrap();
    assert!(join.join().unwrap().is_err());
    stop_join.join().unwrap();
    assert!(stop_result.unwrap().is_ok());
    assert_eq!(stop_count.load(Ordering::Relaxed), 1);
    eprintln!(
        "concurrent duplicate_result={duplicate:?} accepted_while_callback_pending={accepted}"
    );
    assert!(
        !accepted,
        "a pending/rejected required callback cannot be certified by a duplicate cache hit"
    );
}

#[test]
fn cycle_multiple_backedges_keep_all_owner_deadline() {
    for reverse in [false, true] {
        let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1), (1, 4), (4, 5), (5, 1)]);
        if reverse {
            f.links.reverse();
        }
        f.publish(1, 1);
        f.pump(100, 500);
        assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
        assert_eq!(f.errors, 0);
        assert!(
            f.routers
                .iter()
                .all(|r| !r.has_pending_reliable_tx_type(f.ty))
        );
    }
}

#[test]
fn cycle_held_callback_side_reuse_is_aba_safe() {
    let f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let node = f.routers[1].clone();
    let ty = f.ty;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let first = AtomicBool::new(true);
    let weak = Arc::downgrade(&node);
    node.on_network_variable_update(ty, move |_| {
        if first.swap(false, Ordering::Relaxed) {
            entered_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            weak.upgrade()
                .unwrap()
                .invalidate_network_variable_cache(ty);
            return Err(sedsnet::TelemetryError::Io("old side validation rejected"));
        }
        Ok(())
    })
    .unwrap();
    let packet = sedsnet::packet::Packet::new(ty, &[f.ep], "writer", 99, Arc::<[u8]>::from([1]))
        .unwrap()
        .with_nonce(43);
    let id = packet.packet_id();
    let target = Router::sender_hash(node.sender().as_ref());
    let data = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(packet), &[target])
        .unwrap();
    let wire = match data {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    let old = f
        .links
        .iter()
        .find(|l| l.from == 3 && l.to == 1)
        .unwrap()
        .side;
    let worker = node.clone();
    let first_wire = wire.clone();
    let join = std::thread::spawn(move || worker.rx_packed_from_side(&first_wire, old));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let token = node
        .state
        .lock()
        .reliable_return_routes
        .get(&id)
        .unwrap()
        .local_admission_token;
    node.remove_side(old).unwrap();
    let replacement = node.add_side_packed_with_options(
        "replacement",
        |_| Ok(()),
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    assert_eq!(replacement, old);
    assert!(node.rx_packed_from_side(&wire, replacement).is_err());
    {
        let state = node.state.lock();
        let route = state.reliable_return_routes.get(&id).unwrap();
        assert_eq!(route.local_admission_token, token);
        assert!(route.admission_cancelled);
        assert!(!route.local_admission_completed);
    }
    release_tx.send(()).unwrap();
    assert!(join.join().unwrap().is_err());
    assert!(!node.state.lock().reliable_return_routes.contains_key(&id));
    node.rx_packed_from_side(&wire, replacement).unwrap();
    {
        let state = node.state.lock();
        let route = state.reliable_return_routes.get(&id).unwrap();
        assert_eq!(route.local_admission_token, 0);
        assert!(!route.admission_cancelled);
        assert!(route.local_admission_completed);
        assert!(state.local_admission_sequence > token);
    }
}
#[test]
fn cycle_admission_token_exhaustion_is_fail_closed() {
    let f = cycle_fixture(&[(0, 1)]);
    let node = &f.routers[1];
    let side = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    node.state.lock().local_admission_sequence = u64::MAX;
    let count = node.state.lock().reliable_return_routes.len();
    assert!(node.begin_reliable_local_admission(side, 101).is_err());
    assert_eq!(node.state.lock().reliable_return_routes.len(), count);
    assert_eq!(node.state.lock().local_admission_sequence, u64::MAX);
}
#[test]
fn cycle_acyclic_failed_endpoint_with_accepted_children_has_no_local_receipt() {
    let seed = cycle_fixture(&[(0, 1), (1, 2)]);
    let (ty, ep) = (seed.ty, seed.ep);
    drop(seed);
    let mut f = Fixture::new_with_endpoint_failure(
        "acyclic_endpoint_refused",
        &[(0, 1), (1, 2)],
        false,
        ty,
        ep,
        true,
    );
    let packet = sedsnet::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from([1]))
        .unwrap()
        .with_nonce(44);
    let id = packet.packet_id();
    let owners = [
        Router::sender_hash(f.routers[1].sender().as_ref()),
        Router::sender_hash(f.routers[2].sender().as_ref()),
    ];
    let data = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(packet), &owners)
        .unwrap();
    let packet = match data {
        super::RouterItem::Packet(p) => p,
        super::RouterItem::Packed(b) => sedsnet::wire_format::unpack_packet(&b).unwrap(),
    };
    f.routers[0].set_network_variable(packet).unwrap();
    f.pump(100, 300);
    assert_eq!(
        f.callbacks.load(Ordering::Relaxed),
        1,
        "downstream child actually accepted"
    );
    assert!(f.errors > 0);
    let receipt = |from: usize, f: &Fixture| {
        f.frames.iter().any(|(a, _, b)| {
            *a == from
                && sedsnet::wire_format::unpack_packet(b).is_ok_and(|p| {
                    p.data_type() == DataType::ReliableAck
                        && p.payload() == id.to_le_bytes()
                        && Router::end_to_end_ack_sender_hash(&p) == Some(owners[from - 1])
                })
        })
    };
    assert!(
        receipt(2, &f),
        "real exact frozen child receipt must arrive"
    );
    assert!(
        !receipt(1, &f),
        "failed local endpoint cannot receive aggregate success from its accepted child"
    );
    {
        let state = f.routers[0].state.lock();
        let pending = &state
            .end_to_end_reliable_tx
            .get(&id)
            .expect("local receipt still owed")
            .pending_destinations;
        assert!(pending.contains_key(&owners[0]));
        assert!(!pending.contains_key(&owners[1]));
    }
    f.endpoint_reject.store(false, Ordering::Relaxed);
    f.pump(400, 100);
    assert!(
        receipt(1, &f),
        "same-parent retry reaches genuine callback acceptance"
    );
    assert!(
        !f.routers[0]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id)
    );
}
#[test]
fn cycle_four_independent_backedges_do_not_serialize_deadline() {
    let mut f = cycle_fixture(&[
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 1),
        (1, 4),
        (4, 5),
        (5, 1),
        (1, 6),
        (6, 7),
        (7, 1),
        (1, 8),
        (8, 9),
        (9, 1),
    ]);
    f.publish(1, 1);
    f.pump(100, 500);
    assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
    assert_eq!(f.errors, 0);
    assert!(
        f.routers
            .iter()
            .all(|r| !r.has_pending_reliable_tx_type(f.ty)),
        "independent duplicate edges must not wait behind each other's retry cooldown"
    );
}
#[test]
fn cycle_route_layout_reports_real_host_growth() {
    struct OldRoute {
        side: usize,
        delivery_completed: bool,
        last_replay_ms: u64,
        upstream_contract: Option<(u64, u64)>,
    }
    // The baseline shape is copied literally from cb51. No field packing, pool or
    // stack-size changes are used to force the normative layout.
    let old = core::mem::size_of::<OldRoute>();
    let new = core::mem::size_of::<super::ReliableReturnRouteState>();
    eprintln!(
        "ACTUAL_ROUTE_LAYOUT old={old} new={new} RouterInner_new={} return_route_cap={}",
        core::mem::size_of::<super::RouterInner>(),
        super::runtime_reliable_max_return_routes()
    );
    assert!(new <= old + 8);
    let witness = OldRoute {
        side: 0,
        delivery_completed: false,
        last_replay_ms: 0,
        upstream_contract: None,
    };
    assert_eq!(
        (
            witness.side,
            witness.delivery_completed,
            witness.last_replay_ms,
            witness.upstream_contract
        ),
        (0, false, 0, None)
    );
}
#[test]
fn cycle_after_drain_duplicates_have_one_receipt_per_input_and_no_data_replay() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1), (2, 4)]);
    f.links
        .iter()
        .find(|l| l.from == 2 && l.to == 4)
        .unwrap()
        .blocked
        .store(true, Ordering::Relaxed);
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 10);
    let duplicate = f
        .frames
        .iter()
        .find(|(a, b, bytes)| {
            *a == 3
                && *b == 1
                && sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == f.ty)
        })
        .unwrap()
        .2
        .clone();
    let src = f
        .links
        .iter()
        .find(|l| l.from == 3 && l.to == 1)
        .unwrap()
        .side;
    let owner = Router::sender_hash(f.routers[1].sender().as_ref());
    let receipts = |f: &Fixture| {
        f.frames
            .iter()
            .filter(|(a, _, bytes)| {
                *a == 1
                    && sedsnet::wire_format::unpack_packet(bytes).is_ok_and(|p| {
                        p.data_type() == DataType::ReliableAck
                            && p.payload() == id.to_le_bytes()
                            && Router::end_to_end_ack_sender_hash(&p) == Some(owner)
                    })
            })
            .count()
    };
    let data = |f: &Fixture| {
        f.frames
            .iter()
            .filter(|(a, _, bytes)| {
                *a == 1 && sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|p| p.ty == f.ty)
            })
            .count()
    };
    let before = receipts(&f);
    let before_data = data(&f);
    for i in 0..32 {
        f.clock.store(110 + i, Ordering::Relaxed);
        f.routers[1].rx_packed_from_side(&duplicate, src).unwrap();
        f.pump(110 + i, 1);
    }
    assert_eq!(
        receipts(&f) - before,
        32,
        "at most one side-directed receipt per valid input after physical drain"
    );
    assert_eq!(
        data(&f),
        before_data,
        "duplicate closure never expands/reforwards the value"
    );
    assert!(
        f.routers[0]
            .state
            .lock()
            .end_to_end_reliable_tx
            .contains_key(&id),
        "the distinct missing child remains owed"
    );
}
#[cfg(feature = "compact-packet-store")]
#[test]
fn cycle_compact_positive_parked_owner_and_receipt_scans_stay_unpinned() {
    struct Restore(Option<Arc<crate::packet_store::PacketStore>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::packet_store::set_default_store(self.0.take());
        }
    }
    let _restore = Restore(crate::packet_store::default_store());
    let store = crate::packet_store::PacketStore::new(32768, 512, 512).unwrap();
    crate::packet_store::set_default_store(Some(store.clone()));
    let ep = sedsnet::config::register_endpoint("GENERIC_CYCLE_COMPACT_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_CYCLE_COMPACT_VALUE",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let mut f = Fixture::new(
        "parked_cycle",
        &[(0, 1), (1, 2), (2, 3), (3, 1)],
        false,
        ty,
        ep,
    );
    let held = f.links.remove(
        f.links
            .iter()
            .position(|l| l.from == 3 && l.to == 1)
            .unwrap(),
    );
    let mut seed = 0x73912468u32;
    let payload: Vec<u8> = (0..1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect();
    let packet = sedsnet::packet::Packet::new(ty, &[ep], "writer", 99, Arc::<[u8]>::from(payload))
        .unwrap()
        .with_nonce(45);
    let id = packet.packet_id();
    f.routers[0].set_network_variable(packet).unwrap();
    f.pump(100, 20);
    // Move actual retained canonical owner bytes into the configured arena. The
    // bytes, frozen recipients and ownership maps stay exact; this gives a
    // positive witness even when automatic parking thresholds differ by profile.
    for node in 0..4 {
        let mut st = f.routers[node].state.lock();
        let owner = st.end_to_end_reliable_tx.get_mut(&id).unwrap();
        if let super::RouterItem::Packed(bytes) = &mut owner.data {
            let handle = crate::shared_bytes::with_slice(bytes, |view| store.store(view))
                .unwrap()
                .unwrap();
            *bytes = crate::SharedBytes::Managed(crate::packet_store::ParkedPayload::new(handle));
        }
    }
    let input = f.routers[3]
        .state
        .lock()
        .end_to_end_reliable_tx
        .get(&id)
        .unwrap()
        .data
        .clone();
    let item = super::RouterRxItem {
        src: Some(held.side),
        data: input,
        priority: 254,
    };
    let positive = store.stats();
    assert!(positive.live_bytes >= 1024 && positive.live_handles > 0);
    assert_eq!(positive.pinned_bytes, 0);
    f.routers[1]
        .queue_duplicate_proxy_edge_receipt(&item, id)
        .unwrap();
    assert_eq!(ack_count(&f, 1, id), 1);
    // Also make the exact queued ACK an arena owner, exercising the coalescing
    // scan instead of allowing a zero-arena ACK path to pass vacuously.
    {
        let mut st = f.routers[1].state.lock();
        for index in 0..st.transmit_queue.len() {
            st.transmit_queue.update_metadata(index, |queued| {
                if let super::RouterTxItem::ToSide {
                    dst,
                    data: super::RouterItem::Packed(bytes),
                    ..
                } = &mut queued.item
                    && *dst == held.side
                {
                    let is_ack = crate::shared_bytes::with_slice(bytes, |view| {
                        sedsnet::wire_format::scheduling_type(view) == Some(DataType::ReliableAck)
                    })
                    .unwrap();
                    if is_ack {
                        let handle =
                            crate::shared_bytes::with_slice(bytes, |view| store.store(view))
                                .unwrap()
                                .unwrap();
                        *bytes = crate::SharedBytes::Managed(
                            crate::packet_store::ParkedPayload::new(handle),
                        );
                    }
                }
            });
        }
    }
    let baseline = store.stats();
    assert!(baseline.live_handles > positive.live_handles);
    assert_eq!(baseline.pinned_bytes, 0);
    for _ in 0..32 {
        f.routers[1]
            .queue_duplicate_proxy_edge_receipt(&item, id)
            .unwrap();
        let current = store.stats();
        assert_eq!(
            (
                current.live_bytes,
                current.live_handles,
                current.pinned_bytes
            ),
            (baseline.live_bytes, baseline.live_handles, 0)
        );
    }
    eprintln!("CYCLE_COMPACT_POSITIVE owner={positive:?} with_queued_receipt={baseline:?}");
    drop(item);
    drop(f);
    drop(held);
    let final_stats = store.stats();
    assert_eq!(
        (
            final_stats.live_bytes,
            final_stats.live_handles,
            final_stats.pinned_bytes
        ),
        (0, 0, 0)
    );
}
#[test]
fn cycle_edge_receipt_requires_exact_target_source_and_crc_binding() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 3), (3, 1)]);
    let held = f.links.remove(
        f.links
            .iter()
            .position(|l| l.from == 3 && l.to == 1)
            .unwrap(),
    );
    f.publish(1, 1);
    let id = owner_id(&f);
    f.pump(100, 1);
    let body = std::mem::take(&mut *held.wire.lock().unwrap())
        .into_iter()
        .find(|b| sedsnet::wire_format::peek_envelope(b).is_ok_and(|e| e.ty == f.ty))
        .unwrap();
    let packet = sedsnet::wire_format::unpack_packet(&body).unwrap();
    // Reconstruct an unfrozen source identity: the production attach helper
    // intentionally preserves an already frozen cohort instead of retargeting.
    let packet = sedsnet::packet::Packet::new(
        packet.data_type(),
        packet.endpoints(),
        packet.sender(),
        packet.timestamp(),
        Arc::<[u8]>::from(packet.payload()),
    )
    .unwrap()
    .with_nonce(packet.nonce());
    let wrong_target = Router::sender_hash(f.routers[2].sender().as_ref());
    let retargeted = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(packet), &[wrong_target])
        .unwrap();
    let wire = match retargeted {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    assert_eq!(
        sedsnet::wire_format::packet_id_from_wire(&wire).unwrap(),
        id
    );
    f.routers[1].rx_packed_from_side(&wire, held.side).unwrap();
    assert_eq!(ack_count(&f, 1, id), 0);
    let wrong =
        sedsnet::packet::Packet::new(f.ty, &[f.ep], "other-writer", 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(1);
    let local = Router::sender_hash(f.routers[1].sender().as_ref());
    let data = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(wrong), &[local])
        .unwrap();
    let fault = super::RouterRxItem {
        src: Some(held.side),
        data,
        priority: 254,
    };
    // Internal-key fault injection: ordinary RX computes its key from the wire.
    // Even with a deliberately wrong key, a different retained publisher source
    // cannot authorize a receipt for this original owner.
    f.routers[1]
        .queue_duplicate_proxy_edge_receipt(&fault, id)
        .unwrap();
    assert_eq!(ack_count(&f, 1, id), 0);
    let mut damaged = body;
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let malformed = super::RouterRxItem {
        src: Some(held.side),
        data: super::RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(damaged))),
        priority: 254,
    };
    assert!(
        f.routers[1]
            .queue_duplicate_proxy_edge_receipt(&malformed, id)
            .is_err()
    );
    assert_eq!(ack_count(&f, 1, id), 0);
    {
        let state = f.routers[1].state.lock();
        assert!(
            !state
                .reliable_return_routes
                .get(&id)
                .unwrap()
                .delivery_completed
        );
        assert_eq!(
            state
                .end_to_end_reliable_tx
                .get(&id)
                .unwrap()
                .pending_destinations
                .len(),
            2
        );
    }
}
#[test]
fn cycle_original_publisher_is_not_a_downstream_obligation() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 0), (2, 3)]);
    f.publish(1, 1);
    let id = owner_id(&f);
    let publisher = Router::sender_hash(f.routers[0].sender().as_ref());
    f.pump(100, 1);
    let mut publisher_owed = false;
    for (i, node) in f.routers.iter().enumerate() {
        let state = node.state.lock();
        if let Some(owner) = state.end_to_end_reliable_tx.get(&id) {
            eprintln!(
                "PUBLISHER_CYCLE at100 node={i} pending={:?}",
                owner.pending_destinations
            );
            publisher_owed |= owner.pending_destinations.contains_key(&publisher);
        }
    }
    f.pump(101, 499);
    let pending: Vec<_> = f
        .routers
        .iter()
        .map(|node| node.state.lock().end_to_end_reliable_tx.contains_key(&id))
        .collect();
    eprintln!(
        "PUBLISHER_CYCLE publisher_owed={publisher_owed} pending_at500={pending:?} target_callbacks={} errors={}",
        f.callbacks.load(Ordering::Relaxed),
        f.errors
    );
    assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
    assert!(
        pending.iter().all(|p| !*p),
        "the original source echo cannot own an unfulfillable child receipt"
    );
    assert!(
        !publisher_owed,
        "the origin must not become a child of its own forwarded observation"
    );
}
#[test]
fn cycle_assigned_compact_known_publisher_closes_without_self_replay() {
    let mut f = cycle_fixture(&[(0, 1), (1, 2), (2, 0), (2, 3)]);
    let assigned = 0x1357_2468;
    f.routers[0]
        .set_address_assignment(super::AddressAssignmentMode::Static(assigned))
        .unwrap();
    f.pump(100, 200);
    assert_eq!(f.routers[0].current_address(), assigned);
    for node in [1, 2] {
        assert_eq!(
            f.routers[node]
                .resolve_address(assigned)
                .unwrap()
                .hostname
                .as_ref(),
            "writer"
        );
    }
    let now = f.clock.load(Ordering::Relaxed);
    let packet = sedsnet::packet::Packet::new(
        f.ty,
        &[f.ep],
        &format!("@addr:{assigned}"),
        now,
        Arc::<[u8]>::from([1]),
    )
    .unwrap()
    .with_nonce(47);
    let id = packet.packet_id();
    let original = packet.clone();
    f.routers[0].on_network_variable_update(f.ty,move |received|{
        eprintln!("ASSIGNED_OBSERVATION id_same={} sender_original={} sender_received={} time_same={} nonce_same={} payload_same={} endpoints_same={} targets_original={:?} targets_received={:?}",original.packet_id()==received.packet_id(),original.sender(),received.sender(),original.timestamp()==received.timestamp(),original.nonce()==received.nonce(),original.payload()==received.payload(),original.endpoints()==received.endpoints(),original.wire_target_senders(),received.wire_target_senders());Ok(())
    }).unwrap();
    f.routers[0].set_network_variable(packet).unwrap();
    eprintln!(
        "ASSIGNED_SOURCE callback_after_set={}",
        f.observer_callbacks[0].load(Ordering::Relaxed)
    );
    f.routers[0].process_all_queues_with_timeout(0).unwrap();
    eprintln!(
        "ASSIGNED_SOURCE callback_after_local_dispatch={}",
        f.observer_callbacks[0].load(Ordering::Relaxed)
    );
    f.pump(now + 1, 500);
    eprintln!(
        "ASSIGNED_SOURCE callback_after_air={} pending={:?}",
        f.observer_callbacks[0].load(Ordering::Relaxed),
        f.routers
            .iter()
            .map(|node| node.state.lock().end_to_end_reliable_tx.contains_key(&id))
            .collect::<Vec<_>>()
    );
    assert_eq!(f.callbacks.load(Ordering::Relaxed), 1);
    assert_eq!(
        f.observer_callbacks[0].load(Ordering::Relaxed),
        0,
        "self source echo remains suppressed"
    );
    assert!(
        f.routers
            .iter()
            .all(|node| !node.state.lock().end_to_end_reliable_tx.contains_key(&id))
    );
    assert_eq!(f.errors, 0);
}
#[test]
fn cycle_publisher_filter_preserves_frozen_unknown_and_collision_owners() {
    let f = cycle_fixture(&[(0, 1), (1, 2), (2, 0), (2, 3)]);
    let node = &f.routers[2];
    let parent = f
        .links
        .iter()
        .find(|l| l.from == 1 && l.to == 2)
        .unwrap()
        .side;
    let writer = Router::sender_hash("writer");
    let leaf = Router::sender_hash(f.routers[3].sender().as_ref());
    let make = |sender: &str| {
        sedsnet::packet::Packet::new(f.ty, &[f.ep], sender, 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(48)
    };
    let named = make("writer");
    {
        let state = node.state.lock();
        let selected = node
            .expected_end_to_end_destinations_locked(
                &state,
                &super::RouterItem::Packet(named.clone()),
                Some(parent),
                true,
                true,
            )
            .unwrap();
        assert!(!selected.contains_key(&writer));
        assert!(selected.contains_key(&leaf));
    }
    let frozen = f.routers[0]
        .attach_wire_contract_to_item(super::RouterItem::Packet(named), &[writer, leaf])
        .unwrap();
    {
        let state = node.state.lock();
        let selected = node
            .expected_end_to_end_destinations_locked(&state, &frozen, Some(parent), true, false)
            .unwrap();
        assert!(selected.contains_key(&writer));
        assert!(selected.contains_key(&leaf));
    }
    let unknown = 0xdead_beefu32;
    {
        let state = node.state.lock();
        assert!(Router::hostname_for_address_borrowed_locked(&state, unknown).is_none());
    }
    for packed in [false, true] {
        let pkt = make(&format!("@addr:{unknown}"));
        let data = if packed {
            super::RouterItem::Packed(crate::shared_bytes::convert(
                sedsnet::wire_format::pack_packet(&pkt),
            ))
        } else {
            super::RouterItem::Packet(pkt)
        };
        let state = node.state.lock();
        let selected = node
            .expected_end_to_end_destinations_locked(&state, &data, Some(parent), true, true)
            .unwrap();
        assert!(selected.contains_key(&writer));
        assert!(selected.contains_key(&leaf));
    }
    let (a, b) = ("cycle-collision-90789", "cycle-collision-91958");
    let address = crate::packet::sender_address_u32(a);
    assert_eq!(address, crate::packet::sender_address_u32(b));
    assert_ne!(Router::sender_hash(a), Router::sender_hash(b));
    {
        let mut state = node.state.lock();
        state.address_by_value.remove(&address);
        let other = f
            .links
            .iter()
            .find(|l| l.from == 0 && l.to == 2)
            .unwrap()
            .side;
        let route = state.discovery_routes.get_mut(&other).unwrap();
        for name in [a, b] {
            route.announcers.insert(
                name.to_string(),
                Box::new(super::DiscoverySenderState {
                    reachable_network_variables: vec![f.ty],
                    last_seen_ms: 99,
                    ..Default::default()
                }),
            );
        }
        assert!(Router::hostname_for_address_borrowed_locked(&state, address).is_none());
    }
    for packed in [false, true] {
        let pkt = make(&format!("@addr:{address}"));
        let data = if packed {
            super::RouterItem::Packed(crate::shared_bytes::convert(
                sedsnet::wire_format::pack_packet(&pkt),
            ))
        } else {
            super::RouterItem::Packet(pkt)
        };
        let state = node.state.lock();
        let selected = node
            .expected_end_to_end_destinations_locked(&state, &data, Some(parent), true, true)
            .unwrap();
        assert!(selected.contains_key(&Router::sender_hash(a)));
        assert!(selected.contains_key(&Router::sender_hash(b)));
        assert!(selected.contains_key(&leaf));
    }
}
#[test]
fn cycle_incremental_route_budget_refusal_leaks_no_admission_or_receipt() {
    let f = cycle_fixture(&[(0, 1), (1, 2)]);
    let node = &f.routers[1];
    let side = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let packet = sedsnet::packet::Packet::new(f.ty, &[f.ep], "writer", 99, Arc::<[u8]>::from([1]))
        .unwrap()
        .with_nonce(50);
    let id = packet.packet_id();
    let data = f.routers[0]
        .attach_wire_contract_to_item(
            super::RouterItem::Packet(packet),
            &[Router::sender_hash(node.sender().as_ref())],
        )
        .unwrap();
    let wire = match data {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    let (used, count, sequence, queue, budget) = {
        let mut state = node.state.lock();
        let saved = (
            state.shared_queue_bytes_used(),
            state.reliable_return_routes.len(),
            state.local_admission_sequence,
            state.transmit_queue.len(),
            state.memory.max_queue_budget,
        );
        state.memory.max_queue_budget =
            saved.0 + super::RELIABLE_RETURN_ROUTE_EXTRA_LOGICAL_BYTES - 1;
        saved
    };
    assert!(node.rx_packed_from_side(&wire, side).is_err());
    {
        let state = node.state.lock();
        assert_eq!(state.shared_queue_bytes_used(), used);
        assert_eq!(state.reliable_return_routes.len(), count);
        assert!(!state.reliable_return_routes.contains_key(&id));
        assert_eq!(state.local_admission_sequence, sequence);
        assert_eq!(state.transmit_queue.len(), queue);
    }
    assert_eq!(f.observer_callbacks[1].load(Ordering::Relaxed), 0);
    assert_eq!(ack_count(&f, 1, id), 0);
    assert!(node.cached_managed_variable(f.ty).is_none());
    // Exact headroom admits the logical record; renewing it requires no second
    // charge even when the budget is precisely the already-used amount.
    {
        node.state.lock().memory.max_queue_budget =
            used + super::RELIABLE_RETURN_ROUTE_EXTRA_LOGICAL_BYTES;
    }
    let guard = node
        .begin_reliable_local_admission(side, id)
        .unwrap()
        .unwrap();
    drop(guard);
    let exact = node.state.lock().shared_queue_bytes_used();
    assert_eq!(
        exact,
        used + super::RELIABLE_RETURN_ROUTE_EXTRA_LOGICAL_BYTES
    );
    node.state.lock().memory.max_queue_budget = exact;
    let guard = node
        .begin_reliable_local_admission(side, id)
        .unwrap()
        .unwrap();
    drop(guard);
    assert_eq!(node.state.lock().shared_queue_bytes_used(), exact);
    node.state.lock().memory.max_queue_budget = budget;
}
#[test]
fn cycle_full_return_route_window_reuses_charge_without_growth() {
    let f = cycle_fixture(&[(0, 1)]);
    let node = &f.routers[1];
    let side = f
        .links
        .iter()
        .find(|l| l.from == 0 && l.to == 1)
        .unwrap()
        .side;
    let cap = super::runtime_reliable_max_return_routes().max(1);
    for id in 1..=cap {
        let guard = node
            .begin_reliable_local_admission(side, id as u64)
            .unwrap()
            .unwrap();
        drop(guard);
    }
    let (used, budget) = {
        let mut state = node.state.lock();
        assert_eq!(state.reliable_return_routes.len(), cap);
        let saved = (
            state.shared_queue_bytes_used(),
            state.memory.max_queue_budget,
        );
        state.memory.max_queue_budget = saved.0;
        saved
    };
    let guard = node
        .begin_reliable_local_admission(side, u64::MAX - 1)
        .unwrap()
        .unwrap();
    drop(guard);
    {
        let mut state = node.state.lock();
        assert_eq!(state.shared_queue_bytes_used(), used);
        assert_eq!(state.reliable_return_routes.len(), cap);
        assert!(
            state
                .reliable_return_routes
                .values()
                .all(|route| route.local_admission_token == 0)
        );
        state.memory.max_queue_budget = budget;
    }
}
fn held_endpoint_cancellation(replace: bool) {
    let ep = sedsnet::config::register_endpoint("GENERIC_CANCEL_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_CANCEL_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let config = RouterConfig::new([super::EndpointHandler::new_packet_handler(ep, move |_| {
        entered_tx.send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
        Ok(())
    })])
    .with_sender("cancel-reader");
    let node = Arc::new(Router::new_with_clock(config, Box::new(|| 99u64)));
    let old_wire: Wire = Arc::default();
    let old = old_wire.clone();
    let side = node.add_side_packed_with_options(
        "old",
        move |bytes| {
            old.lock().unwrap().push(bytes.to_vec());
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    let packet =
        sedsnet::packet::Packet::new(ty, &[ep], "cancel-writer", 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(51);
    let id = packet.packet_id();
    let data = node
        .attach_wire_contract_to_item(
            super::RouterItem::Packet(packet),
            &[Router::sender_hash(node.sender().as_ref())],
        )
        .unwrap();
    let wire = match data {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    let worker = node.clone();
    let join = std::thread::spawn(move || worker.rx_packed_from_side(&wire, side));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let new_wire: Wire = Arc::default();
    let completed = Arc::new(AtomicBool::new(false));
    if replace {
        node.remove_side(side).unwrap();
        let out = new_wire.clone();
        let weak = Arc::downgrade(&node);
        let seen = completed.clone();
        let new_side = node.add_side_packed_with_options(
            "replacement",
            move |bytes| {
                seen.store(
                    weak.upgrade()
                        .unwrap()
                        .state
                        .lock()
                        .reliable_return_routes
                        .get(&id)
                        .is_some_and(|route| route.delivery_completed),
                    Ordering::Relaxed,
                );
                out.lock().unwrap().push(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions::default().with_small_packet_transport(192),
        );
        assert_eq!(new_side, side);
    } else {
        node.set_side_ingress_enabled(side, false).unwrap();
    }
    release_tx.send(()).unwrap();
    let result = join.join().unwrap();
    assert!(result.is_err());
    let receipts = |wire: &Wire| {
        wire.lock()
            .unwrap()
            .iter()
            .filter(|bytes| {
                sedsnet::wire_format::unpack_packet(bytes).is_ok_and(|p| {
                    p.data_type() == DataType::ReliableAck && p.payload() == id.to_le_bytes()
                })
            })
            .count()
    };
    // A deferred stale receipt would be just as wrong as an immediate one.
    node.dispatch_tx_queue_with_timeout(0).unwrap();
    node.process_rx_queue().unwrap();
    node.dispatch_tx_queue_with_timeout(0).unwrap();
    let escaped = receipts(&old_wire) + receipts(&new_wire);
    eprintln!(
        "HELD_ENDPOINT_CANCEL replace={replace} escaped_receipts={escaped} completion_observed={} result={result:?}",
        completed.load(Ordering::Relaxed)
    );
    assert_eq!(
        escaped, 0,
        "cancelled endpoint admission cannot emit a final receipt"
    );
    assert!(!completed.load(Ordering::Relaxed));
    assert!(!node.state.lock().reliable_return_routes.contains_key(&id));
}
#[test]
fn cycle_held_endpoint_remove_readd_cannot_ack_after_cancellation() {
    held_endpoint_cancellation(true)
}
#[test]
fn cycle_held_endpoint_ingress_disable_cannot_ack_after_cancellation() {
    held_endpoint_cancellation(false)
}
#[test]
fn cycle_unreliable_packed_fast_path_never_checks_admission_or_creates_tokens() {
    let ep = sedsnet::config::register_endpoint("GENERIC_UNRELIABLE_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_UNRELIABLE_VALUE",
        "",
        MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        16,
    )
    .unwrap();
    let received = Arc::new(AtomicU64::new(0));
    let count = received.clone();
    let node = Router::new(
        RouterConfig::new([super::EndpointHandler::new_packet_handler(ep, move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })])
        .with_sender("fast-reader"),
    );
    let side = node.add_side_packed("input", |_| Ok(()));
    let before = super::LOCAL_ADMISSION_CHECKS.with(|v| v.get());
    for i in 0..100 {
        let packet = sedsnet::packet::Packet::new(
            ty,
            &[ep],
            "fast-writer",
            i,
            Arc::<[u8]>::from(vec![i as u8; 1024]),
        )
        .unwrap()
        .with_nonce(i as u16);
        let wire = sedsnet::wire_format::pack_packet(&packet);
        node.rx_packed_from_side(&wire, side).unwrap();
    }
    assert_eq!(received.load(Ordering::Relaxed), 100);
    assert_eq!(super::LOCAL_ADMISSION_CHECKS.with(|v| v.get()), before);
    let state = node.state.lock();
    assert_eq!(state.local_admission_sequence, 0);
    assert!(state.reliable_return_routes.is_empty());
}
fn held_commit_transport(outcome: u8) {
    let ep = sedsnet::config::register_endpoint("GENERIC_COMMIT_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_COMMIT_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let node = Arc::new(Router::new_with_clock(
        RouterConfig::new([super::EndpointHandler::new_packet_handler(ep, |_| Ok(()))])
            .with_sender("commit-reader"),
        Box::new(|| 99u64),
    ));
    node.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let parent = node.add_side_packed_with_options(
        "parent",
        |_| Ok(()),
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let child = node.add_side_packed_with_options(
        "child",
        move |bytes| {
            if sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty) {
                entered_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                match outcome {
                    1 => return Err(sedsnet::TelemetryError::Io("side tx busy")),
                    2 => panic!("expected transport unwind"),
                    _ => {}
                }
            }
            Ok(())
        },
        RouterSideOptions::default().with_small_packet_transport(192),
    );
    let unrelated = node.add_side_packed("unrelated", |_| Ok(()));
    let ad = sedsnet::discovery::AddressAdvertisement {
        hostname: "commit-child".to_owned(),
        address: 0x777,
        requested_address: 0x777,
        mode: 2,
        state: 1,
        birth_ms: 1,
        owner_hash: 0x777,
        reachable_endpoints: vec![ep],
        reachable_network_variables: vec![ty],
        reachable_timesync_sources: vec![],
        link_capabilities: RouterSideOptions::default()
            .with_small_packet_transport(192)
            .link_capabilities(),
    };
    node.rx_from_side(
        &sedsnet::discovery::build_discovery_address("commit-child", 1, &ad).unwrap(),
        child,
    )
    .unwrap();
    let packet =
        sedsnet::packet::Packet::new(ty, &[ep], "commit-writer", 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(52);
    let id = packet.packet_id();
    let data = node
        .attach_wire_contract_to_item(
            super::RouterItem::Packet(packet),
            &[
                Router::sender_hash(node.sender().as_ref()),
                Router::sender_hash("commit-child"),
            ],
        )
        .unwrap();
    let wire = match data {
        super::RouterItem::Packed(b) => b.to_vec(),
        super::RouterItem::Packet(p) => sedsnet::wire_format::pack_packet(&p).to_vec(),
    };
    let worker = node.clone();
    let join = std::thread::spawn(move || worker.rx_packed_from_side(&wire, parent));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    {
        let state = node.state.lock();
        let route = state.reliable_return_routes.get(&id).unwrap();
        assert!(route.admission_committing);
        assert_ne!(route.local_admission_token, 0);
    }
    assert!(node.remove_side(parent).is_err());
    assert!(node.set_side_ingress_enabled(parent, false).is_err());
    assert!(node.set_side_egress_enabled(parent, false).is_err());
    node.remove_side(unrelated).unwrap();
    // A different priority200 logical Stop is accepted while the first transport
    // callback is held; the commit lease is not a Router mutex/global RX gate.
    let stop_ep =
        sedsnet::config::register_endpoint("GENERIC_COMMIT_STOP_ENDPOINT", false).unwrap();
    let stop_ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_COMMIT_STOP",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[stop_ep],
        ReliableMode::Ordered,
        200,
    )
    .unwrap();
    node.enable_network_variable(stop_ty, NetworkVariablePermissions::READ_ONLY)
        .unwrap();
    let stops = Arc::new(AtomicU64::new(0));
    let count = stops.clone();
    node.on_network_variable_update(stop_ty, move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })
    .unwrap();
    let stop = sedsnet::packet::Packet::new(
        stop_ty,
        &[stop_ep],
        "stop-writer",
        99,
        Arc::<[u8]>::from([1]),
    )
    .unwrap()
    .with_nonce(53);
    node.rx_from_side(&stop, parent).unwrap();
    node.process_rx_queue().unwrap();
    assert_eq!(stops.load(Ordering::Relaxed), 1);
    release_tx.send(()).unwrap();
    let result = join.join();
    if outcome == 2 {
        assert!(result.is_err());
    } else {
        let result = result.unwrap();
        eprintln!("COMMIT_TRANSPORT outcome={outcome} result={result:?}");
    }
    {
        let state = node.state.lock();
        assert!(
            state
                .reliable_return_routes
                .values()
                .all(|route| route.local_admission_token == 0 && !route.admission_committing)
        );
    }
    node.set_side_ingress_enabled(parent, false).unwrap();
    node.set_side_egress_enabled(parent, false).unwrap();
    node.remove_side(parent).unwrap();
}
#[test]
fn cycle_commit_reservation_releases_after_success() {
    held_commit_transport(0)
}
#[test]
fn cycle_commit_reservation_releases_after_transport_refusal() {
    held_commit_transport(1)
}
#[test]
fn cycle_commit_reservation_releases_after_unwind() {
    held_commit_transport(2)
}
#[test]
fn cycle_commit_reservation_releases_after_ack_budget_refusal() {
    let ep = sedsnet::config::register_endpoint("GENERIC_ACK_REFUSAL_ENDPOINT", false).unwrap();
    let ty = sedsnet::config::register_data_type_with_description(
        "GENERIC_ACK_REFUSAL_VALUE",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let weak = Arc::new(Mutex::new(None::<std::sync::Weak<Router>>));
    let callback = weak.clone();
    let node = Arc::new(Router::new_with_clock(
        RouterConfig::new([super::EndpointHandler::new_packet_handler(ep, move |_| {
            let node = callback
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap();
            let mut state = node.state.lock();
            state.memory.max_queue_budget = state.shared_queue_bytes_used();
            Ok(())
        })])
        .with_sender("ack-refusal-reader"),
        Box::new(|| 99u64),
    ));
    *weak.lock().unwrap() = Some(Arc::downgrade(&node));
    let side = node.add_side_packed("parent", |_| Ok(()));
    let packet =
        sedsnet::packet::Packet::new(ty, &[ep], "ack-refusal-writer", 99, Arc::<[u8]>::from([1]))
            .unwrap()
            .with_nonce(54);
    let id = packet.packet_id();
    assert!(node.rx_from_side(&packet, side).is_err());
    {
        let state = node.state.lock();
        let route = state.reliable_return_routes.get(&id).unwrap();
        assert_eq!(route.local_admission_token, 0);
        assert!(!route.admission_committing);
        assert!(!route.delivery_completed);
        assert!(state.transmit_queue.is_empty());
    }
    node.set_side_ingress_enabled(side, false).unwrap();
    node.set_side_egress_enabled(side, false).unwrap();
    node.remove_side(side).unwrap();
}
