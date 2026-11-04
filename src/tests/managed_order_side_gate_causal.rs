//! Synthetic two-router chronology. No application IDs or production policy.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex, OnceLock, Weak,
};
use std::time::{Duration, Instant};
const LIMIT: usize = 512;
// The audit selector and schema are process-wide test state. Hold this through
// the full case, including worker teardown. Expected RED panics poison only this
// test mutex; recovering that poison never recovers a production lock.
static CASE: Mutex<()> = Mutex::new(());
struct Worker(Option<std::thread::JoinHandle<TelemetryResult<()>>>);
impl Worker {
    fn spawn(f: impl FnOnce() -> TelemetryResult<()> + Send + 'static) -> Self {
        Self(Some(std::thread::spawn(f)))
    }
    fn join(mut self) -> std::thread::Result<TelemetryResult<()>> {
        self.0.take().unwrap().join()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            // Every fixture barrier has its unchanged three-second timeout.
            // Locals are declared after Fixture, so joins precede CASE release,
            // even if a fixture assertion unwinds before an explicit join.
            let _ = worker.join();
        }
    }
}
struct Pause {
    id: u64,
    reached: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}
struct Audit {
    router: usize,
    started: Instant,
    events: Mutex<Vec<serde_json::Value>>,
    lost: AtomicU64,
    pause: Mutex<Option<Pause>>,
}
static ACTIVE: OnceLock<Mutex<Option<Arc<Audit>>>> = OnceLock::new();
fn active(r: &Router) -> Option<Arc<Audit>> {
    ACTIVE
        .get()?
        .lock()
        .unwrap()
        .as_ref()
        .filter(|a| a.router == r as *const _ as usize)
        .cloned()
}
pub(super) fn data_meta(data: &RouterItem) -> serde_json::Value {
    match data {
        RouterItem::Packet(p) => {
            serde_json::json!({"kind":"Packet","id":p.packet_id(),"utc":p.timestamp(),"type":p.data_type().as_u32(),"payload":&p.payload()[..p.payload().len().min(64)],"payload_len":p.payload().len()})
        }
        RouterItem::Packed(b) => {
            serde_json::json!({"kind":"Packed","id":Router::get_hash(data),"bytes":&b[..b.len().min(2048)],"full_len":b.len()})
        }
    }
}
pub(super) fn item_meta(item: &RouterTxItem) -> serde_json::Value {
    match item {
        RouterTxItem::Broadcast(d) => serde_json::json!({"kind":"Broadcast","data":data_meta(d)}),
        RouterTxItem::ToSide { src, dst, data } => {
            serde_json::json!({"kind":"ToSide","src":src,"dst":dst,"data":data_meta(data)})
        }
        _ => serde_json::json!({"kind":"ReplayOrOther","debug":format!("{item:?}")}),
    }
}
fn queue(r: &Router) -> Vec<serde_json::Value> {
    // Clone at most 32 actual queue records under Core; decode only after drop.
    let rows = {
        let st = r.state.lock();
        st.transmit_queue
            .iter()
            .take(32)
            .cloned()
            .collect::<Vec<_>>()
    };
    rows.iter().map(|q|serde_json::json!({"item":item_meta(&q.item),"delivery":format!("{:?}",q.delivery_state),"accepted_type":q.accepted_type,"ignore_local":q.ignore_local,"flags":q.disposable,"priority":q.priority,"since":q.deferred_since_ms,"retry_after":q.retry_after_ms})).collect()
}
impl Audit {
    fn event(&self, phase: &str, value: serde_json::Value) {
        let row = serde_json::json!({"phase":phase,"us":self.started.elapsed().as_micros(),"thread":format!("{:?}",std::thread::current().id()),"value":value});
        let mut e = self.events.lock().unwrap();
        if e.len() == LIMIT {
            self.lost.fetch_add(1, Ordering::Relaxed);
        } else {
            e.push(row);
        }
    }
}
pub(super) fn observe(r: &Router, phase: &str, value: impl FnOnce() -> serde_json::Value) {
    if let Some(a) = active(r) {
        let value = value();
        let q = queue(r);
        a.event(phase, serde_json::json!({"detail":value,"queue":q}));
    }
}
pub(super) fn after_tail_guard(
    r: &Router,
    data: &RouterItem,
    from_queue: bool,
    ignore_local: bool,
) {
    let Some(a) = active(r) else { return };
    let id = match data {
        RouterItem::Packet(p) => p.packet_id(),
        _ => 0,
    };
    observe(
        r,
        "after_tail_guard",
        || serde_json::json!({"data":data_meta(data),"from_queue":from_queue,"ignore_local":ignore_local}),
    );
    let pause = {
        let mut p = a.pause.lock().unwrap();
        if p.as_ref().is_some_and(|p| p.id == id) && !from_queue && !ignore_local {
            p.take()
        } else {
            None
        }
    };
    if let Some(p) = pause {
        assert!(r.state.try_lock().is_some(), "barrier must be outside Core");
        assert!(
            crate::config::try_prepared_schema_guard().is_some(),
            "barrier must be outside schema"
        );
        p.reached.send(()).unwrap();
        p.resume
            .recv_timeout(Duration::from_secs(3))
            .expect("bounded producer barrier");
    }
}
struct Fixture {
    _case: std::sync::MutexGuard<'static, ()>,
    writer: Arc<Router>,
    peer: Arc<Router>,
    third: Option<Arc<Router>>,
    third_seen: Arc<Mutex<Vec<(u64,u8)>>>,
    clock: Arc<AtomicU64>,
    ep: DataEndpoint,
    ty: DataType,
    audit: Arc<Audit>,
    seen: Arc<Mutex<Vec<(u64, u8)>>>,
    wire: Arc<Mutex<Vec<serde_json::Value>>>,
    armed: Arc<AtomicBool>,
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    nonce: u16,
}
impl Fixture {
    fn new() -> Self {
        Self::with_shared_sender(false)
    }
    fn with_shared_sender(shared: bool) -> Self {
        Self::with_peer_layout(shared, false)
    }
    fn with_peer_layout(shared: bool, three: bool) -> Self {
        Self::with_bus_profile(shared,three,true)
    }
    fn with_bus_profile(shared: bool, three: bool, hop: bool) -> Self {
        let case = CASE.lock().unwrap_or_else(|poison| poison.into_inner());
        crate::tests::ensure_common_test_schema();
        let ep = crate::config::register_endpoint("ORDER_AUDIT_ENDPOINT", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "ORDER_AUDIT_VALUE",
            "Generic ordered publication chronology",
            crate::MessageElement::Static(
                1,
                crate::MessageDataType::UInt8,
                crate::MessageClass::Data,
            ),
            &[ep],
            crate::ReliableMode::Ordered,
            16,
        )
        .unwrap();
        let clock = Arc::new(AtomicU64::new(10000));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let c = clock.clone();
        let writer = Arc::new(Router::new_with_clock(
            if shared {
                RouterConfig::new([])
            } else {
                RouterConfig::new([]).with_sender("audit-writer")
            },
            Box::new(move || c.load(Ordering::Relaxed)),
        ));
        let c = clock.clone();
        let got = seen.clone();
        let peer_config = RouterConfig::new([EndpointHandler::new_packet_handler(
            ep,
            move |p: &Packet| {
                got.lock().unwrap().push((p.packet_id(), p.payload()[0]));
                Ok(())
            },
        )]);
        let peer_config = if shared {
            peer_config
        } else {
            peer_config.with_sender("audit-peer")
        };
        let peer = Arc::new(Router::new_with_clock(
            peer_config,
            Box::new(move || c.load(Ordering::Relaxed)),
        ));
        let audit = Arc::new(Audit {
            router: Arc::as_ptr(&writer) as usize,
            started: Instant::now(),
            events: Mutex::new(Vec::with_capacity(LIMIT)),
            lost: AtomicU64::new(0),
            pause: Mutex::new(None),
        });
        let bus = Arc::new(Mutex::new(Vec::<(Weak<Router>, RouterSideId)>::new()));
        let third_seen = Arc::new(Mutex::new(Vec::new()));
        let armed = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let rx = Arc::new(Mutex::new(release_rx));
        let dest = bus.clone();
        let w = wire.clone();
        let hold = armed.clone();
        let a = audit.clone();
        let rw = Arc::downgrade(&writer);
        let side=writer.add_side_packed_with_options("peer-link",move|bytes|{
            let info=crate::wire_format::peek_frame_info(bytes)?;
            if hold.load(Ordering::Acquire)&&discovery::is_discovery_type(info.envelope.ty)&&hold.swap(false,Ordering::AcqRel){
                let r=rw.upgrade().unwrap();assert!(r.state.try_lock().is_some(),"discovery callback Core unlocked");assert!(crate::config::try_prepared_schema_guard().is_some(),"discovery callback schema unlocked");
                a.event("discovery_gate_held",serde_json::json!({"type":info.envelope.ty.as_u32()}));entered_tx.send(()).unwrap();rx.lock().unwrap().recv_timeout(Duration::from_secs(3)).expect("bounded real discovery callback hold");
            }
            let p=crate::wire_format::unpack_packet(bytes)?;
            capacity_callback_probe(rw.as_ptr() as usize, &p)?;
            let row=serde_json::json!({"direction":"writer_to_peer","id":p.packet_id(),"type":p.data_type().as_u32(),"utc":p.timestamp(),"payload":&p.payload()[..p.payload().len().min(64)],"payload_len":p.payload().len(),"reliable":info.reliable.map(|h|serde_json::json!({"flags":h.flags,"seq":h.seq,"ack":h.ack})),"raw":if bytes.len()<=2048 {Some(bytes)}else{a.lost.fetch_add(1,Ordering::Relaxed);None}});let mut wire = w.lock().unwrap(); if wire.len() < LIMIT { wire.push(row.clone()); } else { a.lost.fetch_add(1, Ordering::Relaxed); } drop(wire);a.event("wire",row);
            let destinations=dest.lock().unwrap().clone();
            for (index,(d,s)) in destinations.into_iter().enumerate() {
                if index!=0 { d.upgrade().unwrap().rx_packed_from_side(bytes,s)?; }
            }
            Ok(())
        },RouterSideOptions{reliable_enabled:hop,link_local_enabled:true,..Default::default()});
        let dest = bus.clone();
        let a = audit.clone();
        let peer_side=peer.add_side_packed_with_options("writer-link",move|bytes|{
            let p=crate::wire_format::unpack_packet(bytes)?;a.event("peer_to_writer",serde_json::json!({"id":p.packet_id(),"type":p.data_type().as_u32(),"raw":if bytes.len()<=2048 {Some(bytes)}else{a.lost.fetch_add(1,Ordering::Relaxed);None}}));let destinations=dest.lock().unwrap().clone();for(index,(d,s))in destinations.into_iter().enumerate(){if index!=1 {d.upgrade().unwrap().rx_packed_from_side(bytes,s)?;}}Ok(())
        },RouterSideOptions{reliable_enabled:hop,link_local_enabled:true,..Default::default()});
        bus.lock().unwrap().push((Arc::downgrade(&writer),side));
        bus.lock().unwrap().push((Arc::downgrade(&peer),peer_side));
        let third=if three {
            let observed=third_seen.clone();let c=clock.clone();
            let node=Arc::new(Router::new_with_clock(RouterConfig::new([EndpointHandler::new_packet_handler(ep,move|p:&Packet|{
                observed.lock().unwrap().push((p.packet_id(),p.payload()[0]));Ok(())
            })]).with_sender("audit-third"),Box::new(move||c.load(Ordering::Relaxed))));
            let dest=bus.clone();let a=audit.clone();
            let bus_side=node.add_side_packed_with_options("shared-bus",move|bytes|{
                let p=crate::wire_format::unpack_packet(bytes)?;
                a.event("third_to_bus",serde_json::json!({"id":p.packet_id(),"type":p.data_type().as_u32()}));
                let destinations=dest.lock().unwrap().clone();for(index,(d,s))in destinations.into_iter().enumerate(){if index!=2 {d.upgrade().unwrap().rx_packed_from_side(bytes,s)?;}}Ok(())
            },RouterSideOptions{reliable_enabled:hop,link_local_enabled:true,..Default::default()});
            bus.lock().unwrap().push((Arc::downgrade(&node),bus_side));Some(node)
        }else{None};
        writer.announce_discovery().unwrap();
        peer.announce_discovery().unwrap();
        if let Some(third)=&third {third.announce_discovery().unwrap();}
        let mut f = Self {
            _case: case,
            writer,
            peer,
            third,
            third_seen,
            clock,
            ep,
            ty,
            audit,
            seen,
            wire,
            armed,
            entered,
            release,
            nonce: 0,
        };
        f.drain();
        if three { capture_shared_setup(&f,if hop{"generic-default-initial8"}else{"rfd-initial8"}); }
        for value in [1, 2, 3, 4, 3, 2, 1, 0, 1, 2] {
            let p = f.packet(value);
            f.writer.set_network_variable(p).unwrap();
            f.drain();
        }
        if three { capture_shared_setup(&f,if hop{"generic-default-warmup"}else{"rfd-warmup"}); }
        f.seen.lock().unwrap().clear();
        f.third_seen.lock().unwrap().clear();
        f.wire.lock().unwrap().clear();
        f.audit.events.lock().unwrap().clear();
        *ACTIVE.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(f.audit.clone());
        f
    }
    fn packet(&mut self, value: u8) -> Packet {
        self.nonce += 1;
        let now = self.clock.fetch_add(1, Ordering::Relaxed) + 1;
        Packet::new(
            self.ty,
            &[self.ep],
            self.writer.sender_arc().as_ref(),
            now,
            Arc::<[u8]>::from([value]),
        )
        .unwrap()
        .with_nonce(self.nonce)
    }
    fn drain(&mut self) {
        for _ in 0..8 {
            self.writer.process_all_queues().unwrap();
            self.peer.process_all_queues().unwrap();
            if let Some(third)=&self.third { third.process_all_queues().unwrap(); }
            self.clock.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn submit(&self, p: Packet) {
        let id = p.packet_id();
        self.audit.event(
            "submit_begin",
            serde_json::json!({"id":id,"utc":p.timestamp(),"value":p.payload()}),
        );
        let r = self.writer.set_network_variable(p);
        self.audit.event(
            "submit_end",
            serde_json::json!({"id":id,"result":format!("{r:?}")}),
        );
        r.unwrap();
    }
    fn finish(&self, name: &str, ids: &[u64]) -> Vec<u64> {
        let all = self.seen.lock().unwrap().clone();
        let ordered = all
            .iter()
            .filter(|(id, _)| ids.contains(id))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let report = serde_json::json!({"writer_sender":self.writer.sender_arc().as_ref(),"peer_sender":self.peer.sender_arc().as_ref(),"case":name,"schema_mode":format!("{:?}",reliable_mode(self.ty)),"expected_original_ids":ids,"all_peer_callbacks":all,"observed_original_ids":ordered,"queue_end":queue(&self.writer),"lost":self.audit.lost.load(Ordering::Relaxed),"events":*self.audit.events.lock().unwrap(),"wire":*self.wire.lock().unwrap()});
        if let Some(root) = std::env::var_os("SEDSNET_ORDER_CAUSAL_DIR") {
            use std::io::Write;
            let path = std::path::PathBuf::from(root).join(format!("{name}.json"));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            serde_json::to_writer(&mut file, &report).unwrap();
            file.write_all(b"\n").unwrap();
        }
        println!(
            "ORDER_CAUSAL case={name} expected={ids:?} actual={ordered:?} lost={}",
            self.audit.lost.load(Ordering::Relaxed)
        );
        ordered
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let (Some(root), Ok(events)) = (
                std::env::var_os("SEDSNET_ORDER_CAUSAL_DIR"),
                self.audit.events.try_lock(),
            )
        {
                let name = std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .replace(':', "_");
                let path = std::path::PathBuf::from(root).join(format!("panic-{name}.json"));
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    let _ = serde_json::to_writer(
                        &mut f,
                        &serde_json::json!({"panic_trace_only":true,"lost":self.audit.lost.load(Ordering::Relaxed),"events":*events}),
                    );
                }
        }
        *ACTIVE.get_or_init(|| Mutex::new(None)).lock().unwrap() = None;
    }
}
#[test]
fn healthy_original_order_control() {
    let mut f = Fixture::new();
    let mut ids = Vec::new();
    for v in [3, 2, 1, 0] {
        let p = f.packet(v);
        ids.push(p.packet_id());
        f.submit(p);
    }
    f.drain();
    let got = f.finish("healthy", &ids);
    assert_eq!(got, ids);
}
#[test]
fn direct_after_tail_discovery_collision_original_order() {
    run_direct_collision(Fixture::new(),"direct_collision",false);
}
fn run_direct_collision(mut f:Fixture,case:&str,unsequenced:bool) {
    let a = f.packet(3);
    let mut ids = vec![a.packet_id()];
    let (reached_tx, reached) = mpsc::channel();
    let (resume, resume_rx) = mpsc::channel();
    *f.audit.pause.lock().unwrap() = Some(Pause {
        id: a.packet_id(),
        reached: reached_tx,
        resume: resume_rx,
    });
    let r = f.writer.clone();
    let audit = f.audit.clone();
    let producer = Worker::spawn(move || {
        let id = a.packet_id();
        audit.event("submit_begin", serde_json::json!({"id":id}));
        let result = r.set_network_variable(a);
        audit.event(
            "submit_end",
            serde_json::json!({"id":id,"result":format!("{result:?}")}),
        );
        result
    });
    reached
        .recv_timeout(Duration::from_secs(3))
        .expect("original reached post-tail barrier");
    f.armed.store(true, Ordering::Release);
    let r = f.writer.clone();
    let discovery = Worker::spawn(move || {
        r.announce_discovery()?;
        r.process_tx_queue_with_timeout(1)
    });
    f.entered
        .recv_timeout(Duration::from_secs(3))
        .expect("real discovery owns side gate");
    resume.send(()).unwrap();
    let result = producer.join().unwrap();
    observe(
        &f.writer,
        "A_return_before_discovery_release",
        || serde_json::json!({"result":format!("{result:?}")}),
    );
    let release_clock = f.clock.fetch_add(1, Ordering::Relaxed) + 1;
    f.audit.event("release_clock_plus_one", serde_json::json!({"now":release_clock,"reason":"ordinary public TX worker1ms budget; no original UTC mutation"}));
    f.release.send(()).unwrap();
    let discovery_result = discovery.join().unwrap();
    result.unwrap();
    discovery_result.unwrap();
    for v in [2, 1, 0] {
        let p = f.packet(v);
        ids.push(p.packet_id());
        f.submit(p);
    }
    f.drain();
    let got = f.finish(case, &ids);
    if unsequenced {
        let rows=f.wire.lock().unwrap();let app=rows.iter().filter(|r|ids.iter().any(|id|r["id"].as_u64()==Some(*id))).collect::<Vec<_>>();
        assert_eq!(app.len(),4);
        assert!(app.iter().all(|r|r["reliable"]["flags"].as_u64()==Some(128)&&r["reliable"]["seq"].as_u64()==Some(0)),"actual multi-announcer default must negotiate unsequenced");
        assert_eq!(f.third_seen.lock().unwrap().iter().filter(|(id,_)|ids.contains(id)).map(|(id,_)|*id).collect::<Vec<_>>(),ids);
    }
    assert_eq!(
        got, ids,
        "actual ordered originals must not cross a deferred direct original"
    );
}
#[test]
fn discovery_active_before_admission_preserves_original_owner_control() {
    let mut f = Fixture::new();
    f.armed.store(true, Ordering::Release);
    let r = f.writer.clone();
    let discovery = Worker::spawn(move || {
        r.announce_discovery()?;
        r.process_tx_queue_with_timeout(1)
    });
    f.entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let p = f.packet(3);
    let mut ids = vec![p.packet_id()];
    f.submit(p);
    observe(
        &f.writer,
        "initial_busy_queued_owner",
        || serde_json::Value::Null,
    );
    let release_clock = f.clock.fetch_add(1, Ordering::Relaxed) + 1;
    f.audit.event("release_clock_plus_one", serde_json::json!({"now":release_clock,"reason":"ordinary public TX worker1ms budget; no original UTC mutation"}));
    f.release.send(()).unwrap();
    discovery.join().unwrap().unwrap();
    for v in [2, 1, 0] {
        let p = f.packet(v);
        ids.push(p.packet_id());
        f.submit(p);
    }
    f.drain();
    let got = f.finish("initial_busy", &ids);
    assert_eq!(got, ids);
}

#[test]
fn shared_default_sender_observation_control() {
    let mut f = Fixture::with_shared_sender(true);
    let mut ids = Vec::new();
    for value in [3, 2, 1, 0] {
        let p = f.packet(value);
        ids.push(p.packet_id());
        f.submit(p);
    }
    f.drain();
    let got = f.finish("shared_default_sender", &ids);
    assert_eq!(
        got, ids,
        "identity observation never weakens original order"
    );
}

#[test]
fn three_distinct_default_shared_side_unsequenced_collision() {
    let f=Fixture::with_peer_layout(false,true);
    assert_eq!(f.writer.sender_arc().as_ref(),"audit-writer");
    assert_eq!(f.peer.sender_arc().as_ref(),"audit-peer");
    assert_eq!(f.third.as_ref().unwrap().sender_arc().as_ref(),"audit-third");
    {let st=f.writer.state.lock();assert!(f.writer.side_has_multiple_announcers_locked(&st,0,f.clock.load(Ordering::Relaxed)));assert!(!st.source_route_modes.contains_key(&None),"actual default routing profile");}
    run_direct_collision(f,"three_default_collision",true);
}

#[test]
fn three_distinct_rfd_shared_side_unsequenced_collision() {
    let f=Fixture::with_bus_profile(false,true,false);
    assert_eq!(f.writer.sender_arc().as_ref(),"audit-writer");
    assert_eq!(f.peer.sender_arc().as_ref(),"audit-peer");
    assert_eq!(f.third.as_ref().unwrap().sender_arc().as_ref(),"audit-third");
    {let st=f.writer.state.lock();assert!(f.writer.side_has_multiple_announcers_locked(&st,0,f.clock.load(Ordering::Relaxed)));assert!(!st.source_route_modes.contains_key(&None));assert!(!st.sides[0].as_ref().unwrap().opts.reliable_enabled,"public RFD shared-bus configuration");}
    run_direct_collision(f,"three_rfd_collision",true);
}

// Focused metadata controls complement the real two-router collision above.
// The original claim uses the actual queue admission and N-conversion helpers;
// no application callback/delivery proof is inferred from these helper cases.
fn two_claimed_siblings(f: &mut Fixture, since: Option<u64>) -> (TxClaim, TxClaim) {
    let second = f.writer.add_side_packet("anchor-second", |_packet: &Packet| Ok(()));
    let data = RouterItem::Packet(f.packet(3));
    let claim = {
        let mut st = f.writer.state.lock();
        assert_eq!(st.transmit_queue.len(), 0);
        let token = st.ordered_claim_seq.wrapping_add(1).max(1);
        st.ordered_claim_seq = token;
        st.push_transmit(TxQueued { disposable: 0, item: RouterTxItem::Broadcast(data.clone()),
            ignore_local: true, priority: 254, delivery_state: QueuedDelivery::ClaimedOrdered,
            accepted_type: f.ty.as_u32(), deferred_since_ms: u64::from(token), retry_after_ms: 0 }).unwrap();
        TxClaim { token, ordered: true, side_retry: false }
    };
    let work = f.writer.admit_local_ordered_group(&data, &[0, second], claim, since).unwrap().unwrap();
    assert_eq!(work.len(), 2);
    let st = f.writer.state.lock();
    assert_eq!(st.transmit_queue.len(), 2, "N rows, not N+1");
    for (_, owner) in &work {
        let row = st.transmit_queue.get(st.claim_index(owner.token).unwrap()).unwrap();
        assert_eq!(RouterInner::local_side_anchor(row), since);
    }
    let other = work[1].1;
    assert_eq!(work[0].1.token, claim.token);
    assert_ne!(claim.token, other.token);
    (claim, other)
}
fn group_anchors(f: &Fixture) -> Vec<Option<u64>> {
    let st = f.writer.state.lock();
    st.transmit_queue.iter().filter(|row| row.accepted_type == f.ty.as_u32()
        && RouterInner::local_ordered_side(row)).map(RouterInner::local_side_anchor).collect()
}
#[test]
fn shared_known_anchor_zero_and_token_remain_exact() {
    let mut f = Fixture::new();
    for selector in [0, 1, 2] {
        let token = f.writer.state.lock().ordered_claim_seq.wrapping_add(1).max(1);
        let anchor = match selector { 0 => 0, 1 => f.clock.load(Ordering::Relaxed) - 2, _ => u64::from(token) };
        let (first, other) = two_claimed_siblings(&mut f, Some(anchor));
        assert_eq!(group_anchors(&f), vec![Some(anchor), Some(anchor)]);
        {
            let st = f.writer.state.lock();
            assert!(st.claim_index(first.token).is_some());
            assert!(st.claim_index(other.token).is_some());
        }
        // Stale stack None must not renew the actual retained anchor.
        let stale = DispatchContext::default();
        f.clock.fetch_add(7, Ordering::Relaxed);
        f.writer.finish_local_ordered_claim(first, &stale, Err(TelemetryError::Io("side tx busy"))).unwrap();
        f.clock.fetch_add(9, Ordering::Relaxed);
        f.writer.finish_local_ordered_claim(other, &stale, Err(TelemetryError::Io("side tx busy"))).unwrap();
        assert_eq!(group_anchors(&f), vec![Some(anchor), Some(anchor)]);
        f.writer.state.lock().cancel_accepted_type(f.ty.as_u32());
    }
}
#[test]
fn concurrently_claimed_late_refusal_keeps_first_anchor() {
    let mut f = Fixture::new();
    let (first, other) = two_claimed_siblings(&mut f, None);
    assert_eq!(group_anchors(&f), vec![None, None]);
    let first_time = f.clock.load(Ordering::Relaxed);
    let (done, waited) = mpsc::channel();
    let r = f.writer.clone();
    let a = Worker::spawn(move || {
        r.finish_local_ordered_claim(first, &DispatchContext::default(), Err(TelemetryError::Io("side tx busy")))?;
        done.send(()).unwrap(); Ok(())
    });
    let r = f.writer.clone(); let clock = f.clock.clone();
    let b = Worker::spawn(move || {
        waited.recv_timeout(Duration::from_secs(3)).unwrap();
        clock.fetch_add(500, Ordering::Relaxed);
        r.finish_local_ordered_claim(other, &DispatchContext::default(), Err(TelemetryError::Io("side tx busy")))
    });
    a.join().unwrap().unwrap(); b.join().unwrap().unwrap();
    assert_eq!(group_anchors(&f), vec![Some(first_time), Some(first_time)]);
    let lifetime = runtime_reliable_retransmit_ms().saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
    f.clock.store(first_time + lifetime, Ordering::Relaxed);
    let before = f.wire.lock().unwrap().len();
    let error = f.writer.dispatch_tx_queue_with_timeout(1).unwrap_err();
    assert!(matches!(error, TelemetryError::HandlerError("accepted reliable delivery expired before dispatch")));
    assert_eq!(f.wire.lock().unwrap().len(), before, "expired sibling cannot emit");
    assert!(group_anchors(&f).is_empty());
}
#[test]
fn slow_first_success_does_not_start_group_ttl() {
    let mut f = Fixture::new();
    let (first, other) = two_claimed_siblings(&mut f, None);
    let lifetime = runtime_reliable_retransmit_ms().saturating_mul(u64::from(runtime_reliable_max_retries()) + 1);
    f.clock.fetch_add(lifetime + 100, Ordering::Relaxed);
    let completed = DispatchContext { admitted: true, ..Default::default() };
    f.writer.finish_local_ordered_claim(first, &completed, Ok(())).unwrap();
    assert_eq!(group_anchors(&f), vec![None], "successful side is not a refusal");
    let first_refusal = f.clock.load(Ordering::Relaxed);
    f.writer.finish_local_ordered_claim(other, &DispatchContext::default(), Err(TelemetryError::Io("side tx busy"))).unwrap();
    assert_eq!(group_anchors(&f), vec![Some(first_refusal)]);
}
#[test]
fn packed_local_origin_is_numeric_crc_checked_and_foreign_inert() {
    let mut f = Fixture::new();
    let p = f.packet(3);
    let wire = wire_format::pack_packet(&p);
    let frame = wire_format::peek_routing_frame_info(&wire).unwrap();
    assert_eq!(frame.envelope.source_address, sender_address_u32(f.writer.sender_arc().as_ref()));
    assert!(f.writer.local_ordered_candidate(&RouterItem::Packed(crate::shared_bytes::convert(wire.clone())), f.ty).unwrap());
    let alias = format!("@addr:{}", frame.envelope.source_address);
    assert_eq!(sender_address_u32(&alias), sender_address_u32(p.sender()));
    let foreign = Packet::new(f.ty, &[f.ep], "foreign-audit", p.timestamp(), Arc::<[u8]>::from([3])).unwrap();
    assert!(!f.writer.local_ordered_candidate(&RouterItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(&foreign))), f.ty).unwrap());
    let mut corrupt = wire.to_vec(); *corrupt.last_mut().unwrap() ^= 1;
    assert!(f.writer.local_ordered_candidate(&RouterItem::Packed(crate::shared_bytes::convert(Arc::<[u8]>::from(corrupt))), f.ty).is_err());
    // Public packed owner path and actual second-router delivery, not predicate alone.
    let id = p.packet_id(); f.writer.tx_packed(wire).unwrap(); f.drain();
    assert_eq!(f.finish("packed_numeric", &[id]), vec![id]);
}
#[test]
fn queued_two_sides_one_busy_success_never_replays() {
    let mut f = Fixture::new();
    let (second_peer, got, second_ep) = attach_second_actual_peer(&mut f);
    let ty = f.ty;
    f.armed.store(true, Ordering::Release);
    let r = f.writer.clone();
    let discovery = Worker::spawn(move || { r.announce_discovery()?; r.process_tx_queue_with_timeout(1) });
    f.entered.recv_timeout(Duration::from_secs(3)).unwrap();
    let mut ids = Vec::new();
    for v in [3,2,1,0] { let p=multi_packet(&mut f, second_ep, v); assert_two_selected_no_managed_cohort(&f,&p); ids.push(p.packet_id()); f.submit(p); }
    f.writer.dispatch_tx_queue_with_timeout(1).unwrap();
    second_peer.process_all_queues().unwrap();
    assert_eq!(*got.lock().unwrap(), vec![ids[0]]);
    assert!(f.seen.lock().unwrap().is_empty());
    {
        let st=f.writer.state.lock();
        assert_eq!(st.transmit_queue.iter().filter(|q| q.accepted_type==ty.as_u32() && RouterInner::local_ordered_side(q)).count(),1);
        assert_eq!(st.transmit_queue.iter().filter(|q| q.accepted_type==ty.as_u32() && q.delivery_state==QueuedDelivery::OrderedTail).count(),3);
    }
    f.writer.dispatch_tx_queue_with_timeout(1).unwrap();
    second_peer.process_all_queues().unwrap();
    assert_eq!(*got.lock().unwrap(), vec![ids[0]], "successful side is not replayed");
    f.clock.fetch_add(1,Ordering::Relaxed); f.release.send(()).unwrap(); discovery.join().unwrap().unwrap();
    for _ in 0..8 { f.writer.process_all_queues().unwrap();f.peer.process_all_queues().unwrap();second_peer.process_all_queues().unwrap();f.clock.fetch_add(1,Ordering::Relaxed); }
    assert_eq!(*got.lock().unwrap(), ids);
    assert_eq!(f.finish("two_sides_one_busy",&ids),ids);
}

// Establish two real, distinct endpoint interests. A bare transport callback is
// not a discovered application destination and must not be assumed routable.
fn attach_second_actual_peer(f: &mut Fixture) -> (Arc<Router>, Arc<Mutex<Vec<u64>>>, DataEndpoint) {
    let ep = crate::config::register_endpoint("ORDER_AUDIT_SECOND_ENDPOINT", false).unwrap();
    let ty = crate::config::register_data_type_with_description("ORDER_AUDIT_MULTI_VALUE", "Generic two-side Ordered control",
        crate::MessageElement::Static(1,crate::MessageDataType::UInt8,crate::MessageClass::Data),
        &[f.ep,ep],crate::ReliableMode::Ordered,16).unwrap();
    f.ty=ty; f.writer.enable_managed_variable(ty).unwrap();
    // Explicit supported Fanout test profile; production default remains adaptive.
    f.writer.set_source_route_mode(None,crate::RouteSelectionMode::Fanout).unwrap();
    let got=Arc::new(Mutex::new(Vec::new())); let observed=got.clone(); let clock=f.clock.clone();
    let second=Arc::new(Router::new_with_clock(RouterConfig::new([EndpointHandler::new_packet_handler(ep, move |p:&Packet| {
        observed.lock().unwrap().push(p.packet_id()); Ok(())
    })]).with_sender("audit-second-peer"),Box::new(move||clock.load(Ordering::Relaxed))));
    let onward=Arc::new(Mutex::new(None::<(Weak<Router>,RouterSideId)>));
    let destination=onward.clone();
    let side=f.writer.add_side_packed_with_options("second-actual-side",move|bytes|{
        let(r,s)=destination.lock().unwrap().clone().unwrap();r.upgrade().unwrap().rx_packed_from_side(bytes,s)
    },RouterSideOptions{reliable_enabled:true,link_local_enabled:true,..Default::default()});
    let writer=Arc::downgrade(&f.writer);
    let back=second.add_side_packed_with_options("writer-actual-side",move|bytes|writer.upgrade().unwrap().rx_packed_from_side(bytes,side),
        RouterSideOptions{reliable_enabled:true,link_local_enabled:true,..Default::default()});
    *onward.lock().unwrap()=Some((Arc::downgrade(&second),back));
    f.writer.announce_discovery().unwrap();second.announce_discovery().unwrap();
    for _ in 0..12 { f.writer.process_all_queues().unwrap();f.peer.process_all_queues().unwrap();second.process_all_queues().unwrap();f.clock.fetch_add(1,Ordering::Relaxed); }
    f.seen.lock().unwrap().clear();f.wire.lock().unwrap().clear();f.audit.events.lock().unwrap().clear();
    assert_eq!(f.audit.lost.load(Ordering::Relaxed),0,"bounded setup capture must not overflow");
    (second,got,ep)
}
fn multi_packet(f:&mut Fixture,second:DataEndpoint,value:u8)->Packet {
    f.nonce+=1;let now=f.clock.fetch_add(1,Ordering::Relaxed)+1;
    Packet::new(f.ty,&[f.ep,second],f.writer.sender_arc().as_ref(),now,Arc::<[u8]>::from([value])).unwrap().with_nonce(f.nonce)
}
#[test]
fn constrained_ring_group_refusal_has_no_output_or_hidden_reservation() {
    let mut f=Fixture::new();let(_second,got,ep)=attach_second_actual_peer(&mut f);
    let p=multi_packet(&mut f,ep,3);let ty=f.ty;
    assert_two_selected_no_managed_cohort(&f,&p);
    {
        let mut st=f.writer.state.lock();assert_eq!(st.transmit_queue.len(),0);
        // A deliberate fixed one-slot queue fixture after normal discovery.
        // Byte budget is unchanged; no fake routing, sender or reliable flags.
        st.transmit_queue=BoundedDeque::new(st.memory.max_queue_budget,size_of::<TxQueued>(),1.0);
        assert_eq!(st.transmit_queue.capacity(),1);
    }
    #[cfg(feature="compression")]
    let reservation_before=f.writer.state.lock().codec_reserved_bytes;
    f.writer.tx_item(RouterTxItem::Broadcast(RouterItem::Packet(p))).unwrap();
    assert!(got.lock().unwrap().is_empty());assert!(f.seen.lock().unwrap().is_empty());
    let anchor={let st=f.writer.state.lock();let rows=st.transmit_queue.iter().filter(|r|r.accepted_type==ty.as_u32()).collect::<Vec<_>>();
        assert_eq!(rows.len(),1);assert_eq!(rows[0].delivery_state,QueuedDelivery::DeferredOrdered);assert!(rows[0].ignore_local);
        assert!(!RouterInner::local_ordered_side(rows[0]));rows[0].deferred_since_ms};
    #[cfg(feature="compression")]
    assert_eq!(f.writer.state.lock().codec_reserved_bytes,reservation_before);
    let lifetime=runtime_reliable_retransmit_ms().saturating_mul(u64::from(runtime_reliable_max_retries())+1);
    f.clock.store(anchor+lifetime,Ordering::Relaxed);
    assert!(matches!(f.writer.dispatch_tx_queue_with_timeout(1),Err(TelemetryError::HandlerError("accepted reliable delivery expired before dispatch"))));
    assert!(got.lock().unwrap().is_empty());assert!(f.seen.lock().unwrap().is_empty());
    assert!(!f.writer.state.lock().transmit_queue.iter().any(|r|r.accepted_type==ty.as_u32()));
}

fn assert_two_selected_no_managed_cohort(f:&Fixture,p:&Packet) {
    let data=RouterItem::Packet(p.clone());
    let RemoteSidePlan::Target(sides)=f.writer.remote_side_plan(&data,None).unwrap();
    assert_eq!(sides.len(),2,"fixture must create two real selected application sides");
    let pending={let st=f.writer.state.lock();f.writer.expected_end_to_end_destinations_locked(&st,&data,None,false,false).unwrap()};
    assert!(pending.is_empty(),"this control covers local-side ownership, not E2E transfer");
}

fn capture_shared_setup(f:&Fixture,stage:&str) {
    let Some(root)=std::env::var_os("SEDSNET_ORDER_CAUSAL_DIR")else{return;};
    let node=|r:&Router|{
        let sender=r.sender_arc();let st=r.state.lock();
        serde_json::json!({"sender":sender.as_ref(),"address":st.local_address.address,"requested":st.local_address.requested_address,"mode":format!("{:?}",st.local_address.mode),"owner_hash":st.local_address.owner_hash,"budget":st.memory.max_queue_budget,"queue_bytes":st.shared_queue_bytes_used(),
            "routes":st.discovery_routes.iter().map(|(side,route)|serde_json::json!({"side":side,"last_seen":route.last_seen_ms,"announcers":route.announcers.iter().map(|(name,a)|serde_json::json!({"name":name,"last_seen":a.last_seen_ms})).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "rx":st.reliable_rx.iter().map(|((side,ty),rx)|serde_json::json!({"side":side,"type":ty,"expected":rx.expected_seq,"buffered":rx.buffered.keys().copied().collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "tx":st.reliable_tx.iter().map(|((side,ty),tx)|serde_json::json!({"side":side,"type":ty,"next":tx.next_seq,"sent":tx.sent.keys().copied().collect::<Vec<_>>()})).collect::<Vec<_>>()})
    };
    let writer=node(&f.writer);let peer=node(&f.peer);let third=node(f.third.as_ref().unwrap());
    let events=f.audit.events.lock().unwrap().clone();let wire=f.wire.lock().unwrap().clone();
    let report=serde_json::json!({"stage":stage,"clock":f.clock.load(Ordering::Relaxed),"lost":f.audit.lost.load(Ordering::Relaxed),"writer":writer,"peer":peer,"third":third,"events":events,"writer_wire":wire});
    let file=std::fs::OpenOptions::new().write(true).create_new(true).open(std::path::PathBuf::from(root).join(format!("shared-setup-{stage}.json"))).unwrap();
    serde_json::to_writer(file,&report).unwrap();
}

struct ExpiryPause {
    router:usize,token:u32,reached:mpsc::Sender<()>,resume:mpsc::Receiver<()>,
}
static EXPIRY_PAUSE:OnceLock<Mutex<Option<ExpiryPause>>>=OnceLock::new();
pub(super) fn before_local_expiry(r:&Router,claim:TxClaim) {
    let pause={let mut slot=EXPIRY_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap();
        if slot.as_ref().is_some_and(|p|p.router==r as *const _ as usize&&p.token==claim.token){slot.take()}else{None}};
    if let Some(p)=pause {
        assert!(r.state.try_lock().is_some(),"expiry pause is outside Core");
        p.reached.send(()).unwrap();p.resume.recv_timeout(Duration::from_secs(3)).expect("bounded expiry owner barrier");
    }
}
fn write_case_artifact(name:&str,value:&serde_json::Value) {
    if let Some(root)=std::env::var_os("SEDSNET_ORDER_CAUSAL_DIR") {
        let file=std::fs::OpenOptions::new().write(true).create_new(true).open(std::path::PathBuf::from(root).join(format!("{name}.json"))).unwrap();
        serde_json::to_writer(file,value).unwrap();
    }
}
#[test]
fn retired_local_expiry_cannot_cancel_fresh_same_type_owner() {
    let mut f=Fixture::new();let(first,old_claim)=two_claimed_siblings(&mut f,None);
    let anchor=f.clock.load(Ordering::Relaxed);
    f.writer.finish_local_ordered_claim(first,&DispatchContext::default(),Err(TelemetryError::Io("side tx busy"))).unwrap();
    let lifetime=runtime_reliable_retransmit_ms().saturating_mul(u64::from(runtime_reliable_max_retries())+1);
    f.clock.store(anchor+lifetime,Ordering::Relaxed);
    let (side,data)={let st=f.writer.state.lock();let row=st.transmit_queue.get(st.claim_index(old_claim.token).unwrap()).unwrap();
        let RouterTxItem::ToSide{dst,data,..}=&row.item else{panic!("actual local side claim")};(*dst,data.clone())};
    let(reached_tx,reached)=mpsc::channel();let(resume,resume_rx)=mpsc::channel();
    *EXPIRY_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap()=Some(ExpiryPause{router:Arc::as_ptr(&f.writer)as usize,token:old_claim.token,reached:reached_tx,resume:resume_rx});
    let r=f.writer.clone();let old=Worker::spawn(move||{
        let mut context=DispatchContext{claim:Some(old_claim),..Default::default()};
        r.send_local_ordered_side(side,data,&mut context,true)
    });
    reached.recv_timeout(Duration::from_secs(3)).expect("old owner reached actual expiry outside Core");
    // These are the real public cancellation and submission operations.
    f.writer.clear_tx_queue();
    let fresh=f.packet(2);let tail=f.packet(1);let expected=vec![fresh.packet_id(),tail.packet_id()];
    f.writer.tx_queue(fresh).unwrap();f.writer.tx_queue(tail).unwrap();
    let before=queue(&f.writer);write_case_artifact("stale-expiry-before",&serde_json::json!({"expected":expected,"anchor":anchor,"old_claim":old_claim.token,"queue":before}));
    resume.send(()).unwrap();let old_result=old.join().unwrap();assert!(old_result.is_err(),"expired or retired old work cannot report success");
    let after=queue(&f.writer);write_case_artifact("stale-expiry-after",&serde_json::json!({"expected":expected,"old_result":format!("{old_result:?}"),"queue":after}));
    let actual=after.iter().filter(|row|row["accepted_type"].as_u64()==Some(u64::from(f.ty.as_u32())))
        .filter_map(|row|row["item"]["data"]["id"].as_u64()).collect::<Vec<_>>();
    assert_eq!(actual,expected,"retired old expiry must not cancel a newly admitted same-type head/tail");
    assert!(f.wire.lock().unwrap().iter().all(|row|row["type"].as_u64()!=Some(u64::from(f.ty.as_u32()))),"retired work cannot emit");
}

static CHILD_DISPATCH_PAUSE:OnceLock<Mutex<Option<ExpiryPause>>>=OnceLock::new();
pub(super) fn before_local_child_dispatch(r:&Router,claim:TxClaim) {
    let pause={let mut slot=CHILD_DISPATCH_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap();
        if slot.as_ref().is_some_and(|p|p.router==r as *const _ as usize&&p.token==claim.token){slot.take()}else{None}};
    if let Some(p)=pause {assert!(r.state.try_lock().is_some(),"child dispatch pause outside Core");p.reached.send(()).unwrap();p.resume.recv_timeout(Duration::from_secs(3)).expect("bounded child dispatch barrier");}
}
#[test]
fn retired_known_local_work_never_falls_back_to_ordinary_send() {
    let mut f=Fixture::new();let(old_claim,_other)=two_claimed_siblings(&mut f,None);
    let work={let st=f.writer.state.lock();let row=st.transmit_queue.get(st.claim_index(old_claim.token).unwrap()).unwrap().clone();
        assert!(RouterInner::local_ordered_side(&row));TxWork{queued:row,claim:Some(old_claim),owed_turn:false,
            #[cfg(feature="latest-value-egress")]service:EgressService::default()}};
    let(reached_tx,reached)=mpsc::channel();let(resume,resume_rx)=mpsc::channel();
    *CHILD_DISPATCH_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap()=Some(ExpiryPause{router:Arc::as_ptr(&f.writer)as usize,token:old_claim.token,reached:reached_tx,resume:resume_rx});
    let r=f.writer.clone();let worker=Worker::spawn(move||r.dispatch_queued_item(work));
    reached.recv_timeout(Duration::from_secs(3)).expect("actual known child paused before generic dispatch");
    f.writer.clear_tx_queue();let fresh=f.packet(2);let tail=f.packet(1);let expected=vec![fresh.packet_id(),tail.packet_id()];
    f.writer.tx_queue(fresh).unwrap();f.writer.tx_queue(tail).unwrap();
    write_case_artifact("retired-dispatch-before",&serde_json::json!({"expected":expected,"queue":queue(&f.writer)}));
    resume.send(()).unwrap();let result=worker.join().unwrap();
    let after=queue(&f.writer);let wire=f.wire.lock().unwrap().clone();
    write_case_artifact("retired-dispatch-after",&serde_json::json!({"expected":expected,"old_result":format!("{result:?}"),"queue":after,"wire":wire}));
    assert!(wire.iter().all(|row|row["type"].as_u64()!=Some(u64::from(f.ty.as_u32()))),"retired known local work cannot become ordinary side output");
    assert!(result.is_err(),"retired local work returns old-owner error");
    let ids=after.iter().filter(|row|row["accepted_type"].as_u64()==Some(u64::from(f.ty.as_u32())))
        .filter_map(|row|row["item"]["data"]["id"].as_u64()).collect::<Vec<_>>();
    assert_eq!(ids,expected,"fresh same-type head/tail must survive retired old work");
}

#[cfg(feature="compression")]
static CODEC_PROBE_ROUTER:OnceLock<Mutex<Weak<Router>>>=OnceLock::new();
#[cfg(feature="compression")]
static CODEC_PROBE_CALLS:AtomicU64=AtomicU64::new(0);
#[cfg(feature="compression")]
static CODEC_PROBE_HELD:AtomicU64=AtomicU64::new(0);
#[cfg(feature="compression")]
static CODEC_PROBE_REFUSE:AtomicBool=AtomicBool::new(false);
#[cfg(feature="compression")]
extern "C" fn codec_owner_probe(additional:usize,_largest:usize)->bool {
    if additional>=2000 {
        let router=CODEC_PROBE_ROUTER.get_or_init(||Mutex::new(Weak::new())).lock().unwrap().upgrade();
        if let Some(router)=router {
            CODEC_PROBE_CALLS.fetch_add(1,Ordering::SeqCst);
            if router.state.try_lock().is_none(){CODEC_PROBE_HELD.fetch_add(1,Ordering::SeqCst);}
            return !CODEC_PROBE_REFUSE.load(Ordering::SeqCst);
        }
    }
    true
}
#[cfg(feature="compression")]
struct CodecProbeReset;
#[cfg(feature="compression")]
impl Drop for CodecProbeReset {fn drop(&mut self){crate::memory_admission::set_probe(None);*CODEC_PROBE_ROUTER.get().unwrap().lock().unwrap()=Weak::new();}}
#[cfg(feature="compression")]
#[test]
fn compressed_direct_local_stages_plaintext_outside_core() {
    let mut f=Fixture::new();
    let ty=crate::config::register_data_type_with_description("ORDER_AUDIT_COMPRESSED_VALUE","Actual codec retained local original",
        crate::MessageElement::Dynamic(crate::MessageDataType::Binary,crate::MessageClass::Data),&[f.ep],crate::ReliableMode::Ordered,16).unwrap();
    f.ty=ty;f.writer.enable_managed_variable(ty).unwrap();
    let packet=Packet::new(ty,&[f.ep],f.writer.sender_arc().as_ref(),f.clock.load(Ordering::Relaxed),Arc::<[u8]>::from(vec![b'Q';1024])).unwrap().with_nonce(999);
    let id=packet.packet_id();
    // Actual public standalone packing already applies beneficial compression.
    // Retain its real bytes, no header/flag fabrication or second compression.
    let compressed=wire_format::pack_packet(&packet);
    assert_eq!(compressed[0]&0x11,1);assert_eq!(wire_format::packet_id_from_wire(&compressed).unwrap(),id);
    *CODEC_PROBE_ROUTER.get_or_init(||Mutex::new(Weak::new())).lock().unwrap()=Arc::downgrade(&f.writer);
    CODEC_PROBE_CALLS.store(0,Ordering::SeqCst);CODEC_PROBE_HELD.store(0,Ordering::SeqCst);
    let _reset=CodecProbeReset;crate::memory_admission::set_probe(Some(codec_owner_probe));
    CODEC_PROBE_REFUSE.store(true,Ordering::SeqCst);
    assert!(f.writer.tx_packed(compressed.clone()).is_err(),"required plaintext staging refuses before packet admission");
    assert!(!queue(&f.writer).iter().any(|row|row["accepted_type"].as_u64()==Some(u64::from(ty.as_u32()))));
    assert!(f.wire.lock().unwrap().iter().all(|row|row["id"].as_u64()!=Some(id)));
    CODEC_PROBE_REFUSE.store(false,Ordering::SeqCst);CODEC_PROBE_CALLS.store(0,Ordering::SeqCst);
    f.writer.tx_packed(compressed).unwrap();f.drain();
    assert!(CODEC_PROBE_CALLS.load(Ordering::SeqCst)>0,"actual large codec work observed");
    assert_eq!(CODEC_PROBE_HELD.load(Ordering::SeqCst),0,"observed codec scratch admission must not run under writer Core");
    assert_eq!(f.finish("compressed_local",&[id]),vec![id]);
}
#[test]
fn inactive_trace_never_constructs_metadata_value() {
    let _f=Fixture::new();let other=Router::new(RouterConfig::new([]).with_sender("inactive-observer"));
    let evaluated=AtomicBool::new(false);
    observe(&other,"must_not_construct",||{evaluated.store(true,Ordering::SeqCst);serde_json::json!({"inactive":true})});
    assert!(!evaluated.load(Ordering::SeqCst));
}

#[test]
fn direct_two_selected_sides_are_attempted_before_return() {
    let mut f=Fixture::new();
    let(second,got,ep)=attach_second_actual_peer(&mut f);
    let p=multi_packet(&mut f,ep,3);assert_two_selected_no_managed_cohort(&f,&p);
    let id=p.packet_id();f.writer.tx(p).unwrap();
    // Only receiver service; no sender queue pump may complete the API contract.
    f.peer.process_all_queues().unwrap();second.process_all_queues().unwrap();
    assert_eq!(*got.lock().unwrap(),vec![id]);assert_eq!(*f.seen.lock().unwrap(),vec![(id,3)]);
    assert!(!f.writer.state.lock().transmit_queue.iter().any(|q|q.accepted_type==f.ty.as_u32()));
}
#[test]
fn direct_busy_first_still_attempts_second_before_return() {
    let mut f=Fixture::new();let(second,got,ep)=attach_second_actual_peer(&mut f);
    let p=multi_packet(&mut f,ep,3);assert_two_selected_no_managed_cohort(&f,&p);let id=p.packet_id();
    let(reached_tx,reached)=mpsc::channel();let(resume,resume_rx)=mpsc::channel();
    *f.audit.pause.lock().unwrap()=Some(Pause{id,reached:reached_tx,resume:resume_rx});
    let r=f.writer.clone();let producer=Worker::spawn(move||r.tx(p));
    reached.recv_timeout(Duration::from_secs(3)).expect("original direct owner admitted before Discovery");
    f.armed.store(true,Ordering::Release);let r=f.writer.clone();
    let discovery=Worker::spawn(move||{r.announce_discovery()?;r.process_tx_queue_with_timeout(1)});
    f.entered.recv_timeout(Duration::from_secs(3)).unwrap();resume.send(()).unwrap();
    producer.join().unwrap().unwrap();second.process_all_queues().unwrap();
    assert_eq!(*got.lock().unwrap(),vec![id]);assert!(f.seen.lock().unwrap().is_empty());
    assert_eq!(f.writer.state.lock().transmit_queue.iter().filter(|q|q.accepted_type==f.ty.as_u32()&&RouterInner::local_ordered_side(q)).count(),1);
    f.clock.fetch_add(1,Ordering::Relaxed);f.release.send(()).unwrap();discovery.join().unwrap().unwrap();
    for _ in 0..8 {f.writer.process_all_queues().unwrap();f.peer.process_all_queues().unwrap();second.process_all_queues().unwrap();f.clock.fetch_add(1,Ordering::Relaxed);}
    assert_eq!(*got.lock().unwrap(),vec![id]);assert_eq!(*f.seen.lock().unwrap(),vec![(id,3)]);
}
#[test]
fn sibling_token_exhaustion_preserves_original_before_conversion() {
    let mut f=Fixture::new();let side=f.writer.add_side_packet("token-second",|_:&Packet|Ok(()));
    let data=RouterItem::Packet(f.packet(3));let claim=TxClaim{token:u32::MAX,ordered:true,side_retry:false};
    {let mut st=f.writer.state.lock();st.ordered_claim_seq=u32::MAX;st.push_transmit(TxQueued{disposable:0,item:RouterTxItem::Broadcast(data.clone()),ignore_local:true,priority:16,delivery_state:QueuedDelivery::ClaimedOrdered,accepted_type:f.ty.as_u32(),deferred_since_ms:u64::from(claim.token),retry_after_ms:0}).unwrap();}
    let before=queue(&f.writer);
    assert!(matches!(f.writer.admit_local_ordered_group(&data,&[0,side],claim,None),Err(TelemetryError::HandlerError("local ordered claim tokens exhausted"))));
    assert_eq!(queue(&f.writer),before);assert_eq!(f.writer.state.lock().ordered_claim_seq,u32::MAX);
    assert!(f.wire.lock().unwrap().is_empty());
}

static GROUP_ACCOUNTING_PAUSE:OnceLock<Mutex<Option<ExpiryPause>>>=OnceLock::new();
pub(super) fn before_local_group_accounting(r:&Router,claim:TxClaim) {
    let pause={let mut slot=GROUP_ACCOUNTING_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap();
        if slot.as_ref().is_some_and(|p|p.router==r as *const _ as usize&&p.token==claim.token){slot.take()}else{None}};
    if let Some(p)=pause {assert!(r.state.try_lock().is_some(),"schema witness staging pause outside Core");p.reached.send(()).unwrap();p.resume.recv_timeout(Duration::from_secs(3)).expect("bounded accounting-stage pause");}
}
#[test]
fn ordinary_group_schema_contention_preserves_synchronous_admission() {
    let mut f=Fixture::new();let side=f.writer.add_side_packet("schema-witness-second",|_:&Packet|Ok(()));
    let data=RouterItem::Packet(f.packet(3));
    let claim={let mut st=f.writer.state.lock();let token=st.ordered_claim_seq.checked_add(1).unwrap();st.ordered_claim_seq=token;
        st.push_transmit(TxQueued{disposable:0,item:RouterTxItem::Broadcast(data.clone()),ignore_local:true,priority:16,delivery_state:QueuedDelivery::ClaimedOrdered,accepted_type:f.ty.as_u32(),deferred_since_ms:u64::from(token),retry_after_ms:0}).unwrap();
        TxClaim{token,ordered:true,side_retry:false}};
    let before=queue(&f.writer);
    let(reached_tx,reached)=mpsc::channel();let(resume,resume_rx)=mpsc::channel();let(result_tx,results)=mpsc::channel();
    *GROUP_ACCOUNTING_PAUSE.get_or_init(||Mutex::new(None)).lock().unwrap()=Some(ExpiryPause{router:Arc::as_ptr(&f.writer)as usize,token:claim.token,reached:reached_tx,resume:resume_rx});
    let r=f.writer.clone();let worker=Worker::spawn(move||{let result=r.admit_local_ordered_group(&data,&[0,side],claim,None);result_tx.send(result).unwrap();Ok(())});
    reached.recv_timeout(Duration::from_secs(3)).expect("actual staged original reached accounting boundary");
    let schema=crate::config::try_prepared_schema_guard().expect("staging released schema");
    resume.send(()).unwrap();
    // Timeout distinguishes legitimate waiting from immediate SchemaBusy refusal;
    // it is not a delivery timeout and does not enlarge any SDK deadline.
    let early=results.recv_timeout(Duration::from_millis(50));
    drop(schema);
    let (immediate,result)=match early {Ok(result)=>(true,result),Err(mpsc::RecvTimeoutError::Timeout)=>(false,results.recv_timeout(Duration::from_secs(3)).unwrap()),Err(error)=>panic!("accounting worker disconnected: {error}")};
    worker.join().unwrap().unwrap();
    let after=queue(&f.writer);
    write_case_artifact("ordinary-schema-held",&serde_json::json!({"immediate_before_schema_release":immediate,"result":format!("{:?}",result.as_ref().map(|work|work.as_ref().map(Vec::len))),"before":before,"after":after,"clock":f.clock.load(Ordering::Relaxed)}));
    if result.is_err() {assert_eq!(after,before,"schema contention must not partially convert or lose original");}
    assert!(result.is_ok(),"ordinary synchronous admission was spuriously refused by held schema: {:?}", result.as_ref().map(|work|work.as_ref().map(Vec::len)));
    assert!(!immediate,"actual held schema must be rechecked only after release");
    assert_eq!(result.unwrap().unwrap().len(),2);
}

struct CapacityCallbackProbe {
    router:usize, ty:DataType, refusing:Arc<AtomicBool>, attempts:Arc<Mutex<Vec<(u64,u64)>>>,
}
static CAPACITY_CALLBACK_PROBE:OnceLock<Mutex<Option<CapacityCallbackProbe>>>=OnceLock::new();
struct CapacityCallbackLease;
impl Drop for CapacityCallbackLease {
    fn drop(&mut self) { *CAPACITY_CALLBACK_PROBE.get_or_init(||Mutex::new(None)).lock().unwrap()=None; }
}
fn capacity_callback_probe(router:usize,packet:&Packet)->TelemetryResult<()> {
    let probe=CAPACITY_CALLBACK_PROBE.get_or_init(||Mutex::new(None)).lock().unwrap();
    if let Some(probe)=probe.as_ref()
        && probe.router==router && probe.ty==packet.data_type()
    {
        probe.attempts.lock().unwrap().push((packet.packet_id(),packet.timestamp()));
        if probe.refusing.load(Ordering::Acquire) {
            return Err(TelemetryError::Io("shared priority queue saturated"));
        }
    }
    Ok(())
}
#[test]
fn actual_side_capacity_pressure_retains_original_until_available() {
    // Existing public RFD shared-bus profile: real three-router Discovery,
    // reliable_enabled=false, natural unsequenced frames. No forced wire flags.
    let mut f=Fixture::with_bus_profile(false,true,false);
    let p=f.packet(3);let identity=(p.packet_id(),p.timestamp());
    let attempts=Arc::new(Mutex::new(Vec::new()));let refusing=Arc::new(AtomicBool::new(true));
    *CAPACITY_CALLBACK_PROBE.get_or_init(||Mutex::new(None)).lock().unwrap()=Some(CapacityCallbackProbe{
        router:Arc::as_ptr(&f.writer)as usize,ty:f.ty,refusing:refusing.clone(),attempts:attempts.clone()});
    let _lease=CapacityCallbackLease;
    let result=f.writer.tx(p);
    let after_first=queue(&f.writer);
    write_case_artifact("capacity-callback-first",&serde_json::json!({"identity":identity,"result":format!("{result:?}"),"attempts":*attempts.lock().unwrap(),"queue":after_first,"wire":*f.wire.lock().unwrap(),"clock":f.clock.load(Ordering::Relaxed)}));
    assert_eq!(*attempts.lock().unwrap(),vec![identity],"one actual public side callback refused");
    assert!(f.wire.lock().unwrap().is_empty(),"callback refusal retained no wire frame or diagnostic packet");
    assert!(result.is_ok(),"accepted original must survive transient capacity refusal: {result:?}");
    assert_eq!(after_first.len(),1);
    assert_eq!(after_first[0]["delivery"],"DeferredLocalOrderedSide");
    assert_eq!(after_first[0]["item"]["data"]["id"].as_u64(),Some(identity.0));
    assert_eq!(after_first[0]["item"]["data"]["utc"].as_u64(),Some(identity.1));
    let anchor=after_first[0]["since"].as_u64().unwrap();
    assert_eq!(anchor,f.clock.load(Ordering::Relaxed));
    assert_eq!(after_first[0]["retry_after"].as_u64(),Some(anchor+1));
    refusing.store(false,Ordering::Release);
    f.clock.fetch_add(1,Ordering::Relaxed);f.drain();
    let app=f.wire.lock().unwrap().iter().filter(|row|row["type"].as_u64()==Some(u64::from(f.ty.as_u32()))).cloned().collect::<Vec<_>>();
    assert_eq!(app.len(),1);assert_eq!(app[0]["id"].as_u64(),Some(identity.0));assert_eq!(app[0]["utc"].as_u64(),Some(identity.1));
    assert_eq!(*attempts.lock().unwrap(),vec![identity,identity],"retry retains immutable ID and original UTC");
    assert_eq!(*f.seen.lock().unwrap(),vec![(identity.0,3)]);assert_eq!(*f.third_seen.lock().unwrap(),vec![(identity.0,3)]);
    assert!(!f.wire.lock().unwrap().iter().any(|row|row["type"].as_u64()==Some(u64::from(DataType::TelemetryError.as_u32()))));
    assert!(!f.writer.state.lock().transmit_queue.iter().any(|row|row.accepted_type==f.ty.as_u32()));
    write_case_artifact("capacity-callback-complete",&serde_json::json!({"identity":identity,"anchor":anchor,"attempts":*attempts.lock().unwrap(),"wire":app,"queue":queue(&f.writer)}));
}
