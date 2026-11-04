//! Private bounded source-level witness; no physical-radio fidelity claim.
use super::*;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};
static CASE: Mutex<()> = Mutex::new(());
static ACK_OLD: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
const LIMIT: usize = 2048;
pub(super) fn observe_ack_old(
    router: &Router,
    side: RouterSideId,
    ty: DataType,
    source: u32,
    seq: u32,
    ack: u32,
) {
    let mut rows = ACK_OLD.lock().unwrap();
    if rows.len() < LIMIT {
        rows.push(serde_json::json!({"router":router as *const Router as usize,"side":side,"type":ty.as_u32(),"source":source,"seq":seq,"ack_old":ack}));
    }
}
struct Fixture {
    _case: std::sync::MutexGuard<'static, ()>,
    nodes: Vec<Arc<Router>>,
    clock: Arc<AtomicU64>,
    rows: Arc<Mutex<Vec<serde_json::Value>>>,
    seen: Vec<Arc<Mutex<Vec<u64>>>>,
    lost: Arc<AtomicU64>,
    drop_third_until: Arc<AtomicU64>,
    ep: DataEndpoint,
    ty: DataType,
    nonce: u16,
    capture_bytes: AtomicU64,
}
impl Fixture {
    fn new(count: usize, drop_until: u64) -> Self {
        let guard = CASE.lock().unwrap_or_else(|e| e.into_inner());
        ACK_OLD.lock().unwrap().clear();
        crate::tests::ensure_common_test_schema();
        let ep = crate::config::register_endpoint("BOOTSTRAP_AUDIT_EP", false).unwrap();
        let ty = crate::config::register_data_type_with_description(
            "BOOTSTRAP_AUDIT_VALUE",
            "Private ordered default side witness",
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
        let rows = Arc::new(Mutex::new(Vec::new()));
        let lost = Arc::new(AtomicU64::new(0));
        let drop_third_until = Arc::new(AtomicU64::new(drop_until));
        let mut nodes = Vec::new();
        let mut seen = Vec::new();
        for name in ["audit-writer", "audit-peer", "audit-third"]
            .into_iter()
            .take(count)
        {
            let got = Arc::new(Mutex::new(Vec::new()));
            seen.push(got.clone());
            let c = clock.clone();
            let cfg = if nodes.is_empty() {
                RouterConfig::new([])
            } else {
                RouterConfig::new([EndpointHandler::new_packet_handler(
                    ep,
                    move |p: &Packet| {
                        got.lock().unwrap().push(p.packet_id());
                        Ok(())
                    },
                )])
            };
            nodes.push(Arc::new(Router::new_with_clock(
                cfg.with_sender(name),
                Box::new(move || c.load(Ordering::Relaxed)),
            )));
        }
        let bus = Arc::new(Mutex::new(Vec::<(Weak<Router>, RouterSideId)>::new()));
        for (index, node) in nodes.iter().enumerate() {
            let b = bus.clone();
            let log = rows.clone();
            let loss = lost.clone();
            let until = drop_third_until.clone();
            let c = clock.clone();
            let side=node.add_side_packed_with_options("shared-default",move|bytes|{
                let info=crate::wire_format::peek_frame_info(bytes)?;let p=crate::wire_format::unpack_packet(bytes)?;
                let drop=index==2 && c.load(Ordering::Relaxed)<until.load(Ordering::Relaxed) && discovery::is_announcer_bootstrap_type(p.data_type());
                let raw=if bytes.len()<=2048 {Some(bytes.to_vec())}else{loss.fetch_add(1,Ordering::Relaxed);None};
                let mut destinations=Vec::new();
                let destinations_snapshot=b.lock().unwrap().clone();
                if !drop {for (dest,(weak,side)) in destinations_snapshot.into_iter().enumerate() {
                    if dest==index {continue;}
                    let result=weak.upgrade().unwrap().rx_packed_from_side(bytes,side);
                    destinations.push(serde_json::json!({"destination":dest,"result":format!("{result:?}")}));
                    if result.is_err(){let mut r=log.lock().unwrap();if r.len()<LIMIT{r.push(serde_json::json!({"sender_index":index,"type":p.data_type().as_u32(),"raw":raw,"destinations":destinations}));}else{loss.fetch_add(1,Ordering::Relaxed);}return result;}
                }}
                let mut r=log.lock().unwrap();if r.len()<LIMIT {r.push(serde_json::json!({"sender_index":index,"source":info.envelope.source_address,"type":p.data_type().as_u32(),"id":p.packet_id(),"utc":p.timestamp(),"reliable":info.reliable.map(|h|serde_json::json!({"seq":h.seq,"ack":h.ack,"flags":h.flags})),"raw":raw,"dropped":drop,"destinations":destinations}));}else{loss.fetch_add(1,Ordering::Relaxed);}Ok(())
            },RouterSideOptions{reliable_enabled:true,link_local_enabled:true,..Default::default()});
            bus.lock().unwrap().push((Arc::downgrade(node), side));
        }
        for node in &nodes {
            node.announce_discovery().unwrap();
        }
        let mut f = Self {
            _case: guard,
            nodes,
            clock,
            rows,
            seen,
            lost,
            drop_third_until,
            ep,
            ty,
            nonce: 0,
            capture_bytes: AtomicU64::new(0),
        };
        f.drain();
        f.capture("initial8");
        for value in [1, 2, 3, 4, 3, 2, 1, 0, 1, 2] {
            let p = f.packet(value);
            f.nodes[0].set_network_variable(p).unwrap();
            f.drain();
        }
        f.capture("warmup");
        for seen in &f.seen {
            seen.lock().unwrap().clear();
        }
        f
    }
    fn packet(&mut self, value: u8) -> Packet {
        self.nonce += 1;
        let now = self.clock.fetch_add(1, Ordering::Relaxed) + 1;
        Packet::new(
            self.ty,
            &[self.ep],
            self.nodes[0].sender_arc().as_ref(),
            now,
            Arc::<[u8]>::from([value]),
        )
        .unwrap()
        .with_nonce(self.nonce)
    }
    fn drain(&mut self) {
        for _ in 0..8 {
            for n in &self.nodes {
                n.process_all_queues().unwrap();
            }
            self.clock.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn all_discovered(&self) -> bool {
        self.nodes.iter().all(|n| {
            let st = n.state.lock();
            st.discovery_routes
                .get(&0)
                .is_some_and(|route| route.announcers.len() == self.nodes.len() - 1)
        })
    }
    fn capture(&self, stage: &str) {
        let Some(root) = std::env::var_os("SEDSNET_BOOTSTRAP_AUDIT_DIR") else {
            return;
        };
        let nodes=self.nodes.iter().map(|n|{let st=n.state.lock();serde_json::json!({"pointer":Arc::as_ptr(n)as usize,"name":n.sender_arc().as_ref(),"address":st.local_address.address,"routes":st.discovery_routes.iter().map(|(side,r)|serde_json::json!({"side":side,"announcers":r.announcers.keys().collect::<Vec<_>>()})).collect::<Vec<_>>(),"rx":st.reliable_rx.iter().map(|((side,ty),rx)|serde_json::json!({"side":side,"type":ty,"expected":rx.expected_seq})).collect::<Vec<_>>()})}).collect::<Vec<_>>();
        let body=serde_json::to_vec(&serde_json::json!({"stage":stage,"clock":self.clock.load(Ordering::Relaxed),"lost":self.lost.load(Ordering::Relaxed),"nodes":nodes,"wire":*self.rows.lock().unwrap(),"ack_old":*ACK_OLD.lock().unwrap()})).unwrap();
        assert!(
            self.capture_bytes
                .fetch_add(body.len() as u64, Ordering::Relaxed)
                + body.len() as u64
                <= 1024 * 1024,
            "bounded case capture exceeded"
        );
        let name = std::thread::current()
            .name()
            .unwrap_or("case")
            .replace(':', "_");
        let path = std::path::PathBuf::from(root).join(format!("{name}-{stage}.json"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        use std::io::Write;
        f.write_all(&body).unwrap();
    }
}
#[test]
fn default_three_discovers_and_delivers_healthy() {
    let mut f = Fixture::new(3, 0);
    assert!(
        f.all_discovered(),
        "real default shared side never learned both independent announcers"
    );
    let mut ids = Vec::new();
    for value in [3, 2, 1, 0] {
        let p = f.packet(value);
        ids.push(p.packet_id());
        f.nodes[0].set_network_variable(p).unwrap();
        f.drain();
    }
    f.capture("healthy-terminal");
    for seen in f.seen.iter().skip(1) {
        assert_eq!(*seen.lock().unwrap(), ids);
    }
    assert_eq!(f.lost.load(Ordering::Relaxed), 0);
}
#[test]
fn point_to_point_application_and_schema_stay_sequenced() {
    let mut f = Fixture::new(2, 0);
    assert!(f.all_discovered());
    let p = f.packet(42);
    let id = p.packet_id();
    f.nodes[0].tx(p).unwrap();
    f.drain();
    f.capture("point-terminal");
    assert_eq!(*f.seen[1].lock().unwrap(), vec![id]);
    let rows = f.rows.lock().unwrap();
    assert!(rows.iter().any(|r| r["type"].as_u64() == Some(10)
        && r["reliable"]["seq"].as_u64().is_some_and(|n| n > 0)
        && r["reliable"]["flags"].as_u64() == Some(0)));
    assert!(rows.iter().any(|r| r["id"].as_u64() == Some(id)
        && r["reliable"]["seq"].as_u64().is_some_and(|n| n > 0)
        && r["reliable"]["flags"].as_u64() == Some(0)));
}
#[test]
fn exact_four_bootstrap_types_only() {
    crate::tests::ensure_common_test_schema();
    for id in 1..=18 {
        if let Some(ty) = DataType::try_from_u32(id) {
            assert_eq!(
                discovery::is_announcer_bootstrap_type(ty),
                matches!(id, 7 | 8 | 9 | 17),
                "type{id}"
            );
        }
    }
}
#[test]
fn default_periodic_repairs_initial_third_bootstrap_loss() {
    let mut f = Fixture::new(3, u64::MAX);
    assert!(!f.all_discovered());
    f.drop_third_until.store(0, Ordering::Relaxed);
    // Separate explicit repair scene; original discovery fixture remains8drain/10warmups.
    for _ in 0..30 {
        f.clock.fetch_add(1000, Ordering::Relaxed);
        f.drain();
    }
    f.capture("periodic-terminal");
    assert!(f.all_discovered());
    assert_eq!(f.lost.load(Ordering::Relaxed), 0);
}
