use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn local(inside: &Arc<AtomicBool>) -> Router {
    let observed = inside.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("LOCAL")
            .with_static_address(11),
        Box::new(move || {
            assert!(
                !observed.load(Ordering::SeqCst),
                "clock under admission guard"
            );
            10000
        }),
    );
    router.clear_queues();
    router
}
type P2pSnapshot = (u64, u32, Vec<(u32, u32, u32)>, usize, usize, usize);
fn snapshot(router: &Router) -> P2pSnapshot {
    let st = router.state.lock();
    let s = st.local_services.as_ref().unwrap();
    (
        st.p2p_revision,
        s.next_p2p_stream_id,
        s.p2p_stream_sessions
            .iter()
            .map(|(id, s)| (*id, s.next_sequence, s.peer_stream_id))
            .collect(),
        st.transmit_queue.len(),
        st.received_queue.len(),
        st.shared_queue_bytes_used(),
    )
}
fn bytes(plan: &PreparedP2p<'_>) -> Vec<Vec<u8>> {
    plan.frames
        .iter()
        .flatten()
        .map(|item| match item {
            RouterItem::Packed(bytes) => bytes.as_ref().to_vec(),
            _ => panic!("frozen packed frames required"),
        })
        .collect()
}
#[test]
fn prepared_p2p_preparation_is_protocol_inert_and_drop_does_not_open() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let before = snapshot(&r);
    let plan = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(0))
        .unwrap();
    assert_eq!(snapshot(&r), before);
    assert_eq!(plan.count, 1);
    let packet = wire_format::unpack_packet(&bytes(&plan)[0]).unwrap();
    assert_eq!(packet.timestamp(), 0);
    drop(plan);
    assert_eq!(snapshot(&r), before);
}
#[test]
fn prepared_p2p_held_core_returns_busy_without_late_retention() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let mut plan = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let before = snapshot(&r);
    let frozen = bytes(&plan);
    let held = r.state.lock();
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();
        let reference = &r;
        let p = &mut plan;
        scope.spawn(move || {
            let start = Instant::now();
            let result = reference.try_queue_prepared_p2p(p);
            tx.send((result, start.elapsed())).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_millis(500));
        drop(held);
        let (outcome, elapsed) = result.expect("try API waited for held core");
        assert_eq!(outcome, Err(TryP2pError::Busy));
        assert!(elapsed < Duration::from_millis(250));
    });
    assert_eq!(snapshot(&r), before);
    assert_eq!(bytes(&plan), frozen);
    inside.store(true, Ordering::SeqCst);
    let receipt = r.try_queue_prepared_p2p(&mut plan).unwrap();
    inside.store(false, Ordering::SeqCst);
    assert_eq!(receipt.frames_queued, 1);
    assert_eq!(
        r.try_queue_prepared_p2p(&mut plan),
        Err(TryP2pError::AlreadyAdmitted)
    );
}
#[test]
fn prepared_p2p_held_schema_returns_busy_without_session_or_sequence() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let mut plan = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let before = snapshot(&r);
    let held = crate::config::try_prepared_schema_guard().unwrap();
    assert_eq!(r.try_queue_prepared_p2p(&mut plan), Err(TryP2pError::Busy));
    drop(held);
    assert_eq!(snapshot(&r), before);
}
#[test]
fn prepared_p2p_loopback_callbacks_run_only_on_worker_full_lifecycle() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = events.clone();
    let guard = inside.clone();
    r.bind_p2p_stream_port(90, move |event| {
        assert!(
            !guard.load(Ordering::SeqCst),
            "handler under admission guard"
        );
        seen.lock()
            .unwrap()
            .push((event.kind, event.payload.to_vec()));
        Ok(())
    })
    .unwrap();
    let mut open = r
        .prepare_p2p_stream_open(P2pTarget::Address(11), 90, 91, Some(9000))
        .unwrap();
    inside.store(true, Ordering::SeqCst);
    let id = r.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    inside.store(false, Ordering::SeqCst);
    assert!(events.lock().unwrap().is_empty());
    r.process_all_queues().unwrap();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Accepted)
    );
    let mut data = r
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"retained"), Some(9001))
        .unwrap();
    let before = events.lock().unwrap().len();
    inside.store(true, Ordering::SeqCst);
    let receipt = r.try_queue_prepared_p2p(&mut data).unwrap();
    inside.store(false, Ordering::SeqCst);
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.frames_queued, 1);
    assert_eq!(events.lock().unwrap().len(), before);
    r.process_all_queues().unwrap();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Data && e.1 == b"retained")
    );
    let mut close = r
        .prepare_p2p_stream_control(id, P2pStreamOperation::Close, Some(9002))
        .unwrap();
    r.try_queue_prepared_p2p(&mut close).unwrap();
    r.process_all_queues().unwrap();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Closed)
    );
    let mut again = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9003))
        .unwrap();
    let id = r.try_queue_prepared_p2p(&mut again).unwrap().stream_id;
    r.process_all_queues().unwrap();
    let mut reset = r
        .prepare_p2p_stream_control(id, P2pStreamOperation::Reset, Some(9004))
        .unwrap();
    r.try_queue_prepared_p2p(&mut reset).unwrap();
    r.process_all_queues().unwrap();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Reset)
    );
}
#[test]
fn prepared_p2p_router_revision_and_counter_exhaustion_do_not_aba() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let other = local(&inside);
    let mut plan = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let before = snapshot(&r);
    assert_eq!(
        other.try_queue_prepared_p2p(&mut plan),
        Err(TryP2pError::Stale)
    );
    assert_eq!(snapshot(&r), before);
    r.set_sender("OTHER");
    r.set_sender("LOCAL");
    assert_eq!(r.try_queue_prepared_p2p(&mut plan), Err(TryP2pError::Stale));
    r.state.lock().p2p_revision = u64::MAX - 1;
    let mut last = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9001))
        .unwrap();
    r.try_queue_prepared_p2p(&mut last).unwrap();
    assert_eq!(r.state.lock().p2p_revision, u64::MAX);
    assert!(
        r.prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9002))
            .is_err()
    );
    // Legacy mutation can continue but never wraps/re-enables prepared authority.
    let _ = r.open_p2p_stream_to_hostname("LOCAL", 90, 91);
    assert_eq!(r.state.lock().p2p_revision, u64::MAX);
}
#[test]
fn prepared_p2p_relay_role_refuses_before_core_wait() {
    let r = Router::new(RouterConfig::relay());
    let _held = r.state.lock();
    assert!(matches!(
        r.prepare_p2p_stream_open(P2pTarget::Hostname("X"), 90, 91, Some(0)),
        Err(TelemetryError::PermissionDenied)
    ));
}

#[cfg(feature = "discovery")]
struct Pair {
    a: Router,
    b: Router,
    ab: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ba: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    aside: usize,
    bside: usize,
}
#[cfg(feature = "discovery")]
impl Pair {
    fn new() -> Self {
        let a = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("A")
                .with_static_address(21),
            Box::new(|| 10000),
        );
        let b = Router::new_with_clock(
            RouterConfig::new([])
                .with_sender("B")
                .with_static_address(22),
            Box::new(|| 10000),
        );
        let ab = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ba = Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = ab.clone();
        let aside = a.add_side_packed("ab", move |bytes| {
            send.lock().unwrap().push(bytes.to_vec());
            Ok(())
        });
        let send = ba.clone();
        let bside = b.add_side_packed("ba", move |bytes| {
            send.lock().unwrap().push(bytes.to_vec());
            Ok(())
        });
        let pair = Self {
            a,
            b,
            ab,
            ba,
            aside,
            bside,
        };
        pair.a.announce_discovery().unwrap();
        pair.b.announce_discovery().unwrap();
        pair.pump();
        pair.a.clear_queues();
        pair.b.clear_queues();
        pair
    }
    fn pump(&self) {
        for _ in 0..20 {
            self.a.process_all_queues_with_timeout(0).unwrap();
            self.b.process_all_queues_with_timeout(0).unwrap();
            for wire in std::mem::take(&mut *self.ab.lock().unwrap()) {
                self.b.rx_packed_from_side(&wire, self.bside).unwrap();
            }
            for wire in std::mem::take(&mut *self.ba.lock().unwrap()) {
                self.a.rx_packed_from_side(&wire, self.aside).unwrap();
            }
        }
    }
}
#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_refresh_syn_data_capacity_is_atomic_and_frozen() {
    let pair = Pair::new();
    let r = &pair.a;
    let mut open = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("B"), 90, 91, Some(9000))
        .unwrap();
    let id = r.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    // No worker has run SYN yet: production session genuinely has peer_id0.
    r.clear_tx_queue();
    let mut plan = r
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"twoframe"), Some(9001))
        .unwrap();
    assert_eq!(plan.count, 2);
    let frozen = bytes(&plan);
    for frame in &frozen {
        assert_eq!(wire_format::unpack_packet(frame).unwrap().timestamp(), 9001);
    }
    let (budget, queue) = {
        let mut st = r.state.lock();
        let budget = st.memory.max_queue_budget;
        let queue = std::mem::replace(
            &mut st.transmit_queue,
            BoundedDeque::new(4096, size_of::<TxQueued>(), 1.0),
        );
        (budget, queue)
    };
    let before = snapshot(r);
    assert_eq!(
        r.try_queue_prepared_p2p(&mut plan),
        Err(TryP2pError::Capacity)
    );
    assert_eq!(snapshot(r), before);
    assert_eq!(bytes(&plan), frozen);
    {
        let mut st = r.state.lock();
        st.transmit_queue = queue;
        st.memory.max_queue_budget =
            st.shared_queue_bytes_used() + plan.costs.iter().sum::<usize>() - 1;
    }
    let before = snapshot(r);
    assert_eq!(
        r.try_queue_prepared_p2p(&mut plan),
        Err(TryP2pError::Capacity)
    );
    assert_eq!(snapshot(r), before);
    assert_eq!(bytes(&plan), frozen);
    r.state.lock().memory.max_queue_budget = budget;
    let result = r.try_queue_prepared_p2p(&mut plan).unwrap();
    assert_eq!(result.frames_queued, 2);
    assert_eq!(result.sequence, 1);
    assert_eq!(
        r.state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .next_sequence,
        2
    );
}
#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_actual_packed_two_router_and_legacy_races() {
    let pair = Pair::new();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = events.clone();
    pair.b
        .bind_p2p_stream_port(90, move |event| {
            seen.lock()
                .unwrap()
                .push((event.kind, event.payload.to_vec()));
            Ok(())
        })
        .unwrap();
    let mut open = pair
        .a
        .prepare_p2p_stream_open(P2pTarget::Hostname("B"), 90, 91, Some(9000))
        .unwrap();
    let id = pair.a.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    assert!(events.lock().unwrap().is_empty());
    pair.pump();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Accepted)
    );
    let mut stale = pair
        .a
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"stale"), Some(9001))
        .unwrap();
    pair.a.send_p2p_stream(id, b"legacy").unwrap();
    assert_eq!(
        pair.a.try_queue_prepared_p2p(&mut stale),
        Err(TryP2pError::Stale)
    );
    pair.pump();
    let mut data = pair
        .a
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"prepared"), Some(9002))
        .unwrap();
    assert_eq!(
        pair.a
            .try_queue_prepared_p2p(&mut data)
            .unwrap()
            .frames_queued,
        1
    );
    pair.pump();
    let values = events.lock().unwrap();
    assert!(values.iter().any(|e| e.1 == b"legacy"));
    assert!(values.iter().any(|e| e.1 == b"prepared"));
    assert!(!values.iter().any(|e| e.1 == b"stale"));
    drop(values);
    let mut stale = pair
        .a
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"closed"), Some(9003))
        .unwrap();
    pair.a.reset_p2p_stream(id).unwrap();
    assert_eq!(
        pair.a.try_queue_prepared_p2p(&mut stale),
        Err(TryP2pError::Stale)
    );
    pair.pump();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.0 == P2pStreamEventKind::Reset)
    );
}

#[test]
fn prepared_p2p_guarded_budget_matches_existing_complete_accounting() {
    let inside = Arc::new(AtomicBool::new(false));
    let router = local(&inside);
    for pass in 0..2 {
        let state = router.state.lock();
        let expected = state.shared_queue_bytes_used();
        let schema = crate::config::try_prepared_schema_guard().unwrap();
        assert_eq!(state.prepared_shared_queue_bytes_used(&schema), expected);
        drop(schema);
        drop(state);
        if pass == 1 {
            break;
        }
        let mut plan = router
            .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
            .unwrap();
        router.try_queue_prepared_p2p(&mut plan).unwrap();
    }
}

#[test]
fn prepared_p2p_schema_change_is_stale_without_protocol_effect() {
    let inside = Arc::new(AtomicBool::new(false));
    let router = local(&inside);
    let mut plan = router
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let before = snapshot(&router);
    let policy = plan.meta.e2e_encryption;
    crate::config::set_data_type_e2e_encryption_policy(
        DataType::P2pMessage,
        E2eEncryptionPolicy::PreferOn,
    )
    .unwrap();
    let result = router.try_queue_prepared_p2p(&mut plan);
    crate::config::set_data_type_e2e_encryption_policy(DataType::P2pMessage, policy).unwrap();
    assert_eq!(result, Err(TryP2pError::Stale));
    assert_eq!(snapshot(&router), before);
}
#[test]
fn prepared_p2p_concurrent_preparations_have_one_atomic_winner() {
    let inside = Arc::new(AtomicBool::new(false));
    let router = local(&inside);
    let mut open = router
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let id = router.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    router.process_all_queues().unwrap();
    let mut first = router
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"one"), Some(9001))
        .unwrap();
    let mut second = router
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"two"), Some(9001))
        .unwrap();
    let before = snapshot(&router);
    let barrier = std::sync::Barrier::new(2);
    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            router.try_queue_prepared_p2p(&mut first)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            router.try_queue_prepared_p2p(&mut second)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(a.is_ok() || matches!(a, Err(TryP2pError::Busy | TryP2pError::Stale)));
    assert!(b.is_ok() || matches!(b, Err(TryP2pError::Busy | TryP2pError::Stale)));
    let after = snapshot(&router);
    assert_eq!(after.0, before.0 + 1);
    assert_eq!(after.4, before.4 + 1);
    assert_eq!(
        router
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .next_sequence,
        2
    );
}
#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_actual_incoming_handshake_rejects_old_pair_then_fresh_send_works() {
    let pair = Pair::new();
    let mut open = pair
        .a
        .prepare_p2p_stream_open(P2pTarget::Hostname("B"), 90, 91, Some(9000))
        .unwrap();
    let id = pair.a.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    let mut old = pair
        .a
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"old-pair"), Some(9001))
        .unwrap();
    assert_eq!(old.count, 2);
    let frozen = bytes(&old);
    pair.pump();
    let before = snapshot(&pair.a);
    assert_eq!(
        pair.a.try_queue_prepared_p2p(&mut old),
        Err(TryP2pError::Stale)
    );
    assert_eq!(snapshot(&pair.a), before);
    assert_eq!(bytes(&old), frozen);
    let mut fresh = pair
        .a
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"fresh"), Some(9001))
        .unwrap();
    assert_eq!(fresh.count, 1);
    assert!(pair.a.try_queue_prepared_p2p(&mut fresh).is_ok());
    pair.pump();
}
#[test]
fn prepared_p2p_wire_sequence_and_stream_id_wrap_keep_revision_identity() {
    let inside = Arc::new(AtomicBool::new(false));
    let router = local(&inside);
    {
        let mut state = router.state.lock();
        state.local_services.as_mut().unwrap().next_p2p_stream_id = u32::MAX;
    }
    let mut open = router
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(0))
        .unwrap();
    assert_eq!(open.stream_id, u32::MAX);
    let id = router.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    router.process_all_queues().unwrap();
    {
        let mut state = router.state.lock();
        state
            .local_services
            .as_mut()
            .unwrap()
            .p2p_stream_sessions
            .get_mut(&id)
            .unwrap()
            .next_sequence = u32::MAX;
        state.invalidate_prepared_p2p();
    }
    let mut a = router
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"wrap"), Some(0))
        .unwrap();
    let mut stale = router
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"stale"), Some(0))
        .unwrap();
    assert_eq!(
        router.try_queue_prepared_p2p(&mut a).unwrap().sequence,
        u32::MAX
    );
    assert_eq!(
        router
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .next_sequence,
        1
    );
    assert_eq!(
        router.try_queue_prepared_p2p(&mut stale),
        Err(TryP2pError::Stale)
    );
}

#[test]
fn prepared_p2p_all_controls_busy_leave_live_session_sequence_and_buffers() {
    let inside = Arc::new(AtomicBool::new(false));
    let router = local(&inside);
    let mut open = router
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9000))
        .unwrap();
    let id = router.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    router.process_all_queues().unwrap();
    for operation in [
        P2pStreamOperation::Data(b"data"),
        P2pStreamOperation::Close,
        P2pStreamOperation::Reset,
    ] {
        let mut prepared = router
            .prepare_p2p_stream_control(id, operation, Some(9001))
            .unwrap();
        let before = snapshot(&router);
        let frozen = bytes(&prepared);
        let held = router.state.lock();
        assert_eq!(
            router.try_queue_prepared_p2p(&mut prepared),
            Err(TryP2pError::Busy)
        );
        drop(held);
        assert_eq!(snapshot(&router), before);
        assert_eq!(bytes(&prepared), frozen);
        drop(prepared);
        assert_eq!(snapshot(&router), before);
    }
}

#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_rejected_peer_controls_do_not_revoke_prepared_owner() {
    use super::super::published_p2p_tuple_causal::Mesh;
    for flags in [P2P_STREAM_DATA, P2P_STREAM_FIN, P2P_STREAM_RST] {
        let mesh = Mesh::new();
        let a = mesh.nodes[0]
            .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
            .unwrap();
        mesh.pump();
        let c = mesh.nodes[2]
            .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
            .unwrap();
        mesh.pump();
        assert_eq!(a, c);
        let receiver = &mesh.nodes[1];
        let id = receiver
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions
            .iter()
            .find(|(_, s)| s.peer_hostname.as_ref() == "CLIENT_A")
            .unwrap()
            .0
            .to_owned();
        let mut prepared = receiver
            .prepare_p2p_stream_control(
                id,
                P2pStreamOperation::Data(b"valid-owned-reply"),
                Some(9000),
            )
            .unwrap();
        let frozen = bytes(&prepared);
        let before = snapshot(receiver);
        let frame = Router::encode_p2p_stream_payload(flags, c, id, 1, b"mismatched-peer").unwrap();
        mesh.nodes[2]
            .send_p2p_to_hostname("SERVICE_B", 90, 91, frame.as_ref())
            .unwrap();
        mesh.pump();
        let after = snapshot(receiver);
        assert_eq!(after.0, before.0, "rejected peer revoked preparation");
        assert_eq!(after.1, before.1);
        assert_eq!(after.2, before.2);
        assert_eq!(bytes(&prepared), frozen);
        assert!(
            receiver.try_queue_prepared_p2p(&mut prepared).is_ok(),
            "same current owner can progress after inert rejection"
        );
        mesh.pump();
    }
}
#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_invalid_synack_is_inert_but_identical_valid_retry_is_progress() {
    use super::super::published_p2p_tuple_causal::Mesh;
    let mesh = Mesh::new();
    let id = mesh.nodes[0]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    mesh.pump();
    let _ = mesh.nodes[2]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    mesh.pump();
    let receiver = &mesh.nodes[0];
    let peer = receiver
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .p2p_stream_sessions[&id]
        .peer_stream_id;
    let mut prepared = receiver
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"pending"), Some(9000))
        .unwrap();
    let before = snapshot(receiver);
    let frozen = bytes(&prepared);
    for (sender, source, src_port, dst_port) in [
        (2, peer, 90, 91),
        (1, peer + 77, 90, 91),
        (1, peer, 92, 91),
        (1, 0, 90, 91),
    ] {
        let frame =
            Router::encode_p2p_stream_payload(P2P_STREAM_SYN | P2P_STREAM_ACK, source, id, 0, &[])
                .unwrap();
        mesh.nodes[sender]
            .send_p2p_to_hostname("CLIENT_A", dst_port, src_port, frame.as_ref())
            .unwrap();
        mesh.pump();
        let after = snapshot(receiver);
        assert_eq!(after.0, before.0);
        assert_eq!(after.2, before.2);
        assert_eq!(bytes(&prepared), frozen);
    }
    // Valid identical SYNACK retries retain the legacy Connected notification;
    // this accepted progress must invalidate an older prepared operation.
    let frame =
        Router::encode_p2p_stream_payload(P2P_STREAM_SYN | P2P_STREAM_ACK, peer, id, 0, &[])
            .unwrap();
    mesh.nodes[1]
        .send_p2p_to_hostname("CLIENT_A", 91, 90, frame.as_ref())
        .unwrap();
    mesh.pump();
    assert!(snapshot(receiver).0 > before.0);
    assert_eq!(
        receiver.try_queue_prepared_p2p(&mut prepared),
        Err(TryP2pError::Stale)
    );
    let mut fresh = receiver
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"fresh"), Some(9000))
        .unwrap();
    assert!(receiver.try_queue_prepared_p2p(&mut fresh).is_ok());
    mesh.pump();
}
#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_inconsistent_packet_name_and_address_never_touch_session() {
    use super::super::published_p2p_tuple_causal::Mesh;
    let mesh = Mesh::new();
    let a = mesh.nodes[0]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    mesh.pump();
    let receiver = &mesh.nodes[1];
    let id = receiver
        .state
        .lock()
        .local_services
        .as_ref()
        .unwrap()
        .p2p_stream_sessions
        .iter()
        .find(|(_, s)| s.peer_hostname.as_ref() == "CLIENT_A")
        .unwrap()
        .0
        .to_owned();
    let calls = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    receiver
        .bind_p2p_stream_port(90, move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    let mut prepared = receiver
        .prepare_p2p_stream_control(id, P2pStreamOperation::Data(b"owned"), Some(9000))
        .unwrap();
    let before = snapshot(receiver);
    for (packet_name, address) in [("CLIENT_C", 31), ("CLIENT_A", 999)] {
        let stream =
            Router::encode_p2p_stream_payload(P2P_STREAM_DATA, a, id, 1, b"mismatched-metadata")
                .unwrap();
        let outer =
            Router::encode_p2p_payload("CLIENT_A", address, 91, 90, stream.as_ref()).unwrap();
        let packet = Packet::new(
            DataType::P2pMessage,
            &[DataEndpoint::Discovery],
            packet_name,
            9000,
            crate::shared_bytes::convert(outer),
        )
        .unwrap();
        receiver.dispatch_p2p_packet(&packet).unwrap();
        assert_eq!(snapshot(receiver), before);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    assert!(receiver.try_queue_prepared_p2p(&mut prepared).is_ok());
    mesh.pump();
}

#[cfg(feature = "discovery")]
#[test]
fn prepared_p2p_zero_source_synack_cannot_establish_unknown_peer() {
    use super::super::published_p2p_tuple_causal::Mesh;
    let mesh = Mesh::new_with_reliable(false);
    let calls = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    mesh.nodes[0]
        .bind_p2p_stream_port(91, move |event| {
            if event.kind == P2pStreamEventKind::Connected {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
        .unwrap();
    let id = mesh.nodes[0]
        .open_p2p_stream_to_hostname("SERVICE_B", 90, 91)
        .unwrap();
    let pending = { std::mem::take(&mut *mesh.wire.lock().unwrap()) };
    for (to, side, wire) in pending {
        mesh.nodes[to].rx_packed_from_side(&wire, side).unwrap();
    }
    let before = snapshot(&mesh.nodes[0]);
    assert_eq!(
        mesh.nodes[0]
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .peer_stream_id,
        0
    );
    let frame =
        Router::encode_p2p_stream_payload(P2P_STREAM_SYN | P2P_STREAM_ACK, 0, id, 0, &[]).unwrap();
    mesh.nodes[1]
        .send_p2p_to_hostname("CLIENT_A", 91, 90, frame.as_ref())
        .unwrap();
    let pending = { std::mem::take(&mut *mesh.wire.lock().unwrap()) };
    let mut held = Vec::new();
    let mut delivered = false;
    for (to, side, wire) in pending {
        let zero = wire_format::unpack_packet(&wire)
            .ok()
            .filter(|p| p.data_type() == DataType::P2pMessage)
            .and_then(|p| {
                let message = Router::decode_p2p_payload(p.payload()).ok()?;
                let frame = Router::decode_p2p_stream_payload(message.payload).ok()??;
                Some(
                    frame.flags == (P2P_STREAM_SYN | P2P_STREAM_ACK) && frame.source_stream_id == 0,
                )
            })
            .unwrap_or(false);
        if to == 0 && zero {
            mesh.nodes[to].rx_packed_from_side(&wire, side).unwrap();
            delivered = true;
        } else {
            held.push((to, side, wire));
        }
    }
    assert!(delivered);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let after = snapshot(&mesh.nodes[0]);
    assert_eq!(after.0, before.0);
    assert_eq!(after.2, before.2);
    assert!(
        !mesh.nodes[0]
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .connected
    );
    mesh.wire.lock().unwrap().extend(held);
    mesh.pump();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_ne!(
        mesh.nodes[0]
            .state
            .lock()
            .local_services
            .as_ref()
            .unwrap()
            .p2p_stream_sessions[&id]
            .peer_stream_id,
        0
    );
}
fn assert_nested_overflow_preserves_plan(
    r: &Router,
    sides: [RouterSideId; 2],
    plan: &mut PreparedP2p<'_>,
) {
    let protocol = || {
        let st = r.state.lock();
        let services = st.local_services.as_ref().unwrap();
        (
            st.p2p_revision,
            services.next_p2p_stream_id,
            services
                .p2p_stream_sessions
                .iter()
                .map(|(id, s)| {
                    (
                        *id,
                        s.peer_stream_id,
                        s.next_sequence,
                        s.peer_address,
                        s.peer_address_bound,
                        s.connected,
                    )
                })
                .collect::<Vec<_>>(),
            st.transmit_queue.len(),
            st.transmit_queue.bytes_used(),
            st.received_queue.len(),
            st.received_queue.bytes_used(),
        )
    };
    let before = protocol();
    let frozen = bytes(plan);
    {
        let mut st = r.state.lock();
        for side in sides {
            st.side_transport.get_mut(&side).unwrap().rx_chunk_bytes = usize::MAX / 2 + 1;
        }
    }
    assert_eq!(r.try_queue_prepared_p2p(plan), Err(TryP2pError::Capacity));
    assert_eq!(protocol(), before);
    assert!(!plan.admitted);
    assert_eq!(bytes(plan), frozen);
    {
        let mut st = r.state.lock();
        for side in sides {
            st.side_transport.get_mut(&side).unwrap().rx_chunk_bytes = 0;
        }
        let ordinary = st.shared_queue_bytes_used();
        let schema = crate::config::try_prepared_schema_guard().unwrap();
        assert_eq!(st.prepared_shared_queue_bytes_used(&schema), ordinary);
    }
}
#[test]
fn prepared_p2p_nested_budget_overflow_refuses_open_data_fin_rst_without_any_transfer() {
    let inside = Arc::new(AtomicBool::new(false));
    let r = local(&inside);
    let sides = [
        r.add_side_packed("overflow-a", |_| Ok(())),
        r.add_side_packed("overflow-b", |_| Ok(())),
    ];
    r.bind_p2p_stream_port(90, |_| Ok(())).unwrap();
    let mut open = r
        .prepare_p2p_stream_open(P2pTarget::Hostname("LOCAL"), 90, 91, Some(9001))
        .unwrap();
    assert_nested_overflow_preserves_plan(&r, sides, &mut open);
    let id = r.try_queue_prepared_p2p(&mut open).unwrap().stream_id;
    r.process_all_queues().unwrap();
    for operation in [
        P2pStreamOperation::Data(b"unchanged"),
        P2pStreamOperation::Close,
        P2pStreamOperation::Reset,
    ] {
        let mut control = r
            .prepare_p2p_stream_control(id, operation, Some(9002))
            .unwrap();
        assert_nested_overflow_preserves_plan(&r, sides, &mut control);
    }
}
