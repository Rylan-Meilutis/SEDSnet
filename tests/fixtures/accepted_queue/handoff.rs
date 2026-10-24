//! Real packed transport failure and concurrent claim regressions; no hardware.
use sedsnet::router::{EndpointHandler, Router, RouterConfig, RouterSideId};
use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError, config,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
type Wire = Arc<Mutex<VecDeque<Vec<u8>>>>;
fn take(w: &Wire) -> Vec<Vec<u8>> {
    w.lock().unwrap().drain(..).collect()
}
fn feed(w: &Wire, r: &Router, s: RouterSideId) {
    for b in take(w) {
        r.rx_packed_from_side(&b, s).unwrap();
    }
}
fn pump(
    a: &Router,
    ai: RouterSideId,
    aw: &Wire,
    b: &Router,
    bi: RouterSideId,
    bw: &Wire,
    clock: &AtomicU64,
) {
    clock.fetch_add(5, Ordering::SeqCst);
    a.process_all_queues_with_timeout(0).unwrap();
    feed(aw, b, bi);
    b.process_all_queues_with_timeout(0).unwrap();
    feed(bw, a, ai);
}
pub fn run(case: &str) {
    let concurrent = case == "concurrent";
    let mode = if case == "unordered-after-send" {
        ReliableMode::Unordered
    } else {
        ReliableMode::Ordered
    };
    let local = config::register_endpoint("PHASE_LOCAL", false).unwrap();
    let remote = config::register_endpoint("PHASE_REMOTE", false).unwrap();
    let ty = config::register_data_type_with_description(
        "PHASE_DATA",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[local, remote],
        mode,
        200,
    )
    .unwrap();
    let other = config::register_data_type_with_description(
        "PHASE_UNRELATED",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[local],
        ReliableMode::None,
        1,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(1000));
    let locals = Arc::new(Mutex::new(Vec::<u8>::new()));
    let effects = locals.clone();
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let local_gate = gate.clone();
    let now = clock.clone();
    let source = Arc::new(Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(local, move |p| {
            let value = p.payload()[0];
            if concurrent && p.data_type() == ty && value == 1 {
                let (lock, cv) = &*local_gate;
                let mut state = lock.lock().unwrap();
                state.0 = true;
                cv.notify_all();
                while !state.1 {
                    let (next, wait) = cv.wait_timeout(state, Duration::from_secs(5)).unwrap();
                    state = next;
                    if wait.timed_out() {
                        panic!("concurrent test gate timed out");
                    }
                }
            }
            if p.payload().len() == 1 && (p.data_type() == ty || p.data_type() == other) {
                effects.lock().unwrap().push(value);
            }
            Ok(())
        })])
        .with_sender("PHASE_SOURCE"),
        Box::new(move || now.load(Ordering::SeqCst)),
    ));
    let outgoing: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let out = outgoing.clone();
    let fail = Arc::new(AtomicBool::new(false));
    let inject = fail.clone();
    let fault_hits = Arc::new(AtomicUsize::new(0));
    let hits = fault_hits.clone();
    let source_side = source.add_side_packed_with_options(
        "packed",
        move |bytes| {
            let is_data = sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|e| e.ty == ty);
            out.lock().unwrap().push_back(bytes.to_vec());
            if is_data && inject.load(Ordering::SeqCst) {
                hits.fetch_add(1, Ordering::SeqCst);
                return Err(TelemetryError::HandlerError(
                    "injected after complete frame handoff",
                ));
            }
            Ok(())
        },
        sedsnet::router::RouterSideOptions {
            reliable_enabled: false,
            ..Default::default()
        },
    );
    let remotes = Arc::new(Mutex::new(Vec::<u8>::new()));
    let effects = remotes.clone();
    let now = clock.clone();
    let sink = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(remote, move |p| {
            if p.data_type() == ty && p.payload().len() == 1 {
                effects.lock().unwrap().push(p.payload()[0]);
            }
            Ok(())
        })])
        .with_sender("PHASE_SINK"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let incoming: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let out = incoming.clone();
    let sink_side = sink.add_side_packed("packed", move |bytes| {
        out.lock().unwrap().push_back(bytes.to_vec());
        Ok(())
    });
    source.announce_discovery().unwrap();
    sink.announce_discovery().unwrap();
    for _ in 0..40 {
        pump(
            &source,
            source_side,
            &outgoing,
            &sink,
            sink_side,
            &incoming,
            &clock,
        );
    }
    source.clear_queues();
    sink.clear_queues();
    take(&outgoing);
    take(&incoming);
    locals.lock().unwrap().clear();
    remotes.lock().unwrap().clear();
    if concurrent {
        source.log_queue(ty, &[1u8]).unwrap();
        let s = source.clone();
        let first = std::thread::spawn(move || s.process_all_queues_with_timeout(0));
        let (lock, cv) = &*gate;
        let state = lock.lock().unwrap();
        let (state, wait) = cv
            .wait_timeout_while(state, Duration::from_secs(5), |s| !s.0)
            .unwrap();
        assert!(!wait.timed_out(), "first callback did not begin");
        drop(state);
        source.log_queue(ty, &[2u8]).unwrap();
        source.log_queue(other, &[9u8]).unwrap();
        source.process_all_queues_with_timeout(0).unwrap();
        let before = locals.lock().unwrap().clone();
        {
            let mut state = lock.lock().unwrap();
            state.1 = true;
            cv.notify_all();
        }
        first.join().unwrap().unwrap();
        assert_eq!(
            before,
            vec![9],
            "same-type successor overtook active predecessor or unrelated work starved"
        );
        for _ in 0..100 {
            pump(
                &source,
                source_side,
                &outgoing,
                &sink,
                sink_side,
                &incoming,
                &clock,
            );
        }
        assert_eq!(*locals.lock().unwrap(), vec![9, 1, 2]);
        assert_eq!(*remotes.lock().unwrap(), vec![1, 2]);
    } else {
        fail.store(true, Ordering::SeqCst);
        source.log_queue(ty, &[7u8]).unwrap();
        let result = source.process_all_queues_with_timeout(0);
        fail.store(false, Ordering::SeqCst);
        assert!(
            fault_hits.load(Ordering::SeqCst) > 0,
            "fault never reached actual data transport"
        );
        assert!(
            result.is_err(),
            "injected error did not propagate after registration"
        );
        // Drain independent error/control notifications without advancing the
        // clock: a deferred original must remain observable if wrongly kept.
        source.dispatch_tx_queue_with_timeout(0).unwrap();
        let q = source.export_runtime_stats().queues.tx_len;
        let pending = source.export_reliable_pending_stats();
        println!("after-send result={result:?} queue={q} pending={pending:?}");
        // Positive control: destination consumes the already handed-off frame,
        // then a real E2E receipt retires it before the source can retry.
        feed(&outgoing, &sink, sink_side);
        sink.process_all_queues_with_timeout(0).unwrap();
        let actual_ack = take(&incoming);
        assert!(
            actual_ack
                .iter()
                .any(|b| sedsnet::wire_format::peek_envelope(b)
                    .is_ok_and(|e| e.ty == config::DataType::ReliableAck)),
            "no real receipt"
        );
        assert!(!pending.is_empty(), "no retained owner before receipt");
        for b in actual_ack {
            source.rx_packed_from_side(&b, source_side).unwrap();
        }
        for _ in 0..100 {
            pump(
                &source,
                source_side,
                &outgoing,
                &sink,
                sink_side,
                &incoming,
                &clock,
            );
        }
        assert_eq!(
            q, 0,
            "registered reliable owner must not also remain as an original queue retry"
        );
        assert_eq!(*locals.lock().unwrap(), vec![7]);
        assert_eq!(*remotes.lock().unwrap(), vec![7]);
    }
    assert!(source.export_reliable_pending_stats().is_empty());
    assert_eq!(source.export_runtime_stats().queues.tx_len, 0);
    println!("PASS {case}: actual packed receipts, one effect and no stranded owner");
}
