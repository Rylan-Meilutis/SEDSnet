//! Concurrency-focused tests that exercise Router’s thread-safety
//! guarantees for logging, receiving, and processing.

use crate::tests::packed_frame_type;
use crate::{
    TelemetryResult,
    config::{DataEndpoint, DataType},
    packet::Packet,
    router::{Clock, EndpointHandler, Router, RouterConfig},
    wire_format,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Simple clock that always returns 0 (blanket impl<Fn() -> u64> for Clock).
fn zero_clock() -> Box<dyn Clock + Send + Sync> {
    Box::new(|| 0u64)
}

// ------------------------------------------------------------------------
// Trait sanity: Router must be Send + Sync
// ------------------------------------------------------------------------

/// Compile-time check: `Router` must be `Send + Sync` to be safely shared
/// across threads.
#[test]
fn router_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Router>();
}

// ------------------------------------------------------------------------
// Concurrent RX queue producers
// ------------------------------------------------------------------------

/// Multiple producer threads call `rx_packet_to_queue` on the same Router;
/// a single drain must deliver all packets to the handler exactly once.
#[test]
fn concurrent_rx_queue_is_thread_safe() {
    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 50;
    let total = THREADS * ITERS_PER_THREAD;

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    let r = Arc::new(router);

    let mut threads_vec = Vec::new();
    for tid in 0..THREADS {
        let r_cloned = r.clone();
        threads_vec.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                // Unique timestamp/payload per (thread, iteration) to avoid dedup.
                let idx = (tid * ITERS_PER_THREAD + i) as u64;
                let base = 1.0_f32 + idx as f32 * 0.001;
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[base, 2.0, 3.0],
                    &[DataEndpoint::named("SD_CARD")],
                    idx,
                )
                .unwrap();
                r_cloned.rx_queue(pkt).unwrap();
            }
        }));
    }

    for t in threads_vec {
        t.join().expect("producer thread panicked");
    }

    r.process_rx_queue().unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        total,
        "expected {total} handler invocations from RX queue"
    );
}

/// RTOS-like pattern: multiple ingress threads queue packed packets while
/// another thread continuously drains router queues. This should not deadlock
/// and all queued packets should eventually be processed once.
#[test]
fn rtos_like_ingress_and_processing_no_deadlock() {
    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 80;
    let total = THREADS * ITERS_PER_THREAD;

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![handler]),
        zero_clock(),
    ));

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let proc_router = router.clone();
    let done_c = done.clone();
    let processor = thread::spawn(move || {
        while !done_c.load(Ordering::SeqCst) {
            proc_router.process_all_queues_with_timeout(1).unwrap();
        }
        proc_router.process_all_queues().unwrap();
    });

    let mut producers = Vec::new();
    for tid in 0..THREADS {
        let r = router.clone();
        producers.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                let idx = (tid * ITERS_PER_THREAD + i) as u64;
                let base = 1.0_f32 + idx as f32 * 0.001;
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[base, 2.0, 3.0],
                    &[DataEndpoint::named("SD_CARD")],
                    idx,
                )
                .unwrap();
                let wire = wire_format::pack_packet(&pkt);
                r.rx_packed_queue(&wire).unwrap();
            }
        }));
    }

    for t in producers {
        t.join().expect("producer thread panicked");
    }

    done.store(true, Ordering::SeqCst);
    processor.join().expect("processor thread panicked");

    assert_eq!(
        hits.load(Ordering::SeqCst),
        total,
        "expected {total} handler invocations from RTOS-like queued ingress"
    );
}

/// RTOS-like relay scenario: packets arrive from two sides while a worker
/// thread drains queues. Ensures side-tagged queue ingress remains stable.
#[test]
fn rtos_like_side_ingress_and_processing_no_deadlock() {
    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 60;
    let total = THREADS * ITERS_PER_THREAD;

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();
    let local = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let tx_count = Arc::new(AtomicUsize::new(0));
    let tx_c0 = tx_count.clone();
    let tx_c1 = tx_count.clone();

    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![local]),
        zero_clock(),
    ));

    let side0 = router.add_side_packed("S0", move |_b| {
        tx_c0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let side1 = router.add_side_packed("S1", move |_b| {
        tx_c1.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(side0, 0);
    assert_eq!(side1, 1);

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let proc_router = router.clone();
    let done_c = done.clone();
    let processor = thread::spawn(move || {
        while !done_c.load(Ordering::SeqCst) {
            proc_router.process_all_queues_with_timeout(1).unwrap();
        }
        proc_router.process_all_queues().unwrap();
    });

    let mut producers = Vec::new();
    for tid in 0..THREADS {
        let r = router.clone();
        producers.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                let idx = (tid * ITERS_PER_THREAD + i) as u64;
                let side = if (idx & 1) == 0 { 0 } else { 1 };
                let base = 10.0_f32 + idx as f32 * 0.01;
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[base, 2.0, 3.0],
                    &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
                    idx,
                )
                .unwrap();
                let wire = wire_format::pack_packet(&pkt);
                r.rx_packed_queue_from_side(&wire, side).unwrap();
            }
        }));
    }

    for t in producers {
        t.join().expect("producer thread panicked");
    }

    done.store(true, Ordering::SeqCst);
    processor.join().expect("processor thread panicked");

    assert_eq!(
        hits.load(Ordering::SeqCst),
        total,
        "expected local handler to see all side-tagged packets"
    );
    assert!(
        tx_count.load(Ordering::SeqCst) > 0,
        "relay mode should have forwarded packets to remote sides"
    );
}

/// A local handler can safely call back into the same Router (enqueueing
/// new work) without deadlocking queue processing.
#[test]
fn handler_can_reenter_router_without_deadlock() {
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;

    let router_ref: Arc<OnceLock<Arc<Router>>> = Arc::new(OnceLock::new());
    let triggered = Arc::new(AtomicBool::new(false));

    let h1_hits = Arc::new(AtomicUsize::new(0));
    let h2_hits = Arc::new(AtomicUsize::new(0));
    let h1_hits_c = h1_hits.clone();
    let h2_hits_c = h2_hits.clone();
    let triggered_c = triggered.clone();
    let router_ref_c = router_ref.clone();

    let h1 = EndpointHandler::new_packet_handler(DataEndpoint::named("SD_CARD"), move |_pkt| {
        h1_hits_c.fetch_add(1, Ordering::SeqCst);
        if !triggered_c.swap(true, Ordering::SeqCst) {
            let chained = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[9.0_f32, 8.0, 7.0],
                &[DataEndpoint::named("RADIO")],
                999,
            )?;
            let r = router_ref_c
                .get()
                .expect("router OnceLock should be initialized");
            r.rx_queue(chained)?;
        }
        Ok(())
    });

    let h2 = EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |_pkt| {
        h2_hits_c.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new(vec![h1, h2]),
        zero_clock(),
    ));
    router_ref
        .set(router.clone())
        .expect("router OnceLock should only be set once");

    let first = Packet::from_f32_slice(
        DataType::named("GPS_DATA"),
        &[1.0_f32, 2.0, 3.0],
        &[DataEndpoint::named("SD_CARD")],
        100,
    )
    .unwrap();
    router.rx_queue(first).unwrap();

    let (tx_done, rx_done) = mpsc::channel();
    let r = router.clone();
    thread::spawn(move || {
        let out = (|| -> TelemetryResult<()> {
            r.process_rx_queue()?;
            r.process_rx_queue()?;
            Ok(())
        })();
        let _ = tx_done.send(out);
    });

    let done = rx_done
        .recv_timeout(Duration::from_secs(2))
        .expect("processing timed out (possible deadlock)");
    done.expect("processing returned error");

    assert_eq!(h1_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        h2_hits.load(Ordering::SeqCst),
        1,
        "chained callback enqueue should be processed exactly once"
    );
}

// ------------------------------------------------------------------------
// Concurrent calls to receive_packed
// ------------------------------------------------------------------------

/// Multiple threads call `receive_packed` concurrently with the same
/// wire buffer; each call should fan out once to the handler.
#[test]
fn concurrent_receive_packed_is_thread_safe() {
    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 50;
    let total = THREADS * ITERS_PER_THREAD;

    // Handler that counts how many times it is invoked.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_c = hits.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            hits_c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    let r = Arc::new(router);

    let mut threads_vec = Vec::new();
    for tid in 0..THREADS {
        let r_cloned = r.clone();
        threads_vec.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                let idx = (tid * ITERS_PER_THREAD + i) as u64;
                let base = 1.0_f32 + idx as f32 * 0.001;
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[base, 2.0, 3.0],
                    &[DataEndpoint::named("SD_CARD")],
                    idx,
                )
                .unwrap();
                let wire = wire_format::pack_packet(&pkt);
                r_cloned.rx_packed(&wire).expect("receive_packed failed");
            }
        }));
    }

    for t in threads_vec {
        t.join().expect("receive thread panicked");
    }

    assert_eq!(
        hits.load(Ordering::SeqCst),
        total,
        "expected {total} handler invocations from receive_packed"
    );
}

// ------------------------------------------------------------------------
// Concurrent logging + processing
// ------------------------------------------------------------------------

/// One thread logs to TX queue while another drains queues; verify that
/// every logged packet is transmitted once and delivered once to the
/// local handler.
#[test]
fn concurrent_logging_and_processing_is_thread_safe() {
    use std::thread;

    const ITERS: usize = 200;

    // Count how many frames are actually transmitted on the "bus".
    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    // Local handler that counts how many packets it sees.
    let rx_count = Arc::new(AtomicUsize::new(0));
    let rxc = rx_count.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            rxc.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    // Shared router: TX + one local endpoint.
    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    router.add_side_packed("tx", tx);
    let r = Arc::new(router);

    // ---------------- Logger thread ----------------
    let r_logger = r.clone();
    let logger = thread::spawn(move || {
        for i in 0..ITERS {
            r_logger
                .log_queue(DataType::named("GPS_DATA"), &[1.0_f32, 5.9 + i as f32, 3.0])
                .expect("log_queue failed");
        }
    });

    // ---------------- Drainer thread ----------------
    let r_drain = r.clone();
    let rx_counter = rx_count.clone();
    let drainer = thread::spawn(move || {
        // Keep draining until we've seen all expected local handler invocations.
        while rx_counter.load(Ordering::SeqCst) < ITERS {
            r_drain
                .process_all_queues()
                .expect("process_all_queues failed");
            thread::yield_now();
        }
    });

    // Wait for both threads to finish.
    logger.join().expect("logger thread panicked");
    drainer.join().expect("drainer thread panicked");

    // After both threads are done, all queued messages should have been
    // transmitted and delivered to the local handler exactly once each.
    let rx = rx_count.load(Ordering::SeqCst);
    let tx = tx_count.load(Ordering::SeqCst);

    assert_eq!(rx, ITERS, "expected {ITERS} handler calls, got {rx}");
    assert_eq!(tx, ITERS, "expected {ITERS} TX frames, got {tx}");
}

/// Mix concurrent logging, RX-queue insertion, and queue draining; ensure
/// that all work is eventually processed exactly once.
#[test]
fn concurrent_log_receive_and_process_mix_is_thread_safe() {
    use std::thread;

    const LOG_ITERS: usize = 100;
    const RX_ITERS: usize = 100;

    let tx_count = Arc::new(AtomicUsize::new(0));
    let txc = tx_count.clone();
    let tx = move |bytes: &[u8]| -> TelemetryResult<()> {
        assert!(!bytes.is_empty());
        if packed_frame_type(bytes) == Some(DataType::named("GPS_DATA")) {
            txc.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };

    let rx_count = Arc::new(AtomicUsize::new(0));
    let rxc = rx_count.clone();
    let handler = EndpointHandler::new_packet_handler(
        DataEndpoint::named("SD_CARD"),
        move |_pkt: &Packet| {
            rxc.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    let router = Router::new_with_clock(RouterConfig::new(vec![handler]), zero_clock());
    router.add_side_packed("tx", tx);
    let r = Arc::new(router);

    // ---------- Logger thread ----------
    let r_logger = r.clone();
    let t_logger = thread::spawn(move || {
        for i in 0..LOG_ITERS {
            let base = 1.0_f32 + i as f32 * 0.01;
            r_logger
                .log_queue(DataType::named("GPS_DATA"), &[base, 2.0, 3.0])
                .expect("log_queue failed");
        }
    });

    // ---------- RX thread ----------
    let r_rx = r.clone();
    let t_rx = thread::spawn(move || {
        for i in 0..RX_ITERS {
            let base = 4.0_f32 + i as f32 * 0.01;
            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[base, 5.0, 6.0],
                &[DataEndpoint::named("SD_CARD")],
                i as u64,
            )
            .unwrap();
            r_rx.rx_queue(pkt).expect("rx_packet_to_queue failed");
        }
    });

    // ---------- Processor thread ----------
    let r_proc = r.clone();
    let rx_counter = rx_count.clone();
    let t_proc = thread::spawn(move || {
        while rx_counter.load(Ordering::SeqCst) < LOG_ITERS + RX_ITERS {
            r_proc
                .process_all_queues()
                .expect("process_all_queues failed");
            thread::yield_now();
        }
    });

    t_logger.join().expect("logger thread panicked");
    t_rx.join().expect("rx thread panicked");
    t_proc.join().expect("processor thread panicked");

    let tx = tx_count.load(Ordering::SeqCst);
    let rx = rx_count.load(Ordering::SeqCst);
    assert_eq!(tx, LOG_ITERS, "expected {LOG_ITERS} TX frames");
    assert_eq!(
        rx,
        LOG_ITERS + RX_ITERS,
        "expected {LOG_ITERS}+{RX_ITERS} handler invocations"
    );
}
