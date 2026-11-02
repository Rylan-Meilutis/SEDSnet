#![cfg(feature = "std")]

use sedsnet::{
    MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryError,
    config::{DataEndpoint, DataType, register_data_type, register_endpoint},
    packet::Packet,
    router::{EndpointHandler, Router, RouterConfig},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

fn schema(name: &str) -> (DataType, DataEndpoint) {
    let endpoint = register_endpoint(name, false).unwrap();
    let ty = register_data_type(
        name,
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[endpoint],
        ReliableMode::Unordered,
        128,
    )
    .unwrap();
    (ty, endpoint)
}

fn packet(ty: DataType, endpoint: DataEndpoint, value: u8) -> Packet {
    Packet::new(ty, &[endpoint], "producer", 10, Arc::from([value])).unwrap()
}

#[test]
fn queue_budget_refusal_and_delivery_order_match_blocking_queue() {
    let endpoint = register_endpoint("TRY_TX_QUEUE_PARITY", false).unwrap();
    let ty = register_data_type(
        "TRY_TX_QUEUE_PARITY",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Error),
        &[endpoint],
        ReliableMode::Unordered,
        128,
    )
    .unwrap();
    let captured = |rows: Arc<Mutex<Vec<u8>>>| {
        let memory = sedsnet::config::RuntimeMemoryConfig::new(8192, 32, 512, 1.0).unwrap();
        Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(
                endpoint,
                move |packet| {
                    rows.lock().unwrap().push(packet.payload()[0]);
                    Ok(())
                },
            )])
            .with_sender("sink")
            .with_memory_config(memory)
            .unwrap(),
            Box::new(|| 10),
        )
    };
    let old_rows = Arc::new(Mutex::new(Vec::new()));
    let new_rows = Arc::new(Mutex::new(Vec::new()));
    let old = captured(old_rows.clone());
    let new = captured(new_rows.clone());
    let mut count = 0;
    for index in 0..512 {
        let candidate = packet(ty, endpoint, index as u8);
        let old_result = old.tx_queue(candidate.clone());
        let new_result = new.try_tx_queue(candidate);
        assert_eq!(old_result.is_ok(), new_result.is_ok());
        if old_result.is_err() {
            assert_eq!(format!("{old_result:?}"), format!("{new_result:?}"));
            break;
        }
        count += 1;
    }
    assert!(
        count > 0 && count < 512,
        "must actually exercise finite queue refusal: {count}"
    );
    assert!(old_rows.lock().unwrap().is_empty());
    assert!(new_rows.lock().unwrap().is_empty());
    assert_eq!(
        old.export_runtime_stats().queues.tx_len,
        new.export_runtime_stats().queues.tx_len
    );
    old.drain_queues_with_timeout(0).unwrap();
    new.drain_queues_with_timeout(0).unwrap();
    assert_eq!(*old_rows.lock().unwrap(), *new_rows.lock().unwrap());
    assert_eq!(old_rows.lock().unwrap().len(), count);
}

#[test]
fn managed_type_priority_and_deferred_callback_match_blocking_queue() {
    let (ordinary, ordinary_endpoint) = schema("TRY_TX_QUEUE_ORDINARY_ORDER");
    let (managed, managed_endpoint) = schema("TRY_TX_QUEUE_MANAGED_ORDER");
    let run = |nonwaiting: bool| {
        let output = Arc::new(Mutex::new(Vec::new()));
        let ordinary_output = output.clone();
        let managed_output = output.clone();
        let router = Router::new_with_clock(
            RouterConfig::new([
                EndpointHandler::new_packet_handler(ordinary_endpoint, move |packet| {
                    ordinary_output
                        .lock()
                        .unwrap()
                        .push((packet.data_type(), packet.payload()[0]));
                    Ok(())
                }),
                EndpointHandler::new_packet_handler(managed_endpoint, move |packet| {
                    managed_output
                        .lock()
                        .unwrap()
                        .push((packet.data_type(), packet.payload()[0]));
                    Ok(())
                }),
            ])
            .with_sender("sink"),
            Box::new(|| 10),
        );
        router.enable_managed_variable(managed).unwrap();
        for packet in [
            packet(ordinary, ordinary_endpoint, 1),
            packet(managed, managed_endpoint, 2),
        ] {
            if nonwaiting {
                router.try_tx_queue(packet).unwrap();
            } else {
                router.tx_queue(packet).unwrap();
            }
        }
        assert!(output.lock().unwrap().is_empty());
        router.drain_queues_with_timeout(0).unwrap();
        output.lock().unwrap().clone()
    };
    let old = run(false);
    let new = run(true);
    assert_eq!(old, new);
    assert_eq!(new.len(), 2);
    assert_eq!(
        new[0].0, managed,
        "managed scheduling priority is preserved"
    );
}

#[test]
#[cfg(feature = "discovery")]
fn held_public_core_refuses_without_waiting_or_admitting_then_retries_exact_packet() {
    let (seed_ty, seed_endpoint) = schema("TRY_TX_QUEUE_HELD_SEED");
    let (ty, endpoint) = schema("TRY_TX_QUEUE_HELD_CONTROL");
    let armed = Arc::new(AtomicBool::new(false));
    let paused = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }
    let release = Release(paused.clone());
    let (entered, reached) = std::sync::mpsc::channel();
    let clock_armed = armed.clone();
    let clock_paused = paused.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let received = Arc::new(Mutex::new(Vec::new()));
    let callback_received = received.clone();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(
            endpoint,
            move |packet| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                callback_received.lock().unwrap().push((
                    packet.packet_id(),
                    packet.timestamp(),
                    packet.payload().to_vec(),
                ));
                Ok(())
            },
        )])
        .with_sender("sink"),
        Box::new(move || {
            if clock_armed.load(Ordering::SeqCst)
                && std::thread::current().name() == Some("try-tx-core-holder")
            {
                let _ = entered.send(());
                let mut finished = clock_paused.0.lock().unwrap();
                while !*finished {
                    finished = clock_paused.1.wait(finished).unwrap();
                }
            }
            10
        }),
    ));
    router.enable_managed_variable(seed_ty).unwrap();
    let held_router = router.clone();
    armed.store(true, Ordering::SeqCst);
    let holder = std::thread::Builder::new()
        .name("try-tx-core-holder".into())
        .spawn(move || held_router.seed_managed_variable(packet(seed_ty, seed_endpoint, 1)))
        .unwrap();
    reached
        .recv_timeout(Duration::from_secs(2))
        .expect("actual public managed-cache clock reached under router core");
    let candidate = packet(ty, endpoint, 7);
    let identity = candidate.packet_id();
    let started = Instant::now();
    let refusal = router.try_tx_queue(candidate.clone());
    let elapsed = started.elapsed();
    drop(release);
    holder.join().unwrap().unwrap();
    assert!(matches!(
        refusal,
        Err(TelemetryError::Io("router core busy"))
    ));
    assert!(
        elapsed < Duration::from_millis(100),
        "core contention must not wait: {elapsed:?}"
    );
    assert!(!router.has_queued_work());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    router.try_tx_queue(candidate).unwrap();
    assert!(router.has_queued_work());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "admission must not call endpoint handlers"
    );
    router.drain_queues_with_timeout(0).unwrap();
    assert_eq!(*received.lock().unwrap(), [(identity, 10, vec![7])]);
}

#[test]
#[cfg(feature = "discovery")]
fn poisoned_public_core_panics_instead_of_reporting_retryable_busy() {
    let (ty, endpoint) = schema("TRY_TX_QUEUE_POISON_CORE");
    let armed = Arc::new(AtomicBool::new(false));
    let clock_armed = armed.clone();
    let router = Arc::new(Router::new_with_clock(
        RouterConfig::new([]).with_sender("poison-probe"),
        Box::new(move || {
            assert!(
                !clock_armed.load(Ordering::SeqCst),
                "deliberate core poison"
            );
            10
        }),
    ));
    router.enable_managed_variable(ty).unwrap();
    armed.store(true, Ordering::SeqCst);
    let holder = router.clone();
    assert!(
        std::thread::spawn(move || {
            holder
                .seed_managed_variable(packet(ty, endpoint, 1))
                .unwrap();
        })
        .join()
        .is_err()
    );
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        router.try_tx_queue(packet(ty, endpoint, 2))
    }))
    .expect_err("poison must remain fatal, not a retryable busy result");
    let message = failure
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| failure.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("");
    assert!(message.contains("RouterMutex poisoned"), "{message}");
}
