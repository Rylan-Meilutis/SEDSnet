//! Actual two-Router wire loss. Only wire delivery and the public clock are modeled.
//! No forced reliable headers, routes, metadata, retry state or counters.
use super::*;
use crate::ReliableMode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use super::HOP_FAILURE_FIXTURE_LOCK as FIXTURE;
static SCHEMA: Once = Once::new();
const ORDERED: &str = "HOP_TIMEOUT_CAUSAL_ORDERED";
const UNORDERED: &str = "HOP_TIMEOUT_CAUSAL_UNORDERED";
const MAX_WIRE: usize = 256;
const MAX_TRACE: usize = 4096;

#[derive(Default)]
struct Loss {
    armed: bool,
    once: bool,
    first_id: Option<u64>,
    first_seq: Option<u32>,
    dropped: usize,
}
#[derive(Default)]
struct Wire {
    pending: std::collections::VecDeque<(bool, Vec<u8>)>,
    trace: Vec<serde_json::Value>,
    loss: Loss,
}
impl Wire {
    fn emit(&mut self, forward: bool, bytes: &[u8], now: u64) -> TelemetryResult<()> {
        let frame = crate::wire_format::peek_frame_info(bytes)?;
        let id = crate::wire_format::packet_id_from_wire(bytes)?;
        let data = forward
            && frame.envelope.ty == DataType::named(ORDERED)
            && frame
                .reliable
                .is_some_and(|h| h.flags & crate::wire_format::RELIABLE_FLAG_ACK_ONLY == 0);
        let drop = data
            && self.loss.armed
            && (self.loss.first_id.is_none() || self.loss.first_id == Some(id))
            && (!self.loss.once || self.loss.dropped == 0);
        if drop {
            self.loss.first_id.get_or_insert(id);
            self.loss
                .first_seq
                .get_or_insert(frame.reliable.unwrap().seq);
            self.loss.dropped += 1;
        }
        assert!(
            self.trace.len() < MAX_TRACE,
            "bounded trace capacity exceeded"
        );
        self.trace.push(
            serde_json::json!({"forward":forward,"clock":now,"type":frame.envelope.ty.as_u32(),
            "id":id,"sourceUTC":frame.envelope.timestamp_ms,"sender":frame.envelope.sender.as_ref(),
            "reliable":frame.reliable.map(|h|(h.flags,h.seq,h.ack)),"dropped":drop,
            "wireHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()}),
        );
        if !drop {
            assert!(self.pending.len() < MAX_WIRE, "bounded wire FIFO exceeded");
            self.pending.push_back((forward, bytes.to_vec()));
        }
        Ok(())
    }
}
struct Scene {
    a: Router,
    b: Router,
    a_side: usize,
    b_side: usize,
    now: Arc<AtomicU64>,
    wire: Arc<Mutex<Wire>>,
    delivered: Arc<Mutex<Vec<(u64, u64, u32, Vec<u8>)>>>,
    errors: Vec<String>,
}
fn schema() {
    SCHEMA.call_once(|| {
        crate::tests::ensure_common_test_schema();
        let endpoint = DataEndpoint::named("SD_CARD");
        for (name, mode) in [
            (ORDERED, ReliableMode::Ordered),
            (UNORDERED, ReliableMode::Unordered),
        ] {
            crate::config::register_data_type_with_description(
                name,
                "actual hop exhaustion scene",
                MessageElement::Static(
                    3,
                    crate::MessageDataType::Float32,
                    crate::MessageClass::Data,
                ),
                &[endpoint],
                mode,
                1,
            )
            .unwrap();
        }
    });
}
impl Scene {
    fn new() -> Self {
        schema();
        let now = Arc::new(AtomicU64::new(10000));
        let wire = Arc::new(Mutex::new(Wire::default()));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let sink = delivered.clone();
        let a_now = now.clone();
        let b_now = now.clone();
        let a = Router::new_with_clock(
            RouterConfig::new(Vec::new())
                .with_sender("HOP_TIMEOUT_A")
                .with_reliable_enabled(true),
            Box::new(move || a_now.load(Ordering::Relaxed)),
        );
        let b = Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                move |p: &Packet| {
                    if p.data_type() == DataType::named(ORDERED)
                        || p.data_type() == DataType::named(UNORDERED)
                    {
                        sink.lock().unwrap().push((
                            p.packet_id(),
                            p.timestamp(),
                            p.data_type().as_u32(),
                            p.payload().to_vec(),
                        ));
                    }
                    Ok(())
                },
            )])
            .with_sender("HOP_TIMEOUT_B")
            .with_reliable_enabled(true),
            Box::new(move || b_now.load(Ordering::Relaxed)),
        );
        let out = wire.clone();
        let clock = now.clone();
        let a_side = a.add_side_packed_with_options(
            "TO_B",
            move |bytes| {
                out.lock()
                    .unwrap()
                    .emit(true, bytes, clock.load(Ordering::Relaxed))
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );
        let out = wire.clone();
        let clock = now.clone();
        let b_side = b.add_side_packed_with_options(
            "TO_A",
            move |bytes| {
                out.lock()
                    .unwrap()
                    .emit(false, bytes, clock.load(Ordering::Relaxed))
            },
            RouterSideOptions {
                reliable_enabled: true,
                ..RouterSideOptions::default()
            },
        );
        Self {
            a,
            b,
            a_side,
            b_side,
            now,
            wire,
            delivered,
            errors: Vec::new(),
        }
    }
    fn pump(&mut self) {
        for _ in 0..32 {
            if let Err(e) = self.a.process_all_queues_with_timeout(0) {
                self.errors.push(format!("A:{e:?}"));
            }
            if let Err(e) = self.b.process_all_queues_with_timeout(0) {
                self.errors.push(format!("B:{e:?}"));
            }
            let mut moved = 0;
            loop {
                let next = self.wire.lock().unwrap().pending.pop_front();
                let Some((forward, bytes)) = next else {
                    break;
                };
                moved += 1;
                assert!(moved <= MAX_WIRE, "wire circulation exceeded phase cap");
                let result = if forward {
                    self.b.rx_packed_from_side(&bytes, self.b_side)
                } else {
                    self.a.rx_packed_from_side(&bytes, self.a_side)
                };
                if let Err(e) = result {
                    self.errors.push(format!("RX({forward}):{e:?}"));
                }
            }
            if moved == 0 {
                break;
            }
        }
    }
    fn tick(&mut self) {
        self.now
            .fetch_add(runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
        self.pump();
    }
    fn send(&mut self, serial: u32, ordered: bool) -> (u64, u64) {
        let stamp = self.now.load(Ordering::Relaxed);
        let ty = DataType::named(if ordered { ORDERED } else { UNORDERED });
        let bytes = [serial as f32, serial as f32 + 0.5, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>();
        let packet = Packet::new(
            ty,
            &[DataEndpoint::named("SD_CARD")],
            "HOP_TIMEOUT_A",
            stamp,
            Arc::<[u8]>::from(bytes),
        )
        .unwrap()
        .with_nonce(u16::try_from(serial).unwrap());
        let id = packet.packet_id();
        let result = self.a.tx(packet);
        eprintln!("ACTUAL_INTENT serial={serial} id={id} UTC={stamp} result={result:?}");
        result.unwrap();
        self.pump();
        (id, stamp)
    }
    fn history_has(&self, id: u64) -> bool {
        let st = self.a.state.lock();
        st.end_to_end_reliable_tx.contains_key(&id)
            || st
                .reliable_tx
                .get(&(self.a_side, DataType::named(ORDERED).as_u32()))
                .is_some_and(|v| {
                    v.sent
                        .values()
                        .any(|s| crate::wire_format::packet_id_from_wire(&s.bytes).ok() == Some(id))
                })
    }
    fn snapshot(&self) -> serde_json::Value {
        let a = self.a.state.lock();
        let b = self.b.state.lock();
        let ty = DataType::named(ORDERED).as_u32();
        let tx = a.reliable_tx.get(&(self.a_side, ty));
        let rx = b.reliable_rx.get(&(self.b_side, ty));
        serde_json::json!({"clock":self.now.load(Ordering::Relaxed),"tx_next":tx.map(|s|s.next_seq),
            "tx_sent":tx.map(|s|s.sent.iter().map(|(seq,v)|(*seq,v.retries,v.queued,v.partial_acked)).collect::<Vec<_>>()),
            "rx_expected":rx.map(|s|s.expected_seq),"rx_buffered":rx.map(|s|s.buffered.keys().copied().collect::<Vec<_>>())})
    }
    fn report(&self, case: &str) {
        let snapshot = self.snapshot();
        let (loss_id, loss_seq, dropped, trace) = {
            let wire = self.wire.lock().unwrap();
            (
                wire.loss.first_id,
                wire.loss.first_seq,
                wire.loss.dropped,
                wire.trace.clone(),
            )
        };
        let value = serde_json::json!({"case":case,"snapshot":snapshot,"loss_id":loss_id,"loss_seq":loss_seq,
            "dropped":dropped,"wire":trace,"delivered":*self.delivered.lock().unwrap(),"errors":self.errors,
            "A_runtime":format!("{:?}",self.a.export_runtime_stats()),"B_runtime":format!("{:?}",self.b.export_runtime_stats()),
            "retry_interval":runtime_reliable_retransmit_ms(),"retry_max":runtime_reliable_max_retries(),"no_forced_state":true});
        let text = serde_json::to_string_pretty(&value).unwrap();
        assert!(text.len() < 64 * 1024 * 1024);
        if let Some(root) = std::env::var_os("HOP_TIMEOUT_TRACE_DIR") {
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(
                std::path::PathBuf::from(root).join(format!("{case}.json")),
                text,
            )
            .unwrap();
        } else {
            eprintln!("{text}");
        }
    }
}
// The original four-case RED fixture is retained unchanged in its own file.
#[test]
fn exhaustion_is_terminal_and_sticky() {
    let _serialized = FIXTURE.lock().unwrap_or_else(|p| p.into_inner());
    for warm in [false, true] {
        let mut s = Scene::new();
        if warm {
            s.send(1, true);
        }
        {
            let mut w = s.wire.lock().unwrap();
            w.loss.armed = true;
        }
        let lost = s.send(10, true);
        for _ in 0..(runtime_reliable_max_retries() + 2) * 2 {
            s.tick();
        }
        assert_eq!(
            s.errors
                .iter()
                .filter(|e| e.contains("ordered hop delivery exhausted retries"))
                .count(),
            1
        );
        {
            let st = s.a.state.lock();
            let tx = st
                .reliable_tx
                .get(&(s.a_side, DataType::named(ORDERED).as_u32()))
                .unwrap();
            assert_eq!(tx.next_seq, 0);
            assert!(tx.sent.is_empty());
            assert!(tx.sent_order.is_empty());
        }
        assert!(!s.history_has(lost.0));
        s.wire.lock().unwrap().loss.armed = false;
        let before = s
            .wire
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|v| v["type"] == DataType::named(ORDERED).as_u32())
            .count();
        for serial in 20..36 {
            let bytes = Arc::<[u8]>::from([0u8; 12]);
            let p = Packet::new(
                DataType::named(ORDERED),
                &[DataEndpoint::named("SD_CARD")],
                "HOP_TIMEOUT_A",
                s.now.load(Ordering::Relaxed),
                bytes,
            )
            .unwrap()
            .with_nonce(serial);
            assert!(s.a.tx(p).is_err());
        }
        assert_eq!(
            s.wire
                .lock()
                .unwrap()
                .trace
                .iter()
                .filter(|v| v["type"] == DataType::named(ORDERED).as_u32())
                .count(),
            before
        );
        s.a.handle_reliable_ack(s.a_side, DataType::named(ORDERED), u32::MAX);
        s.a.handle_reliable_partial_ack(s.a_side, DataType::named(ORDERED), 1);
        assert!(
            s.a.queue_reliable_retransmit(s.a_side, DataType::named(ORDERED), 1, true)
                .is_err()
        );
        s.a.clear_queues();
        s.a.set_side_egress_enabled(s.a_side, false).unwrap();
        s.a.set_side_egress_enabled(s.a_side, true).unwrap();
        assert_eq!(
            s.a.state
                .lock()
                .reliable_tx
                .get(&(s.a_side, DataType::named(ORDERED).as_u32()))
                .unwrap()
                .next_seq,
            0
        );
        let control = s.send(90, false);
        assert!(s.delivered.lock().unwrap().iter().any(|v| v.0 == control.0));
        s.report(if warm {
            "contract-warm"
        } else {
            "contract-cold"
        });
    }
}

#[test]
fn callback_owned_packet_cannot_resurrect_failed_history() {
    let _serialized = FIXTURE.lock().unwrap_or_else(|p| p.into_inner());
    schema();
    let now = Arc::new(AtomicU64::new(10000));
    let clock = now.clone();
    let a = Arc::new(Router::new_with_clock(
        RouterConfig::new(Vec::new())
            .with_sender("HOP_TIMEOUT_A")
            .with_reliable_enabled(true),
        Box::new(move || clock.load(Ordering::Relaxed)),
    ));
    let owner = Arc::downgrade(&a);
    let during = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let trigger = during.clone();
    let clock = now.clone();
    let results = Arc::new(Mutex::new(Vec::new()));
    let captured = results.clone();
    let side = a.add_side_packed_with_options(
        "DROPPED",
        move |bytes| {
            let frame = crate::wire_format::peek_frame_info(bytes)?;
            if frame.envelope.ty == DataType::named(ORDERED)
                && trigger.swap(false, Ordering::Relaxed)
            {
                clock.fetch_add(runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
                captured.lock().unwrap().push(format!(
                    "{:?}",
                    owner.upgrade().unwrap().process_reliable_timeouts()
                ));
            }
            Ok(()) // actual callback ownership, modeled wire loss
        },
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    let packet = |nonce| {
        Packet::new(
            DataType::named(ORDERED),
            &[DataEndpoint::named("SD_CARD")],
            "HOP_TIMEOUT_A",
            10000,
            Arc::<[u8]>::from([0u8; 12]),
        )
        .unwrap()
        .with_nonce(nonce)
    };
    a.tx(packet(1)).unwrap();
    for _ in 0..runtime_reliable_max_retries() {
        now.fetch_add(runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
        a.process_all_queues_with_timeout(0).unwrap();
    }
    during.store(true, Ordering::Relaxed);
    assert!(a.tx(packet(2)).is_err()); // callback already owned bytes: no zero-issued claim
    assert!(
        results
            .lock()
            .unwrap()
            .iter()
            .any(|v| v.contains("ordered hop delivery exhausted retries"))
    );
    let st = a.state.lock();
    let tx = st
        .reliable_tx
        .get(&(side, DataType::named(ORDERED).as_u32()))
        .unwrap();
    assert_eq!(tx.next_seq, 0);
    assert!(tx.sent.is_empty());
    assert!(tx.sent_order.is_empty());
}

#[test]
fn exhausted_ordered_error_wins_over_actual_replay_queue_refusal() {
    let _serialized = FIXTURE.lock().unwrap_or_else(|p| p.into_inner());
    schema();
    crate::config::register_data_type_with_description(
        "HOP_TIMEOUT_PROTECTED_QUEUE",
        "protected capacity fixture",
        MessageElement::Static(
            3,
            crate::MessageDataType::Float32,
            crate::MessageClass::Data,
        ),
        &[DataEndpoint::named("SD_CARD")],
        ReliableMode::Ordered,
        255,
    )
    .unwrap();
    let protected = DataType::named("HOP_TIMEOUT_PROTECTED_QUEUE");
    crate::config::register_data_type_with_description(
        "HOP_TIMEOUT_LARGE_UNORDERED",
        "large actual replay",
        MessageElement::Static(
            256,
            crate::MessageDataType::Float32,
            crate::MessageClass::Data,
        ),
        &[DataEndpoint::named("SD_CARD")],
        ReliableMode::Unordered,
        1,
    )
    .unwrap();
    let large = DataType::named("HOP_TIMEOUT_LARGE_UNORDERED");
    let now = Arc::new(AtomicU64::new(10000));
    let clock = now.clone();
    let a = Router::new_with_clock(
        RouterConfig::new(Vec::new())
            .with_sender("HOP_TIMEOUT_A")
            .with_reliable_enabled(true),
        Box::new(move || clock.load(Ordering::Relaxed)),
    );
    let side = a.add_side_packed_with_options(
        "MODELED_LOSS",
        |_bytes| Ok(()),
        RouterSideOptions {
            reliable_enabled: true,
            ..RouterSideOptions::default()
        },
    );
    let packet = |ty, nonce| {
        Packet::new(
            ty,
            &[DataEndpoint::named("SD_CARD")],
            "HOP_TIMEOUT_A",
            now.load(Ordering::Relaxed),
            Arc::<[u8]>::from([0u8; 12]),
        )
        .unwrap()
        .with_nonce(nonce)
    };
    a.tx(packet(DataType::named(ORDERED), 1)).unwrap();
    for _ in 0..runtime_reliable_max_retries() {
        now.fetch_add(runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
        a.process_all_queues_with_timeout(0).unwrap();
    }
    let unordered_started = now.load(Ordering::Relaxed);
    a.tx(Packet::new(
        large,
        &[DataEndpoint::named("SD_CARD")],
        "HOP_TIMEOUT_A",
        unordered_started,
        Arc::<[u8]>::from([0u8; 1024]),
    )
    .unwrap()
    .with_nonce(2))
        .unwrap();
    let mut accepted = 0;
    let capacity_error = loop {
        assert!(
            accepted < 10000,
            "bounded public admission did not saturate"
        );
        match a.tx_queue(packet(protected, 100 + accepted)) {
            Ok(()) => accepted += 1,
            Err(e) => break e,
        }
    };
    assert!(accepted > 0);
    eprintln!("REAL_PROTECTED_QUEUE_CAPACITY accepted={accepted} error={capacity_error:?}");
    now.fetch_add(runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
    // Prove this exact normal replay admission is refused before service,
    // without changing retry counters, headers, queue contents or history.
    let before = a.queue_reliable_retransmit(side, large, 1, true);
    assert!(
        before.is_err(),
        "premise: actual replay queue must be saturated"
    );
    let result = a.process_reliable_timeouts();
    assert!(matches!(
        result,
        Err(TelemetryError::HandlerError(
            "ordered hop delivery exhausted retries"
        ))
    ));
    let st = a.state.lock();
    let ordered = st
        .reliable_tx
        .get(&(side, DataType::named(ORDERED).as_u32()))
        .unwrap();
    assert_eq!(ordered.next_seq, 0);
    assert!(ordered.sent.is_empty());
    let unordered = st
        .reliable_tx
        .get(&(side, large.as_u32()))
        .unwrap()
        .sent
        .get(&1)
        .unwrap();
    // Refused replay admission is not a completed wire offer.
    assert_eq!(unordered.retries, 0);
    assert!(!unordered.first_offer.pending());
    assert_eq!(
        unordered.offer_stamp, unordered_started,
        "actual timeout replay must also have refused admission"
    );
    eprintln!(
        "REAL_MIXED_FAILURE result={result:?} replay_before={before:?} unordered_retries={} last_send={} now={}",
        unordered.retries,
        unordered.offer_stamp,
        now.load(Ordering::Relaxed)
    );
}
