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
type DeliveredPacket = (u64, u64, u32, Vec<u8>);
type DeliveredPackets = Arc<Mutex<Vec<DeliveredPacket>>>;

struct Scene {
    a: Router,
    b: Router,
    a_side: usize,
    b_side: usize,
    now: Arc<AtomicU64>,
    wire: Arc<Mutex<Wire>>,
    delivered: DeliveredPackets,
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
    fn ids(&self) -> Vec<u64> {
        self.delivered
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v.2 == DataType::named(ORDERED).as_u32())
            .map(|v| v.0)
            .collect()
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
fn scene(case: &str) {
    let _serialized = FIXTURE.lock().unwrap_or_else(|p| p.into_inner());
    let mut s = Scene::new();
    let max = runtime_reliable_max_retries();
    assert!(max <= 16, "bounded scene requires recorded baseline config");
    let mut expected = Vec::new();
    if case == "healthy" {
        for serial in 1..=3 {
            expected.push(s.send(serial, true).0);
        }
        s.report(case);
        assert_eq!(s.ids(), expected);
        return;
    }
    if case == "warm_exhaustion" {
        expected.push(s.send(1, true).0);
        assert_eq!(s.ids(), expected);
    }
    {
        let mut w = s.wire.lock().unwrap();
        w.loss.armed = true;
        w.loss.once = case == "recoverable";
    }
    let lost = s.send(10, true);
    if case == "recoverable" {
        s.tick();
        expected.push(lost.0);
        expected.push(s.send(11, true).0);
        s.report(case);
        assert_eq!(s.ids(), expected);
        return;
    }
    for _ in 0..(max + 2) * (max + 2) {
        s.tick();
        if !s.history_has(lost.0) {
            break;
        }
    }
    let still_retained = s.history_has(lost.0);
    s.report(&format!("{case}-before-restore"));
    assert!(
        !still_retained,
        "premise failed: original has not naturally retired in bounded retry scene"
    );
    {
        let mut w = s.wire.lock().unwrap();
        assert!(w.loss.dropped > 1);
        assert_eq!(w.loss.first_id, Some(lost.0));
        w.loss.armed = false;
    }
    let b = s.send(20, true);
    let c = s.send(21, true);
    let control = s.send(90, false);
    for _ in 0..(max + 2) * (max + 2) {
        s.tick();
    }
    s.report(case);
    assert!(
        s.delivered.lock().unwrap().iter().any(|v| v.0 == control.0),
        "premise failed: restored normal wire/control not alive"
    );
    // The first owner may already have an explicit E2E error. This assertion
    // checks NEW actually accepted intents after restoration, not revival of A.
    let delivered = s.ids();
    assert!(
        delivered.contains(&b.0) && delivered.contains(&c.0),
        "accepted later Ordered intents stalled after natural retry retirement and real link restoration"
    );
}
#[test]
fn actual_ordered_hop_healthy() {
    scene("healthy")
}
#[test]
fn actual_ordered_hop_recoverable_loss() {
    scene("recoverable")
}
#[cfg(feature = "discovery")]
#[test]
fn actual_ordered_hop_cold_exhaustion() {
    scene("cold_exhaustion")
}
#[cfg(feature = "discovery")]
#[test]
fn actual_ordered_hop_warm_exhaustion() {
    scene("warm_exhaustion")
}
