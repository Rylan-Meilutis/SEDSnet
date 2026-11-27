//! An Ordered hop stream across an outage longer than its retry window.
//!
//! Two routers joined by one hop-reliable link. The link goes down for longer
//! than the hop retry window, so the sender gives up on the frames in flight
//! ("ordered hop delivery exhausted retries", reported once). Before 7.0.3 the
//! stream then stayed failed until the side was removed: every later frame of
//! that type on that side was refused with "ordered hop stream failed" (one
//! "tx handler failed" per frame). Now, once the link is back, the stream
//! finds where the receiver stands and resumes: in order, without
//! duplicates, and without an error per frame.
//!
//! Time is a manual clock; the wire is a FIFO. "Replies" outages lose only the
//! receiver's ACKs, so the receiver holds frames the sender gave up on;
//! "Held" outages keep those ACKs and deliver them late, after the sender
//! gave up (a radio or modem that buffers through the outage).

use super::{EndpointHandler, Router, RouterConfig, RouterSideOptions};
use crate::config::{DataEndpoint, DataType};
use crate::packet::Packet;
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode, TelemetryResult};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const TYPE: &str = "HOP_OUTAGE_RESYNC_ORDERED";
const ENDPOINT: &str = "HOP_OUTAGE_RESYNC_EP";

fn ordered_type() -> DataType {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::try_named(ENDPOINT)
        .unwrap_or_else(|| crate::config::register_endpoint(ENDPOINT, false).unwrap());
    DataType::try_named(TYPE).unwrap_or_else(|| {
        crate::config::register_data_type_with_description(
            TYPE,
            "hop outage resync",
            MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
            &[endpoint],
            ReliableMode::Ordered,
            50,
        )
        .unwrap()
    })
}

/// Which directions of the link are down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Down {
    Up,
    /// Everything is lost both ways.
    Both,
    /// Only the receiver's replies are lost: frames still arrive.
    Replies,
    /// The receiver's replies are held and delivered when the link returns.
    Held,
}

#[derive(Default)]
struct Wire {
    /// (toward the receiver B, bytes)
    pending: VecDeque<(bool, Vec<u8>)>,
    /// Replies held through a `Held` outage.
    held: VecDeque<Vec<u8>>,
}

struct Scene {
    a: Router,
    b: Router,
    a_side: usize,
    b_side: usize,
    now: Arc<AtomicU64>,
    wire: Arc<Mutex<Wire>>,
    down: Arc<Mutex<Down>>,
    delivered: Arc<Mutex<Vec<u32>>>,
    errors: Vec<String>,
    ty: DataType,
}

impl Scene {
    fn new() -> Self {
        let ty = ordered_type();
        let now = Arc::new(AtomicU64::new(10_000));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let sink = delivered.clone();
        let (a_now, b_now) = (now.clone(), now.clone());
        let a = Router::new_with_clock(
            RouterConfig::new(Vec::new())
                .with_sender("HOP_OUTAGE_A")
                .with_reliable_enabled(true),
            Box::new(move || a_now.load(Ordering::Relaxed)),
        );
        let b = Router::new_with_clock(
            RouterConfig::new([EndpointHandler::new_packet_handler(
                DataEndpoint::named(ENDPOINT),
                move |p: &Packet| -> TelemetryResult<()> {
                    if p.data_type() == ty {
                        sink.lock().unwrap().push(p.data_as_u32()?[0]);
                    }
                    Ok(())
                },
            )])
            .with_sender("HOP_OUTAGE_B")
            .with_reliable_enabled(true),
            Box::new(move || b_now.load(Ordering::Relaxed)),
        );
        let wire = Arc::new(Mutex::new(Wire::default()));
        let down = Arc::new(Mutex::new(Down::Up));
        let opts = RouterSideOptions { reliable_enabled: true, ..RouterSideOptions::default() };
        let (out, gate) = (wire.clone(), down.clone());
        let a_side = a.add_side_packed_with_options(
            "TO_B",
            move |bytes: &[u8]| {
                if *gate.lock().unwrap() != Down::Both {
                    out.lock().unwrap().pending.push_back((true, bytes.to_vec()));
                }
                Ok(())
            },
            opts.clone(),
        );
        let (out, gate) = (wire.clone(), down.clone());
        let b_side = b.add_side_packed_with_options(
            "TO_A",
            move |bytes: &[u8]| {
                let mut wire = out.lock().unwrap();
                match *gate.lock().unwrap() {
                    Down::Up => wire.pending.push_back((false, bytes.to_vec())),
                    Down::Held => wire.held.push_back(bytes.to_vec()),
                    Down::Both | Down::Replies => {}
                }
                Ok(())
            },
            opts,
        );
        Self { a, b, a_side, b_side, now, wire, down, delivered, errors: Vec::new(), ty }
    }

    fn set_down(&self, down: Down) {
        *self.down.lock().unwrap() = down;
        if down == Down::Up {
            let mut wire = self.wire.lock().unwrap();
            let held: Vec<_> = wire.held.drain(..).collect();
            wire.pending.extend(held.into_iter().map(|bytes| (false, bytes)));
        }
    }

    fn pump(&mut self) {
        for _ in 0..64 {
            if let Err(e) = self.a.process_all_queues_with_timeout(0) {
                self.errors.push(format!("A:{e:?}"));
            }
            if let Err(e) = self.b.process_all_queues_with_timeout(0) {
                self.errors.push(format!("B:{e:?}"));
            }
            let frames: Vec<_> = self.wire.lock().unwrap().pending.drain(..).collect();
            if frames.is_empty() {
                break;
            }
            for (forward, bytes) in frames {
                let result = if forward {
                    self.b.rx_packed_from_side(&bytes, self.b_side)
                } else {
                    self.a.rx_packed_from_side(&bytes, self.a_side)
                };
                if let Err(e) = result {
                    self.errors.push(format!("RX({forward}):{e:?}"));
                }
            }
        }
    }

    /// One retransmit interval passes.
    fn tick(&mut self) {
        self.now.fetch_add(crate::config::runtime_reliable_retransmit_ms() + 1, Ordering::Relaxed);
        self.pump();
    }

    fn ticks(&mut self, n: u32) {
        for _ in 0..n {
            self.tick();
        }
    }

    /// Longer than the whole retry window.
    fn outage_ticks() -> u32 {
        crate::config::runtime_reliable_max_retries() * 2 + 4
    }

    fn send(&mut self, value: u32) {
        let packet = Packet::new(
            self.ty,
            &[DataEndpoint::named(ENDPOINT)],
            "HOP_OUTAGE_A",
            self.now.load(Ordering::Relaxed),
            Arc::<[u8]>::from(value.to_le_bytes()),
        )
        .unwrap();
        if let Err(e) = self.a.tx(packet) {
            self.errors.push(format!("TX({value}):{e:?}"));
        }
        self.pump();
    }

    fn count(&self, needle: &str) -> usize {
        self.errors.iter().filter(|e| e.contains(needle)).count()
    }

    /// Errors other than the one-time exhaustion reports.
    fn other_errors(&self) -> Vec<&String> {
        self.errors.iter().filter(|e| !e.contains("delivery exhausted retries")).collect()
    }

}

// ---------------------------------------------------------------------------
// SEDSnet's own Ordered control stream (Schema), as in the field: B's Schema
// to A exhausts while A's link back is down, and must flow again afterwards.
// ---------------------------------------------------------------------------

#[cfg(feature = "discovery")]
mod schema_stream {
    use super::*;

    fn schema_state(s: &Scene) -> (u32, usize, bool, u32) {
        let ty = DataType::DiscoverySchema.as_u32();
        let b = s.b.state.lock();
        let tx = b.reliable_tx.get(&(s.b_side, ty)).expect("B has a Schema hop stream");
        let a = s.a.state.lock();
        let expected = a.reliable_rx.get(&(s.a_side, ty)).map_or(1, |rx| rx.expected_seq);
        (tx.next_seq, tx.sent.len(), tx.resync.is_some(), expected)
    }

    fn run(down: Down) {
        let mut s = Scene::new();
        s.send(1);
        s.ticks(2);
        s.set_down(down);
        // A asks for B's Schema while its replies cannot get through.
        s.a.request_schema().unwrap();
        s.send(2);
        s.ticks(Scene::outage_ticks());
        assert_eq!(s.count("ordered hop delivery exhausted retries"), 1, "{:?}", s.errors);
        // Still down: requests for B's Schema wait instead of failing.
        s.a.request_schema().unwrap();
        s.ticks(4);
        assert!(s.other_errors().is_empty(), "no error per frame while down: {:?}", s.errors);

        s.set_down(Down::Up);
        s.ticks(12);
        let (next, history, resyncing, _) = schema_state(&s);
        assert!(next != 0 && !resyncing, "Schema stream resumed: next={next}");
        assert_eq!(history, 0, "Schema stream drained");

        // And keeps working: two more Schema rounds reach A in order.
        let (_, _, _, before) = schema_state(&s);
        for _ in 0..2 {
            s.a.request_schema().unwrap();
            s.ticks(4);
        }
        let (next, history, resyncing, after) = schema_state(&s);
        assert!(after > before, "A received B's Schema again ({before} -> {after})");
        assert_eq!(after, next, "A expects exactly B's next sequence: no gap, no repeat");
        assert!(!resyncing && history == 0);
        let errors = s.other_errors();
        assert!(errors.is_empty(), "no error after the exhaustion: {errors:?}");
    }

    #[test]
    fn schema_stream_resumes_after_replies_were_lost_longer_than_its_retries() {
        run(Down::Replies);
    }

    #[test]
    fn schema_stream_resumes_after_replies_were_held_longer_than_its_retries() {
        run(Down::Held);
    }
}

// ---------------------------------------------------------------------------
// An application Ordered type on the hop alone. The frames go straight to the
// hop layer (no end-to-end receipt above it); a frame the hop refuses waits
// in the sender's own FIFO, as the router's queue holds it.
// ---------------------------------------------------------------------------

mod application_stream {
    use super::*;
    use crate::router::RouterItem;

    struct Hop {
        s: Scene,
        backlog: VecDeque<u32>,
        stamp: u64,
    }

    impl Hop {
        fn new() -> Self {
            Self { s: Scene::new(), backlog: VecDeque::new(), stamp: 1 }
        }

        fn flush(&mut self) {
            while let Some(&value) = self.backlog.front() {
                self.stamp += 1;
                let packet = Packet::new(
                    self.s.ty,
                    &[DataEndpoint::named(ENDPOINT)],
                    "HOP_OUTAGE_A",
                    self.stamp,
                    Arc::<[u8]>::from(value.to_le_bytes()),
                )
                .unwrap();
                match self.s.a.send_reliable_to_side(self.s.a_side, RouterItem::Packet(packet), false) {
                    Ok(()) => {
                        self.backlog.pop_front();
                    }
                    Err(e) if Router::is_transient_tx_error(&e) => break,
                    Err(e) => {
                        self.s.errors.push(format!("HOP({value}):{e:?}"));
                        self.backlog.pop_front();
                    }
                }
            }
        }

        fn send(&mut self, value: u32) {
            self.backlog.push_back(value);
            self.flush();
            self.s.pump();
        }

        fn ticks(&mut self, n: u32) {
            for _ in 0..n {
                self.flush();
                self.s.tick();
            }
        }
    }

    fn run(down: Down) -> Hop {
        let mut h = Hop::new();
        h.send(1);
        h.ticks(1);
        assert_eq!(*h.s.delivered.lock().unwrap(), vec![1]);

        h.s.set_down(down);
        h.send(2);
        h.send(3);
        h.ticks(Scene::outage_ticks());
        // A gives up on 2 and 3 once (B's own Schema stream to A may give up
        // too while A's replies are down; it resumes the same way).
        assert_eq!(h.s.count("A:HandlerError(\"ordered hop delivery exhausted retries"), 1, "{:?}", h.s.errors);

        // Frames sent while still down wait (here in the backlog); nothing
        // is sent into a gap and no error is reported per frame.
        h.send(4);
        h.send(5);
        h.ticks(8);
        assert_eq!(h.backlog.len(), 2, "frames wait while the stream resynchronises");

        h.s.set_down(Down::Up);
        h.ticks(12);
        h.send(6);
        h.ticks(6);
        assert!(h.backlog.is_empty());
        h
    }

    fn assert_resumed(h: &Hop, lost: &[u32]) {
        let delivered = h.s.delivered.lock().unwrap().clone();
        let expected: Vec<u32> = (1..=6).filter(|v| !lost.contains(v)).collect();
        let errors = h.s.other_errors();
        assert!(errors.is_empty(), "no error after the exhaustion: {errors:?}");
        assert_eq!(delivered, expected, "in order, no duplicates");
        let st = h.s.a.state.lock();
        let tx = st.reliable_tx.get(&(h.s.a_side, h.s.ty.as_u32())).unwrap();
        assert!(tx.resync.is_none() && tx.sent.is_empty() && tx.next_seq != 0);
    }

    #[test]
    fn application_hop_stream_resumes_after_an_outage_longer_than_its_retries() {
        let h = run(Down::Both);
        // 2 and 3 were in flight when the sender gave up and never arrived.
        assert_resumed(&h, &[2, 3]);
    }

    #[test]
    fn application_hop_stream_resumes_when_only_the_acks_were_lost() {
        let h = run(Down::Replies);
        // 2 and 3 arrived (only their ACKs were lost): nothing repeats.
        assert_resumed(&h, &[]);
    }

    #[test]
    fn application_hop_stream_resumes_when_the_acks_arrive_late() {
        let h = run(Down::Held);
        assert_resumed(&h, &[]);
    }
}
