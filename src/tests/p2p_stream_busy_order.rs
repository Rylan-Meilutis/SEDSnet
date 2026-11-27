//! Frames of one P2P stream leave in the order the application sent them,
//! even when a side refuses one of them ("side tx busy": another thread is
//! inside that side's TX callback) and the next one is sent from a different
//! thread once the side is free again. The refused frame waits in the retry
//! queue; the later frame must queue behind it, not go out first.
//!
//! Synchronisation is by channels only: one thread is held inside the side's
//! TX callback while the first stream frame is sent, so that frame is refused
//! deterministically. Time is a manual clock.

use crate::TelemetryResult;
use crate::packet::Packet;
use crate::router::{P2pStreamEventKind, P2pStreamOperation, Router, RouterConfig};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

const CLIENT_PORT: u16 = 49_300;
const SERVER_PORT: u16 = 7_300;
const OTHER_PORT: u16 = 7_301;

struct Pair {
    client: Arc<Router>,
    server: Arc<Router>,
    now: Arc<AtomicU64>,
    /// Frames the client's side took, in the order it took them.
    to_server: Arc<Mutex<Vec<Packet>>>,
    /// Arms a one-shot hold inside the client's side TX callback.
    hold: Arc<AtomicBool>,
    /// Arms a one-shot "side tx busy" refusal from the client's side.
    refuse: Arc<AtomicBool>,
    held_rx: mpsc::Receiver<()>,
    release_tx: mpsc::SyncSender<()>,
    /// Stream payloads the server received, in order.
    server_data: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Pair {
    fn pump(&self) {
        for _ in 0..64 {
            self.now.fetch_add(1, Ordering::SeqCst);
            self.client.process_all_queues().unwrap();
            let frames: Vec<Packet> = core::mem::take(&mut *self.to_server.lock().unwrap());
            for pkt in &frames {
                self.server.rx_from_side(pkt, 0).unwrap();
            }
            self.server.process_all_queues().unwrap();
        }
    }
}

fn pair() -> Pair {
    crate::tests::ensure_common_test_schema();
    let now = Arc::new(AtomicU64::new(10_000));
    let clock = now.clone();
    let client = Arc::new(Router::new_with_clock(
        RouterConfig::default()
            .with_hostname("order-client")
            .with_dynamic_address(),
        Box::new(move || clock.load(Ordering::SeqCst)),
    ));
    let server_clock = now.clone();
    let server = Arc::new(Router::new_with_clock(
        RouterConfig::default()
            .with_hostname("order-server")
            .with_static_address(0x7300),
        Box::new(move || server_clock.load(Ordering::SeqCst)),
    ));

    let to_server = Arc::new(Mutex::new(Vec::<Packet>::new()));
    let hold = Arc::new(AtomicBool::new(false));
    let (held_tx, held_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let release_rx = Mutex::new(release_rx);
    let refuse = Arc::new(AtomicBool::new(false));
    let (sink, armed, refusing) = (to_server.clone(), hold.clone(), refuse.clone());
    client.add_side_packet("client-to-server", move |pkt: &Packet| -> TelemetryResult<()> {
        if refusing.swap(false, Ordering::SeqCst) {
            return Err(crate::TelemetryError::Io("side tx busy"));
        }
        if armed.swap(false, Ordering::SeqCst) {
            held_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }
        sink.lock().unwrap().push(pkt.clone());
        Ok(())
    });
    let client_rx = client.clone();
    server.add_side_packet("server-to-client", move |pkt: &Packet| client_rx.rx_from_side(pkt, 0));

    let server_data = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let data = server_data.clone();
    server
        .bind_p2p_stream_port(SERVER_PORT, move |event| {
            if event.kind == P2pStreamEventKind::Data {
                data.lock().unwrap().push(event.payload.to_vec());
            }
            Ok(())
        })
        .unwrap();
    server.bind_p2p_port(OTHER_PORT, |_| Ok(())).unwrap();
    client.bind_p2p_stream_port(CLIENT_PORT, |_| Ok(())).unwrap();

    let p = Pair { client, server, now, to_server, hold, refuse, held_rx, release_tx, server_data };
    for _ in 0..3 {
        p.client.announce_discovery().unwrap();
        p.server.announce_discovery().unwrap();
        p.pump();
    }
    p
}

fn run_once() {
    run_scenario(false);
}

/// `refuse_retry`: the side also refuses the first frame's first retry, after
/// the second frame has queued behind it.
fn run_scenario(refuse_retry: bool) {
    let p = pair();
    let stream = p
        .client
        .open_p2p_stream_to_hostname("order-server", SERVER_PORT, CLIENT_PORT)
        .unwrap();
    p.pump();

    // Thread H holds the side's TX callback with an unrelated frame.
    p.hold.store(true, Ordering::SeqCst);
    let holder_router = p.client.clone();
    let holder = thread::spawn(move || {
        holder_router
            .send_p2p_to_hostname("order-server", OTHER_PORT, CLIENT_PORT, b"other")
            .unwrap();
    });
    p.held_rx.recv().unwrap();

    // Thread A: the first stream frame is refused (side busy) and queued.
    let first = p.client.clone();
    thread::spawn(move || first.send_p2p_stream(stream, b"first").unwrap())
        .join()
        .unwrap();
    assert!(
        p.to_server.lock().unwrap().is_empty(),
        "the side took no frame while its callback was held"
    );

    // The side is free again.
    p.release_tx.send(()).unwrap();
    holder.join().unwrap();

    // Thread B: the second stream frame, sent while the first still waits
    // for its retry.
    let second = p.client.clone();
    thread::spawn(move || second.send_p2p_stream(stream, b"second").unwrap())
        .join()
        .unwrap();

    if refuse_retry {
        p.refuse.store(true, Ordering::SeqCst);
    }
    p.pump();
    assert!(!p.refuse.load(Ordering::SeqCst), "the side was offered a retry");
    let seen = p.server_data.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![b"first".to_vec(), b"second".to_vec()],
        "P2P stream frames reordered behind a side-busy retry"
    );
}

#[test]
fn p2p_stream_keeps_send_order_across_threads_when_side_busy() {
    run_once();
}

/// The same scenario repeated, for stability under parallel test load.
#[test]
fn p2p_stream_keeps_send_order_across_threads_when_side_busy_repeated() {
    for _ in 0..50 {
        run_once();
    }
}

/// The first frame's retry is refused again; it keeps its place ahead of
/// the second frame, which queued behind it.
#[test]
fn p2p_stream_keeps_send_order_when_side_refuses_the_retry() {
    for _ in 0..50 {
        run_scenario(true);
    }
}

/// A stream frame admitted to the queue (prepared send) and the next frame
/// of the same stream sent directly: the direct send queues behind it.
#[test]
fn p2p_stream_direct_send_follows_queued_prepared_frame() {
    let p = pair();
    let stream = p
        .client
        .open_p2p_stream_to_hostname("order-server", SERVER_PORT, CLIENT_PORT)
        .unwrap();
    p.pump();

    let mut prepared = p
        .client
        .prepare_p2p_stream_control(stream, P2pStreamOperation::Data(b"first"), None)
        .unwrap();
    p.client.try_queue_prepared_p2p(&mut prepared).unwrap();
    drop(prepared);
    p.client.send_p2p_stream(stream, b"second").unwrap();

    p.pump();
    let seen = p.server_data.lock().unwrap().clone();
    assert_eq!(seen, vec![b"first".to_vec(), b"second".to_vec()]);
}
