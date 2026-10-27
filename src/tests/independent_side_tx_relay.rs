use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
struct Frozen;
impl crate::router::Clock for Frozen {
    fn now_ms(&self) -> u64 {
        0
    }
}
#[test]
fn blocked_transport_does_not_block_an_independent_side_but_serializes_itself() {
    let r = Arc::new(Relay::new(Box::new(Frozen)));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let a = r.add_side_packet("blocked Ethernet", move |_| {
        entered_tx.send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        Ok(())
    });
    let hits = Arc::new(AtomicUsize::new(0));
    let hc = hits.clone();
    let b = r.add_side_packet("independent radio", move |_| {
        hc.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let endpoint = crate::config::register_endpoint("SIDE_GATE_relay_DEST", false).unwrap();
    let ty = crate::config::register_data_type_with_description(
        "SIDE_GATE_relay_VALUE",
        "independent callback test",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        16,
    )
    .unwrap();
    let packet = crate::packet::Packet::new_local(
        ty,
        crate::message_meta(ty).endpoints_owned(),
        Arc::from("GS"),
        1,
        crate::config::StandardSmallPayload::new(&[1]),
    )
    .unwrap();
    let data = RouterItem::Packet(packet);
    let data_a = data.clone();
    let rc = r.clone();
    let worker = std::thread::spawn(move || {
        let r = rc;
        r.send_reliable_to_side(a, data_a, true)
    });
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(r.side_tx_active());
    assert!(
        r.remove_side(a).is_err(),
        "busy side must not be replaced mid-callback"
    );
    let other = r.send_reliable_to_side(b, data.clone(), true);
    let same = r.send_reliable_to_side(a, data.clone(), true);
    assert!(
        r.side_tx_active(),
        "finishing B must not clear the still-active A callback"
    );
    release_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(same.is_err(), "callbacks on one side must never overlap");
    assert!(other.is_ok(), "unrelated side refused: {other:?}");
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert!(!r.side_tx_active());
    r.remove_side(a).unwrap();
    let hc = hits.clone();
    let reused = r.add_side_packet("replacement", move |_| {
        hc.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    assert_eq!(reused, a);
    r.send_reliable_to_side(reused, data, true).unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 2);
}
