//! True end-to-end reliable causal fixture: packed transports only.
//! Known unrelated GB, accepted close, no-owner drains, then real GS discovery.
//! Hold actual GS E2E receipt bytes to prove pending ownership before retirement.
use sedsnet::config;
use sedsnet::router::{EndpointHandler, Router, RouterConfig, RouterSideId};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
type Wire = Arc<Mutex<VecDeque<Vec<u8>>>>;
fn take(wire: &Wire) -> Vec<Vec<u8>> {
    wire.lock().unwrap().drain(..).collect()
}
fn endpoint(router: &Router, side: RouterSideId, bytes: &[u8]) {
    router.rx_packed_from_side(bytes, side).unwrap();
}
fn e2e_ack_id(bytes: &[u8]) -> Option<u64> {
    let envelope = sedsnet::wire_format::peek_envelope(bytes).ok()?;
    if envelope.ty != config::DataType::ReliableAck || envelope.target_senders.len() < 2 {
        return None;
    }
    let packet = sedsnet::wire_format::unpack_packet(bytes).ok()?;
    Some(u64::from_le_bytes(packet.payload().try_into().ok()?))
}
fn count_type(bytes: &[u8], ty: config::DataType) -> bool {
    sedsnet::wire_format::peek_envelope(bytes).is_ok_and(|env| env.ty == ty)
}
fn require(failures: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        failures.push(message.into());
    }
}
pub fn run() {
    let local = config::register_endpoint("PACKED_CHURN_LOCAL", false).unwrap();
    let remote = config::register_endpoint("PACKED_CHURN_REMOTE", false).unwrap();
    let unrelated = config::register_endpoint("PACKED_CHURN_GB_ONLY", false).unwrap();
    let ty = config::register_data_type_with_description(
        "PACKED_CHURN_CLOSE_OPEN",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[local, remote],
        ReliableMode::Ordered,
        255,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(1000));
    let now = clock.clone();
    let locals = Arc::new(Mutex::new(Vec::new()));
    let local_effects = locals.clone();
    let source = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(local, move |packet| {
            local_effects
                .lock()
                .unwrap()
                .push(packet.payload().to_vec());
            Ok(())
        })])
        .with_sender("VB"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let outgoing: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let tx = outgoing.clone();
    let data_transmits = Arc::new(AtomicUsize::new(0));
    let count = data_transmits.clone();
    let source_side = source.add_side_packed("shared-can", move |bytes| {
        if count_type(bytes, ty) {
            count.fetch_add(1, Ordering::SeqCst);
        }
        tx.lock().unwrap().push_back(bytes.to_vec());
        Ok(())
    });
    let now = clock.clone();
    let gb = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(unrelated, |_| Ok(()))])
            .with_sender("GB"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let gb_out: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let tx = gb_out.clone();
    let gb_side = gb.add_side_packed("shared-can", move |bytes| {
        tx.lock().unwrap().push_back(bytes.to_vec());
        Ok(())
    });
    source.clear_queues();
    gb.clear_queues();
    gb.announce_discovery().unwrap();
    for _ in 0..15 {
        let _ = gb.process_all_queues_with_timeout(0);
        for bytes in take(&gb_out) {
            endpoint(&source, source_side, &bytes)
        }
        let _ = source.process_all_queues_with_timeout(0);
        for bytes in take(&outgoing) {
            endpoint(&gb, gb_side, &bytes)
        }
    }
    source.clear_queues();
    gb.clear_queues();
    take(&outgoing);
    take(&gb_out);
    data_transmits.store(0, Ordering::SeqCst);
    let mut failures = Vec::new();
    source
        .log_queue(ty, &[0u8])
        .expect("close must be accepted");
    let mut no_route_queue_lens = Vec::new();
    for _ in 0..3 {
        clock.fetch_add(300, Ordering::SeqCst);
        let _ = source.process_all_queues_with_timeout(0);
        no_route_queue_lens.push(source.export_runtime_stats().queues.tx_len);
        for bytes in take(&outgoing) {
            endpoint(&gb, gb_side, &bytes)
        }
        let _ = gb.process_all_queues_with_timeout(0);
        for bytes in take(&gb_out) {
            endpoint(&source, source_side, &bytes)
        }
    }
    let locals_without_owner = locals.lock().unwrap().clone();
    let sent_without_owner = data_transmits.load(Ordering::SeqCst);
    require(
        &mut failures,
        locals_without_owner == vec![vec![0]],
        format!("accepted close local effects after no-route drains: {locals_without_owner:?}"),
    );
    require(
        &mut failures,
        no_route_queue_lens.iter().all(|&len| len > 0),
        format!(
            "accepted close owner not retained across no-route drains: {no_route_queue_lens:?}"
        ),
    );
    require(
        &mut failures,
        sent_without_owner == 0,
        format!("command sent before any peer owned requested endpoint: {sent_without_owner}"),
    );
    // New peer is a real Router whose actual handler owns the formerly missing endpoint.
    let remote_effects = Arc::new(Mutex::new(Vec::new()));
    let effects = remote_effects.clone();
    let now = clock.clone();
    let sink = Router::new_with_clock(
        RouterConfig::new([EndpointHandler::new_packet_handler(remote, move |packet| {
            effects.lock().unwrap().push(packet.payload().to_vec());
            Ok(())
        })])
        .with_sender("GS"),
        Box::new(move || now.load(Ordering::SeqCst)),
    );
    let sink_out: Wire = Arc::new(Mutex::new(VecDeque::new()));
    let tx = sink_out.clone();
    let sink_side = sink.add_side_packed("shared-can", move |bytes| {
        tx.lock().unwrap().push_back(bytes.to_vec());
        Ok(())
    });
    sink.clear_queues();
    sink.announce_discovery().unwrap();
    let mut held_receipts = Vec::<(u64, Vec<u8>)>::new();
    for _ in 0..12 {
        clock.fetch_add(10, Ordering::SeqCst);
        let _ = sink.process_all_queues_with_timeout(0);
        for bytes in take(&sink_out) {
            if let Some(id) = e2e_ack_id(&bytes) {
                held_receipts.push((id, bytes))
            } else {
                endpoint(&source, source_side, &bytes);
                endpoint(&gb, gb_side, &bytes)
            }
        }
        let _ = source.process_all_queues_with_timeout(0);
        for bytes in take(&outgoing) {
            endpoint(&gb, gb_side, &bytes);
            endpoint(&sink, sink_side, &bytes)
        }
        let _ = gb.process_all_queues_with_timeout(0);
        for bytes in take(&gb_out) {
            endpoint(&source, source_side, &bytes);
            endpoint(&sink, sink_side, &bytes)
        }
    }
    source
        .log_queue(ty, &[1u8])
        .expect("open must be accepted behind retained close");
    for _ in 0..5 {
        clock.fetch_add(10, Ordering::SeqCst);
        let _ = source.process_all_queues_with_timeout(0);
        for bytes in take(&outgoing) {
            endpoint(&gb, gb_side, &bytes);
            endpoint(&sink, sink_side, &bytes)
        }
        let _ = sink.process_all_queues_with_timeout(0);
        for bytes in take(&sink_out) {
            if let Some(id) = e2e_ack_id(&bytes) {
                held_receipts.push((id, bytes))
            } else {
                endpoint(&source, source_side, &bytes);
                endpoint(&gb, gb_side, &bytes)
            }
        }
    }
    let before_ack = source.export_reliable_pending_stats();
    let status_pending: Vec<_> = before_ack
        .iter()
        .filter(|row| row.data_type == ty)
        .collect();
    let matched_ack_ids: Vec<_> = held_receipts
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| status_pending.iter().any(|row| row.packet_id == *id))
        .collect();
    require(
        &mut failures,
        !status_pending.is_empty(),
        "packed status did not create true E2E pending ownership before peer ACK",
    );
    require(
        &mut failures,
        !matched_ack_ids.is_empty(),
        "no actual GS owner ACK bytes matched a pending status packet",
    );
    let before_ack_remote = remote_effects.lock().unwrap().clone();
    require(
        &mut failures,
        before_ack_remote == vec![vec![0]],
        format!(
            "before first owner ACK, remote Ordered effects must be close only: {before_ack_remote:?}"
        ),
    );
    let pending_ids_before: Vec<_> = status_pending.iter().map(|row| row.packet_id).collect();
    for (_, bytes) in held_receipts.drain(..) {
        endpoint(&source, source_side, &bytes);
    }
    let _ = source.process_all_queues_with_timeout(0);
    let after_first_ack = source.export_reliable_pending_stats();
    require(
        &mut failures,
        matched_ack_ids
            .iter()
            .all(|id| !after_first_ack.iter().any(|row| row.packet_id == *id)),
        "delivering actual GS owner ACK bytes did not retire matching pending packet",
    );
    let mut delivered_receipts = matched_ack_ids.len();
    for _ in 0..60 {
        clock.fetch_add(20, Ordering::SeqCst);
        let _ = source.process_all_queues_with_timeout(0);
        for bytes in take(&outgoing) {
            endpoint(&gb, gb_side, &bytes);
            endpoint(&sink, sink_side, &bytes)
        }
        let _ = gb.process_all_queues_with_timeout(0);
        for bytes in take(&gb_out) {
            endpoint(&source, source_side, &bytes);
            endpoint(&sink, sink_side, &bytes)
        }
        let _ = sink.process_all_queues_with_timeout(0);
        for bytes in take(&sink_out) {
            if e2e_ack_id(&bytes).is_some() {
                delivered_receipts += 1
            }
            endpoint(&source, source_side, &bytes);
            endpoint(&gb, gb_side, &bytes)
        }
        if remote_effects.lock().unwrap().as_slice() == [vec![0], vec![1]]
            && source
                .export_reliable_pending_stats()
                .iter()
                .all(|row| row.data_type != ty)
            && source.export_runtime_stats().queues.tx_len == 0
        {
            break;
        }
    }
    let received = remote_effects.lock().unwrap().clone();
    let local = locals.lock().unwrap().clone();
    let pending = source.export_reliable_pending_stats();
    require(
        &mut failures,
        received == vec![vec![0], vec![1]],
        format!("accepted close/open lost, duplicated or reordered remotely: {received:?}"),
    );
    require(
        &mut failures,
        local == vec![vec![0], vec![1]],
        format!("local close/open effects repeated or lost: {local:?}"),
    );
    require(
        &mut failures,
        pending.iter().all(|row| row.data_type != ty),
        format!("status E2E pending remains after real receipts: {pending:?}"),
    );
    println!(
        "TRACE no_route_tx={no_route_queue_lens:?} local_before_owner={locals_without_owner:?} status_wire_before_owner={sent_without_owner} pending_status_ids_before_ack={pending_ids_before:?} matching_actual_gs_ack_ids={matched_ack_ids:?} ack_deliveries={delivered_receipts} before_ack_remote={before_ack_remote:?} remote={received:?} local={local:?} pending_after={}",
        pending.iter().filter(|row| row.data_type == ty).count()
    );
    if !failures.is_empty() {
        for failure in failures {
            eprintln!("FAIL {failure}")
        }
        std::process::exit(1)
    }
    println!(
        "PASS packed transport: accepted close survives three no-owner drains; real GS discovery restores ordered close/open exactly once; pending exists before actual peer receipt bytes retire it"
    );
}
