//! Regression for RF bay-1792379104896398535: incomplete RX transfers
//! retained more than10KiB of payload independently of the shared TX budget.
use super::*;
use crate::config::{DataEndpoint, DataType};
struct StoreReset;
impl Drop for StoreReset {
    fn drop(&mut self) {
        #[cfg(feature = "compact-packet-store")]
        crate::packet_store::set_default_store(None);
    }
}

fn fragment(id: u32, index: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut wire = b"SDT\x03".to_vec();
    wire.extend_from_slice(&id.to_le_bytes());
    wire.extend_from_slice(&index.to_le_bytes());
    wire.extend_from_slice(&total.to_le_bytes());
    wire.extend_from_slice(payload);
    let crc = crc32fast::hash(&wire);
    wire.extend_from_slice(&crc.to_le_bytes());
    wire
}
fn fixture() -> (Router, usize, usize) {
    let (node, a, b, _) = fixture_with_clock();
    (node, a, b)
}
fn fixture_with_clock() -> (Router, usize, usize, Arc<core::sync::atomic::AtomicU64>) {
    #[cfg(feature = "compact-packet-store")]
    crate::packet_store::set_default_store(Some(
        crate::packet_store::PacketStore::new(32768, 512, 512).unwrap(),
    ));
    let clock = Arc::new(core::sync::atomic::AtomicU64::new(0));
    let read = clock.clone();
    let node = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF"),
        Box::new(move || read.load(core::sync::atomic::Ordering::Relaxed)),
    );
    let a = node.add_side_packed("can", |_| Ok(()));
    let b = node.add_side_packed("radio", |_| Ok(()));
    node.clear_queues();
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used() + 16384;
    }
    (node, a, b, clock)
}
fn partials(node: &Router) -> usize {
    let st = node.state.lock();
    for state in st.side_transport.values() {
        let actual = state
            .rx_chunks
            .values()
            .flat_map(|a| a.received.values())
            .map(|p| p.len() + 64)
            .sum::<usize>();
        assert_eq!(
            state.rx_chunk_bytes, actual,
            "per-link cache differs from retained fragments"
        );
    }
    st.side_transport
        .values()
        .flat_map(|s| s.rx_chunks.values())
        .flat_map(|a| a.received.values())
        .map(|p| p.len() + 64)
        .sum()
}
fn populate(node: &Router, a: usize, b: usize) {
    for (side, base) in [(a, 10), (b, 20)] {
        for id in base..base + 3 {
            for index in 0..23 {
                node.decode_side_transport_frame(side, &fragment(id, index, 28, &[id as u8; 112]))
                    .unwrap();
            }
        }
    }
}
#[test]
fn shared_chunk_budget_bounds_two_links_together() {
    let _reset = StoreReset;
    let (node, a, b) = fixture();
    populate(&node, a, b);
    let retained = partials(&node);
    assert!(
        node.export_runtime_stats()
            .sides
            .iter()
            .map(|s| s.side_transport_chunk_reclaims)
            .sum::<u64>()
            > 0
    );
    assert!(
        retained <= 16384,
        "per-side budgets multiply retained fragment storage: {retained}"
    );
    let st = node.state.lock();
    assert!(
        st.shared_queue_bytes_used() >= retained,
        "partial transfers missing from shared queue accounting"
    );
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
}
#[test]
fn shared_chunk_budget_keeps_active_schema_progress_and_bytes() {
    let _reset = StoreReset;
    let (node, a, b) = fixture();
    populate(&node, a, b);
    let raw = wire_format::pack_packet(
        &Packet::new(
            DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "GS",
            1,
            Arc::<[u8]>::from((0..3652).map(|i| (i % 251) as u8).collect::<Vec<_>>()),
        )
        .unwrap(),
    );
    let parts = raw.chunks(112).collect::<Vec<_>>();
    let mut completed = None;
    for (index, payload) in parts.iter().enumerate() {
        let result = node
            .decode_side_transport_frame(
                b,
                &fragment(99, index as u16, parts.len() as u16, payload),
            )
            .unwrap();
        if let Some(bytes) = result {
            assert!(completed.is_none());
            completed = Some(bytes);
        }
        assert!(
            partials(&node) <= 16384,
            "an active schema must reclaim unrelated incomplete transfers"
        );
    }
    assert_eq!(completed.unwrap().as_ref(), &raw[..]);
}
#[test]
fn shared_chunk_budget_duplicate_does_not_grow_or_reclaim() {
    let _reset = StoreReset;
    let (node, a, b) = fixture();
    populate(&node, a, b);
    let before = partials(&node);
    let keys = {
        let st = node.state.lock();
        st.side_transport
            .iter()
            .flat_map(|(side, s)| s.rx_chunks.keys().map(move |id| (*side, *id)))
            .collect::<Vec<_>>()
    };
    let &(side, id) = keys.last().unwrap();
    node.decode_side_transport_frame(side, &fragment(id, 0, 28, &[id as u8; 112]))
        .unwrap();
    assert_eq!(partials(&node), before);
    let after = {
        let st = node.state.lock();
        st.side_transport
            .iter()
            .flat_map(|(side, s)| s.rx_chunks.keys().map(move |id| (*side, *id)))
            .collect::<Vec<_>>()
    };
    assert_eq!(keys, after);
}

#[test]
fn shared_chunk_budget_expiry_releases_accounting_and_counts_reclaims() {
    let _reset = StoreReset;
    let (node, a, b, clock) = fixture_with_clock();
    let baseline = node.state.lock().shared_queue_bytes_used();
    populate(&node, a, b);
    let count = {
        let st = node.state.lock();
        st.side_transport
            .values()
            .map(|s| s.rx_chunks.len())
            .sum::<usize>()
    };
    let before = node
        .export_runtime_stats()
        .sides
        .iter()
        .map(|s| s.side_transport_chunk_reclaims)
        .sum::<u64>();
    assert!(count > 0);
    clock.store(2001, core::sync::atomic::Ordering::Relaxed);
    node.expire_side_chunks();
    assert_eq!(partials(&node), 0);
    assert_eq!(node.state.lock().shared_queue_bytes_used(), baseline);
    let after = node
        .export_runtime_stats()
        .sides
        .iter()
        .map(|s| s.side_transport_chunk_reclaims)
        .sum::<u64>();
    assert_eq!(after, before + count as u64);
}
#[test]
fn shared_chunk_budget_bad_crc_cannot_reclaim_partial_schema() {
    let _reset = StoreReset;
    let (node, a, b) = fixture();
    populate(&node, a, b);
    let before = partials(&node);
    let reclaims = node
        .export_runtime_stats()
        .sides
        .iter()
        .map(|s| s.side_transport_chunk_reclaims)
        .sum::<u64>();
    let mut bad = fragment(99, 0, 28, &[7; 112]);
    *bad.last_mut().unwrap() ^= 1;
    assert!(node.decode_side_transport_frame(a, &bad).is_err());
    assert_eq!(partials(&node), before);
    assert_eq!(
        node.export_runtime_stats()
            .sides
            .iter()
            .map(|s| s.side_transport_chunk_reclaims)
            .sum::<u64>(),
        reclaims
    );
}

#[test]
fn shared_chunk_budget_oversized_metadata_cannot_evict_another_transfer() {
    let _reset = StoreReset;
    let (node, a, _) = fixture();
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used() + 65536;
    }
    for id in 0..4 {
        for index in 0..23 {
            node.decode_side_transport_frame(a, &fragment(id, index, 28, &[id as u8; 112]))
                .unwrap();
        }
    }
    let before = partials(&node);
    let count = node
        .export_runtime_stats()
        .sides
        .iter()
        .map(|s| s.side_transport_chunk_reclaims)
        .sum::<u64>();
    assert!(
        node.decode_side_transport_frame(a, &fragment(99, 0, u16::MAX, &[9; 112]))
            .is_err()
    );
    assert_eq!(
        partials(&node),
        before,
        "invalid metadata evicted a valid incomplete schema"
    );
    assert_eq!(
        node.export_runtime_stats()
            .sides
            .iter()
            .map(|s| s.side_transport_chunk_reclaims)
            .sum::<u64>(),
        count
    );
}

fn packet_rows(node: &Router) -> Vec<(String, DataType)> {
    node.state
        .lock()
        .transmit_queue
        .iter()
        .filter_map(|q| match &q.item {
            RouterTxItem::Broadcast(RouterItem::Packet(p)) => {
                Some((p.sender().to_owned(), p.data_type()))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
}
#[test]
fn shared_chunk_budget_sheds_fast_bulk_before_slow_report_and_control() {
    let _reset = StoreReset;
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let ep = crate::config::register_endpoint("CHUNK_BACKLOG_EP_ROUTER", false).unwrap();
    let bulk = crate::config::register_data_type(
        "CHUNK_BACKLOG_VALUE_ROUTER",
        MessageElement::Static(128, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        0,
    )
    .unwrap();
    let control = crate::config::register_data_type(
        "CHUNK_BACKLOG_CONTROL_ROUTER",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        201,
    )
    .unwrap();
    let (node, a, _) = fixture();
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used() + 4096;
    }
    for t in 0..12 {
        let packet = Packet::new(bulk, &[ep], "DAQ", t, Arc::<[u8]>::from([t as u8; 128])).unwrap();
        node.tx_queue(packet).unwrap();
    }
    let packet = Packet::new(bulk, &[ep], "VALVE", 99, Arc::<[u8]>::from([42; 128])).unwrap();
    node.tx_queue(packet).unwrap();
    let packet = Packet::new(control, &[ep], "GS", 100, Arc::<[u8]>::from([1])).unwrap();
    node.tx_queue(packet).unwrap();
    let before = packet_rows(&node);
    assert_eq!(
        before
            .iter()
            .filter(|(sender, _)| sender == "VALVE")
            .count(),
        1
    );
    assert_eq!(before.iter().filter(|(_, ty)| *ty == control).count(), 1);
    #[cfg(feature = "compact-packet-store")]
    assert!(
        crate::packet_store::default_store()
            .unwrap()
            .stats()
            .live_handles
            > 0,
        "arena must actually hold queued payloads"
    );
    for index in 0..16 {
        node.decode_side_transport_frame(a, &fragment(99, index, 28, &[7; 112]))
            .unwrap();
    }
    let after = packet_rows(&node);
    assert!(
        after.iter().filter(|(sender, _)| sender == "DAQ").count()
            < before.iter().filter(|(sender, _)| sender == "DAQ").count()
    );
    assert_eq!(
        after.iter().filter(|(sender, _)| sender == "VALVE").count(),
        1
    );
    assert_eq!(after.iter().filter(|(_, ty)| *ty == control).count(), 1);
    let st = node.state.lock();
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
}

#[test]
fn shared_chunk_budget_same_transfer_id_is_scoped_to_each_link() {
    let _reset = StoreReset;
    let (node, a, b) = fixture();
    node.decode_side_transport_frame(a, &fragment(7, 0, 3, &[1; 112]))
        .unwrap();
    node.decode_side_transport_frame(b, &fragment(7, 0, 3, &[2; 112]))
        .unwrap();
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
    }
    node.decode_side_transport_frame(b, &fragment(7, 1, 3, &[3; 112]))
        .unwrap();
    let st = node.state.lock();
    assert!(!st.side_transport[&a].rx_chunks.contains_key(&7));
    assert_eq!(st.side_transport[&b].rx_chunks[&7].received.len(), 2);
    assert!(st.shared_queue_bytes_used() <= st.memory.max_queue_budget);
}

#[test]
fn shared_chunk_budget_busy_is_retryable_memory_pressure() {
    let _reset = StoreReset;
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let ep = crate::config::register_endpoint("CHUNK_BUSY_EP_ROUTER", false).unwrap();
    let ty = crate::config::register_data_type(
        "CHUNK_BUSY_VALUE_ROUTER",
        MessageElement::Static(256, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        201,
    )
    .unwrap();
    let (node, a, _) = fixture();
    for t in 0..4 {
        let packet = Packet::new(ty, &[ep], "GS", t, Arc::<[u8]>::from([4; 256])).unwrap();
        node.tx_queue(packet).unwrap();
    }
    let before = packet_rows(&node);
    assert_eq!(before.len(), 4);
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
    }
    let frame = fragment(91, 0, 3, &[7; 112]);
    let result = node.decode_side_transport_frame(a, &frame);
    assert!(
        matches!(result, Err(TelemetryError::Io("memory pressure"))),
        "temporary receive saturation must preserve sender fragment retry semantics: {result:?}"
    );
    assert_eq!(
        packet_rows(&node),
        before,
        "fragment pressure evicted protected work"
    );
    node.clear_queues();
    assert!(
        node.decode_side_transport_frame(a, &frame)
            .unwrap()
            .is_none()
    );
    assert_eq!(partials(&node), 176);
}

#[test]
fn shared_chunk_budget_busy_preserves_already_received_fragments() {
    let _reset = StoreReset;
    use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
    let ep = crate::config::register_endpoint("CONTINUATION_EP_ROUTER", false).unwrap();
    let ty = crate::config::register_data_type(
        "CONTINUATION_VALUE_ROUTER",
        MessageElement::Static(256, MessageDataType::UInt8, MessageClass::Data),
        &[ep],
        ReliableMode::None,
        201,
    )
    .unwrap();
    let (node, a, _) = fixture();
    for t in 0..4 {
        node.tx_queue(Packet::new(ty, &[ep], "GS", t, Arc::<[u8]>::from([4; 256])).unwrap())
            .unwrap();
    }
    let raw = wire_format::pack_packet(
        &Packet::new(
            DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "GS",
            1,
            Arc::<[u8]>::from((0..300).map(|i| (i % 251) as u8).collect::<Vec<_>>()),
        )
        .unwrap(),
    );
    let parts = raw.chunks(112).collect::<Vec<_>>();
    assert!(parts.len() > 2);
    node.decode_side_transport_frame(a, &fragment(92, 0, parts.len() as u16, parts[0]))
        .unwrap();
    let retained = partials(&node);
    let before = packet_rows(&node);
    let reclaims = node
        .export_runtime_stats()
        .sides
        .iter()
        .map(|s| s.side_transport_chunk_reclaims)
        .sum::<u64>();
    {
        let mut st = node.state.lock();
        st.memory.max_queue_budget = st.shared_queue_bytes_used();
    }
    let result =
        node.decode_side_transport_frame(a, &fragment(92, 1, parts.len() as u16, parts[1]));
    assert!(
        matches!(result, Err(TelemetryError::Io("memory pressure"))),
        "{result:?}"
    );
    assert_eq!(
        partials(&node),
        retained,
        "retryable refusal discarded previously accepted fragments"
    );
    assert_eq!(packet_rows(&node), before, "protected work was evicted");
    assert_eq!(
        node.export_runtime_stats()
            .sides
            .iter()
            .map(|s| s.side_transport_chunk_reclaims)
            .sum::<u64>(),
        reclaims
    );
    node.clear_queues();
    let mut complete = None;
    for (index, part) in parts.iter().enumerate().skip(1) {
        complete = node
            .decode_side_transport_frame(a, &fragment(92, index as u16, parts.len() as u16, part))
            .unwrap();
    }
    assert_eq!(
        complete.unwrap().as_ref(),
        &raw[..],
        "same-fragment retry must complete the exact packet"
    );
}
