use super::*;

fn template(hash: u64) -> SideHeaderTemplate {
    crate::side_transport::SideHeaderTemplateView {
        hash,
        base_flags: 0,
        prefix: &[1u8, 2],
        between: &[],
        reliable_flags: None,
        reliable_compact: false,
    }
    .into_owned()
}

#[test]
fn receive_eviction_matches_transmitter_hash_order_not_wire_id() {
    let mut tx = SideTransportState::default();
    let mut rx = SideTransportState::default();
    for (hash, id) in [(100, 1), (1, 2), (50, 3)] {
        let header = template(hash);
        tx.insert_tx_template(header.clone(), id, 2);
        rx.insert_rx_template(id, header, 2);
    }
    assert_eq!(rx.rx_template_count(), 2);
    assert!(rx.rx_templates_by_id.contains_key(&1));
    assert!(!rx.rx_templates_by_id.contains_key(&2));
    assert!(rx.rx_templates_by_id.contains_key(&3));
    for (hash, id) in &tx.tx_template_ids {
        assert_eq!(rx.rx_templates.get(hash), Some(id));
    }
    // The secondary index stores four bytes per value, not a second header.
    assert_eq!(
        core::mem::size_of_val(rx.rx_templates.values().next().unwrap()),
        4
    );
}

#[test]
fn replacing_template_ids_and_hash_aliases_keeps_indices_and_timestamps_consistent() {
    let mut rx = SideTransportState::default();
    rx.insert_rx_template(1, template(100), 2);
    rx.insert_rx_template(2, template(50), 2);
    rx.rx_last_timestamps.insert(1, 123);
    assert!(!rx.insert_rx_template(1, template(75), 2));
    assert!(!rx.rx_templates.contains_key(&100));
    assert!(!rx.rx_last_timestamps.contains_key(&1));
    rx.rx_last_timestamps.insert(1, 456);
    assert!(!rx.insert_rx_template(3, template(75), 2));
    assert_eq!(rx.rx_template_count(), 2);
    assert!(!rx.rx_templates_by_id.contains_key(&1));
    assert!(!rx.rx_last_timestamps.contains_key(&1));
    assert_eq!(rx.rx_templates.get(&75), Some(&3));
    assert!(rx.rx_templates_by_id.contains_key(&2));
}
