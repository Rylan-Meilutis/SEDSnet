use super::*;

fn control_type() -> crate::DataType {
    crate::tests::ensure_common_test_schema();
    crate::config::register_data_type_with_description(
        "RELAY_FROZEN_CONTROL_PRIORITY",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[crate::DataEndpoint::named("RADIO")],
        crate::ReliableMode::None,
        16,
    )
    .unwrap()
}

#[test]
fn frozen_owner_controls_remain_canonical_across_relay_transport() {
    let ty = control_type();
    let relay = Relay::new(Box::new(|| 0));
    let opts = RelaySideOptions::default().with_small_packet_transport(256);
    let side = relay.add_side_packed_with_options("radio", |_| Ok(()), opts.clone());
    let packet = Packet::new_with_wire_contract(
        ty,
        &[crate::DataEndpoint::named("RADIO")],
        "GS",
        1,
        1,
        Arc::<[u8]>::from([1]),
        None,
        Arc::from([0x1234u64]),
    )
    .unwrap();
    let raw = wire_format::pack_packet(&packet);
    for _ in 0..3 {
        let frames = relay
            .encode_side_transport_frames(
                side,
                opts.clone(),
                crate::shared_bytes::convert(raw.clone()),
            )
            .unwrap();
        let mut count = 0;
        relay
            .send_side_frames_resumable(side, frames, |bytes| {
                assert_eq!(bytes, raw.as_ref());
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
    }
}

#[test]
fn relay_backpressure_retains_the_original_queue_priority() {
    let ty = control_type();
    for combined in [false, true] {
        let relay = Relay::new(Box::new(|| 0));
        let side = relay.add_side_packed("radio", |_| Err(TelemetryError::Io("side tx busy")));
        let packet = Packet::new(
            ty,
            &[crate::DataEndpoint::named("RADIO")],
            "GS",
            1,
            Arc::<[u8]>::from([1]),
        )
        .unwrap();
        relay
            .state
            .lock()
            .push_tx(RelayTxItem {
                src: None,
                dst: side,
                data: RouterItem::Packet(packet),
                priority: 254,
                retry_after_ms: 0,
            })
            .unwrap();
        if combined {
            relay.drain_queues_with_timeout(1).unwrap();
        } else {
            relay.process_tx_queue_with_timeout(1).unwrap();
        }
        let (priority, retry_after_ms) = relay.state.lock().transmit_queue.iter()
            .find(|queued| matches!(queued_data(queued), RouterItem::Packet(packet) if packet.data_type() == ty))
            .map(|queued| (queued.priority, queued.retry_after_ms)).expect("control is retained after backpressure");
        assert_eq!(
            priority, 254,
            "backpressure must not demote a service-priority control"
        );
        assert_eq!(retry_after_ms, 1);
    }
}

#[test]
fn relay_retains_original_return_side_for_echoes_but_allows_disabled_side_failover() {
    crate::tests::ensure_common_test_schema();
    let ep = crate::DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "RELAY_ECHO_RETURN_PATH",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::Ordered,
        16,
    )
    .unwrap();
    let now = Arc::new(core::sync::atomic::AtomicU64::new(0));
    let clock = now.clone();
    let relay = Relay::new(Box::new(move || {
        clock.load(core::sync::atomic::Ordering::Relaxed)
    }));
    let radio = relay.add_side_packed("radio", |_| Ok(()));
    let can = relay.add_side_packed("can", |_| Ok(()));
    let packet = Packet::new(ty, &[ep], "GS", 123, Arc::<[u8]>::from([1])).unwrap();
    relay.rx_from_side(radio, packet.clone()).unwrap();
    relay.rx_from_side(can, packet.clone()).unwrap();
    relay.process_rx_queue().unwrap();
    assert_eq!(
        relay.state.lock().reliable_return_routes[&packet.packet_id()].side,
        radio
    );
    now.store(
        runtime_reliable_retransmit_ms() + 1,
        core::sync::atomic::Ordering::Relaxed,
    );
    relay.rx_from_side(can, packet.clone()).unwrap();
    relay.process_rx_queue().unwrap();
    assert_eq!(
        relay.state.lock().reliable_return_routes[&packet.packet_id()].side,
        can
    );
    relay.set_side_egress_enabled(can, false).unwrap();
    relay.rx_from_side(radio, packet.clone()).unwrap();
    relay.process_rx_queue().unwrap();
    assert_eq!(
        relay.state.lock().reliable_return_routes[&packet.packet_id()].side,
        radio
    );
}

#[test]
fn relay_queued_receipt_keeps_its_destination_after_return_cache_churn() {
    let ty = control_type();
    let radio_frames = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = radio_frames.clone();
    let relay = Relay::new(Box::new(|| 0));
    let radio = relay.add_side_packed("radio", move |wire| {
        received.lock().unwrap().push(wire.to_vec());
        Ok(())
    });
    let can = relay.add_side_packed("can", |_| Ok(()));
    let packet = Packet::new_with_wire_contract(
        ty,
        &[crate::DataEndpoint::named("RADIO")],
        "GS",
        1,
        1,
        Arc::<[u8]>::from([1]),
        None,
        Arc::from([Router::sender_hash("VB")]),
    )
    .unwrap();
    let id = packet.packet_id();
    relay.rx_from_side(radio, packet).unwrap();
    relay.process_rx_queue().unwrap();
    let ack = Packet::new_with_wire_contract(
        crate::DataType::ReliableAck,
        &[crate::DataEndpoint::named("RADIO")],
        "E2EACK:VB",
        2,
        2,
        Arc::<[u8]>::from(id.to_le_bytes()),
        None,
        Arc::from([Router::sender_hash("VB"), Router::sender_hash("GS")]),
    )
    .unwrap();
    relay.rx_from_side(can, ack).unwrap();
    relay.process_rx_queue().unwrap();
    for index in 0..runtime_reliable_max_return_routes().max(1) {
        relay.note_reliable_return_route(can, 10000 + index as u64);
    }
    relay.note_reliable_return_route(can, id);
    relay.process_tx_queue().unwrap();
    assert!(
        radio_frames.lock().unwrap().iter().any(|wire| {
            wire_format::unpack_packet(wire).is_ok_and(|packet| {
                packet.data_type() == crate::DataType::ReliableAck
                    && packet.payload() == id.to_le_bytes()
            })
        }),
        "queued receipt must retain the radio destination selected at admission"
    );
}
