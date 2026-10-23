use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
#[test]
fn relay_accepted_hop_queue_waits_for_ack_credit() {
    for ordered in [false, true] {
        for packed in [false, true] {
            crate::tests::ensure_common_test_schema();
            let ep = crate::config::register_endpoint_with_description(
                &format!("RELAY_HOP_WINDOW_{ordered}_{packed}"),
                "",
                false,
            )
            .unwrap();
            let ty = crate::config::register_data_type_with_description(
                &format!("RELAY_HOP_BATCH_{ordered}_{packed}"),
                "",
                crate::MessageElement::Static(
                    44,
                    crate::MessageDataType::UInt8,
                    crate::MessageClass::Data,
                ),
                &[ep],
                if ordered {
                    crate::ReliableMode::Ordered
                } else {
                    crate::ReliableMode::Unordered
                },
                0,
            )
            .unwrap();
            let time = Arc::new(AtomicU64::new(1000));
            let clock = time.clone();
            let relay = Relay::new(Box::new(move || clock.load(Ordering::Relaxed)));
            let src = relay.add_side_packed("source", |_| Ok(()));
            let wanted = Arc::new(AtomicU64::new(0));
            let wanted_wire = wanted.clone();
            let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
            let output = frames.clone();
            let side = relay.add_side_packed_with_options(
                "CAN",
                move |bytes| {
                    if wire_format::packet_id_from_wire(bytes)
                        .is_ok_and(|id| id == wanted_wire.load(Ordering::Relaxed))
                    {
                        output.lock().unwrap().push(bytes.to_vec());
                    }
                    Ok(())
                },
                RelaySideOptions {
                    reliable_enabled: true,
                    header_template_enabled: false,
                    ..Default::default()
                },
            );
            relay.clear_tx_queue();
            for n in 0..runtime_reliable_max_pending() {
                let packet = Packet::new(
                    ty,
                    &[ep],
                    "source",
                    n as u64 + 1,
                    Arc::<[u8]>::from([1u8; 44]),
                )
                .unwrap();
                relay
                    .send_reliable_to_side(side, RelayItem::Packet(Arc::new(packet)))
                    .unwrap();
            }
            let packet =
                Packet::new(ty, &[ep], "source", 10000, Arc::<[u8]>::from([42u8; 44])).unwrap();
            let id = packet.packet_id();
            wanted.store(id, Ordering::Relaxed);
            let data = if packed {
                RelayItem::Packed(crate::shared_bytes::convert(wire_format::pack_packet(
                    &packet,
                )))
            } else {
                RelayItem::Packet(Arc::new(packet))
            };
            relay
                .state
                .lock()
                .push_tx(RelayTxItem {
                    src: Some(src),
                    dst: side,
                    data,
                    priority: 0,
                    retry_after_ms: 0,
                })
                .unwrap();
            relay
                .process_tx_queue()
                .expect("relay hop pressure must preserve accepted data");
            assert!(frames.lock().unwrap().is_empty());
            assert_eq!(relay.state.lock().tx_queue.len(), 1);
            relay
                .rx_packed_from_side(side, &wire_format::pack_reliable_ack("sink", ty, 1000, 1))
                .unwrap();
            time.store(1002, Ordering::Relaxed);
            relay.process_tx_queue().unwrap();
            assert_eq!(frames.lock().unwrap().len(), 1);
            assert_eq!(
                relay.state.lock().reliable_tx[&(side, ty.as_u32())]
                    .sent
                    .len(),
                runtime_reliable_max_pending()
            );
        }
    }
}
