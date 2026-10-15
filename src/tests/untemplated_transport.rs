use super::*;

fn canonical_frame() -> crate::SharedBytes {
    // Use a dedicated best-effort type: the compiled qualification schema
    // configures GPS_DATA as reliable, unlike the fallback unit-test schema.
    let ep = crate::config::register_endpoint_with_description("UNTEMPLATED_TEST_DEST", "", false)
        .unwrap();
    let ty = crate::config::register_data_type_with_description(
        "UNTEMPLATED_TEST_DATA",
        "",
        crate::MessageElement::Static(
            3,
            crate::MessageDataType::Float32,
            crate::MessageClass::Data,
        ),
        &[ep],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    let packet = Packet::new(ty, &[ep], "FRAME_SOURCE", 100, Arc::<[u8]>::from([0u8; 12])).unwrap();
    crate::shared_bytes::convert(wire_format::pack_packet(&packet))
}

#[test]
fn zero_dictionary_keeps_canonical_bytes_and_rejects_bad_crc() {
    let node = untemplated_test_node();
    let mut opts = untemplated_test_options();
    opts.max_side_transport_templates = 0;
    let side = node.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
    let raw = canonical_frame();
    assert!(raw.len() <= opts.max_frame_bytes);
    for _ in 0..64 {
        let mut frames = node
            .encode_side_transport_frames(side, opts.clone(), raw.clone())
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames.next().unwrap().as_ref(), raw.as_ref());
        assert_eq!(
            node.state.lock().side_transport[&side].tx_template_count(),
            0
        );
    }
    let mut bad = raw.as_ref().to_vec();
    bad[3] ^= 1;
    assert!(
        node.encode_side_transport_frames(
            side,
            opts,
            crate::shared_bytes::convert(Arc::<[u8]>::from(bad))
        )
        .is_err()
    );
}

#[test]
fn shared_bus_switches_to_canonical_frames_without_forgetting_rx_dictionary() {
    let node = untemplated_test_node();
    let opts = untemplated_test_options();
    let side = node.add_side_packed_with_options("wire", |_| Ok(()), opts.clone());
    let raw = canonical_frame();
    // Establish the point-to-point dictionary before a second producer joins.
    node.encode_side_transport_frames(side, opts.clone(), raw.clone())
        .unwrap();
    {
        let mut st = node.state.lock();
        assert_eq!(st.side_transport[&side].tx_template_count(), 1);
        let (template, ..) = extract_side_header_template(raw.as_ref()).unwrap();
        st.side_transport
            .get_mut(&side)
            .unwrap()
            .insert_rx_template(123, template, 8);
        for peer in ["PEER_A", "PEER_B"] {
            st.discovery_routes
                .entry(side)
                .or_default()
                .announcers
                .insert(peer.into(), DiscoverySenderState::default());
        }
    }
    for _ in 0..64 {
        let mut frames = node
            .encode_side_transport_frames(side, opts.clone(), raw.clone())
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames.next().unwrap().as_ref(), raw.as_ref());
    }
    let st = node.state.lock();
    assert_eq!(st.side_transport[&side].tx_template_count(), 0);
    assert_eq!(st.side_transport[&side].rx_template_count(), 1);
    assert!(
        st.side_transport[&side]
            .rx_templates_by_id
            .contains_key(&123)
    );
}
