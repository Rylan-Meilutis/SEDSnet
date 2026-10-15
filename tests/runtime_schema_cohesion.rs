#![cfg(feature = "discovery")]

#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_lock() {}
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
extern "C" fn telemetry_unlock() {}

#[test]
fn runtime_declarations_and_complementary_catalogs_form_one_routable_schema() {
    use sedsnet::config::*;
    use sedsnet::packet::Packet;
    use sedsnet::wire_format::{pack_packet, unpack_packet};
    use sedsnet::{
        E2eEncryptionPolicy, MessageClass, MessageDataType, MessageElement, ReliableMode,
    };

    // Built-in and application names must use one identity API; callers do
    // not need a separate numeric map when runtime declarations reference controls.
    for definition in export_schema()
        .endpoints
        .into_iter()
        .filter(|entry| (200..=202).contains(&entry.id.0))
    {
        assert_eq!(DataEndpoint::identity(&definition.name), definition.id);
    }
    for definition in export_schema()
        .types
        .into_iter()
        .filter(|entry| entry.id.0 <= 18)
    {
        assert_eq!(DataType::identity(&definition.name), definition.id);
    }

    // No schema file supplies these definitions, in either build context.
    let a = register_endpoint("COHESION_A", false).unwrap();
    let b = DataEndpoint::identity("COHESION_B");
    assert!(!endpoint_exists(b));
    let element = MessageElement::Static(1, MessageDataType::Float32, MessageClass::Data);
    let ty = register_data_type("COHESION_FLOW", element, &[a], ReliableMode::None, 10).unwrap();
    assert_eq!(ty, DataType::identity("COHESION_FLOW"));
    assert_eq!(a, DataEndpoint::identity("COHESION_A"));
    let before = Packet::from_f32_slice(ty, &[2.5], &[a], 123).unwrap();
    let receipt = before.packet_id();

    // Another node contributes a destination whose definition arrives later.
    let fragment = OwnedRuntimeSchemaSnapshot {
        endpoints: vec![],
        types: vec![OwnedDataTypeDefinition {
            id: ty,
            name: "COHESION_FLOW".into(),
            description: String::new(),
            element,
            endpoints: vec![b],
            reliable: ReliableMode::None,
            priority: 12,
            e2e_encryption: E2eEncryptionPolicy::PreferOff,
        }],
    };
    let report = merge_owned_schema_snapshot_with_budget(fragment.clone(), 65536).unwrap();
    assert!(report.changed());
    let merged = data_type_definition(ty).unwrap();
    assert_eq!(merged.priority, 12);
    assert_eq!(merged.endpoints.len(), 2);
    assert!(merged.endpoints.contains(&a) && merged.endpoints.contains(&b));
    assert!(!endpoint_exists(b));
    assert_eq!(before.packet_id(), receipt);
    // This packet retains its one destination even though merged metadata has two.
    let decoded = unpack_packet(&pack_packet(&before)).unwrap();
    assert_eq!(decoded.endpoints(), &[a]);
    assert_eq!(decoded.packet_id(), receipt);
    assert_eq!(decoded.data_as_f32().unwrap(), vec![2.5]);
    // Missing endpoint documentation must not prevent numeric routing/receipts.
    let unresolved = Packet::from_f32_slice(ty, &[3.5], &[b], 124).unwrap();
    let unresolved_receipt = unresolved.packet_id();
    let unresolved = unpack_packet(&pack_packet(&unresolved)).unwrap();
    assert_eq!(unresolved.endpoints(), &[b]);
    assert_eq!(register_endpoint("COHESION_B", false).unwrap(), b);
    assert_eq!(unresolved.packet_id(), unresolved_receipt);

    // Export/reannounce contains only the effective declaration, not old overlays.
    let effective = export_schema();
    assert_eq!(
        effective
            .types
            .iter()
            .filter(|entry| entry.id == ty)
            .count(),
        1
    );
    assert_eq!(
        effective.types.iter().find(|entry| entry.id == ty).unwrap(),
        &merged
    );
    let retained = schema_bytes_used();
    assert!(
        !merge_owned_schema_snapshot_with_budget(fragment, 65536)
            .unwrap()
            .changed()
    );
    assert_eq!(schema_bytes_used(), retained);

    let received = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = received.clone();
    let router = sedsnet::router::Router::new_with_clock(
        sedsnet::router::RouterConfig::new(vec![
            sedsnet::router::EndpointHandler::new_packet_handler(a, move |packet| {
                assert_eq!(packet.data_as_f32().unwrap(), vec![2.5]);
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }),
        ]),
        Box::new(|| 0),
    );
    let side = router.add_side_packed("peer", |_| Ok(()));
    router
        .rx_packed_from_side(&pack_packet(&before), side)
        .unwrap();
    assert_eq!(received.load(std::sync::atomic::Ordering::Relaxed), 1);
}
