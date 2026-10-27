//! The legacy router and relay names are one side-configuration contract.
use sedsnet::{
    relay::RelaySideOptions,
    router::{CompactTimestampOmissionPolicy, RouterSideOptions, SideTransportProfile},
    routing_config::SideOptions,
};

#[test]
fn legacy_side_configuration_names_are_interchangeable_without_translation() {
    // Exercise an exhaustive legacy struct literal, not only Default: removing or
    // renaming a field would break existing applications even if presets worked.
    let relay = RelaySideOptions {
        reliable_enabled: true,
        link_local_enabled: true,
        ingress_enabled: false,
        egress_enabled: true,
        header_template_enabled: true,
        max_frame_bytes: 64,
        compact_header_target_bytes: 40,
        max_side_transport_templates: 3,
        omit_unchanged_compact_timestamps: true,
        compact_timestamp_omission_types: CompactTimestampOmissionPolicy::none(),
        side_transport_profile: SideTransportProfile::Ipv6Like,
    };
    let mut router: RouterSideOptions = relay;
    router.egress_enabled = false;
    let shared: SideOptions = router;
    assert!(!shared.ingress_enabled && !shared.egress_enabled);
    assert!(shared.reliable_enabled && shared.link_local_enabled);
    assert_eq!(shared.max_frame_bytes, 64);
    assert_eq!(shared.max_side_transport_templates, 3);
    assert_eq!(
        shared.effective_transport_profile(),
        SideTransportProfile::Ipv6Like
    );
}

#[test]
fn shared_presets_keep_small_link_and_default_reliability_contracts() {
    let defaults = SideOptions::default();
    assert!(!defaults.reliable_enabled);
    assert!(defaults.ingress_enabled && defaults.egress_enabled);
    assert_eq!(
        defaults.effective_transport_profile(),
        SideTransportProfile::Canonical
    );
    let small = RelaySideOptions::default().with_small_packet_transport(64);
    assert!(!small.reliable_enabled);
    assert_eq!(small.max_frame_bytes, 64);
    assert_eq!(
        small.effective_transport_profile(),
        SideTransportProfile::Ipv6Like
    );
    let ipv4: RouterSideOptions = small.with_ipv4_like_compact_header_target();
    assert!(ipv4.omit_unchanged_compact_timestamps);
    assert_eq!(ipv4.max_frame_bytes, 64);
    assert_eq!(
        ipv4.effective_transport_profile(),
        SideTransportProfile::Ipv4Like
    );
}
