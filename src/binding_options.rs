//! Transport-profile defaults shared by the C and Python bindings.

use crate::{
    relay::RelaySideOptions,
    router::{RouterSideOptions, SideTransportProfile},
};

pub(crate) fn router_side_options_for_profile(
    reliable_enabled: bool,
    profile: SideTransportProfile,
    max_frame_bytes: usize,
    compact_header_target_bytes: usize,
    max_side_transport_templates: usize,
) -> RouterSideOptions {
    let mut opts = RouterSideOptions {
        reliable_enabled,
        max_frame_bytes,
        max_side_transport_templates,
        side_transport_profile: profile,
        ..RouterSideOptions::default()
    };
    match profile {
        SideTransportProfile::Canonical => {}
        SideTransportProfile::Template => {
            opts.header_template_enabled = true;
        }
        SideTransportProfile::Ipv6Like => {
            opts.header_template_enabled = true;
            opts.compact_header_target_bytes = if compact_header_target_bytes == 0 {
                crate::router::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES
            } else {
                compact_header_target_bytes
            };
        }
        SideTransportProfile::Ipv4Like => {
            opts.header_template_enabled = true;
            opts.omit_unchanged_compact_timestamps = true;
            opts.compact_header_target_bytes = if compact_header_target_bytes == 0 {
                crate::router::IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES
            } else {
                compact_header_target_bytes
            };
        }
    }
    opts
}

pub(crate) fn relay_side_options_for_profile(
    reliable_enabled: bool,
    profile: SideTransportProfile,
    max_frame_bytes: usize,
    compact_header_target_bytes: usize,
    max_side_transport_templates: usize,
) -> RelaySideOptions {
    let mut opts = RelaySideOptions {
        reliable_enabled,
        max_frame_bytes,
        max_side_transport_templates,
        side_transport_profile: profile,
        ..RelaySideOptions::default()
    };
    match profile {
        SideTransportProfile::Canonical => {}
        SideTransportProfile::Template => {
            opts.header_template_enabled = true;
        }
        SideTransportProfile::Ipv6Like => {
            opts.header_template_enabled = true;
            opts.compact_header_target_bytes = if compact_header_target_bytes == 0 {
                crate::relay::IPV6_LIKE_COMPACT_HEADER_TARGET_BYTES
            } else {
                compact_header_target_bytes
            };
        }
        SideTransportProfile::Ipv4Like => {
            opts.header_template_enabled = true;
            opts.omit_unchanged_compact_timestamps = true;
            opts.compact_header_target_bytes = if compact_header_target_bytes == 0 {
                crate::relay::IPV4_LIKE_COMPACT_HEADER_TARGET_BYTES
            } else {
                compact_header_target_bytes
            };
        }
    }
    opts
}
