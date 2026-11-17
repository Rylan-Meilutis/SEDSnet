use super::*;

/// The C surface of steps and epochs: configure a source, set its time, step
/// it four hours back, and read the epoch, the status step fields and the age
/// of a pre-step stamp translated across the step.
#[test]
fn c_station_step_reports_epoch_status_and_translated_stamp_age() {
    let router = seds_router_new(None, ptr::null_mut(), ptr::null(), 0);
    assert!(!router.is_null());
    assert_eq!(seds_router_configure_timesync(router, true, 1, 10, 5_000, 1_000, 1_000), SedsResult::SedsOk as i32);
    assert_eq!(seds_router_set_timesync_step_policy(router, 0, 0), SedsResult::SedsOk as i32);
    assert_eq!(
        seds_router_set_local_network_datetime_millis(router, 2026, 11, 16, 20, 0, 0, 0),
        SedsResult::SedsOk as i32
    );
    let (mut before, mut epoch0) = (0u64, u16::MAX);
    assert_eq!(seds_router_get_network_time_ms_with_epoch(router, &mut before, &mut epoch0), SedsResult::SedsOk as i32);
    assert_eq!(epoch0, 0);

    // Inhibited, four hours are slewed: still epoch 0.
    assert_eq!(seds_router_set_timesync_steps_allowed(router, false), SedsResult::SedsOk as i32);
    assert_eq!(
        seds_router_set_local_network_datetime_millis(router, 2026, 11, 16, 16, 0, 0, 0),
        SedsResult::SedsOk as i32
    );
    let mut status = SedsTimeSyncStatus::default();
    assert_eq!(seds_router_get_timesync_status(router, &mut status), SedsResult::SedsOk as i32);
    assert_eq!((status.epoch, status.steps, status.steps_allowed, status.last_step_reason), (0, 0, 0, 0));
    assert_eq!(status.last_step_age_ms, u32::MAX);

    // Allowed: the same correction steps into epoch 1.
    assert_eq!(seds_router_set_timesync_steps_allowed(router, true), SedsResult::SedsOk as i32);
    assert_eq!(
        seds_router_set_local_network_datetime_millis(router, 2026, 11, 16, 16, 0, 0, 0),
        SedsResult::SedsOk as i32
    );
    assert_eq!(seds_router_get_timesync_status(router, &mut status), SedsResult::SedsOk as i32);
    assert_eq!((status.epoch, status.steps, status.steps_allowed), (1, 1, 1));
    assert_eq!(status.last_step_reason, crate::timesync::TimeSyncStepReason::LocalSource.code());
    assert_eq!((status.last_step_from_epoch, status.last_step_to_epoch), (0, 1));
    assert!(status.last_step_delta_ms.abs_diff(-4 * 3_600_000) < 1_000, "{status:?}");

    // A stamp from before the step is seconds old, not hours in the future.
    let (mut kind, mut age) = (u8::MAX, 0i64);
    assert_eq!(seds_router_network_stamp_age_ms(router, epoch0, before, &mut kind, &mut age), SedsResult::SedsOk as i32);
    assert_eq!(kind, 0);
    assert!((0..1_000).contains(&age), "age {age}");
    assert_eq!(seds_router_network_stamp_age_ms(router, 2, before, &mut kind, &mut age), SedsResult::SedsOk as i32);
    assert_eq!(kind, 1, "newer epoch");
    assert_ne!(seds_router_network_stamp_age_ms(ptr::null_mut(), 0, 0, &mut kind, &mut age), SedsResult::SedsOk as i32);

    // The validity-window check: the pre-step stamp is fresh within 5 s; a
    // 6 s old one is not; a newer epoch passes while just heard of.
    let mut fresh = false;
    assert_eq!(seds_router_network_stamp_fresh(router, epoch0, before, 5_000, 1_000, &mut fresh), SedsResult::SedsOk as i32);
    assert!(fresh);
    assert_eq!(seds_router_network_stamp_fresh(router, epoch0, before - 6_000, 5_000, 1_000, &mut fresh), SedsResult::SedsOk as i32);
    assert!(!fresh);
    assert_eq!(seds_router_network_stamp_fresh(router, 2, before, 5_000, 1_000, &mut fresh), SedsResult::SedsOk as i32);
    assert!(fresh);
    assert_ne!(seds_router_network_stamp_fresh(router, 0, 0, 0, 0, ptr::null_mut()), SedsResult::SedsOk as i32);

    // A persisted epoch raises the clock's epoch, never lowers it.
    let mut epoch = 0u16;
    assert_eq!(seds_router_raise_time_epoch(router, 5, &mut epoch), SedsResult::SedsOk as i32);
    assert_eq!(epoch, 5);
    assert_eq!(seds_router_raise_time_epoch(router, 3, ptr::null_mut()), SedsResult::SedsOk as i32);
    assert_eq!(seds_router_get_timesync_status(router, &mut status), SedsResult::SedsOk as i32);
    assert_eq!(status.epoch, 5);
    assert_eq!(status.last_step_reason, crate::timesync::TimeSyncStepReason::Raised.code());
    seds_router_free(router);
}
