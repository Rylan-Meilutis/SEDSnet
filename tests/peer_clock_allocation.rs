#![cfg(all(feature = "std", feature = "timesync"))]
//! Fail the new record/key allocations with the real global allocator.
use sedsnet::timesync::{NetworkClock, PartialNetworkTime};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
struct Allocator;
thread_local! {
    static FAIL: Cell<Option<usize>> = const { Cell::new(None) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let deny = FAIL
            .try_with(|target| {
                let Some(target) = target.get() else {
                    return false;
                };
                COUNT.with(|count| {
                    count.set(count.get() + 1);
                    count.get() == target
                })
            })
            .unwrap_or(false);
        if deny {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = FAIL.try_with(|target| {
                if target.get().is_some() {
                    LIVE.with(|live| live.set(live.get() + layout.size() as isize));
                }
            });
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = FAIL.try_with(|target| {
            if target.get().is_some() {
                LIVE.with(|live| live.set(live.get() - layout.size() as isize));
            }
        });
        unsafe { System.dealloc(ptr, layout) };
    }
}
fn watch(target: usize) {
    COUNT.with(|v| v.set(0));
    LIVE.with(|v| v.set(0));
    FAIL.with(|v| v.set(Some(target)));
}
fn finish() -> (usize, isize) {
    FAIL.with(|v| v.set(None));
    (COUNT.with(Cell::get), LIVE.with(Cell::get))
}
#[test]
fn null_record_or_key_allocation_keeps_old_clock_and_releases_staging() {
    for target in 1..=2 {
        let mut clock = NetworkClock::default();
        clock
            .try_update_source(
                "BASE",
                10,
                PartialNetworkTime::from_unix_ms(100_000),
                0,
                0,
                None,
            )
            .unwrap();
        let before = clock.current_time(0);
        watch(target);
        let result = clock.try_update_source(
            "NEW",
            0,
            PartialNetworkTime::from_unix_ms(200_000),
            0,
            0,
            None,
        );
        let (count, live) = finish();
        assert!(matches!(
            result,
            Err(sedsnet::TelemetryError::Io("memory pressure"))
        ));
        assert_eq!(count, target);
        assert_eq!(live, 0, "staged storage must be freed");
        assert_eq!(clock.current_time(0), before);
        clock.remove_source("BASE");
        assert_eq!(clock.current_time(0), None);
        clock
            .try_update_source(
                "NEW",
                0,
                PartialNetworkTime::from_unix_ms(200_000),
                0,
                0,
                None,
            )
            .unwrap();
        assert_eq!(clock.current_time(0).unwrap().unix_time_ms, Some(200_000));
    }
}
#[test]
fn known_clock_source_refresh_needs_no_record_or_key_allocation() {
    let mut clock = NetworkClock::default();
    clock
        .try_update_source(
            "BASE",
            10,
            PartialNetworkTime::from_unix_ms(100_000),
            0,
            0,
            None,
        )
        .unwrap();
    watch(1);
    let result = clock.try_update_source(
        "BASE",
        0,
        PartialNetworkTime::from_unix_ms(200_000),
        0,
        0,
        None,
    );
    let (count, live) = finish();
    assert!(result.is_ok());
    assert_eq!((count, live), (0, 0));
    assert_eq!(clock.current_time(0).unwrap().unix_time_ms, Some(200_000));
}
