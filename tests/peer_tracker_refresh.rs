#![cfg(all(feature = "std", feature = "timesync"))]
use sedsnet::timesync::{
    TimeSyncConfig, TimeSyncSource, TimeSyncTracker, build_timesync_announce_with_sender,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
struct Allocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
    static RECORDS: Cell<usize> = const { Cell::new(0) };
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let refused = LIMIT
            .try_with(|limit| {
                limit.get().is_some_and(|max| {
                    LARGEST.with(|largest| largest.set(largest.get().max(layout.size())));
                    layout.size() > max
                })
            })
            .unwrap_or(false);
        if refused {
            return std::ptr::null_mut();
        }
        let _ = TRACK.try_with(|enabled| {
            if enabled.get() && layout.size() == std::mem::size_of::<TimeSyncSource>() {
                RECORDS.with(|count| count.set(count.get() + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[test]
fn tracker_refresh_reuses_the_peer_record() {
    let mut tracker = TimeSyncTracker::new(TimeSyncConfig::default());
    let first = build_timesync_announce_with_sender("CLOCK_PEER", 1, 100_000).unwrap();
    let next = build_timesync_announce_with_sender("CLOCK_PEER", 1, 101_000).unwrap();
    tracker.handle_announce(&first, 0).unwrap();
    RECORDS.with(|v| v.set(0));
    TRACK.with(|v| v.set(true));
    let result = tracker.handle_announce(&next, 1000);
    TRACK.with(|v| v.set(false));
    assert!(result.is_ok());
    assert_eq!(
        RECORDS.with(Cell::get),
        0,
        "known peer refresh must reuse its record"
    );
    assert_eq!(
        tracker.best_active_source(1000).unwrap().last_time_ms,
        101_000
    );
}

#[test]
fn thirty_two_peer_sources_fit_small_contiguous_blocks_and_keep_all_sources() {
    let names = [
        "P00", "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10", "P11", "P12",
        "P13", "P14", "P15", "P16", "P17", "P18", "P19", "P20", "P21", "P22", "P23", "P24", "P25",
        "P26", "P27", "P28", "P29", "P30", "P31",
    ];
    let cfg = TimeSyncConfig {
        source_timeout_ms: 1000,
        ..Default::default()
    };
    let mut tracker = TimeSyncTracker::new(cfg);
    let packets: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            build_timesync_announce_with_sender(name, i as u64, 100_000 + i as u64).unwrap()
        })
        .collect();
    LARGEST.with(|n| n.set(0));
    LIMIT.with(|limit| limit.set(Some(512)));
    for (i, packet) in packets.iter().enumerate() {
        tracker.handle_announce(packet, i as u64).unwrap();
    }
    LIMIT.with(|limit| limit.set(None));
    assert!(LARGEST.with(Cell::get) <= 512);
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            tracker.best_active_source(1000 + i as u64).unwrap().sender,
            *name
        );
    }
    tracker.refresh(2000);
    assert!(tracker.best_active_source(2000).is_none());
}
