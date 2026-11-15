//! Cortex-M4 instruction counts of SEDSnet time sync hot paths.
//!
//! Runs under `qemu-system-arm -M mps2-an386` with one instruction per
//! translation block; `count.sh` counts executed instructions between the
//! `marker` calls. Each case runs `N` calls; the per-call count is the
//! difference between the case and an empty loop, divided by `N`.
#![no_std]
#![no_main]

extern crate alloc;

use core::hint::black_box;
use cortex_m_rt::entry;
use sedsnet::router::{Router, RouterConfig};
use sedsnet::timesync::{NetworkTime, PartialNetworkTime, SlewedNetworkClock, TimeSyncConfig, TimeSyncRole};

static mut NOW_NS: u64 = 1_000_000_000;
struct SimClock;
impl sedsnet::router::Clock for SimClock {
    fn now_ms(&self) -> u64 {
        unsafe { NOW_NS / 1_000_000 }
    }
    fn now_ns(&self) -> u64 {
        unsafe { NOW_NS }
    }
}

// SEDSnet's embedded build brings its allocator and panic handler; the
// firmware supplies these hooks (a bump heap here).
static mut HEAP: [u8; 1024 * 1024] = [0; 1024 * 1024];
static mut NEXT: usize = 0;
#[unsafe(no_mangle)]
pub extern "C" fn telemetryMalloc(size: usize) -> *mut core::ffi::c_void {
    unsafe {
        let start = (NEXT + 7) & !7;
        if start + size > 1024 * 1024 {
            return core::ptr::null_mut();
        }
        NEXT = start + size;
        (&raw mut HEAP as *mut u8).add(start).cast()
    }
}
// Firmware critical-section hooks the SDK's router lock calls.
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_lock() {}
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_unlock() {}
#[unsafe(no_mangle)]
pub extern "C" fn telemetryFree(_: *mut core::ffi::c_void) {}
#[unsafe(no_mangle)]
pub extern "C" fn telemetry_panic_hook(_: *const u8, _: usize) {
    exit(1)
}

/// Semihosting SYS_EXIT.
fn exit(code: u32) -> ! {
    let block = [0x20026u32, code];
    unsafe {
        core::arch::asm!("bkpt 0xAB", in("r0") 0x20u32, in("r1") &block as *const _ as u32);
    }
    loop {}
}

/// Executed-instruction boundary the counter looks for (address in the log).
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn marker(case: u32) {
    black_box(case);
}

const N: u32 = 64;

#[entry]
fn main() -> ! {
    // A clock as RF runs it: slewing out an offset, with a learned rate.
    let mut clock = SlewedNetworkClock::new(50_000);
    clock.steer_unix_ns(1_000_000_000, 1_767_225_600_000_000_000);
    clock.steer_unix_ns(2_000_000_000, 1_767_225_601_003_000_000);
    let mut settled = clock;
    settled.steer_unix_ns(3_000_000_000, 1_767_225_602_000_000_000);
    marker(0);
    for i in 0..N {
        black_box(i);
    }
    marker(1);
    for i in 0..N {
        // Slew still in progress.
        black_box(black_box(&clock).read_unix_ms(2_000_000_000 + u64::from(i) * 100_000));
    }
    marker(2);
    for i in 0..N {
        // Slew finished long ago (the common case between exchanges).
        black_box(black_box(&settled).read_unix_ms(9_000_000_000 + u64::from(i) * 100_000));
    }
    marker(3);
    for i in 0..N {
        black_box(NetworkTime::from_unix_ns(black_box(1_767_225_600_123_456_789i128 + i128::from(i) * 1_000_000)));
    }
    marker(4);
    // The router read every packet timestamp takes (RF leading on GPS time).
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RF").with_timesync(TimeSyncConfig {
            role: TimeSyncRole::Source,
            priority: 70,
            ..Default::default()
        }),
        alloc::boxed::Box::new(SimClock),
    );
    router.set_local_network_time(PartialNetworkTime::from_unix_ms(1_767_225_600_000));
    marker(5);
    for _ in 0..N {
        unsafe { NOW_NS += 100_000 };
        black_box(black_box(&router).network_time_ms());
    }
    marker(6);
    for _ in 0..N {
        unsafe { NOW_NS += 100_000 };
    }
    marker(7);
    exit(0)
}
