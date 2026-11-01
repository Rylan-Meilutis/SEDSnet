#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::{
    router::{Router, RouterConfig},
    wire_format,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ffi::{c_char, c_void},
    ptr,
    sync::{Arc, Mutex},
};
// Exercise the public C ABI symbols; the Rust c_api module stays private.
unsafe extern "C" {
    safe fn seds_router_new(
        now: Option<extern "C" fn(*mut c_void) -> u64>,
        user: *mut c_void,
        handlers: *const c_void,
        count: usize,
    ) -> *mut c_void;
    safe fn seds_router_free(router: *mut c_void);
    safe fn seds_router_add_side_packed(
        router: *mut c_void,
        name: *const c_char,
        len: usize,
        tx: Option<extern "C" fn(*const u8, usize, *mut c_void) -> i32>,
        user: *mut c_void,
        reliable: bool,
    ) -> i32;
    safe fn seds_router_receive_packed_from_side(
        router: *mut c_void,
        side: u32,
        data: *const u8,
        len: usize,
    ) -> i32;
    safe fn seds_router_process_all_queues(router: *mut c_void) -> i32;
    safe fn seds_router_sender_matches_hostname(
        router: *const c_void,
        sender: *const c_char,
        sender_len: usize,
        hostname: *const c_char,
        hostname_len: usize,
    ) -> bool;
}
thread_local! {static COUNT:Cell<Option<usize>>=const{Cell::new(None)};}
struct Counting;
#[global_allocator]
static ALLOCATOR: Counting = Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let _ = COUNT.try_with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1))
            }
        });
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
extern "C" fn discard(_: *const u8, _: usize, _: *mut c_void) -> i32 {
    0
}
#[test]
fn sender_match_rust_and_c_predicates_allocate_nothing() {
    let name = "identity-allocation-source";
    let frames = Arc::new(Mutex::new(Vec::new()));
    let capture = frames.clone();
    let producer = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname(name)
            .with_static_address(101),
        Box::new(|| 1),
    );
    producer.add_side_packed("wire", move |wire| {
        capture.lock().unwrap().push(wire.to_vec());
        Ok(())
    });
    producer.announce_discovery().unwrap();
    producer.process_all_queues_with_timeout(0).unwrap();
    let frames = frames.lock().unwrap();
    let compact = format!(
        "@addr:{}",
        wire_format::peek_envelope(&frames[0])
            .unwrap()
            .source_address
    );
    let receiver = Router::new_with_clock(
        RouterConfig::new([])
            .with_hostname("identity-allocation-receiver")
            .with_static_address(5000),
        Box::new(|| 1),
    );
    let side = receiver.add_side_packed("source", |_| Ok(()));
    assert!(!receiver.sender_matches_hostname(&compact, name));
    let c = seds_router_new(None, ptr::null_mut(), ptr::null(), 0);
    assert!(!c.is_null());
    let c_side = seds_router_add_side_packed(
        c,
        c"source".as_ptr(),
        6,
        Some(discard),
        ptr::null_mut(),
        false,
    );
    assert!(c_side >= 0);
    let expected = name.as_ptr() as *const c_char;
    assert!(!seds_router_sender_matches_hostname(
        c,
        compact.as_ptr() as *const c_char,
        compact.len(),
        expected,
        name.len()
    ));
    for wire in frames.iter() {
        receiver.rx_packed_from_side(wire, side).unwrap();
        assert_eq!(
            seds_router_receive_packed_from_side(c, c_side as u32, wire.as_ptr(), wire.len()),
            0
        );
    }
    receiver.process_all_queues_with_timeout(0).unwrap();
    assert_eq!(seds_router_process_all_queues(c), 0);
    let assigned = "@addr:101";
    let unknown = "@addr:4294967295";
    COUNT.with(|c| c.set(Some(0)));
    for _ in 0..1000 {
        assert!(receiver.sender_matches_hostname(name, name));
        assert!(receiver.sender_matches_hostname(&compact, name));
        assert!(receiver.sender_matches_hostname(assigned, name));
        assert!(!receiver.sender_matches_hostname(unknown, name));
        assert!(seds_router_sender_matches_hostname(
            c,
            compact.as_ptr() as *const c_char,
            compact.len(),
            expected,
            name.len()
        ));
        assert!(seds_router_sender_matches_hostname(
            c,
            assigned.as_ptr() as *const c_char,
            assigned.len(),
            expected,
            name.len()
        ));
    }
    let allocations = COUNT.with(|c| c.replace(None)).unwrap();
    assert_eq!(allocations, 0);
    seds_router_free(c);
    eprintln!(
        "SENDER_MATCH_ALLOCATION: calls=6000 Rust_and_C allocations={allocations} compact={compact} assigned={assigned}"
    );
}
