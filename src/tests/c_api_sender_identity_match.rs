use super::*;
#[test]
fn c_sender_match_validates_counted_utf8_and_fails_closed() {
    let router = seds_router_new(None, ptr::null_mut(), ptr::null(), 0);
    assert!(!router.is_null());
    let sender = b"identity-source";
    let p = sender.as_ptr() as *const c_char;
    assert!(seds_router_sender_matches_hostname(
        router,
        p,
        sender.len(),
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        ptr::null(),
        p,
        sender.len(),
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        ptr::null(),
        0,
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        p,
        0,
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        p,
        sender.len(),
        ptr::null(),
        0
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        p,
        isize::MAX as usize + 1,
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        p,
        sender.len(),
        p,
        isize::MAX as usize + 1
    ));
    let invalid = [0xffu8];
    assert!(!seds_router_sender_matches_hostname(
        router,
        invalid.as_ptr() as *const c_char,
        1,
        p,
        sender.len()
    ));
    assert!(!seds_router_sender_matches_hostname(
        router,
        p,
        sender.len(),
        invalid.as_ptr() as *const c_char,
        1
    ));
    let alias = b"@addr:101";
    assert!(!seds_router_sender_matches_hostname(
        router,
        alias.as_ptr() as *const c_char,
        alias.len(),
        p,
        sender.len()
    ));
    seds_router_free(router);
}
