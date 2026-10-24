//! Accepted reliable commands keep one owner through route churn and callbacks.
//! Each case uses a fresh process because the runtime schema is process-wide.
#![cfg(all(feature = "std", feature = "discovery"))]
#[path = "fixtures/accepted_queue/route_churn.rs"]
mod route_churn;
#[path = "fixtures/accepted_queue/handoff.rs"]
mod handoff;

fn isolated(name: &str, run: impl FnOnce()) {
    if std::env::var("SEDSNET_QUEUE_REGRESSION_CHILD").as_deref() == Ok(name) {
        run();
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("SEDSNET_QUEUE_REGRESSION_CHILD", name)
        .output()
        .unwrap();
    assert!(result.status.success(), "{name} failed: {}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}
#[test]
fn no_route_preserves_accepted_ordered_publications() {
    isolated("no_route_preserves_accepted_ordered_publications", route_churn::run);
}
#[test]
fn post_handoff_failure_has_one_reliable_owner() {
    isolated("post_handoff_failure_has_one_reliable_owner", || handoff::run("after-send"));
}
#[test]
fn unordered_post_handoff_failure_has_one_reliable_owner() {
    isolated("unordered_post_handoff_failure_has_one_reliable_owner", || handoff::run("unordered-after-send"));
}
#[test]
fn concurrent_publications_preserve_order_without_starving_other_types() {
    isolated("concurrent_publications_preserve_order_without_starving_other_types", || handoff::run("concurrent"));
}
