//! Actual private unit retry compared with its unchanged former generic body.
use super::*;
use std::sync::Mutex;
use core::cell::Cell;
fn former<F,T>(router:&Router,times:usize,f:F)->Result<(T,usize),(TelemetryError,usize)>
where F:Fn()->TelemetryResult<T> {
    let times=if router.cfg.role.local_services(){times}else{times.min(1)};
    let mut last_err=None;
    for attempt in 0..times {
        match f() {
            Ok(v)=>return Ok((v,attempt+1)),
            Err(e) if Router::is_transient_tx_error(&e)=>return Err((e,attempt+1)),
            Err(e)=>last_err=Some((e,attempt+1)),
        }
    }
    Err(last_err.expect("times > 0"))
}
#[derive(Clone,Copy,Debug)]
enum Outcome { Success, Permanent, Busy }
fn outcome(kind:Outcome, identity:&Arc<str>)->TelemetryResult<()> {
    match kind {Outcome::Success=>Ok(()),Outcome::Permanent=>Err(TelemetryError::GenericError(Some(identity.clone()))),Outcome::Busy=>Err(TelemetryError::Io("side tx busy"))}
}
fn result_facts(result:Result<((),usize),(TelemetryError,usize)>,identity:&Arc<str>)->(&'static str,usize) {
    match result {
        Ok(((),n))=>("ok",n),
        Err((TelemetryError::GenericError(Some(value)),n))=>{assert!(Arc::ptr_eq(&value,identity));("permanent",n)},
        Err((TelemetryError::Io("side tx busy"),n))=>("busy",n),
        unexpected=>panic!("unexpected result {unexpected:?}"),
    }
}
#[test]
fn unit_retry_all_attempt_policies_and_error_owner_match_former_generic() {
    for role in [crate::routing_config::RoutingRole::Router,crate::routing_config::RoutingRole::Relay] {
        let mut cfg=RouterConfig::new([]);cfg.role=role;
        let router=Router::new_with_clock(cfg,Box::new(||1000));
        for (limit,script) in [(1,vec![Outcome::Success]),(4,vec![Outcome::Permanent;4]),
            (4,vec![Outcome::Permanent,Outcome::Success]),(4,vec![Outcome::Busy]),
            (4,vec![Outcome::Permanent,Outcome::Busy]),(1,vec![Outcome::Permanent]),
            (7,vec![Outcome::Success])] {
            let identity:Arc<str>=Arc::from("same immutable error owner");
            let old_calls=Cell::new(0);let new_calls=Cell::new(0);
            let old=former(&router,limit,||{let n=old_calls.get();old_calls.set(n+1);outcome(script[n],&identity)});
            let new=router.retry_with_attempts(limit,&||{let n=new_calls.get();new_calls.set(n+1);outcome(script[n],&identity)});
            assert_eq!(result_facts(old,&identity),result_facts(new,&identity));
            assert_eq!(old_calls.get(),new_calls.get());
            assert_eq!(Arc::strong_count(&identity),1,"no clone retained by retry helper");
        }
    }
}
#[test]
fn zero_attempts_preserves_original_panic_without_callback() {
    let router=Router::new_with_clock(RouterConfig::new([]),Box::new(||1000));
    let calls=Cell::new(0);
    let old=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||former(&router,0,||{calls.set(calls.get()+1);Ok(())})));
    let new=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||router.retry_with_attempts(0,&||{calls.set(calls.get()+1);Ok(())})));
    assert!(old.is_err()&&new.is_err());assert_eq!(calls.get(),0);
}
struct Capture(Arc<Mutex<Vec<&'static str>>>);
impl Drop for Capture {fn drop(&mut self){self.0.lock().unwrap().push("capture_drop");}}
fn tail_or_early(old:bool,early:bool,router:&Router,log:Arc<Mutex<Vec<&'static str>>>,fail:bool)->TelemetryResult<()> {
    let capture=Capture(log.clone());
    let callback=move||{capture.0.lock().unwrap().push("callback");if fail{Err(TelemetryError::Io("side tx busy"))}else{Ok(())}};
    let result=if old {former(router,3,callback)}else{router.retry_with_attempts(3,&callback)};
    if early {return result.map(|_|()).map_err(|(e,_)|e)}
    result.map(|_|()).map_err(|(e,_)|e)
}
#[test]
fn owned_capture_drop_and_tail_early_return_timing_match_former() {
    let router=Router::new_with_clock(RouterConfig::new([]),Box::new(||1000));
    for early in [false,true] {for fail in [false,true] {
        let old=Arc::new(Mutex::new(Vec::new()));let new=Arc::new(Mutex::new(Vec::new()));
        assert_eq!(tail_or_early(true,early,&router,old.clone(),fail).is_err(),fail);
        old.lock().unwrap().push("caller_after_return");
        assert_eq!(tail_or_early(false,early,&router,new.clone(),fail).is_err(),fail);
        new.lock().unwrap().push("caller_after_return");
        assert_eq!(*old.lock().unwrap(),*new.lock().unwrap());
        assert_eq!(*new.lock().unwrap(),vec!["callback","capture_drop","caller_after_return"]);
    }}
}
