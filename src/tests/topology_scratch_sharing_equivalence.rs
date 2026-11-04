//! Exact former estimator oracle, with complete peer lookup chronology.
use super::*;
use core::cell::RefCell;
fn former_topology_snapshot_scratch_impl<'a>(
    sender: &str,
    local_endpoints: usize,
    variables: usize,
    graph_copies: usize,
    include_wire: bool,
    peer_at: &dyn Fn(usize) -> Option<TopologyScratchPeer<'a>>,
) -> (usize, usize) {
    // One calculation body avoids duplicating nested iterator chains for every
    // caller's routing-table iterator; access remains borrowed and allocation-free.
    let peers = core::iter::from_fn({
        let mut index = 0usize;
        move || {
            let peer = peer_at(index);
            index = index.saturating_add(1);
            peer
        }
    });
    #[derive(Clone, Copy)]
    struct View<'a> {
        name: &'a str,
        endpoints: &'a [DataEndpoint],
        sources: &'a [String],
        connections: &'a [String],
        backlink: bool,
    }
    let node_size = core::mem::size_of::<TopologyBoardNode>();
    let string_size = core::mem::size_of::<String>();
    let mut nodes = 1usize;
    let mut graph = node_size
        .saturating_add(sender.len().saturating_mul(2))
        .saturating_add(local_endpoints.saturating_add(1).saturating_mul(4))
        .saturating_add(string_size);
    let mut wire = 24usize
        .saturating_add(sender.len().saturating_mul(2))
        .saturating_add(local_endpoints.saturating_add(1).saturating_mul(4));
    for (index, (name, _, _, _)) in peers.clone().enumerate() {
        if name != sender && !peers.clone().take(index).any(|(old, _, _, _)| old == name) {
            graph = graph.saturating_add(string_size).saturating_add(name.len());
            wire = wire.saturating_add(4).saturating_add(name.len());
        }
    }
    // Mirror the union used by merge_topology_boards without creating owned
    // scratch. Overlapping peer catalogs retain each node and field only once.
    let views = peers.flat_map(|(name, endpoints, sources, boards)| {
        core::iter::once(View {
            name,
            endpoints,
            sources,
            connections: &[],
            backlink: true,
        })
        .filter(move |_| boards.is_empty())
        .chain(boards.iter().map(move |board| View {
            name: &board.sender_id,
            endpoints: &board.reachable_endpoints,
            sources: &board.reachable_timesync_sources,
            connections: &board.connections,
            backlink: board.sender_id == name,
        }))
    });
    for (index, node) in views.clone().enumerate() {
        let prior = || {
            views
                .clone()
                .take(index)
                .filter(|old| old.name == node.name)
        };
        if node.name != sender && prior().next().is_none() {
            nodes = nodes.saturating_add(1);
            graph = graph
                .saturating_add(node_size)
                .saturating_add(node.name.len());
            wire = wire.saturating_add(20).saturating_add(node.name.len());
        }
        for endpoint in node.endpoints {
            if !prior().any(|old| old.endpoints.contains(endpoint)) {
                graph = graph.saturating_add(4);
                wire = wire.saturating_add(4);
            }
        }
        for source in node.sources {
            if !prior().any(|old| old.sources.contains(source)) {
                graph = graph
                    .saturating_add(string_size)
                    .saturating_add(source.len());
                wire = wire.saturating_add(4).saturating_add(source.len());
            }
        }
        for connection in node.connections {
            if connection != node.name
                && !prior().any(|old| {
                    old.connections.contains(connection) || (old.backlink && connection == sender)
                })
            {
                graph = graph
                    .saturating_add(string_size)
                    .saturating_add(connection.len());
                wire = wire.saturating_add(4).saturating_add(connection.len());
            }
        }
        if node.backlink
            && node.name != sender
            && !node.connections.iter().any(|value| value == sender)
            && !prior()
                .any(|old| old.backlink || old.connections.iter().any(|value| value == sender))
        {
            graph = graph
                .saturating_add(string_size)
                .saturating_add(sender.len());
            wire = wire.saturating_add(4).saturating_add(sender.len());
        }
    }
    let grow = |bytes: usize| bytes.checked_next_power_of_two().unwrap_or(usize::MAX);
    let largest = 1024usize
        .max(grow(nodes).saturating_mul(node_size))
        .max(if include_wire { grow(wire) } else { 0 });
    // Election and per-side serialization run in separate phases. Account for
    // the live graph copies in this phase, plus geometric vector growth;
    // packet headers, statistics and queue bookkeeping have separate headroom.
    let additional = 2048usize
        .saturating_add(graph.saturating_mul(graph_copies))
        .saturating_add(variables.saturating_mul(32));
    (additional, largest)
}

fn former_views<'a,'f>(peer_at:&'f dyn Fn(usize)->Option<TopologyScratchPeer<'a>>)
    ->impl Iterator<Item=TopologyScratchView<'a>>+Clone+'f where 'a:'f {
    let peers=core::iter::from_fn({let mut index=0usize;move||{let peer=peer_at(index);index=index.saturating_add(1);peer}});
    peers.flat_map(|(name,endpoints,sources,boards)| {
        core::iter::once(TopologyScratchView{name,endpoints,sources,connections:&[],backlink:true})
            .filter(move |_|boards.is_empty())
            .chain(boards.iter().map(move|board|TopologyScratchView{
                name:&board.sender_id,endpoints:&board.reachable_endpoints,
                sources:&board.reachable_timesync_sources,connections:&board.connections,
                backlink:board.sender_id==name,
            }))
    })
}
fn view_facts(view:Option<TopologyScratchView<'_>>)->Option<(String,usize,usize,usize,usize,bool)> {
    view.map(|v|(v.name.into(),v.name.as_ptr() as usize,v.endpoints.as_ptr() as usize,
        v.sources.as_ptr() as usize,v.connections.as_ptr() as usize,v.backlink))
}
#[test]
fn lazy_views_clone_partial_and_nonfused_outer_end_keep_exact_ledger() {
    let ep=[DataEndpoint(2),DataEndpoint(3)];let sources=vec![String::from("S")];
    let boards=vec![TopologyBoardNode{sender_id:"P".into(),reachable_endpoints:ep.to_vec(),
        reachable_timesync_sources:sources.clone(),connections:vec!["GS".into()]},
        TopologyBoardNode{sender_id:"OTHER".into(),reachable_endpoints:vec![],reachable_timesync_sources:vec![],connections:vec![]}];
    for gap in [false,true] {
        let old_log=RefCell::new(Vec::new());let new_log=RefCell::new(Vec::new());
        let peer=|i|match i {0=>Some(("P",ep.as_slice(),sources.as_slice(),boards.as_slice())),
            1 if !gap=>Some(("FALLBACK",ep.as_slice(),sources.as_slice(),&[][..])),
            2=>Some(("AFTER",ep.as_slice(),sources.as_slice(),boards.as_slice())),_=>None};
        let old_at=|i|{old_log.borrow_mut().push(i);peer(i)};let new_at=|i|{new_log.borrow_mut().push(i);peer(i)};
        let mut old=former_views(&old_at);let mut new=TopologyScratchViews::new(&new_at);
        for _ in 0..9 {
            // Clone/take0 must not invoke the callback; partial clones preserve
            // the current board without looking up that peer again.
            assert_eq!(old.clone().take(0).count(),new.clone().take(0).count());
            let a:Vec<_>=old.clone().take(2).map(|v|view_facts(Some(v))).collect();
            let b:Vec<_>=new.clone().take(2).map(|v|view_facts(Some(v))).collect();assert_eq!(a,b);
            assert_eq!(*old_log.borrow(),*new_log.borrow());
            assert_eq!(view_facts(old.next()),view_facts(new.next()));
            assert_eq!(*old_log.borrow(),*new_log.borrow());
        }
        if gap {assert!(!old_log.borrow().contains(&2),"FlatMap fuses after first missing peer");}
    }
}
type OwnedPeer=(String,Vec<DataEndpoint>,Vec<String>,Vec<TopologyBoardNode>);
fn generated(seed:u64)->Vec<OwnedPeer> {
    let mut state=seed+1;let mut rng=||{state=state.wrapping_mul(6364136223846793005).wrapping_add(1);state};
    (0..seed%7).map(|i| {
        let name=format!("P{}",rng()%3);
        let ep=(0..rng()%4).map(|_|DataEndpoint((rng()%5) as u32)).collect();
        let sources=(0..rng()%4).map(|_|format!("S{}",rng()%3)).collect();
        let boards=(0..rng()%4).map(|_|TopologyBoardNode{
            sender_id:if rng()%4==0{"GS".into()}else{format!("P{}",rng()%3)},
            reachable_endpoints:(0..rng()%4).map(|_|DataEndpoint((rng()%5) as u32)).collect(),
            reachable_timesync_sources:(0..rng()%4).map(|_|format!("S{}",rng()%3)).collect(),
            connections:(0..rng()%4).map(|_|if rng()%3==0{"GS".into()}else{format!("P{}",rng()%3)}).collect(),
        }).collect();let _=i;(name,ep,sources,boards)
    }).collect()
}
fn borrow_peer(peers:&[OwnedPeer],i:usize)->Option<TopologyScratchPeer<'_>> {
    peers.get(i).map(|(n,e,s,b)|(n.as_str(),e.as_slice(),s.as_slice(),b.as_slice()))
}
#[test]
fn actual_estimator_matches_former_results_and_every_lookup_across_bounded_random_catalogs() {
    for seed in 0..48 {
        let peers=generated(seed);
        for (local,variables,copies,wire) in [(0,0,0,false),(4,3,2,true),
            (usize::MAX,usize::MAX,usize::MAX,true),(usize::MAX-1,0,4,false)] {
            let old_log=RefCell::new(Vec::new());let new_log=RefCell::new(Vec::new());
            let old_at=|i|{old_log.borrow_mut().push(i);borrow_peer(&peers,i)};
            let new_at=|i|{new_log.borrow_mut().push(i);borrow_peer(&peers,i)};
            let old=former_topology_snapshot_scratch_impl("GS",local,variables,copies,wire,&old_at);
            let new=topology_snapshot_scratch_impl("GS",local,variables,copies,wire,&new_at);
            assert_eq!(old,new,"seed={seed},local={local},copies={copies},wire={wire}");
            assert_eq!(*old_log.borrow(),*new_log.borrow(),"lookup order seed={seed}");
        }
    }
}
#[test]
fn typed_prior_queries_keep_same_short_circuit_and_provider_ledger() {
    let peers=generated(47);let name="P1";let endpoint=DataEndpoint(2);let source=String::from("S1");let connection=String::from("GS");
    for limit in [0,1,2,4,8,usize::MAX] {for query in 0..5 {
        let a_log=RefCell::new(Vec::new());let b_log=RefCell::new(Vec::new());
        let a_at=|i|{a_log.borrow_mut().push(i);borrow_peer(&peers,i)};let b_at=|i|{b_log.borrow_mut().push(i);borrow_peer(&peers,i)};
        let mut prior=former_views(&a_at).take(limit).filter(|v|v.name==name);
        let a=match query {0=>prior.next().is_some(),1=>prior.any(|v|v.endpoints.contains(&endpoint)),
            2=>prior.any(|v|v.sources.contains(&source)),3=>prior.any(|v|v.connections.contains(&connection)||(v.backlink&&connection=="GS")),
            _=>prior.any(|v|v.backlink||v.connections.iter().any(|v|v=="GS"))};
        let q=match query {0=>ScratchPriorQuery::Any,1=>ScratchPriorQuery::Endpoint(&endpoint),
            2=>ScratchPriorQuery::Source(&source),3=>ScratchPriorQuery::Connection(&connection,"GS"),_=>ScratchPriorQuery::Backlink("GS")};
        let b=prior_scratch_view_matches(TopologyScratchViews::new(&b_at),limit,name,q);
        assert_eq!(a,b);assert_eq!(*a_log.borrow(),*b_log.borrow());
    }}
}
#[test]
fn cursor_clones_never_own_or_early_drop_the_borrowed_provider() {
    use std::sync::Mutex;
    struct ProviderGuard(Arc<Mutex<Vec<&'static str>>>);
    impl ProviderGuard {
        fn observe(&self,index:usize)->Option<TopologyScratchPeer<'static>> {
            self.0.lock().unwrap().push("lookup");
            (index==0).then_some(("P",&[],&[],&[]))
        }
    }
    impl Drop for ProviderGuard {fn drop(&mut self){self.0.lock().unwrap().push("provider_drop");}}
    fn observe(old:bool)->Vec<&'static str> {
        let log=Arc::new(Mutex::new(Vec::new()));let guard=ProviderGuard(log.clone());
        let provider=move |i|guard.observe(i);
        if old {
            let mut cursor=former_views(&provider);cursor.next();let _copy=cursor.clone();
        } else {
            let mut cursor=TopologyScratchViews::new(&provider);cursor.next();let _copy=cursor.clone();
        }
        log.lock().unwrap().push("cursors_gone");drop(provider);
        log.lock().unwrap().clone()
    }
    assert_eq!(observe(true),observe(false));
    assert_eq!(observe(false),vec!["lookup","cursors_gone","provider_drop"]);
}
