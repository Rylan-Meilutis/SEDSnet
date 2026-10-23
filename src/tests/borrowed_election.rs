//! Preserve discovery-master election semantics while borrowing graph names.
use crate::discovery::{TopologyBoardNode, elect_discovery_master};
use std::collections::BTreeMap;
fn reference_election(local_sender: &str, boards: &[TopologyBoardNode]) -> String {
    let mut nodes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for board in boards {
        nodes.entry(board.sender_id.clone()).or_default();
        for peer in board.connections.iter() {
            nodes
                .entry(peer.clone())
                .or_default()
                .push(board.sender_id.clone());
            nodes
                .entry(board.sender_id.clone())
                .or_default()
                .push(peer.clone());
        }
    }
    nodes.entry(local_sender.to_string()).or_default();
    for peers in nodes.values_mut() {
        peers.sort_unstable();
        peers.dedup();
    }

    let mut best_sender = local_sender.to_string();
    let mut best_unreachable = usize::MAX;
    let mut best_max_hops = usize::MAX;
    let mut best_total_hops = usize::MAX;

    for sender in nodes.keys() {
        let mut frontier = vec![sender.clone()];
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        seen.insert(sender.clone(), 0);
        let mut idx = 0;
        while idx < frontier.len() {
            let cur = frontier[idx].clone();
            idx += 1;
            let cur_dist = seen[&cur];
            if let Some(peers) = nodes.get(&cur) {
                for peer in peers {
                    if !seen.contains_key(peer) {
                        seen.insert(peer.clone(), cur_dist + 1);
                        frontier.push(peer.clone());
                    }
                }
            }
        }

        let unreachable = nodes.len().saturating_sub(seen.len());
        let max_hops = seen.values().copied().max().unwrap_or(0);
        let total_hops = seen.values().copied().sum();
        let better = unreachable < best_unreachable
            || (unreachable == best_unreachable && max_hops < best_max_hops)
            || (unreachable == best_unreachable
                && max_hops == best_max_hops
                && total_hops < best_total_hops)
            || (unreachable == best_unreachable
                && max_hops == best_max_hops
                && total_hops == best_total_hops
                && sender < &best_sender);
        if better {
            best_sender = sender.clone();
            best_unreachable = unreachable;
            best_max_hops = max_hops;
            best_total_hops = total_hops;
        }
    }

    best_sender
}

#[test]
fn borrowed_election_matches_owned_reference_for_partial_and_mixed_graphs() {
    for seed in 0..80u32 {
        let width = 1 + seed as usize % 10;
        let names: Vec<String> = (0..width + 3)
            .map(|i| {
                if i % 3 == 0 {
                    format!("node_{i}_α")
                } else {
                    format!("node_{i}")
                }
            })
            .collect();
        let mut random = seed + 1;
        let mut boards = Vec::new();
        for i in 0..width {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let mut connections = Vec::new();
            for _ in 0..random % 7 {
                random = random.wrapping_mul(1664525).wrapping_add(1013904223);
                connections.push(names[random as usize % names.len()].clone());
            }
            if seed % 4 == 0 {
                connections.push(names[i].clone());
            }
            if let Some(first) = connections.first().cloned() {
                connections.push(first);
            }
            boards.push(TopologyBoardNode {
                sender_id: names[i].clone(),
                reachable_endpoints: Vec::new(),
                reachable_timesync_sources: Vec::new(),
                connections,
            });
        }
        if seed % 3 == 0 {
            boards.push(boards[0].clone());
        }
        if seed % 2 == 0 {
            boards.reverse();
        }
        let before = boards.clone();
        for local in [names[0].as_str(), "LOCAL_ONLY", ""] {
            assert_eq!(
                elect_discovery_master(local, &boards),
                reference_election(local, &boards),
                "election changed for seed {seed}, local {local:?}"
            );
        }
        assert_eq!(boards, before, "election changed its borrowed input");
    }
    assert_eq!(elect_discovery_master("LOCAL", &[]), "LOCAL");
}
