
use crate::{
    TelemetryResult,
    router::{AddressChange, AddressChangeReason, P2pStreamEventKind, Router, RouterConfig},
};
use alloc::{sync::Arc, vec::Vec};
use std::sync::Mutex;

fn crosswire(a: &Arc<Router>, b: &Arc<Router>) {
    let b_rx = b.clone();
    a.add_side_packet("a-to-b", move |pkt| b_rx.rx_from_side(pkt, 0));
    let a_rx = a.clone();
    b.add_side_packet("b-to-a", move |pkt| a_rx.rx_from_side(pkt, 0));
}

fn exchange_discovery(a: &Router, b: &Router) {
    a.announce_discovery().unwrap();
    b.announce_discovery().unwrap();
    a.process_all_queues().unwrap();
    b.process_all_queues().unwrap();
    a.process_all_queues().unwrap();
    b.process_all_queues().unwrap();
}

#[test]
fn p2p_service_port_delivers_http_like_payload_by_hostname_and_address() {
    let server_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let server_seen_c = server_seen.clone();

    let client = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("client-node")
            .with_dynamic_address(),
    ));
    let server = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("http-service")
            .with_static_address(0x1020_3040),
    ));
    server
        .bind_p2p_port(80, move |msg| -> TelemetryResult<()> {
            assert_eq!(msg.source_hostname, "client-node");
            assert_eq!(msg.source_port, 49_152);
            assert_eq!(msg.destination_port, 80);
            server_seen_c.lock().unwrap().push(msg.payload.to_vec());
            Ok(())
        })
        .unwrap();

    crosswire(&client, &server);
    exchange_discovery(&client, &server);

    client
        .send_p2p_to_hostname(
            "http-service",
            80,
            49_152,
            b"GET /status HTTP/1.1\r\nHost: http-service\r\n\r\n",
        )
        .unwrap();
    server.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    client
        .send_p2p_to_address(
            0x1020_3040,
            80,
            49_152,
            b"POST /upload HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
    server.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    let seen = server_seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].starts_with(b"GET /status HTTP/1.1"));
    assert!(seen[1].starts_with(b"POST /upload HTTP/1.1"));
}

#[test]
fn duplicate_dynamic_addresses_are_shifted_and_reported() {
    let changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
    let changes_c = changes.clone();
    let older = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("older-dynamic")
            .with_requested_address(77),
    ));
    let newer = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("newer-dynamic")
            .with_requested_address(77)
            .on_address_change(move |change| {
                changes_c.lock().unwrap().push(change);
                Ok(())
            }),
    ));
    crosswire(&older, &newer);
    exchange_discovery(&older, &newer);

    assert_eq!(older.current_address(), 77);
    assert_ne!(newer.current_address(), 77);
    let changes = changes.lock().unwrap().clone();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].reason, AddressChangeReason::RequestedConflict);
    assert_eq!(changes[0].old_address, 77);
    assert_eq!(changes[0].new_address, newer.current_address());
}

#[test]
fn static_address_beats_dynamic_and_duplicate_static_older_wins() {
    let static_node = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("static-owner")
            .with_static_address(0x55),
    ));
    let dynamic = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("dynamic-loser")
            .with_requested_address(0x55),
    ));
    crosswire(&static_node, &dynamic);
    exchange_discovery(&static_node, &dynamic);
    assert_eq!(static_node.current_address(), 0x55);
    assert_ne!(dynamic.current_address(), 0x55);

    let static_changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
    let static_changes_c = static_changes.clone();
    let newer_static = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("static-newer")
            .with_static_address(0x55)
            .on_address_change(move |change| {
                static_changes_c.lock().unwrap().push(change);
                Ok(())
            }),
    ));
    crosswire(&static_node, &newer_static);
    exchange_discovery(&static_node, &newer_static);

    assert_eq!(static_node.current_address(), 0x55);
    assert_ne!(newer_static.current_address(), 0x55);
    let changes = static_changes.lock().unwrap().clone();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].reason, AddressChangeReason::StaticConflict);
}

#[test]
fn duplicate_hostnames_are_renamed_and_hostname_p2p_uses_discovered_name() {
    let changes = Arc::new(Mutex::new(Vec::<AddressChange>::new()));
    let changes_c = changes.clone();
    let first = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("duplicate-host")
            .with_static_address(0x301),
    ));
    let second_seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let second_seen_c = second_seen.clone();
    let second = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("duplicate-host")
            .with_static_address(0x302)
            .on_address_change(move |change| {
                changes_c.lock().unwrap().push(change);
                Ok(())
            }),
    ));
    second
        .bind_p2p_port(443, move |msg| {
            second_seen_c.lock().unwrap().push(msg.payload.to_vec());
            Ok(())
        })
        .unwrap();

    crosswire(&first, &second);
    exchange_discovery(&first, &second);

    assert_eq!(first.hostname().as_ref(), "duplicate-host");
    assert_ne!(second.hostname().as_ref(), "duplicate-host");
    let renamed = second.hostname().to_string();
    let changes = changes.lock().unwrap().clone();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].reason, AddressChangeReason::HostnameConflict);

    first
        .send_p2p_to_hostname(&renamed, 443, 50_000, b"GET /secure HTTP/1.1\r\n\r\n")
        .unwrap();
    second.process_all_queues().unwrap();
    first.process_all_queues().unwrap();
    assert_eq!(
        second_seen.lock().unwrap().as_slice(),
        &[b"GET /secure HTTP/1.1\r\n\r\n".to_vec()]
    );
}

#[test]
fn p2p_stream_connects_sends_and_closes_without_datagram_delivery() {
    let client_events = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_events = Arc::new(Mutex::new(Vec::<String>::new()));
    let datagrams = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));

    let client = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("stream-client")
            .with_dynamic_address(),
    ));
    let server = Arc::new(Router::new(
        RouterConfig::default()
            .with_hostname("stream-server")
            .with_static_address(0x4040),
    ));

    let client_events_c = client_events.clone();
    client
        .bind_p2p_stream_port(49_200, move |event| {
            assert!(matches!(
                event.kind,
                P2pStreamEventKind::Connected
                    | P2pStreamEventKind::Data
                    | P2pStreamEventKind::Closed
                    | P2pStreamEventKind::Reset
            ));
            client_events_c.lock().unwrap().push(format!(
                "{:?}:{}:{}:{}:{}",
                event.kind,
                event.stream_id,
                event.peer_stream_id,
                event.sequence,
                String::from_utf8_lossy(event.payload)
            ));
            Ok(())
        })
        .unwrap();

    let server_events_c = server_events.clone();
    server
        .bind_p2p_stream_port(8080, move |event| {
            assert!(matches!(
                event.kind,
                P2pStreamEventKind::Accepted
                    | P2pStreamEventKind::Data
                    | P2pStreamEventKind::Closed
                    | P2pStreamEventKind::Reset
            ));
            server_events_c.lock().unwrap().push(format!(
                "{:?}:{}:{}:{}:{}",
                event.kind,
                event.stream_id,
                event.peer_stream_id,
                event.sequence,
                String::from_utf8_lossy(event.payload)
            ));
            Ok(())
        })
        .unwrap();

    let datagrams_c = datagrams.clone();
    server
        .bind_p2p_port(8080, move |msg| {
            datagrams_c.lock().unwrap().push(msg.payload.to_vec());
            Ok(())
        })
        .unwrap();

    crosswire(&client, &server);
    exchange_discovery(&client, &server);

    let client_stream = client
        .open_p2p_stream_to_hostname("stream-server", 8080, 49_200)
        .unwrap();
    server.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    let connected = client_events.lock().unwrap().clone();
    assert_eq!(connected.len(), 1);
    assert!(connected[0].starts_with("Connected:"));

    let accepted = server_events.lock().unwrap().clone();
    assert_eq!(accepted.len(), 1);
    assert!(accepted[0].starts_with("Accepted:"));
    let server_stream: u32 = accepted[0].split(':').nth(1).unwrap().parse().unwrap();

    client
        .send_p2p_stream(client_stream, b"GET /stream HTTP/1.1\r\n\r\n")
        .unwrap();
    server.process_all_queues().unwrap();
    client.process_all_queues().unwrap();

    server
        .send_p2p_stream(
            server_stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        )
        .unwrap();
    client.process_all_queues().unwrap();
    server.process_all_queues().unwrap();

    client.close_p2p_stream(client_stream).unwrap();
    server.process_all_queues().unwrap();

    let server_events = server_events.lock().unwrap().clone();
    assert!(
        server_events
            .iter()
            .any(|e| { e.starts_with("Data:") && e.ends_with("GET /stream HTTP/1.1\r\n\r\n") })
    );
    assert!(server_events.iter().any(|e| e.starts_with("Closed:")));

    let client_events = client_events.lock().unwrap().clone();
    assert!(client_events.iter().any(|e| {
        e.starts_with("Data:") && e.ends_with("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    }));

    assert!(datagrams.lock().unwrap().is_empty());
}
