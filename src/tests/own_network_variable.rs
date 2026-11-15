use super::*;
use std::sync::Mutex;

// A writer of a network variable answers requests with its own last write,
// never with another sender's report of the same type that it cached later
// (a flight computer's own state report on a station that writes the
// desired state). Its cache still holds the newest observation for readers.

const WRITER: &str = "WRITER";

fn own_type() -> (DataType, DataEndpoint) {
    crate::tests::ensure_common_test_schema();
    let endpoint = DataEndpoint::named("RADIO");
    let ty = crate::config::register_data_type_with_description(
        "OWN_NETWORK_VARIABLE",
        "",
        crate::MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[endpoint],
        crate::ReliableMode::None,
        16,
    )
    .unwrap();
    (ty, endpoint)
}

fn value(ty: DataType, endpoint: DataEndpoint, sender: &str, timestamp: u64, byte: u8) -> Packet {
    Packet::new(ty, &[endpoint], sender, timestamp, Arc::<[u8]>::from([byte])).unwrap()
}

/// A writer and a requesting client, linked both ways. Returns the writer,
/// the client and what the client received from the writer.
type Received = Arc<Mutex<Vec<(String, u8)>>>;

fn link(ty: DataType) -> (Arc<Router>, Arc<Router>, Received) {
    let writer = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender(WRITER), Box::new(|| 1000)));
    writer.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE).unwrap();
    let client = Arc::new(Router::new_with_clock(RouterConfig::new([]).with_sender("CLIENT"), Box::new(|| 1000)));
    client.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (to_client, record) = (client.clone(), seen.clone());
    writer.add_side_packet("to-client", move |pkt: &Packet| {
        if pkt.data_type() == ty {
            record.lock().unwrap().push((pkt.sender().to_string(), pkt.payload()[0]));
        }
        to_client.rx_from_side(pkt, 0)
    });
    let to_writer = writer.clone();
    client.add_side_packet("to-writer", move |pkt: &Packet| to_writer.rx_from_side(pkt, 0));
    (writer, client, seen)
}

fn pump(routers: &[&Arc<Router>]) {
    for _ in 0..5 {
        for router in routers {
            router.process_all_queues().unwrap();
        }
    }
}

/// Another sender's report reaching the writer, as from a side.
fn report(writer: &Router, packet: &Packet) {
    writer.rx_from_side(packet, 0).unwrap();
}

#[test]
fn a_writer_answers_a_request_with_its_own_write_not_a_newer_report() {
    let (ty, endpoint) = own_type();
    let (writer, client, seen) = link(ty);
    writer.set_network_variable(value(ty, endpoint, WRITER, 10, 15)).unwrap();
    pump(&[&writer, &client]);
    report(&writer, &value(ty, endpoint, "REPORTER", 20, 16));
    pump(&[&writer, &client]);
    assert_eq!(writer.cached_managed_variable(ty).map(|p| p.payload()[0]), Some(16), "the cache keeps the newest observation");
    seen.lock().unwrap().clear();
    client.request_managed_variable(ty).unwrap();
    pump(&[&client, &writer]);
    assert_eq!(*seen.lock().unwrap(), vec![(WRITER.to_string(), 15)]);
}

#[test]
fn a_writer_never_answers_with_another_senders_report() {
    let (ty, endpoint) = own_type();
    let (writer, client, seen) = link(ty);
    report(&writer, &value(ty, endpoint, "REPORTER", 20, 16));
    pump(&[&writer, &client]);
    seen.lock().unwrap().clear();
    client.request_managed_variable(ty).unwrap();
    pump(&[&client, &writer]);
    assert_eq!(*seen.lock().unwrap(), vec![], "no write of its own to answer with");
}

#[test]
fn own_network_variable_is_the_routers_own_latest_write() {
    let (ty, endpoint) = own_type();
    let writer = Router::new_with_clock(RouterConfig::new([]).with_sender(WRITER), Box::new(|| 1000));
    writer.enable_network_variable(ty, NetworkVariablePermissions::READ_WRITE).unwrap();
    writer.add_side_packet("radio", |_: &Packet| Ok(()));
    assert!(writer.own_network_variable(ty).is_none());
    writer.set_network_variable(value(ty, endpoint, WRITER, 10, 1)).unwrap();
    writer.set_network_variable(value(ty, endpoint, WRITER, 20, 2)).unwrap();
    report(&writer, &value(ty, endpoint, "REPORTER", 30, 9));
    assert_eq!(writer.own_network_variable(ty).map(|p| (p.timestamp(), p.payload()[0])), Some((20, 2)));
    // An older copy of its own write, served back by some other cache, is not newer.
    report(&writer, &value(ty, endpoint, WRITER, 10, 1));
    assert_eq!(writer.own_network_variable(ty).map(|p| (p.timestamp(), p.payload()[0])), Some((20, 2)));
    // Its own later write is.
    writer.set_network_variable(value(ty, endpoint, WRITER, 40, 3)).unwrap();
    assert_eq!(writer.own_network_variable(ty).map(|p| p.payload()[0]), Some(3));
    assert!(writer.invalidate_network_variable_cache(ty));
    assert!(writer.own_network_variable(ty).is_none(), "invalidated with the cache");
}

/// A read-only router keeps its own transmitted value too (a station that
/// writes it only as ordinary data), and still never answers.
#[test]
fn a_read_only_router_keeps_its_own_sent_value_and_never_answers() {
    let (ty, endpoint) = own_type();
    let (writer, client, seen) = link(ty);
    writer.enable_network_variable(ty, NetworkVariablePermissions::READ_ONLY).unwrap();
    writer.tx(value(ty, endpoint, WRITER, 10, 15)).unwrap();
    pump(&[&writer, &client]);
    report(&writer, &value(ty, endpoint, "REPORTER", 20, 16));
    assert_eq!(writer.own_network_variable(ty).map(|p| p.payload()[0]), Some(15));
    seen.lock().unwrap().clear();
    client.request_managed_variable(ty).unwrap();
    pump(&[&client, &writer]);
    assert_eq!(*seen.lock().unwrap(), vec![]);
}
