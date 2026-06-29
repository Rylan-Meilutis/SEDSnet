#!/usr/bin/env python3
import sedsnet as seds


def main() -> None:
    server = seds.Router(hostname="http-service", address_mode=2, requested_address=0x10203040)
    client = seds.Router(hostname="python-client", address_mode=1, requested_address=0x10203041)
    received: list[tuple[dict, bytes]] = []

    server.bind_p2p_port(80, lambda meta, payload: received.append((dict(meta), bytes(payload))))
    server.add_side_packet("to-client", lambda pkt: client.receive_packet_from_side(0, pkt))
    client.add_side_packet("to-server", lambda pkt: server.receive_packet_from_side(0, pkt))

    server.announce_discovery()
    client.announce_discovery()
    server.process_all_queues()
    client.process_all_queues()
    server.process_all_queues()
    client.process_all_queues()

    client.send_p2p_to_hostname("http-service", 80, 49152, b"GET / HTTP/1.1\r\n\r\n")
    client.process_all_queues()
    server.process_all_queues()

    client.send_p2p_to_address(0x10203040, 80, 49152, b"GET / HTTP/1.1\r\n\r\n")
    client.process_all_queues()
    server.process_all_queues()

    assert len(received) == 2
    print(received[0][1].decode("ascii").splitlines()[0])


if __name__ == "__main__":
    main()
