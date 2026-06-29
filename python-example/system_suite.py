from __future__ import annotations

import json
from dataclasses import dataclass

import sedsnet as seds

from schema_helpers import FLOAT32, UINT8, ensure_endpoint, ensure_type


@dataclass
class SystemSuiteResult:
    p2p_messages: list[tuple[dict, bytes]]
    packet_bytes: list[bytes]
    topology_router_count: int
    memory_used: int
    memory_allocated: int


def _pump(*routers: seds.Router, rounds: int = 3) -> None:
    for _ in range(rounds):
        for router in routers:
            router.process_all_queues()


def _exchange_discovery(*routers: seds.Router) -> None:
    for router in routers:
        router.announce_discovery()
    _pump(*routers, rounds=4)


def run_python_system_suite() -> SystemSuiteResult:
    radio = ensure_endpoint(9301, "PY_SYS_RADIO_9301", "python system radio link")
    storage = ensure_endpoint(9302, "PY_SYS_STORAGE_9302", "python system storage side")
    telemetry_ty = ensure_type(
        9303,
        "PY_SYS_TELEMETRY_9303",
        is_static=True,
        element_count=3,
        message_data_type=FLOAT32,
        endpoints=[radio, storage],
        reliable=1,
        priority=70,
        description="python system telemetry vector",
    )
    state_ty = ensure_type(
        9304,
        "PY_SYS_STATE_9304",
        is_static=True,
        element_count=1,
        message_data_type=UINT8,
        endpoints=[radio],
        priority=90,
        description="python system state network variable",
    )

    ground = seds.Router(
        hostname="py-system-ground",
        address_mode=2,
        requested_address=0x400001,
        timesync_enabled=True,
        timesync_role=1,
        timesync_priority=5,
        max_queue_budget=65536,
        max_recent_rx_ids=16,
        starting_queue_size=512,
    )
    flight = seds.Router(
        hostname="py-system-flight",
        address_mode=1,
        requested_address=0x400002,
        timesync_enabled=True,
        timesync_role=0,
        max_queue_budget=65536,
        max_recent_rx_ids=16,
        starting_queue_size=512,
    )
    payload = seds.Router(
        hostname="py-system-payload",
        address_mode=0,
        timesync_enabled=True,
        timesync_role=0,
        max_queue_budget=65536,
        max_recent_rx_ids=16,
        starting_queue_size=512,
    )

    p2p_messages: list[tuple[dict, bytes]] = []
    packet_bytes: list[bytes] = []

    ground_to_flight = ground.add_side_packet(
        "ground-to-flight",
        lambda pkt: flight.receive_packet_from_side(0, pkt),
        reliable_enabled=True,
    )
    flight_to_ground = flight.add_side_packet(
        "flight-to-ground",
        lambda pkt: ground.receive_packet_from_side(0, pkt),
        reliable_enabled=True,
    )
    flight_to_payload = flight.add_side_packet(
        "flight-to-payload",
        lambda pkt: payload.receive_packet_from_side(0, pkt),
        reliable_enabled=False,
    )
    payload_to_flight = payload.add_side_packet(
        "payload-to-flight",
        lambda pkt: flight.receive_packet_from_side(flight_to_payload, pkt),
        reliable_enabled=False,
    )
    ground_packed = ground.add_side_packed(
        "ground-packed-capture",
        lambda data: packet_bytes.append(bytes(data)),
        reliable_enabled=False,
    )

    ground.set_route(None, ground_to_flight, True)
    ground.set_route_weight(None, ground_to_flight, 3)
    ground.set_route_weight(None, ground_packed, 1)
    ground.set_source_route_mode(None, 1)
    flight.set_route(None, flight_to_ground, True)
    flight.set_route(None, flight_to_payload, True)
    payload.set_route(None, payload_to_flight, True)

    ground.bind_p2p_port(
        8080,
        lambda meta, payload_bytes: p2p_messages.append((dict(meta), bytes(payload_bytes))),
    )

    _exchange_discovery(ground, flight, payload)
    assert flight.resolve_hostname("py-system-ground") is not None
    assert payload.current_address != 0

    flight.send_p2p_to_hostname(
        "py-system-ground",
        8080,
        49152,
        b"GET /health HTTP/1.1\r\nHost: py-system-ground\r\n\r\n",
    )
    _pump(ground, flight, payload)
    flight.send_p2p_to_address(
        ground.current_address,
        8080,
        49152,
        b"POST /event HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    )
    _pump(ground, flight, payload)

    ground.enable_network_variable(state_ty, True, True)
    state_packet = seds.make_packet(state_ty, ground.sender_id, [radio], 10, b"\x07")
    ground.set_network_variable(state_packet)
    cached = ground.cached_network_variable(state_ty)
    assert cached is not None
    assert cached.data_as_u8() == b"\x07"

    for sample in range(20):
        ground.log_f32(
            telemetry_ty,
            [float(sample), float(sample + 1), float(sample + 2)],
            timestamp_ms=100 + sample,
            queue=True,
        )
    _pump(ground, flight, payload, rounds=8)

    ground.remove_side(ground_packed)
    replacement_packed = ground.add_side_packed(
        "ground-packed-replacement",
        lambda data: packet_bytes.append(bytes(data)),
        reliable_enabled=False,
    )
    ground.set_route(None, replacement_packed, True)
    ground.log_f32(telemetry_ty, [1.0, 2.0, 3.0], timestamp_ms=999, queue=True)
    _pump(ground, flight, payload, rounds=4)

    topology = ground.export_topology()
    memory = json.loads(ground.export_memory_layout_json())
    assert len(p2p_messages) == 2
    assert p2p_messages[0][1].startswith(b"GET /health")
    assert p2p_messages[1][1].startswith(b"POST /event")
    assert packet_bytes
    assert memory["shared_queue_bytes_used"] <= memory["shared_queue_bytes_allocated"]

    return SystemSuiteResult(
        p2p_messages=p2p_messages,
        packet_bytes=packet_bytes,
        topology_router_count=len(topology["routers"]),
        memory_used=int(memory["shared_queue_bytes_used"]),
        memory_allocated=int(memory["shared_queue_bytes_allocated"]),
    )
