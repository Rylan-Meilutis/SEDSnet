from __future__ import annotations

import json
import unittest
from schema_identity import ENDPOINT_PROTOCOL, TYPE_PROTOCOL, resolve_id

try:
    import sedsnet as seds
except Exception as exc:  # pragma: no cover - environment dependent
    seds = None
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@unittest.skipIf(seds is None, f"sedsnet binding unavailable: {IMPORT_ERROR}")
class PythonCurrentApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not seds.endpoint_info_by_name("PY_API_RADIO_9201").get("exists"):
            seds.register_endpoint(9201, "PY_API_RADIO_9201", False, "python API radio")
        cls.radio = int(seds.endpoint_info_by_name("PY_API_RADIO_9201")["id"])

        if not seds.data_type_info_by_name("PY_API_FLOAT_9202").get("exists"):
            seds.register_data_type(
                9202,
                "PY_API_FLOAT_9202",
                True,
                3,
                1,
                0,
                [cls.radio],
                reliable=1,
                priority=33,
                description="python API float test",
            )
        cls.float_ty = int(seds.data_type_info_by_name("PY_API_FLOAT_9202")["id"])

        if not seds.data_type_info_by_name("PY_API_STATE_9203").get("exists"):
            seds.register_data_type(
                9203,
                "PY_API_STATE_9203",
                True,
                1,
                2,
                0,
                [cls.radio],
                priority=44,
                description="python API state test",
            )
        cls.state_ty = int(seds.data_type_info_by_name("PY_API_STATE_9203")["id"])

    def test_canonical_runtime_identities_before_registration(self) -> None:
        for name, legacy in [("SD_CARD", 100), ("RADIO", 101), ("SOFTWARE_BUS", 102)]:
            self.assertEqual(seds.endpoint_identity(name), resolve_id(name, endpoint=True))
            self.assertNotEqual(seds.endpoint_identity(name), legacy)
        for name, legacy in [("GPS_DATA", 100), ("IMU_DATA", 101), ("BATTERY_STATUS", 102),
                             ("SYSTEM_STATUS", 103), ("BAROMETER_DATA", 104), ("MESSAGE_DATA", 105),
                             ("HEARTBEAT", 106), ("IPC_MESSAGE", 107)]:
            self.assertEqual(seds.data_type_identity(name), resolve_id(name))
            self.assertNotEqual(seds.data_type_identity(name), legacy)
        for name, identity in ENDPOINT_PROTOCOL.items():
            self.assertEqual(seds.endpoint_identity(name), identity)
        for name, identity in TYPE_PROTOCOL.items():
            self.assertEqual(seds.data_type_identity(name), identity)
        name = "PY_API_CANONICAL_UNDECLARED_ENDPOINT"
        type_name = "PY_API_CANONICAL_RUNTIME_FLOW"
        ep = seds.endpoint_identity(name)
        ty = seds.data_type_identity(type_name)
        self.assertFalse(seds.endpoint_exists(ep))
        self.assertFalse(seds.data_type_exists(ty))
        # An unresolved destination may be declared by another node later.
        seds.register_data_type(ty, type_name, True, 1, 2, 0, [ep], reliable=2)
        seds.register_endpoint(ep, name)
        self.assertEqual(seds.endpoint_info_by_name(name)["id"], ep)
        info = seds.data_type_info_by_name(type_name)
        self.assertEqual(info["id"], ty)
        self.assertEqual(info["endpoints"], [ep])
        self.assertEqual(info["reliable"], 2)
        self.assertNotIn("reliable_mode", info)

    def test_network_variable_cache_invalidation_preserves_registration(self) -> None:
        router = seds.Router(hostname="py-cache-owner")
        router.enable_network_variable(self.state_ty, True, True)
        packet = seds.make_packet(self.state_ty, router.sender_id, [self.radio], 1, bytes([1]))
        router.set_network_variable(packet)
        self.assertTrue(router.invalidate_network_variable_cache(self.state_ty))
        self.assertIsNone(router.cached_network_variable(self.state_ty))
        self.assertFalse(router.invalidate_network_variable_cache(self.state_ty))
        # A second set still succeeds: invalidation retains write permission.
        router.set_network_variable(packet)
        self.assertEqual(router.clear_network_variable_caches(), 1)
        self.assertEqual(router.clear_network_variable_caches(), 0)
        router.set_network_variable(packet)
        self.assertIsNotNone(router.cached_network_variable(self.state_ty))

    def test_runtime_config_memory_and_network_variable_api(self) -> None:
        seds.set_runtime_device_identifier("PY_API_DEFAULT")
        self.assertEqual(seds.runtime_device_identifier(), "PY_API_DEFAULT")
        tuning = seds.set_runtime_tuning_config(payload_compress_threshold=31)
        self.assertEqual(tuning["payload_compress_threshold"], 31)

        router = seds.Router(
            hostname="py-api-router",
            address_mode=1,
            requested_address=0x10203055,
            timesync_enabled=True,
            timesync_role=1,
            timesync_priority=7,
            max_queue_budget=8192,
            max_recent_rx_ids=8,
            starting_queue_size=512,
            queue_grow_step=1.5,
        )
        self.assertEqual(router.sender_id, "py-api-router")
        self.assertEqual(router.current_address, 0x10203055)
        router.configure_address(address_mode=2, requested_address=0x10203056)
        self.assertEqual(router.current_address, 0x10203056)

        layout = json.loads(router.export_memory_layout_json())
        self.assertEqual(layout["shared_queue_bytes_allocated"], 8192)
        self.assertLessEqual(
            layout["shared_queue_bytes_used"],
            layout["shared_queue_bytes_allocated"],
        )

        router.enable_network_variable(self.state_ty, True, True)
        packet = seds.make_packet(self.state_ty, router.sender_id, [self.radio], 1, bytes([5]))
        router.set_network_variable(packet)
        cached = router.cached_network_variable(self.state_ty)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.data_as_u8(), b"\x05")

    def test_p2p_service_port_routes_by_address(self) -> None:
        server = seds.Router(
            hostname="py-api-service",
            address_mode=2,
            requested_address=0x10203060,
        )
        client = seds.Router(
            hostname="py-api-client",
            address_mode=1,
            requested_address=0x10203061,
        )
        received: list[tuple[dict, bytes]] = []
        server.bind_p2p_port(
            8080,
            lambda meta, payload: received.append((dict(meta), bytes(payload))),
        )

        # Model transport ownership: callbacks accept a frame, then the peer
        # receives it after the sender returns. Inline peer dispatch recursively
        # reentered the Python Router mutex through discovery replies and hung.
        to_client, to_server = [], []
        server.add_side_packet("to-client", to_client.append)
        client.add_side_packet("to-server", to_server.append)

        def pump():
            for _ in range(64):
                while to_client:
                    client.receive_packet_queue_from_side(0, to_client.pop(0))
                while to_server:
                    server.receive_packet_queue_from_side(0, to_server.pop(0))
                server.process_all_queues()
                client.process_all_queues()
                if not to_client and not to_server:
                    return
            self.fail("packet transport did not quiesce")

        server.announce_discovery()
        client.announce_discovery()
        pump()

        client.send_p2p_to_address(0x10203060, 8080, 49152, b"GET /status HTTP/1.1\r\n\r\n")
        pump()

        self.assertEqual(received[0][1], b"GET /status HTTP/1.1\r\n\r\n")
        self.assertEqual(received[0][0]["destination_port"], 8080)


if __name__ == "__main__":
    unittest.main()
