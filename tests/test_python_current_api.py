from __future__ import annotations

import json
import unittest

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

        server.add_side_packet("to-client", lambda pkt: client.receive_packet_from_side(0, pkt))
        client.add_side_packet("to-server", lambda pkt: server.receive_packet_from_side(0, pkt))

        server.announce_discovery()
        client.announce_discovery()
        server.process_all_queues()
        client.process_all_queues()
        server.process_all_queues()
        client.process_all_queues()

        client.send_p2p_to_address(0x10203060, 8080, 49152, b"GET /status HTTP/1.1\r\n\r\n")
        client.process_all_queues()
        server.process_all_queues()

        self.assertEqual(received[0][1], b"GET /status HTTP/1.1\r\n\r\n")
        self.assertEqual(received[0][0]["destination_port"], 8080)


if __name__ == "__main__":
    unittest.main()
