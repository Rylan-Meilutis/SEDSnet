import sedsnet as seds

from schema_helpers import E2E_PREFER_OFF, UINT8, ensure_endpoint, ensure_type

FLIGHT_STATE = 3100


def main() -> None:
    radio = ensure_endpoint(101, "RADIO", "packed radio link")
    flight_state = ensure_type(
        FLIGHT_STATE,
        "FLIGHT_STATE",
        is_static=True,
        element_count=1,
        message_data_type=UINT8,
        endpoints=[radio],
        priority=90,
        description="network-managed flight state",
        e2e_encryption=E2E_PREFER_OFF,
    )

    router = seds.Router(hostname="FLIGHT_COMPUTER", e2e_mode=1, e2e_key_id=7)
    router.enable_network_variable(flight_state, True, True)
    router.add_side_packed("RADIO", lambda _bytes: None)

    packet = seds.make_packet(flight_state, router.sender_id, [radio], 1, bytes([3]))
    router.set_network_variable(packet)
    cached = router.cached_network_variable(flight_state)
    assert cached is not None
    assert cached.data_as_u8() == b"\x03"
    router.get_network_variable(flight_state, stale_after_ms=0)
    router.process_all_queues()


if __name__ == "__main__":
    main()
