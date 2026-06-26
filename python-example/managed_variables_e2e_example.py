import sedsnet as seds


RADIO = 101
FLIGHT_STATE = 3100


def main() -> None:
    seds.register_endpoint(RADIO, "RADIO", False, "packed radio link")
    seds.register_data_type(
        FLIGHT_STATE,
        "FLIGHT_STATE",
        True,
        1,
        0,  # UInt8
        0,  # Data
        [RADIO],
        priority=90,
        description="network-managed flight state",
        e2e_encryption=2,  # RequireOn
    )

    router = seds.Router(e2e_mode=1, e2e_key_id=7)  # RequiredOnly
    router.set_sender_id("FLIGHT_COMPUTER")
    router.enable_managed_variable(FLIGHT_STATE)
    router.add_side_packed("RADIO", lambda _bytes: None)

    router.log_bytes(FLIGHT_STATE, bytes([3]))
    router.request_managed_variable(FLIGHT_STATE)
    router.process_all_queues()


if __name__ == "__main__":
    main()
