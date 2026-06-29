from __future__ import annotations

import sedsnet as seds

FLOAT32 = 1
UINT8 = 2
STRING = 13
NO_DATA = 15
DATA = 0
RELIABLE_NONE = 0
RELIABLE_ORDERED = 1
E2E_PREFER_OFF = 0
E2E_REQUIRE_ON = 2


def ensure_endpoint(endpoint_id: int, name: str, description: str = "") -> int:
    info = seds.endpoint_info_by_name(name)
    if info.get("exists"):
        return int(info["id"])
    return int(seds.register_endpoint(endpoint_id, name, False, description))


def ensure_type(
    type_id: int,
    name: str,
    *,
    is_static: bool,
    element_count: int,
    message_data_type: int,
    endpoints: list[int],
    reliable: int = RELIABLE_NONE,
    priority: int = 0,
    description: str = "",
    e2e_encryption: int = E2E_PREFER_OFF,
) -> int:
    info = seds.data_type_info_by_name(name)
    if info.get("exists"):
        return int(info["id"])
    return int(
        seds.register_data_type(
            type_id,
            name,
            is_static,
            element_count,
            message_data_type,
            DATA,
            endpoints,
            reliable=reliable,
            priority=priority,
            description=description,
            e2e_encryption=e2e_encryption,
        )
    )


def ensure_example_schema() -> dict[str, int]:
    radio = ensure_endpoint(101, "RADIO", "packed radio link")
    sd_card = ensure_endpoint(102, "SD_CARD", "local storage")
    return {
        "RADIO": radio,
        "SD_CARD": sd_card,
        "GPS_DATA": ensure_type(
            3101,
            "GPS_DATA",
            is_static=True,
            element_count=3,
            message_data_type=FLOAT32,
            endpoints=[radio, sd_card],
            reliable=RELIABLE_ORDERED,
            priority=80,
            description="GPS latitude, longitude, altitude",
        ),
        "IMU_DATA": ensure_type(
            3102,
            "IMU_DATA",
            is_static=True,
            element_count=6,
            message_data_type=FLOAT32,
            endpoints=[radio, sd_card],
            priority=40,
            description="IMU acceleration and gyro vector",
        ),
        "MESSAGE_DATA": ensure_type(
            3103,
            "MESSAGE_DATA",
            is_static=False,
            element_count=0,
            message_data_type=STRING,
            endpoints=[sd_card, radio],
            description="UTF-8 text message",
        ),
        "HEARTBEAT": ensure_type(
            3104,
            "HEARTBEAT",
            is_static=True,
            element_count=0,
            message_data_type=NO_DATA,
            endpoints=[sd_card, radio],
            priority=100,
            description="empty heartbeat",
        ),
    }
