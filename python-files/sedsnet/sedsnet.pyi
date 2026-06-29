from typing import Any, Callable, Dict, Optional

class Packet:
    ...

class Router:
    def __init__(
        self,
        now_ms: Optional[Callable[[], int]] = None,
        handlers: Any = None,
        hostname: Optional[str] = None,
        address_mode: int = 0,
        requested_address: int = 0,
        timesync_enabled: bool = True,
        timesync_role: int = 0,
        timesync_priority: int = 100,
        timesync_source_timeout_ms: int = 5000,
        timesync_announce_interval_ms: int = 1000,
        timesync_request_interval_ms: int = 1000,
        timesync_consumer_promotion_enabled: bool = True,
        timesync_max_slew_ppm: int = 50000,
        e2e_mode: int = 255,
        e2e_key_id: int = 0,
        max_queue_budget: Optional[int] = None,
        max_recent_rx_ids: Optional[int] = None,
        starting_queue_size: Optional[int] = None,
        queue_grow_step: Optional[float] = None,
    ) -> None: ...
    @staticmethod
    def new_singleton(
        now_ms: Optional[Callable[[], int]] = None,
        handlers: Any = None,
        hostname: Optional[str] = None,
        address_mode: int = 0,
        requested_address: int = 0,
        timesync_enabled: bool = True,
        timesync_role: int = 0,
        timesync_priority: int = 100,
        timesync_source_timeout_ms: int = 5000,
        timesync_announce_interval_ms: int = 1000,
        timesync_request_interval_ms: int = 1000,
        timesync_consumer_promotion_enabled: bool = True,
        timesync_max_slew_ppm: int = 50000,
        e2e_mode: int = 255,
        e2e_key_id: int = 0,
        max_queue_budget: Optional[int] = None,
        max_recent_rx_ids: Optional[int] = None,
        starting_queue_size: Optional[int] = None,
        queue_grow_step: Optional[float] = None,
    ) -> "Router": ...
    @property
    def sender_id(self) -> str: ...
    def set_sender_id(self, sender_id: str) -> None: ...
    def configure_address(
        self,
        address_mode: int = 0,
        requested_address: int = 0,
    ) -> None: ...
    @property
    def current_address(self) -> int: ...
    def resolve_hostname(self, hostname: str) -> Optional[Dict[str, Any]]: ...
    def bind_p2p_port(
        self,
        port: int,
        callback: Callable[[Dict[str, Any], bytes], object],
    ) -> None: ...
    def clear_p2p_port(self, port: int) -> None: ...
    def send_p2p_to_hostname(
        self,
        hostname: str,
        dst_port: int,
        src_port: int,
        payload: bytes,
    ) -> None: ...
    def send_p2p_to_address(
        self,
        address: int,
        dst_port: int,
        src_port: int,
        payload: bytes,
    ) -> None: ...
    def bind_p2p_stream_port(
        self,
        port: int,
        callback: Callable[[Dict[str, Any], bytes], object],
    ) -> None: ...
    def clear_p2p_stream_port(self, port: int) -> None: ...
    def open_p2p_stream_to_hostname(
        self,
        hostname: str,
        dst_port: int,
        src_port: int,
    ) -> int: ...
    def open_p2p_stream_to_address(
        self,
        address: int,
        dst_port: int,
        src_port: int,
    ) -> int: ...
    def send_p2p_stream(self, stream_id: int, payload: bytes) -> None: ...
    def close_p2p_stream(self, stream_id: int) -> None: ...
    def reset_p2p_stream(self, stream_id: int) -> None: ...
    def configure_timesync(
        self,
        enabled: bool = True,
        role: int = 0,
        priority: int = 100,
        source_timeout_ms: int = 5000,
        announce_interval_ms: int = 1000,
        request_interval_ms: int = 1000,
        consumer_promotion_enabled: bool = True,
        max_slew_ppm: int = 50000,
    ) -> None: ...
    def export_memory_layout_json(self) -> str: ...

class Relay:
    def __init__(
        self,
        now_ms: Optional[Callable[[], int]] = None,
        max_queue_budget: Optional[int] = None,
        max_recent_rx_ids: Optional[int] = None,
        starting_queue_size: Optional[int] = None,
        queue_grow_step: Optional[float] = None,
    ) -> None: ...
    def export_memory_layout_json(self) -> str: ...
    ...

def unpack_packet_py(data: bytes) -> Packet: ...
def peek_header_py(data: bytes) -> Dict[str, Any]: ...
def runtime_device_identifier() -> str: ...
def set_runtime_device_identifier(value: str) -> str: ...
def runtime_tuning_config() -> Dict[str, int]: ...
def set_runtime_tuning_config(
    payload_compress_threshold: Optional[int] = None,
    static_string_length: Optional[int] = None,
    static_hex_length: Optional[int] = None,
    string_precision: Optional[int] = None,
    max_handler_retries: Optional[int] = None,
    reliable_retransmit_ms: Optional[int] = None,
    reliable_max_retries: Optional[int] = None,
    reliable_max_pending: Optional[int] = None,
    reliable_max_return_routes: Optional[int] = None,
    reliable_max_end_to_end_pending: Optional[int] = None,
    reliable_max_end_to_end_ack_cache: Optional[int] = None,
) -> Dict[str, int]: ...
