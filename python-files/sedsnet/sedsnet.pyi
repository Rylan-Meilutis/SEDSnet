from typing import Any, Callable, Dict, List, Optional

class Packet:
    @property
    def ty(self) -> int: ...
    @property
    def data_size(self) -> int: ...
    @property
    def sender(self) -> str: ...
    @property
    def endpoints(self) -> List[int]: ...
    @property
    def timestamp_ms(self) -> int: ...
    @property
    def payload(self) -> bytes: ...
    def data_as_u8(self) -> bytes: ...
    def data_as_f32(self) -> List[float]: ...
    def data_as_string(self) -> str: ...
    def header_string(self) -> str: ...
    def wire_size(self) -> int: ...
    def pack(self) -> bytes: ...

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
    def announce_discovery(self) -> None: ...
    def announce_leave(self) -> None: ...
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
    def add_side_packed(
        self,
        name: str,
        tx: Callable[[bytes], object],
        reliable_enabled: bool = False,
    ) -> int: ...
    def add_side_packed_profile(
        self,
        name: str,
        tx: Callable[[bytes], object],
        reliable_enabled: bool = False,
        profile: str = "ipv6_like",
        max_frame_bytes: int = 0,
        compact_header_target_bytes: int = 0,
        max_side_transport_templates: int = 64,
    ) -> int: ...
    def add_side_packet(
        self,
        name: str,
        tx: Callable[[Packet], object],
        reliable_enabled: bool = False,
    ) -> int: ...
    def remove_side(self, side_id: int) -> None: ...
    def set_route(
        self,
        src_side_id: Optional[int],
        dst_side_id: int,
        enabled: bool,
    ) -> None: ...
    def set_typed_route(
        self,
        src_side_id: Optional[int],
        ty: int,
        dst_side_id: int,
        enabled: bool,
    ) -> None: ...
    def set_source_route_mode(self, src_side_id: Optional[int], mode: int) -> None: ...
    def set_route_weight(
        self,
        src_side_id: Optional[int],
        dst_side_id: int,
        weight: int,
    ) -> None: ...
    def log_bytes(
        self,
        ty: int,
        data: bytes,
        timestamp_ms: Optional[int] = None,
        queue: bool = False,
    ) -> None: ...
    def log_f32(
        self,
        ty: int,
        values: List[float],
        timestamp_ms: Optional[int] = None,
        queue: bool = False,
    ) -> None: ...
    def receive_packet_from_side(self, side_id: int, packet: Packet) -> None: ...
    def receive_packed_from_side(self, side_id: int, data: bytes) -> None: ...
    def process_all_queues(self) -> None: ...
    def periodic(self, timeout_ms: int) -> None: ...
    def network_time_ms(self) -> Optional[int]: ...
    def set_local_network_datetime_millis(
        self,
        year: int,
        month: int,
        day: int,
        hour: int,
        minute: int,
        second: int,
        millisecond: int,
    ) -> None: ...
    def export_topology(self) -> Dict[str, Any]: ...
    def export_runtime_stats(self) -> Dict[str, Any]: ...
    def enable_network_variable(self, ty: int, can_read: bool, can_write: bool) -> None: ...
    def set_network_variable(self, pkt: Packet) -> None: ...
    def get_network_variable(
        self,
        ty: int,
        stale_after_ms: Optional[int] = None,
    ) -> Optional[Packet]: ...
    def cached_network_variable(self, ty: int) -> Optional[Packet]: ...
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
    @property
    def sender_id(self) -> str: ...
    def set_sender_id(self, sender_id: str) -> None: ...
    def add_side_packet(
        self,
        name: str,
        tx: Callable[[Packet], object],
        reliable_enabled: bool = False,
    ) -> int: ...
    def rx_packet_from_side(self, side_id: int, packet: Packet) -> None: ...
    def process_all_queues(self) -> None: ...
    def export_topology(self) -> Dict[str, Any]: ...
    def export_runtime_stats(self) -> Dict[str, Any]: ...
    def export_memory_layout_json(self) -> str: ...
    ...

def make_packet(
    ty: int,
    sender: str,
    endpoints: List[int],
    timestamp_ms: int,
    payload: bytes,
) -> Packet: ...
def unpack_packet_py(data: bytes) -> Packet: ...
def peek_header_py(data: bytes) -> Dict[str, Any]: ...
def endpoint_exists(endpoint: int) -> bool: ...
def data_type_exists(ty: int) -> bool: ...
def register_endpoint(
    endpoint: int,
    name: str,
    link_local_only: bool = False,
    description: str = "",
) -> int: ...
def register_data_type(
    ty: int,
    name: str,
    is_static: bool,
    element_count: int,
    message_data_type: int,
    message_class: int,
    endpoints: List[int],
    reliable: int = 0,
    priority: int = 0,
    description: str = "",
    e2e_encryption: int = 0,
) -> int: ...
def endpoint_info_by_name(name: str) -> Dict[str, Any]: ...
def data_type_info_by_name(name: str) -> Dict[str, Any]: ...
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
