#!/usr/bin/env python3
import sedsnet as seds

from schema_helpers import ensure_example_schema

ROUTE_WEIGHTED = 1


def main() -> None:
    ids = ensure_example_schema()
    router = seds.Router(
        handlers=[(ids["RADIO"], lambda pkt: None, None)],
        hostname="python-load-balancer",
        max_queue_budget=65536,
    )

    side_a = router.add_side_packet("WAN_A", lambda pkt: print("[router WAN_A]", pkt))
    side_b = router.add_side_packet("WAN_B", lambda pkt: print("[router WAN_B]", pkt))

    router.set_source_route_mode(None, ROUTE_WEIGHTED)
    router.set_route_weight(None, side_a, 3)
    router.set_route_weight(None, side_b, 1)

    for seq in range(4):
        router.log_f32(ids["GPS_DATA"], [float(seq), 10.0, 20.0])
    router.process_all_queues()


if __name__ == "__main__":
    main()
