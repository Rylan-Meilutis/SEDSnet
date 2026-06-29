#!/usr/bin/env python3
from __future__ import annotations

from system_suite import run_python_system_suite


def main() -> None:
    result = run_python_system_suite()
    print(
        "python system suite passed: "
        f"{len(result.p2p_messages)} p2p messages, "
        f"{len(result.packet_bytes)} packed frames, "
        f"{result.topology_router_count} discovered routers, "
        f"{result.memory_used}/{result.memory_allocated} queue bytes"
    )


if __name__ == "__main__":
    main()
