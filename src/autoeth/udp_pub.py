from __future__ import annotations

import argparse
import socket
import time
from typing import Dict

from .signal_catalog import load_catalog
from .codec import build_payload, encode_frame


def _make_sock(iface: str | None, ttl: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    if iface:
        # Linux only: bind TX device
        try:
            s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
        except OSError:
            pass
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description="autoeth UDP publisher (unicast or multicast)")
    ap.add_argument("--dest-ip", default=None, help="destination IP for unicast")
    ap.add_argument("--mcast", default=None, help="multicast group IP (e.g. 239.255.0.1)")
    ap.add_argument("--port", type=int, default=30509)
    ap.add_argument("--iface", default=None, help="interface name for multicast (e.g. eth0)")
    ap.add_argument("--ttl", type=int, default=1)
    ap.add_argument("--period-ms", type=int, default=100)
    ap.add_argument("--catalog", required=True, help="path to signal catalog YAML")
    args = ap.parse_args()

    if (args.dest_ip is None) == (args.mcast is None):
        ap.error("provide exactly one of --dest-ip or --mcast")

    catalog = load_catalog(args.catalog)

    s = _make_sock(args.iface, args.ttl)
    dest_ip = args.dest_ip or args.mcast
    dest = (dest_ip, args.port)

    seq = 0
    values: Dict[str, float] = {}

    print(f"[pub] dest={dest} period_ms={args.period_ms} catalog={args.catalog}")
    while True:
        # Demo waveform: increment speed and rpm slowly
        values["vehicle_speed_kph"] = (values.get("vehicle_speed_kph", 0.0) + 0.5) % 200.0
        values["engine_rpm"] = 800.0 + (values["vehicle_speed_kph"] * 30.0)
        values["steering_angle_deg"] = (values.get("steering_angle_deg", 0.0) + 1.0) % 180.0 - 90.0

        payload = build_payload(catalog, values)
        frame = encode_frame(msg_type=1, seq=seq, payload=payload)
        s.sendto(frame, dest)

        seq = (seq + 1) & 0xFFFF
        time.sleep(max(args.period_ms, 1) / 1000.0)


if __name__ == "__main__":
    raise SystemExit(main())
