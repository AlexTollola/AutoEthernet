from __future__ import annotations

import argparse
import socket

from .signal_catalog import load_catalog
from .codec import decode_frame, parse_payload


def _join_multicast(sock: socket.socket, group: str, iface_ip: str = "0.0.0.0") -> None:
    mreq = socket.inet_aton(group) + socket.inet_aton(iface_ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def main() -> int:
    ap = argparse.ArgumentParser(description="autoeth UDP subscriber (unicast or multicast)")
    ap.add_argument("--bind-ip", default="0.0.0.0", help="bind IP (unicast or all)")
    ap.add_argument("--mcast", default=None, help="multicast group IP (e.g. 239.255.0.1)")
    ap.add_argument("--port", type=int, default=30509)
    ap.add_argument("--iface", default=None, help="interface name (Linux) for multicast receive")
    ap.add_argument("--iface-ip", default="0.0.0.0", help="interface IPv4 for multicast membership (optional)")
    ap.add_argument("--catalog", default="configs/signals.yaml", help="signal catalog YAML")
    args = ap.parse_args()

    catalog = load_catalog(args.catalog)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if args.iface:
        # Linux only: bind RX device
        try:
            s.setsockopt(socket.SOL_SOCKET, 25, args.iface.encode())  # SO_BINDTODEVICE
        except OSError:
            pass

    s.bind((args.bind_ip, args.port))

    if args.mcast:
        _join_multicast(s, args.mcast, args.iface_ip)

    print(f"[sub] bind={args.bind_ip}:{args.port} mcast={args.mcast} catalog={args.catalog}")
    while True:
        data, addr = s.recvfrom(2048)
        try:
            fr = decode_frame(data)
            vals = parse_payload(catalog, fr.raw_payload)
            print(f"rx from {addr} seq={fr.seq} ts_ms={fr.ts_ms} values={vals}")
        except Exception as e:
            print(f"rx from {addr} decode_error={e}")


if __name__ == "__main__":
    raise SystemExit(main())
