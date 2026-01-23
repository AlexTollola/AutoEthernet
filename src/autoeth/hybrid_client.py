from __future__ import annotations

import argparse
import socket
from typing import Dict

from .codec import build_payload, decode_frame, parse_payload
from .hybrid_common import CatalogIndex
from .message_config import load_messages_config
from .signal_catalog import load_catalog
from .tcp_stream import recv_lp_frame, send_lp_frame
from .udp_transport import join_multicast
from .codec import encode_frame


def tcp_call(server_ip: str, port: int, req_msg_id: int, payload: bytes, timeout_ms: int) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(max(timeout_ms, 1) / 1000.0)
    s.connect((server_ip, port))
    send_lp_frame(s, encode_frame(msg_type=req_msg_id, seq=1, payload=payload))
    rsp = recv_lp_frame(s)
    s.close()
    return rsp


def main() -> int:
    ap = argparse.ArgumentParser(description="Hybrid tester (TCP method call + optional UDP subscribe)")
    ap.add_argument("--signals", default="configs/signals.yaml")
    ap.add_argument("--messages", default="configs/messages.yaml")
    ap.add_argument("--tcp-server-ip", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=30510)
    ap.add_argument("--set-steer-deg", type=float, default=10.0)
    ap.add_argument("--udp-sub", action="store_true")
    ap.add_argument("--udp-bind-ip", default="0.0.0.0")
    ap.add_argument("--udp-port", type=int, default=30509)
    ap.add_argument("--mcast", default="239.255.0.1")
    ap.add_argument("--iface-ip", default="0.0.0.0")
    args = ap.parse_args()

    catalog = load_catalog(args.signals)
    cat_index = CatalogIndex.from_catalog(catalog)
    mc = load_messages_config(args.messages)

    req = mc.by_name.get("control_method_req")
    rsp = mc.by_name.get("control_method_rsp")
    if req is None or rsp is None:
        raise SystemExit("Expected messages: control_method_req and control_method_rsp")

    req_subset = cat_index.subset(req.signals)
    rsp_subset = cat_index.subset(rsp.signals)

    values: Dict[str, float] = {"steering_angle_deg": float(args.set_steer_deg)}
    req_payload = build_payload(req_subset, values)

    print(f"[client] TCP call -> {args.tcp_server_ip}:{args.tcp_port} steering_angle_deg={args.set_steer_deg}")
    rsp_bytes = tcp_call(args.tcp_server_ip, args.tcp_port, req.msg_id, req_payload, req.timeout_ms)

    fr = decode_frame(rsp_bytes)
    vals = parse_payload(rsp_subset, fr.raw_payload)
    print(f"[client] TCP rsp msg_id={fr.msg_type} seq={fr.seq} values={vals}")

    if args.udp_sub:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.udp_bind_ip, args.udp_port))
        join_multicast(s, args.mcast, args.iface_ip)

        evt = mc.by_name.get("fast_dynamics_event")
        if evt is None:
            raise SystemExit("Expected message: fast_dynamics_event")
        evt_subset = cat_index.subset(evt.signals)

        print(f"[client] UDP subscribe -> {args.mcast}:{args.udp_port} (5 frames)")
        for _ in range(5):
            data, addr = s.recvfrom(2048)
            fr = decode_frame(data)
            vals = parse_payload(evt_subset, fr.raw_payload)
            print(f"[client] UDP rx from {addr} msg_id={fr.msg_type} seq={fr.seq} values={vals}")
        s.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
