from __future__ import annotations

import argparse
import socket
from tabnanny import verbose
from typing import Dict, Optional

from autoeth.core.config import MessageDef, load_catalog
from autoeth.core.serialization.codec import decode, encode
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.tcp import recv_frame, send_frame
from autoeth.core.transport.udp import join_multicast
from autoeth.core.validation.frame import PROTO_VER, pack_header, unpack_header
from autoeth.core.serialization.codec import encoded_size



def _find_method(cat, name: str) -> MessageDef:
    for m in cat.messages:
        if m.kind == "method" and m.transport == "tcp" and m.name == name:
            return m
    raise SystemExit(f"Method not found: {name}")


def _find_event(cat, name: str) -> MessageDef:
    for m in cat.messages:
        if m.kind == "event" and m.transport == "udp" and m.name == name:
            return m
    raise SystemExit(f"Event not found: {name}")


def _tcp_call(
    *,
    method: MessageDef,
    sig_index: SignalIndex,
    tcp_ip: str,
    tcp_port: Optional[int],
    values: Dict[str, float],
    timeout_ms: int,
    verbose: bool,
) -> Dict[str, float]:
    tcp_cfg = method.tcp or {}
    port = int(tcp_port if tcp_port is not None else tcp_cfg.get("port"))
    if not port:
        raise SystemExit(f"{method.name}: missing tcp.port")
    to_ms = int(tcp_cfg.get("timeout_ms", timeout_ms))

    sigs = sig_index.subset(method.signals)
    payload = encode(sigs, values)
    seq = 1
    frame = bytes([method.msg_id]) + pack_header(seq=seq) + payload


    if verbose:
        print(f"[tcp] connect {tcp_ip}:{port} method={method.name} id={method.msg_id} values={values}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(to_ms, 1) / 1000.0)
    sock.connect((tcp_ip, port))
    send_frame(sock, frame)
    rsp = recv_frame(sock)
    sock.close()

    if not rsp:
        raise SystemExit("TCP: empty response")

    rsp_id = rsp[0]
    if rsp_id != method.msg_id:
        raise SystemExit(f"TCP: response msg_id mismatch (got {rsp_id}, expected {method.msg_id})")

    hdr, pl = unpack_header(rsp[1:])
    if hdr.proto_ver != PROTO_VER:
        raise SystemExit(f"TCP: proto_ver mismatch {hdr.proto_ver}")
    if hdr.seq != seq:
        raise SystemExit(f"TCP: seq mismatch {hdr.seq} != {seq}")

    exp = encoded_size(sigs)
    if len(pl) != exp:
        raise SystemExit(f"TCP: payload len mismatch {len(pl)} != {exp}")

    vals = decode(sigs, pl)

    if verbose:
        print(f"[tcp] rsp id={rsp_id} values={vals}")
    return vals


def _udp_subscribe(
    *,
    event: MessageDef,
    sig_index: SignalIndex,
    bind_ip: str,
    iface_ip: str,
    count: int,
    timeout_s: float,
    verbose: bool,
) -> None:
    udp_cfg = event.udp or {}
    port = int(udp_cfg.get("port", 0))
    if not port:
        raise SystemExit(f"{event.name}: missing udp.port")

    mode = str(udp_cfg.get("mode", "unicast"))
    group = str(udp_cfg.get("mcast_group", ""))

    sigs = sig_index.subset(event.signals)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout_s)
    s.bind((bind_ip, port))

    if mode == "multicast":
        if not group:
            raise SystemExit(f"{event.name}: multicast requires udp.mcast_group")
        join_multicast(s, group, iface_ip=iface_ip)

    if verbose:
        desc = f"{bind_ip}:{port}"
        if mode == "multicast":
            desc += f" group={group} iface_ip={iface_ip}"
        print(f"[udp] sub event={event.name} id={event.msg_id} -> {desc} count={count}")

    got = 0
    while got < count:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            print("[udp] timeout waiting for datagram")
            continue

        if len(data) < 1:
            continue

        msg_id = data[0]
        if msg_id != event.msg_id:
            if verbose:
                print(f"[udp] rx other msg_id={msg_id} from={addr} len={len(data)}")
            continue

        hdr, pl = unpack_header(data[1:])
        if hdr.proto_ver != PROTO_VER:
            if verbose:
                print(f"[udp] drop proto_ver={hdr.proto_ver}")
            continue

        exp = encoded_size(sigs)
        if len(pl) != exp:
            if verbose:
                print(f"[udp] drop len={len(pl)} expected={exp}")
            continue

        vals = decode(sigs, pl)

        print(f"[udp] rx from={addr} id={msg_id} values={vals}")
        got += 1

    s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Client (TCP method call + UDP subscribe)")
    ap.add_argument("--catalog", default="configs/catalog.yaml")

    ap.add_argument("--tcp-ip", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=None)
    ap.add_argument("--timeout-ms", type=int, default=500)

    ap.add_argument("--call-method", default=None, help="method name to call (catalog message name)")
    ap.add_argument("--set", action="append", default=[], help="set values: name=value (repeatable)")

    ap.add_argument("--sub-event", default=None, help="event name to subscribe (catalog message name)")
    ap.add_argument("--udp-bind-ip", default="0.0.0.0")
    ap.add_argument("--iface-ip", default="0.0.0.0", help="multicast join interface IP")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--udp-timeout-s", type=float, default=2.0)

    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)
    cat.validate()

    sig_index = SignalIndex.from_signals(cat.signals)

    # TCP call
    if args.call_method:
        method = _find_method(cat, args.call_method)
        values: Dict[str, float] = {}
        for item in args.set:
            if "=" not in item:
                raise SystemExit(f"--set expects name=value, got: {item}")
            k, v = item.split("=", 1)
            values[k.strip()] = float(v.strip())

        if not values:
            # if user didn't provide anything, set defaults for method signals
            for n in method.signals:
                values[n] = float(sig_index.by_name[n].default)

        _tcp_call(
            method=method,
            sig_index=sig_index,
            tcp_ip=args.tcp_ip,
            tcp_port=args.tcp_port,
            values=values,
            timeout_ms=args.timeout_ms,
            verbose=args.verbose,
        )

    # UDP subscribe
    if args.sub_event:
        event = _find_event(cat, args.sub_event)
        _udp_subscribe(
            event=event,
            sig_index=sig_index,
            bind_ip=args.udp_bind_ip,
            iface_ip=args.iface_ip,
            count=args.count,
            timeout_s=args.udp_timeout_s,
            verbose=args.verbose,
        )

    if not args.call_method and not args.sub_event:
        ap.print_help()
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
