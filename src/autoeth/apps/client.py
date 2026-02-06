from __future__ import annotations

import argparse
import socket
from typing import Dict, Optional

from autoeth.core.config import Catalog, MessageDef, load_catalog, resolve_someip
from autoeth.core.serialization.codec import decode, encode
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.udp import join_multicast
from autoeth.core.validation.e2e import unwrap as e2e_unwrap, wrap as e2e_wrap
from autoeth.core.service.discovery import SdAnnounce, SdEvent, SdService, parse_sd_datagram
from autoeth.protocols.someip.header import MT_NOTIFICATION, parse_message, build_message, MT_REQUEST, MT_RESPONSE
from autoeth.protocols.someip.stream import recv_someip, send_someip



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

def _e2e_enabled(msg: MessageDef) -> bool:
    return bool((msg.e2e or {}).get("enabled", False))


def _find_sd_service(ann: SdAnnounce, svc_id: int) -> SdService | None:
    for svc in ann.services:
        if svc.service_id == svc_id:
            return svc
    return None


def _find_sd_event(svc: SdService, event_id: int) -> SdEvent | None:
    for ev in svc.events:
        if ev.event_id == event_id:
            return ev
    return None


def _print_sd_summary(ann: SdAnnounce) -> None:
    for svc in ann.services:
        print(
            f"[sd] service sid=0x{svc.service_id:04X} inst=0x{svc.instance_id:04X} "
            f"iface_ver={svc.iface_ver} tcp_ports={list(svc.tcp_ports)}"
        )
        for ev in svc.events:
            mode = "multicast" if ev.udp_mode == 1 else "unicast"
            print(
                f"[sd] event id=0x{ev.event_id:04X} udp_port={ev.udp_port} "
                f"mode={mode} group={ev.mcast_group} ttl={ev.ttl}"
            )


def _tcp_call(
    *,
    cat: Catalog,
    method: MessageDef,
    sig_index: SignalIndex,
    tcp_ip: str,
    tcp_port: Optional[int],
    values: Dict[str, float],
    timeout_ms: int,
    verbose: bool,
) -> Dict[str, float]:
    tcp_cfg = method.tcp or {}
    port_value = tcp_port if tcp_port is not None else tcp_cfg.get("port")
    if port_value is None:
        raise SystemExit(f"{method.name}: missing tcp.port")
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        raise SystemExit(f"{method.name}: invalid tcp.port {port_value!r}")
    if not port:
        raise SystemExit(f"{method.name}: missing tcp.port")
    to_ms = int(tcp_cfg.get("timeout_ms", timeout_ms))

    svc_id, iface_ver, method_id = resolve_someip(cat, method)

    CLIENT_ID = 0x0001
    session_id = 1

    sigs = sig_index.subset(method.signals)
    payload = encode(sigs, values)
    if _e2e_enabled(method):
        payload = e2e_wrap(payload, counter=session_id)

    req = build_message(
        service_id=svc_id,
        method_id=method_id,
        client_id=CLIENT_ID,
        session_id=session_id,
        iface_ver=iface_ver,
        msg_type=MT_REQUEST,
        payload=payload,
    )

    if verbose:
        print(f"[tcp] connect {tcp_ip}:{port} method={method.name} id={method.msg_id} values={values}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(to_ms, 1) / 1000.0)
    sock.connect((tcp_ip, port))
    send_someip(sock, req)
    hdr, pl = recv_someip(sock, max_payload=4096)
    sock.close()

    if hdr.msg_type != MT_RESPONSE:
        raise SystemExit(f"TCP: expected RESPONSE got 0x{hdr.msg_type:02X}")

    if _e2e_enabled(method):
        pl_core, counter = e2e_unwrap(pl)
        if counter != hdr.session_id:
            raise SystemExit("TCP: E2E counter mismatch")
    else:
        pl_core = pl

    vals = decode(sigs, pl_core)

    print(
        f"[tcp] rsp sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} "
        f"sess={hdr.session_id} values={vals}"
    )
    return vals


def _udp_subscribe(
    *,
    cat: Catalog,
    event: MessageDef,
    sig_index: SignalIndex,
    bind_ip: str,
    iface_ip: str,
    count: int,
    timeout_s: float,
    verbose: bool,
    discover_event: SdEvent | None = None,
) -> None:
    udp_cfg = event.udp or {}
    if discover_event is not None:
        port = int(discover_event.udp_port)
        mode = "multicast" if discover_event.udp_mode == 1 else "unicast"
        group = discover_event.mcast_group if mode == "multicast" else ""
    else:
        port = int(udp_cfg.get("port", 0))
        mode = str(udp_cfg.get("mode", "unicast"))
        group = str(udp_cfg.get("mcast_group", ""))
    if not port:
        raise SystemExit(f"{event.name}: missing udp.port")

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

        svc_id, _iface_ver, method_id = resolve_someip(cat, event)

        hdr, payload = parse_message(data)

        if hdr.service_id != svc_id or hdr.method_id != method_id or hdr.msg_type != MT_NOTIFICATION:
            if verbose:
                print(
                    f"[udp] drop someip sid={hdr.service_id:04X} mid={hdr.method_id:04X} type={hdr.msg_type:02X}"
                )
            continue

        # Optional E2E check
        if _e2e_enabled(event):
            payload_core, counter = e2e_unwrap(payload)
            if counter != hdr.session_id:
                if verbose:
                    print(f"[udp] drop e2e counter({counter}) != session_id({hdr.session_id})")
                continue
        else:
            payload_core = payload

        vals = decode(sigs, payload_core)
        print(
            f"[udp] rx someip sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} "
            f"sess={hdr.session_id} values={vals}"
        )
        got += 1

    s.close()


def _discover(*, group: str, port: int, bind_ip: str, iface_ip: str, timeout_s: float, verbose: bool):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout_s)
    s.bind((bind_ip, port))

    join_multicast(s, group, iface_ip=iface_ip)

    if verbose:
        print(f"[sd] listen {bind_ip}:{port} group={group} iface_ip={iface_ip}")

    while True:
        data, addr = s.recvfrom(2048)
        parsed = parse_sd_datagram(data)
        if not parsed:
            continue
        seq, ann = parsed
        if verbose:
            print(f"[sd] rx from={addr} seq={seq} ann={ann}")
        s.close()
        # Use source IP as the server IP (most reliable)
        return addr[0], ann


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

    ap.add_argument("--discover", action="store_true", help="listen for SD announce and auto-fill tcp-ip/port")
    ap.add_argument("--sd-group", default="239.0.0.2")
    ap.add_argument("--sd-port", type=int, default=30490)
    ap.add_argument("--sd-timeout-s", type=float, default=2.0)

    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)
    cat.validate()

    sig_index = SignalIndex.from_signals(cat.signals)

    discovered: tuple[str, SdAnnounce] | None = None
    if args.discover:
        tcp_ip, ann = _discover(
            group=args.sd_group,
            port=args.sd_port,
            bind_ip="0.0.0.0",
            iface_ip=args.iface_ip,
            timeout_s=args.sd_timeout_s,
            verbose=args.verbose,
        )
        discovered = (tcp_ip, ann)
        _print_sd_summary(ann)

        # If user didn't explicitly set tcp-ip/port, override.
        if args.tcp_ip == "127.0.0.1":
            args.tcp_ip = tcp_ip

    # TCP call
    if args.call_method:
        method = _find_method(cat, args.call_method)
        if discovered and args.tcp_port is None:
            svc_id, _iface_ver, _method_id = resolve_someip(cat, method)
            svc = _find_sd_service(discovered[1], svc_id)
            if svc and svc.tcp_ports:
                if len(svc.tcp_ports) != 1:
                    raise SystemExit(
                        f"Discovery has multiple TCP ports for sid=0x{svc_id:04X}: {list(svc.tcp_ports)}"
                    )
                args.tcp_port = int(svc.tcp_ports[0])
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
            cat=cat,
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
        disc_event = None
        if discovered:
            svc_id, _iface_ver, event_id = resolve_someip(cat, event)
            svc = _find_sd_service(discovered[1], svc_id)
            if svc:
                disc_event = _find_sd_event(svc, event_id)
        _udp_subscribe(
            cat=cat,
            event=event,
            sig_index=sig_index,
            bind_ip=args.udp_bind_ip,
            iface_ip=args.iface_ip,
            count=args.count,
            timeout_s=args.udp_timeout_s,
            verbose=args.verbose,
            discover_event=disc_event,
        )

    if not args.call_method and not args.sub_event:
        ap.print_help()
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
