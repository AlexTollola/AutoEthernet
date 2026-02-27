from __future__ import annotations

import argparse
import socket
import time
from typing import Dict, Optional, Tuple

from autoeth.core.config import (
    Catalog, MessageDef, load_catalog, resolve_someip,
    resolve_eventgroup_id, get_discovery_cfg,
)
from autoeth.core.serialization.codec import decode, encode
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.udp import join_multicast
from autoeth.core.validation.e2e import unwrap as e2e_unwrap, wrap as e2e_wrap
from autoeth.core.service.discovery import (
    SdMessage, ServiceEntry, EventgroupEntry,
    Ipv4EndpointOption, Ipv4MulticastOption,
    ET_OFFER_SERVICE, ET_SUBSCRIBE_EVENTGROUP, ET_SUBSCRIBE_EVENTGROUP_ACK,
    L4_TCP, L4_UDP,
    TTL_DEFAULT, TTL_STOP,
    SD_FLAG_UNICAST,
    build_sd_message, parse_sd_message,
)
from autoeth.protocols.someip.header import (
    MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE,
    parse_message, build_message,
)
from autoeth.protocols.someip.stream import recv_someip, send_someip


def _find_method(cat: Catalog, name: str) -> MessageDef:
    for m in cat.messages:
        if m.kind == "method" and m.transport == "tcp" and m.name == name:
            return m
    raise SystemExit(f"Method not found: {name}")


def _find_event(cat: Catalog, name: str) -> MessageDef:
    for m in cat.messages:
        if m.kind == "event" and m.transport == "udp" and m.name == name:
            return m
    raise SystemExit(f"Event not found: {name}")


def _e2e_enabled(msg: MessageDef) -> bool:
    return bool((msg.e2e or {}).get("enabled", False))


def _find_offer_entry(sd_msg: SdMessage, svc_id: int) -> Optional[ServiceEntry]:
    for e in sd_msg.entries:
        if isinstance(e, ServiceEntry) and e.entry_type == ET_OFFER_SERVICE and e.service_id == svc_id:
            return e
    return None


def _tcp_port_from_entry(entry: ServiceEntry) -> Optional[int]:
    for opt in entry.options:
        if isinstance(opt, Ipv4EndpointOption) and opt.l4_proto == L4_TCP:
            return opt.port
    return None


def _print_sd_summary(sd_msg: SdMessage) -> None:
    for e in sd_msg.entries:
        if isinstance(e, ServiceEntry):
            tcp_ports = [o.port for o in e.options if isinstance(o, Ipv4EndpointOption) and o.l4_proto == L4_TCP]
            mcast     = [f"{o.address}:{o.port}" for o in e.options if isinstance(o, Ipv4MulticastOption)]
            print(f"[sd] OfferService sid=0x{e.service_id:04X} inst=0x{e.instance_id:04X} "
                  f"major={e.major_version} tcp_ports={tcp_ports} multicast={mcast}")


def _discover(*, group: str, port: int, bind_ip: str, iface_ip: str,
              timeout_s: float, verbose: bool) -> Tuple[str, SdMessage]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout_s)
    s.bind((bind_ip, port))
    join_multicast(s, group, iface_ip=iface_ip)
    if verbose:
        print(f"[sd] listening on {group}:{port}")
    while True:
        data, addr = s.recvfrom(4096)
        msg = parse_sd_message(data)
        if msg is None:
            continue
        offers = [e for e in msg.entries if isinstance(e, ServiceEntry) and e.entry_type == ET_OFFER_SERVICE]
        if not offers:
            continue
        s.close()
        return addr[0], msg


def _subscribe_eventgroup(
    *, sd_group: str, sd_port: int,
    client_ip: str, client_udp_port: int,
    svc_id: int, inst_id: int, major: int,
    eventgroup_id: int, counter: int = 0,
    timeout_s: float = 2.0, verbose: bool,
) -> bool:
    """Send SubscribeEventgroup and wait for Ack. Returns True on success."""
    sub = EventgroupEntry(
        entry_type=ET_SUBSCRIBE_EVENTGROUP,
        service_id=svc_id, instance_id=inst_id, major_version=major,
        eventgroup_id=eventgroup_id, counter=counter, ttl=TTL_DEFAULT,
        options=[Ipv4EndpointOption(address=client_ip, port=client_udp_port, l4_proto=L4_UDP)],
    )
    pkt  = build_sd_message(session_id=1, entries=[sub], flags=SD_FLAG_UNICAST)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout_s)
    sock.bind(("0.0.0.0", sd_port))
    join_multicast(sock, sd_group, iface_ip="0.0.0.0")
    try:
        sock.sendto(pkt, (sd_group, sd_port))
        if verbose:
            print(f"[sd] subscribe egid=0x{eventgroup_id:04X} client={client_ip}:{client_udp_port}")
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            ack = parse_sd_message(data)
            if ack is None:
                continue
            for e in ack.entries:
                if (isinstance(e, EventgroupEntry)
                        and e.entry_type == ET_SUBSCRIBE_EVENTGROUP_ACK
                        and e.service_id == svc_id
                        and e.eventgroup_id == eventgroup_id):
                    if verbose:
                        print(f"[sd] ack from {addr} egid=0x{eventgroup_id:04X}")
                    return True
    except OSError as e:
        if verbose:
            print(f"[sd] subscribe error: {e}")
    finally:
        sock.close()
    if verbose:
        print(f"[sd] subscribe ack timeout egid=0x{eventgroup_id:04X}")
    return False


def _tcp_call(
    *, cat: Catalog, method: MessageDef, sig_index: SignalIndex,
    tcp_ip: str, tcp_port: Optional[int],
    values: Dict[str, float], timeout_ms: int, verbose: bool,
) -> Dict[str, float]:
    tcp_cfg    = method.tcp or {}
    port_value = tcp_port if tcp_port is not None else tcp_cfg.get("port")
    if not port_value:
        raise SystemExit(f"{method.name}: missing tcp.port")
    port = int(port_value)
    to_ms = int(tcp_cfg.get("timeout_ms", timeout_ms))
    svc_id, iface_ver, method_id = resolve_someip(cat, method)

    sigs    = sig_index.subset(method.signals)
    payload = encode(sigs, values)
    session_id = 1
    if _e2e_enabled(method):
        payload = e2e_wrap(payload, counter=session_id)

    req = build_message(
        service_id=svc_id, method_id=method_id,
        client_id=0x0001, session_id=session_id,
        iface_ver=iface_ver, msg_type=MT_REQUEST, payload=payload,
    )
    if verbose:
        print(f"[tcp] connect {tcp_ip}:{port} method={method.name} values={values}")

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
    print(f"[tcp] rsp sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} sess={hdr.session_id} values={vals}")
    return vals


def _udp_subscribe(
    *, cat: Catalog, event: MessageDef, sig_index: SignalIndex,
    bind_ip: str, iface_ip: str, count: int, timeout_s: float, verbose: bool,
    server_ip: Optional[str] = None,
    sd_group: Optional[str] = None, sd_port: Optional[int] = None,
    offer_entry: Optional[ServiceEntry] = None,
) -> None:
    udp_cfg = event.udp or {}
    port    = int(udp_cfg.get("port", 0))
    mode    = str(udp_cfg.get("mode", "unicast"))
    group   = str(udp_cfg.get("mcast_group", ""))
    if not port:
        raise SystemExit(f"{event.name}: missing udp.port")

    svc_id, iface_ver, event_id = resolve_someip(cat, event)
    egid = resolve_eventgroup_id(event)

    if mode != "multicast" and sd_group and sd_port:
        svc   = next((s for s in cat.services if s.service_id == svc_id), None)
        _subscribe_eventgroup(
            sd_group=sd_group, sd_port=sd_port,
            client_ip=bind_ip if bind_ip != "0.0.0.0" else "127.0.0.1",
            client_udp_port=port,
            svc_id=svc_id,
            inst_id=svc.instance_id if svc else 0,
            major=svc.major_version if svc else 1,
            eventgroup_id=egid,
            timeout_s=timeout_s, verbose=verbose,
        )

    sigs = sig_index.subset(event.signals)
    s    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
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
            desc += f" group={group}"
        print(f"[udp] sub event={event.name} egid=0x{egid:04X} -> {desc} count={count}")

    got = 0
    while got < count:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            print("[udp] timeout waiting for datagram")
            continue

        hdr, payload = parse_message(data)
        if hdr.service_id != svc_id or hdr.method_id != event_id or hdr.msg_type != MT_NOTIFICATION:
            if verbose:
                print(f"[udp] drop sid={hdr.service_id:04X} mid={hdr.method_id:04X}")
            continue

        if _e2e_enabled(event):
            payload, _ = e2e_unwrap(payload)

        vals = decode(sigs, payload)
        print(f"[udp] rx someip sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} "
              f"sess={hdr.session_id} values={vals}")
        got += 1

    s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Client")
    ap.add_argument("--catalog",       default="configs/catalog.yaml")
    ap.add_argument("--tcp-ip",        default="127.0.0.1")
    ap.add_argument("--tcp-port",      type=int, default=None)
    ap.add_argument("--timeout-ms",    type=int, default=500)
    ap.add_argument("--call-method",   default=None)
    ap.add_argument("--set",           action="append", default=[])
    ap.add_argument("--sub-event",     default=None)
    ap.add_argument("--udp-bind-ip",   default="0.0.0.0")
    ap.add_argument("--iface-ip",      default="0.0.0.0")
    ap.add_argument("--count",         type=int, default=5)
    ap.add_argument("--udp-timeout-s", type=float, default=2.0)
    ap.add_argument("--discover",      action="store_true")
    ap.add_argument("--sd-group",      default=None)
    ap.add_argument("--sd-port",       type=int, default=None)
    ap.add_argument("--sd-timeout-s",  type=float, default=2.0)
    ap.add_argument("--verbose",       action="store_true")
    args = ap.parse_args()

    cat       = load_catalog(args.catalog)
    sig_index = SignalIndex.from_signals(cat.signals)

    discovered_ip:  Optional[str]       = None
    discovered_msg: Optional[SdMessage] = None

    if args.discover:
        sd_group, sd_port, _, _ = get_discovery_cfg(cat)
        if args.sd_group is not None: sd_group = str(args.sd_group)
        if args.sd_port  is not None: sd_port  = int(args.sd_port)
        discovered_ip, discovered_msg = _discover(
            group=sd_group, port=sd_port,
            bind_ip="0.0.0.0", iface_ip=args.iface_ip,
            timeout_s=args.sd_timeout_s, verbose=args.verbose,
        )
        _print_sd_summary(discovered_msg)
        if args.tcp_ip == "127.0.0.1":
            args.tcp_ip = discovered_ip

    if args.call_method:
        method = _find_method(cat, args.call_method)
        if discovered_msg is not None and args.tcp_port is None:
            svc_id, _, _ = resolve_someip(cat, method)
            offer = _find_offer_entry(discovered_msg, svc_id)
            if offer:
                p = _tcp_port_from_entry(offer)
                if p:
                    args.tcp_port = p

        values: Dict[str, float] = {}
        for item in args.set:
            if "=" not in item:
                raise SystemExit(f"--set expects name=value, got: {item}")
            k, v = item.split("=", 1)
            values[k.strip()] = float(v.strip())
        if not values:
            for n in method.signals:
                values[n] = float(sig_index.by_name[n].default)

        _tcp_call(cat=cat, method=method, sig_index=sig_index,
                  tcp_ip=args.tcp_ip, tcp_port=args.tcp_port,
                  values=values, timeout_ms=args.timeout_ms, verbose=args.verbose)

    if args.sub_event:
        event = _find_event(cat, args.sub_event)
        sub_sd_group, sub_sd_port = None, None
        offer_entry = None
        if args.discover:
            sd_group, sd_port, _, _ = get_discovery_cfg(cat)
            if args.sd_group is not None: sd_group = str(args.sd_group)
            if args.sd_port  is not None: sd_port  = int(args.sd_port)
            sub_sd_group, sub_sd_port = sd_group, sd_port
            if discovered_msg:
                svc_id, _, _ = resolve_someip(cat, event)
                offer_entry  = _find_offer_entry(discovered_msg, svc_id)

        _udp_subscribe(
            cat=cat, event=event, sig_index=sig_index,
            bind_ip=args.udp_bind_ip, iface_ip=args.iface_ip,
            count=args.count, timeout_s=args.udp_timeout_s,
            verbose=args.verbose, server_ip=discovered_ip,
            sd_group=sub_sd_group, sd_port=sub_sd_port,
            offer_entry=offer_entry,
        )

    if not args.call_method and not args.sub_event:
        ap.print_help()
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
