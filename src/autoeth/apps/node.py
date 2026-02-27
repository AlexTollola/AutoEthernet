from __future__ import annotations

import argparse
import signal
import socket
import threading
import time
from typing import Dict, List, Set, Tuple, NamedTuple

from autoeth.core.config import (
    Catalog, MessageDef, SignalDef, load_catalog,
    resolve_someip, resolve_eventgroup_id, get_discovery_cfg,
)
from autoeth.core.serialization.codec import decode, encode, encoded_size
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.tcp import TcpServer
from autoeth.core.transport import udp as udp_transport
from autoeth.core.validation.e2e import unwrap as e2e_unwrap, wrap as e2e_wrap
from autoeth.core.service.discovery import (
    SdMessage, ServiceEntry, EventgroupEntry,
    Ipv4EndpointOption, Ipv4MulticastOption,
    ET_OFFER_SERVICE, ET_SUBSCRIBE_EVENTGROUP, ET_SUBSCRIBE_EVENTGROUP_ACK,
    L4_TCP, L4_UDP,
    TTL_DEFAULT, TTL_STOP,
    SD_FLAG_REBOOT, SD_FLAG_UNICAST,
    build_sd_message, parse_sd_message,
)
from autoeth.protocols.someip.header import (
    build_message, MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE, MT_ERROR,
    RC_OK, RC_NOT_OK,
)
from autoeth.protocols.someip.stream import recv_someip, send_someip


def _init_state(signals: List[SignalDef]) -> Dict[str, float]:
    return {s.name: float(s.default) for s in signals}


def _e2e_enabled(msg: MessageDef) -> bool:
    return bool((msg.e2e or {}).get("enabled", False))


class MethodRoute(NamedTuple):
    msg: MessageDef
    iface_ver: int
    sigs: list[SignalDef]


class EventRoute(NamedTuple):
    msg: MessageDef
    iface_ver: int
    sigs: list[SignalDef]
    svc_id: int
    event_id: int
    eventgroup_id: int


def _build_tcp_routes(cat: Catalog, sig_index: SignalIndex) -> dict[tuple[int, int], MethodRoute]:
    routes: dict[tuple[int, int], MethodRoute] = {}
    for m in cat.messages:
        if m.kind != "method" or m.transport != "tcp":
            continue
        if not int((m.tcp or {}).get("port", 0)):
            raise SystemExit(f"{m.name}: tcp.port missing/0")
        svc_id, iface_ver, method_id = resolve_someip(cat, m)
        key = (svc_id, method_id)
        if key in routes:
            raise SystemExit(
                f"Duplicate TCP method sid=0x{svc_id:04X} mid=0x{method_id:04X} "
                f"({routes[key].msg.name} vs {m.name})"
            )
        routes[key] = MethodRoute(msg=m, iface_ver=iface_ver, sigs=sig_index.subset(m.signals))
    if not routes:
        raise SystemExit("No TCP methods found in catalog.")
    return routes


def _build_udp_events(cat: Catalog, sig_index: SignalIndex) -> dict[str, EventRoute]:
    out: dict[str, EventRoute] = {}
    used: set[tuple[int, int]] = set()
    for m in cat.messages:
        if m.kind != "event" or m.transport != "udp":
            continue
        svc_id, iface_ver, eid = resolve_someip(cat, m)
        key = (svc_id, eid)
        if key in used:
            raise SystemExit(f"Duplicate UDP event sid=0x{svc_id:04X} eid=0x{eid:04X}")
        used.add(key)
        udp = m.udp or {}
        if not int(udp.get("port", 0)):
            raise SystemExit(f"{m.name}: udp.port missing/0")
        mode = str(udp.get("mode", "unicast"))
        if mode == "multicast" and not udp.get("mcast_group"):
            raise SystemExit(f"{m.name}: udp.mcast_group required for multicast")
        egid = resolve_eventgroup_id(m)
        out[m.name] = EventRoute(
            msg=m, iface_ver=iface_ver, sigs=sig_index.subset(m.signals),
            svc_id=svc_id, event_id=eid, eventgroup_id=egid,
        )
    if not out:
        raise SystemExit("No UDP events found.")
    return out


class SubscriberRegistry:
    """Thread-safe per-eventgroup unicast subscriber set."""

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._subs: Dict[Tuple[int, int], Set[Tuple[str, int]]] = {}

    def subscribe(self, svc_id: int, egid: int, ip: str, port: int) -> None:
        with self._lock:
            self._subs.setdefault((svc_id, egid), set()).add((ip, port))

    def unsubscribe(self, svc_id: int, egid: int, ip: str, port: int) -> None:
        with self._lock:
            self._subs.get((svc_id, egid), set()).discard((ip, port))

    def get_subscribers(self, svc_id: int, egid: int) -> Set[Tuple[str, int]]:
        with self._lock:
            return set(self._subs.get((svc_id, egid), set()))


def _tcp_handler(
    conn: socket.socket, addr: tuple, *,
    cat: Catalog, routes: dict[tuple[int, int], MethodRoute],
    state: Dict[str, float], state_lock: threading.Lock,
    verbose: bool,
) -> None:
    if verbose:
        print(f"[tcp] client connected: {addr}")
    while True:
        try:
            hdr, pl = recv_someip(conn, max_payload=4096)
        except ConnectionError:
            break
        except Exception as e:
            if verbose:
                print(f"[tcp] recv error: {e}")
            continue

        if hdr.msg_type != MT_REQUEST:
            continue

        key   = (hdr.service_id, hdr.method_id)
        route = routes.get(key)
        if not route:
            if verbose:
                print(f"[tcp] unknown method sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X}")
            send_someip(conn, build_message(
                service_id=hdr.service_id, method_id=hdr.method_id,
                client_id=hdr.client_id, session_id=hdr.session_id,
                iface_ver=hdr.iface_ver, msg_type=MT_ERROR,
                payload=b"", return_code=RC_NOT_OK,
            ))
            continue

        msg, sigs, iface_ver = route.msg, route.sigs, route.iface_ver

        if _e2e_enabled(msg):
            try:
                pl_core, counter = e2e_unwrap(pl)
            except Exception as e:
                if verbose:
                    print(f"[tcp] drop e2e: {e}")
                continue
            if counter != hdr.session_id:
                if verbose:
                    print(f"[tcp] drop e2e counter mismatch")
                continue
        else:
            pl_core = pl

        values = decode(sigs, pl_core)
        with state_lock:
            for k, v in values.items():
                state[k] = float(v)

        if verbose:
            print(f"[tcp] rx {msg.name} sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} values={values}")

        rsp_pl = encode(sigs, values)
        if _e2e_enabled(msg):
            rsp_pl = e2e_wrap(rsp_pl, counter=hdr.session_id)

        send_someip(conn, build_message(
            service_id=hdr.service_id, method_id=hdr.method_id,
            client_id=hdr.client_id, session_id=hdr.session_id,
            iface_ver=iface_ver, msg_type=MT_RESPONSE,
            payload=rsp_pl, return_code=RC_OK,
        ))

    if verbose:
        print(f"[tcp] client disconnected: {addr}")


class UdpEventPublisher(threading.Thread):
    """Publishes one UDP event periodically. Uses its own stop_evt for toggling."""

    def __init__(self, *, route: EventRoute,
                 state: Dict[str, float], state_lock: threading.Lock,
                 stop_evt: threading.Event,
                 registry: SubscriberRegistry,
                 dest_ip: str, verbose: bool) -> None:
        super().__init__(daemon=True)
        self.msg        = route.msg
        self.sigs       = route.sigs
        self.state      = state
        self.state_lock = state_lock
        self.stop_evt   = stop_evt
        self.registry   = registry
        self.verbose    = verbose
        self.svc_id     = route.svc_id
        self.iface_ver  = route.iface_ver
        self.event_id   = route.event_id
        self.egid       = route.eventgroup_id

        udp_cfg    = self.msg.udp or {}
        self.mode  = str(udp_cfg.get("mode", "unicast"))
        self.group = udp_cfg.get("mcast_group")
        self.port  = int(udp_cfg["port"])
        self.ttl   = int(udp_cfg.get("ttl", 1))
        self.iface = udp_cfg.get("iface")
        self.sock  = udp_transport.make_socket(iface=self.iface, ttl=self.ttl)
        self.mcast_dest: Tuple[str, int] = (self.group or "", self.port)
        self._dest_ip = dest_ip
        self.period_s = max(float(self.msg.period_ms or 1000) / 1000.0, 0.001)
        self.seq = 0

    def run(self) -> None:
        if self.verbose:
            print(f"[udp] pub {self.msg.name} sid=0x{self.svc_id:04X} "
                  f"eid=0x{self.event_id:04X} mode={self.mode} period_ms={int(self.period_s*1000)}")
        next_t = time.monotonic()
        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self.period_s

            with self.state_lock:
                vals = {s.name: float(self.state.get(s.name, s.default)) for s in self.sigs}

            self.seq = (self.seq + 1) & 0xFFFF
            payload  = encode(self.sigs, vals)
            if _e2e_enabled(self.msg):
                payload = e2e_wrap(payload, counter=self.seq)

            datagram = build_message(
                service_id=self.svc_id, method_id=self.event_id,
                client_id=0x0000, session_id=self.seq,
                iface_ver=self.iface_ver, msg_type=MT_NOTIFICATION,
                payload=payload,
            )

            if self.mode == "multicast":
                self._sendto(datagram, self.mcast_dest)
            else:
                for sub_ip, sub_port in self.registry.get_subscribers(self.svc_id, self.egid):
                    self._sendto(datagram, (sub_ip, sub_port))

        try:
            self.sock.close()
        except Exception:
            pass

    def _sendto(self, data: bytes, dest: Tuple[str, int]) -> None:
        try:
            self.sock.sendto(data, dest)
        except OSError as e:
            if self.verbose:
                print(f"[udp] send error {self.msg.name} -> {dest}: {e}")


class SdAnnouncer(threading.Thread):
    """Sends SOME/IP-SD OfferService messages periodically."""

    _PERIOD_S = 1.0

    def __init__(self, *, cat: Catalog,
                 routes: dict[tuple[int, int], MethodRoute],
                 udp_events: dict[str, EventRoute],
                 announce_ip: str,
                 sd_group: str, sd_port: int,
                 sd_iface: str | None, sd_ttl: int,
                 stop_evt: threading.Event, verbose: bool) -> None:
        super().__init__(daemon=True)
        self.dest     = (sd_group, sd_port)
        self.stop_evt = stop_evt
        self.verbose  = verbose
        self.sock     = udp_transport.make_socket(iface=sd_iface, ttl=sd_ttl)
        self.seq      = 0
        self._entries = self._build_entries(cat, routes, udp_events, announce_ip)

    @staticmethod
    def _build_entries(cat, routes, udp_events, announce_ip) -> list:
        entries = []
        for svc in cat.services:
            tcp_opts, tcp_seen = [], set()
            for r in routes.values():
                if str((r.msg.someip or {}).get("service", "")) != svc.name:
                    continue
                p = int((r.msg.tcp or {}).get("port", 0))
                if p and p not in tcp_seen:
                    tcp_seen.add(p)
                    tcp_opts.append(Ipv4EndpointOption(address=announce_ip, port=p, l4_proto=L4_TCP))

            udp_opts = []
            for r in udp_events.values():
                if str((r.msg.someip or {}).get("service", "")) != svc.name:
                    continue
                udp_cfg = r.msg.udp or {}
                mode    = str(udp_cfg.get("mode", "unicast"))
                port    = int(udp_cfg.get("port", 0))
                if mode == "multicast":
                    group = str(udp_cfg.get("mcast_group", ""))
                    if group and port:
                        udp_opts.append(Ipv4MulticastOption(address=group, port=port))
                elif port:
                    udp_opts.append(Ipv4EndpointOption(address=announce_ip, port=port, l4_proto=L4_UDP))

            entries.append(ServiceEntry(
                entry_type=ET_OFFER_SERVICE,
                service_id=svc.service_id, instance_id=svc.instance_id,
                major_version=svc.major_version, minor_version=svc.minor_version,
                ttl=TTL_DEFAULT, options=tcp_opts + udp_opts,
            ))
        return entries

    def run(self) -> None:
        if self.verbose:
            print(f"[sd] announcer -> {self.dest} every {self._PERIOD_S}s")
        next_t = time.monotonic()
        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self._PERIOD_S
            pkt = build_sd_message(session_id=self.seq, entries=self._entries,
                                   flags=SD_FLAG_REBOOT | SD_FLAG_UNICAST)
            try:
                self.sock.sendto(pkt, self.dest)
            except OSError as e:
                if self.verbose:
                    print(f"[sd] send error: {e}")
            self.seq = (self.seq + 1) & 0xFFFF
        try:
            self.sock.close()
        except Exception:
            pass


class SdListener(threading.Thread):
    """Listens for SubscribeEventgroup messages and manages the registry."""

    def __init__(self, *, sd_group: str, sd_port: int, iface_ip: str,
                 udp_events: dict[str, EventRoute],
                 registry: SubscriberRegistry,
                 stop_evt: threading.Event, verbose: bool) -> None:
        super().__init__(daemon=True)
        self.sd_group  = sd_group
        self.sd_port   = sd_port
        self.iface_ip  = iface_ip
        self.registry  = registry
        self.stop_evt  = stop_evt
        self.verbose   = verbose
        self._seq      = 0
        self._egid_map: Dict[Tuple[int, int], EventRoute] = {
            (r.svc_id, r.eventgroup_id): r for r in udp_events.values()
        }

    def run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.5)
        s.bind(("0.0.0.0", self.sd_port))
        udp_transport.join_multicast(s, self.sd_group, iface_ip=self.iface_ip)
        if self.verbose:
            print(f"[sd] listener on {self.sd_group}:{self.sd_port}")

        while not self.stop_evt.is_set():
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            msg = parse_sd_message(data)
            if msg is None:
                continue
            for entry in msg.entries:
                if isinstance(entry, EventgroupEntry):
                    self._handle_subscribe(entry, addr)
        try:
            s.close()
        except Exception:
            pass

    def _handle_subscribe(self, entry: EventgroupEntry, addr: Tuple[str, int]) -> None:
        key   = (entry.service_id, entry.eventgroup_id)
        route = self._egid_map.get(key)
        if not route:
            return

        sub_ip, sub_port = addr[0], 0
        for opt in entry.options:
            if isinstance(opt, Ipv4EndpointOption) and opt.l4_proto == L4_UDP:
                sub_ip, sub_port = opt.address, opt.port
                break

        if entry.ttl == TTL_STOP:
            if sub_port:
                self.registry.unsubscribe(entry.service_id, entry.eventgroup_id, sub_ip, sub_port)
            if self.verbose:
                print(f"[sd] stop-subscribe sid=0x{entry.service_id:04X} egid=0x{entry.eventgroup_id:04X}")
            return

        if sub_port:
            self.registry.subscribe(entry.service_id, entry.eventgroup_id, sub_ip, sub_port)
            if self.verbose:
                print(f"[sd] subscribe sid=0x{entry.service_id:04X} egid=0x{entry.eventgroup_id:04X} from {sub_ip}:{sub_port}")

        # Send SubscribeEventgroupAck
        ack = EventgroupEntry(
            entry_type=ET_SUBSCRIBE_EVENTGROUP_ACK,
            service_id=entry.service_id, instance_id=entry.instance_id,
            major_version=entry.major_version, eventgroup_id=entry.eventgroup_id,
            counter=entry.counter, ttl=entry.ttl, options=[],
        )
        self._seq = (self._seq + 1) & 0xFFFF
        pkt  = build_sd_message(session_id=self._seq, entries=[ack])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(pkt, (addr[0], self.sd_port))
            if self.verbose:
                print(f"[sd] ack -> {addr[0]} egid=0x{entry.eventgroup_id:04X}")
        except OSError:
            pass
        finally:
            sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Node (TCP methods + UDP events)")
    ap.add_argument("--catalog",     default="configs/catalog.yaml")
    ap.add_argument("--listen-ip",   default="0.0.0.0")
    ap.add_argument("--announce-ip", default="127.0.0.1")
    ap.add_argument("--iface-ip",    default="0.0.0.0")
    ap.add_argument("--sd-group",    default=None)
    ap.add_argument("--sd-port",     type=int, default=None)
    ap.add_argument("--sd-ttl",      type=int, default=None)
    ap.add_argument("--sd-iface",    default=None)
    ap.add_argument("--verbose",     action="store_true")
    args = ap.parse_args()

    cat       = load_catalog(args.catalog)
    sig_index = SignalIndex.from_signals(cat.signals)
    state: Dict[str, float] = _init_state(cat.signals)
    state_lock = threading.Lock()
    stop_evt   = threading.Event()
    registry   = SubscriberRegistry()

    routes     = _build_tcp_routes(cat, sig_index)
    udp_events = _build_udp_events(cat, sig_index)

    sd_group, sd_port, sd_ttl, sd_iface = get_discovery_cfg(cat)
    if args.sd_group  is not None: sd_group = str(args.sd_group)
    if args.sd_port   is not None: sd_port  = int(args.sd_port)
    if args.sd_ttl    is not None: sd_ttl   = int(args.sd_ttl)
    if args.sd_iface  is not None: sd_iface = str(args.sd_iface)

    all_ports: set[int] = set()
    for r in routes.values():
        p = int((r.msg.tcp or {}).get("port", 0))
        if p: all_ports.add(p)

    def _handler(conn, addr):
        _tcp_handler(conn, addr, cat=cat, routes=routes,
                     state=state, state_lock=state_lock, verbose=args.verbose)

    tcp_servers = []
    for port in sorted(all_ports):
        srv = TcpServer(listen_ip=args.listen_ip, port=port, handler=_handler)
        srv.start()
        tcp_servers.append(srv)
        print(f"[node] TCP listening on {args.listen_ip}:{port}")

    SdAnnouncer(
        cat=cat, routes=routes, udp_events=udp_events,
        announce_ip=args.announce_ip,
        sd_group=sd_group, sd_port=sd_port,
        sd_iface=sd_iface, sd_ttl=sd_ttl,
        stop_evt=stop_evt, verbose=args.verbose,
    ).start()

    SdListener(
        sd_group=sd_group, sd_port=sd_port, iface_ip=args.iface_ip,
        udp_events=udp_events, registry=registry,
        stop_evt=stop_evt, verbose=args.verbose,
    ).start()

    udp_threads = []
    for route in udp_events.values():
        pub_stop = threading.Event()
        t = UdpEventPublisher(
            route=route, state=state, state_lock=state_lock,
            stop_evt=pub_stop, registry=registry,
            dest_ip="127.0.0.1", verbose=args.verbose,
        )
        t.start()
        udp_threads.append((t, pub_stop))

    print(f"[node] tcp_ports={sorted(all_ports)} events={list(udp_events.keys())} sd={sd_group}:{sd_port}")

    def _sigint(_s, _f): stop_evt.set()
    signal.signal(signal.SIGINT,  _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    while not stop_evt.is_set():
        stop_evt.wait(0.2)

    for _, ps in udp_threads:
        ps.set()
    for srv in tcp_servers:
        srv.stop()
    print("[node] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
