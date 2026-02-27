from __future__ import annotations

import argparse
import signal
import socket
import threading
import time
from typing import Dict, List, Set, Tuple, NamedTuple

from autoeth.core.config import Catalog, MessageDef, SignalDef, load_catalog, resolve_someip, get_discovery_cfg
from autoeth.core.serialization.codec import decode, encode, encoded_size
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.tcp import TcpServer
from autoeth.core.transport import udp as udp_transport
from autoeth.core.validation.e2e import unwrap as e2e_unwrap, wrap as e2e_wrap
from autoeth.core.service.discovery import (
    SdAnnounce, SdEvent, SdService, SdSubscribeEventgroup,
    build_sd_datagram, build_sd_subscribe_eventgroup_ack, parse_sd_message,
)
from autoeth.protocols.someip.header import (
    build_message, MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE, MT_ERROR, RC_OK, RC_NOT_OK,
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


# ── Subscriber registry ───────────────────────────────────────────────────────

class SubscriberRegistry:
    """
    Thread-safe registry of active eventgroup subscriptions.

    Key: (service_id, eventgroup_id)
    Value: set of (client_ip, client_udp_port) endpoints
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._subs: Dict[Tuple[int, int], Set[Tuple[str, int]]] = {}

    def add(self, service_id: int, eg_id: int, client_ip: str, client_port: int) -> None:
        key = (service_id, eg_id)
        with self._lock:
            self._subs.setdefault(key, set()).add((client_ip, client_port))

    def remove(self, service_id: int, eg_id: int, client_ip: str, client_port: int) -> None:
        key = (service_id, eg_id)
        with self._lock:
            s = self._subs.get(key)
            if s:
                s.discard((client_ip, client_port))

    def get_subscribers(self, service_id: int, eg_id: int) -> List[Tuple[str, int]]:
        key = (service_id, eg_id)
        with self._lock:
            return list(self._subs.get(key, set()))

    def has_subscribers(self, service_id: int, eg_id: int) -> bool:
        key = (service_id, eg_id)
        with self._lock:
            return bool(self._subs.get(key))


# ── SD subscriber listener ────────────────────────────────────────────────────

class SdSubscriberListener(threading.Thread):
    """
    Listens on the SD multicast port for SubscribeEventgroup messages,
    updates the SubscriberRegistry, and sends SubscribeEventgroupAck replies.
    """

    def __init__(
        self,
        *,
        sd_group: str,
        sd_port: int,
        iface_ip: str,
        udp_events: Dict[str, EventRoute],
        registry: SubscriberRegistry,
        stop_evt: threading.Event,
        verbose: bool,
    ) -> None:
        super().__init__(daemon=True)
        self._sd_group  = sd_group
        self._sd_port   = sd_port
        self._registry  = registry
        self._stop_evt  = stop_evt
        self._verbose   = verbose
        self._seq       = 0

        # (service_id, eventgroup_id) -> EventRoute
        self._eg_map: Dict[Tuple[int, int], EventRoute] = {
            (r.svc_id, r.event_id): r for r in udp_events.values()
        }

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(0.5)
        self._sock.bind(("0.0.0.0", sd_port))
        try:
            udp_transport.join_multicast(self._sock, sd_group, iface_ip=iface_ip)
        except Exception as exc:
            if verbose:
                print(f"[sd-listener] multicast join warning: {exc}")

    def run(self) -> None:
        if self._verbose:
            print(f"[sd-listener] listening on {self._sd_group}:{self._sd_port}")

        while not self._stop_evt.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                break

            msg = parse_sd_message(data)
            if not msg or not msg.subscribes:
                continue

            for sub in msg.subscribes:
                self._handle_subscribe(sub, addr)

        try:
            self._sock.close()
        except Exception:
            pass

    def _handle_subscribe(
        self, sub: SdSubscribeEventgroup, client_addr: Tuple[str, int]
    ) -> None:
        key    = (sub.service_id, sub.eventgroup_id)
        route  = self._eg_map.get(key)
        if not route:
            if self._verbose:
                print(
                    f"[sd-listener] unknown eventgroup "
                    f"sid=0x{sub.service_id:04X} eg=0x{sub.eventgroup_id:04X}"
                )
            return

        udp_cfg      = route.msg.udp or {}
        is_multicast = str(udp_cfg.get("mode", "unicast")) == "multicast"

        if sub.ttl > 0:
            if not is_multicast:
                self._registry.add(
                    sub.service_id, sub.eventgroup_id,
                    sub.client_ip, sub.client_udp_port,
                )
            if self._verbose:
                print(
                    f"[sd-listener] subscribe sid=0x{sub.service_id:04X} "
                    f"eg=0x{sub.eventgroup_id:04X} "
                    f"client={sub.client_ip}:{sub.client_udp_port} ttl={sub.ttl}"
                )
            self._send_ack(sub, route, client_addr)
        else:
            if not is_multicast:
                self._registry.remove(
                    sub.service_id, sub.eventgroup_id,
                    sub.client_ip, sub.client_udp_port,
                )
            if self._verbose:
                print(
                    f"[sd-listener] stop-subscribe sid=0x{sub.service_id:04X} "
                    f"eg=0x{sub.eventgroup_id:04X} "
                    f"client={sub.client_ip}:{sub.client_udp_port}"
                )

    def _send_ack(
        self,
        sub: SdSubscribeEventgroup,
        route: EventRoute,
        client_addr: Tuple[str, int],
    ) -> None:
        udp_cfg      = route.msg.udp or {}
        is_multicast = str(udp_cfg.get("mode", "unicast")) == "multicast"
        mcast_group  = str(udp_cfg.get("mcast_group", "")) if is_multicast else ""
        mcast_port   = int(udp_cfg.get("port", 0))         if is_multicast else 0

        self._seq = (self._seq + 1) & 0xFFFF
        ack = build_sd_subscribe_eventgroup_ack(
            seq=self._seq,
            service_id=sub.service_id,
            instance_id=sub.instance_id,
            major_version=sub.major_version,
            eventgroup_id=sub.eventgroup_id,
            mcast_group=mcast_group,
            mcast_port=mcast_port,
            ttl=3,
        )
        try:
            self._sock.sendto(ack, client_addr)
            if self._verbose:
                print(
                    f"[sd-listener] ack -> {client_addr} "
                    f"eg=0x{sub.eventgroup_id:04X}"
                )
        except OSError as exc:
            if self._verbose:
                print(f"[sd-listener] ack send error: {exc}")


# ── Catalog helpers ───────────────────────────────────────────────────────────

def _build_tcp_routes(cat: Catalog, sig_index: SignalIndex) -> dict[tuple[int, int], MethodRoute]:
    routes: dict[tuple[int, int], MethodRoute] = {}

    for m in cat.messages:
        if m.kind == "method" and m.transport == "tcp":
            tcp = m.tcp or {}
            if int(tcp.get("port", 0)) == 0:
                raise SystemExit(f"{m.name}: tcp.port missing/0")
            svc_id, iface_ver, method_id = resolve_someip(cat, m)
            key = (svc_id, method_id)

            if key in routes:
                raise SystemExit(
                    f"Duplicate TCP method mapping sid=0x{svc_id:04X} mid=0x{method_id:04X} "
                    f"({routes[key].msg.name} vs {m.name})"
                )

            routes[key] = MethodRoute(
                msg=m,
                iface_ver=iface_ver,
                sigs=sig_index.subset(m.signals),
            )

    if not routes:
        raise SystemExit("No TCP methods found in catalog (kind=method, transport=tcp).")

    return routes


def _build_udp_events(cat: Catalog, sig_index: SignalIndex) -> dict[str, EventRoute]:
    out:  dict[str, EventRoute]   = {}
    used: set[tuple[int, int]]    = set()

    for m in cat.messages:
        if m.kind == "event" and m.transport == "udp":
            svc_id, iface_ver, eid = resolve_someip(cat, m)
            key = (svc_id, eid)
            if key in used:
                raise SystemExit(f"Duplicate UDP event sid=0x{svc_id:04X} eid=0x{eid:04X}")
            used.add(key)

            udp = m.udp or {}
            if int(udp.get("port", 0)) == 0:
                raise SystemExit(f"{m.name}: udp.port missing/0")
            mode = str(udp.get("mode", "unicast"))
            if mode == "multicast" and not udp.get("mcast_group"):
                raise SystemExit(f"{m.name}: udp.mcast_group required for multicast")

            out[m.name] = EventRoute(
                msg=m,
                iface_ver=iface_ver,
                sigs=sig_index.subset(m.signals),
                svc_id=svc_id,
                event_id=eid,
            )

    if not out:
        raise SystemExit("No UDP events found (kind=event, transport=udp).")

    return out


def _build_sd_announce(
    *,
    cat: Catalog,
    routes: dict[tuple[int, int], MethodRoute],
    udp_events: dict[str, EventRoute],
    server_ip: str = "0.0.0.0",
) -> SdAnnounce:
    services_by_name = cat.services_by_name()
    used_names: set[str] = set()

    for m in cat.messages:
        svc_name = str((m.someip or {}).get("service", "")).strip()
        if svc_name:
            used_names.add(svc_name)

    if not used_names:
        raise SystemExit("No someip.service entries found for discovery announce")

    services: list[SdService] = []
    for svc_name in sorted(used_names):
        svc = services_by_name.get(svc_name)
        if not svc:
            raise SystemExit(f"Discovery: unknown service {svc_name!r}")

        # Collect all TCP ports for this service (one per method message)
        tcp_ports = sorted({
            int((r.msg.tcp or {}).get("port", 0))
            for r in routes.values()
            if str((r.msg.someip or {}).get("service", "")).strip() == svc_name
        } - {0})

        events: list[SdEvent] = []
        for route in udp_events.values():
            if str((route.msg.someip or {}).get("service", "")).strip() != svc_name:
                continue
            udp = route.msg.udp or {}
            mode     = str(udp.get("mode", "unicast"))
            udp_mode = 1 if mode == "multicast" else 0
            group    = str(udp.get("mcast_group", "0.0.0.0")) if udp_mode else "0.0.0.0"
            events.append(SdEvent(
                event_id=int(route.event_id),
                udp_port=int(udp.get("port", 0)),
                mcast_group=group,
                udp_mode=udp_mode,
                ttl=int(udp.get("ttl", 1)),
                eventgroup_id=int(route.event_id),  # eventgroup_id == event_id
            ))

        services.append(SdService(
            service_id=int(svc.service_id),
            instance_id=int(svc.instance_id),
            iface_ver=int(svc.interface_version),
            tcp_ports=tuple(tcp_ports),
            events=tuple(events),
            major_version=int(svc.major_version),
            minor_version=int(svc.minor_version),
            server_ip=server_ip,
        ))

    return SdAnnounce(services=tuple(services))


# ── TCP handler ───────────────────────────────────────────────────────────────

def _tcp_handler(
    conn: socket.socket,
    addr: tuple,
    *,
    cat: Catalog,
    routes: dict[tuple[int, int], MethodRoute],
    state: Dict[str, float],
    state_lock: threading.Lock,
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
            err = build_message(
                service_id=hdr.service_id, method_id=hdr.method_id,
                client_id=hdr.client_id, session_id=hdr.session_id,
                iface_ver=hdr.iface_ver, msg_type=MT_ERROR,
                payload=b"", return_code=RC_NOT_OK,
            )
            send_someip(conn, err)
            continue

        msg      = route.msg
        sigs     = route.sigs
        iface_ver = route.iface_ver

        if _e2e_enabled(msg):
            try:
                pl_core, counter = e2e_unwrap(pl)
            except Exception as e:
                if verbose:
                    print(f"[tcp] drop e2e: {e}")
                continue
            if counter != hdr.session_id:
                if verbose:
                    print(f"[tcp] drop e2e counter({counter}) != session_id({hdr.session_id})")
                continue
        else:
            pl_core = pl

        values = decode(sigs, pl_core)

        with state_lock:
            for k, v in values.items():
                state[k] = float(v)

        if verbose:
            print(
                f"[tcp] rx {msg.name} sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X} "
                f"sess={hdr.session_id} values={values}"
            )

        rsp_pl = encode(sigs, values)
        if _e2e_enabled(msg):
            rsp_pl = e2e_wrap(rsp_pl, counter=hdr.session_id)

        rsp = build_message(
            service_id=hdr.service_id, method_id=hdr.method_id,
            client_id=hdr.client_id, session_id=hdr.session_id,
            iface_ver=iface_ver, msg_type=MT_RESPONSE,
            payload=rsp_pl, return_code=RC_OK,
        )
        send_someip(conn, rsp)

    if verbose:
        print(f"[tcp] client disconnected: {addr}")


# ── UDP event publisher ───────────────────────────────────────────────────────

class UdpEventPublisher(threading.Thread):
    """
    Publishes a single UDP event at its configured period.

    Multicast mode: always sends to the multicast group.
    Unicast mode:   only sends to endpoints registered in the SubscriberRegistry.
    """

    def __init__(
        self,
        *,
        route: EventRoute,
        state: Dict[str, float],
        state_lock: threading.Lock,
        stop_evt: threading.Event,
        dest_ip: str,
        registry: SubscriberRegistry,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.msg        = route.msg
        self.sigs       = route.sigs
        self.state      = state
        self.state_lock = state_lock
        self.stop_evt   = stop_evt
        self.verbose    = verbose
        self.svc_id     = route.svc_id
        self.iface_ver  = route.iface_ver
        self.event_id   = route.event_id
        self.registry   = registry

        udp_cfg     = self.msg.udp or {}
        self.mode   = str(udp_cfg.get("mode", "unicast"))
        self.group  = udp_cfg.get("mcast_group")
        self.port   = int(udp_cfg["port"])
        self.ttl    = int(udp_cfg.get("ttl", 1))
        self.iface  = udp_cfg.get("iface")

        self.sock = udp_transport.make_socket(
            iface=self.iface, ttl=self.ttl, bind_ip="0.0.0.0", bind_port=0,
        )
        self._mcast_dest: Tuple[str, int] = udp_transport.dest(
            self.mode, self.group, dest_ip, self.port,
        )
        self.period_s = max(float(self.msg.period_ms or 1000) / 1000.0, 0.001)
        self.seq = 0

    def run(self) -> None:
        next_t = time.monotonic()

        if self.verbose:
            print(
                f"[udp] pub {self.msg.name} id={self.msg.msg_id} "
                f"sid=0x{self.svc_id:04X} eid=0x{self.event_id:04X} "
                f"mode={self.mode} period_ms={int(self.period_s * 1000)}"
            )

        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self.period_s

            with self.state_lock:
                vals = {s.name: float(self.state.get(s.name, s.default)) for s in self.sigs}

            self.seq = (self.seq + 1) & 0xFFFF

            payload = encode(self.sigs, vals)
            if _e2e_enabled(self.msg):
                payload = e2e_wrap(payload, counter=self.seq)

            datagram = build_message(
                service_id=self.svc_id,
                method_id=self.event_id,
                client_id=0x0000,
                session_id=self.seq,
                iface_ver=self.iface_ver,
                msg_type=MT_NOTIFICATION,
                payload=payload,
            )

            if self.mode == "multicast":
                # Multicast: always send to the group
                try:
                    self.sock.sendto(datagram, self._mcast_dest)
                except OSError as exc:
                    if self.verbose:
                        print(f"[udp] send error {self.msg.name}: {exc}")
            else:
                # Unicast: only send to registered subscribers
                subscribers = self.registry.get_subscribers(self.svc_id, self.event_id)
                for endpoint in subscribers:
                    try:
                        self.sock.sendto(datagram, endpoint)
                    except OSError as exc:
                        if self.verbose:
                            print(f"[udp] send error {self.msg.name} -> {endpoint}: {exc}")

        try:
            self.sock.close()
        except Exception:
            pass


# ── SD announcer ──────────────────────────────────────────────────────────────

class SdAnnouncer(threading.Thread):
    def __init__(
        self,
        *,
        ann: SdAnnounce,
        group_ip: str,
        group_port: int,
        iface: str | None,
        ttl: int,
        stop_evt: threading.Event,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.ann      = ann
        self.dest     = (group_ip, int(group_port))
        self.stop_evt = stop_evt
        self.verbose  = verbose
        self.sock     = udp_transport.make_socket(iface=iface, ttl=ttl, bind_ip="0.0.0.0", bind_port=0)
        self.seq      = 0

    def run(self) -> None:
        if self.verbose:
            print(f"[sd] announce -> {self.dest} every 1000ms")

        next_t = time.monotonic()
        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += 1.0

            d = build_sd_datagram(seq=self.seq, ann=self.ann)
            try:
                self.sock.sendto(d, self.dest)
            except OSError as exc:
                if self.verbose:
                    print(f"[sd] send error: {exc}")

            self.seq = (self.seq + 1) & 0xFFFF

        try:
            self.sock.close()
        except Exception:
            pass


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Node (TCP methods + UDP events)")
    ap.add_argument("--catalog", default="configs/catalog.yaml")
    ap.add_argument("--listen-ip", default="0.0.0.0")
    ap.add_argument(
        "--tcp-port", type=int, default=None,
        help="Override TCP port (only used when catalog has exactly one TCP method port)",
    )
    ap.add_argument("--udp-dest-ip", default="127.0.0.1", help="Destination for unicast UDP events")
    ap.add_argument("--sd-group",  default=None)
    ap.add_argument("--sd-port",   type=int, default=None)
    ap.add_argument("--sd-ttl",    type=int, default=None)
    ap.add_argument("--sd-iface",  default=None)
    ap.add_argument("--iface-ip",  default="0.0.0.0", help="Multicast join interface IP")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)
    cat.validate()

    sig_index  = SignalIndex.from_signals(cat.signals)
    state:      Dict[str, float] = _init_state(cat.signals)
    state_lock  = threading.Lock()
    stop_evt    = threading.Event()

    # ── TCP servers (one per distinct port) ──
    routes = _build_tcp_routes(cat, sig_index)

    ports = sorted({int((r.msg.tcp or {}).get("port", 0)) for r in routes.values()} - {0})
    if not ports:
        raise SystemExit("No valid TCP ports found in catalog methods.")

    # --tcp-port override: only honoured when catalog has exactly one port
    if args.tcp_port is not None:
        if len(ports) == 1:
            ports = [int(args.tcp_port)]
        else:
            print(
                f"[node] --tcp-port ignored: catalog has multiple TCP ports {ports}. "
                f"Using catalog ports."
            )

    def _handler(conn: socket.socket, addr: tuple) -> None:
        _tcp_handler(
            conn, addr,
            cat=cat, routes=routes,
            state=state, state_lock=state_lock,
            verbose=args.verbose,
        )

    tcp_servers: List[TcpServer] = []
    for port in ports:
        srv = TcpServer(listen_ip=args.listen_ip, port=port, handler=_handler)
        srv.start()
        tcp_servers.append(srv)

    # ── UDP events ──
    udp_events = _build_udp_events(cat, sig_index)

    # ── SD config (catalog defaults, overridable via CLI) ──
    sd_group, sd_port, sd_ttl, sd_iface = get_discovery_cfg(cat)
    if args.sd_group  is not None: sd_group = str(args.sd_group)
    if args.sd_port   is not None: sd_port  = int(args.sd_port)
    if args.sd_ttl    is not None: sd_ttl   = int(args.sd_ttl)
    if args.sd_iface  is not None: sd_iface = str(args.sd_iface)

    # ── Subscriber registry + SD listener ──
    registry = SubscriberRegistry()

    sd_listener = SdSubscriberListener(
        sd_group=sd_group,
        sd_port=sd_port,
        iface_ip=args.iface_ip,
        udp_events=udp_events,
        registry=registry,
        stop_evt=stop_evt,
        verbose=args.verbose,
    )
    sd_listener.start()

    # ── SD announcer ──
    ann = _build_sd_announce(
        cat=cat,
        routes=routes,
        udp_events=udp_events,
        server_ip=args.listen_ip,
    )
    sd_announcer = SdAnnouncer(
        ann=ann,
        group_ip=sd_group,
        group_port=sd_port,
        iface=sd_iface,
        ttl=sd_ttl,
        stop_evt=stop_evt,
        verbose=args.verbose,
    )
    sd_announcer.start()

    # ── UDP event publishers ──
    udp_threads: List[UdpEventPublisher] = []
    for route in udp_events.values():
        t = UdpEventPublisher(
            route=route,
            state=state,
            state_lock=state_lock,
            stop_evt=stop_evt,
            dest_ip=args.udp_dest_ip,
            registry=registry,
            verbose=args.verbose,
        )
        t.start()
        udp_threads.append(t)

    print(
        f"[node] tcp_ports={ports} listen={args.listen_ip} "
        f"tcp_methods={sorted(r.msg.msg_id for r in routes.values())} "
        f"udp_events={[r.msg.msg_id for r in udp_events.values()]}"
    )

    def _sigint(_signum, _frame):
        stop_evt.set()

    signal.signal(signal.SIGINT,  _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    while not stop_evt.is_set():
        stop_evt.wait(0.2)

    for srv in tcp_servers:
        srv.stop()
    for t in udp_threads:
        t.join(timeout=0.5)

    print("[node] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
