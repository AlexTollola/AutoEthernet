from __future__ import annotations

import argparse
import signal
import socket
import threading
import time
from typing import Dict, List, Tuple, NamedTuple

from autoeth.core.config import Catalog, MessageDef, SignalDef, load_catalog, resolve_someip
from autoeth.core.serialization.codec import decode, encode, encoded_size
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.tcp import TcpServer
from autoeth.core.transport import udp as udp_transport
from autoeth.core.validation.e2e import unwrap as e2e_unwrap, wrap as e2e_wrap
from autoeth.core.service.discovery import SdAnnounce, SdEvent, SdService, build_sd_datagram
from autoeth.protocols.someip.header import build_message, MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE, MT_ERROR, RC_OK, RC_NOT_OK
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
    out: dict[str, EventRoute] = {}
    used: set[tuple[int, int]] = set()

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

        tcp_ports = sorted(
            {
                int((r.msg.tcp or {}).get("port", 0))
                for r in routes.values()
                if str((r.msg.someip or {}).get("service", "")).strip() == svc_name
            }
        )
        tcp_ports = [p for p in tcp_ports if p]

        events: list[SdEvent] = []
        for route in udp_events.values():
            if str((route.msg.someip or {}).get("service", "")).strip() != svc_name:
                continue
            udp = route.msg.udp or {}
            mode = str(udp.get("mode", "unicast"))
            udp_mode = 1 if mode == "multicast" else 0
            group = str(udp.get("mcast_group", "0.0.0.0")) if udp_mode == 1 else "0.0.0.0"
            events.append(
                SdEvent(
                    event_id=int(route.event_id),
                    udp_port=int(udp.get("port", 0)),
                    mcast_group=group,
                    udp_mode=udp_mode,
                    ttl=int(udp.get("ttl", 1)),
                )
            )

        services.append(
            SdService(
                service_id=int(svc.service_id),
                instance_id=int(svc.instance_id),
                iface_ver=int(svc.interface_version),
                tcp_ports=tuple(tcp_ports),
                events=tuple(events),
            )
        )

    return SdAnnounce(services=tuple(services))


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

        # Solo aceptamos REQUEST
        if hdr.msg_type != MT_REQUEST:
            continue

        key = (hdr.service_id, hdr.method_id)
        route = routes.get(key)
        if not route:
            if verbose:
                print(f"[tcp] unknown method sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X}")

            err = build_message(
                service_id=hdr.service_id,
                method_id=hdr.method_id,
                client_id=hdr.client_id,
                session_id=hdr.session_id,
                iface_ver=hdr.iface_ver,
                msg_type=MT_ERROR,
                payload=b"",
                return_code=RC_NOT_OK,
            )
            send_someip(conn, err)
            continue

        msg = route.msg
        sigs = route.sigs
        iface_ver = route.iface_ver

        # E2E opcional (counter = session_id)
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
            service_id=hdr.service_id,
            method_id=hdr.method_id,
            client_id=hdr.client_id,
            session_id=hdr.session_id,
            iface_ver=iface_ver,
            msg_type=MT_RESPONSE,
            payload=rsp_pl,
            return_code=RC_OK,
        )
        send_someip(conn, rsp)

    if verbose:
        print(f"[tcp] client disconnected: {addr}")


class UdpEventPublisher(threading.Thread):
    def __init__(
        self,
        *,
        route: EventRoute,
        state: Dict[str, float],
        state_lock: threading.Lock,
        stop_evt: threading.Event,
        dest_ip: str,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.msg = route.msg
        self.sigs = route.sigs
        self.state = state
        self.state_lock = state_lock
        self.stop_evt = stop_evt
        self.dest_ip = dest_ip
        self.verbose = verbose
        self.svc_id = route.svc_id
        self.iface_ver = route.iface_ver
        self.event_id = route.event_id

        udp_cfg = self.msg.udp or {}
        self.mode = str(udp_cfg.get("mode", "unicast"))
        self.group = udp_cfg.get("mcast_group")
        self.port = int(udp_cfg["port"])
        self.ttl = int(udp_cfg.get("ttl", 1))
        self.iface = udp_cfg.get("iface")

        self.sock = udp_transport.make_socket(iface=self.iface, ttl=self.ttl, bind_ip="0.0.0.0", bind_port=0)
        self.dest: Tuple[str, int] = udp_transport.dest(self.mode, self.group, self.dest_ip, self.port)

        self.period_s = max(float(self.msg.period_ms or 1000) / 1000.0, 0.001)

        self.seq = 0
        self.exp_len = encoded_size(self.sigs)


    def run(self) -> None:
        next_t = time.monotonic()

        if self.verbose:
            print(
                f"[udp] pub {self.msg.name} id={self.msg.msg_id} "
                f"sid=0x{self.svc_id:04X} eid=0x{self.event_id:04X} -> {self.dest} "
                f"period_ms={int(self.period_s*1000)}"
            )

        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self.period_s

            with self.state_lock:
                vals = {s.name: float(self.state.get(s.name, s.default)) for s in self.sigs}

            svc_id, iface_ver, method_id = self.svc_id, self.iface_ver, self.event_id

            self.seq = (self.seq + 1) & 0xFFFF

            payload = encode(self.sigs, vals)
            if _e2e_enabled(self.msg):
                payload = e2e_wrap(payload, counter=self.seq)

            datagram = build_message(
                service_id=svc_id,
                method_id=method_id,
                client_id=0x0000,
                session_id=self.seq,
                iface_ver=iface_ver,
                msg_type=MT_NOTIFICATION,
                payload=payload,
            )

            try:
                self.sock.sendto(datagram, self.dest)
            except OSError as e:
                if self.verbose:
                    print(f"[udp] send error {self.msg.name}: {e}")

        try:
            self.sock.close()
        except Exception:
            pass


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
        self.ann = ann
        self.dest = (group_ip, int(group_port))
        self.stop_evt = stop_evt
        self.verbose = verbose
        self.sock = udp_transport.make_socket(iface=iface, ttl=ttl, bind_ip="0.0.0.0", bind_port=0)
        self.seq = 0

    def run(self) -> None:
        if self.verbose:
            print(f"[sd] announce -> {self.dest} every 1000ms payload={self.ann}")

        next_t = time.monotonic()
        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += 1.0  # 1000 ms

            d = build_sd_datagram(seq=self.seq, ann=self.ann)
            try:
                self.sock.sendto(d, self.dest)
            except OSError as e:
                if self.verbose:
                    print(f"[sd] send error: {e}")

            self.seq = (self.seq + 1) & 0xFFFF

        try:
            self.sock.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Node (TCP methods + UDP events)")
    ap.add_argument("--catalog", default="configs/catalog.yaml", help="canonical catalog YAML")
    ap.add_argument("--listen-ip", default="0.0.0.0", help="TCP listen IP")
    ap.add_argument("--tcp-port", type=int, default=None, help="override TCP port (else first TCP method port in catalog)")
    ap.add_argument("--udp-dest-ip", default="127.0.0.1", help="used for UDP unicast mode")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)
    cat.validate()

    sig_index = SignalIndex.from_signals(cat.signals)
    state: Dict[str, float] = _init_state(cat.signals)
    state_lock = threading.Lock()

    stop_evt = threading.Event()

    # TCP server (methods)
    routes = _build_tcp_routes(cat, sig_index)

    # Por ahora: 1 solo puerto TCP para todos los methods (milestone actual)
    ports = {int((r.msg.tcp or {}).get("port", 0)) for r in routes.values()}
    if 0 in ports:
        raise SystemExit("One or more TCP methods missing tcp.port")

    if args.tcp_port is None:
        if len(ports) != 1:
            raise SystemExit(f"Multiple TCP ports in catalog not supported yet: {sorted(ports)}")
        tcp_port = next(iter(ports))
    else:
        tcp_port = int(args.tcp_port)

    def _handler(conn: socket.socket, addr: tuple) -> None:
        _tcp_handler(
            conn,
            addr,
            cat=cat,
            routes=routes,
            state=state,
            state_lock=state_lock,
            verbose=args.verbose,
        )

    srv = TcpServer(listen_ip=args.listen_ip, port=tcp_port, handler=_handler)
    srv.start()

    # UDP events
    udp_events = _build_udp_events(cat, sig_index)
    first_event = next(iter(udp_events.values())).msg
    udp_cfg = first_event.udp or {}

    # SD multicast (use a dedicated group/port)
    sd_group = "239.0.0.2"
    sd_port = 30490
    sd_iface = str(udp_cfg.get("iface")) if str(udp_cfg.get("mode", "unicast")) == "multicast" else None
    sd_ttl = int(udp_cfg.get("ttl", 1))

    ann = _build_sd_announce(cat=cat, routes=routes, udp_events=udp_events)
    sd = SdAnnouncer(
        ann=ann,
        group_ip=sd_group,
        group_port=sd_port,
        iface=sd_iface,
        ttl=sd_ttl,
        stop_evt=stop_evt,
        verbose=args.verbose,
    )
    sd.start()

    # UDP publishers (events)
    udp_threads: List[UdpEventPublisher] = []
    for route in udp_events.values():
        t = UdpEventPublisher(
            route=route,
            state=state,
            state_lock=state_lock,
            stop_evt=stop_evt,
            dest_ip=args.udp_dest_ip,
            verbose=args.verbose,
        )
        t.start()
        udp_threads.append(t)

    print(
        f"[node] tcp_methods={sorted(r.msg.msg_id for r in routes.values())} "
        f"tcp_listen={args.listen_ip}:{tcp_port} "
        f"udp_events={[r.msg.msg_id for r in udp_events.values()]}"
    )

    def _sigint(_signum, _frame):
        stop_evt.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    while not stop_evt.is_set():
        stop_evt.wait(0.2)

    srv.stop()
    for t in udp_threads:
        t.join(timeout=0.5)

    print("[node] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
