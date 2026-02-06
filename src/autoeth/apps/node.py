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
from autoeth.core.service.discovery import SdAnnounce, build_sd_datagram
from autoeth.protocols.someip.header import build_message, MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE, MT_ERROR, RC_OK, RC_NOT_OK
from autoeth.protocols.someip.stream import recv_someip, send_someip





def _udp_events(cat: Catalog) -> List[MessageDef]:
    return [m for m in cat.messages if m.kind == "event" and m.transport == "udp"]


def _init_state(signals: List[SignalDef]) -> Dict[str, float]:
    return {s.name: float(s.default) for s in signals}

def _e2e_enabled(msg: MessageDef) -> bool:
    return bool((msg.e2e or {}).get("enabled", False))


class MethodRoute(NamedTuple):
    msg: MessageDef
    iface_ver: int
    sigs: list[SignalDef]


def _build_tcp_routes(cat: Catalog, sig_index: SignalIndex) -> dict[tuple[int, int], MethodRoute]:
    routes: dict[tuple[int, int], MethodRoute] = {}

    for m in cat.messages:
        if m.kind == "method" and m.transport == "tcp":
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
        cat: Catalog,
        msg: MessageDef,
        sigs: List[SignalDef],
        state: Dict[str, float],
        state_lock: threading.Lock,
        stop_evt: threading.Event,
        dest_ip: str,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.cat = cat
        self.msg = msg
        self.sigs = sigs
        self.state = state
        self.state_lock = state_lock
        self.stop_evt = stop_evt
        self.dest_ip = dest_ip
        self.verbose = verbose

        udp_cfg = msg.udp or {}
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
        self.svc_id, self.iface_ver, self.someip_id = resolve_someip(cat, msg)


    def run(self) -> None:
        next_t = time.monotonic()

        if self.verbose:
            print(f"[udp] pub {self.msg.name} id={self.msg.msg_id} -> {self.dest} period_ms={int(self.period_s*1000)}")

        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self.period_s

            with self.state_lock:
                vals = {s.name: float(self.state.get(s.name, s.default)) for s in self.sigs}

            svc_id, iface_ver, method_id = self.svc_id, self.iface_ver, self.someip_id

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
        service_id: int,
        instance_id: int,
        tcp_port: int,
        event_port: int,
        udp_mode: int,
        mcast_group: str,
        flags: int,
        group_ip: str,
        group_port: int,
        iface: str | None,
        ttl: int,
        stop_evt: threading.Event,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.ann = SdAnnounce(
            service_id=service_id,
            instance_id=instance_id,
            tcp_port=tcp_port,
            event_port=event_port,
            mcast_group=mcast_group,
            udp_mode=udp_mode,
            flags=flags,
        )
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

    first_method = next(iter(routes.values())).msg

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

    # Determine a "primary" UDP event to announce (first UDP event in catalog)
    udp_msgs = _udp_events(cat)
    if not udp_msgs:
        raise SystemExit("No UDP events found in catalog (kind=event, transport=udp).")
    first_event = udp_msgs[0]
    udp_cfg = first_event.udp or {}
    event_port = int(udp_cfg.get("port", 0))
    udp_mode = 1 if str(udp_cfg.get("mode", "unicast")) == "multicast" else 0
    mcast_group = str(udp_cfg.get("mcast_group", "0.0.0.0")) if udp_mode == 1 else "0.0.0.0"

    # Service IDs (service referenced by catalog messages)
    primary_svc_name = (first_method.someip or {}).get("service") or (first_event.someip or {}).get("service")
    if not primary_svc_name:
        raise SystemExit("No someip.service found to announce in SD")
    svc = cat.services_by_name()[str(primary_svc_name)]
    svc_id = int(svc.service_id)
    inst_id = int(svc.instance_id)

    # Flags: bit0=event E2E enabled, bit1=method E2E enabled
    event_e2e = 1 if _e2e_enabled(first_event) else 0
    method_e2e = 1 if _e2e_enabled(first_method) else 0
    flags = (event_e2e << 0) | (method_e2e << 1)

    # SD multicast (use a dedicated group/port)
    sd_group = "239.0.0.2"
    sd_port = 30490
    sd_iface = str(udp_cfg.get("iface")) if udp_mode == 1 else None
    sd_ttl = int(udp_cfg.get("ttl", 1))

    sd = SdAnnouncer(
        service_id=svc_id,
        instance_id=inst_id,
        tcp_port=int(tcp_port),
        event_port=int(event_port),
        udp_mode=int(udp_mode),
        mcast_group=mcast_group,
        flags=int(flags),
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
    for m in udp_msgs:
        sigs = sig_index.subset(m.signals)
        t = UdpEventPublisher(
            cat=cat,
            msg=m,
            sigs=sigs,
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
        f"tcp_listen={args.listen_ip}:{tcp_port} udp_events={[m.msg_id for m in udp_msgs]}"
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
