"""
AutoEth Terminal UI  (tui.py)
─────────────────────────────
Interactive menu to operate the node (server) or client from the terminal.
All interaction stays in the terminal; no GUI required.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

# ── Core imports ──────────────────────────────────────────────────────────────
from autoeth.core.config import (
    Catalog, MessageDef, SignalDef,
    load_catalog, resolve_someip, resolve_eventgroup_id, get_discovery_cfg,
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
    MT_NOTIFICATION, MT_REQUEST, MT_RESPONSE, MT_ERROR,
    RC_OK, RC_NOT_OK, build_message,
)
from autoeth.protocols.someip.stream import recv_someip, send_someip

# Re-use the application logic from node / client where possible
from autoeth.apps.node import (
    _init_state, _e2e_enabled, _build_tcp_routes, _build_udp_events,
    MethodRoute, EventRoute, SubscriberRegistry,
    UdpEventPublisher, SdAnnouncer, SdListener,
)
from autoeth.apps.client import (
    _find_method, _find_event,
    _subscribe_eventgroup,
)

import yaml
from pathlib import Path
from dataclasses import dataclass


# ─────────────────────────────────────────────────────────────────────────────
# Network configuration loader  (configs/network.yaml)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkConfig:
    # Server defaults
    server_listen_ip:        str = "0.0.0.0"
    server_announce_ip:      str = "127.0.0.1"
    server_multicast_iface:  str = "0.0.0.0"
    # Client defaults
    client_server_ip:        str = "127.0.0.1"
    client_multicast_iface:  str = "0.0.0.0"
    client_bind_ip:          str = "0.0.0.0"


def load_network_config(path: str = "configs/network.yaml") -> NetworkConfig:
    """
    Load network.yaml if it exists.
    Missing keys fall back to safe defaults so the file is fully optional.
    """
    p = Path(path)
    if not p.exists():
        return NetworkConfig()
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    srv = raw.get("server", {}) or {}
    cli = raw.get("client",  {}) or {}
    return NetworkConfig(
        server_listen_ip       = str(srv.get("listen_ip",        "0.0.0.0")),
        server_announce_ip     = str(srv.get("announce_ip",      "127.0.0.1")),
        server_multicast_iface = str(srv.get("multicast_iface_ip", "0.0.0.0")),
        client_server_ip       = str(cli.get("server_ip",        "127.0.0.1")),
        client_multicast_iface = str(cli.get("multicast_iface_ip", "0.0.0.0")),
        client_bind_ip         = str(cli.get("bind_ip",          "0.0.0.0")),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tiny terminal helpers
# ─────────────────────────────────────────────────────────────────────────────

_DIVIDER = "─" * 52

def _header(title: str) -> None:
    print(f"\n{_DIVIDER}")
    print(f"  {title}")
    print(_DIVIDER)

def _prompt(text: str = "> ") -> str:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        return "q"

def _ask_ip(label: str = "Server IP", default: str = "127.0.0.1") -> str:
    ans = _prompt(f"  {label} [{default}]: ")
    return ans if ans else default

def _ask_int(label: str, default: int) -> int:
    ans = _prompt(f"  {label} [{default}]: ")
    if not ans:
        return default
    try:
        return int(ans)
    except ValueError:
        print(f"  Invalid — using {default}")
        return default

def _ask_float(label: str, default: float) -> float:
    ans = _prompt(f"  {label} [{default}]: ")
    if not ans:
        return default
    try:
        return float(ans)
    except ValueError:
        print(f"  Invalid — using {default}")
        return default


# ─────────────────────────────────────────────────────────────────────────────
# Signal Database - Thread-safe storage for signal values
# ─────────────────────────────────────────────────────────────────────────────

class SignalDatabase:
    """Thread-safe database for signal values. Used by server to store/retrieve data."""
    
    def __init__(self, signals: List[SignalDef]) -> None:
        self._lock = threading.Lock()
        self._data: Dict[str, float] = {s.name: float(s.default) for s in signals}
        self._signals = {s.name: s for s in signals}
    
    def get(self, name: str) -> float:
        """Get a single signal value."""
        with self._lock:
            return self._data.get(name, 0.0)
    
    def get_all(self) -> Dict[str, float]:
        """Get a copy of all signal values."""
        with self._lock:
            return dict(self._data)
    
    def get_subset(self, names: List[str]) -> Dict[str, float]:
        """Get values for a subset of signals."""
        with self._lock:
            return {n: self._data.get(n, 0.0) for n in names}
    
    def set(self, name: str, value: float) -> None:
        """Set a single signal value."""
        with self._lock:
            if name in self._data:
                self._data[name] = float(value)
    
    def set_multiple(self, values: Dict[str, float]) -> None:
        """Set multiple signal values."""
        with self._lock:
            for name, value in values.items():
                if name in self._data:
                    self._data[name] = float(value)
    
    def get_signal_info(self, name: str) -> Optional[SignalDef]:
        """Get signal definition."""
        return self._signals.get(name)
    
    def list_signals(self) -> List[str]:
        """List all signal names."""
        with self._lock:
            return list(self._data.keys())


# ─────────────────────────────────────────────────────────────────────────────
# Custom TCP handler that uses the SignalDatabase
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_handler_with_db(
    conn: socket.socket, addr: tuple, *,
    cat: Catalog, routes: dict[tuple[int, int], MethodRoute],
    database: SignalDatabase,
    verbose: bool,
) -> None:
    """TCP handler that reads/writes from the SignalDatabase."""
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

        # Decode incoming values
        values = decode(sigs, pl_core)
        
        # Update database with received values (WRITE operation)
        database.set_multiple(values)
        
        if verbose:
            print(f"[tcp] rx {msg.name} sid=0x{hdr.service_id:04X} mid=0x{hdr.method_id:04X}")
            print(f"      write: {values}")

        # Read current values from database for response
        response_values = database.get_subset([s.name for s in sigs])
        
        if verbose:
            print(f"      response: {response_values}")

        rsp_pl = encode(sigs, response_values)
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


# ─────────────────────────────────────────────────────────────────────────────
# Custom UDP publisher that reads from SignalDatabase
# ─────────────────────────────────────────────────────────────────────────────

class UdpEventPublisherWithDb(threading.Thread):
    """Publishes UDP events using values from SignalDatabase."""

    def __init__(self, *, route: EventRoute,
                 database: SignalDatabase,
                 stop_evt: threading.Event,
                 registry: SubscriberRegistry,
                 verbose: bool) -> None:
        super().__init__(daemon=True)
        self.msg        = route.msg
        self.sigs       = route.sigs
        self.database   = database
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

            # Read current values from database
            sig_names = [s.name for s in self.sigs]
            vals = self.database.get_subset(sig_names)

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


# ─────────────────────────────────────────────────────────────────────────────
# Server infrastructure (shared by auto and manual server modes)
# ─────────────────────────────────────────────────────────────────────────────

class ServerContext:
    """
    Holds all running server threads and the signal database.
    Call start_infrastructure() once, then start/stop individual event publishers.
    """

    def __init__(
        self, *,
        cat: Catalog,
        sig_index: SignalIndex,
        listen_ip: str,
        announce_ip: str,
        iface_ip: str,
        sd_group: str, sd_port: int, sd_ttl: int, sd_iface: Optional[str],
        verbose: bool,
    ) -> None:
        self.cat          = cat
        self.sig_index    = sig_index
        self.listen_ip    = listen_ip
        self.announce_ip  = announce_ip
        self.iface_ip     = iface_ip
        self.sd_group     = sd_group
        self.sd_port      = sd_port
        self.sd_ttl       = sd_ttl
        self.sd_iface     = sd_iface
        self.verbose      = verbose

        # Signal database - the central data store
        self.database     = SignalDatabase(cat.signals)
        
        self.stop_evt     = threading.Event()
        self.registry     = SubscriberRegistry()

        self.routes       = _build_tcp_routes(cat, sig_index)
        self.udp_events   = _build_udp_events(cat, sig_index)

        self._tcp_servers: List[TcpServer]          = []
        self._sd_announcer: Optional[SdAnnouncer]   = None
        self._sd_listener:  Optional[SdListener]    = None
        # name → (running publisher, stop_event)
        self._publishers: Dict[str, Tuple[UdpEventPublisherWithDb, threading.Event]] = {}

    # ── Start TCP + SD (always on) ────────────────────────────────────────────
    def start_infrastructure(self) -> None:
        # TCP servers — one per unique port
        all_ports: set[int] = set()
        for r in self.routes.values():
            p = int((r.msg.tcp or {}).get("port", 0))
            if p:
                all_ports.add(p)

        def _handler(conn: socket.socket, addr: tuple) -> None:
            _tcp_handler_with_db(
                conn, addr,
                cat=self.cat, routes=self.routes,
                database=self.database,
                verbose=self.verbose,
            )

        for port in sorted(all_ports):
            srv = TcpServer(listen_ip=self.listen_ip, port=port, handler=_handler)
            srv.start()
            self._tcp_servers.append(srv)

        # SD Announcer
        self._sd_announcer = SdAnnouncer(
            cat=self.cat, routes=self.routes, udp_events=self.udp_events,
            announce_ip=self.announce_ip,
            sd_group=self.sd_group, sd_port=self.sd_port,
            sd_iface=self.sd_iface, sd_ttl=self.sd_ttl,
            stop_evt=self.stop_evt, verbose=self.verbose,
        )
        self._sd_announcer.start()

        # SD Listener (handles SubscribeEventgroup)
        self._sd_listener = SdListener(
            sd_group=self.sd_group, sd_port=self.sd_port,
            iface_ip=self.iface_ip,
            udp_events=self.udp_events,
            registry=self.registry,
            stop_evt=self.stop_evt,
            verbose=self.verbose,
        )
        self._sd_listener.start()

    # ── Event publisher control ───────────────────────────────────────────────
    def is_publishing(self, name: str) -> bool:
        return name in self._publishers

    def get_tx_count(self, name: str) -> int:
        """Get the TX count for a publisher."""
        if name in self._publishers:
            pub, _ = self._publishers[name]
            return pub.seq
        return 0

    def toggle_event(self, name: str) -> bool:
        """Toggle publisher. Returns new state (True = now publishing)."""
        if name in self._publishers:
            pub, stop = self._publishers.pop(name)
            stop.set()
            return False
        else:
            route    = self.udp_events[name]
            pub_stop = threading.Event()
            pub = UdpEventPublisherWithDb(
                route=route,
                database=self.database,
                stop_evt=pub_stop,
                registry=self.registry,
                verbose=self.verbose,
            )
            pub.start()
            self._publishers[name] = (pub, pub_stop)
            return True

    def start_all_events(self) -> None:
        for name in self.udp_events:
            if name not in self._publishers:
                self.toggle_event(name)

    # ── Database access ───────────────────────────────────────────────────────
    def get_database_values(self) -> Dict[str, float]:
        """Get all current values from the database."""
        return self.database.get_all()
    
    def set_database_value(self, name: str, value: float) -> None:
        """Set a value in the database."""
        self.database.set(name, value)

    # ── Full shutdown ─────────────────────────────────────────────────────────
    def stop_all(self) -> None:
        self.stop_evt.set()
        # Stop individual publishers
        for name in list(self._publishers.keys()):
            _, pub_stop = self._publishers.pop(name)
            pub_stop.set()
        for srv in self._tcp_servers:
            srv.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Client subscription thread
# ─────────────────────────────────────────────────────────────────────────────

class EventSubscription(threading.Thread):
    """Receives and prints UDP events until stop() is called."""

    def __init__(self, *, cat: Catalog, event: MessageDef,
                 sig_index: SignalIndex, bind_ip: str, iface_ip: str,
                 timeout_s: float = 1.0, verbose: bool = False,
                 quiet: bool = False) -> None:
        super().__init__(daemon=True)
        self.cat       = cat
        self.event     = event
        self.sig_index = sig_index
        self.bind_ip   = bind_ip
        self.iface_ip  = iface_ip
        self.verbose   = verbose
        self.quiet     = quiet  # If True, don't print each message
        self._stop     = threading.Event()

        udp_cfg    = event.udp or {}
        self.port  = int(udp_cfg.get("port", 0))
        self.mode  = str(udp_cfg.get("mode", "unicast"))
        self.group = str(udp_cfg.get("mcast_group", ""))
        self._sock: Optional[socket.socket] = None

        svc_id, iface_ver, eid = resolve_someip(cat, event)
        self.svc_id  = svc_id
        self.eid     = eid
        self.sigs    = sig_index.subset(event.signals)
        self.count   = 0
        self.last_values: Optional[Dict[str, float]] = None

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1.0)
        
        # For multicast, must bind to 0.0.0.0 (not interface IP) to receive group traffic
        if self.mode == "multicast":
            s.bind(("0.0.0.0", self.port))
        else:
            s.bind((self.bind_ip, self.port))
        self._sock = s

        if self.mode == "multicast" and self.group:
            udp_transport.join_multicast(s, self.group, iface_ip=self.iface_ip)

        from autoeth.protocols.someip.header import parse_message, MT_NOTIFICATION

        while not self._stop.is_set():
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                hdr, payload = parse_message(data)
            except Exception:
                continue

            if hdr.service_id != self.svc_id or hdr.method_id != self.eid:
                continue
            if hdr.msg_type != MT_NOTIFICATION:
                continue

            if _e2e_enabled(self.event):
                try:
                    payload, _ = e2e_unwrap(payload)
                except Exception:
                    continue

            try:
                vals = decode(self.sigs, payload)
            except Exception:
                continue

            self.count += 1
            self.last_values = vals

            if not self.quiet:
                print(
                    f"\n  [rx] {self.event.name}  #{self.count}"
                    f"  sid=0x{hdr.service_id:04X}  sess={hdr.session_id}"
                    f"\n       {vals}"
                    f"\n> ",
                    end="", flush=True,
                )

        try:
            s.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# SERVER menus
# ─────────────────────────────────────────────────────────────────────────────

def _server_config(cat: Catalog, net: NetworkConfig) -> dict:
    """Ask the user for server parameters, defaulting from network.yaml."""
    _header("Server — Configuration")
    sd_group, sd_port, sd_ttl, sd_iface = get_discovery_cfg(cat)
    listen_ip   = _ask_ip("Listen IP (TCP)",    net.server_listen_ip)
    announce_ip = _ask_ip("Announce IP (SD)",   net.server_announce_ip)
    iface_ip    = _ask_ip("Multicast iface IP", net.server_multicast_iface)
    return dict(
        listen_ip=listen_ip, announce_ip=announce_ip, iface_ip=iface_ip,
        sd_group=sd_group, sd_port=sd_port, sd_ttl=sd_ttl, sd_iface=sd_iface,
    )


def _show_database(ctx: ServerContext) -> None:
    """Display current database values."""
    print("\n  ── Signal Database ──")
    values = ctx.get_database_values()
    for name, value in sorted(values.items()):
        sig = ctx.database.get_signal_info(name)
        unit = sig.unit if sig else ""
        print(f"    {name:<25} = {value:>10.2f} {unit}")
    print()


def _edit_database(ctx: ServerContext) -> None:
    """Let user edit database values."""
    print("\n  ── Edit Signal Values ──")
    signals = ctx.database.list_signals()
    for idx, name in enumerate(signals, start=1):
        value = ctx.database.get(name)
        sig = ctx.database.get_signal_info(name)
        unit = sig.unit if sig else ""
        print(f"    [{idx}] {name:<22} = {value:>10.2f} {unit}")
    print("    [b] Back")
    
    cmd = _prompt("  Select signal to edit: ")
    if cmd.lower() == "b":
        return
    
    try:
        n = int(cmd)
        if 1 <= n <= len(signals):
            name = signals[n - 1]
            current = ctx.database.get(name)
            new_val = _ask_float(f"    New value for {name}", current)
            ctx.database.set(name, new_val)
            print(f"    {name} = {new_val}")
    except ValueError:
        print("  Invalid selection.")


def _server_auto(cat: Catalog, sig_index: SignalIndex, cfg: dict) -> None:
    """Start everything, print status, block until user presses q."""
    _header("Server — Automatic mode")
    ctx = ServerContext(cat=cat, sig_index=sig_index, verbose=False, **cfg)
    ctx.start_infrastructure()
    ctx.start_all_events()

    ports = sorted({int((r.msg.tcp or {}).get("port", 0)) for r in ctx.routes.values()})
    events = list(ctx.udp_events.keys())
    print(f"  TCP ports  : {ports}")
    print(f"  UDP events : {events}")
    print(f"  SD group   : {cfg['sd_group']}:{cfg['sd_port']}")
    print("\n  Commands:")
    print("    [s] Show status    [d] Show database")
    print("    [e] Edit values    [q] Quit\n")

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "q":
            break
        elif cmd.lower() == "s":
            print("\n  ── Status ──")
            for name in events:
                tx = ctx.get_tx_count(name)
                subs = len(ctx.registry.get_subscribers(
                    ctx.udp_events[name].svc_id,
                    ctx.udp_events[name].eventgroup_id
                ))
                print(f"    {name}: tx={tx}  subscribers={subs}")
            print()
        elif cmd.lower() == "d":
            _show_database(ctx)
        elif cmd.lower() == "e":
            _edit_database(ctx)

    ctx.stop_all()
    print("  Server stopped.")


def _server_manual(cat: Catalog, sig_index: SignalIndex, cfg: dict) -> None:
    """TCP + SD always on; user toggles individual UDP event publishers."""
    _header("Server — Manual mode")
    ctx = ServerContext(cat=cat, sig_index=sig_index, verbose=True, **cfg)
    ctx.start_infrastructure()

    ports  = sorted({int((r.msg.tcp or {}).get("port", 0)) for r in ctx.routes.values()})
    events = list(ctx.udp_events.keys())

    print(f"  TCP servers started on ports {ports}  [always on]")
    print(f"  SD Announcer + Listener running  [always on]")

    def _show_events() -> None:
        print()
        print("  Events:")
        for idx, name in enumerate(events, start=1):
            if name in ctx._publishers:
                tx = ctx.get_tx_count(name)
                state = f"ON  tx={tx}"
            else:
                state = "OFF"
            route  = ctx.udp_events[name]
            period = route.msg.period_ms or "?"
            mode   = str((route.msg.udp or {}).get("mode", "unicast"))
            subs   = len(ctx.registry.get_subscribers(route.svc_id, route.eventgroup_id))
            print(f"    [{idx}] {name:<22} [{state:<12}]  {period}ms  {mode}  subs={subs}")
        
        methods = [r.msg for r in ctx.routes.values()]
        print()
        print("  Methods (TCP):")
        for idx, m in enumerate(methods, start=len(events) + 1):
            port = int((m.tcp or {}).get("port", 0))
            print(f"    [{idx}] {m.name:<22} [TCP]  port={port}  (always on)")
        print()
        print("  [d] Database  [e] Edit values  [b] Back / stop server")

    _show_events()

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "b":
            break
        elif cmd.lower() == "d":
            _show_database(ctx)
            _show_events()
            continue
        elif cmd.lower() == "e":
            _edit_database(ctx)
            _show_events()
            continue
        
        try:
            n = int(cmd)
        except ValueError:
            _show_events()
            continue
        if 1 <= n <= len(events):
            name = events[n - 1]
            now  = ctx.toggle_event(name)
            print(f"  {name} → {'ON' if now else 'OFF'}")
        else:
            print("  Out of range.")
        _show_events()

    ctx.stop_all()
    print("  Server stopped.")


def menu_server(cat: Catalog, sig_index: SignalIndex, net: NetworkConfig) -> None:
    cfg = _server_config(cat, net)

    while True:
        _header("Server")
        print("  [1] Automatic   — start everything")
        print("  [2] Manual      — toggle individual events")
        print("  [b] Back")
        cmd = _prompt("> ")

        if cmd == "1":
            _server_auto(cat, sig_index, cfg)
        elif cmd == "2":
            _server_manual(cat, sig_index, cfg)
        elif cmd.lower() == "b":
            break


# ─────────────────────────────────────────────────────────────────────────────
# CLIENT menus
# ─────────────────────────────────────────────────────────────────────────────

class ClientContext:
    """Holds active subscriptions and SD connection info."""

    def __init__(self, *, cat: Catalog, sig_index: SignalIndex,
                 server_ip: str, iface_ip: str,
                 sd_group: str, sd_port: int,
                 bind_ip: str, verbose: bool) -> None:
        self.cat        = cat
        self.sig_index  = sig_index
        self.server_ip  = server_ip
        self.iface_ip   = iface_ip
        self.sd_group   = sd_group
        self.sd_port    = sd_port
        self.bind_ip    = bind_ip
        self.verbose    = verbose
        # name → EventSubscription
        self._subs: Dict[str, EventSubscription] = {}
        # Track method call counts
        self._method_calls: Dict[str, int] = {}

    def is_subscribed(self, name: str) -> bool:
        return name in self._subs

    def get_rx_count(self, name: str) -> int:
        """Get the RX count for a subscription."""
        sub = self._subs.get(name)
        return sub.count if sub else 0

    def get_last_values(self, name: str) -> Optional[Dict[str, float]]:
        """Get the last received values for a subscription."""
        sub = self._subs.get(name)
        return sub.last_values if sub else None

    def toggle_sub(self, event: MessageDef, quiet: bool = False) -> bool:
        name = event.name
        if name in self._subs:
            self._subs.pop(name).stop()
            # Send StopSubscribeEventgroup for unicast
            udp_cfg = event.udp or {}
            if str(udp_cfg.get("mode", "unicast")) != "multicast":
                self._send_subscribe(event, stop=True)
            return False
        else:
            # Subscribe via SD for unicast
            udp_cfg = event.udp or {}
            port    = int(udp_cfg.get("port", 0))
            mode    = str(udp_cfg.get("mode", "unicast"))
            if mode != "multicast":
                svc_id, _, _ = resolve_someip(self.cat, event)
                svc   = next((s for s in self.cat.services if s.service_id == svc_id), None)
                _subscribe_eventgroup(
                    sd_group=self.sd_group, sd_port=self.sd_port,
                    client_ip=self.bind_ip if self.bind_ip != "0.0.0.0" else "127.0.0.1",
                    client_udp_port=port,
                    svc_id=svc_id,
                    inst_id=svc.instance_id if svc else 0,
                    major=svc.major_version if svc else 1,
                    eventgroup_id=resolve_eventgroup_id(event),
                    timeout_s=2.0,
                    verbose=self.verbose,
                )
            sub = EventSubscription(
                cat=self.cat, event=event, sig_index=self.sig_index,
                bind_ip=self.bind_ip, iface_ip=self.iface_ip,
                verbose=self.verbose, quiet=quiet,
            )
            sub.start()
            self._subs[name] = sub
            return True

    def _send_subscribe(self, event: MessageDef, *, stop: bool) -> None:
        udp_cfg = event.udp or {}
        port    = int(udp_cfg.get("port", 0))
        svc_id, _, _ = resolve_someip(self.cat, event)
        svc   = next((s for s in self.cat.services if s.service_id == svc_id), None)
        egid  = resolve_eventgroup_id(event)

        entry = EventgroupEntry(
            entry_type=ET_SUBSCRIBE_EVENTGROUP,
            service_id=svc_id,
            instance_id=svc.instance_id if svc else 0,
            major_version=svc.major_version if svc else 1,
            eventgroup_id=egid,
            counter=0,
            ttl=TTL_STOP if stop else TTL_DEFAULT,
            options=[] if stop else [
                Ipv4EndpointOption(
                    address=self.bind_ip if self.bind_ip != "0.0.0.0" else "127.0.0.1",
                    port=port, l4_proto=L4_UDP,
                )
            ],
        )
        pkt = build_sd_message(session_id=1, entries=[entry])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(pkt, (self.sd_group, self.sd_port))
        except OSError:
            pass
        finally:
            sock.close()

    def stop_all(self) -> None:
        for name in list(self._subs.keys()):
            event = _find_event(self.cat, name)
            self.toggle_sub(event)


def _tcp_call_with_response(
    *, cat: Catalog, method: MessageDef, sig_index: SignalIndex,
    tcp_ip: str, tcp_port: Optional[int],
    values: Dict[str, float], timeout_ms: int, verbose: bool,
) -> Dict[str, float]:
    """Make a TCP call and return the response values."""
    from autoeth.core.transport.tcp import TcpClient
    
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
        print(f"[tcp] connect {tcp_ip}:{port} method={method.name}")
        print(f"      write: {values}")

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

    response_vals = decode(sigs, pl_core)
    if verbose:
        print(f"      response: {response_vals}")
    return response_vals


def _client_connect(cat: Catalog, net: NetworkConfig) -> Optional[ClientContext]:
    """Gather connection params. Returns ClientContext or None to go back."""
    _header("Client — Connection")
    sd_group, sd_port, _, _ = get_discovery_cfg(cat)

    print("  [1] Manual server IP")
    print("  [2] Auto-discover via SD")
    print("  [b] Back")
    cmd = _prompt("> ")

    if cmd.lower() == "b":
        return None

    iface_ip = _ask_ip("Multicast iface IP", net.client_multicast_iface)
    bind_ip  = _ask_ip("Local bind IP",      net.client_bind_ip)
    verbose  = _prompt("  Verbose? [y/N]: ").lower() == "y"

    if cmd == "2":
        print(f"  Listening for SD offer on {sd_group}:{sd_port} ...")
        try:
            from autoeth.apps.client import _discover, _print_sd_summary
            server_ip, sd_msg = _discover(
                group=sd_group, port=sd_port,
                bind_ip="0.0.0.0", iface_ip=iface_ip,
                timeout_s=3.0, verbose=verbose,
            )
            _print_sd_summary(sd_msg)
            print(f"  Discovered server at {server_ip}")
        except socket.timeout:
            print(f"  Discover timed out. Falling back to {net.client_server_ip}")
            server_ip = net.client_server_ip
    else:
        server_ip = _ask_ip("Server IP", net.client_server_ip)

    return ClientContext(
        cat=cat, sig_index=SignalIndex.from_signals(cat.signals),
        server_ip=server_ip, iface_ip=iface_ip,
        sd_group=sd_group, sd_port=sd_port,
        bind_ip=bind_ip, verbose=verbose,
    )


def _sig_index_for(cat: Catalog) -> SignalIndex:
    return SignalIndex.from_signals(cat.signals)


def _client_auto(ctx: ClientContext) -> None:
    """Subscribe all events + call all methods with defaults, then block."""
    _header("Client — Automatic mode")
    events  = [m for m in ctx.cat.messages if m.kind == "event"  and m.transport == "udp"]
    methods = [m for m in ctx.cat.messages if m.kind == "method" and m.transport == "tcp"]

    for event in events:
        ctx.toggle_sub(event)
        print(f"  Subscribed to {event.name}")

    for method in methods:
        values = {n: float(ctx.sig_index.by_name[n].default) for n in method.signals}
        print(f"  Calling {method.name} with defaults {values}")
        try:
            response = _tcp_call_with_response(
                cat=ctx.cat, method=method, sig_index=ctx.sig_index,
                tcp_ip=ctx.server_ip, tcp_port=None,
                values=values, timeout_ms=500, verbose=ctx.verbose,
            )
            ctx._method_calls[method.name] = ctx._method_calls.get(method.name, 0) + 1
            print(f"    Response: {response}")
        except (SystemExit, TimeoutError, OSError, ConnectionRefusedError) as e:
            print(f"  TCP error ({method.name}): {e}")

    print("\n  Commands:")
    print("    [s] Show status    [q] Quit\n")

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "q":
            break
        elif cmd.lower() == "s":
            print("\n  ── Status ──")
            for event in events:
                rx = ctx.get_rx_count(event.name)
                last = ctx.get_last_values(event.name)
                print(f"    {event.name}: rx={rx}")
                if last:
                    print(f"       last: {last}")
            print()

    ctx.stop_all()
    print("  Client stopped.")


def _client_manual(ctx: ClientContext) -> None:
    """Interactive: toggle subscriptions, one-shot method calls."""
    _header("Client — Manual mode")

    events  = [m for m in ctx.cat.messages if m.kind == "event"  and m.transport == "udp"]
    methods = [m for m in ctx.cat.messages if m.kind == "method" and m.transport == "tcp"]

    def _show() -> None:
        print()
        print("  Events:")
        for idx, ev in enumerate(events, start=1):
            if ctx.is_subscribed(ev.name):
                rx = ctx.get_rx_count(ev.name)
                state = f"ON  rx={rx}"
            else:
                state = "OFF"
            udp    = ev.udp or {}
            mode   = str(udp.get("mode", "unicast"))
            egid   = resolve_eventgroup_id(ev)
            period = ev.period_ms or "?"
            print(f"    [{idx}] {ev.name:<22} [{state:<12}]  {mode}  egid=0x{egid:04X}  {period}ms")

        print()
        print("  Methods (one-shot):")
        base = len(events)
        for idx, m in enumerate(methods, start=base + 1):
            port = int((m.tcp or {}).get("port", 0))
            calls = ctx._method_calls.get(m.name, 0)
            call_info = f"calls={calls}" if calls > 0 else ""
            print(f"    [{idx}] {m.name:<22} [TCP]  port={port}  {call_info}")

        print()
        print("  [s] Show values  [b] Back (stops all subscriptions)")

    _show()

    while True:
        cmd = _prompt("> ")
        if cmd.lower() in ("b", "q"):
            break

        if cmd.lower() == "s":
            print("\n  ── Current Values ──")
            for ev in events:
                if ctx.is_subscribed(ev.name):
                    rx = ctx.get_rx_count(ev.name)
                    last = ctx.get_last_values(ev.name)
                    print(f"    {ev.name}: rx={rx}")
                    if last:
                        for k, v in last.items():
                            sig = ctx.sig_index.by_name.get(k)
                            unit = sig.unit if sig else ""
                            print(f"       {k:<22} = {v:>10.2f} {unit}")
            print()
            _show()
            continue

        try:
            n = int(cmd)
        except ValueError:
            _show()
            continue

        base = len(events)

        if 1 <= n <= base:
            event = events[n - 1]
            now   = ctx.toggle_sub(event, quiet=False)  # Show messages in manual mode
            print(f"  {event.name} → {'SUBSCRIBED' if now else 'UNSUBSCRIBED'}")
            _show()

        elif base + 1 <= n <= base + len(methods):
            method = methods[n - base - 1]
            print(f"  Calling {method.name}")
            values: Dict[str, float] = {}
            for sig_name in method.signals:
                default = float(ctx.sig_index.by_name[sig_name].default)
                values[sig_name] = _ask_float(f"    {sig_name}", default)

            try:
                response = _tcp_call_with_response(
                    cat=ctx.cat, method=method, sig_index=ctx.sig_index,
                    tcp_ip=ctx.server_ip, tcp_port=None,
                    values=values, timeout_ms=500, verbose=ctx.verbose,
                )
                ctx._method_calls[method.name] = ctx._method_calls.get(method.name, 0) + 1
                print(f"    Response: {response}")
            except (SystemExit, TimeoutError, OSError, ConnectionRefusedError) as e:
                print(f"  TCP error ({method.name}): {e}")
            _show()
        else:
            print("  Out of range.")
            _show()

    ctx.stop_all()
    print("  All subscriptions stopped.")


def menu_client(cat: Catalog, sig_index: SignalIndex, net: NetworkConfig) -> None:
    ctx = _client_connect(cat, net)
    if ctx is None:
        return

    while True:
        _header("Client")
        print("  [1] Automatic  — subscribe all events + call all methods")
        print("  [2] Manual     — toggle subscriptions, call methods one-shot")
        print("  [b] Back")
        cmd = _prompt("> ")

        if cmd == "1":
            _client_auto(ctx)
        elif cmd == "2":
            _client_manual(ctx)
        elif cmd.lower() == "b":
            break


# ─────────────────────────────────────────────────────────────────────────────
# Top-level menu
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Terminal UI")
    ap.add_argument("--catalog", default="configs/catalog.yaml")
    ap.add_argument("--network", default="configs/network.yaml")
    args = ap.parse_args()

    cat       = load_catalog(args.catalog)
    sig_index = SignalIndex.from_signals(cat.signals)
    net       = load_network_config(args.network)

    while True:
        _header("AutoEth")
        print("  [1] Server")
        print("  [2] Client")
        print("  [q] Quit")
        cmd = _prompt("> ")

        if cmd == "1":
            menu_server(cat, sig_index, net)
        elif cmd == "2":
            menu_client(cat, sig_index, net)
        elif cmd.lower() == "q":
            print("  Bye.")
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
