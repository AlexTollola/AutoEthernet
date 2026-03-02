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
    _tcp_handler, UdpEventPublisher, SdAnnouncer, SdListener,
)
from autoeth.apps.client import (
    _find_method, _find_event,
    _tcp_call, _subscribe_eventgroup,
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
# Server infrastructure (shared by auto and manual server modes)
# ─────────────────────────────────────────────────────────────────────────────

class ServerContext:
    """
    Holds all running server threads.
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

        self.state: Dict[str, float]     = _init_state(cat.signals)
        self.state_lock   = threading.Lock()
        self.stop_evt     = threading.Event()
        self.registry     = SubscriberRegistry()

        self.routes       = _build_tcp_routes(cat, sig_index)
        self.udp_events   = _build_udp_events(cat, sig_index)

        self._tcp_servers: List[TcpServer]          = []
        self._sd_announcer: Optional[SdAnnouncer]   = None
        self._sd_listener:  Optional[SdListener]    = None
        # name → running UdpEventPublisher
        self._publishers: Dict[str, UdpEventPublisher] = {}

    # ── Start TCP + SD (always on) ────────────────────────────────────────────
    def start_infrastructure(self) -> None:
        # TCP servers — one per unique port
        all_ports: set[int] = set()
        for r in self.routes.values():
            p = int((r.msg.tcp or {}).get("port", 0))
            if p:
                all_ports.add(p)

        def _handler(conn: socket.socket, addr: tuple) -> None:
            _tcp_handler(
                conn, addr,
                cat=self.cat, routes=self.routes,
                state=self.state, state_lock=self.state_lock,
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

    def start_event(self, name: str) -> None:
        if name in self._publishers:
            return
        route = self.udp_events[name]
        t = UdpEventPublisher(
            route=route,
            state=self.state, state_lock=self.state_lock,
            stop_evt=self.stop_evt,
            registry=self.registry,
            dest_ip="127.0.0.1",
            verbose=self.verbose,
        )
        t.start()
        self._publishers[name] = t

    def stop_event(self, name: str) -> None:
        t = self._publishers.pop(name, None)
        # We can't stop a single thread cleanly without its own stop event,
        # so we mark it by replacing with a fresh one that never starts.
        # The running thread will complete its next sleep and check stop_evt,
        # which we signal here just for this thread using a private stop event.
        # Instead: give each publisher its own stop event.
        # (See _make_publisher for the per-thread approach.)
        pass  # handled by _make_publisher below

    def _make_publisher(self, name: str) -> None:
        """Create publisher with its own stop event for individual toggling."""
        if name in self._publishers:
            return
        route       = self.udp_events[name]
        pub_stop    = threading.Event()
        t = _IndividualPublisher(
            route=route,
            state=self.state, state_lock=self.state_lock,
            stop_evt=pub_stop,
            global_stop=self.stop_evt,
            registry=self.registry,
            dest_ip="127.0.0.1",
            verbose=self.verbose,
        )
        t.start()
        self._publishers[name] = (t, pub_stop)   # type: ignore[assignment]

    def toggle_event(self, name: str) -> bool:
        """Toggle publisher. Returns new state (True = now publishing)."""
        if name in self._publishers:
            t, stop = self._publishers.pop(name)  # type: ignore[misc]
            stop.set()
            return False
        else:
            route    = self.udp_events[name]
            pub_stop = threading.Event()
            t = _IndividualPublisher(
                route=route,
                state=self.state, state_lock=self.state_lock,
                stop_evt=pub_stop,
                global_stop=self.stop_evt,
                registry=self.registry,
                dest_ip="127.0.0.1",
                verbose=self.verbose,
            )
            t.start()
            self._publishers[name] = (t, pub_stop)  # type: ignore[assignment]
            return True

    def start_all_events(self) -> None:
        for name in self.udp_events:
            if name not in self._publishers:
                self.toggle_event(name)

    # ── Full shutdown ─────────────────────────────────────────────────────────
    def stop_all(self) -> None:
        self.stop_evt.set()
        # Stop individual publishers
        for name in list(self._publishers.keys()):
            _, pub_stop = self._publishers.pop(name)  # type: ignore[misc]
            pub_stop.set()
        for srv in self._tcp_servers:
            srv.stop()


class _IndividualPublisher(threading.Thread):
    """UdpEventPublisher that has its own stop event so it can be toggled."""

    def __init__(self, *, route: EventRoute,
                 state, state_lock, stop_evt: threading.Event,
                 global_stop: threading.Event,
                 registry: SubscriberRegistry,
                 dest_ip: str, verbose: bool) -> None:
        super().__init__(daemon=True)
        self._inner = UdpEventPublisher(
            route=route, state=state, state_lock=state_lock,
            stop_evt=stop_evt, registry=registry,
            dest_ip=dest_ip, verbose=verbose,
        )
        self._inner.stop_evt = stop_evt
        self._global_stop   = global_stop

    def run(self) -> None:
        self._inner.run()


# ─────────────────────────────────────────────────────────────────────────────
# Client subscription thread
# ─────────────────────────────────────────────────────────────────────────────

class EventSubscription(threading.Thread):
    """Receives and prints UDP events until stop() is called."""

    def __init__(self, *, cat: Catalog, event: MessageDef,
                 sig_index: SignalIndex, bind_ip: str, iface_ip: str,
                 timeout_s: float = 1.0, verbose: bool = False) -> None:
        super().__init__(daemon=True)
        self.cat       = cat
        self.event     = event
        self.sig_index = sig_index
        self.bind_ip   = bind_ip
        self.iface_ip  = iface_ip
        self.verbose   = verbose
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
            print(
                f"\n  [rx] {self.event.name}  #{self.count}"
                f"  sid=0x{hdr.service_id:04X}  sess={hdr.session_id}"
                f"  {vals}"
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
    print("\n  Running — press [q] + Enter to stop.\n")

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "q":
            break

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
        for idx, name in enumerate(events, start=1):
            state  = "ON " if name in ctx._publishers else "OFF"
            route  = ctx.udp_events[name]
            period = route.msg.period_ms or "?"
            mode   = str((route.msg.udp or {}).get("mode", "unicast"))
            print(f"  [{idx}] {name:<28} [{state}]  {period}ms  {mode}")
        methods = [r.msg for r in ctx.routes.values()]
        print()
        for idx, m in enumerate(methods, start=len(events) + 1):
            port = int((m.tcp or {}).get("port", 0))
            print(f"  [{idx}] {m.name:<28} [TCP]  port={port}  (always on)")
        print()
        print("  [b] Back / stop server")

    _show_events()

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "b":
            break
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

    def is_subscribed(self, name: str) -> bool:
        return name in self._subs

    def toggle_sub(self, event: MessageDef) -> bool:
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
                verbose=self.verbose,
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
            print("  Discover timed out. Falling back to 127.0.0.1")
            server_ip = "127.0.0.1"
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
            _tcp_call(
                cat=ctx.cat, method=method, sig_index=ctx.sig_index,
                tcp_ip=ctx.server_ip, tcp_port=None,
                values=values, timeout_ms=500, verbose=ctx.verbose,
            )
        except SystemExit as e:
            print(f"  Error: {e}")

    print("\n  Receiving — press [q] + Enter to stop.\n")
    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "q":
            break

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
            state  = "ON " if ctx.is_subscribed(ev.name) else "OFF"
            udp    = ev.udp or {}
            mode   = str(udp.get("mode", "unicast"))
            egid   = resolve_eventgroup_id(ev)
            period = ev.period_ms or "?"
            print(f"  [{idx}] {ev.name:<28} [{state}]  {mode}  egid=0x{egid:04X}  {period}ms")

        print()
        print("  Methods (one-shot):")
        base = len(events)
        for idx, m in enumerate(methods, start=base + 1):
            port = int((m.tcp or {}).get("port", 0))
            sigs = ", ".join(m.signals)
            print(f"  [{idx}] {m.name:<28} [TCP]  port={port}  signals=[{sigs}]")

        print()
        print("  [b] Back (stops all subscriptions)")

    _show()

    while True:
        cmd = _prompt("> ")
        if cmd.lower() == "b":
            break

        try:
            n = int(cmd)
        except ValueError:
            _show()
            continue

        base = len(events)

        if 1 <= n <= base:
            event = events[n - 1]
            now   = ctx.toggle_sub(event)
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
                _tcp_call(
                    cat=ctx.cat, method=method, sig_index=ctx.sig_index,
                    tcp_ip=ctx.server_ip, tcp_port=None,
                    values=values, timeout_ms=500, verbose=ctx.verbose,
                )
            except SystemExit as e:
                print(f"  Error: {e}")
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
