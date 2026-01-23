from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml


@dataclass(frozen=True)
class UdpTransportCfg:
    default_ttl: int = 1


@dataclass(frozen=True)
class TcpTransportCfg:
    listen_ip: str = "0.0.0.0"
    reconnect_ms: int = 500
    read_timeout_ms: int = 2000


@dataclass(frozen=True)
class MessageDef:
    name: str
    msg_id: int              # 0..255 (stored in codec header msg_type field)
    kind: str                # event | method_request | method_response
    transport: str           # udp | tcp

    # UDP fields (when transport == udp)
    mode: str = "unicast"    # unicast | multicast
    mcast_group: str = ""
    port: int = 30509
    period_ms: int = 100
    ttl: Optional[int] = None
    iface: Optional[str] = None  # optional Linux iface bind for TX

    # TCP fields (when transport == tcp)
    listen_ip: Optional[str] = None
    connect_ip: Optional[str] = None
    timeout_ms: int = 200

    # Signals included in payload
    signals: List[str] = None


@dataclass(frozen=True)
class MessageConfig:
    udp: UdpTransportCfg
    tcp: TcpTransportCfg
    messages: List[MessageDef]
    by_id: Dict[int, MessageDef]
    by_name: Dict[str, MessageDef]


def _as_int(v, field: str) -> int:
    try:
        return int(v)
    except Exception as e:
        raise ValueError(f"Invalid int for {field}: {v}") from e


def load_messages_config(path: str | Path) -> MessageConfig:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    transports = data.get("transports", {}) or {}
    udp_cfg = transports.get("udp", {}) or {}
    tcp_cfg = transports.get("tcp", {}) or {}

    udp = UdpTransportCfg(default_ttl=_as_int(udp_cfg.get("default_ttl", 1), "udp.default_ttl"))
    tcp = TcpTransportCfg(
        listen_ip=str(tcp_cfg.get("listen_ip", "0.0.0.0")),
        reconnect_ms=_as_int(tcp_cfg.get("reconnect_ms", 500), "tcp.reconnect_ms"),
        read_timeout_ms=_as_int(tcp_cfg.get("read_timeout_ms", 2000), "tcp.read_timeout_ms"),
    )

    msgs_in = data.get("messages", []) or []
    msgs: List[MessageDef] = []
    by_id: Dict[int, MessageDef] = {}
    by_name: Dict[str, MessageDef] = {}

    for m in msgs_in:
        name = str(m["name"])
        msg_id = _as_int(m["msg_id"], f"{name}.msg_id")
        if not (0 <= msg_id <= 255):
            raise ValueError(f"{name}.msg_id must be 0..255 (got {msg_id})")

        kind = str(m.get("kind", "event"))
        transport = str(m.get("transport", "udp"))

        signals = list(m.get("signals", []))
        if not signals:
            raise ValueError(f"{name}.signals must be a non-empty list")

        md = MessageDef(
            name=name,
            msg_id=msg_id,
            kind=kind,
            transport=transport,
            mode=str(m.get("mode", "unicast")),
            mcast_group=str(m.get("mcast_group", "")),
            port=_as_int(m.get("port", 30509), f"{name}.port"),
            period_ms=_as_int(m.get("period_ms", 100), f"{name}.period_ms"),
            ttl=_as_int(m.get("ttl", udp.default_ttl), f"{name}.ttl") if transport == "udp" else None,
            iface=m.get("iface", None),
            listen_ip=str(m.get("listen_ip", tcp.listen_ip)) if transport == "tcp" else None,
            connect_ip=m.get("connect_ip", None),
            timeout_ms=_as_int(m.get("timeout_ms", 200), f"{name}.timeout_ms"),
            signals=signals,
        )

        if msg_id in by_id:
            raise ValueError(f"Duplicate msg_id {msg_id} for {name} and {by_id[msg_id].name}")
        if name in by_name:
            raise ValueError(f"Duplicate message name: {name}")

        msgs.append(md)
        by_id[msg_id] = md
        by_name[name] = md

    return MessageConfig(udp=udp, tcp=tcp, messages=msgs, by_id=by_id, by_name=by_name)
