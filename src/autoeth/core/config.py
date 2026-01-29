from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml


def _as_int(v: Any, field: str) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise TypeError(f"{field}: expected int or str, got {type(v).__name__}")


@dataclass(frozen=True)
class SignalDef:
    name: str
    type: str  # u8/u16/u32/i8/i16/i32
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""
    default: float = 0.0


@dataclass(frozen=True)
class ServiceDef:
    name: str
    service_id: int
    instance_id: int
    interface_version: int = 1
    major_version: int = 1
    minor_version: int = 0


@dataclass(frozen=True)
class MessageDef:
    name: str
    msg_id: int  # 0..255 internal message index
    kind: str  # event | method
    transport: str  # udp | tcp
    signals: List[str]

    period_ms: Optional[int] = None
    udp: Optional[Dict[str, Any]] = None
    tcp: Optional[Dict[str, Any]] = None
    someip: Optional[Dict[str, Any]] = None

    e2e: Optional[Dict[str, Any]] = None



@dataclass(frozen=True)
class Catalog:
    version: int
    signals: List[SignalDef]
    services: List[ServiceDef]
    messages: List[MessageDef]

    def signals_by_name(self) -> Dict[str, SignalDef]:
        return {s.name: s for s in self.signals}

    def messages_by_name(self) -> Dict[str, MessageDef]:
        return {m.name: m for m in self.messages}

    def messages_by_id(self) -> Dict[int, MessageDef]:
        return {m.msg_id: m for m in self.messages}

    def validate(self) -> None:
        # signals unique
        sig_names = [s.name for s in self.signals]
        if len(sig_names) != len(set(sig_names)):
            raise ValueError("signals: duplicate names")

        sig_set: Set[str] = set(sig_names)

        # messages unique
        msg_ids = [m.msg_id for m in self.messages]
        if len(msg_ids) != len(set(msg_ids)):
            raise ValueError("messages: duplicate msg_id")

        msg_names = [m.name for m in self.messages]
        if len(msg_names) != len(set(msg_names)):
            raise ValueError("messages: duplicate name")

        allowed_types = {"u8", "i8", "u16", "i16", "u32", "i32"}
        for s in self.signals:
            if s.type not in allowed_types:
                raise ValueError(f"signal {s.name}: unsupported type {s.type}")
            if s.scale == 0:
                raise ValueError(f"signal {s.name}: scale must not be 0")

        allowed_kinds = {"event", "method"}
        allowed_transports = {"udp", "tcp"}

        for m in self.messages:
            if not (0 <= m.msg_id <= 255):
                raise ValueError(f"{m.name}.msg_id must be 0..255")
            if m.kind not in allowed_kinds:
                raise ValueError(f"{m.name}.kind invalid: {m.kind}")
            if m.transport not in allowed_transports:
                raise ValueError(f"{m.name}.transport invalid: {m.transport}")
            if not m.signals:
                raise ValueError(f"{m.name}.signals must not be empty")

            missing = [n for n in m.signals if n not in sig_set]
            if missing:
                raise ValueError(f"{m.name}.signals missing: {missing}")

            if m.transport == "udp":
                if not m.udp:
                    raise ValueError(f"{m.name}: udp block missing")
                if "port" not in m.udp:
                    raise ValueError(f"{m.name}.udp.port missing")
            if m.transport == "tcp":
                if not m.tcp:
                    raise ValueError(f"{m.name}: tcp block missing")
                if "port" not in m.tcp:
                    raise ValueError(f"{m.name}.tcp.port missing")

            if m.kind == "event":
                if m.transport == "tcp":
                    raise ValueError(f"{m.name}: event over tcp not supported in this project")
                if m.period_ms is None:
                    raise ValueError(f"{m.name}.period_ms missing for event")
            if m.kind == "method":
                if m.transport == "udp":
                    raise ValueError(f"{m.name}: method over udp not supported in this project")
                
            e2e = m.e2e or {}
            if e2e.get("enabled", False):
                algo = str(e2e.get("crc16", "ccitt-false"))
                if algo != "ccitt-false":
                    raise ValueError(f"{m.name}.e2e.crc16 must be 'ccitt-false'")

        # services unique name
        svc_names = [s.name for s in self.services]
        if len(svc_names) != len(set(svc_names)):
            raise ValueError("services: duplicate names")


def load_catalog(path: str | Path) -> Catalog:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    version = int(raw.get("version", 1))

    signals = [
        SignalDef(
            name=str(s["name"]),
            type=str(s["type"]),
            scale=float(s.get("scale", 1.0)),
            offset=float(s.get("offset", 0.0)),
            unit=str(s.get("unit", "")),
            default=float(s.get("default", 0.0)),
        )
        for s in raw.get("signals", [])
    ]

    services = [
        ServiceDef(
            name=str(sv["name"]),
            service_id=_as_int(sv["service_id"], f"{sv.get('name','service')}.service_id"),
            instance_id=_as_int(sv["instance_id"], f"{sv.get('name','service')}.instance_id"),
            interface_version=int(sv.get("interface_version", 1)),
            major_version=int(sv.get("major_version", 1)),
            minor_version=int(sv.get("minor_version", 0)),
        )
        for sv in raw.get("services", [])
    ]

    messages = [
        MessageDef(
            name=str(m["name"]),
            msg_id=_as_int(m["msg_id"], f"{m.get('name','message')}.msg_id"),
            kind=str(m["kind"]),
            transport=str(m["transport"]),
            period_ms=int(m["period_ms"]) if "period_ms" in m else None,
            udp=m.get("udp"),
            tcp=m.get("tcp"),
            someip=m.get("someip"),
            signals=[str(x) for x in m.get("signals", [])],
            e2e=m.get("e2e"),
        )
        for m in raw.get("messages", [])
    ]

    cat = Catalog(version=version, signals=signals, services=services, messages=messages)
    cat.validate()
    return cat
