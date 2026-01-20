from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Dict, List

from .signal_catalog import SignalDef


MAGIC = b"AETH"
VERSION = 1

# Demo header:
# magic(4) version(u8) msg_type(u8) seq(u16) ts_ms(u32) payload_len(u16)
_HDR = struct.Struct("!4sBBHIH")  # network byte order


_TYPE_MAP = {
    "u8": ("!B", 0, 255),
    "u16": ("!H", 0, 65535),
    "u32": ("!I", 0, 4294967295),
    "i8": ("!b", -128, 127),
    "i16": ("!h", -32768, 32767),
    "i32": ("!i", -2147483648, 2147483647),
    "f32": ("!f", None, None),
}


@dataclass
class Frame:
    msg_type: int
    seq: int
    ts_ms: int
    raw_payload: bytes


def _encode_signal(sig: SignalDef, physical_value: float) -> bytes:
    fmt, mn, mx = _TYPE_MAP[sig.type]
    if sig.type == "f32":
        raw = float(physical_value)
    else:
        raw = int(round((physical_value - sig.offset) / sig.scale))
        if mn is not None and raw < mn:
            raw = mn
        if mx is not None and raw > mx:
            raw = mx
    return struct.pack(fmt, raw)


def _decode_signal(sig: SignalDef, raw_bytes: bytes) -> float:
    fmt, _, _ = _TYPE_MAP[sig.type]
    raw = struct.unpack(fmt, raw_bytes)[0]
    if sig.type == "f32":
        return float(raw)
    return float(raw) * sig.scale + sig.offset


def build_payload(catalog: List[SignalDef], values: Dict[str, float]) -> bytes:
    parts: List[bytes] = []
    for sig in catalog:
        v = float(values.get(sig.name, sig.default))
        parts.append(_encode_signal(sig, v))
    return b"".join(parts)


def parse_payload(catalog: List[SignalDef], payload: bytes) -> Dict[str, float]:
    out: Dict[str, float] = {}
    idx = 0
    for sig in catalog:
        fmt, _, _ = _TYPE_MAP[sig.type]
        size = struct.calcsize(fmt)
        raw = payload[idx : idx + size]
        if len(raw) != size:
            raise ValueError(f"payload too short for {sig.name} ({sig.type})")
        out[sig.name] = _decode_signal(sig, raw)
        idx += size
    return out


def encode_frame(msg_type: int, seq: int, payload: bytes) -> bytes:
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
    hdr = _HDR.pack(MAGIC, VERSION, msg_type & 0xFF, seq & 0xFFFF, ts_ms, len(payload) & 0xFFFF)
    return hdr + payload


def decode_frame(data: bytes) -> Frame:
    if len(data) < _HDR.size:
        raise ValueError("frame too short")
    magic, ver, msg_type, seq, ts_ms, plen = _HDR.unpack(data[: _HDR.size])
    if magic != MAGIC:
        raise ValueError("bad magic")
    if ver != VERSION:
        raise ValueError(f"unsupported version {ver}")
    payload = data[_HDR.size : _HDR.size + plen]
    if len(payload) != plen:
        raise ValueError("truncated payload")
    return Frame(msg_type=msg_type, seq=seq, ts_ms=ts_ms, raw_payload=payload)
