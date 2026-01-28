from __future__ import annotations

import struct
from typing import Dict, List

from autoeth.core.config import SignalDef


_FMT = {
    "u8":  ("!B", 0, 255),
    "i8":  ("!b", -128, 127),
    "u16": ("!H", 0, 65535),
    "i16": ("!h", -32768, 32767),
    "u32": ("!I", 0, 4294967295),
    "i32": ("!i", -2147483648, 2147483647),
}


def encode(signals: List[SignalDef], values: Dict[str, float]) -> bytes:
    """Encode by packing signals sequentially (fixed order)."""
    out = bytearray()
    for s in signals:
        fmt, lo, hi = _fmt(s.type)
        phys = float(values.get(s.name, s.default))
        raw = int(round((phys - float(s.offset)) / float(s.scale)))
        if raw < lo:
            raw = lo
        if raw > hi:
            raw = hi
        out += struct.pack(fmt, raw)
    return bytes(out)


def decode(signals: List[SignalDef], payload: bytes) -> Dict[str, float]:
    """Decode sequentially-packed signal payload."""
    res: Dict[str, float] = {}
    off = 0
    for s in signals:
        fmt, _, _ = _fmt(s.type)
        n = struct.calcsize(fmt)
        if off + n > len(payload):
            raise ValueError("payload too short for signal list")
        (raw,) = struct.unpack_from(fmt, payload, off)
        off += n
        phys = (float(raw) * float(s.scale)) + float(s.offset)
        res[s.name] = float(phys)
    return res


def _fmt(sig_type: str):
    if sig_type not in _FMT:
        raise ValueError(f"unsupported signal type: {sig_type}")
    return _FMT[sig_type]

