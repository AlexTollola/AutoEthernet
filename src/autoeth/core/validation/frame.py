from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple

PROTO_VER = 1

_HDR = struct.Struct("!BH")  # u8 proto_ver, u16 seq (network order)


@dataclass(frozen=True)
class FrameHeader:
    proto_ver: int
    seq: int


def pack_header(seq: int, proto_ver: int = PROTO_VER) -> bytes:
    return _HDR.pack(int(proto_ver) & 0xFF, int(seq) & 0xFFFF)


def unpack_header(data: bytes) -> Tuple[FrameHeader, bytes]:
    if len(data) < _HDR.size:
        raise ValueError("frame too short for header")
    proto_ver, seq = _HDR.unpack_from(data, 0)
    return FrameHeader(proto_ver=proto_ver, seq=seq), data[_HDR.size:]


def header_size() -> int:
    return _HDR.size
