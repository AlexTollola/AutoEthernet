from __future__ import annotations

import struct
from typing import Tuple

_TRAILER = struct.Struct("!HH")  # counter_u16, crc_u16


def crc16_ccitt_false(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE: poly=0x1021 init=0xFFFF refin/out=False xorout=0x0000."""
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def wrap(payload: bytes, *, counter: int) -> bytes:
    """Append (counter, crc) trailer. CRC covers payload + counter (excludes CRC field)."""
    c = int(counter) & 0xFFFF
    c_bytes = struct.pack("!H", c)
    data_no_crc = (payload or b"") + c_bytes
    crc = crc16_ccitt_false(data_no_crc)
    return data_no_crc + struct.pack("!H", crc)


def unwrap(payload: bytes) -> Tuple[bytes, int]:
    """Verify and strip trailer. Returns (payload_without_trailer, counter)."""
    if payload is None or len(payload) < _TRAILER.size:
        raise ValueError("E2E: payload too short for trailer")

    counter, rx_crc = _TRAILER.unpack_from(payload, len(payload) - _TRAILER.size)

    data_no_crc = payload[:-2]  # includes counter, excludes crc
    calc = crc16_ccitt_false(data_no_crc)
    if calc != rx_crc:
        raise ValueError(f"E2E: CRC mismatch calc=0x{calc:04X} rx=0x{rx_crc:04X}")

    return payload[:-4], int(counter)
