from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Tuple

_HDR = struct.Struct("!HHIHHBBBB")

# Message types (subset)
MT_REQUEST = 0x00
MT_REQUEST_NO_RETURN = 0x01
MT_NOTIFICATION = 0x02
MT_RESPONSE = 0x80
MT_ERROR = 0x81

# Return codes (subset)
RC_OK = 0x00
RC_NOT_OK = 0x01

PROTO_VER = 0x01


@dataclass(frozen=True)
class SomeIpHeader:
    service_id: int
    method_id: int
    length: int
    client_id: int
    session_id: int
    proto_ver: int
    iface_ver: int
    msg_type: int
    return_code: int

    def pack(self) -> bytes:
        return _HDR.pack(
            self.service_id & 0xFFFF,
            self.method_id & 0xFFFF,
            self.length & 0xFFFFFFFF,
            self.client_id & 0xFFFF,
            self.session_id & 0xFFFF,
            self.proto_ver & 0xFF,
            self.iface_ver & 0xFF,
            self.msg_type & 0xFF,
            self.return_code & 0xFF,
        )

    @staticmethod
    def unpack(data: bytes) -> "SomeIpHeader":
        if len(data) < _HDR.size:
            raise ValueError("SOME/IP header too short")
        fields = _HDR.unpack_from(data, 0)
        return SomeIpHeader(*fields)


def build_message(
    *,
    service_id: int,
    method_id: int,
    client_id: int,
    session_id: int,
    iface_ver: int,
    msg_type: int,
    payload: bytes,
    return_code: int = RC_OK,
) -> bytes:
    payload = payload or b""
    length = 8 + len(payload)  # per SOME/IP spec: length excludes first 8 bytes
    hdr = SomeIpHeader(
        service_id=service_id,
        method_id=method_id,
        length=length,
        client_id=client_id,
        session_id=session_id,
        proto_ver=PROTO_VER,
        iface_ver=iface_ver,
        msg_type=msg_type,
        return_code=return_code,
    )
    return hdr.pack() + payload


def parse_message(data: bytes) -> Tuple[SomeIpHeader, bytes]:
    hdr = SomeIpHeader.unpack(data)
    payload = data[_HDR.size:]
    return hdr, payload

