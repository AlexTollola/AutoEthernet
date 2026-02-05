from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from autoeth.core.validation.frame import pack_header, unpack_header

# Reserve a msg_id for discovery announcements (must not collide with your catalog msg_ids).
SD_MSG_ID = 0xF0

# Payload (16 bytes):
# service_id(u16), instance_id(u16), tcp_port(u16), event_port(u16),
# mcast_group_ipv4(u32), udp_mode(u16), flags(u16)
# udp_mode: 0=unicast, 1=multicast
# flags: bit0=event_e2e_enabled, bit1=method_e2e_enabled
_SD_PL = struct.Struct("!HHHHIHH")


@dataclass(frozen=True)
class SdAnnounce:
    service_id: int
    instance_id: int
    tcp_port: int
    event_port: int
    mcast_group: str  # dotted IPv4, "0.0.0.0" if not multicast
    udp_mode: int     # 0/1
    flags: int        # bitfield


def _ip_to_u32(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _u32_to_ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", v & 0xFFFFFFFF))


def build_sd_datagram(*, seq: int, ann: SdAnnounce) -> bytes:
    group_u32 = _ip_to_u32(ann.mcast_group) if ann.mcast_group else 0
    pl = _SD_PL.pack(
        int(ann.service_id) & 0xFFFF,
        int(ann.instance_id) & 0xFFFF,
        int(ann.tcp_port) & 0xFFFF,
        int(ann.event_port) & 0xFFFF,
        group_u32,
        int(ann.udp_mode) & 0xFFFF,
        int(ann.flags) & 0xFFFF,
    )
    return bytes([SD_MSG_ID]) + pack_header(seq=int(seq) & 0xFFFF) + pl


def parse_sd_datagram(data: bytes) -> Optional[Tuple[int, SdAnnounce]]:
    """
    Returns (seq, SdAnnounce) if this is an SD datagram, else None.
    """
    if not data or len(data) < 1:
        return None
    if data[0] != SD_MSG_ID:
        return None

    hdr, pl = unpack_header(data[1:])
    if len(pl) != _SD_PL.size:
        return None

    service_id, instance_id, tcp_port, event_port, group_u32, udp_mode, flags = _SD_PL.unpack(pl)
    ann = SdAnnounce(
        service_id=service_id,
        instance_id=instance_id,
        tcp_port=tcp_port,
        event_port=event_port,
        mcast_group=_u32_to_ip(group_u32) if group_u32 else "0.0.0.0",
        udp_mode=udp_mode,
        flags=flags,
    )
    return int(hdr.seq), ann
