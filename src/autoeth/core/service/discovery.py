from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from autoeth.core.validation.frame import pack_header, unpack_header

# Reserve a msg_id for discovery announcements (must not collide with your catalog msg_ids).
SD_MSG_ID = 0xF0

# Payload (variable):
# u8 service_count
# repeated per service:
#   service_id(u16), instance_id(u16), iface_ver(u8), tcp_count(u8), event_count(u8)
#   tcp_count * tcp_port(u16)
#   event_count * (event_id(u16), udp_port(u16), mcast_group_ipv4(u32), ttl(u8), udp_mode(u8))
_SD_SVC = struct.Struct("!HHBBB")
_SD_EVENT = struct.Struct("!HHIBB")


@dataclass(frozen=True)
class SdEvent:
    event_id: int
    udp_port: int
    mcast_group: str  # dotted IPv4, "0.0.0.0" if not multicast
    udp_mode: int     # 0/1
    ttl: int


@dataclass(frozen=True)
class SdService:
    service_id: int
    instance_id: int
    iface_ver: int
    tcp_ports: tuple[int, ...]
    events: tuple[SdEvent, ...]


@dataclass(frozen=True)
class SdAnnounce:
    services: tuple[SdService, ...]


def _ip_to_u32(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _u32_to_ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", v & 0xFFFFFFFF))


def build_sd_datagram(*, seq: int, ann: SdAnnounce) -> bytes:
    services = ann.services or ()
    if len(services) > 255:
        raise ValueError("SD: too many services")

    pl = bytearray()
    pl.append(len(services) & 0xFF)

    for svc in services:
        tcp_ports = list(svc.tcp_ports or ())
        events = list(svc.events or ())
        if len(tcp_ports) > 255 or len(events) > 255:
            raise ValueError("SD: too many tcp ports or events for a service")

        pl.extend(
            _SD_SVC.pack(
                int(svc.service_id) & 0xFFFF,
                int(svc.instance_id) & 0xFFFF,
                int(svc.iface_ver) & 0xFF,
                len(tcp_ports) & 0xFF,
                len(events) & 0xFF,
            )
        )

        for p in tcp_ports:
            pl.extend(struct.pack("!H", int(p) & 0xFFFF))

        for ev in events:
            group_u32 = _ip_to_u32(ev.mcast_group) if ev.mcast_group else 0
            pl.extend(
                _SD_EVENT.pack(
                    int(ev.event_id) & 0xFFFF,
                    int(ev.udp_port) & 0xFFFF,
                    group_u32,
                    int(ev.ttl) & 0xFF,
                    int(ev.udp_mode) & 0xFF,
                )
            )

    return bytes([SD_MSG_ID]) + pack_header(seq=int(seq) & 0xFFFF) + bytes(pl)


def parse_sd_datagram(data: bytes) -> Optional[Tuple[int, SdAnnounce]]:
    """
    Returns (seq, SdAnnounce) if this is an SD datagram, else None.
    """
    if not data or len(data) < 1:
        return None
    if data[0] != SD_MSG_ID:
        return None

    hdr, pl = unpack_header(data[1:])
    if len(pl) < 1:
        return None

    svc_count = pl[0]
    idx = 1
    services: list[SdService] = []

    for _ in range(int(svc_count)):
        if len(pl) - idx < _SD_SVC.size:
            return None
        service_id, instance_id, iface_ver, tcp_count, event_count = _SD_SVC.unpack_from(pl, idx)
        idx += _SD_SVC.size

        tcp_ports: list[int] = []
        for _ in range(int(tcp_count)):
            if len(pl) - idx < 2:
                return None
            (port,) = struct.unpack_from("!H", pl, idx)
            idx += 2
            tcp_ports.append(int(port))

        events: list[SdEvent] = []
        for _ in range(int(event_count)):
            if len(pl) - idx < _SD_EVENT.size:
                return None
            event_id, udp_port, group_u32, ttl, udp_mode = _SD_EVENT.unpack_from(pl, idx)
            idx += _SD_EVENT.size
            events.append(
                SdEvent(
                    event_id=int(event_id),
                    udp_port=int(udp_port),
                    mcast_group=_u32_to_ip(group_u32) if group_u32 else "0.0.0.0",
                    udp_mode=int(udp_mode),
                    ttl=int(ttl),
                )
            )

        services.append(
            SdService(
                service_id=int(service_id),
                instance_id=int(instance_id),
                iface_ver=int(iface_ver),
                tcp_ports=tuple(tcp_ports),
                events=tuple(events),
            )
        )

    return int(hdr.seq), SdAnnounce(services=tuple(services))
