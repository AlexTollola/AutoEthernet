from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from autoeth.protocols.someip.header import build_message, parse_message, MT_NOTIFICATION

# ── SOME/IP-SD wire constants ─────────────────────────────────────────────────

SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID  = 0x8100
SD_IFACE_VER  = 0x01
SD_CLIENT_ID  = 0x0000

SD_FLAG_REBOOT  = 0x80
SD_FLAG_UNICAST = 0x40

# Entry types
ET_FIND_SERVICE     = 0x00
ET_OFFER_SERVICE    = 0x01
ET_SUBSCRIBE_EG     = 0x06
ET_SUBSCRIBE_EG_ACK = 0x07

# Option types
OT_IPV4_ENDPOINT  = 0x04
OT_IPV4_MULTICAST = 0x24

# L4 protocol codes used inside options
L4_TCP = 0x06
L4_UDP = 0x11

ENTRY_SZ    = 16   # all SD entry types are exactly 16 bytes
OPT_IPV4_SZ = 12   # IPv4 endpoint / multicast options are 12 bytes each


# ── High-level dataclasses ────────────────────────────────────────────────────

@dataclass(frozen=True)
class SdEvent:
    event_id: int
    udp_port: int
    mcast_group: str    # dotted-decimal IPv4; "0.0.0.0" means unicast
    udp_mode: int       # 1 = multicast, 0 = unicast
    ttl: int
    eventgroup_id: int = 0   # SOME/IP-SD eventgroup ID (equals event_id in simple setups)


@dataclass(frozen=True)
class SdService:
    service_id: int
    instance_id: int
    iface_ver: int
    tcp_ports: tuple        # tuple[int, ...]
    events: tuple           # tuple[SdEvent, ...]
    major_version: int = 1
    minor_version: int = 0
    server_ip: str = "0.0.0.0"   # node IP embedded in IPv4 Endpoint options


@dataclass(frozen=True)
class SdAnnounce:
    services: tuple   # tuple[SdService, ...]


@dataclass(frozen=True)
class SdSubscribeEventgroup:
    """Parsed SubscribeEventgroup entry received from a client."""
    service_id: int
    instance_id: int
    major_version: int
    eventgroup_id: int
    ttl: int             # 0 = StopSubscribeEventgroup
    client_ip: str
    client_udp_port: int


@dataclass(frozen=True)
class SdMessage:
    """Fully-parsed SOME/IP-SD datagram (all entry types)."""
    session_id: int
    offered: tuple      # tuple[SdService, ...]      from ET_OFFER_SERVICE
    subscribes: tuple   # tuple[SdSubscribeEventgroup, ...]  from ET_SUBSCRIBE_EG


# ── Low-level wire helpers ────────────────────────────────────────────────────

def _u24_pack(v: int) -> bytes:
    v &= 0xFFFFFF
    return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def _u24_unpack(b: bytes, off: int = 0) -> int:
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]


def _opt_ipv4_endpoint(ip: str, port: int, l4: int) -> bytes:
    """
    Build a 12-byte IPv4 Endpoint Option (type 0x04).

    Layout:
      [0:2]  Length  = 0x0009  (covers bytes 3..11, i.e. everything after Type)
      [2]    Type    = 0x04
      [3]    Rsvd    = 0x00
      [4:8]  IPv4 address
      [8]    Rsvd    = 0x00
      [9]    L4 proto (0x06=TCP, 0x11=UDP)
      [10:12] Port
    """
    return (
        struct.pack("!HBB", 0x0009, OT_IPV4_ENDPOINT, 0x00)
        + socket.inet_aton(ip)
        + struct.pack("!BBH", 0x00, l4, port & 0xFFFF)
    )


def _opt_ipv4_multicast(group: str, port: int) -> bytes:
    """Build a 12-byte IPv4 Multicast Option (type 0x24)."""
    return (
        struct.pack("!HBB", 0x0009, OT_IPV4_MULTICAST, 0x00)
        + socket.inet_aton(group)
        + struct.pack("!BBH", 0x00, L4_UDP, port & 0xFFFF)
    )


def _entry_service(
    etype: int,
    svc_id: int, inst_id: int, major: int, minor: int, ttl: int,
    idx1: int = 0, n1: int = 0, idx2: int = 0, n2: int = 0,
) -> bytes:
    """Build a 16-byte service entry (OfferService / FindService)."""
    return (
        bytes([etype, idx1 & 0xFF, idx2 & 0xFF, ((n1 & 0xF) << 4) | (n2 & 0xF)])
        + struct.pack("!HHB", svc_id & 0xFFFF, inst_id & 0xFFFF, major & 0xFF)
        + _u24_pack(ttl)
        + struct.pack("!I", minor & 0xFFFFFFFF)
    )


def _entry_eventgroup(
    etype: int,
    svc_id: int, inst_id: int, major: int, eg_id: int, ttl: int,
    counter: int = 0, idx1: int = 0, n1: int = 0, idx2: int = 0, n2: int = 0,
) -> bytes:
    """Build a 16-byte eventgroup entry (SubscribeEventgroup / Ack)."""
    return (
        bytes([etype, idx1 & 0xFF, idx2 & 0xFF, ((n1 & 0xF) << 4) | (n2 & 0xF)])
        + struct.pack("!HHB", svc_id & 0xFFFF, inst_id & 0xFFFF, major & 0xFF)
        + _u24_pack(ttl)
        + struct.pack("!HH", counter & 0x000F, eg_id & 0xFFFF)
    )


def _sd_payload(entries: bytes, options: bytes, flags: int = SD_FLAG_REBOOT) -> bytes:
    """Wrap entries + options into the SD payload body."""
    return (
        bytes([flags, 0x00, 0x00, 0x00])
        + struct.pack("!I", len(entries))
        + entries
        + struct.pack("!I", len(options))
        + options
    )


def _sd_msg(payload: bytes, session_id: int) -> bytes:
    """Wrap SD payload in a SOME/IP header (service=0xFFFF, method=0x8100)."""
    return build_message(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=SD_CLIENT_ID,
        session_id=session_id & 0xFFFF,
        iface_ver=SD_IFACE_VER,
        msg_type=MT_NOTIFICATION,
        payload=payload,
    )


# ── Public build functions ────────────────────────────────────────────────────

def build_sd_datagram(*, seq: int, ann: SdAnnounce) -> bytes:
    """
    Build a SOME/IP-SD OfferService datagram for all services in ann.

    For each service:
    - One IPv4 Endpoint option (TCP) per tcp_port in svc.tcp_ports
    - One IPv4 Multicast option per multicast event in svc.events
    All options for a service are referenced by a single option run in the entry.
    """
    entries = bytearray()
    options = bytearray()

    for svc in ann.services:
        opt_start = len(options) // OPT_IPV4_SZ
        num_opts = 0

        for port in svc.tcp_ports:
            options += _opt_ipv4_endpoint(svc.server_ip, port, L4_TCP)
            num_opts += 1

        for ev in svc.events:
            if ev.udp_mode == 1 and ev.mcast_group not in ("", "0.0.0.0"):
                options += _opt_ipv4_multicast(ev.mcast_group, ev.udp_port)
                num_opts += 1

        entries += _entry_service(
            ET_OFFER_SERVICE,
            svc.service_id, svc.instance_id,
            svc.major_version, svc.minor_version,
            ttl=3,
            idx1=opt_start, n1=num_opts,
        )

    return _sd_msg(_sd_payload(bytes(entries), bytes(options)), seq)


def build_sd_subscribe_eventgroup(
    *,
    seq: int,
    service_id: int,
    instance_id: int,
    major_version: int,
    eventgroup_id: int,
    client_ip: str,
    client_udp_port: int,
    ttl: int = 3,
    counter: int = 0,
) -> bytes:
    """
    Build a SOME/IP-SD SubscribeEventgroup datagram.
    client_ip / client_udp_port: where the client wants to receive unicast events.
    """
    opt   = _opt_ipv4_endpoint(client_ip, client_udp_port, L4_UDP)
    entry = _entry_eventgroup(
        ET_SUBSCRIBE_EG,
        service_id, instance_id, major_version, eventgroup_id,
        ttl=ttl, counter=counter, idx1=0, n1=1,
    )
    return _sd_msg(_sd_payload(entry, opt), seq)


def build_sd_subscribe_eventgroup_ack(
    *,
    seq: int,
    service_id: int,
    instance_id: int,
    major_version: int,
    eventgroup_id: int,
    mcast_group: str = "",
    mcast_port: int = 0,
    server_ip: str = "0.0.0.0",
    server_udp_port: int = 0,
    ttl: int = 3,
    counter: int = 0,
) -> bytes:
    """
    Build a SOME/IP-SD SubscribeEventgroupAck datagram.
    Include multicast option when mcast_group is set; otherwise unicast endpoint.
    """
    opts     = bytearray()
    num_opts = 0
    if mcast_group and mcast_group not in ("", "0.0.0.0"):
        opts += _opt_ipv4_multicast(mcast_group, mcast_port)
        num_opts += 1
    elif server_udp_port:
        opts += _opt_ipv4_endpoint(server_ip, server_udp_port, L4_UDP)
        num_opts += 1

    entry = _entry_eventgroup(
        ET_SUBSCRIBE_EG_ACK,
        service_id, instance_id, major_version, eventgroup_id,
        ttl=ttl, counter=counter, idx1=0, n1=num_opts,
    )
    return _sd_msg(_sd_payload(entry, bytes(opts)), seq)


# ── SD Parser ─────────────────────────────────────────────────────────────────

def _parse_options(buf: bytes) -> Dict[int, Tuple]:
    """
    Parse the SD options block.
    Returns {option_index: (opt_type, ip_str, port, l4_proto)}.

    Option wire layout:
      [0:2]  Length  (uint16 BE) = total option size - 3
                                   (excludes Length field AND Type field)
      [2]    Type
      [3...] content (Length bytes)

    Only IPv4 Endpoint (0x04) and IPv4 Multicast (0x24) options are decoded.
    Unknown option types are counted but skipped.
    """
    result: Dict[int, Tuple] = {}
    pos = 0
    idx = 0
    while pos + 3 <= len(buf):
        length = struct.unpack_from("!H", buf, pos)[0]
        otype  = buf[pos + 2]
        opt_total = 3 + length   # Length(2) + Type(1) + length_value
        if pos + opt_total > len(buf):
            break
        if otype in (OT_IPV4_ENDPOINT, OT_IPV4_MULTICAST) and length == 9:
            ip   = socket.inet_ntoa(buf[pos + 4: pos + 8])
            l4   = buf[pos + 9]
            port = struct.unpack_from("!H", buf, pos + 10)[0]
            result[idx] = (otype, ip, port, l4)
        pos += opt_total
        idx += 1
    return result


def parse_sd_message(data: bytes) -> Optional[SdMessage]:
    """
    Parse a raw UDP payload as a SOME/IP-SD datagram.
    Returns SdMessage on success, None if not a valid SD datagram.

    Handles ET_OFFER_SERVICE and ET_SUBSCRIBE_EG entries.
    ET_FIND_SERVICE and ET_SUBSCRIBE_EG_ACK are silently accepted but not decoded.
    """
    if len(data) < 16:   # minimum SOME/IP header size
        return None
    try:
        hdr, payload = parse_message(data)
    except Exception:
        return None

    if hdr.service_id != SD_SERVICE_ID or hdr.method_id != SD_METHOD_ID:
        return None
    # SD payload minimum: flags(4) + entries_len(4) + opts_len(4) = 12
    if len(payload) < 12:
        return None

    pos = 4  # skip Flags(1) + Reserved(3)
    entries_len = struct.unpack_from("!I", payload, pos)[0]; pos += 4
    if pos + entries_len > len(payload):
        return None
    entries_buf = payload[pos: pos + entries_len]; pos += entries_len

    if pos + 4 > len(payload):
        return None
    opts_len = struct.unpack_from("!I", payload, pos)[0]; pos += 4
    if pos + opts_len > len(payload):
        return None
    opts_buf = payload[pos: pos + opts_len]

    options = _parse_options(opts_buf)

    offered:    List[SdService]             = []
    subscribes: List[SdSubscribeEventgroup] = []

    for i in range(len(entries_buf) // ENTRY_SZ):
        e = entries_buf[i * ENTRY_SZ: (i + 1) * ENTRY_SZ]
        if len(e) < ENTRY_SZ:
            break

        etype  = e[0]
        idx1   = e[1]
        idx2   = e[2]
        n1     = (e[3] >> 4) & 0xF
        n2     = e[3] & 0xF
        svc_id, inst_id = struct.unpack_from("!HH", e, 4)
        major  = e[8]
        ttl    = _u24_unpack(e, 9)

        # All option indices referenced by this entry
        opt_indices = list(range(idx1, idx1 + n1)) + list(range(idx2, idx2 + n2))

        if etype == ET_OFFER_SERVICE:
            minor     = struct.unpack_from("!I", e, 12)[0]
            tcp_ports: List[int]    = []
            ev_list:   List[SdEvent] = []

            for oi in opt_indices:
                opt = options.get(oi)
                if not opt:
                    continue
                ot, ip, port, l4 = opt
                if ot == OT_IPV4_ENDPOINT and l4 == L4_TCP:
                    tcp_ports.append(port)
                elif ot == OT_IPV4_MULTICAST:
                    ev_list.append(SdEvent(
                        event_id=0, udp_port=port, mcast_group=ip,
                        udp_mode=1, ttl=ttl, eventgroup_id=0,
                    ))

            offered.append(SdService(
                service_id=svc_id, instance_id=inst_id, iface_ver=major,
                tcp_ports=tuple(tcp_ports), events=tuple(ev_list),
                major_version=major, minor_version=minor,
            ))

        elif etype == ET_SUBSCRIBE_EG:
            eg_id       = struct.unpack_from("!H", e, 14)[0]
            client_ip   = "0.0.0.0"
            client_port = 0

            for oi in opt_indices:
                opt = options.get(oi)
                if not opt:
                    continue
                ot, ip, port, l4 = opt
                if ot == OT_IPV4_ENDPOINT and l4 == L4_UDP:
                    client_ip   = ip
                    client_port = port
                    break

            subscribes.append(SdSubscribeEventgroup(
                service_id=svc_id, instance_id=inst_id,
                major_version=major, eventgroup_id=eg_id,
                ttl=ttl, client_ip=client_ip, client_udp_port=client_port,
            ))

    return SdMessage(
        session_id=hdr.session_id,
        offered=tuple(offered),
        subscribes=tuple(subscribes),
    )


def parse_sd_datagram(data: bytes) -> Optional[Tuple[int, SdAnnounce]]:
    """
    Backward-compatible wrapper.
    Returns (session_id, SdAnnounce) if the datagram contains OfferService entries,
    otherwise None.
    """
    msg = parse_sd_message(data)
    if msg is None or not msg.offered:
        return None
    return msg.session_id, SdAnnounce(services=tuple(msg.offered))
