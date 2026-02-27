"""
SOME/IP-SD wire format implementation.

Exports used by node.py, client.py and tui.py
──────────────────────────────────────────────
Constants:
  ET_OFFER_SERVICE, ET_SUBSCRIBE_EVENTGROUP, ET_SUBSCRIBE_EVENTGROUP_ACK
  L4_TCP, L4_UDP
  SD_FLAG_REBOOT, SD_FLAG_UNICAST
  TTL_DEFAULT, TTL_STOP

Option dataclasses:
  Ipv4EndpointOption(address, port, l4_proto)
  Ipv4MulticastOption(address, port)

Entry dataclasses:
  ServiceEntry(entry_type, service_id, instance_id, major_version,
               minor_version, ttl, options)
  EventgroupEntry(entry_type, service_id, instance_id, major_version,
                  eventgroup_id, counter, ttl, initial_data_req, options)

Message dataclass:
  SdMessage(session_id, flags, entries)

Functions:
  build_sd_message(*, session_id, entries, flags) -> bytes
  parse_sd_message(data) -> SdMessage | None

Wire format (AUTOSAR SOME/IP-SD):
  SOME/IP header  service_id=0xFFFF  method_id=0x8100  msg_type=0x02
  SD payload:
    flags(u8) + reserved(3)
    entries_array_length(u32) + N x 16-byte entries
    options_array_length(u32)  + M x variable options
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

# ── SOME/IP-SD header IDs ─────────────────────────────────────────────────────
SD_SERVICE_ID       = 0xFFFF
SD_METHOD_ID        = 0x8100
SD_CLIENT_ID        = 0x0000
SD_IFACE_VER        = 0x01
_SOMEIP_PROTO_VER   = 0x01
_SOMEIP_MT_NOTIF    = 0x02
_SOMEIP_RC_OK       = 0x00

# ── SD Flags ──────────────────────────────────────────────────────────────────
SD_FLAG_REBOOT  = 0x80
SD_FLAG_UNICAST = 0x40

# ── Entry types ───────────────────────────────────────────────────────────────
ET_FIND_SERVICE             = 0x00
ET_OFFER_SERVICE            = 0x01
ET_SUBSCRIBE_EVENTGROUP     = 0x06
ET_SUBSCRIBE_EVENTGROUP_ACK = 0x07

# ── Option types ──────────────────────────────────────────────────────────────
_OT_IPV4_ENDPOINT  = 0x04
_OT_IPV4_MULTICAST = 0x14

# ── L4 protocol identifiers ───────────────────────────────────────────────────
L4_TCP = 0x06
L4_UDP = 0x11

# ── TTL sentinel values ───────────────────────────────────────────────────────
TTL_STOP    = 0x000000   # StopOffer / StopSubscribe
TTL_DEFAULT = 0xFFFFFF   # "infinite"

# ── Struct layouts ────────────────────────────────────────────────────────────
#  SOME/IP header:  service_id(H) method_id(H) length(I)
#                   client_id(H)  session_id(H)
#                   proto_ver(B)  iface_ver(B)  msg_type(B)  return_code(B)
_SOMEIP_HDR  = struct.Struct("!HHIHHBBBB")   # 16 bytes

# SD entry (all types are exactly 16 bytes):
#   type(B) idx1(B) idx2(B) num_opts(B)
#   service_id(H) instance_id(H)
#   major(B) ttl_hi(B) ttl_mid(B) ttl_lo(B)
#   last32(I)   — minor_version for service entries
#               — (reserved[11:0] | counter[3:0] | egid[15:0]) for eventgroup
_SD_ENTRY   = struct.Struct("!BBBBHHBBBBI")  # 16 bytes

# IPv4 option (endpoint and multicast share the same 12-byte layout):
#   length_field(H)=0x0009  type(B)  reserved(B)
#   ipv4(I)  reserved(B)  l4_proto(B)  port(H)
_OPT_IPV4   = struct.Struct("!HBBIBBH")     # 12 bytes
_OPT_IPV4_LEN_FIELD = 0x0009               # bytes following the Type byte

_ENTRY_SIZE = _SD_ENTRY.size   # 16
_OPT_SIZE   = _OPT_IPV4.size  # 12


# ── Option dataclasses ────────────────────────────────────────────────────────

@dataclass
class Ipv4EndpointOption:
    """IPv4 unicast endpoint option (Type=0x04). TCP or UDP."""
    address: str
    port: int
    l4_proto: int   # L4_TCP or L4_UDP


@dataclass
class Ipv4MulticastOption:
    """IPv4 multicast option (Type=0x14). Always UDP."""
    address: str
    port: int


SdOption = Union[Ipv4EndpointOption, Ipv4MulticastOption]


# ── Entry dataclasses ─────────────────────────────────────────────────────────

@dataclass
class ServiceEntry:
    """OfferService (0x01) or FindService (0x00) entry."""
    entry_type: int
    service_id: int
    instance_id: int
    major_version: int
    minor_version: int
    ttl: int
    options: List[SdOption] = field(default_factory=list)


@dataclass
class EventgroupEntry:
    """SubscribeEventgroup (0x06) or SubscribeEventgroupAck (0x07) entry."""
    entry_type: int
    service_id: int
    instance_id: int
    major_version: int
    eventgroup_id: int
    counter: int
    ttl: int
    initial_data_req: bool = False
    options: List[SdOption] = field(default_factory=list)


SdEntry = Union[ServiceEntry, EventgroupEntry]


# ── Message dataclass ─────────────────────────────────────────────────────────

@dataclass
class SdMessage:
    """Fully-parsed SOME/IP-SD datagram."""
    session_id: int
    flags: int
    entries: List[SdEntry]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ttl_bytes(ttl: int) -> Tuple[int, int, int]:
    t = max(0, min(int(ttl), 0xFFFFFF))
    return (t >> 16) & 0xFF, (t >> 8) & 0xFF, t & 0xFF


def _ttl_from_bytes(b2: int, b1: int, b0: int) -> int:
    return (int(b2) << 16) | (int(b1) << 8) | int(b0)


def _ip_to_u32(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _u32_to_ip(v: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", int(v) & 0xFFFFFFFF))


def _pack_option(opt: SdOption) -> bytes:
    if isinstance(opt, Ipv4EndpointOption):
        otype = _OT_IPV4_ENDPOINT
        l4    = int(opt.l4_proto)
    elif isinstance(opt, Ipv4MulticastOption):
        otype = _OT_IPV4_MULTICAST
        l4    = L4_UDP
    else:
        raise TypeError(f"Unknown SD option type: {type(opt)}")
    return _OPT_IPV4.pack(
        _OPT_IPV4_LEN_FIELD,
        otype,
        0x00,
        _ip_to_u32(opt.address),
        0x00,
        l4,
        int(opt.port) & 0xFFFF,
    )


def _parse_option(data: bytes, offset: int) -> Tuple[Optional[SdOption], int]:
    """Parse one SD option starting at offset. Returns (option|None, next_offset)."""
    if offset + 3 > len(data):
        return None, len(data)
    length_field = struct.unpack_from("!H", data, offset)[0]
    opt_type     = data[offset + 2]
    total        = 2 + 1 + length_field   # length(2) + type(1) + content
    next_off     = offset + total
    if next_off > len(data):
        return None, next_off
    if opt_type in (_OT_IPV4_ENDPOINT, _OT_IPV4_MULTICAST) and total == _OPT_SIZE:
        _, _, _, ipv4_u32, _, l4, port = _OPT_IPV4.unpack_from(data, offset)
        addr = _u32_to_ip(ipv4_u32)
        if opt_type == _OT_IPV4_ENDPOINT:
            return Ipv4EndpointOption(address=addr, port=int(port), l4_proto=int(l4)), next_off
        else:
            return Ipv4MulticastOption(address=addr, port=int(port)), next_off
    return None, next_off


# ── Public API ────────────────────────────────────────────────────────────────

def build_sd_message(
    *,
    session_id: int,
    entries: List[SdEntry],
    flags: int = SD_FLAG_REBOOT | SD_FLAG_UNICAST,
) -> bytes:
    """Build a complete SOME/IP-SD datagram ready to send over UDP."""

    # Flatten per-entry options into a shared global options list
    all_options: List[SdOption] = []
    opt_refs: List[Tuple[int, int]] = []   # (start_idx, count) per entry
    for e in entries:
        start = len(all_options)
        all_options.extend(e.options)
        opt_refs.append((start, len(e.options)))

    opts_bytes = b"".join(_pack_option(o) for o in all_options)

    # Build entries bytes
    entries_buf = bytearray()
    for i, e in enumerate(entries):
        idx1, num_opts = opt_refs[i]
        # High nibble = num_opts1 (single option run), low nibble = 0
        num_byte = ((num_opts & 0xF) << 4) | 0x00
        t2, t1, t0 = _ttl_bytes(e.ttl)

        if isinstance(e, ServiceEntry):
            entries_buf += _SD_ENTRY.pack(
                e.entry_type & 0xFF,
                idx1 & 0xFF, 0x00, num_byte,
                e.service_id  & 0xFFFF,
                e.instance_id & 0xFFFF,
                e.major_version & 0xFF,
                t2, t1, t0,
                e.minor_version & 0xFFFFFFFF,
            )
        elif isinstance(e, EventgroupEntry):
            # last32: bits[31:21]=reserved | bit[20]=InitDataReq
            #         bits[19:16]=Counter  | bits[15:0]=EventgroupID
            last32 = (e.eventgroup_id & 0xFFFF) | ((e.counter & 0xF) << 16)
            if e.initial_data_req:
                last32 |= (1 << 20)
            entries_buf += _SD_ENTRY.pack(
                e.entry_type & 0xFF,
                idx1 & 0xFF, 0x00, num_byte,
                e.service_id  & 0xFFFF,
                e.instance_id & 0xFFFF,
                e.major_version & 0xFF,
                t2, t1, t0,
                last32,
            )

    # SD payload: flags(1)+reserved(3) + entries_len(4)+entries + opts_len(4)+opts
    sd_body = (
        struct.pack("!BBBBI", flags & 0xFF, 0, 0, 0, len(entries_buf))
        + bytes(entries_buf)
        + struct.pack("!I", len(opts_bytes))
        + opts_bytes
    )

    # SOME/IP header: length = 8 (second half of header) + len(sd_body)
    someip_hdr = _SOMEIP_HDR.pack(
        SD_SERVICE_ID,
        SD_METHOD_ID,
        8 + len(sd_body),
        SD_CLIENT_ID,
        int(session_id) & 0xFFFF,
        _SOMEIP_PROTO_VER,
        SD_IFACE_VER,
        _SOMEIP_MT_NOTIF,
        _SOMEIP_RC_OK,
    )
    return someip_hdr + sd_body


def parse_sd_message(data: bytes) -> Optional[SdMessage]:
    """
    Parse a raw UDP payload as SOME/IP-SD.
    Returns SdMessage on success, None if data is not a valid SD datagram.
    """
    if len(data) < _SOMEIP_HDR.size + 8:
        return None

    svc_id, method_id, length, _, session_id, _, _, msg_type, _ = \
        _SOMEIP_HDR.unpack_from(data, 0)

    if svc_id != SD_SERVICE_ID or method_id != SD_METHOD_ID:
        return None

    payload = data[_SOMEIP_HDR.size:]

    # SD header: flags(1) + reserved(3) + entries_length(4)
    if len(payload) < 8:
        return None

    flags       = payload[0]
    entries_len = struct.unpack_from("!I", payload, 4)[0]
    pos         = 8

    if pos + entries_len > len(payload):
        return None

    entries_data = payload[pos: pos + entries_len]
    pos += entries_len

    if pos + 4 > len(payload):
        return None

    opts_len = struct.unpack_from("!I", payload, pos)[0]
    pos += 4
    opts_data = payload[pos: pos + opts_len]

    # Parse options into an indexed list
    all_opts: List[Optional[SdOption]] = []
    opt_pos = 0
    while opt_pos < len(opts_data):
        opt, opt_pos = _parse_option(opts_data, opt_pos)
        all_opts.append(opt)

    # Parse entries
    entries: List[SdEntry] = []
    e_pos = 0
    while e_pos + _ENTRY_SIZE <= len(entries_data):
        (etype, idx1, idx2, num_byte,
         svc_id_e, inst_id,
         major, t2, t1, t0,
         last32) = _SD_ENTRY.unpack_from(entries_data, e_pos)
        e_pos += _ENTRY_SIZE

        ttl      = _ttl_from_bytes(t2, t1, t0)
        num_opt1 = (num_byte >> 4) & 0xF

        entry_opts: List[SdOption] = [
            all_opts[k]
            for k in range(idx1, idx1 + num_opt1)
            if k < len(all_opts) and all_opts[k] is not None
        ]

        if etype in (ET_OFFER_SERVICE, ET_FIND_SERVICE):
            entries.append(ServiceEntry(
                entry_type=etype,
                service_id=svc_id_e,
                instance_id=inst_id,
                major_version=major,
                minor_version=last32,
                ttl=ttl,
                options=entry_opts,
            ))

        elif etype in (ET_SUBSCRIBE_EVENTGROUP, ET_SUBSCRIBE_EVENTGROUP_ACK):
            counter         = (last32 >> 16) & 0xF
            eventgroup_id   = last32 & 0xFFFF
            initial_data_req = bool((last32 >> 20) & 0x1)
            entries.append(EventgroupEntry(
                entry_type=etype,
                service_id=svc_id_e,
                instance_id=inst_id,
                major_version=major,
                eventgroup_id=eventgroup_id,
                counter=counter,
                ttl=ttl,
                initial_data_req=initial_data_req,
                options=entry_opts,
            ))

    return SdMessage(session_id=int(session_id), flags=int(flags), entries=entries)
