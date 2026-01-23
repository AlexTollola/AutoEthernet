from __future__ import annotations

import socket
from typing import Optional, Tuple


def make_udp_socket(iface: Optional[str] = None, ttl: int = 1) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    if iface:
        # Linux only: SO_BINDTODEVICE=25
        try:
            s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
        except OSError:
            pass
    return s


def udp_dest(mode: str, mcast_group: str, dest_ip: str, port: int) -> Tuple[str, int]:
    if mode == "multicast":
        return (mcast_group, port)
    return (dest_ip, port)


def join_multicast(sock: socket.socket, group: str, iface_ip: str = "0.0.0.0") -> None:
    mreq = socket.inet_aton(group) + socket.inet_aton(iface_ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
