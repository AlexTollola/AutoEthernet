from __future__ import annotations

import socket
from typing import Optional, Tuple


def make_socket(
    *,
    iface: Optional[str] = None,
    ttl: int = 1,
    bind_ip: str = "0.0.0.0",
    bind_port: int = 0,
    reuse: bool = True,
) -> socket.socket:
    """Create a UDP socket configured for unicast/multicast TX/RX."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    if reuse:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, int(ttl) & 0xFF)

    if iface:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
        except OSError:
            pass

    s.bind((bind_ip, int(bind_port)))
    return s


def join_multicast(sock: socket.socket, group: str, *, iface_ip: str = "0.0.0.0") -> None:
    """Join an IPv4 multicast group on the given socket."""
    mreq = socket.inet_aton(group) + socket.inet_aton(iface_ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def dest(mode: str, mcast_group: Optional[str], unicast_ip: str, port: int) -> Tuple[str, int]:
    """Resolve destination tuple for UDP send."""
    if mode == "multicast":
        if not mcast_group:
            raise ValueError("multicast mode requires mcast_group")
        return (mcast_group, int(port))
    return (unicast_ip, int(port))

