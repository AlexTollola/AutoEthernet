from __future__ import annotations

import socket
from typing import Tuple

from autoeth.protocols.someip.header import SomeIpHeader, HDR_SIZE, parse_message

DEFAULT_MAX_PAYLOAD = 4096  # keep sane for now


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_someip(sock: socket.socket, *, max_payload: int = DEFAULT_MAX_PAYLOAD) -> Tuple[SomeIpHeader, bytes]:
    # read header first
    hdr_bytes = _recv_exact(sock, HDR_SIZE)
    hdr = SomeIpHeader.unpack(hdr_bytes)

    payload_len = hdr.length - 8
    if payload_len < 0:
        raise ValueError("SOME/IP invalid length")
    if payload_len > max_payload:
        raise ValueError(f"SOME/IP payload too large: {payload_len} > {max_payload}")

    payload = _recv_exact(sock, payload_len) if payload_len else b""

    # reuse parse_message validation path
    hdr2, payload2 = parse_message(hdr_bytes + payload)
    return hdr2, payload2


def send_someip(sock: socket.socket, msg: bytes) -> None:
    sock.sendall(msg)
