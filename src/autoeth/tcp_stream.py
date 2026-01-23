from __future__ import annotations

import socket
import struct

# TCP framing: length-prefixed frames
# [u32_be length][frame_bytes...]
_LEN = struct.Struct("!I")


def read_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        b = sock.recv(n - got)
        if not b:
            raise ConnectionError("socket closed")
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def recv_lp_frame(sock: socket.socket) -> bytes:
    hdr = read_exact(sock, _LEN.size)
    (length,) = _LEN.unpack(hdr)
    if length == 0:
        return b""
    if length > 65535:
        raise ValueError(f"frame too large: {length}")
    return read_exact(sock, length)


def send_lp_frame(sock: socket.socket, frame: bytes) -> None:
    if frame is None:
        frame = b""
    if len(frame) > 65535:
        raise ValueError(f"frame too large: {len(frame)}")
    sock.sendall(_LEN.pack(len(frame)) + frame)
