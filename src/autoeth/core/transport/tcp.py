from __future__ import annotations

import socket
import struct
import threading
from typing import Callable, Optional


_LEN = struct.Struct("!I")  # uint32 length prefix (network byte order)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a single length-prefixed frame over TCP."""
    payload = payload or b""
    sock.sendall(_LEN.pack(len(payload)) + payload)


def recv_frame(sock: socket.socket, *, max_len: int = 1024 * 1024) -> bytes:
    """Receive one length-prefixed frame over TCP."""
    hdr = _recv_exact(sock, _LEN.size)
    if not hdr:
        return b""
    (n,) = _LEN.unpack(hdr)
    if n < 0 or n > max_len:
        raise ValueError(f"frame too large: {n}")
    return _recv_exact(sock, n)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


class TcpServer:
    """Minimal TCP server wrapper.

    Step 1: wrapper only; application logic is added in later steps.
    """

    def __init__(
        self,
        *,
        listen_ip: str,
        port: int,
        handler: Callable[[socket.socket, tuple], None],
        backlog: int = 5,
    ):
        self.listen_ip = listen_ip
        self.port = int(port)
        self.handler = handler
        self.backlog = int(backlog)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_ip, self.port))
        srv.listen(self.backlog)
        srv.settimeout(0.5)

        try:
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(target=self._handle_one, args=(conn, addr), daemon=True)
                t.start()
        finally:
            try:
                srv.close()
            except Exception:
                pass

    def _handle_one(self, conn: socket.socket, addr: tuple) -> None:
        try:
            self.handler(conn, addr)
        finally:
            try:
                conn.close()
            except Exception:
                pass


class TcpClient:
    """Minimal TCP client wrapper."""

    def __init__(self, *, ip: str, port: int, timeout_ms: int = 500):
        self.ip = ip
        self.port = int(port)
        self.timeout = max(int(timeout_ms), 1) / 1000.0

    def connect(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.ip, self.port))
        return s

