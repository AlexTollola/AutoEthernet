from __future__ import annotations

import argparse
import signal
import socket
import threading
import time
from typing import Dict, List, Tuple

from autoeth.core.config import Catalog, MessageDef, SignalDef, load_catalog
from autoeth.core.serialization.codec import decode, encode, encoded_size
from autoeth.core.serialization.index import SignalIndex
from autoeth.core.transport.tcp import TcpServer, recv_frame, send_frame
from autoeth.core.transport import udp as udp_transport
from autoeth.core.validation.frame import PROTO_VER, pack_header, unpack_header, header_size


def _method_by_id(cat: Catalog) -> Dict[int, MessageDef]:
    return {m.msg_id: m for m in cat.messages if m.kind == "method" and m.transport == "tcp"}


def _udp_events(cat: Catalog) -> List[MessageDef]:
    return [m for m in cat.messages if m.kind == "event" and m.transport == "udp"]


def _init_state(signals: List[SignalDef]) -> Dict[str, float]:
    return {s.name: float(s.default) for s in signals}


def _tcp_handler(
    conn: socket.socket,
    addr: tuple,
    *,
    method_by_id: Dict[int, MessageDef],
    sig_index: SignalIndex,
    state: Dict[str, float],
    state_lock: threading.Lock,
    verbose: bool,
) -> None:
    if verbose:
        print(f"[tcp] client connected: {addr}")

    while True:
        frame = recv_frame(conn)
        if not frame:
            break

        if len(frame) < 1:
            if verbose:
                print("[tcp] rx invalid frame (too short)")
            continue

        msg_id = frame[0]
        payload = frame[1:]

        msg = method_by_id.get(msg_id)
        if msg is None:
            if verbose:
                print(f"[tcp] rx unknown msg_id={msg_id} (ignored)")
            continue

        sigs = sig_index.subset(msg.signals)

        try:
            hdr, pl = unpack_header(payload)
            if hdr.proto_ver != PROTO_VER:
                if verbose:
                    print(f"[tcp] drop {msg.name}: proto_ver={hdr.proto_ver} != {PROTO_VER}")
                continue

            exp = encoded_size(sigs)
            if len(pl) != exp:
                if verbose:
                    print(f"[tcp] drop {msg.name}: payload_len={len(pl)} expected={exp}")
                continue

            values = decode(sigs, pl)

        except Exception as e:
            if verbose:
                print(f"[tcp] decode error msg={msg.name} id={msg_id}: {e}")
            continue

        # Update shared state
        with state_lock:
            for k, v in values.items():
                state[k] = float(v)

        if verbose:
            print(f"[tcp] rx method {msg.name} id={msg_id} values={values}")

        rsp_pl = encode(sigs, values)
        rsp = bytes([msg_id]) + pack_header(seq=hdr.seq) + rsp_pl
        send_frame(conn, rsp)

    if verbose:
        print(f"[tcp] client disconnected: {addr}")


class UdpEventPublisher(threading.Thread):
    def __init__(
        self,
        *,
        msg: MessageDef,
        sigs: List[SignalDef],
        state: Dict[str, float],
        state_lock: threading.Lock,
        stop_evt: threading.Event,
        dest_ip: str,
        verbose: bool,
    ):
        super().__init__(daemon=True)
        self.msg = msg
        self.sigs = sigs
        self.state = state
        self.state_lock = state_lock
        self.stop_evt = stop_evt
        self.dest_ip = dest_ip
        self.verbose = verbose

        udp_cfg = msg.udp or {}
        self.mode = str(udp_cfg.get("mode", "unicast"))
        self.group = udp_cfg.get("mcast_group")
        self.port = int(udp_cfg["port"])
        self.ttl = int(udp_cfg.get("ttl", 1))
        self.iface = udp_cfg.get("iface")

        self.sock = udp_transport.make_socket(iface=self.iface, ttl=self.ttl, bind_ip="0.0.0.0", bind_port=0)
        self.dest: Tuple[str, int] = udp_transport.dest(self.mode, self.group, self.dest_ip, self.port)

        self.period_s = max(float(self.msg.period_ms or 1000) / 1000.0, 0.001)

        self.seq = 0
        self.exp_len = encoded_size(self.sigs)


    def run(self) -> None:
        next_t = time.monotonic()

        if self.verbose:
            print(f"[udp] pub {self.msg.name} id={self.msg.msg_id} -> {self.dest} period_ms={int(self.period_s*1000)}")

        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now < next_t:
                self.stop_evt.wait(next_t - now)
                continue
            next_t += self.period_s

            with self.state_lock:
                vals = {s.name: float(self.state.get(s.name, s.default)) for s in self.sigs}

            payload = encode(self.sigs, vals)
            self.seq = (self.seq + 1) & 0xFFFF
            datagram = bytes([self.msg.msg_id]) + pack_header(seq=self.seq) + payload

            try:
                self.sock.sendto(datagram, self.dest)
            except OSError as e:
                if self.verbose:
                    print(f"[udp] send error {self.msg.name}: {e}")

        try:
            self.sock.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="AutoEth Node (TCP methods + UDP events)")
    ap.add_argument("--catalog", default="configs/catalog.yaml", help="canonical catalog YAML")
    ap.add_argument("--listen-ip", default="0.0.0.0", help="TCP listen IP")
    ap.add_argument("--tcp-port", type=int, default=None, help="override TCP port (else first TCP method port in catalog)")
    ap.add_argument("--udp-dest-ip", default="127.0.0.1", help="used for UDP unicast mode")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)
    cat.validate()

    sig_index = SignalIndex.from_signals(cat.signals)
    state: Dict[str, float] = _init_state(cat.signals)
    state_lock = threading.Lock()

    stop_evt = threading.Event()

    # TCP server (methods)
    method_by_id = _method_by_id(cat)
    if not method_by_id:
        raise SystemExit("No TCP methods found in catalog (kind=method, transport=tcp).")

    first_method = next(iter(method_by_id.values()))
    tcp_port = args.tcp_port
    if tcp_port is None:
        tcp_block = first_method.tcp or {}
        if "port" not in tcp_block:
            raise SystemExit(f"Method {first_method.name} missing tcp.port")
        tcp_port = int(tcp_block["port"])

    def _handler(conn: socket.socket, addr: tuple) -> None:
        _tcp_handler(
            conn,
            addr,
            method_by_id=method_by_id,
            sig_index=sig_index,
            state=state,
            state_lock=state_lock,
            verbose=args.verbose,
        )

    srv = TcpServer(listen_ip=args.listen_ip, port=tcp_port, handler=_handler)
    srv.start()

    # UDP publishers (events)
    udp_msgs = _udp_events(cat)
    udp_threads: List[UdpEventPublisher] = []
    for m in udp_msgs:
        sigs = sig_index.subset(m.signals)
        t = UdpEventPublisher(
            msg=m,
            sigs=sigs,
            state=state,
            state_lock=state_lock,
            stop_evt=stop_evt,
            dest_ip=args.udp_dest_ip,
            verbose=args.verbose,
        )
        t.start()
        udp_threads.append(t)

    print(
        f"[node] tcp_methods={sorted(method_by_id.keys())} tcp_listen={args.listen_ip}:{tcp_port} "
        f"udp_events={[m.msg_id for m in udp_msgs]}"
    )

    def _sigint(_signum, _frame):
        stop_evt.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    while not stop_evt.is_set():
        stop_evt.wait(0.2)

    srv.stop()
    for t in udp_threads:
        t.join(timeout=0.5)

    print("[node] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
