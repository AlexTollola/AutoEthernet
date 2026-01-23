from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import Dict, Optional

from .codec import build_payload, decode_frame, encode_frame, parse_payload
from .hybrid_common import CatalogIndex
from .message_config import load_messages_config, MessageDef
from .signal_catalog import load_catalog
from .tcp_stream import recv_lp_frame, send_lp_frame
from .udp_transport import make_udp_socket, udp_dest


def _now_ms() -> int:
    return int(time.time() * 1000)


class UdpEventPublisher:
    def __init__(self, msg: MessageDef, sig_subset, iface: Optional[str], dest_ip: str):
        self.msg = msg
        self.sig_subset = sig_subset
        self.sock = make_udp_socket(iface=iface or msg.iface, ttl=int(msg.ttl or 1))
        self.dest = udp_dest(msg.mode, msg.mcast_group, dest_ip, msg.port)
        self.seq = 0
        self.values: Dict[str, float] = {}

    def step_demo_values(self) -> None:
        # Demo waveform
        self.values["vehicle_speed_kph"] = (self.values.get("vehicle_speed_kph", 0.0) + 0.5) % 200.0
        self.values["engine_rpm"] = 800.0 + (self.values.get("vehicle_speed_kph", 0.0) * 30.0)
        self.values["steering_angle_deg"] = (self.values.get("steering_angle_deg", 0.0) + 1.0) % 180.0 - 90.0

    def publish_once(self) -> None:
        self.step_demo_values()
        payload = build_payload(self.sig_subset, self.values)
        frame = encode_frame(msg_type=self.msg.msg_id, seq=self.seq, payload=payload)
        self.sock.sendto(frame, self.dest)
        self.seq = (self.seq + 1) & 0xFFFF


class TcpMethodServer:
    def __init__(self, listen_ip: str, port: int, cfg_by_id, cat_index: CatalogIndex, verbose: bool = False):
        self.listen_ip = listen_ip
        self.port = port
        self.cfg_by_id = cfg_by_id
        self.cat_index = cat_index
        self.verbose = verbose
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_ip, self.port))
        srv.listen(5)
        if self.verbose:
            print(f"[tcp_srv] listening on {self.listen_ip}:{self.port}")

        srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
            t.start()

    def _select_response_def(self):
        # Starter policy: select the first configured method_response definition
        for m in self.cfg_by_id.values():
            if m.transport == "tcp" and m.kind == "method_response":
                return m
        return None

    def _handle_client(self, conn: socket.socket, addr) -> None:
        if self.verbose:
            print(f"[tcp_srv] client connected: {addr}")
        try:
            while True:
                data = recv_lp_frame(conn)
                if not data:
                    return
                fr = decode_frame(data)

                md = self.cfg_by_id.get(fr.msg_type)
                if md is None:
                    if self.verbose:
                        print(f"[tcp_srv] unknown msg_id={fr.msg_type} from {addr}")
                    continue

                sig_subset = self.cat_index.subset(md.signals)
                vals = parse_payload(sig_subset, fr.raw_payload)

                if self.verbose:
                    print(f"[tcp_srv] rx {md.name} id={md.msg_id} seq={fr.seq} values={vals}")

                rsp_def = self._select_response_def()
                if rsp_def:
                    rsp_id = rsp_def.msg_id
                    rsp_subset = self.cat_index.subset(rsp_def.signals)
                    rsp_payload = build_payload(rsp_subset, vals)
                else:
                    rsp_id = fr.msg_type
                    rsp_payload = fr.raw_payload

                rsp = encode_frame(msg_type=rsp_id, seq=fr.seq, payload=rsp_payload)
                send_lp_frame(conn, rsp)
        except (ConnectionError, OSError):
            return
        except Exception as e:
            if self.verbose:
                print(f"[tcp_srv] client error {addr}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            if self.verbose:
                print(f"[tcp_srv] client disconnected: {addr}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Hybrid service (UDP events + TCP method server)")
    ap.add_argument("--signals", default="configs/signals.yaml", help="signals catalog YAML")
    ap.add_argument("--messages", default="configs/messages.yaml", help="message config YAML")
    ap.add_argument("--udp-dest-ip", default="127.0.0.1", help="UDP unicast destination IP (if mode=unicast)")
    ap.add_argument("--udp-iface", default=None, help="UDP interface name for TX (e.g. eth0)")
    ap.add_argument("--tcp-listen-ip", default=None, help="Override TCP listen IP")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    catalog = load_catalog(args.signals)
    cat_index = CatalogIndex.from_catalog(catalog)
    mc = load_messages_config(args.messages)

    udp_pubs = []
    for msg in mc.messages:
        if msg.transport == "udp" and msg.kind == "event":
            sig_subset = cat_index.subset(msg.signals)
            udp_pubs.append(UdpEventPublisher(msg, sig_subset, args.udp_iface, args.udp_dest_ip))

    tcp_ports = sorted({m.port for m in mc.messages if m.transport == "tcp"})
    tcp_servers = []
    for port in tcp_ports:
        listen_ip = args.tcp_listen_ip or mc.tcp.listen_ip
        srv = TcpMethodServer(listen_ip=listen_ip, port=port, cfg_by_id=mc.by_id, cat_index=cat_index, verbose=args.verbose)
        tcp_servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    if args.verbose:
        print(f"[hybrid] udp_events={len(udp_pubs)} tcp_ports={tcp_ports}")

    next_due = {p.msg.name: _now_ms() for p in udp_pubs}
    periods = {p.msg.name: int(p.msg.period_ms) for p in udp_pubs}

    try:
        while True:
            now = _now_ms()
            for p in udp_pubs:
                name = p.msg.name
                if now >= next_due[name]:
                    p.publish_once()
                    next_due[name] = now + max(periods[name], 1)
            time.sleep(0.001)
    except KeyboardInterrupt:
        for s in tcp_servers:
            s.stop()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
