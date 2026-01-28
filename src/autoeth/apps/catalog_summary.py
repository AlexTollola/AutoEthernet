from __future__ import annotations

import argparse

from autoeth.core.config import load_catalog


def main() -> int:
    ap = argparse.ArgumentParser(description="Print catalog summary")
    ap.add_argument("--catalog", default="configs/catalog.yaml")
    args = ap.parse_args()

    cat = load_catalog(args.catalog)

    print(f"[catalog] version={cat.version}")
    print(f"[catalog] signals={len(cat.signals)} services={len(cat.services)} messages={len(cat.messages)}")

    if cat.services:
        print("[catalog] services:")
        for s in cat.services:
            print(
                f"  - {s.name} svc=0x{s.service_id:04X} inst=0x{s.instance_id:04X} "
                f"iface_ver={s.interface_version} ver={s.major_version}.{s.minor_version}"
            )

    print("[catalog] messages:")
    for m in cat.messages:
        if m.transport == "udp":
            udp = m.udp or {}
            mode = udp.get("mode", "unicast")
            group = udp.get("mcast_group", udp.get("dest_ip", ""))
            port = udp.get("port", "")
            extra = f" udp:{mode} {group}:{port} period_ms={m.period_ms}"
        else:
            tcp = m.tcp or {}
            extra = f" tcp:port={tcp.get('port')} timeout_ms={tcp.get('timeout_ms')}"

        print(f"  - {m.name} id={m.msg_id} kind={m.kind} transport={m.transport} signals={len(m.signals)}{extra}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
