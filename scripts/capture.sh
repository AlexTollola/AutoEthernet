\
    #!/usr/bin/env bash
    set -euo pipefail

    IFACE="${1:-eth0}"
    PORT="${2:-30509}"
    OUT_DIR="${3:-pcaps}"

    mkdir -p "$OUT_DIR"
    TS="$(date +%Y%m%d_%H%M%S)"
    OUT="$OUT_DIR/capture_${IFACE}_${PORT}_${TS}.pcapng"

    echo "[capture] iface=$IFACE port=$PORT -> $OUT"
    sudo tcpdump -i "$IFACE" "udp port $PORT" -w "$OUT"
