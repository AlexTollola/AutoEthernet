\
    #!/usr/bin/env bash
    set -euo pipefail

    sudo apt-get update
    sudo apt-get install -y python3 python3-venv python3-pip tcpdump iproute2 ethtool

    echo "[ok] packages installed"
    echo "Next:"
    echo "  python3 -m venv .venv"
    echo "  source .venv/bin/activate"
    echo "  pip install -r requirements.txt"
