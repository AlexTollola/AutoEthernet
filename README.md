# autoeth-pi (Python starter)

Goal: develop Automotive-Ethernet-style messaging on Raspberry Pi using Python in WSL, then clone and run on the Pi.
This starter implements **Stage 1**: UDP unicast/multicast publisher/subscriber + a DBC-like signal catalog + binary serialization.

> Note: WSL2 networking may limit multicast to external networks. For initial validation, run pub/sub on the same host (WSL),
or test multicast on the Raspberry Pi network where it behaves like normal Linux.

## Quick start (WSL)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip tcpdump iproute2 ethtool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run UDP unicast (two terminals):
```bash
# Terminal A
source .venv/bin/activate
python -m autoeth.udp_sub --bind-ip 127.0.0.1 --port 30509

# Terminal B
source .venv/bin/activate
python -m autoeth.udp_pub --dest-ip 127.0.0.1 --port 30509 --catalog configs/signals.yaml
```

Run UDP multicast (recommended on Raspberry Pi / real LAN):
```bash
# Subscriber
python -m autoeth.udp_sub --mcast 239.255.0.1 --port 30509 --iface eth0

# Publisher
python -m autoeth.udp_pub --mcast 239.255.0.1 --port 30509 --iface eth0 --catalog configs/signals.yaml
```

Capture traffic:
```bash
sudo ./scripts/capture.sh eth0 30509
```

## Next steps
- Stage 2: implement a minimal SOME/IP-like header and a simple Service Discovery demo over multicast.
- Stage 3: keep the same signal catalog but place it inside SOME/IP-like events.
- Stage 4: optional E2E-like counter + CRC inside payload (CAN-like robustness).

## Hybrid UDP/TCP (Stage 1.5)

Adds a config-driven hybrid approach:
- UDP **events** (periodic publish/subscribe)
- TCP **methods** (request/response)

Configuration:
- Signals: `configs/signals.yaml`
- Message groups + transports: `configs/messages.yaml`

Run hybrid service (WSL localhost demo):
```bash
source .venv/bin/activate
PYTHONPATH=src python -m autoeth.hybrid_service --udp-dest-ip 127.0.0.1 --verbose
```

In another terminal, issue a TCP method command and optionally listen to UDP:
```bash
source .venv/bin/activate
PYTHONPATH=src python -m autoeth.hybrid_client --tcp-server-ip 127.0.0.1 --tcp-port 30510 --set-steer-deg 25 --udp-sub
```

Raspberry Pi LAN:
- Start service on Pi:
  ```bash
  PYTHONPATH=src python -m autoeth.hybrid_service --udp-iface eth0 --udp-dest-ip <peer_ip_if_unicast> --verbose
  ```
- Point client to Pi:
  ```bash
  PYTHONPATH=src python -m autoeth.hybrid_client --tcp-server-ip <pi_ip> --tcp-port 30510 --set-steer-deg 5 --udp-sub
  ```
