# AutoEth (Pi) — Simple Layered Build (Step 1)

This repo is a learning-oriented, AUTOSAR-aligned Automotive Ethernet project using Python.
The focus is a **simple but robust layered architecture**, not a “hybrid mode”.

## Layering (frozen API surface in Step 1)

### `autoeth.core.transport`
Lowest layer: UDP/TCP mechanics only.

- `udp.make_socket(...)` -> returns a configured UDP socket
- `udp.join_multicast(sock, group, iface_ip=...)`
- `tcp.send_frame(sock, payload)` / `tcp.recv_frame(sock)` (length-prefixed framing)
- `tcp.TcpServer` / `tcp.TcpClient` (thin wrappers; extended in later steps)

### `autoeth.core.serialization`
DBC-like signal serialization:

- `codec.encode(signals, values)` -> bytes
- `codec.decode(signals, payload)` -> dict(name->float)
- `index.SignalIndex` for fast lookup and subsets

### `autoeth.core.config`
Single-file configuration loader for `configs/catalog.yaml` (used starting Step 2).
Present now as a placeholder interface.

### `autoeth.protocols.someip`
Protocol wrappers (used in later steps):
- SOME/IP 16-byte header pack/unpack in `header.py`

## Configuration

Single canonical config file:
- `configs/catalog.yaml`

Step 1 does not yet start a node/client; it establishes the modular building blocks.
Next step: implement `apps/node.py` and `apps/client.py` that run from `catalog.yaml`.

## Quick sanity check

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

PYTHONPATH=src python -m compileall -q src
```
