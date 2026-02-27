# AutoEth (Pi) — Layered Automotive Ethernet Stack

Learning-oriented, AUTOSAR-aligned Automotive Ethernet project in Python.
Implements SOME/IP transport, SOME/IP-SD service discovery, E2E protection,
and a DBC-style signal codec over UDP/TCP.

---

## Project layout

```
autoeth/
├── configs/
│   └── catalog.yaml              # Single source of truth — signals, services, messages
├── src/autoeth/
│   ├── apps/
│   │   ├── tui.py                # Interactive terminal menu (start here)
│   │   ├── node.py               # Server — TCP methods + UDP events + SD announcer
│   │   ├── client.py             # Client — TCP calls + UDP subscribe + SD discover
│   │   └── catalog_summary.py    # Print catalog contents
│   ├── core/
│   │   ├── config.py             # Catalog loader and validators
│   │   ├── serialization/        # Signal encode / decode
│   │   ├── transport/            # UDP and TCP socket helpers
│   │   ├── validation/           # AutoEth frame header + E2E CRC16 trailer
│   │   └── service/
│   │       └── discovery.py      # SOME/IP-SD wire format (OfferService, Subscribe…)
│   └── protocols/someip/
│       ├── header.py             # SOME/IP 16-byte header pack / unpack
│       └── stream.py             # TCP stream framing for SOME/IP
└── docs/
    ├── data_format.md
    └── layer_api.md
```

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

---

## Quick sanity check

```bash
PYTHONPATH=src python -m compileall -q src

PYTHONPATH=src python -m autoeth.apps.catalog_summary
```

---

## Architecture overview

### Layers

| Layer | Package | Purpose |
|---|---|---|
| Transport | `core.transport` | Raw UDP / TCP sockets, multicast join |
| Serialization | `core.serialization` | Signal pack / unpack (DBC-style) |
| Validation | `core.validation` | AutoEth frame header, E2E CRC16-CCITT-FALSE trailer |
| SOME/IP | `protocols.someip` | 16-byte header, TCP stream framing |
| SOME/IP-SD | `core.service.discovery` | OfferService, SubscribeEventgroup, Ack |
| Config | `core.config` | `catalog.yaml` loader, signal / service / message validation |
| Apps | `apps/` | `tui.py`, `node.py`, `client.py` |

### Message flow

```
Server (node.py)                           Client (client.py)
────────────────                           ─────────────────
SD Announcer ──── OfferService ──────────► SD Discover
                                           │
TCP Server   ◄─── SOME/IP REQUEST ────────── _tcp_call()
             ──── SOME/IP RESPONSE ──────►

UDP Publisher ─── SOME/IP NOTIFICATION ──► EventSubscription
                  (multicast or unicast)
                                           (unicast only)
SD Listener  ◄─── SubscribeEventgroup ──── toggle_sub()
             ──── SubscribeEventgroupAck ►
             registers (ip, port) in
             SubscriberRegistry
```

---

## Configuration — `configs/catalog.yaml`

All signals, services and messages are declared in one file.

Key fields:

| Field | Description |
|---|---|
| `signals[].type` | `u8 u16 u32 i8 i16 i32` |
| `signals[].scale / offset` | Physical = raw × scale + offset |
| `messages[].kind` | `event` (periodic UDP) or `method` (request/response TCP) |
| `messages[].period_ms` | Required for events; drives publish rate |
| `messages[].someip.event_id` | SOME/IP event ID; also used as SD eventgroup_id by default |
| `messages[].someip.eventgroup_id` | Optional override for SD eventgroup ID |
| `messages[].e2e.enabled` | Appends CRC16-CCITT-FALSE + counter trailer |

---

## Interactive terminal menu (`tui.py`)

The recommended way to run the project. One entry point for both sides.

```bash
PYTHONPATH=src python -m autoeth.apps.tui
# or after pip install -e .
autoeth-tui
```

### Top-level menu

```
────────────────────────────────────────────────────
  AutoEth
────────────────────────────────────────────────────
  [1] Server
  [2] Client
  [q] Quit
```

### Server — configuration prompt

Before the server sub-menu you are asked for:

| Prompt | Default | Description |
|---|---|---|
| Listen IP (TCP) | `0.0.0.0` | IP the TCP servers bind to |
| Announce IP (SD) | `127.0.0.1` | IP advertised in SD OfferService options |
| Multicast iface IP | `0.0.0.0` | Interface for multicast join |

### Server — Automatic mode

Starts **all** TCP servers, the SD Announcer, the SD Listener, and **all**
UDP event publishers immediately. Blocks until you press `q`.

```
  TCP ports  : [30510]
  UDP events : ['fast_dynamics_event']
  SD group   : 239.0.0.2:30490

  Running — press [q] + Enter to stop.
```

### Server — Manual mode

TCP servers, SD Announcer and SD Listener start automatically and stay on.
UDP event publishers can be toggled individually.

```
  [1] fast_dynamics_event         [OFF]  50ms  multicast
  [2] control_method              [TCP]  port=30510  (always on)
  [3] testing_method              [TCP]  port=30510  (always on)

  [b] Back / stop server
```

Type a number to toggle the corresponding event on or off.
TCP methods are always served; they cannot be toggled off.

### Client — connection prompt

| Prompt | Notes |
|---|---|
| `[1] Manual server IP` | Type the server IP directly |
| `[2] Auto-discover via SD` | Listens on the SD multicast group for an OfferService announcement (3 s timeout) |

You are also asked for:
- **Multicast iface IP** — interface used to join multicast groups
- **Local bind IP** — IP reported to the server in SubscribeEventgroup options
- **Verbose** — print SD and SOME/IP details

### Client — Automatic mode

Subscribes to **all** events and calls **all** methods with their catalog
default values, then streams incoming datagrams until `q`.

```
  Subscribed to fast_dynamics_event
  Calling control_method with defaults {'steering_angle_deg': 0.0}

  [rx] fast_dynamics_event  #1  sid=0x1234  sess=3
       {'vehicle_speed_kph': 0.0, 'engine_rpm': 800.0, 'steering_angle_deg': 0.0}
```

### Client — Manual mode

```
  Events:
  [1] fast_dynamics_event         [OFF]  multicast  egid=0x0100  50ms

  Methods (one-shot):
  [2] control_method              [TCP]  port=30510  signals=[steering_angle_deg]
  [3] testing_method              [TCP]  port=30510  signals=[vehicle_speed_kph]

  [b] Back (stops all subscriptions)
```

- Selecting an **event** number toggles the subscription on / off.
  While on, received datagrams are printed to the terminal as they arrive.
  Unsubscribing sends a `StopSubscribeEventgroup` for unicast events.

- Selecting a **method** number prompts for signal values (Enter = catalog default),
  makes one TCP call and prints the response.

---

## Direct CLI usage (without the menu)

Useful for scripting, automated tests, or running node and client in separate
terminals during development.

### Starting the server (node)

```bash
# Minimal — all defaults from catalog
PYTHONPATH=src python -m autoeth.apps.node

# With explicit IPs
PYTHONPATH=src python -m autoeth.apps.node \
    --listen-ip   0.0.0.0    \
    --announce-ip 127.0.0.1  \
    --iface-ip    0.0.0.0    \
    --verbose

# Override SD group/port (useful when testing without a real multicast network)
PYTHONPATH=src python -m autoeth.apps.node \
    --sd-group 239.0.0.2 \
    --sd-port  30490     \
    --verbose
```

**Node flags**

| Flag | Default | Description |
|---|---|---|
| `--catalog` | `configs/catalog.yaml` | Path to catalog |
| `--listen-ip` | `0.0.0.0` | TCP bind address |
| `--announce-ip` | `127.0.0.1` | IP advertised in SD options |
| `--iface-ip` | `0.0.0.0` | Multicast interface IP |
| `--sd-group` | from catalog | Override SD multicast group |
| `--sd-port` | from catalog | Override SD UDP port |
| `--sd-ttl` | from catalog | Override SD multicast TTL |
| `--sd-iface` | from catalog | Override SD interface name |
| `--verbose` | off | Print every SOME/IP + SD event |

---

### Calling a TCP method

```bash
# Call control_method with steering_angle_deg = 10.5
PYTHONPATH=src python -m autoeth.apps.client \
    --call-method control_method            \
    --set steering_angle_deg=10.5           \
    --tcp-ip 127.0.0.1                      \
    --verbose

# Call testing_method with vehicle_speed_kph = 80.0
PYTHONPATH=src python -m autoeth.apps.client \
    --call-method testing_method            \
    --set vehicle_speed_kph=80.0            \
    --tcp-ip 127.0.0.1

# Let the client auto-discover the server IP via SD, then call
PYTHONPATH=src python -m autoeth.apps.client \
    --discover                              \
    --call-method control_method            \
    --set steering_angle_deg=5.0
```

---

### Subscribing to a UDP event

```bash
# Receive 10 datagrams from fast_dynamics_event (multicast)
PYTHONPATH=src python -m autoeth.apps.client \
    --sub-event fast_dynamics_event         \
    --count 10                              \
    --iface-ip 0.0.0.0                      \
    --verbose

# Auto-discover server, then subscribe (sends SubscribeEventgroup for unicast)
PYTHONPATH=src python -m autoeth.apps.client \
    --discover                              \
    --sub-event fast_dynamics_event         \
    --count 5
```

**Client flags**

| Flag | Default | Description |
|---|---|---|
| `--catalog` | `configs/catalog.yaml` | Path to catalog |
| `--tcp-ip` | `127.0.0.1` | Server IP for TCP calls |
| `--tcp-port` | from catalog | Override TCP port |
| `--timeout-ms` | `500` | TCP response timeout |
| `--call-method` | — | Method name to call (from catalog) |
| `--set` | — | `name=value`, repeatable |
| `--sub-event` | — | Event name to subscribe (from catalog) |
| `--udp-bind-ip` | `0.0.0.0` | Local UDP bind address |
| `--iface-ip` | `0.0.0.0` | Multicast join interface IP |
| `--count` | `5` | Number of datagrams to receive before exit |
| `--udp-timeout-s` | `2.0` | Per-datagram receive timeout |
| `--discover` | off | Enable SD auto-discover |
| `--sd-group` | from catalog | Override SD multicast group |
| `--sd-port` | from catalog | Override SD UDP port |
| `--sd-timeout-s` | `2.0` | SD listen timeout |
| `--verbose` | off | Print SD and SOME/IP details |

---

## Testing locally (two terminals)

Open two terminals in the project root with the virtualenv activated.

### Terminal 1 — Server

```bash
PYTHONPATH=src python -m autoeth.apps.node --verbose
```

Expected output:

```
[node] TCP server listening on 0.0.0.0:30510
[sd]   announcer -> ('239.0.0.2', 30490) every 1.0s
[sd]   listener on 239.0.0.2:30490
[udp]  pub fast_dynamics_event sid=0x1234 eid=0x0100 egid=0x0100 mode=multicast period_ms=50
```

### Terminal 2 — Client: call a method

```bash
PYTHONPATH=src python -m autoeth.apps.client \
    --call-method control_method            \
    --set steering_angle_deg=15.0           \
    --verbose
```

Expected output:

```
[tcp] connect 127.0.0.1:30510 method=control_method values={'steering_angle_deg': 15.0}
[tcp] rsp sid=0x1234 mid=0x0200 sess=1 values={'steering_angle_deg': 15.0}
```

### Terminal 2 — Client: subscribe to events

```bash
PYTHONPATH=src python -m autoeth.apps.client \
    --sub-event fast_dynamics_event         \
    --count 5                               \
    --verbose
```

Expected output:

```
[udp] sub event=fast_dynamics_event egid=0x0100 -> 0.0.0.0:30509 group=239.255.0.1 count=5
[udp] rx someip sid=0x1234 mid=0x0100 sess=1 values={'vehicle_speed_kph': 0.0, 'engine_rpm': 800.0, 'steering_angle_deg': 0.0}
...
```

### Terminal 2 — Client: auto-discover then call

```bash
PYTHONPATH=src python -m autoeth.apps.client \
    --discover                              \
    --call-method testing_method            \
    --set vehicle_speed_kph=60.0            \
    --verbose
```

### Both sides via TUI (single terminal each)

```bash
# Terminal 1
PYTHONPATH=src python -m autoeth.apps.tui
# → [1] Server → [1] Automatic

# Terminal 2
PYTHONPATH=src python -m autoeth.apps.tui
# → [2] Client → [2] Auto-discover → [1] Automatic
```

---

## Catalog summary

```bash
PYTHONPATH=src python -m autoeth.apps.catalog_summary
```

```
[catalog] version=1
[catalog] signals=3 services=1 messages=3
[catalog] services:
  - demo_service svc=0x1234 inst=0x0001 iface_ver=1 ver=1.0
[catalog] messages:
  - fast_dynamics_event id=1 kind=event  transport=udp signals=3 udp:multicast 239.255.0.1:30509 period_ms=50
  - control_method      id=2 kind=method transport=tcp signals=1 tcp:port=30510 timeout_ms=200
  - testing_method      id=3 kind=method transport=tcp signals=1 tcp:port=30510 timeout_ms=200
```
