# Architecture (Stage 1)

This stage validates the Linux networking stack and message transport mechanisms before introducing SOME/IP.

Layers (conceptual):
- Application: publisher/subscriber apps
- Presentation: serialization of signals into a binary payload
- Transport: UDP unicast or UDP multicast
- Network: IPv4
- Data link: Ethernet (MAC, optional VLAN later)
- Physical: RJ45 on Pi/WSL host (T1 comes later via media converters)

Artifacts:
- configs/signals.yaml: signal catalog (DBC-like)
- src/autoeth/codec.py: serialization/deserialization
- src/autoeth/udp_pub.py: publisher
- src/autoeth/udp_sub.py: subscriber
- scripts/capture.sh: tcpdump helper

## Stage 1.5 (Hybrid UDP/TCP)

Adds config-driven message groups (`configs/messages.yaml`):

- UDP **event** message groups for periodic / streaming signals (publish-subscribe).
- TCP **method** request/response message groups for reliable commands/config transfers.

TCP uses length-prefixed framing:
- [u32_be length][frame_bytes...]
where `frame_bytes` uses the same `codec.encode_frame()` header+payload format.
