# Layer API (Current)

Stable APIs between layers for the AutoEth project.

---

## autoeth.core.transport.udp
Purpose: UDP socket creation, multicast join, destination resolution.

- make_socket(iface=None, ttl=1, bind_ip="0.0.0.0", bind_port=0, reuse=True) -> socket
- join_multicast(sock, group, iface_ip="0.0.0.0")
- dest(mode, mcast_group, unicast_ip, port) -> (ip, port)

---

## autoeth.core.transport.tcp
Purpose: TCP framing + thin server wrapper.

- send_frame(sock, payload)
- recv_frame(sock, max_len=...) -> payload

Wrappers:
- TcpServer(listen_ip, port, handler).start()/stop()

TCP framing:
- u32 length prefix (network order, !I)
- followed by a single AutoEth Message (see docs/frame_format.md)

---

## autoeth.core.serialization.codec
Purpose: DBC-like signal serialization.

- encode(signals, values) -> bytes
- decode(signals, payload) -> dict
- encoded_size(signals) -> int

Rules:
- raw = round((phys - offset) / scale)
- clamp to type range
- pack sequentially in network byte order

---

## autoeth.core.serialization.index
Purpose: deterministic signal lookup.

- SignalIndex.from_signals(signals) -> index
- index.subset(names) -> [SignalDef]

---

## autoeth.core.config
Purpose: load + validate the single canonical catalog file.

- load_catalog(path) -> Catalog
- Catalog.validate()

Source of truth:
- configs/catalog.yaml

---

## autoeth.core.validation.frame
Purpose: AutoEth header pack/unpack used by UDP and TCP message bodies.

Constants:
- PROTO_VER = 1

APIs:
- pack_header(seq, proto_ver=PROTO_VER) -> bytes
- unpack_header(data) -> (FrameHeader, payload_after_header)

Header layout (network byte order, !BH):
- proto_ver: u8
- seq: u16

---

## autoeth.core.validation.e2e
Purpose: optional E2E-style trailer (counter + CRC16).

CRC:
- CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, refin/out=False, xorout=0)

APIs:
- wrap(payload, counter) -> payload_with_trailer
- unwrap(payload_with_trailer) -> (payload, counter)

Trailer layout (network byte order, !HH):
- counter: u16
- crc16: u16

---

## autoeth.protocols.someip.header (future)
Purpose: SOME/IP header helpers for later integration.
