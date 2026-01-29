# AutoEth Frame / Message Format (Raw Transport)

This document defines how AutoEth builds message bytes over UDP and TCP, and how the format changes when E2E protection is enabled.

---

## 1) UDP payload

One UDP datagram carries exactly one AutoEth message:

+---------+-------------------+----------------------+--------------------+
| msg_id  | AutoEth Header    | Signal Payload       | E2E Trailer (opt)  |
| 1 byte  | 3 bytes           | N bytes              | 4 bytes            |
+---------+-------------------+----------------------+--------------------+

### msg_id (u8)
Message selector (0..255). Maps to messages[] entry in configs/catalog.yaml.

### AutoEth Header (3 bytes, !BH)
- proto_ver: u8 (current = 1)
- seq: u16 (monotonic per publisher, wraps at 65535)

### Signal Payload (N bytes)
Signals are packed in the exact order listed in messages[].signals:

Per signal:
1) raw = round((phys - offset)/scale)
2) clamp to integer range for type
3) pack in network order
   u8=!B i8=!b u16=!H i16=!h u32=!I i32=!i

Payload size:
N = sum(sizeof(type_i))

---

## 2) E2E Trailer (optional)

If messages[].e2e.enabled = true, append trailer:

Trailer layout (4 bytes, !HH):
- counter: u16
- crc16: u16

Constraints:
- counter must equal AutoEth Header seq

CRC16 algorithm:
- CRC-16/CCITT-FALSE
- poly=0x1021 init=0xFFFF refin/out=False xorout=0
- coverage: (Signal Payload + counter)
  (CRC field itself is excluded)

So the “post-header payload” becomes:
- E2E OFF: SignalPayload
- E2E ON : SignalPayload + counter + crc16

---

## 3) TCP stream framing

TCP is a byte stream, so each AutoEth message is framed:

+---------------------+----------------------------------------------+
| length_prefix       | frame_body                                   |
| u32 BE (!I)         | AutoEth message bytes (same as UDP payload)  |
+---------------------+----------------------------------------------+

frame_body:
[msg_id:1][proto_ver:1][seq:2][SignalPayload:N][E2E:optional 4]

---

## 4) Size example (fast_dynamics_event)

Signals:
- vehicle_speed_kph: u16 (2)
- engine_rpm: u16 (2)
- steering_angle_deg: i16 (2)
SignalPayload = 6 bytes

AutoEth Header = 3 bytes

UDP total:
- E2E OFF: 1 + 3 + 6 = 10 bytes
- E2E ON : 1 + 3 + 6 + 4 = 14 bytes

Subscriber note:
Most validators unpack header first, so “len(pl)” refers to bytes after the AutoEth header:
- E2E OFF => len(pl)=6
- E2E ON  => len(pl)=10
