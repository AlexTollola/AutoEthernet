# AutoEth Architecture

This document describes the SOME/IP service architecture, data flow, and signal organization used in the AutoEth project.

---

## Overview

AutoEth simulates an automotive Ethernet network with multiple ECUs communicating via SOME/IP protocol:

- **TCP Methods** - Reliable request/response for writing commands to the server database
- **UDP Events** - Periodic multicast broadcasts of current vehicle state
- **SOME/IP-SD** - Service discovery for automatic endpoint detection

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              VEHICLE NETWORK                                     │
└─────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐         TCP Methods (Write)          ┌─────────────────────┐
    │  ADAS ECU   │ ───────────────────────────────────► │                     │
    │  (Client)   │  set_steering, set_brakes            │   CHASSIS SERVER    │
    └─────────────┘                                      │   (Database)        │
                                                         │                     │
    ┌─────────────┐         TCP Methods (Write)          │  ┌───────────────┐  │
    │  ACC ECU    │ ───────────────────────────────────► │  │ steering_angle│  │
    │  (Client)   │  set_throttle                        │  │ brake_pressure│  │
    └─────────────┘                                      │  │ vehicle_speed │  │
                                                         │  │ yaw_rate      │  │
    ┌─────────────┐         TCP Methods (Write)          │  └───────────────┘  │
    │  TCU        │ ───────────────────────────────────► │                     │
    │  (Client)   │  set_gear                            │                     │
    └─────────────┘                                      └──────────┬──────────┘
                                                                    │
    ┌─────────────┐         TCP Methods (Write)                     │
    │  Wheel ECU  │ ───────────────────────────────────►            │
    │  (Client)   │  set_vehicle_speed                              │
    └─────────────┘                                                 │
                                                                    │ UDP Events
                                                                    │ (Broadcast)
                                                                    ▼
                                                         ┌─────────────────────┐
    ┌─────────────┐  UDP Subscribe                       │ chassis_dynamics    │
    │  Logger     │ ◄─────────────────────────────────── │ (25ms multicast)    │
    │  (Client)   │  steering, brake, speed, yaw         │                     │
    └─────────────┘                                      │ powertrain_status   │
                                                         │ (25ms multicast)    │
    ┌─────────────┐  UDP Subscribe                       └─────────────────────┘
    │  Dashboard  │ ◄───────────────────────────────────
    │  (Client)   │  rpm, speed, gear
    └─────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│  LEGEND                                                                          │
│  ─────────►  TCP Request/Response (reliable, write to database)                 │
│  ◄─────────  UDP Multicast (periodic broadcast of database state)               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Services

### Service Summary

| Service | Service ID | Instance ID | TCP Port | UDP Multicast | Description |
|---------|------------|-------------|----------|---------------|-------------|
| chassis_service | 0x1001 | 0x0001 | 30501 | 239.255.1.1:30511 | Steering, brakes, vehicle dynamics |
| powertrain_service | 0x1002 | 0x0001 | 30502 | 239.255.1.2:30512 | Engine, throttle, transmission |

### Future Services (not yet implemented)

| Service | Service ID | Description |
|---------|------------|-------------|
| body_service | 0x1003 | Lights, doors, wipers, windows |
| adas_service | 0x1004 | Cruise control, lane keeping, collision avoidance |
| climate_service | 0x1005 | HVAC, seat heating, defrost |
| infotainment_service | 0x1006 | Audio, navigation, connectivity |

---

## Signals

### Chassis Signals

| Signal | Type | Scale | Offset | Unit | Range | Default | Description |
|--------|------|-------|--------|------|-------|---------|-------------|
| steering_angle | i16 | 0.1 | 0 | deg | -540 to +540 | 0.0 | Steering wheel angle (+ = right) |
| brake_pressure | u16 | 0.1 | 0 | bar | 0 to 200 | 0.0 | Brake system pressure |
| vehicle_speed | u16 | 0.01 | 0 | kph | 0 to 655 | 0.0 | Current vehicle speed |
| yaw_rate | i16 | 0.01 | 0 | deg/s | -327 to +327 | 0.0 | Vehicle rotation rate (+ = clockwise) |

### Powertrain Signals

| Signal | Type | Scale | Offset | Unit | Range | Default | Description |
|--------|------|-------|--------|------|-------|---------|-------------|
| throttle_position | u8 | 1.0 | 0 | % | 0 to 100 | 0.0 | Accelerator pedal position |
| engine_rpm | u16 | 1.0 | 0 | rpm | 0 to 8000 | 800.0 | Engine rotational speed |
| engine_torque | i16 | 0.1 | 0 | Nm | -500 to +500 | 0.0 | Current engine torque output |
| gear_position | i8 | 1.0 | 0 | - | -1 to 6 | 0 | Gear (-1=R, 0=N, 1-6=forward) |

---

## Methods (TCP)

Methods are used to **write data to the server database**. Each method call:
1. Client sends a TCP request with signal values
2. Server writes values to the database
3. Server responds with the values that were written (confirmation)

### Chassis Methods

| Method | Method ID | Port | Signals | Description |
|--------|-----------|------|---------|-------------|
| set_steering | 0x0001 | 30501 | steering_angle | Set steering wheel angle |
| set_brakes | 0x0002 | 30501 | brake_pressure | Set brake pressure |
| set_vehicle_speed | 0x0003 | 30501 | vehicle_speed | Report current speed (from wheel sensor) |
| set_yaw_rate | 0x0004 | 30501 | yaw_rate | Report yaw rate (from IMU) |

### Powertrain Methods

| Method | Method ID | Port | Signals | Description |
|--------|-----------|------|---------|-------------|
| set_throttle | 0x0001 | 30502 | throttle_position | Set throttle pedal position |
| set_engine_rpm | 0x0002 | 30502 | engine_rpm | Report engine RPM (from engine ECU) |
| set_engine_torque | 0x0003 | 30502 | engine_torque | Report engine torque |
| set_gear | 0x0004 | 30502 | gear_position | Set/report gear position |

---

## Events (UDP)

Events **broadcast the current database state** periodically via UDP multicast. Subscribers receive updates without polling.

### Event Summary

| Event | Event ID | Eventgroup ID | Multicast Group | Port | Period | Signals |
|-------|----------|---------------|-----------------|------|--------|---------|
| chassis_dynamics_event | 0x8001 | 0x0001 | 239.255.1.1 | 30511 | 25ms | steering_angle, brake_pressure, vehicle_speed, yaw_rate |
| powertrain_status_event | 0x8001 | 0x0001 | 239.255.1.2 | 30512 | 25ms | throttle_position, engine_rpm, engine_torque, gear_position |

### Event Timing

| Category | Period | Frequency | Use Case |
|----------|--------|-----------|----------|
| Safety-critical | 25ms | 40 Hz | Chassis dynamics, powertrain state |
| Comfort features | 500ms | 2 Hz | Body status, climate (future) |
| Infotainment | 1000ms | 1 Hz | Media status, navigation (future) |

---

## Network Configuration

### Port Allocation

| Port Range | Protocol | Purpose |
|------------|----------|---------|
| 30490 | UDP | SOME/IP-SD (Service Discovery) |
| 30501-30509 | TCP | Service methods |
| 30511-30519 | UDP | Service events (multicast) |

### Multicast Groups

| Group | Service |
|-------|---------|
| 239.0.0.2 | SOME/IP-SD announcements |
| 239.255.1.1 | Chassis events |
| 239.255.1.2 | Powertrain events |
| 239.255.1.3 | Body events (future) |
| 239.255.1.4 | ADAS events (future) |

---

## Message Format

All messages use the SOME/IP header format with optional E2E protection.

### SOME/IP Header (16 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────┼───────────────────────────────┤
│          Service ID           │           Method ID           │
├───────────────────────────────────────────────────────────────┤
│                            Length                             │
├───────────────────────────────┼───────────────────────────────┤
│          Client ID            │          Session ID           │
├───────────────┼───────────────┼───────────────┼───────────────┤
│  Protocol Ver │ Interface Ver │  Message Type │  Return Code  │
├───────────────┴───────────────┴───────────────┴───────────────┤
│                         Payload...                            │
└───────────────────────────────────────────────────────────────┘
```

### E2E Protection (4 bytes trailer)

When enabled, a CRC16-CCITT trailer is appended:

```
├───────────────────────────────┼───────────────────────────────┤
│           Counter             │            CRC16              │
└───────────────────────────────┴───────────────────────────────┘
```

---

## Example Use Cases

### Use Case 1: ADAS Steering Control

1. ADAS ECU calculates required steering angle (45°)
2. ADAS calls `set_steering(steering_angle=45.0)` via TCP
3. Server stores `steering_angle=45.0` in database
4. Server responds with `{steering_angle: 45.0}` (confirmation)
5. Next `chassis_dynamics_event` includes `steering_angle=45.0`
6. All subscribers (logger, dashboard) receive the updated value

### Use Case 2: Speed Monitoring

1. Wheel speed sensor ECU measures 60 kph
2. Wheel ECU calls `set_vehicle_speed(vehicle_speed=60.0)` via TCP
3. Server stores and confirms
4. Dashboard subscriber receives speed in `chassis_dynamics_event`
5. Dashboard displays current speed to driver

### Use Case 3: Emergency Braking

1. ADAS detects obstacle, needs emergency brake
2. ADAS calls `set_brakes(brake_pressure=150.0)` via TCP
3. ADAS calls `set_throttle(throttle_position=0.0)` via TCP
4. Server updates both values immediately
5. All subscribers receive updated state within 25ms

---

## Extending the Architecture

### Adding a New Service

1. Define service in `catalog.yaml` under `services:`
2. Add signals under `signals:`
3. Add methods (TCP) under `messages:` with `kind: method`
4. Add events (UDP) under `messages:` with `kind: event`
5. Assign unique:
   - Service ID (0x1001, 0x1002, ...)
   - TCP port (30501, 30502, ...)
   - Multicast group (239.255.1.x)
   - UDP port (30511, 30512, ...)

### Adding a New Signal

1. Add signal definition under `signals:`
2. Add to relevant method(s) if it should be writable
3. Add to relevant event(s) if it should be broadcast
4. Update this documentation

---

## References

- AUTOSAR SOME/IP Protocol Specification
- AUTOSAR SOME/IP Service Discovery Protocol Specification
- AUTOSAR E2E Protection Specification
- ISO 11898 (CAN) - for comparison with traditional automotive networks
