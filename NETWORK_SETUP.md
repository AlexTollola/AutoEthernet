# Network Setup Guide (Direct Ethernet / Automotive Ethernet)

This section should be added to the main README.md after the "Installation" section.

---

## Network Setup (Direct Ethernet / Automotive Ethernet)

When connecting two devices directly via Ethernet (or through automotive Ethernet converters like 100BASE-T1), you need to configure static IPs since there's no DHCP server.

### Prerequisites

- Two Raspberry Pi devices (or any Linux machines)
- Ethernet cables
- (Optional) 100BASE-T1 automotive Ethernet converters

### Step 1: Verify Ethernet link is up

On both devices:
```bash
ethtool eth0 | grep "Link detected"
```

You should see `Link detected: yes`. If not, check cables and converters.

### Step 2: Assign static IPs using NetworkManager

**On the Server:**
```bash
sudo nmcli con add type ethernet con-name eth0-static ifname eth0 ip4 10.0.0.1/24
sudo nmcli con up eth0-static
```

**On the Client:**
```bash
sudo nmcli con add type ethernet con-name eth0-static ifname eth0 ip4 10.0.0.2/24
sudo nmcli con up eth0-static
```

> **Note:** Using `nmcli` ensures the IP persists across reboots and prevents NetworkManager from removing manual IP assignments.

### Step 3: Verify IPs are assigned

On both devices:
```bash
ip addr show eth0 | grep inet
```

Expected output:
- Server: `inet 10.0.0.1/24 scope global eth0`
- Client: `inet 10.0.0.2/24 scope global eth0`

### Step 4: Test connectivity

From the client:
```bash
ping 10.0.0.1
```

From the server:
```bash
ping 10.0.0.2
```

You should see replies. If not, check the troubleshooting section below.

### Step 5: Update network.yaml

Edit `configs/network.yaml` to use the Ethernet IPs:

```yaml
server:
  listen_ip: "0.0.0.0"
  announce_ip: "10.0.0.1"
  multicast_iface_ip: "10.0.0.1"

client:
  server_ip: "10.0.0.1"
  multicast_iface_ip: "10.0.0.2"
  bind_ip: "10.0.0.2"
```

### Step 6: Run the TUI

**On the Server:**
```bash
PYTHONPATH=src python -m autoeth.apps.tui
# Select [1] Server → accept defaults → [1] Automatic
```

**On the Client:**
```bash
PYTHONPATH=src python -m autoeth.apps.tui
# Select [2] Client → [2] Auto-discover (or [1] Manual with IP 10.0.0.1)
```

---

## Troubleshooting

### Link is UP but no communication

1. **Check converters have power** - Status LEDs should be on
2. **Verify link on both ends:**
   ```bash
   ethtool eth0 | grep -E "Speed|Link"
   ```
3. **Check for traffic:**
   ```bash
   sudo tcpdump -i eth0 -n -c 10
   ```

### IP address disappears

NetworkManager may be resetting it. Use the `nmcli` commands above instead of `ip addr add`.

To remove a conflicting connection:
```bash
nmcli con show
sudo nmcli con delete "Wired connection 1"  # or whatever the old name is
```

### Multicast not working over WiFi

WiFi access points often block multicast between wireless clients (AP isolation). Solutions:

1. **Use Ethernet instead** (recommended)
2. **Switch to unicast mode** in `catalog.yaml`:
   ```yaml
   udp:
     mode: unicast  # instead of multicast
     port: 30509
   ```
3. **Check router settings** - disable AP isolation, enable multicast/IGMP

### Verify multicast group membership

```bash
netstat -gn | grep 239
```

You should see `239.255.0.1` (or your configured multicast group) listed.

### Check multicast traffic

On the server (sending):
```bash
sudo tcpdump -i eth0 udp port 30509 -n
```

On the client (receiving):
```bash
sudo tcpdump -i eth0 udp port 30509 -n
```

If packets appear on the server but not the client, there's a network/routing issue.

---

## Quick Reference

| Device | Static IP | Role |
|--------|-----------|------|
| Server | 10.0.0.1  | Publishes events, serves methods |
| Client | 10.0.0.2  | Subscribes to events, calls methods |

| Port | Protocol | Purpose |
|------|----------|---------|
| 30490 | UDP | SOME/IP-SD (service discovery) |
| 30509 | UDP | Event multicast |
| 30510 | TCP | Method requests/responses |
