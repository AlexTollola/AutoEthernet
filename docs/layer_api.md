# Step 1 API Surface

Defines the frozen APIs between layers.

## core.transport.udp
- `make_socket(iface=None, ttl=1, bind_ip="0.0.0.0", bind_port=0, reuse=True) -> socket`
- `join_multicast(sock, group, iface_ip="0.0.0.0")`
- `dest(mode, mcast_group, unicast_ip, port) -> (ip, port)`

## core.transport.tcp
- `send_frame(sock, payload)`
- `recv_frame(sock, max_len=...) -> payload`
- `TcpServer(listen_ip, port, handler).start()/stop()`
- `TcpClient(ip, port, timeout_ms).connect() -> socket`

## core.serialization.codec
- `encode(signals, values) -> bytes`
- `decode(signals, payload) -> dict`

## core.serialization.index
- `SignalIndex.from_signals(signals) -> index`
- `index.subset(names) -> [SignalDef]`

## protocols.someip.header
- `build_message(...) -> bytes`
- `parse_message(data) -> (SomeIpHeader, payload)`
