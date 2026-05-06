# quic-sol slot-stream

Stream confirmed Solana block transactions in real time over QUIC.

## What you get
## Usage

```bash
cargo run --bin slot-ingress -- <server> <rpc-url>
```

## Example

```bash
cargo run --bin slot-ingress -- 216.128.152.28:4433 "https://mainnet.helius-rpc.com/?api-key=YOUR_KEY"
```


## rpc-health indicator

The `rpc-health` field shows how well your RPC is keeping up:

| indicator | latency | meaning |
|-----------|---------|---------|
| 🟢 LOW | < 1.5s | RPC keeping up perfectly |
| 🟡 MID | 1.5s–5s | RPC under load |
| 🔴 HIGH | 5s–20s | RPC struggling |
| ⚫ LIMIT | 20s–30s | Consider switching RPC |
| 💀 OFFLINE | > 30s | RPC is down |

## Notes

- Use a dedicated or paid RPC endpoint for best performance
- Shared free-tier RPCs could show higher rpc-health indicators
- Server location: Chicago, IL — best latency from US/EU
