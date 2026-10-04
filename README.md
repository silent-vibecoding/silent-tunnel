# Silent Tunnel 🔇

**A dedicated Iran ⇄ abroad tunnel** — TLS disguise with a fake SNI, an inner
ChaCha20-Poly1305 encryption layer, connection pooling and multiplexing, an
interactive TUI and a one-line pairing token.

Silent Tunnel combines the best techniques of
[RTT](https://github.com/radkesvat/ReverseTlsTunnel),
[Hedioum](https://github.com/hedioum/Hedioum-Pool-Tunnel),
[BackPack](https://github.com/AminMGMT/BackPack) and
[Easy-Mesh](https://github.com/Musixal/Easy-Mesh) into one lightweight,
transparent and resilient tunnel for the classic "x-ui/3x-ui panel on the
abroad server" setup.

## ⚡ One-line install

On any VPS (Debian/Ubuntu) as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/silent-vibecoding/silent-tunnel/main/install.sh)
```

The script installs the right binary for your architecture and opens the
**interactive menu** — pick option 1 (hub) on the Iran server and option 2
(node) on the abroad server. If GitHub is unreachable from the server, copy a
`silent-linux-*` binary over manually:
`install -m755 silent-linux-amd64 /usr/local/bin/silent && silent`.

## How it works

```
user ──▶ Iran server (hub) ═══ tunnel ═══▶ abroad server (node) ──▶ x-ui / 3x-ui
         forwarded ports         TLS + fake SNI             service on 127.0.0.1
```

- **Reverse:** the *abroad* server dials the *Iran* server — the abroad side
  needs no open inbound ports at all.
- **Camouflage:** the connection is a real TLS session with a configurable
  SNI (default `cloudflare.com`) and a browser-like ALPN.
- **Inner encryption:** after TLS everything travels in ChaCha20-Poly1305
  frames whose keys are derived from the token via HKDF — the token never
  crosses the wire, and the payload stays encrypted even if TLS were broken.
- **Anti-probe:** any scanner that fails authentication gets a plain
  nginx-style `404 Not Found` page.
- **Connection pool:** 3 parallel connections by default with automatic
  reconnection (exponential backoff + jitter); user connections are spread
  across healthy sessions, so a single connection dying is not noticeable.
- **Multiplexing:** hundreds of user connections per physical connection via
  [smux](https://github.com/xtaci/smux) with large buffers for high-latency links.
- **Certificate pinning:** the SHA-256 fingerprint of the hub certificate
  travels inside the pairing token — a changed certificate breaks the
  connection, like SSH's security model.

## Quick start

Grab a binary from `bin/` (or build with `./build.sh`) and put it on both servers.

### 1) Iran server (hub)

```bash
sudo ./silent            # menu → option 1 (hub)
```

The wizard asks for: public IP, tunnel port (default 443), fake SNI and the
ports to forward abroad. It prints the **pairing token** (`st1_...`) and the
`ufw` commands to open the firewall.

Non-interactive equivalent:

```bash
sudo silent setup-hub --port 443 --sni cloudflare.com --maps 2087,44301
```

`--maps` accepts two shapes: `2087,44301` (same-port — like RTT's multiport)
or `2087=8443` (explicit mapping).

### 2) Abroad server (node)

```bash
sudo ./silent            # menu → option 2 (node) → paste the token
```

Non-interactive equivalent:

```bash
sudo silent setup-node --token st1_...
sudo silent node         # or menu option 4 → install the systemd service
```

### 3) Always-on service

Pick **option 4 (install the systemd service)** in the menu, or:

```bash
sudo silent install      # creates and enables silent-hub or silent-node
```

## 🖥 Interactive menu

Running `silent` with no arguments opens the arrow-key menu — everything
without memorized commands:

```
▸ Set this server up as the hub (Iran)
  Set this server up as the node (abroad)
  Run the tunnel (based on the existing config)
  Install the systemd service (start on boot)
  Live status
  Health check (doctor)
  Show the pairing token
  Full removal (uninstall)
  Exit
```

## 🧪 Troubleshooting & status

```bash
silent doctor   # certificate, ports, server clock, hub reachability, full handshake
silent status   # uptime, healthy sessions, open streams, down/up bytes, reconnects
silent token    # print the pairing token again (hub only)
```

Service logs: `journalctl -u silent-hub -f` or `journalctl -u silent-node -f`

## 📁 Files

| Path (Linux) | Content |
|---|---|
| `/etc/silent/hub.json` | hub config (Iran) |
| `/etc/silent/cert.pem`, `cert.key` | hub self-signed certificate (10 years) |
| `/etc/silent/node.json` | node config (abroad) |
| `/var/lib/silent/status.json` | live daemon status (every 5 s) |
| `/etc/systemd/system/silent-*.service` | services |

On Windows everything lives under `%LOCALAPPDATA%\silent`.

## 🔐 Security

- **Treat the pairing token like a private key** — anyone holding it can use
  the tunnel. Leaked? Wipe the hub config, re-run `setup-hub` (new key and
  certificate) and re-run `setup-node` with the new token.
- Keys are derived with HKDF-SHA256 from the token plus a random per-connection
  salt; nonces use a per-direction monotonic counter, so replay and reordering
  always fail to open.
- The auth window is ±2 minutes — keep both servers' clocks synced with NTP
  (`doctor` checks this).
- The tunnel is a transparent TCP pipe; the real encryption of your traffic is
  whatever runs behind it (V2Ray, SSH, ...).

## 🏗 Build from source

```bash
git clone https://github.com/silent-vibecoding/silent-tunnel && cd silent-tunnel
./build.sh        # output: bin/silent-linux-amd64, silent-linux-arm64, silent-windows-amd64.exe
go test ./...     # unit tests + a full end-to-end test
```

Only Go plus [smux](https://github.com/xtaci/smux) and [x/crypto](https://golang.org/x/crypto) — no heavy dependencies.

## 🗺 Roadmap

- [ ] UDP over the tunnel (QUIC/HTTP3 clients)
- [ ] Multi-mimic connection pool (SSH/cPanel/Grafana, à la Hedioum) with protocol rotation
- [ ] WSS transport through CDNs with a Chrome uTLS handshake (à la BackPack)
- [ ] L3 mode (full IP tunnel, à la BackPack Direct / EasyTier)

## 📄 License

MIT — and a reminder: you are responsible for how you use it. This tool is
built for keeping free and secure access to the internet.
