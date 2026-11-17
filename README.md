# Secure Tunnel VPN (Server & Client)
### Computer Networks (CN) Project — Group 15

**Team Members:**
- **Mayank Shrivastava** (2401MC16)
- **Bhavya Sharma** (2401MC08)
- **Udit Garg** (2401MC07)
- **Ranveer Gupta** (2401MC20)

A high-performance, modular, cross-platform VPN implementation in Python featuring:
- **Layer 3 IP Packet Tunneling:** Virtual network interface (`/dev/net/tun` on Linux, Wintun on Windows) for true system-wide IP routing and ICMP/TCP/UDP packet forwarding.
- **Layer 4 Encrypted User-Space Tunneling:** RFC 1928 SOCKS5 encrypted proxy tunnel requiring **zero root/admin privileges and zero kernel drivers**.
- **Modern Cryptography:** Enforces **TLS 1.3** with AES-256-GCM / ChaCha20-Poly1305, Perfect Forward Secrecy (PFS), mutual certificate authentication (mTLS), and shared secret tokens.
- **Multiplexed Wire Protocol:** Custom binary framing engine with magic headers, stream IDs, and keepalive heartbeat ping/pong.
- **Zero External Dependencies:** Built entirely with Python's standard library (`ssl`, `socket`, `struct`, `threading`, `ipaddress`).

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                                  CLIENT HOST                                      |
|                                                                                   |
|  [Applications: Browser / curl / etc.]                                            |
|          |                                                                        |
|          +--> [Local SOCKS5 Proxy 127.0.0.1:1080] (L4 Mode)                       |
|          |                                     |                                  |
|          +--> [Virtual TUN Adapter: 10.8.0.2]  (L3 Mode)                          |
|                            |                                                      |
|               +------------v------------+                                         |
|               | Frame Encapsulation     | [Magic 2B | Type 1B | Stream 4B | Len 2B]
|               +------------+------------+                                         |
|                            |                                                      |
|               +------------v------------+                                         |
|               | TLS 1.3 / mTLS Engine   | AES-256-GCM / ChaCha20-Poly1305         |
|               +------------+------------+                                         |
+----------------------------|------------------------------------------------------+
                             | Encrypted TCP Tunnel (WAN/LAN)
+----------------------------|------------------------------------------------------+
|                            v                                                      |
|               +------------+------------+                                         |
|               | TLS 1.3 / mTLS Engine   | Handshake & Certificate Verification    |
|               +------------+------------+                                         |
|                            |                                                      |
|               +------------v------------+                                         |
|               | Frame Decapsulation     | Stream Multiplexer / Packet Router      |
|               +------------+------------+                                         |
|                            |                                                      |
|          +-----------------+-----------------+                                    |
|          | (L3 IP Packets)                   | (L4 TCP Streams)                   |
|          v                                   v                                    |
|   [Server TUN Interface: 10.8.0.1]     [Server Outbound TCP Egress]               |
|          | (iptables NAT MASQUERADE)         |                                    |
|          v                                   v                                    |
|   [Public Internet Gateway]            [Public Internet Gateway]                  |
|                                                                                   |
|                                  SERVER HOST                                      |
+-----------------------------------------------------------------------------------+
```

---

## Directory Structure

```
d:\vpn\
├── README.md                 # Complete documentation and setup guide
├── cert_gen.py               # Automated PKI generator (CA, Server, Client certs)
├── vpn_server.py             # VPN Server implementation
├── vpn_client.py             # VPN Client CLI implementation
├── vpn_gui.py                # Native Desktop GUI with Connect button (Tkinter)
├── web_gui.py                # Web Browser Dashboard (HTML5/CSS3/REST API)
├── core/
│   ├── __init__.py           # Core package exports
│   ├── protocol.py           # Framing format, packet types, and serialization
│   ├── crypto.py             # TLS 1.3 context builder and authentication
│   ├── tun_interface.py      # Abstract Linux/Windows/Simulated TUN driver
│   ├── packet_parser.py      # IPv4/IPv6 packet header inspection and logger
│   └── proxy_handler.py      # SOCKS5 multiplexer and server egress engine
└── scripts/
    ├── test_vpn.py           # Automated end-to-end integration test suite
    ├── generate_certs.ps1    # PowerShell cert generator for Windows
    ├── generate_certs.sh     # Bash cert generator for Linux/macOS
    └── setup_linux_server.sh # Linux gateway NAT & IP forwarding configuration
```

---

## Wire Protocol Specification

Every packet transmitted across the TLS tunnel is wrapped in a 9-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic (0x56 0x50)       |   Type (1B)   |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                       Stream ID (4B)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length (2B)     |       Payload (N Bytes)...    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|---|---|---|
| **Magic** | 2 Bytes | Fixed signature `b'VP'` (`0x56 0x50`) for frame sync |
| **Type** | 1 Byte | Packet opcode (see table below) |
| **Stream ID** | 4 Bytes | Connection stream ID (0 for L3 packets; >0 for L4 streams) |
| **Length** | 2 Bytes | Big-endian unsigned 16-bit integer (max 65,535 bytes) |
| **Payload** | N Bytes | Encapsulated raw IP packet or JSON control message |

### Packet Types:
- `0x01` (`PKT_HANDSHAKE_REQ`): Client authentication & IP request
- `0x02` (`PKT_HANDSHAKE_RESP`): Server parameters (Assigned IP, Gateway, DNS, MTU)
- `0x03` (`PKT_DATA`): Raw Layer 3 IP Packet (IPv4 / IPv6)
- `0x04` (`PKT_PING`): Heartbeat keepalive ping with timestamp
- `0x05` (`PKT_PONG`): Heartbeat response (used to compute RTT latency)
- `0x06` (`PKT_DISCONNECT`): Clean teardown notice
- `0x10` (`PKT_PROXY_CONNECT`): Open outbound TCP stream (`host`, `port`)
- `0x12` (`PKT_PROXY_DATA`): Multiplexed application payload
- `0x13` (`PKT_PROXY_CLOSE`): Stream teardown

---

## Quick Start Guide

### Step 1: Generate PKI Certificates
Generate Root CA, Server Certificate (with SAN), and Client Certificate in one command:

```powershell
# Windows PowerShell
python cert_gen.py --out-dir certs --server-san "127.0.0.1,localhost"

# Or on Linux / macOS:
python3 cert_gen.py --out-dir certs --server-san "127.0.0.1,localhost,your-server-domain.com"
```

Files produced in `certs/`:
- `ca.crt`: Root CA Certificate (trusted by client & server)
- `server.crt` / `server.key`: VPN Server certificate and private key
- `client.crt` / `client.key`: VPN Client certificate and private key (for mTLS)

---

### Step 2: Run Automated Integration Tests
Verify the complete handshake, packet encryption, Layer 3 routing, and SOCKS5 proxy tunnel:

```bash
python scripts/test_vpn.py
```

Expected output:
```
[INFO] [Test 1/5] PKI certificates verified.
[INFO] [Test 2/5] Initializing VPN Server on port 18443 (Dual Mode)...
[INFO] [Test 3/5] Initializing VPN Client and establishing TLS 1.3 tunnel...
[INFO] [OK] Handshake verified! Virtual IP 10.8.0.2 assigned successfully.
[INFO] [Test 4/5] Injecting synthetic Layer 3 packet into tunnel...
[INFO] [OK] Layer 3 packet encapsulated, encrypted, and processed without errors.
[INFO] [Test 5/5] Testing SOCKS5 Tunnel (127.0.0.1:11080 -> Target 19999)...
[INFO] [OK] Encrypted Tunnel verified! Payload successfully tunneled and echoed: ECHO: SecureTunnelPayload123
[INFO] ==================================================
[INFO]       ALL 5 VPN INTEGRATION TESTS PASSED!         
[INFO] ==================================================
```

---

### Step 3: Start the VPN Server

#### Production Linux Server (with full L3 TUN routing):
```bash
# 1. Enable NAT and IP forwarding (run once on server)
sudo bash scripts/setup_linux_server.sh

# 2. Launch the VPN Server
sudo python3 vpn_server.py --port 8443 --mode dual --verify-client --verbose
```

#### Development / Windows Server:
```powershell
python vpn_server.py --port 8443 --mode dual --verbose
```

Server Options:
- `--host`: Listen address (default: `0.0.0.0`)
- `--port`: Listen port (default: `8443`)
- `--mode`: `dual` (L3 TUN + L4 Proxy), `tun` (L3 only), or `proxy` (L4 only)
- `--net`: Virtual network CIDR (default: `10.8.0.0/24`)
- `--server-ip`: Server virtual IP (default: `10.8.0.1`)
- `--verify-client`: Enforce mTLS client certificate validation
- `--auth-secret`: Shared secret token for authorization
- `--verbose`: Print live IP packet headers and metadata

---

### Step 4: Start the VPN Client

You can run the client in **Desktop GUI Mode**, **Web Browser Dashboard Mode**, or **CLI Mode**:

#### A. Native Desktop GUI (Recommended)
Launch the dark-mode desktop app with the big **CONNECT** toggle button:
```powershell
python vpn_gui.py
```
- Click **CONNECT TO VPN** to negotiate TLS 1.3 and establish the encrypted tunnel.
- View live latency, assigned IP (`10.8.0.2`), and bandwidth in real-time.
- One-click copy for the SOCKS5 curl test command.

#### B. Browser Web Dashboard
If you want to view or control the VPN from any web browser (on this laptop or from your phone):
```powershell
python web_gui.py --port 5000
```
Open **`http://localhost:5000`** in Chrome, Edge, or Firefox.

#### C. Command-Line (CLI) Mode
```powershell
python vpn_client.py --server 127.0.0.1 --port 8443 --mode auto --verbose
```

Client Options:
- `--server`: Server hostname or IP address
- `--port`: Server port (default: `8443`)
- `--mode`: `auto` (uses TUN if available; provides SOCKS5 tunnel on `127.0.0.1:1080`)
- `--proxy-port`: Local SOCKS5 port (default: `1080`)
- `--test-ping`: Sends synthetic ICMP packet to verify tunnel routing
- `--verbose`: Print tunnel latency and packet metadata

---

## Using the Encrypted Tunnel

### 1. Zero-Configuration SOCKS5 Tunnel (Driverless Mode)
With the client running, route any application or browser through the encrypted tunnel:

```bash
# Test external IP through the VPN
curl --socks5-hostname 127.0.0.1:1080 https://icanhazip.com

# Fetch any website securely
curl -x socks5h://127.0.0.1:1080 https://www.google.com
```

### 2. Full OS Layer 3 TUN Routing (Linux)
When running as root on Linux, the client creates `vpn-cli0` with IP `10.8.0.2`:

```bash
# Ping the VPN gateway through the encrypted tunnel
ping 10.8.0.1

# Route all default traffic through the VPN gateway:
sudo ip route add default via 10.8.0.1 dev vpn-cli0
```
