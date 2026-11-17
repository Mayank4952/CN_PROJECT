"""
Secure Tunnel VPN Client (CN Project - Group 15)
------------------------------------------------
Encrypted VPN Client supporting:
  - Layer 3 IP Packet Tunneling (TUN adapter)
  - Layer 4 Local SOCKS5 Encrypted Proxy (Driverless/Zero-privilege)
  - TLS 1.3 / mTLS mutual certificate authentication
  - Pre-shared secret authentication
  - Heartbeat keepalive and dead-peer detection
  - Built-in diagnostic packet injection and latency testing

Run:
  python vpn_client.py [--server 127.0.0.1] [--port 8443] [--mode auto]
"""

import os
import sys
import time
import socket
import select
import struct
import threading
import argparse
import logging
from typing import Optional

from core.protocol import (
    MAGIC,
    PKT_HANDSHAKE_REQ,
    PKT_HANDSHAKE_RESP,
    PKT_DATA,
    PKT_PING,
    PKT_PONG,
    PKT_DISCONNECT,
    PKT_PROXY_CONNECT,
    PKT_PROXY_RESP,
    PKT_PROXY_DATA,
    PKT_PROXY_CLOSE,
    encode_frame,
    encode_json_frame,
    decode_json_payload,
    read_frame,
    ProtocolError,
)
from core.crypto import (
    create_client_ssl_context,
)
from core.tun_interface import create_tun_interface, BaseTunInterface, SimulatedTunInterface
from core.packet_parser import parse_ip_packet, format_packet_summary
from core.proxy_handler import ClientSocks5Proxy

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Client] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("VPN.Client")


class VpnClient:
    """Encrypted VPN Client."""

    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 8443,
        ca_file: str = "certs/ca.crt",
        cert_file: str = "certs/client.crt",
        key_file: str = "certs/client.key",
        verify_server: bool = True,
        auth_secret: str = "supersecretvpnkey",
        client_id: str = "vpn-client-1",
        mode: str = "auto",  # "tun", "proxy", or "auto"
        proxy_bind_host: str = "127.0.0.1",
        proxy_bind_port: int = 1080,
        tun_name: str = "vpn-cli0",
        verbose: bool = False,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.ca_file = ca_file
        self.cert_file = cert_file
        self.key_file = key_file
        self.verify_server = verify_server
        self.auth_secret = auth_secret
        self.client_id = client_id
        self.mode = mode
        self.proxy_bind_host = proxy_bind_host
        self.proxy_bind_port = proxy_bind_port
        self.tun_name = tun_name
        self.verbose = verbose

        self.running = False
        self.tls_sock: Optional[socket.socket] = None
        self._send_lock = threading.Lock()

        # Assigned Network Configuration
        self.virtual_ip: Optional[str] = None
        self.server_virtual_ip: Optional[str] = None
        self.netmask: Optional[str] = None
        self.mtu: int = 1500

        # Subsystems
        self.tun: Optional[BaseTunInterface] = None
        self.proxy: Optional[ClientSocks5Proxy] = None

        # Statistics
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.last_ping_rtt_ms = 0.0

    def send_frame(self, pkt_type: int, stream_id: int = 0, payload: bytes = b""):
        """Thread-safe frame transmission across the TLS tunnel."""
        if not self.tls_sock:
            return
        frame = encode_frame(pkt_type, stream_id, payload)
        with self._send_lock:
            try:
                self.tls_sock.sendall(frame)
                self.bytes_sent += len(frame)
            except Exception as e:
                logger.debug(f"Failed to send frame to server: {e}")

    def connect(self) -> bool:
        """Establish TLS connection, perform handshake, and start tunnel threads."""
        logger.info("=" * 60)
        logger.info(f"   Connecting to VPN Server at {self.server_host}:{self.server_port}")
        logger.info(f"   Client ID: {self.client_id} | Mode: {self.mode.upper()}")
        logger.info("=" * 60)

        # 1. Build SSL context
        ssl_ctx = create_client_ssl_context(
            ca_file=self.ca_file,
            cert_file=self.cert_file,
            key_file=self.key_file,
            verify_server=self.verify_server,
        )

        # 2. Connect raw TCP socket and wrap in TLS
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(10.0)
        try:
            raw_sock.connect((self.server_host, self.server_port))
            self.tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=self.server_host)
            cipher = self.tls_sock.cipher()
            logger.info(f"Encrypted TLS 1.3 tunnel established with server: {cipher[0]} ({cipher[1]})")
        except Exception as e:
            logger.error(f"Failed to connect to VPN server: {e}")
            raw_sock.close()
            return False

        self.tls_sock.settimeout(None)  # Blocking operations for main receive loop

        # 3. Handshake
        logger.info("Performing authentication and configuration handshake...")
        handshake_payload = {
            "client_id": self.client_id,
            "auth_token": self.auth_secret,
            "version": 1,
        }
        self.send_frame(PKT_HANDSHAKE_REQ, 0, encode_json_frame(PKT_HANDSHAKE_REQ, 0, handshake_payload)[9:])

        # Read handshake response
        pkt_type, stream_id, payload = read_frame(self.tls_sock)
        if pkt_type != PKT_HANDSHAKE_RESP:
            logger.error(f"Unexpected packet type during handshake: {pkt_type}")
            self.tls_sock.close()
            return False

        resp = decode_json_payload(payload)
        if resp.get("status") != "OK":
            logger.error(f"Handshake rejected by server: {resp.get('message')}")
            self.tls_sock.close()
            return False

        self.virtual_ip = resp["assigned_ip"]
        self.server_virtual_ip = resp["server_ip"]
        self.netmask = resp.get("netmask", "255.255.255.0")
        self.mtu = resp.get("mtu", 1500)

        logger.info(f"Handshake successful!")
        logger.info(f"  - Assigned Virtual IP: {self.virtual_ip}")
        logger.info(f"  - Server Virtual IP:   {self.server_virtual_ip}")
        logger.info(f"  - Netmask:             {self.netmask}")
        logger.info(f"  - MTU:                 {self.mtu}")

        self.running = True

        # 4. Initialize Network Subsystems
        effective_mode = self.mode
        if effective_mode in ("tun", "auto"):
            self.tun = create_tun_interface(
                name=self.tun_name,
                ip=self.virtual_ip,
                netmask=self.netmask,
                mtu=self.mtu,
            )
            # If auto mode and native TUN wasn't available, we also enable SOCKS5 proxy
            if not self.tun.is_open or isinstance(self.tun, SimulatedTunInterface):
                if effective_mode == "auto":
                    logger.info("Enabling SOCKS5 user-space proxy mode for zero-privilege tunneling.")
                    effective_mode = "proxy"

        if effective_mode in ("proxy", "dual", "auto"):
            self.proxy = ClientSocks5Proxy(
                bind_host=self.proxy_bind_host,
                bind_port=self.proxy_bind_port,
                send_frame_fn=self.send_frame,
            )
            self.proxy.start()
            logger.info(f"SOCKS5 Proxy Tunnel ready at {self.proxy_bind_host}:{self.proxy_bind_port}")
            logger.info(f"Tip: Route web traffic via 'curl --socks5-hostname {self.proxy_bind_host}:{self.proxy_bind_port} https://icanhazip.com'")

        # Start TUN outbound forwarder if active
        if self.tun and self.tun.is_open:
            threading.Thread(target=self._tun_outbound_loop, daemon=True, name="ClientTunOutbound").start()

        # Start background Keepalive ping thread
        threading.Thread(target=self._keepalive_loop, daemon=True, name="ClientKeepalive").start()

        return True

    def run_forever(self):
        """Main inbound receive loop for server traffic."""
        try:
            while self.running:
                pkt_type, stream_id, payload = read_frame(self.tls_sock)
                self.bytes_recv += len(payload) + 9

                if pkt_type == PKT_DATA:
                    # Layer 3 IP Packet arriving from VPN server
                    self._handle_inbound_l3(payload)

                elif pkt_type == PKT_PROXY_DATA:
                    if self.proxy:
                        self.proxy.deliver_inbound_data(stream_id, payload)

                elif pkt_type == PKT_PROXY_CLOSE:
                    if self.proxy:
                        self.proxy.close_stream(stream_id)

                elif pkt_type == PKT_PING:
                    self.send_frame(PKT_PONG, stream_id, payload)

                elif pkt_type == PKT_PONG:
                    # Pong reply received
                    if len(payload) >= 8:
                        sent_time = struct.unpack("!d", payload[:8])[0]
                        self.last_ping_rtt_ms = (time.time() - sent_time) * 1000.0
                        if self.verbose:
                            logger.info(f"[Tunnel Latency] Server round-trip: {self.last_ping_rtt_ms:.2f} ms")

                elif pkt_type == PKT_DISCONNECT:
                    logger.warning("VPN Server sent disconnect notification. Terminating tunnel.")
                    break

        except (EOFError, ConnectionResetError):
            logger.info("VPN server closed the connection.")
        except Exception as e:
            if self.running:
                logger.error(f"Inbound tunnel error: {e}")
        finally:
            self.disconnect()

    def _handle_inbound_l3(self, packet_bytes: bytes):
        """Delivers received Layer 3 IP packet to local TUN interface."""
        info = parse_ip_packet(packet_bytes)
        if self.verbose and info:
            logger.info(f"[L3 RECV] {format_packet_summary(info)}")

        if self.tun and self.tun.is_open:
            self.tun.write(packet_bytes)

    def _tun_outbound_loop(self):
        """Reads outgoing IP packets from local TUN interface and forwards to VPN server."""
        logger.info("Client TUN outbound forwarder active.")
        while self.running:
            try:
                packet = self.tun.read(4096)
                if not packet:
                    time.sleep(0.005)
                    continue

                info = parse_ip_packet(packet)
                if self.verbose and info:
                    logger.info(f"[L3 SEND] {format_packet_summary(info)}")

                self.send_frame(PKT_DATA, 0, packet)
            except Exception as e:
                if self.running:
                    logger.debug(f"TUN read error: {e}")
                break

    def _keepalive_loop(self):
        """Periodically sends PING frames to maintain NAT state and check tunnel liveness."""
        while self.running:
            time.sleep(15.0)
            if not self.running:
                break
            payload = struct.pack("!d", time.time())
            self.send_frame(PKT_PING, 0, payload)

    def send_synthetic_ping(self):
        """Constructs and injects a real IPv4 ICMP Echo Request to test end-to-end routing."""
        if not self.virtual_ip or not self.server_virtual_ip:
            return

        # Simple synthetic ICMP packet to server virtual IP
        src_bytes = socket.inet_aton(self.virtual_ip)
        dst_bytes = socket.inet_aton(self.server_virtual_ip)

        # IPv4 Header (20 bytes)
        # Ver=4, IHL=5, TOS=0, Len=28, ID=1234, Flags=0, TTL=64, Proto=1 (ICMP), Checksum=0
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 28, 1234, 0, 64, 1, 0, src_bytes, dst_bytes
        )
        # ICMP Echo Request: Type=8, Code=0, Checksum=0, ID=1, Seq=1
        icmp_packet = struct.pack("!BBHHH", 8, 0, 0, 1, 1)

        full_packet = ip_header + icmp_packet
        logger.info(f"[Test Diagnostic] Sending synthetic ICMP ping from {self.virtual_ip} -> {self.server_virtual_ip}")
        self.send_frame(PKT_DATA, 0, full_packet)

    def disconnect(self):
        """Gracefully disconnect from VPN server and clean up resources."""
        self.running = False
        logger.info("Disconnecting from VPN server...")

        if self.proxy:
            self.proxy.stop()

        if self.tun:
            self.tun.close()

        if self.tls_sock:
            try:
                self.send_frame(PKT_DISCONNECT, 0, b"Client disconnecting")
                self.tls_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.tls_sock.close()
            except Exception:
                pass

        logger.info("VPN client disconnected cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure VPN Client - Group 15")
    parser.add_argument("--server", default="127.0.0.1", help="VPN Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="VPN Server port (default: 8443)")
    parser.add_argument("--ca", default="certs/ca.crt", help="CA certificate to verify server")
    parser.add_argument("--cert", default="certs/client.crt", help="Client certificate file for mTLS")
    parser.add_argument("--key", default="certs/client.key", help="Client private key file")
    parser.add_argument("--insecure", action="store_true", help="Disable server certificate verification")
    parser.add_argument("--auth-secret", default="supersecretvpnkey", help="Shared secret authentication key")
    parser.add_argument("--client-id", default=f"client-{os.getpid()}", help="Client identifier")
    parser.add_argument("--mode", choices=["tun", "proxy", "auto"], default="auto", help="Tunneling mode (default: auto)")
    parser.add_argument("--proxy-port", type=int, default=1080, help="Local SOCKS5 proxy port (default: 1080)")
    parser.add_argument("--tun-name", default="vpn-cli0", help="Virtual TUN interface name")
    parser.add_argument("--test-ping", action="store_true", help="Send a test synthetic ICMP packet after connecting")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose packet inspection logging")
    args = parser.parse_args()

    client = VpnClient(
        server_host=args.server,
        server_port=args.port,
        ca_file=args.ca,
        cert_file=args.cert,
        key_file=args.key,
        verify_server=not args.insecure,
        auth_secret=args.auth_secret,
        client_id=args.client_id,
        mode=args.mode,
        proxy_bind_port=args.proxy_port,
        tun_name=args.tun_name,
        verbose=args.verbose,
    )

    if client.connect():
        if args.test_ping:
            # Wait brief moment and inject synthetic test packet
            threading.Timer(1.0, client.send_synthetic_ping).start()
        try:
            client.run_forever()
        except KeyboardInterrupt:
            logger.info("Client interrupt received. Exiting...")
            client.disconnect()
