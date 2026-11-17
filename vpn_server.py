"""
Secure Tunnel VPN Server (CN Project - Group 15)
------------------------------------------------
Multi-client encrypted VPN Server supporting:
  - Layer 3 IP Packet Tunneling (TUN device routing)
  - Layer 4 SOCKS5 Encrypted Tunneling (Driverless/Zero-privilege)
  - TLS 1.3 / mTLS mutual certificate authentication
  - Pre-shared token validation
  - In-memory routing table & dynamic virtual IP pool management
  - Live packet inspection and bandwidth metrics

Run:
  python vpn_server.py [--port 8443] [--mode dual] [--verify-client]
"""

import os
import sys
import time
import socket
import select
import struct
import ipaddress
import threading
import argparse
import logging
from typing import Dict, Optional, Set

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
    create_server_ssl_context,
    verify_auth_token,
)
from core.tun_interface import create_tun_interface, BaseTunInterface
from core.packet_parser import parse_ip_packet, format_packet_summary
from core.proxy_handler import ServerProxyEgress

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Server] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("VPN.Server")


class ClientSession:
    """Maintains state, assigned IP, and egress handlers for an active client connection."""

    def __init__(self, client_id: str, virtual_ip: str, sock: socket.socket, addr: tuple):
        self.client_id = client_id
        self.virtual_ip = virtual_ip
        self.sock = sock
        self.addr = addr
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.bytes_sent = 0
        self.bytes_recv = 0
        self._send_lock = threading.Lock()
        self.egress_handler = ServerProxyEgress(self.send_frame)

    def send_frame(self, pkt_type: int, stream_id: int = 0, payload: bytes = b""):
        """Thread-safe frame transmission across the TLS tunnel."""
        frame = encode_frame(pkt_type, stream_id, payload)
        with self._send_lock:
            try:
                self.sock.sendall(frame)
                self.bytes_sent += len(frame)
            except Exception as e:
                logger.debug(f"Failed to send frame to {self.client_id} ({self.virtual_ip}): {e}")

    def close(self):
        self.egress_handler.stop_all()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class VpnServer:
    """High-performance encrypted VPN Server."""

    def __init__(
        self,
        bind_host: str = "0.0.0.0",
        bind_port: int = 8443,
        cert_file: str = "certs/server.crt",
        key_file: str = "certs/server.key",
        ca_file: str = "certs/ca.crt",
        verify_client: bool = False,
        auth_secret: str = "supersecretvpnkey",
        mode: str = "dual",  # "tun", "proxy", or "dual"
        network_cidr: str = "10.8.0.0/24",
        server_virtual_ip: str = "10.8.0.1",
        tun_name: str = "vpn-srv0",
        mtu: int = 1500,
        verbose: bool = False,
    ):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.verify_client = verify_client
        self.auth_secret = auth_secret
        self.mode = mode
        self.network = ipaddress.IPv4Network(network_cidr)
        self.server_virtual_ip = server_virtual_ip
        self.tun_name = tun_name
        self.mtu = mtu
        self.verbose = verbose

        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.ssl_context = None

        # Virtual IP pool & Routing table: virtual_ip -> ClientSession
        self.routing_table: Dict[str, ClientSession] = {}
        self.allocated_ips: Set[str] = {self.server_virtual_ip}
        self._table_lock = threading.Lock()

        # Virtual Network Interface (TUN)
        self.tun: Optional[BaseTunInterface] = None

    def _allocate_virtual_ip(self) -> Optional[str]:
        """Allocate next available IPv4 address from the VPN subnet pool."""
        with self._table_lock:
            for ip in self.network.hosts():
                ip_str = str(ip)
                if ip_str not in self.allocated_ips:
                    self.allocated_ips.add(ip_str)
                    return ip_str
        return None

    def _release_virtual_ip(self, virtual_ip: str):
        with self._table_lock:
            self.allocated_ips.discard(virtual_ip)
            self.routing_table.pop(virtual_ip, None)

    def start(self):
        """Initialize TUN adapter, build SSL context, and begin listening."""
        logger.info("=" * 60)
        logger.info("   Starting Secure VPN Server (Group 15)")
        logger.info(f"   Mode: {self.mode.upper()} | Network: {self.network} | Gateway: {self.server_virtual_ip}")
        logger.info("=" * 60)

        # 1. Initialize Virtual TUN interface if mode includes TUN
        if self.mode in ("tun", "dual"):
            self.tun = create_tun_interface(
                name=self.tun_name,
                ip=self.server_virtual_ip,
                netmask=str(self.network.netmask),
                mtu=self.mtu,
            )
            # Start TUN reader thread to route packets arriving from OS gateway back to clients
            threading.Thread(target=self._tun_reader_loop, daemon=True, name="ServerTunReader").start()

        # 2. Build hardened SSL/TLS context
        self.ssl_context = create_server_ssl_context(
            cert_file=self.cert_file,
            key_file=self.key_file,
            ca_file=self.ca_file,
            verify_client=self.verify_client,
        )

        # 3. Bind TCP listening socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.bind_host, self.bind_port))
        raw_sock.listen(128)
        self.server_sock = raw_sock
        self.running = True

        logger.info(f"TLS Server listening on {self.bind_host}:{self.bind_port} (TLS 1.3 / mTLS)")
        logger.info("Ready for secure client tunnel connections.")

        try:
            while self.running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                except OSError:
                    if not self.running:
                        break
                    continue
                threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_sock, client_addr),
                    daemon=True,
                    name=f"ClientWorker-{client_addr[0]}:{client_addr[1]}"
                ).start()
        except KeyboardInterrupt:
            logger.info("Server interrupt received. Shutting down...")
        finally:
            self.stop()

    def _handle_client_connection(self, raw_sock: socket.socket, client_addr: tuple):
        """Wrap connection in TLS and conduct mutual handshake."""
        tls_sock = None
        session = None
        try:
            # TLS Handshake
            tls_sock = self.ssl_context.wrap_socket(raw_sock, server_side=True)
            cipher = tls_sock.cipher()
            logger.info(f"Encrypted TLS connection from {client_addr} established: {cipher[0]} ({cipher[1]})")

            # VPN Handshake Protocol
            pkt_type, stream_id, payload = read_frame(tls_sock)
            if pkt_type != PKT_HANDSHAKE_REQ:
                logger.warning(f"Expected handshake request from {client_addr}, received {pkt_type}. Terminating.")
                tls_sock.close()
                return

            req = decode_json_payload(payload)
            client_id = req.get("client_id", f"client-{client_addr[0]}:{client_addr[1]}")
            auth_token = req.get("auth_token", "")

            # Verify authorization secret
            if self.auth_secret and auth_token != self.auth_secret:
                logger.warning(f"Authentication failed for client '{client_id}' from {client_addr}")
                resp = {"status": "ERROR", "message": "Invalid authentication credentials."}
                tls_sock.sendall(encode_json_frame(PKT_HANDSHAKE_RESP, 0, resp))
                tls_sock.close()
                return

            # Allocate Virtual IP
            virtual_ip = self._allocate_virtual_ip()
            if not virtual_ip:
                logger.error(f"IP pool exhausted. Cannot allocate virtual IP for '{client_id}'.")
                resp = {"status": "ERROR", "message": "VPN IP pool exhausted."}
                tls_sock.sendall(encode_json_frame(PKT_HANDSHAKE_RESP, 0, resp))
                tls_sock.close()
                return

            session = ClientSession(client_id, virtual_ip, tls_sock, client_addr)
            with self._table_lock:
                self.routing_table[virtual_ip] = session

            # Respond with network parameters
            handshake_resp = {
                "status": "OK",
                "assigned_ip": virtual_ip,
                "server_ip": self.server_virtual_ip,
                "netmask": str(self.network.netmask),
                "mtu": self.mtu,
                "dns": "1.1.1.1",
                "mode": self.mode,
            }
            session.send_frame(PKT_HANDSHAKE_RESP, 0, encode_json_frame(PKT_HANDSHAKE_RESP, 0, handshake_resp)[9:])
            logger.info(f"Client authenticated: '{client_id}' -> Assigned Virtual IP {virtual_ip}")

            # Main client receive loop
            while self.running:
                pkt_type, stream_id, payload = read_frame(tls_sock)
                session.bytes_recv += len(payload) + 9
                session.last_seen = time.time()

                if pkt_type == PKT_DATA:
                    # Layer 3 IP Packet received from client
                    self._route_l3_packet(session, payload)

                elif pkt_type == PKT_PROXY_CONNECT:
                    session.egress_handler.handle_connect(stream_id, payload)

                elif pkt_type == PKT_PROXY_DATA:
                    session.egress_handler.handle_data(stream_id, payload)

                elif pkt_type == PKT_PROXY_CLOSE:
                    session.egress_handler.close_stream(stream_id)

                elif pkt_type == PKT_PING:
                    session.send_frame(PKT_PONG, stream_id, payload)

                elif pkt_type == PKT_PONG:
                    pass

                elif pkt_type == PKT_DISCONNECT:
                    logger.info(f"Client '{client_id}' ({virtual_ip}) requested graceful disconnect.")
                    break

        except (EOFError, ConnectionResetError):
            logger.info(f"Client connection closed: {client_addr}")
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            if session:
                logger.info(f"Cleaning up session for {session.client_id} ({session.virtual_ip})...")
                self._release_virtual_ip(session.virtual_ip)
                session.close()
            elif tls_sock:
                try:
                    tls_sock.close()
                except Exception:
                    pass

    def _route_l3_packet(self, sender: ClientSession, packet_bytes: bytes):
        """Route an encapsulated Layer 3 IP packet to destination peer or OS gateway."""
        info = parse_ip_packet(packet_bytes)
        if self.verbose and info:
            logger.info(f"[L3 IN] {format_packet_summary(info)}")

        if not info:
            return

        dst_ip = info["dst_ip"]

        # 1. Peer-to-Peer Client Routing: Is packet destined for another VPN client?
        with self._table_lock:
            target_peer = self.routing_table.get(dst_ip)

        if target_peer:
            if self.verbose:
                logger.info(f"[P2P Routing] Forwarding {info['src_ip']} -> {dst_ip} directly to peer")
            target_peer.send_frame(PKT_DATA, 0, packet_bytes)
            return

        # 2. Packet destined for server virtual IP or Internet: Deliver to server's TUN
        if self.tun and self.tun.is_open:
            self.tun.write(packet_bytes)

    def _tun_reader_loop(self):
        """Reads outbound/reply packets from server TUN and encapsulates back to client."""
        logger.info("Server TUN reader loop initialized.")
        while self.running:
            try:
                packet = self.tun.read(4096)
                if not packet:
                    time.sleep(0.005)
                    continue

                info = parse_ip_packet(packet)
                if not info:
                    continue

                dst_ip = info["dst_ip"]
                with self._table_lock:
                    target_client = self.routing_table.get(dst_ip)

                if target_client:
                    if self.verbose:
                        logger.info(f"[TUN -> Client {dst_ip}] {format_packet_summary(info)}")
                    target_client.send_frame(PKT_DATA, 0, packet)
            except Exception as e:
                if self.running:
                    logger.debug(f"TUN reader exception: {e}")
                break

    def stop(self):
        """Shut down the server, disconnect clients, and release interfaces."""
        self.running = False
        logger.info("Stopping VPN server...")

        # Disconnect all active clients
        with self._table_lock:
            for session in list(self.routing_table.values()):
                try:
                    session.send_frame(PKT_DISCONNECT, 0, b"Server shutting down")
                    session.close()
                except Exception:
                    pass
            self.routing_table.clear()

        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

        if self.tun:
            self.tun.close()

        logger.info("VPN server terminated gracefully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure VPN Server - Group 15")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="Listen port (default: 8443)")
    parser.add_argument("--cert", default="certs/server.crt", help="Server certificate file")
    parser.add_argument("--key", default="certs/server.key", help="Server private key file")
    parser.add_argument("--ca", default="certs/ca.crt", help="CA certificate for client verification")
    parser.add_argument("--verify-client", action="store_true", help="Enforce mutual TLS (mTLS) client certificate verification")
    parser.add_argument("--auth-secret", default="supersecretvpnkey", help="Shared secret authentication key")
    parser.add_argument("--mode", choices=["tun", "proxy", "dual"], default="dual", help="VPN Tunnel mode: tun, proxy, or dual (default: dual)")
    parser.add_argument("--net", default="10.8.0.0/24", help="Virtual network CIDR (default: 10.8.0.0/24)")
    parser.add_argument("--server-ip", default="10.8.0.1", help="Virtual IP for VPN server (default: 10.8.0.1)")
    parser.add_argument("--tun-name", default="vpn-srv0", help="Virtual TUN interface name")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose packet inspection logging")
    args = parser.parse_args()

    # Ensure certificates exist
    if not os.path.isfile(args.cert) or not os.path.isfile(args.key):
        print(f"Certificates not found. Running cert_gen.py to generate them automatically...")
        from cert_gen import generate_pki
        generate_pki(output_dir="certs")

    server = VpnServer(
        bind_host=args.host,
        bind_port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        ca_file=args.ca,
        verify_client=args.verify_client,
        auth_secret=args.auth_secret,
        mode=args.mode,
        network_cidr=args.net,
        server_virtual_ip=args.server_ip,
        tun_name=args.tun_name,
        verbose=args.verbose,
    )
    server.start()
