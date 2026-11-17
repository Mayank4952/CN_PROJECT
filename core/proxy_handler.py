"""
Layer 4 SOCKS5 Encrypted Tunnel Handler
---------------------------------------
Provides a zero-privilege, driverless tunneling mode:
  - Client runs a local SOCKS5 proxy listener (RFC 1928).
  - Outbound connections are multiplexed and encrypted across the VPN tunnel.
  - The VPN server egresses the TCP traffic to the target destinations.
"""

import socket
import select
import struct
import threading
import logging
from typing import Dict, Tuple, Optional, Callable
from .protocol import (
    PKT_PROXY_CONNECT,
    PKT_PROXY_RESP,
    PKT_PROXY_DATA,
    PKT_PROXY_CLOSE,
    encode_json_frame,
    encode_frame,
    decode_json_payload,
)

logger = logging.getLogger("VPN.Proxy")

# SOCKS5 constants
SOCKS_VERSION = 5
SOCKS_AUTH_NONE = 0
SOCKS_CMD_CONNECT = 1
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4


class ClientSocks5Proxy:
    """Runs a local SOCKS5 server on the client machine and forwards through the VPN tunnel."""

    def __init__(self, bind_host: str, bind_port: int, send_frame_fn: Callable[[int, int, bytes], None]):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.send_frame = send_frame_fn
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self.active_streams: Dict[int, socket.socket] = {}
        self._next_stream_id = 1
        self._lock = threading.Lock()

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.bind_host, self.bind_port))
        self.server_sock.listen(128)
        self.running = True
        logger.info(f"Local SOCKS5 proxy listening on {self.bind_host}:{self.bind_port}")
        threading.Thread(target=self._accept_loop, daemon=True, name="Socks5AcceptLoop").start()

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        with self._lock:
            for s in self.active_streams.values():
                try:
                    s.close()
                except Exception:
                    pass
            self.active_streams.clear()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
                threading.Thread(target=self._handle_socks_client, args=(client_sock,), daemon=True).start()
            except Exception:
                break

    def _handle_socks_client(self, sock: socket.socket):
        try:
            # 1. Negotiation handshake
            ver, nmethods = struct.unpack("!BB", sock.recv(2))
            if ver != SOCKS_VERSION:
                sock.close()
                return
            methods = sock.recv(nmethods)
            # Response: No authentication required
            sock.sendall(struct.pack("!BB", SOCKS_VERSION, SOCKS_AUTH_NONE))

            # 2. Connection Request
            data = sock.recv(4)
            if len(data) < 4:
                sock.close()
                return
            ver, cmd, rsv, atyp = struct.unpack("!BBBB", data)
            if cmd != SOCKS_CMD_CONNECT:
                # Command not supported
                sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                sock.close()
                return

            if atyp == SOCKS_ATYP_IPV4:
                target_ip = socket.inet_ntoa(sock.recv(4))
                target_port = struct.unpack("!H", sock.recv(2))[0]
                target_host = target_ip
            elif atyp == SOCKS_ATYP_DOMAIN:
                domain_len = ord(sock.recv(1))
                target_host = sock.recv(domain_len).decode("utf-8")
                target_port = struct.unpack("!H", sock.recv(2))[0]
            elif atyp == SOCKS_ATYP_IPV6:
                target_ip = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
                target_port = struct.unpack("!H", sock.recv(2))[0]
                target_host = target_ip
            else:
                sock.close()
                return

            with self._lock:
                stream_id = self._next_stream_id
                self._next_stream_id += 1
                self.active_streams[stream_id] = sock

            logger.info(f"[Proxy Stream {stream_id}] Initiating tunnel connection to {target_host}:{target_port}")

            # Send connect request across VPN tunnel
            req_data = {"host": target_host, "port": target_port}
            self.send_frame(PKT_PROXY_CONNECT, stream_id, encode_json_frame(PKT_PROXY_CONNECT, stream_id, req_data)[9:])

            # Reply success to SOCKS client
            # BND.ADDR 0.0.0.0, BND.PORT 0
            sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # Forward local client data to VPN tunnel
            while self.running:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                self.send_frame(PKT_PROXY_DATA, stream_id, chunk)

        except Exception as e:
            logger.debug(f"SOCKS client error: {e}")
        finally:
            with self._lock:
                if stream_id in self.active_streams:
                    del self.active_streams[stream_id]
            self.send_frame(PKT_PROXY_CLOSE, stream_id, b"")
            try:
                sock.close()
            except Exception:
                pass

    def deliver_inbound_data(self, stream_id: int, data: bytes):
        """Called when server sends back web/traffic data for this stream."""
        with self._lock:
            sock = self.active_streams.get(stream_id)
        if sock:
            try:
                sock.sendall(data)
            except Exception:
                self.close_stream(stream_id)

    def close_stream(self, stream_id: int):
        with self._lock:
            sock = self.active_streams.pop(stream_id, None)
        if sock:
            try:
                sock.close()
            except Exception:
                pass


class ServerProxyEgress:
    """Handles outbound egress connections on the VPN server side for proxy streams."""

    def __init__(self, send_frame_fn: Callable[[int, int, bytes], None]):
        self.send_frame = send_frame_fn
        self.active_sockets: Dict[int, socket.socket] = {}
        self._lock = threading.Lock()
        self.running = True

    def handle_connect(self, stream_id: int, payload: bytes):
        """Open an outbound TCP connection to the destination specified by client."""
        try:
            req = decode_json_payload(payload)
            target_host = req["host"]
            target_port = req["port"]
            logger.info(f"[Server Egress {stream_id}] Connecting to {target_host}:{target_port}...")

            outbound_sock = socket.create_connection((target_host, target_port), timeout=10.0)
            with self._lock:
                self.active_sockets[stream_id] = outbound_sock

            threading.Thread(
                target=self._egress_reader_loop,
                args=(stream_id, outbound_sock),
                daemon=True,
                name=f"EgressReader-{stream_id}"
            ).start()
        except Exception as e:
            logger.warning(f"[Server Egress {stream_id}] Connection failed: {e}")
            self.send_frame(PKT_PROXY_CLOSE, stream_id, b"")

    def handle_data(self, stream_id: int, payload: bytes):
        """Forward data from client across the outbound socket to the internet."""
        with self._lock:
            outbound_sock = self.active_sockets.get(stream_id)
        if outbound_sock:
            try:
                outbound_sock.sendall(payload)
            except Exception:
                self.close_stream(stream_id)

    def _egress_reader_loop(self, stream_id: int, sock: socket.socket):
        """Read data from the internet server and forward it back to client through VPN tunnel."""
        while self.running:
            try:
                data = sock.recv(16384)
                if not data:
                    break
                self.send_frame(PKT_PROXY_DATA, stream_id, data)
            except Exception:
                break
        self.close_stream(stream_id)

    def close_stream(self, stream_id: int):
        with self._lock:
            sock = self.active_sockets.pop(stream_id, None)
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        self.send_frame(PKT_PROXY_CLOSE, stream_id, b"")

    def stop_all(self):
        self.running = False
        with self._lock:
            for s in self.active_sockets.values():
                try:
                    s.close()
                except Exception:
                    pass
            self.active_sockets.clear()
