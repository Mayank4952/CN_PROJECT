"""
Tunneling Protocol and Frame Specification
-----------------------------------------
Encapsulation Format:
  [2 Bytes Magic: 0x56 0x50 ('VP')]
  [1 Byte Packet Type]
  [4 Bytes Stream ID (big-endian uint32)]
  [2 Bytes Payload Length (big-endian uint16, max 65535)]
  [N Bytes Payload (Raw IP packet, Handshake JSON, or Stream Data)]
"""

import json
import struct
import socket
from typing import Optional, Tuple, Dict, Any

# Protocol Constants
MAGIC = b"\x56\x50"  # 'VP'
HEADER_FORMAT = "!2sBIH"  # magic (2s), type (B), stream_id (I), length (H)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 9 bytes
MAX_PAYLOAD_SIZE = 65535

# Packet Types
PKT_HANDSHAKE_REQ = 0x01
PKT_HANDSHAKE_RESP = 0x02
PKT_DATA = 0x03          # Raw Layer 3 IP Packet
PKT_PING = 0x04          # Heartbeat ping
PKT_PONG = 0x05          # Heartbeat pong
PKT_DISCONNECT = 0x06    # Graceful shutdown notification

# Layer 4 User-Space Proxy Tunnel Types (Multiplexed)
PKT_PROXY_CONNECT = 0x10 # Open new outbound TCP stream: {host, port}
PKT_PROXY_RESP = 0x11    # Connection outcome: {status: "OK"/"ERR", msg: ...}
PKT_PROXY_DATA = 0x12    # Stream data payload
PKT_PROXY_CLOSE = 0x13   # Stream closed


class ProtocolError(Exception):
    """Raised when an invalid or corrupted packet frame is encountered."""
    pass


def encode_frame(pkt_type: int, stream_id: int = 0, payload: bytes = b"") -> bytes:
    """Pack packet type, stream ID, and payload into a binary frame."""
    payload_len = len(payload)
    if payload_len > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload size {payload_len} exceeds maximum frame size {MAX_PAYLOAD_SIZE}")
    header = struct.pack(HEADER_FORMAT, MAGIC, pkt_type, stream_id, payload_len)
    return header + payload


def encode_json_frame(pkt_type: int, stream_id: int = 0, data: Dict[str, Any] = None) -> bytes:
    """Encode a dictionary as a JSON payload inside a frame."""
    json_bytes = json.dumps(data or {}).encode("utf-8")
    return encode_frame(pkt_type, stream_id, json_bytes)


def decode_json_payload(payload: bytes) -> Dict[str, Any]:
    """Decode a JSON frame payload into a python dictionary."""
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ProtocolError(f"Failed to parse JSON frame payload: {e}") from e


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from a socket. Raises EOFError if disconnected."""
    chunks = []
    bytes_recd = 0
    while bytes_recd < num_bytes:
        chunk = sock.recv(num_bytes - bytes_recd)
        if not chunk:
            raise EOFError("Connection closed by remote peer while reading frame.")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b"".join(chunks)


def read_frame(sock: socket.socket) -> Tuple[int, int, bytes]:
    """
    Read and decode the next frame from a socket.
    Returns: (pkt_type, stream_id, payload)
    """
    header_bytes = recv_exact(sock, HEADER_SIZE)
    magic, pkt_type, stream_id, length = struct.unpack(HEADER_FORMAT, header_bytes)

    if magic != MAGIC:
        raise ProtocolError(f"Invalid magic bytes received: {magic!r}")

    payload = recv_exact(sock, length) if length > 0 else b""
    return pkt_type, stream_id, payload
