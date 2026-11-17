"""
Secure Tunnel VPN Core Package - Group 15
-----------------------------------------
Modular tunneling, protocol framing, packet parsing, crypto, and network interface abstraction.
"""

from .protocol import (
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
)
from .crypto import (
    create_server_ssl_context,
    create_client_ssl_context,
    generate_auth_token,
    verify_auth_token,
)
from .packet_parser import parse_ip_packet, format_packet_summary
from .tun_interface import create_tun_interface, BaseTunInterface

__all__ = [
    "MAGIC",
    "PKT_HANDSHAKE_REQ",
    "PKT_HANDSHAKE_RESP",
    "PKT_DATA",
    "PKT_PING",
    "PKT_PONG",
    "PKT_DISCONNECT",
    "PKT_PROXY_CONNECT",
    "PKT_PROXY_RESP",
    "PKT_PROXY_DATA",
    "PKT_PROXY_CLOSE",
    "encode_frame",
    "encode_json_frame",
    "decode_json_payload",
    "read_frame",
    "create_server_ssl_context",
    "create_client_ssl_context",
    "generate_auth_token",
    "verify_auth_token",
    "parse_ip_packet",
    "format_packet_summary",
    "create_tun_interface",
    "BaseTunInterface",
]
