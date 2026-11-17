"""
IP Packet Header Parser and Traffic Inspector
---------------------------------------------
Parses raw Layer 3 IP packets (IPv4 and IPv6) to extract routing
metadata, source/destination IPs, protocols, and payload sizes.
"""

import socket
import struct
from typing import Optional, Dict, Any

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


def parse_ip_packet(packet_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a raw IP packet (IPv4 or IPv6) and returns metadata.
    Returns None if packet is malformed or too short.
    """
    if len(packet_bytes) < 20:
        return None

    version = packet_bytes[0] >> 4

    if version == 4:
        return _parse_ipv4(packet_bytes)
    elif version == 6:
        return _parse_ipv6(packet_bytes)
    else:
        return None


def _parse_ipv4(packet_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Parse an IPv4 packet header."""
    if len(packet_bytes) < 20:
        return None

    ihl = (packet_bytes[0] & 0x0F) * 4
    if len(packet_bytes) < ihl:
        return None

    tos, total_len, identification, flags_offset, ttl, proto, checksum = struct.unpack(
        "!BHHHBBH", packet_bytes[1:12]
    )
    src_ip = socket.inet_ntoa(packet_bytes[12:16])
    dst_ip = socket.inet_ntoa(packet_bytes[16:20])

    proto_name = PROTO_NAMES.get(proto, f"Proto-{proto}")

    info = {
        "version": 4,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "protocol_name": proto_name,
        "ttl": ttl,
        "total_len": total_len,
        "header_len": ihl,
        "payload_len": len(packet_bytes) - ihl,
    }

    # Extract port numbers for TCP and UDP
    if proto in (PROTO_TCP, PROTO_UDP) and len(packet_bytes) >= ihl + 4:
        src_port, dst_port = struct.unpack("!HH", packet_bytes[ihl:ihl + 4])
        info["src_port"] = src_port
        info["dst_port"] = dst_port

    return info


def _parse_ipv6(packet_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Parse an IPv6 packet header."""
    if len(packet_bytes) < 40:
        return None

    vtc_fl, payload_len, next_header, hop_limit = struct.unpack("!IHBB", packet_bytes[:8])
    src_ip = socket.inet_ntop(socket.AF_INET6, packet_bytes[8:24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, packet_bytes[24:40])

    proto_name = PROTO_NAMES.get(next_header, f"Proto-{next_header}")

    info = {
        "version": 6,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": next_header,
        "protocol_name": proto_name,
        "ttl": hop_limit,
        "total_len": 40 + payload_len,
        "header_len": 40,
        "payload_len": payload_len,
    }

    if next_header in (PROTO_TCP, PROTO_UDP) and len(packet_bytes) >= 44:
        src_port, dst_port = struct.unpack("!HH", packet_bytes[40:44])
        info["src_port"] = src_port
        info["dst_port"] = dst_port

    return info


def format_packet_summary(info: Optional[Dict[str, Any]]) -> str:
    """Format parsed packet metadata into a clean log line."""
    if not info:
        return "[Unknown / Malformed Packet]"

    ver = f"IPv{info['version']}"
    src = info["src_ip"]
    dst = info["dst_ip"]
    proto = info["protocol_name"]

    if "src_port" in info and "dst_port" in info:
        return f"[{ver}] {src}:{info['src_port']} -> {dst}:{info['dst_port']} ({proto}, len={info['total_len']}, ttl={info['ttl']})"
    return f"[{ver}] {src} -> {dst} ({proto}, len={info['total_len']}, ttl={info['ttl']})"
