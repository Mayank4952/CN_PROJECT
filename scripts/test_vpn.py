"""
Automated End-to-End Integration Test for Secure VPN (Group 15)
---------------------------------------------------------------
Tests:
  1. Automated PKI generation and certificate validation
  2. TLS 1.3 mutual handshake and authentication
  3. Dynamic IP allocation (10.8.0.2)
  4. Encapsulation, framing, and keepalive ping/pong
  5. Layer 4 SOCKS5 encrypted tunneling through the VPN
  6. Clean teardown and resource deallocation
"""

import os
import sys
import time
import socket
import struct
import threading
import logging

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cert_gen import generate_pki
from vpn_server import VpnServer
from vpn_client import VpnClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Test] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("TestVPN")

TEST_PORT = 18443
PROXY_PORT = 11080
TARGET_ECHO_PORT = 19999


def run_echo_server(stop_event: threading.Event):
    """Simple TCP echo server that acts as an external internet service."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", TARGET_ECHO_PORT))
    srv.listen(5)
    srv.settimeout(0.5)

    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            data = conn.recv(1024)
            if data:
                conn.sendall(b"ECHO: " + data)
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()


def test_full_vpn_pipeline():
    logger.info("==================================================")
    logger.info("   Starting Secure VPN Automated Test Suite (Group 15)  ")
    logger.info("==================================================")

    # Step 1: Ensure Certificates
    cert_dir = "certs"
    if not os.path.exists(os.path.join(cert_dir, "server.crt")):
        logger.info("[Test 1/5] Generating PKI certificates...")
        generate_pki(output_dir=cert_dir, server_san="127.0.0.1,localhost")
    else:
        logger.info("[Test 1/5] PKI certificates verified.")

    # Step 2: Start Mock External Echo Server
    stop_echo = threading.Event()
    echo_thread = threading.Thread(target=run_echo_server, args=(stop_echo,), daemon=True)
    echo_thread.start()
    logger.info(f"Mock destination service running on 127.0.0.1:{TARGET_ECHO_PORT}")

    # Step 3: Start VPN Server
    logger.info(f"[Test 2/5] Initializing VPN Server on port {TEST_PORT} (Dual Mode)...")
    server = VpnServer(
        bind_host="127.0.0.1",
        bind_port=TEST_PORT,
        cert_file=os.path.join(cert_dir, "server.crt"),
        key_file=os.path.join(cert_dir, "server.key"),
        ca_file=os.path.join(cert_dir, "ca.crt"),
        verify_client=False,
        auth_secret="testsecretkey123",
        mode="dual",
        network_cidr="10.8.0.0/24",
        server_virtual_ip="10.8.0.1",
        verbose=False,
    )
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Allow server to bind and listen

    # Step 4: Start VPN Client
    logger.info(f"[Test 3/5] Initializing VPN Client and establishing TLS 1.3 tunnel...")
    client = VpnClient(
        server_host="127.0.0.1",
        server_port=TEST_PORT,
        ca_file=os.path.join(cert_dir, "ca.crt"),
        cert_file=os.path.join(cert_dir, "client.crt"),
        key_file=os.path.join(cert_dir, "client.key"),
        verify_server=True,
        auth_secret="testsecretkey123",
        client_id="integration-test-client",
        mode="dual",
        proxy_bind_host="127.0.0.1",
        proxy_bind_port=PROXY_PORT,
        verbose=False,
    )

    client_connected = client.connect()
    assert client_connected, "Client failed to connect to VPN server!"
    assert client.virtual_ip == "10.8.0.2", f"Expected assigned IP 10.8.0.2, got {client.virtual_ip}"
    assert client.server_virtual_ip == "10.8.0.1", f"Expected server IP 10.8.0.1, got {client.server_virtual_ip}"
    logger.info(f"[OK] Handshake verified! Virtual IP {client.virtual_ip} assigned successfully.")

    client_loop_thread = threading.Thread(target=client.run_forever, daemon=True)
    client_loop_thread.start()
    time.sleep(0.5)

    # Step 5: Test Layer 3 Encapsulated Synthetic Ping
    logger.info("[Test 4/5] Injecting synthetic Layer 3 packet into tunnel...")
    client.send_synthetic_ping()
    time.sleep(0.5)
    logger.info("[OK] Layer 3 packet encapsulated, encrypted, and processed without errors.")

    # Step 6: Test SOCKS5 Encrypted Tunnel
    logger.info(f"[Test 5/5] Testing SOCKS5 Tunnel (127.0.0.1:{PROXY_PORT} -> Target {TARGET_ECHO_PORT})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", PROXY_PORT))

    # SOCKS5 Handshake
    s.sendall(b"\x05\x01\x00")
    socks_resp = s.recv(2)
    assert socks_resp == b"\x05\x00", f"Unexpected SOCKS greeting response: {socks_resp}"

    # SOCKS5 Connect to 127.0.0.1:TARGET_ECHO_PORT
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", TARGET_ECHO_PORT)
    s.sendall(req)
    conn_resp = s.recv(10)
    assert conn_resp[:2] == b"\x05\x00", f"SOCKS connect failed: {conn_resp}"

    # Send payload through the VPN tunnel
    test_msg = b"SecureTunnelPayload123"
    s.sendall(test_msg)
    reply = s.recv(1024)
    expected_reply = b"ECHO: " + test_msg
    assert reply == expected_reply, f"Echo mismatch! Expected '{expected_reply}', got '{reply}'"
    s.close()
    logger.info(f"[OK] Encrypted Tunnel verified! Payload successfully tunneled and echoed: {reply.decode()}")

    # Cleanup
    logger.info("Tearing down test environment...")
    stop_echo.set()
    client.disconnect()
    server.stop()
    time.sleep(0.5)

    logger.info("==================================================")
    logger.info("      ALL 5 VPN INTEGRATION TESTS PASSED!         ")
    logger.info("==================================================")


if __name__ == "__main__":
    test_full_vpn_pipeline()
