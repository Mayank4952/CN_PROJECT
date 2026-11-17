"""
Certificate and Key Authority Generator
---------------------------------------
Generates a complete PKI infrastructure for mutual TLS (mTLS):
  - Root Certificate Authority (ca.key, ca.crt)
  - VPN Server Certificate & Key (server.key, server.crt) with SAN extensions
  - VPN Client Certificate & Key (client.key, client.crt)

Run:
  python cert_gen.py [--out-dir certs] [--server-san 127.0.0.1]
"""

import os
import sys
import argparse
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CertGen")


def run_cmd(cmd: list):
    """Executes a system command and raises an exception if it fails."""
    logger.debug(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        logger.error(f"Command failed: {' '.join(cmd)}\nError: {result.stderr}")
        raise RuntimeError(f"OpenSSL error: {result.stderr}")
    return result.stdout


def generate_pki(output_dir: str = "certs", server_san: str = "127.0.0.1,localhost", days: int = 365):
    """Generates CA, Server, and Client certificates using OpenSSL."""
    os.makedirs(output_dir, exist_ok=True)

    ca_key = os.path.join(output_dir, "ca.key")
    ca_crt = os.path.join(output_dir, "ca.crt")
    server_key = os.path.join(output_dir, "server.key")
    server_csr = os.path.join(output_dir, "server.csr")
    server_crt = os.path.join(output_dir, "server.crt")
    server_ext = os.path.join(output_dir, "server.ext")
    client_key = os.path.join(output_dir, "client.key")
    client_csr = os.path.join(output_dir, "client.csr")
    client_crt = os.path.join(output_dir, "client.crt")

    # 1. Generate Root CA
    logger.info("Generating Root Certificate Authority (CA)...")
    run_cmd([
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256",
        "-days", str(days * 2), "-nodes",
        "-keyout", ca_key,
        "-out", ca_crt,
        "-subj", "/CN=Secure-VPN-Root-CA/O=Group15/C=US"
    ])
    logger.info(f"CA Certificate created: {ca_crt}")

    # Prepare SAN config for Server
    san_entries = []
    for item in server_san.split(","):
        item = item.strip()
        # Check if IP or DNS
        if any(c.isalpha() for c in item):
            san_entries.append(f"DNS:{item}")
        else:
            san_entries.append(f"IP:{item}")
    san_string = ",".join(san_entries)

    with open(server_ext, "w", encoding="utf-8") as f:
        f.write("basicConstraints=CA:FALSE\n")
        f.write("keyUsage=digitalSignature,keyEncipherment\n")
        f.write("extendedKeyUsage=serverAuth\n")
        f.write(f"subjectAltName={san_string}\n")

    # 2. Generate Server Key & CSR
    logger.info("Generating VPN Server Certificate and Key...")
    run_cmd([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", server_key,
        "-out", server_csr,
        "-subj", "/CN=vpn-server/O=VPN/C=US"
    ])

    # Sign Server Cert with CA
    run_cmd([
        "openssl", "x509", "-req", "-sha256",
        "-in", server_csr,
        "-CA", ca_crt,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", server_crt,
        "-days", str(days),
        "-extfile", server_ext
    ])
    logger.info(f"Server Certificate signed: {server_crt} (SANs: {san_string})")

    # 3. Generate Client Key & CSR
    logger.info("Generating VPN Client Certificate and Key (for mTLS)...")
    run_cmd([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", client_key,
        "-out", client_csr,
        "-subj", "/CN=vpn-client-1/O=VPN/C=US"
    ])

    client_ext = os.path.join(output_dir, "client.ext")
    with open(client_ext, "w", encoding="utf-8") as f:
        f.write("basicConstraints=CA:FALSE\n")
        f.write("keyUsage=digitalSignature,keyEncipherment\n")
        f.write("extendedKeyUsage=clientAuth\n")

    # Sign Client Cert with CA
    run_cmd([
        "openssl", "x509", "-req", "-sha256",
        "-in", client_csr,
        "-CA", ca_crt,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", client_crt,
        "-days", str(days),
        "-extfile", client_ext
    ])
    logger.info(f"Client Certificate signed: {client_crt}")

    # Clean temporary CSR and EXT files
    for tmp in [server_csr, server_ext, client_csr, client_ext]:
        try:
            os.remove(tmp)
        except OSError:
            pass

    logger.info("\nPKI Generation Complete!")
    logger.info(f"Certificates directory: {os.path.abspath(output_dir)}")
    logger.info("  - ca.crt       : Root CA public certificate (distribute to all clients & servers)")
    logger.info("  - server.crt   : VPN server certificate")
    logger.info("  - server.key   : VPN server private key")
    logger.info("  - client.crt   : VPN client certificate")
    logger.info("  - client.key   : VPN client private key")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate PKI Certificates for Secure VPN - Group 15")
    parser.add_argument("--out-dir", default="certs", help="Output directory for generated certificates (default: certs)")
    parser.add_argument("--server-san", default="127.0.0.1,localhost", help="Comma-separated SANs (e.g. '127.0.0.1,vpn.mycompany.com')")
    parser.add_argument("--days", type=int, default=365, help="Certificate validity period in days")
    args = parser.parse_args()

    generate_pki(output_dir=args.out_dir, server_san=args.server_san, days=args.days)
