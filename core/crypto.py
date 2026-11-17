"""
TLS 1.3 / mTLS Cryptographic Context and Security Setup
-------------------------------------------------------
Provides hardened SSL/TLS contexts with modern cipher suites,
mutual certificate authentication (mTLS), and pre-shared token validation.
"""

import os
import ssl
import hmac
import hashlib
import logging

logger = logging.getLogger("VPN.Crypto")


def create_server_ssl_context(
    cert_file: str,
    key_file: str,
    ca_file: str = None,
    verify_client: bool = False
) -> ssl.SSLContext:
    """
    Creates an SSL context for the VPN Server.
    Enforces TLS 1.3 / TLS 1.2 with PFS (Perfect Forward Secrecy) and AEAD ciphers.
    """
    if not os.path.isfile(cert_file):
        raise FileNotFoundError(f"Server certificate file not found: {cert_file}")
    if not os.path.isfile(key_file):
        raise FileNotFoundError(f"Server private key file not found: {key_file}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # Security options
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

    # Prefer modern AEAD ciphers
    try:
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
        )
    except ssl.SSLError:
        pass  # Fall back to default TLS 1.3 ciphers

    # Mutual TLS (mTLS) - authenticate the client
    if verify_client:
        if not ca_file or not os.path.isfile(ca_file):
            raise FileNotFoundError(f"CA certificate required for client verification: {ca_file}")
        ctx.load_verify_locations(cafile=ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        logger.info("Mutual TLS (mTLS) enabled: Client certificates will be strictly verified against CA.")
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def create_client_ssl_context(
    ca_file: str = None,
    cert_file: str = None,
    key_file: str = None,
    verify_server: bool = True
) -> ssl.SSLContext:
    """
    Creates an SSL context for the VPN Client.
    Optionally authenticates to server using client certificate (mTLS).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # Load client certificate for mTLS if provided
    if cert_file and key_file:
        if os.path.isfile(cert_file) and os.path.isfile(key_file):
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
            logger.info("Loaded client certificate and private key for mTLS.")

    if verify_server and ca_file and os.path.isfile(ca_file):
        ctx.load_verify_locations(cafile=ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # Custom VPN hostnames often use IP addresses
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if not verify_server:
            logger.warning("Server certificate verification disabled (Development / Self-Signed Mode).")

    return ctx


def generate_auth_token(secret: str, salt: str) -> str:
    """Generate an HMAC-SHA256 authentication token using a shared secret."""
    return hmac.new(secret.encode("utf-8"), salt.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_auth_token(secret: str, salt: str, token: str) -> bool:
    """Constant-time verification of shared secret token."""
    expected = generate_auth_token(secret, salt)
    return hmac.compare_digest(expected, token)
