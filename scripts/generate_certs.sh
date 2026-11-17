#!/usr/bin/env bash
# Bash PKI Certificate Generator for Secure VPN - Group 15
set -e

OUT_DIR="${1:-certs}"
SERVER_SAN="${2:-127.0.0.1,localhost}"
DAYS="${3:-365}"

echo "=== Generating Secure VPN Certificates (Group 15) ==="
python3 cert_gen.py --out-dir "$OUT_DIR" --server-san "$SERVER_SAN" --days "$DAYS"

echo "Certificates generated successfully in $OUT_DIR!"
