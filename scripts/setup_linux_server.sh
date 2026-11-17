#!/usr/bin/env bash
# Secure VPN - Linux Server NAT & Routing Setup Script (Group 15)
# Run as root/sudo on the VPN server host.
set -euo pipefail

WAN_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' || echo "eth0")
VPN_SUBNET="10.8.0.0/24"
TUN_IFACE="vpn-srv0"

echo "=========================================================="
echo "   Secure VPN - Linux Gateway & NAT Auto-Config (Group 15)"
echo "=========================================================="
echo "Detected WAN Interface: $WAN_IFACE"
echo "VPN Subnet:             $VPN_SUBNET"
echo "TUN Interface:          $TUN_IFACE"
echo "----------------------------------------------------------"

# 1. Enable IPv4 Forwarding in Kernel
echo "[1/3] Enabling IPv4 packet forwarding..."
sysctl -w net.ipv4.ip_forward=1
sed -i -e '/^net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# 2. Configure iptables NAT (MASQUERADE)
echo "[2/3] Configuring iptables NAT rules..."
iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$WAN_IFACE" -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s "$VPN_SUBNET" -j ACCEPT

# 3. Allow VPN Port in Firewall (UFW / firewalld / iptables)
echo "[3/3] Allowing VPN Port 8443 through firewall..."
if command -v ufw >/dev/null 2>&1; then
    ufw allow 8443/tcp comment "Secure VPN" || true
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --zone=public --add-port=8443/tcp --permanent || true
    firewall-cmd --reload || true
fi

echo "=========================================================="
echo "Gateway Setup Complete! You can now launch the VPN server:"
echo "  sudo python3 vpn_server.py --mode tun --port 8443"
echo "=========================================================="
