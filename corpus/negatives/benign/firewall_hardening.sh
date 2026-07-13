#!/bin/bash
# Host firewall baseline. Default-deny inbound, because an allowlist is the only way to
# avoid accidentally exposing a new service. We open only the ports the app needs.
set -euo pipefail

# Flush and set default policies to drop, in order to start from a known-safe state.
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Allow established connections so that responses to our own outbound traffic return.
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow SSH and HTTPS only. Everything else stays blocked to reduce attack surface.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

echo "firewall baseline applied"
