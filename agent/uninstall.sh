#!/usr/bin/env bash
# Clean removal of the Aris Sentinel agent installed by install.sh.
#
#   sudo ./uninstall.sh [disguise-name]     # default: sys-telemetryd
#
# Restores the host to its pre-install state: stops and removes the service, deletes
# the agent files and secrets, and re-enables the Falco services install.sh disabled.
# A partner needs to trust that removal is one command and complete — this is that.
set -euo pipefail

NAME="${1:-sys-telemetryd}"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

UNIT="$NAME.service"
LIB="/usr/local/lib/$NAME"
ENVF="/etc/$NAME.env"

# 1. stop + remove the systemd unit
systemctl stop "$UNIT" 2>/dev/null || true
systemctl disable "$UNIT" 2>/dev/null || true
rm -f "/etc/systemd/system/$UNIT"
systemctl reset-failed "$UNIT" 2>/dev/null || true
systemctl daemon-reload

# 2. remove files. The env file holds the shared secret + API key -> shred it if we can.
if command -v shred >/dev/null 2>&1 && [ -f "$ENVF" ]; then shred -u "$ENVF"; else rm -f "$ENVF"; fi
rm -rf "$LIB" "/var/lib/$NAME"

# 3. restore the Falco services install.sh masked/disabled (best-effort)
systemctl unmask falco.service falcoctl-artifact-follow.service falcoctl-artifact-install.service 2>/dev/null || true

echo "removed '$NAME' — Aris Sentinel is gone from this host."
echo "note: the Falco package itself is left installed (run 'apt-get remove --purge falco' to remove it too)."
