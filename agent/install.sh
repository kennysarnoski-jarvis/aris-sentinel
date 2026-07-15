#!/usr/bin/env bash
# De-branded installer for the Aris Sentinel agent.
#
# Deploys under a GENERIC identity so on-box recon (ps, top, systemctl, ls, find)
# reveals nothing that says "security tool." An autonomous attacker that isn't trained
# to recognize Aris sees a boring telemetry daemon it can't confidently kill.
#
#   sudo ./install.sh [disguise-name]        # default: sys-telemetryd
#
# Pick a DIFFERENT name per customer — a fixed name would itself become a signature.
# Imports existing secrets from /etc/aris-sentinel.env if present (ANTHROPIC_API_KEY,
# ARIS_CLOUD_URL, ARIS_INGEST_KEY), so re-installing over the demo setup is seamless.
set -euo pipefail

# Args (any order): [disguise-name]  and optional --enforce.
# Default is MONITOR mode (detect + alert, no kill) — safe for a first pilot. Add
# --enforce only once you trust it on the target box.
NAME="sys-telemetryd"
EXECFLAGS=""
for a in "$@"; do
  case "$a" in
    --enforce) EXECFLAGS=" --enforce" ;;
    -*) ;;
    *) NAME="$a" ;;
  esac
done
SRC="$(cd "$(dirname "$0")" && pwd)"
LIB="/usr/local/lib/$NAME"
ENVF="/etc/$NAME.env"
UNIT="/etc/systemd/system/$NAME.service"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

# 1. code under a generic path with generic names
install -d "$LIB" "/var/lib/$NAME"
install -m 0644 "$SRC/sentinel-core.mjs"  "$LIB/core.mjs"
install -m 0644 "$SRC/sentinel-agent.mjs" "$LIB/agentd.mjs"
install -m 0644 "$SRC/aris_rules.yaml"    "$LIB/rules.yaml"
# agentd imports ./sentinel-core.mjs; we renamed it to core.mjs — fix the import.
sed -i 's#\./sentinel-core\.mjs#./core.mjs#' "$LIB/agentd.mjs"

# 2. rename the Falco binary so ITS process blends in too (it's a famous security tool).
FALCO_SRC="$(command -v falco || true)"
[ -n "$FALCO_SRC" ] || { echo "falco not found on PATH"; exit 1; }
cp -f "$FALCO_SRC" "$LIB/${NAME}-probe"
chmod 0755 "$LIB/${NAME}-probe"

# 3. env file at a generic path. Import prior secrets; set generic config.
OLD="/etc/aris-sentinel.env"
touch "$ENVF"; chmod 600 "$ENVF"
import_key() { local k="$1"; if ! grep -q "^$k=" "$ENVF" 2>/dev/null && [ -f "$OLD" ]; then grep "^$k=" "$OLD" >> "$ENVF" 2>/dev/null || true; fi; }
import_key ANTHROPIC_API_KEY
import_key ARIS_CLOUD_URL
import_key ARIS_INGEST_KEY
set_kv() { local k="$1" v="$2"; grep -q "^$k=" "$ENVF" || echo "$k=$v" >> "$ENVF"; }
set_kv ARIS_RULES     "$LIB/rules.yaml"
set_kv FALCO_BIN      "$LIB/${NAME}-probe"
set_kv ARIS_PROC_NAME "$NAME"
set_kv ARIS_INCIDENTS "/var/lib/$NAME/events"

# 4. generic systemd unit (Restart=always -> respawns if the attacker kills it;
#    killing/stopping it is a tamper event the dead-man's switch will catch).
cat > "$UNIT" <<UNITEOF
[Unit]
Description=System telemetry agent
After=network.target

[Service]
Type=simple
EnvironmentFile=$ENVF
WorkingDirectory=$LIB
ExecStart=/usr/bin/node $LIB/agentd.mjs$EXECFLAGS
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable "$NAME.service" >/dev/null 2>&1 || true
systemctl restart "$NAME.service"

echo "installed as '$NAME'"
echo "  mode    : ${EXECFLAGS:+ENFORCE (kills on detection)}${EXECFLAGS:-MONITOR (detect + alert, no kill — re-run with --enforce to arm)}"
echo "  service : systemctl status $NAME"
echo "  files   : $LIB   env: $ENVF"
echo "  ps/top  : shows '$NAME' (not node/sentinel);  falco -> ${NAME}-probe"
