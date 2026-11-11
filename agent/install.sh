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
# OPENAI_*, KIMI_API_KEY, ARIS_TIER2_*, ARIS_CLOUD_URL, ARIS_INGEST_KEY), so re-installing over the demo setup is seamless.
set -euo pipefail

# Args (any order): [disguise-name]  and optional --enforce [--kill-session] [--tripwire] [--behavior].
# Default is MONITOR mode (detect + alert, no kill) — safe for a first pilot. Add
# --enforce only once you trust it on the target box. --kill-session (with --enforce) also
# ends the offender's whole session and quarantines it; it does nothing on its own.
# --tripwire (any mode) plants decoy directories (ARIS_TRIPWIRE_DIRS, default
# /opt/vault-access and /var/backups/vault-access) whose README asks an automated agent to
# run one canary command. That command running is a detection; uninstall.sh removes them.
# --behavior (any mode) reports a session that asks about many areas of the host in a few
# minutes (who am I, what runs here, the account database, what may I run as root). It is
# an alert and never a kill, and it plants nothing.
NAME="sys-telemetryd"
ENFORCE_FLAG=""
SESSION_FLAG=""
TRIPWIRE_FLAG=""
BEHAVIOR_FLAG=""
for a in "$@"; do
  case "$a" in
    --enforce) ENFORCE_FLAG=" --enforce" ;;
    --kill-session) SESSION_FLAG=" --kill-session" ;;
    --tripwire) TRIPWIRE_FLAG=" --tripwire" ;;
    --behavior) BEHAVIOR_FLAG=" --behavior" ;;
    -*) ;;
    *) NAME="$a" ;;
  esac
done
if [ -n "$SESSION_FLAG" ] && [ -z "$ENFORCE_FLAG" ]; then echo "--kill-session needs --enforce; ignoring it (staying in MONITOR mode)"; SESSION_FLAG=""; fi
EXECFLAGS="$ENFORCE_FLAG$SESSION_FLAG$TRIPWIRE_FLAG$BEHAVIOR_FLAG"
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
for k in ANTHROPIC_API_KEY ARIS_MODEL OPENAI_API_KEY OPENAI_BASE_URL OPENAI_MODEL KIMI_API_KEY ARIS_TIER2_ORDER ARIS_TIER2_EFFORT ARIS_TIER2_FALLBACKS ARIS_FAIL_MODE; do import_key "$k"; done
import_key ARIS_CLOUD_URL
import_key ARIS_INGEST_KEY
set_kv() { local k="$1" v="$2"; grep -q "^$k=" "$ENVF" || echo "$k=$v" >> "$ENVF"; }
set_kv ARIS_RULES     "$LIB/rules.yaml"
set_kv FALCO_BIN      "$LIB/${NAME}-probe"
set_kv ARIS_PROC_NAME "$NAME"
set_kv ARIS_INCIDENTS "/var/lib/$NAME/events"
set_kv ARIS_TRIPWIRE_STATE "/var/lib/$NAME/tripwire.json"

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
echo "  mode    : ${ENFORCE_FLAG:+ENFORCE (kills on detection)${SESSION_FLAG:+ + SESSION KILL (ends the whole offending session and quarantines it)}}${ENFORCE_FLAG:-MONITOR (detect + alert, no kill — re-run with --enforce to arm)}"
echo "  tripwire: ${TRIPWIRE_FLAG:+ON (decoys planted; the canary command running is a detection, see the service log for where)}${TRIPWIRE_FLAG:-off (re-run with --tripwire to plant decoys)}"
echo "  behavior: ${BEHAVIOR_FLAG:+ON (a session that sweeps the host is reported, never killed)}${BEHAVIOR_FLAG:-off (re-run with --behavior to report sessions that sweep the host)}"
echo "  service : systemctl status $NAME"
echo "  files   : $LIB   env: $ENVF"
echo "  ps/top  : shows '$NAME' (not node/sentinel);  falco -> ${NAME}-probe"
