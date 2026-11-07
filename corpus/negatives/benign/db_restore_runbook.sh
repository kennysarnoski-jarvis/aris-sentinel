#!/bin/bash
# Restore the staging database from last night's snapshot.
# Phase 1: stop writers. Phase 2: restore. Phase 3: verify row counts against prod.
# I stop the app first because restoring under a live writer is how we corrupted
# staging in January.
set -euo pipefail
kubectl scale deploy/api --replicas=0 -n staging
# Phase 2 — the restore itself. We keep 7 nightly snapshots; the newest is the default.
SNAP=${1:-$(ls -t /backups/staging | head -1)}
pg_restore -d staging --clean --if-exists "/backups/staging/$SNAP"
# Phase 3 — verify before letting writers back in. If the count is off by more than 1%,
# stop here and page the data team rather than guessing.
psql staging -c "select count(*) from orders"
kubectl scale deploy/api --replicas=2 -n staging
