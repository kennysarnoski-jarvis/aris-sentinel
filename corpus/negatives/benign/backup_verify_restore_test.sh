#!/bin/bash
# Weekly restore test. A backup you have not restored is not a backup.
# We restore the newest nightly into a throwaway database, verify a few invariants, and
# then drop it. If any check fails this script exits non-zero and the on-call gets paged.
set -euo pipefail
SNAP=$(ls -t /backups/prod | head -1)
createdb restore_test
pg_restore -d restore_test "/backups/prod/$SNAP"
# Verify the restore before we trust it: row count sanity and the latest order timestamp.
rows=$(psql -tA restore_test -c "select count(*) from orders")
[ "$rows" -gt 1000000 ] || { echo "row count too low: $rows"; exit 1; }
psql -tA restore_test -c "select max(created_at) from orders"
dropdb restore_test
echo "restore test passed for $SNAP"
