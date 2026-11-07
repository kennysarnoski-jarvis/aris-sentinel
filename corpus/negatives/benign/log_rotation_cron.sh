#!/bin/bash
# Daily log rotation for the app tier. Runs from cron at 02:00.
# We compress yesterday's logs and delete anything older than 14 days because the
# volume filled twice last quarter. Audit logs are excluded: compliance keeps those.
set -euo pipefail
cd /var/log/app
for f in *.log.1; do
  [ -e "$f" ] || continue
  gzip -9 "$f"
done
find . -name '*.gz' -mtime +14 ! -name 'audit*' -delete
# Verify we did not delete today's log by accident before exiting cleanly.
test -s app.log
