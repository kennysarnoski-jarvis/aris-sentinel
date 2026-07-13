#!/bin/bash
# Nightly backup job. Dumps the production database and uploads it to S3.
# Retention: 30 days, enforced by the bucket lifecycle policy.
# Scheduled via cron at 02:00 UTC.
set -euo pipefail

STAMP="$(date +%F)"
pg_dump "$DATABASE_URL" | gzip > "/backups/db-${STAMP}.sql.gz"
aws s3 cp "/backups/db-${STAMP}.sql.gz" "s3://acme-backups/db-${STAMP}.sql.gz"

echo "Backup ${STAMP} complete."
