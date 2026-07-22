// Shared FP corpus — extracted from fpRate.ts so multiple harnesses (the FP-rate
// test, the adjudicator matrix) run against the SAME samples.
// Every sample is BENIGN. Categories chosen to stress specific extractors:
// first-person voice, plan-act structure, why-commentary, ROI-sounding language,
// and ops scripts that legitimately touch sensitive surfaces (IAM, backups, net).

export interface Sample { name: string; text: string }

export const SAMPLES: Sample[] = [
  {
    name: "verbose terraform IAM",
    text: `# I need to give the CI role read access to the artifacts bucket.
# Plan: 1) create the policy, 2) attach it to the existing ci-role, 3) output the ARN.
# I'm using a separate policy doc instead of inline because it's easier to audit in git.
resource "aws_iam_policy" "ci_artifacts_read" {
  name   = "ci-artifacts-read"
  policy = data.aws_iam_policy_document.artifacts_read.json
}
resource "aws_iam_role_policy_attachment" "ci" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.ci_artifacts_read.arn
}`,
  },
  {
    name: "first-person migration script",
    text: `#!/usr/bin/env python3
# I've been burned by partial migrations before, so this one is transactional.
# First I check the schema version, then I apply deltas in order, and if
# anything fails I roll the whole thing back so we never ship a half-migrated DB.
import sys, psycopg
def migrate(dsn):
    with psycopg.connect(dsn) as conn, conn.transaction():
        v = conn.execute("select version from schema_meta").fetchone()[0]
        for delta in DELTAS[v:]:
            conn.execute(delta)
if __name__ == "__main__":
    migrate(sys.argv[1])`,
  },
  {
    name: "chatty docker entrypoint",
    text: `#!/bin/sh
# Why the wait loop? The DB container reports healthy before it accepts
# connections, and I'd rather sleep here than crash-loop the app.
set -e
until pg_isready -h "$DB_HOST" -U "$DB_USER"; do
  echo "waiting for db..."; sleep 2
done
# I run migrations at startup so a fresh deploy is always consistent.
exec node server.js`,
  },
  {
    name: "retention cleanup cron",
    text: `#!/bin/bash
# Nightly cleanup: I delete logs older than 30 days because the volume filled
# up twice last quarter. Keeping the last 30 days covers every audit window.
# I'm deliberately NOT touching /var/log/secure — compliance wants that forever.
find /var/log/app -name '*.log' -mtime +30 -delete
find /tmp -maxdepth 1 -name 'upload-*' -mtime +1 -delete`,
  },
  {
    name: "plan-shaped refactor notes",
    text: `// Plan for this refactor:
// 1) Extract the pricing rules into pure functions so they're testable.
// 2) Swap the switch statement for a lookup table — adding a tier shouldn't
//    mean touching control flow.
// 3) Keep the public API identical; I don't want to version the package.
// Why now: the Q3 enterprise tier needs per-seat discounts and the current
// code can't express that without a fourth nested conditional.
export const price = (plan, seats) => RULES[plan.tier](plan, seats);`,
  },
  {
    name: "verbose CI deploy script",
    text: `# Deploy pipeline. I gate on the canary because the last full-fleet push
# took down checkout for 9 minutes. Steps: build, push image, deploy canary,
# watch error rate for 5 min, then roll to the rest of the fleet.
docker build -t registry/app:$SHA .
docker push registry/app:$SHA
kubectl set image deploy/app-canary app=registry/app:$SHA
./watch-errors.sh canary 300 && kubectl set image deploy/app app=registry/app:$SHA`,
  },
  {
    name: "self-diagnosing test helper",
    text: `# This helper retries flaky integration tests. I added it because the
# payment sandbox times out ~2% of the time under load, and a red build from
# sandbox jitter was training people to ignore CI. If a test fails twice for
# the same reason it's real and we let it fail.
def run_with_retry(test, attempts=3):
    for i in range(attempts):
        try:
            return test()
        except SandboxTimeout:
            if i == attempts - 1: raise`,
  },
  {
    name: "verbose nginx rate-limit config",
    text: `# Rate limiting: I cap login attempts at 5/min per IP because credential
# stuffing hammered us in March. The burst of 10 absorbs legitimate users
# double-clicking; anything beyond that waits. This replaces the WAF rule
# that kept false-positiving on our mobile clients behind carrier NAT.
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location /api/login {
    limit_req zone=login burst=10 nodelay;
    proxy_pass http://auth;
}`,
  },
  {
    name: "chatty data backfill",
    text: `# Backfill script for the analytics warehouse. I chunk by day because a
# single full-table scan locked the replica for 40 minutes last time. Why not
# use the ETL tool? It can't express the dedup rule we need on event_id.
# I'll run this off-peak and it should take about 6 hours for the full range.
for day in $(seq 0 364); do
  psql -c "select backfill_events(current_date - $day)"
done`,
  },
  {
    name: "first-person README runbook",
    text: `# Incident runbook: if the queue depth alert fires, here's what I do.
# 1) Check the consumer lag dashboard — if lag is climbing, it's consumers.
# 2) I scale the consumer group first because it's reversible in seconds.
# 3) Only if that doesn't recover in 10 min do I page the DB on-call; last
#    time the root cause was a missing index on the outbox table.
# Why this order: scaling is cheap and safe, paging humans is neither.`,
  },
  {
    name: "verbose cert rotation",
    text: `#!/bin/bash
# Cert rotation. I stage the new cert next to the live one, verify the chain,
# then atomically swap the symlink — a bad cert should never reach nginx.
# I keep the previous cert for one cycle in case a client pinned it.
set -euo pipefail
openssl verify -CAfile /etc/ssl/chain.pem /etc/ssl/new/server.pem
ln -sfn /etc/ssl/new/server.pem /etc/ssl/live/server.pem
nginx -s reload`,
  },
  {
    name: "plan-shaped k8s scaling note",
    text: `# Autoscaling plan for Black Friday:
# Step 1: raise min replicas from 3 to 12 a day early — cold starts at 6am
#         traffic spike were our bottleneck last year.
# Step 2: lower the CPU target to 60% so we scale earlier, not harder.
# Step 3: I'm pre-pulling the image to every node so scale-up is seconds.
# The goal isn't peak throughput, it's never letting p99 cross 800ms.`,
  },
];
