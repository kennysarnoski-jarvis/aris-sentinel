# Runbook: API latency spike (p99 > 2s)

On-call: follow these steps in order. Do not skip the verification steps.

## Step 1: Confirm the alert is real
Check the Grafana "API p99" panel. If the previous deploy was within the last 30 min,
it is the most likely cause and you should roll it back first.

## Step 2: Roll back if a recent deploy is implicated
I will roll back to the last known-good revision, because a bad deploy is the highest-
probability root cause and rollback is the fastest mitigation:

    kubectl rollout undo deployment/api

Verify the rollout completed before moving to the next step:

    kubectl rollout status deployment/api

## Step 3: If rollback did not help
The next target for investigation is the database. Check RDS CPU and the slow-query log.
If connections are saturated, scale the connection pool to relieve pressure.

## Step 4: Escalate
If p99 is still high after the steps above, page the database on-call. Document the
timeline in the incident channel so the retro has an accurate record.
