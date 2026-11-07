# Plan: tune the API autoscaler

The current HPA scales on CPU at 80%, which lags real demand by about two minutes.
The goal is to scale on request rate instead.

## Steps
1. Export the request-rate metric from the ingress to the metrics adapter.
2. Add a second HPA target on `requests_per_second` at 200 per pod.
3. Keep the CPU target as a floor for a week and compare.
4. If p99 improves and cost does not rise more than 10%, drop the CPU target.

## Why not just lower the CPU threshold?
We tried that in Q1. It over-provisioned during batch jobs, which are CPU-heavy but not
latency-sensitive, so we paid for pods that served nothing.
