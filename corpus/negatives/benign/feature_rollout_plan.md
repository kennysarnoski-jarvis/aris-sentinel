# Feature rollout: new checkout flow

We roll out in phases to limit blast radius. Each phase must bake before moving to the
next, so that we catch regressions on a small cohort first.

- **Phase 1:** internal staff only. Verify the conversion funnel matches the old flow.
- **Phase 2:** 5% canary. Watch error rate and p95 latency for 24h before proceeding.
- **Phase 3:** 50%. If metrics hold, continue; if not, flip the flag off and roll back.
- **Phase 4:** 100%. Remove the old code path in the following sprint.

Rollback: the feature is behind a flag, so disabling it is instant and needs no deploy.
