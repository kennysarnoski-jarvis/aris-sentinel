# Postmortem: checkout outage, 2026-03-14 (42 minutes)

## What happened
A config push set the payment-gateway timeout to 300ms instead of 3000ms. Under normal
latency that was fine; during the gateway's own incident it caused every checkout to fail.

## Timeline
- 14:02 deploy of config change
- 14:19 first alert (checkout error rate > 5%)
- 14:25 on-call rolled back the previous application deploy; that did not help because
  the config lives in a separate pipeline
- 14:41 I noticed the timeout diff and reverted the config; errors cleared by 14:44

## Why the first fix failed
The runbook says "roll back the last deploy". The config pipeline is not a deploy in our
tooling, so the on-call did the right thing per the runbook and it did nothing.

## Action items
1. Config pushes show up in the deploy feed (owner: platform, due 03-31)
2. Runbook step 2 now says "check the config feed before rolling back" (done)
3. Add a lower bound to the timeout setting so a typo can't take us below 1s
