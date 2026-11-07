# The kill demo, reproducibly

`docs/demo-kill.gif` is the agent stopping a narrated attacker on a real Linux kernel:
Falco (eBPF) sees the exec, tier 1 scores the script at 0.78, the process tree is
SIGKILLed before its destructive step, and a benign job on the same box is untouched.
This is the demo from [agent/DEPLOY.md](../../agent/DEPLOY.md), run in a throwaway VM so
anyone with a Mac or Linux box can reproduce it in about ten minutes.

## 1. Boot the VM (Lima: `brew install lima`)

```bash
limactl start --name aris-demo --tty=false docs/demo-kill/lima.yaml
```

Ubuntu 24.04, Falco (modern eBPF, no kernel module) and Node installed natively by the
provisioning script, the repo mounted read-write at its own path. Verified on an Apple
M5 Pro: kernel 6.8, Falco 0.45, BTF present.

## 2. Arm the agent inside the VM, in enforce mode

```bash
limactl shell aris-demo -- sudo bash -c 'cd /Volumes/ArisLLM/Projects-Archive/aris-sentinel && ARIS_RULES=$PWD/agent/aris_rules.yaml ARIS_INCIDENTS=/tmp/incidents.jsonl setsid nohup node agent/sentinel-agent.mjs --enforce > /tmp/agent.log 2>&1 < /dev/null & sleep 5; tail -3 /tmp/agent.log'
```

Adjust the repo path if yours differs. The log should end with `armed — watching process
execs via Falco`. The `sys_enter_creat` warning from Falco on arm64 is harmless.

## 3. Stage the demo scripts and run them

```bash
limactl shell aris-demo -- bash -c 'cp /Volumes/ArisLLM/Projects-Archive/aris-sentinel/agent/{attacker_impact,benign_job}.py /tmp/ && cd /tmp && python3 attacker_impact.py; python3 benign_job.py; ls /tmp/DESTRUCTIVE_STEP_HAPPENED /tmp/BENIGN_JOB_RAN; grep -A2 "SENTINEL KILL" /tmp/agent.log | tail -3'
```

Expected: the attacker is killed within milliseconds of exec, `DESTRUCTIVE_STEP_HAPPENED`
never appears, `BENIGN_JOB_RAN` does, and the log shows `SENTINEL KILL tier-1 … score=0.78`
with `cmd: python3 attacker_impact.py`. The incident row in `/tmp/incidents.jsonl` carries
`cwd: /tmp/`, the process's own working directory, which is how the agent found the script.

## 4. Record it (VHS: `brew install vhs`)

```bash
limactl shell aris-demo -- rm -f /tmp/DESTRUCTIVE_STEP_HAPPENED /tmp/BENIGN_JOB_RAN
```

```bash
vhs docs/demo-kill.tape
```

The tape drives the VM from the host through `limactl shell`, so the recording is the
real thing, not a replay.

## 5. Tear down

```bash
limactl delete -f aris-demo
```
