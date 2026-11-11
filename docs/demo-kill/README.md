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

## Live validation of session evidence and session kill

The same VM runs an end-to-end check of the session features against real processes and
the session ids Falco reports. It arms the agent with `--enforce --kill-session` and no
judge, and needs nothing but the mounted repo:

```bash
limactl shell aris-demo -- sudo bash /Volumes/ArisLLM/Projects-Archive/aris-sentinel/docs/demo-kill/validate-session-kill.sh
```

Six scenarios, 24 checks, about 75 seconds: a session kill (tree, driving shell and a
helper), quarantine of a convicted session with a protected survivor, an unrelated
control, a session alert from thin narration across three execs (which must kill
nothing), reading the incident log with an interpreter (which must not be an attack), and
a conviction inside the agent's own launch session (process killed, session spared).
Exit code 0 means every check passed. 2 CPUs and 4 GB are enough:
`limactl start --cpus 2 --memory 4 …`.

The first run of this script, on 2026-11-10, failed 8 of 17 checks and found two real
bugs: the agent read its own incident log as a script and convicted the reader, and the
session kill that followed quarantined the operator's own terminal. Both are fixed and
both are now scenarios here.

A third came out of the tripwire run the same day. The script passed 23/23 while the
convicted session's driving shell still got one more command off: the agent killed the
offender first, that woke the shell waiting on it, and the shell ran its next command
before the session kill reached it. The old check had a `sleep`
there, which hid it. The session is now killed before the offender, outermost ancestor
first, and check 24 is a `touch` on the very next line that must never happen.

## Live validation of the tripwire

`validate-tripwire.sh` does the same for `--tripwire`: it arms the agent with
`--enforce --kill-session --tripwire`, the decoys under `/tmp/aris-tripwire` rather than
`/opt`, and checks eight things in 26 checks: the decoys are planted with the right modes
and the state file is root-only; an unprivileged session that reads the README raises an
alert and carries on; a stand-in "agent" (a five-line shell script) that runs the command
it found in the README is convicted and its whole session ended before its very next command; the
same command wrapped in base64 is convicted too; an unrelated session is untouched; the
token appears in neither log; a restart keeps the token and puts a deleted decoy back; and
`--tripwire-remove` leaves nothing behind.

```bash
limactl shell aris-demo -- sudo bash /Volumes/ArisLLM/Projects-Archive/aris-sentinel/docs/demo-kill/validate-tripwire.sh
```

**Run live on 2026-11-10: 26/26** (kernel 6.8.0-147, Falco 0.45.2, Node 18.19, 2 CPU / 4 GB).
It did not start there. The first run passed 25/25 and the log still showed the session's
next command being executed after the conviction. With the check tightened to "the very
next command must not run" it failed 24/26, for two reasons that both needed fixing:

1. The decoy helper returned at once, so the session was already one command ahead when
   the conviction was handled (its next exec was logged 5 ms after the conviction). The
   helper now holds its caller for two seconds.
2. Holding was not enough: the agent killed the helper first, which is exactly what let
   the waiting shell go. The session kill now runs before the offender is killed (see the
   session-kill section above; the same fix, the same bug).

## Live validation of session behavior

`validate-behavior.sh` does the same for `--behavior`. It arms the agent fully
(`--enforce --kill-session --behavior`, no judge) so that "a sweep never kills" is checked
where a kill was possible, shortens the window to 20 seconds, and runs eight scenarios in
29 checks: a silent sweep of six questions two seconds apart (one alert, on the command
that completes it, nothing killed, the session runs on); the same questions chained three
to a `bash -c`; a login triage that must stay quiet; a script whose *text* holds a whole
sweep that never runs; a collector that reads everything back to back (reported: the
known false positive); half a sweep in each of two sessions; a sweep followed by a
narrated step (the sweep is an alert, the narrated step is a kill); and the first sweep
again at one command every six seconds, slower than the window.

```bash
limactl shell aris-demo -- sudo bash /Volumes/ArisLLM/Projects-Archive/aris-sentinel/docs/demo-kill/validate-behavior.sh
```

**Run live on 2026-11-10: 29/29**, three times in a row on the final code (kernel 6.8.0-147, Falco 0.45.2,
Node 18.19, 2 CPU / 4 GB). The first run passed as written (28/28) and its incident log
still held a finding. The alert reported the median gap between commands, and for the
chained sweep that gap was one millisecond: on a real host `bash -c 'id; uname -a'` is
three execs a millisecond apart, so the gap between execs measures fan-out, not think
time. The alert now groups execs less than half a second apart into one **step** and
reports the steps and the pauses between them: six steps with two-second pauses for the
paced sweep, three for the chained one, one for the collector. Check 12 pins that down.

Two things Falco does that are worth knowing when you read an incident: a setuid program
is reported under its effective user (`sudo -n -l` run by `nobody` shows `user=root`), and
a `#!` script is reported as `<comm> <script path> <args>` with the comm cut to 15
characters (`deb-systemd-hel /usr/bin/deb-systemd-helper enable cron.service`).

## What real administration looks like to the agent

Two more scripts, both measurements rather than pass/fail checks, both written because
the sessions in `corpus/behavior/` are ours and a real box is not.

```bash
limactl shell aris-demo -- sudo bash /Volumes/ArisLLM/Projects-Archive/aris-sentinel/docs/demo-kill/soak-behavior.sh
```

`soak-behavior.sh` installs `ansible-core`, `sosreport`, `lynis` and `inxi`, arms the agent
in monitor mode with `--behavior` and the default five-minute window, and runs fourteen
ordinary activities with the distribution's own tools, each in a session of its own: apt
update, install and upgrade check, the login banner, a login shell, `cron.daily`,
`adduser`, a service restart, a disk triage, `inxi`, an ansible fact run,
`unattended-upgrade --dry-run`, a lynis audit and a sos report. It prints what each
session asked about and whether it was reported. Nobody here wrote those command lines.

```bash
limactl shell aris-demo -- sudo node /Volumes/ArisLLM/Projects-Archive/aris-sentinel/docs/demo-kill/scan-system-scripts.mjs
```

`scan-system-scripts.mjs` scores every `#!` file under `/usr`, `/etc` and `/usr/local` the
way the agent scores a script on exec, and prints the tier-1 tally. None of those files is
an attack, so a block is a false positive and an escalate is a judge call every time that
script runs. It is read-only and runs on any Linux box with Node. The results of both, and
the false block they found in tier 1, are in [corpus/README.md](../../corpus/README.md).

## 5. Tear down

```bash
limactl delete -f aris-demo
```
