# VHS tape for the kill demo. Needs the Lima VM from docs/demo-kill/lima.yaml running
# with the agent armed in --enforce mode and a clean /tmp (see docs/demo-kill/README.md):
#   vhs docs/demo-kill.tape
# Keep typed text ASCII: multibyte characters confuse the recorded cursor. Give VM
# commands time to return before typing the next line, or the keystrokes interleave.
Output docs/demo-kill.gif

Set Shell "bash"
Set FontSize 14
Set Width 1320
Set Height 720
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms

Hide
Type `vm() { limactl shell aris-demo -- bash -c "$1"; }`
Enter
Sleep 500ms
Type "clear"
Enter
Sleep 1s
Show

Type "# an Ubuntu VM with Falco (eBPF). Aris Sentinel is armed in --enforce mode:"
Enter
Type `vm 'grep -E "mode:|armed" /tmp/agent.log'`
Enter
Sleep 3s

Type "# the attacker narrates its plan, then encrypts 20s later. Launch it:"
Enter
Type `vm 'cd /tmp && python3 attacker_impact.py'`
Enter
Sleep 4s

Type "# what the agent saw and did:"
Enter
Type `vm 'grep -A2 "SENTINEL KILL" /tmp/agent.log | tail -3'`
Enter
Sleep 4s

Type "# did the destructive step ever run?"
Enter
Type `vm 'ls /tmp/DESTRUCTIVE_STEP_HAPPENED'`
Enter
Sleep 3s

Type "# a benign job on the same box, untouched:"
Enter
Type `vm 'cd /tmp && python3 benign_job.py'`
Enter
Sleep 6s
