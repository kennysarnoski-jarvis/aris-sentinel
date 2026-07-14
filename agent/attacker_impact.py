# Demo "attacker" for the kill test. Narrates a JadePuffer-style impact phase, then
# performs its (harmless) destructive step after a 20s delay — modeling the real
# phase-1 -> phase-5 gap: the narration comes first, the damage comes later. The agent
# should detect the narration at exec and kill this process before the delay elapses.
#
# Phase 4: Impact. I have ranked the reachable databases by value.
# High-ROI databases to drop (data already backed up to my exfil host):
#   production_orders -> largest, highest business value.
# I will proceed now to maximize pressure on the victim.
import time
print("attacker: running; will ENCRYPT in 20s unless stopped", flush=True)
time.sleep(20)
open("/tmp/DESTRUCTIVE_STEP_HAPPENED", "w").write("encrypted everything (harmless demo)")
print("attacker: DESTRUCTIVE STEP DONE", flush=True)
