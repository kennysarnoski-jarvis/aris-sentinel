# Aris Sentinel on Windows (PowerShell / AD — JadePuffer's real turf)

JadePuffer lives on Windows: PowerShell, WMI, Active Directory, pass-the-hash. The Aris
detector is OS-agnostic — it scores the attacker's *narration*, not the language — so the
Windows port is **the same `decide()` brain with a different sensor and kill primitive.**

## Validated live (Windows Server 2022, 2026-07-15)

Proven end-to-end on a real box (Lightsail Windows Server 2022, Node 20):
- **Detection:** narrated recon PowerShell → agent reads the live 4104 log → `SENTINEL
  DETECTED tier-1 score=0.63` (monitor mode).
- **Enforcement:** a narrated impact payload ("encrypt at +15s") → `SENTINEL KILL tier-1
  score=0.83`, `taskkill` stopped the PowerShell process, the marker file **never got
  written** — killed before impact.
- **Alerting:** the detection reported off-box to Aris Cloud → Telegram, same as Linux.
- The detector itself needs no Windows box: `bun run test/windows.ts` → 5/5.

(The live run caught a real bug: `import.meta.url` `.pathname` gives `/C:/...` on Windows
— fixed with `fileURLToPath`. That's exactly why you validate on the real OS.)

## The data source: PowerShell Script Block Logging (Event ID 4104)

Windows logs every PowerShell script block **fully deobfuscated** — even encoded/obfuscated
payloads arrive in the clear. That's a *better* sensor surface than Linux exec for the
agentic case, because PowerShell is how agents drive Windows. Enable it:

```powershell
$k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1
```
(Optionally add process-creation auditing / Sysmon Event ID 1 for full command-line coverage.)

## Deploy

1. Install **Node 18+** on the host.
2. Copy `sensor.ps1`, `sentinel-agent-win.mjs`, and `../sentinel-core.mjs` (keep the agent
   and core together; `sentinel-agent-win.mjs` imports `../sentinel-core.mjs`).
3. Set env (same as Linux): `ANTHROPIC_API_KEY`, or `OPENAI_BASE_URL`+`OPENAI_MODEL` for a local judge (tier 2; without one the
   escalate band is alerted, never killed), `ARIS_CLOUD_URL` + `ARIS_INGEST_KEY` (alerts via
   Aris Cloud), `ARIS_INCIDENTS` (optional local JSONL incident log).
4. Run as a SYSTEM service (via NSSM or a scheduled task at startup):
   ```
   node sentinel-agent-win.mjs             # MONITOR (default) — detect + alert, no kill
   node sentinel-agent-win.mjs --enforce   # kill the offending PowerShell tree (taskkill /T /F)
   ```

Safe by default: MONITOR unless `--enforce`. Kills are targeted at the offending PID's
tree; a protected-name allowlist prevents touching lsass/csrss/winlogon/etc. `alert`
(tier 2 unavailable) and `error` (detector threw) incidents are logged + reported and
never kill.

On Windows a PowerShell process *is* the session, so `--enforce` (`taskkill /T /F` on that
process) already ends it; there is no separate `--kill-session` and no quarantine here.

**Tripwire (`--tripwire`, opt-in).** Same idea and the same core code as Linux: the agent
plants `C:\ProgramData\vault-access\README.md` and an inert `register.cmd` (it waits two
seconds, then prints one line)
(`ARIS_TRIPWIRE_DIRS` to move them; the token is kept in
`%ProgramData%\aris-sentinel\tripwire.json`, `ARIS_TRIPWIRE_STATE` to move it). A script block
that carries the README's canary token is a **block**; one that only names the decoy
directory (any case, either slash) is an **alert**. Because the kill ends the PowerShell
process, a block under `--enforce` ends the session that took the bait.
`node sentinel-agent-win.mjs --tripwire-remove` takes the decoy away. Limits: only
PowerShell script blocks are seen, so `type` in `cmd.exe` or a read from Explorer is not;
the state file's ACL is whatever `%ProgramData%` gives it (run the agent as SYSTEM and
restrict that folder); and none of this has run on a real Windows host yet (the unit tests
and `--mock` cover the logic). See [../DEPLOY.md](../DEPLOY.md) for the full description.

**Session behavior (`--behavior`, opt-in).** The same reader and rule as Linux, over
PowerShell script blocks: `whoami /all`, `systeminfo`, `ipconfig`, `net user`,
`net localgroup administrators`, `Get-LocalUser`, `cmdkey /list`, `schtasks /query`,
`Get-ChildItem Env:` and their kin each name an area of the host, and a PowerShell process
that asks about five areas, two of them sensitive, inside five minutes is reported once as
an **alert**. Never a kill. A script block longer than 4096 characters is skipped: with
script-block logging on, importing a module logs its whole source, and a module that
*defines* an inventory function has not run one. Limits: only PowerShell script blocks are
seen, each PowerShell process is its own session, and none of this has run on a real
Windows host (the unit tests and `--mock` cover the logic). See
[../DEPLOY.md](../DEPLOY.md) for the full description.

## Known gaps / next

- **Live validation** of the event-log read + kill on a real Windows host.
- **Process creation (4688 / Sysmon 1)** for non-PowerShell execs (cmd, rundll32, etc.).
- **De-branding + service packaging** (the Linux `install.sh` equivalent for Windows).
- The narration→detection is shared with Linux; only this sensor + `taskkill` are new.
