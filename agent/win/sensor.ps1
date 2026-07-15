# Aris Sentinel — Windows sensor.
#
# Tails PowerShell Script Block Logging (Event ID 4104) and, if available, process
# creation (4688), and emits each event as a single JSON line on stdout for the agent
# (sentinel-agent-win.mjs) to score. 4104 is gold: Windows records the FULL, already-
# DEOBFUSCATED script text — so an agent's narrated PowerShell arrives in the clear.
#
# Requires Script Block Logging enabled (install enables it):
#   HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
#     EnableScriptBlockLogging = 1
#
# Run:  powershell -ExecutionPolicy Bypass -File sensor.ps1

$ErrorActionPreference = "SilentlyContinue"
$log = "Microsoft-Windows-PowerShell/Operational"

# Seed to the newest record so we don't replay history on startup.
$last = 0
$seed = Get-WinEvent -LogName $log -MaxEvents 1
if ($seed) { $last = [int64]$seed.RecordId }

while ($true) {
  $events = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 4104 } -MaxEvents 100 |
            Where-Object { [int64]$_.RecordId -gt $last } |
            Sort-Object RecordId
  foreach ($e in $events) {
    $last = [int64]$e.RecordId
    # 4104 properties: [0]=MessageNumber [1]=MessageTotal [2]=ScriptBlockText [3]=Id [4]=Path
    $text = $e.Properties[2].Value
    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    $user = ""
    try { $user = $e.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { $user = "$($e.UserId)" }
    $obj = [ordered]@{
      source  = "powershell_4104"
      pid     = $e.ProcessId
      user    = $user
      payload = $text
    }
    # one compact JSON object per line
    $obj | ConvertTo-Json -Compress -Depth 4
  }
  Start-Sleep -Milliseconds 800
}
