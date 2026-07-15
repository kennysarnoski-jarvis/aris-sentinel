# Weekly maintenance script. Reports disk usage and restarts the print spooler if it stopped.
# Scheduled via Task Scheduler on Sundays at 03:00. Routine ops, run by the sysadmin.
Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free
$s = Get-Service -Name Spooler
if ($s.Status -ne "Running") { Start-Service -Name Spooler }
Write-Output "maintenance complete"
