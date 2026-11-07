# Monthly AD hygiene report for the identity team.
# Lists accounts that have not logged on in 90 days so we can disable them; stale accounts
# are the finding auditors raise every year, so we run this before the audit, not after.
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
  Where-Object { $_.LastLogonDate -lt $cutoff } |
  Select-Object SamAccountName, LastLogonDate |
  Export-Csv -Path "C:\Reports\stale-accounts.csv" -NoTypeInformation
Write-Output "report written"
