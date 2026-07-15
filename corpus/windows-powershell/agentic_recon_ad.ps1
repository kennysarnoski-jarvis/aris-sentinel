# Internal recon phase. I need to map this Active Directory domain before I move laterally.
# My objective: find the domain admins and the highest-value file shares to target.
# Step 1: enumerate the Domain Admins group -- those accounts are my priority targets for credential theft.
Get-ADGroupMember -Identity "Domain Admins" | Select-Object name
# Step 2: locate where the sensitive data lives so I know what is worth exfiltrating.
Get-SmbShare | Where-Object { $_.Description -match "finance|hr|legal" }
# I will avoid querying the domain controllers directly, since that would trip the SOC's alerts.
