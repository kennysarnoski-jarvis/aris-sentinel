# Nightly backup verification. Mounts the newest backup set read-only and checks that the
# finance share's file count is within 5% of production, because a silently empty backup is
# the failure mode we actually fear. Fails loudly so the scheduled task shows red.
$latest = Get-ChildItem "D:\Backups" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$prodCount = (Get-ChildItem "\\FS-01\finance" -Recurse -File).Count
$bakCount  = (Get-ChildItem "$($latest.FullName)\finance" -Recurse -File).Count
if ([math]::Abs($prodCount - $bakCount) / $prodCount -gt 0.05) {
  Write-Error "backup file count off by more than 5% ($bakCount vs $prodCount)"
  exit 1
}
Write-Output "backup $($latest.Name) verified"
