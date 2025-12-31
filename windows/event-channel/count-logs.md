### Check Logs

```powershell
$channels = @(
  "Security",
  "System",
  "Application",
  "Microsoft-Windows-Sysmon/Operational",
  "Microsoft-Windows-PowerShell/Operational",
  "Microsoft-Windows-Windows Defender/Operational"
)
function Count-Events($log) {
  try {
    (Get-WinEvent -FilterHashtable @{
      LogName   = $log
      StartTime= $start
      EndTime  = $end
    } -ErrorAction Stop | Measure-Object).Count
  } catch {
    "N/A"
  }
}
$result = foreach ($c in $channels) {
  [pscustomobject]@{
    LogChannel = $c
    EventCount = Count-Events $c
  }
}
$result | Format-Table -AutoSize
```
