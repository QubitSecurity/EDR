# Get-SystemRestoreConfig.ps1
# 시스템 복원(시스템 보호) 상태 확인

Write-Host "`n[시스템 복원 구성 상태]" -ForegroundColor Cyan

$drives = Get-Volume | Where-Object DriveLetter | Select-Object -Expand DriveLetter
foreach ($d in $drives) {
    $out = (vssadmin list shadowstorage /for:$("$d`:" ) 2>$null)
    if (-not $out) { continue }

    $enabled = -not ($out | Select-String "No items found" -Quiet)
    if ($enabled) {
        $used = ($out | Select-String "Used Shadow Copy Storage space").ToString().Split(":")[-1].Trim()
        $alloc = ($out | Select-String "Allocated Shadow Copy Storage space").ToString().Split(":")[-1].Trim()
        $max  = ($out | Select-String "Maximum Shadow Copy Storage space").ToString().Split(":")[-1].Trim()
        [pscustomobject]@{
            Drive      = "$d:"
            Protected  = $true
            Used       = $used
            Allocated  = $alloc
            MaxSize    = $max
        }
    } else {
        [pscustomobject]@{
            Drive      = "$d:"
            Protected  = $false
            Used       = "-"
            Allocated  = "-"
            MaxSize    = "-"
        }
    }
} | Format-Table -AutoSize
