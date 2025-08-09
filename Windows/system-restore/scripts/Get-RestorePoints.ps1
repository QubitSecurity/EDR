# Get-RestorePoints.ps1
# 최근 복원 지점 목록 보기

param([int]$Top = 20)

Write-Host "`n[최근 복원 지점 목록]" -ForegroundColor Cyan

try {
    Get-ComputerRestorePoint |
        Sort-Object CreationTime -Descending |
        Select-Object -First $Top `
            @{n='Created';e={$_.CreationTime}},
            @{n='Type';e={$_.RestorePointType}},
            @{n='Event';e={$_.EventType}},
            @{n='Seq';e={$_.SequenceNumber}},
            @{n='Description';e={$_.Description}} |
        Format-Table -Wrap
} catch {
    Write-Warning "복원 지점을 가져오지 못했습니다: $($_.Exception.Message)"
}
