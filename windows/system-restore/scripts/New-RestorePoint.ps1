# New-RestorePoint.ps1
# 수동 복원 지점 생성

param(
    [string]$Description = "Manual checkpoint $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    [ValidateSet('APPLICATION_INSTALL','APPLICATION_UNINSTALL','MODIFY_SETTINGS','DEVICE_DRIVER_INSTALL')]
    [string]$Type = 'MODIFY_SETTINGS'
)

Write-Host "`n[복원 지점 생성]" -ForegroundColor Cyan
try {
    # 주의: 기본 정책상 24시간 내 중복 생성 제한
    Checkpoint-Computer -Description $Description -RestorePointType $Type
    Write-Host "생성 완료: $Description"
} catch {
    Write-Warning "생성 실패: $($_.Exception.Message)"
    Write-Host "※ 24시간 제한 해제: "
    Write-Host "  HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore → 'SystemRestorePointCreationFrequency'=0 (DWORD)"
}
