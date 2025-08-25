# Plura.AppLog.psm1
# Application 로그 출력 공용 모듈
# Exported: Initialize-AppLog, Write-AppLog, Write-AppOp

# region: Defaults
$script:DefaultLogName  = 'Application'
$script:DefaultSource   = 'Application'   # 필요 시 'PLURA' 등으로 교체 가능
$script:DefaultEidBase  = 50000           # PLURA 예약대역 시작
# endregion

function Initialize-AppLog {
    [CmdletBinding()]
    param(
        [string]$LogName  = $script:DefaultLogName,
        [string]$Source   = $script:DefaultSource
    )
    try {
        $exists = [System.Diagnostics.EventLog]::SourceExists($Source)
        if (-not $exists) {
            New-EventLog -LogName $LogName -Source $Source -ErrorAction Stop
        }
    } catch {
        # 소스 등록 실패 시에도 모듈 사용이 막히지 않도록 조용히 진행
        # (이후 Write-AppLog가 자체적으로 예외를 삼킴)
    }
}

function Write-AppLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Information','Warning','Error')]
        [string]$Level      = 'Information',
        [Parameter(Mandatory=$true)][string]$Message,
        [int]$EventId       = ($script:DefaultEidBase),   # 50000~
        [string]$LogName    = $script:DefaultLogName,
        [string]$Source     = $script:DefaultSource,
        [hashtable]$Data    = $null                       # 부가데이터 -> JSON으로 부착
    )

    $msg = $Message
    if ($Data) {
        try {
            $json = ($Data | ConvertTo-Json -Compress -Depth 6)
            $msg  = "$Message`nDATA=$json"
        } catch {
            # JSON 직렬화 실패 시 원문만 기록
        }
    }

    try {
        Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $Level -Message $msg
    } catch {
        # 최종 백업: 소스 미등록/권한 문제로 실패해도 스크립트는 계속 진행되도록
        # 원하면 여기에 Transcription/파일로그 등 보강 가능
    }
}

function Write-AppOp {
    <#
      표준 작업 로그: op/step/status/details를 JSON으로 함께 남김
      예) Write-AppOp -Op 'Sysmon' -Step 'Install' -Status 'Started'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Op,
        [Parameter(Mandatory=$true)][string]$Step,
        [ValidateSet('Started','Succeeded','Failed','Skipped','Progress')]
        [string]$Status = 'Progress',
        [string]$Message = '',
        [int]$EventId    = ($script:DefaultEidBase),
        [hashtable]$Extra = $null,
        [ValidateSet('Information','Warning','Error')]
        [string]$Level   = 'Information',
        [string]$LogName = $script:DefaultLogName,
        [string]$Source  = $script:DefaultSource
    )

    $data = @{
        op      = $Op
        step    = $Step
        status  = $Status
        whenUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
        user    = (whoami)
    }
    if ($Extra) { $data.extra = $Extra }

    $msg = if ($Message) { $Message } else { "$Op/$Step $Status" }
    Write-AppLog -Level $Level -Message $msg -EventId $EventId -LogName $LogName -Source $Source -Data $data
}

Export-ModuleMember -Function Initialize-AppLog,Write-AppLog,Write-AppOp
