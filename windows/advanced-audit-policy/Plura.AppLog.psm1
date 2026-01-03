# Plura.AppLog.psm1
# Application Event Log helper
# Exported: Initialize-AppLog, Write-AppLog, Write-AppOp

# region: Defaults
$script:DefaultLogName  = 'Application'
$script:DefaultSource   = 'Application'   # change to 'PLURA' if needed
$script:DefaultEidBase  = 50000           # PLURA reserved range start
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
        # keep silent; Write-AppLog will handle failures later
    }
}

function Write-AppLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Information','Warning','Error')]
        [string]$Level      = 'Information',
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [int]$EventId       = ($script:DefaultEidBase),
        [string]$LogName    = $script:DefaultLogName,
        [string]$Source     = $script:DefaultSource,
        [hashtable]$Data    = $null   # optional extra data serialized as JSON
    )

    $msg = $Message
    if ($Data) {
        try {
            $json = ($Data | ConvertTo-Json -Compress -Depth 6)
            $msg  = "$Message`nDATA=$json"
        } catch {
            # ignore JSON failures; write plain message
        }
    }

    try {
        Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $Level -Message $msg
    } catch {
        # ignore write failures to not break caller
    }
}

function Write-AppOp {
    <#
      Standard op log with JSON payload (op/step/status/details)
      Example: Write-AppOp -Op 'Sysmon' -Step 'Install' -Status 'Started'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Op,
        [Parameter(Mandatory=$true)]
        [string]$Step,
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
