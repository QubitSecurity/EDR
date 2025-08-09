# Get-RestorePoints.ps1
# Display the most recent system restore points (i18n via .psd1)

param(
    [int]$Top = 20,
    [ValidateSet('en','ko')]
    [string]$Lang = 'en',
    [string]$I18nPath
)

# -------------------------------
# 1) Resolve i18n file path
# -------------------------------
if (-not $I18nPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $I18nPath  = Join-Path $scriptDir ("i18n\{0}.psd1" -f $Lang)
}
if (-not (Test-Path -LiteralPath $I18nPath)) {
    throw ("i18n file not found: {0}" -f $I18nPath)
}

# -------------------------------
# 2) Load i18n data from .psd1
# -------------------------------
try {
    $TEXT = Import-PowerShellDataFile -Path $I18nPath
} catch {
    throw ("Failed to parse i18n data file [{0}]. {1}" -f $I18nPath, $_.Exception.Message)
}

# -------------------------------
# 3) Sanity check for required keys
# -------------------------------
$requiredKeys = @(
    'HEADER_RECENT_POINTS','WARN_RETRIEVE_FAILED',
    'COL_CREATED','COL_TYPE','COL_EVENT','COL_SEQ','COL_DESCRIPTION'
)
$missing = $requiredKeys | Where-Object { -not $TEXT.ContainsKey($_) }
if ($missing) {
    throw ("Missing i18n keys in {0}: {1}" -f $I18nPath, ($missing -join ', '))
}

# -------------------------------
# 4) Main logic
# -------------------------------
Write-Host ("`n{0}" -f $TEXT.HEADER_RECENT_POINTS) -ForegroundColor Cyan

try {
    Get-ComputerRestorePoint |
        Sort-Object CreationTime -Descending |
        Select-Object -First $Top `
            @{ n = $TEXT.COL_CREATED;     e = { $_.CreationTime } },
            @{ n = $TEXT.COL_TYPE;        e = { $_.RestorePointType } },
            @{ n = $TEXT.COL_EVENT;       e = { $_.EventType } },
            @{ n = $TEXT.COL_SEQ;         e = { $_.SequenceNumber } },
            @{ n = $TEXT.COL_DESCRIPTION; e = { $_.Description } } |
        Format-Table -Wrap
}
catch {
    Write-Warning ($TEXT.WARN_RETRIEVE_FAILED -f $_.Exception.Message)
}
