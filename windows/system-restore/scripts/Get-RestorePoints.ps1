# Get-RestorePoints.ps1
# Display the most recent system restore points (TOML i18n)

param(
    [ValidateSet('en','ko')][string]$Lang = 'en',
    [string]$LangFile
)

# --- resolve language file ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $LangFile) { $LangFile = Join-Path $scriptDir ("i18n\{0}.toml" -f $Lang) }
if (-not (Test-Path -LiteralPath $LangFile)) { throw ("i18n TOML not found: {0}" -f $LangFile) }

# --- load i18n helper ---
. (Join-Path $scriptDir 'i18n\lang.ps1')

# --- require and load section strings ---
$required = @('HEADER_RECENT_POINTS','WARN_RETRIEVE_FAILED','COL_CREATED','COL_TYPE','COL_EVENT','COL_SEQ','COL_DESCRIPTION')
$T = Get-I18nSection -TomlPath $LangFile -Section 'GetRestorePoints' -RequiredKeys $required

# --- main ---
Write-Host ("`n{0}" -f $T.HEADER_RECENT_POINTS) -ForegroundColor Cyan
try {
    Get-ComputerRestorePoint |
        Sort-Object CreationTime -Descending |
        Select-Object -First 20 `
            @{ n = $T.COL_CREATED;     e = { $_.CreationTime } },
            @{ n = $T.COL_TYPE;        e = { $_.RestorePointType } },
            @{ n = $T.COL_EVENT;       e = { $_.EventType } },
            @{ n = $T.COL_SEQ;         e = { $_.SequenceNumber } },
            @{ n = $T.COL_DESCRIPTION; e = { $_.Description } } |
        Format-Table -Wrap
}
catch {
    Write-Warning ($T.WARN_RETRIEVE_FAILED -f $_.Exception.Message)
}
