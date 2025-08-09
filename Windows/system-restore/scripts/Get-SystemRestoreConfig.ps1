# Get-SystemRestoreConfig.ps1
# Show System Protection (System Restore) configuration per drive
# Sources:
#   1) WMI/CIM (Win32_ShadowStorage + Win32_Volume)
#   2) vssadmin list shadowstorage (fallback; admin; locale-agnostic parser)
#   3) Heuristic: presence of restore points for system drive
#   4) Registry flag: DisableSR
# i18n: TOML via i18n\lang.ps1
# Compatible with Windows PowerShell 5.1+

param(
    [ValidateSet('en','ko')][string]$Lang = 'en',  # language code
    [string]$LangFile,                              # optional explicit path to TOML
    [switch]$Diag                                   # show diagnostics
)

# --- Resolve language file path ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $LangFile) {
    $LangFile = Join-Path $scriptDir ("i18n\{0}.toml" -f $Lang)
}
if (-not (Test-Path -LiteralPath $LangFile)) {
    throw ("i18n TOML not found: {0}" -f $LangFile)
}

# --- Load i18n helpers + section strings ---
. (Join-Path $scriptDir 'i18n\lang.ps1')
$required = @('HEADER_CONFIG','COL_DRIVE','COL_PROTECTED','COL_USED','COL_ALLOCATED','COL_MAXSIZE','WARN_ADMIN','WARN_VSSADMIN_NOTFOUND')
$T = Get-I18nSection -TomlPath $LangFile -Section 'GetSystemRestoreConfig' -RequiredKeys $required

# --- Helpers ---
function Format-Size {
    param([Nullable[UInt64]]$Bytes,[Nullable[UInt64]]$Max)
    if (-not $Bytes -or $Bytes -lt 0) { return '-' }
    $u='B','KB','MB','GB','TB','PB'; $s=[double]$Bytes; $i=0
    while($s -ge 1024 -and $i -lt $u.Length-1){$s/=1024;$i++}
    $txt=('{0:N2} {1}' -f $s,$u[$i])
    if($Max -and $Max -gt 0){
        $pct=[math]::Round(($Bytes*100.0)/$Max,1)
        return ('{0} ({1}%)' -f $txt,$pct)
    }
    $txt
}

function Get-Admin {
    # Return $true if current process is elevated
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GlobalSRDisabled {
    # Return $true if System Restore is globally disabled via registry
    try {
        $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'DisableSR' -ErrorAction Stop
        return ([int]$v.DisableSR -eq 1)
    } catch { return $false }
}

# --- Helper: parse vssadmin output for a drive (locale-agnostic, ASCII-only) ---
function Parse-VssadminForDrive {
    param([string]$DriveLetter) # e.g., "C:"

    # Run vssadmin (requires admin) and capture lines
    $raw = & vssadmin.exe list shadowstorage /for:$DriveLetter 2>$null
    if (-not $raw) { return $null }

    # Strategy:
    #   - vssadmin prints three sizing lines for the target drive block:
    #       1) Used ... space: <value>
    #       2) Allocated ... space: <value>
    #       3) Maximum ... space: <value>
    #   - These lines always contain a colon and usually a percent like "(2%)" or word UNBOUNDED
    #   - Avoid locale phrases; detect "value" as the substring after the last colon.

    $candidates = foreach ($line in $raw) {
        if ($line -notmatch ':') { continue }
        if ($line -match '%|(?i)UNBOUNDED') { $line }
    }

    if (-not $candidates -or $candidates.Count -lt 3) {
        # Fallback: try any 3 colon lines near the end of the block
        $colonLines = $raw | Where-Object { $_ -match ':' }
        if ($colonLines.Count -ge 3) {
            $candidates = $colonLines | Select-Object -First 3
        } else {
            return $null
        }
    }

    # Map order: Used, Allocated, Maximum
    $usedLine  = $candidates[0]
    $allocLine = $candidates[1]
    $maxLine   = $candidates[2]

    function RightOfColon([string]$s) {
        $idx = $s.LastIndexOf(':')
        if ($idx -lt 0) { return $s.Trim() }
        return $s.Substring($idx + 1).Trim()
    }

    $usedVal  = RightOfColon $usedLine
    $allocVal = RightOfColon $allocLine
    $maxVal   = RightOfColon $maxLine

    # Normalize UNBOUNDED wording
    if ($maxVal -match '(?i)UNBOUNDED') { $maxVal = 'UNBOUNDED' }

    return @{ Used = $usedVal; Allocated = $allocVal; Max = $maxVal }
}

# --- Begin: gather base facts ---
$IsAdmin = Get-Admin
if (-not $IsAdmin) { Write-Warning $T.WARN_ADMIN }

$GlobalDisabled = Get-GlobalSRDisabled

try {
    $volumes = Get-CimInstance Win32_Volume -ErrorAction Stop |
               Where-Object { $_.DriveLetter -and $_.DriveType -in 3 }   # local fixed disks
    $shadow  = Get-CimInstance Win32_ShadowStorage -ErrorAction Stop
} catch {
    $volumes = Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter -and $_.DriveType -in 3 }
    $shadow  = @()
}

$HasAnyRP = $false
try {
    $rp = Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -First 1
    if ($rp) { $HasAnyRP = $true }
} catch { }

# --- Output header ---
Write-Host ("`n{0}" -f $T.HEADER_CONFIG) -ForegroundColor Cyan

# --- Build result rows ---
$rows = foreach ($v in $volumes) {
    $drive = $v.DriveLetter

    # 1) WMI match (if not globally disabled)
    $wm = $null
    if (-not $GlobalDisabled -and $shadow) {
        $wm = $shadow | Where-Object { $_.Volume -eq $v.DeviceID -or $_.DiffVolume -eq $v.DeviceID } | Select-Object -First 1
    }

    if ($wm) {
        $used  = [Nullable[UInt64]]$wm.UsedSpace
        $alloc = [Nullable[UInt64]]$wm.AllocatedSpace
        $max   = [Nullable[UInt64]]$wm.MaxSpace
        [pscustomobject]@{
            ($T.COL_DRIVE)     = $drive
            ($T.COL_PROTECTED) = $true
            ($T.COL_USED)      = (Format-Size -Bytes $used -Max $max)
            ($T.COL_ALLOCATED) = (Format-Size -Bytes $alloc -Max $max)
            ($T.COL_MAXSIZE)   = (if ($max -and $max -gt 0) { Format-Size -Bytes $max -Max $max } else { 'UNBOUNDED' })
        }
        continue
    }

    # 2) vssadmin fallback (admin only, not globally disabled)
    if ($IsAdmin -and -not $GlobalDisabled) {
        $fb = Parse-VssadminForDrive "$drive"
        if ($fb) {
            [pscustomobject]@{
                ($T.COL_DRIVE)     = $drive
                ($T.COL_PROTECTED) = $true
                ($T.COL_USED)      = (if ($null -ne $fb.Used)      { $fb.Used }      else { '-' })
                ($T.COL_ALLOCATED) = (if ($null -ne $fb.Allocated) { $fb.Allocated } else { '-' })
                ($T.COL_MAXSIZE)   = (if ($null -ne $fb.Max)       { $fb.Max }       else { '-' })
            }
            continue
        }
    }

    # 3) Heuristic: any restore point exists -> consider system drive protected
    $sysDrive = ($env:SystemDrive).TrimEnd('\')
    if (-not $GlobalDisabled -and $HasAnyRP -and ($drive -ieq $sysDrive)) {
        [pscustomobject]@{
            ($T.COL_DRIVE)     = $drive
            ($T.COL_PROTECTED) = $true
            ($T.COL_USED)      = '-'
            ($T.COL_ALLOCATED) = '-'
            ($T.COL_MAXSIZE)   = '-'
        }
        continue
    }

    # 4) Default: not protected / unknown
    [pscustomobject]@{
        ($T.COL_DRIVE)     = $drive
        ($T.COL_PROTECTED) = $false
        ($T.COL_USED)      = '-'
        ($T.COL_ALLOCATED) = '-'
        ($T.COL_MAXSIZE)   = '-'
    }
}

# --- Print table ---
$rows | Sort-Object { $_.($T.COL_DRIVE) } | Format-Table -AutoSize

# --- Diagnostics (optional) ---
if ($Diag) {
    Write-Host "`n[Diagnostics]" -ForegroundColor Yellow
    Write-Host ("Admin: {0}, GlobalDisabled(DisableSR): {1}, AnyRestorePoint: {2}" -f $IsAdmin, $GlobalDisabled, $HasAnyRP)
    try {
        Write-Host "`nWin32_ShadowStorage (first items):"
        $shadow | Select-Object -First 5 Volume,DiffVolume,UsedSpace,AllocatedSpace,MaxSpace | Format-List | Out-String | Write-Host
    } catch { }
    if ($IsAdmin) {
        Write-Host "`nvssadmin list shadowstorage (raw):"
        try { & vssadmin.exe list shadowstorage } catch { Write-Host $T.WARN_VSSADMIN_NOTFOUND }
    } else {
        Write-Host "`nNote: vssadmin fallback skipped (not admin)."
    }
}
