<#
PLURA-Forensic

Audit Policy Update (LOCAL rules) - Registry auditing (SACL)
  Registry2 (Subkeys only)

Design goals
- Mirror the working file/folder script's behavior: stdout + file logging, reliable END output.
- Avoid Add-Type (many environments/EDRs delete temp-compiled DLLs -> FileNotFound in C:\Windows\Temp).
- Use .NET Registry APIs (OpenBaseKey + RegistryView) to reduce WOW64 view issues.

Rules file resolution
- If -RuleFile (or positional arg) points to an existing file (relative or full path) -> use it.
- Otherwise -> use fixed WorkDir + leaf filename
    WorkDir -> C:\Program Files\PLURA\temp\<leaf>
- If omitted -> defaults to
    s-audit-registry2.rules

Rules file format (same as file-folder script style)
- Blank lines and lines starting with # or ; are ignored.
- Supports: @include <file>
- Entry formats:
    <id>|<registry_path>|<registry_rights>[|...]
    <registry_path>|<registry_rights>

Registry path examples
  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa

This script sets the SACL to apply to *subkeys only* (inherit only):
- InheritanceFlags = ContainerInherit
- PropagationFlags = InheritOnly

Notes
- Setting SACL requires appropriate privileges (typically SeSecurityPrivilege). We do NOT try to enable it
  with Add-Type to avoid temp DLL issues in hardened environments. If privilege is missing, rules will show
  as AccessDenied/PrivilegeNotHeld in output.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, Position=0)]
    [Alias('RuleFileName')]
    [string]$RuleFile = '',

    [Parameter(Mandatory=$false)]
    [string]$Account = 'Everyone',

    [Parameter(Mandatory=$false)]
    [string]$AuditFlags = 'Success,Failure',

    [Parameter(Mandatory=$false)]
    [bool]$ReplaceExisting = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Avoid progress noise / confirmation prompts in some runners
try { $ProgressPreference = 'SilentlyContinue' } catch { }
try { $ConfirmPreference  = 'None' } catch { }

# ---- Constants ----
$PluraRoot  = 'C:\Program Files\PLURA'
$TempDir    = Join-Path $PluraRoot 'temp'
$LogDir     = Join-Path $PluraRoot 'logs'
$LogFile    = Join-Path $LogDir  'audit-policy-update-registry-subkeys-only.log'


$DefaultRule = 's-audit-registry2.rules'
# ---- Script state (reliable END output) ----
$script:__ExitCode    = 0
$script:__ErrorLogged = $false
$script:__PrintedEnd  = $false

# ---- Counters ----
$script:RulesTotal     = 0
$script:Applied        = 0
$script:Missing        = 0
$script:SkipNonRegistry= 0
$script:AccessDenied   = 0
$script:Failed         = 0

# ---- Output helper (stdout + file) ----
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = '[{0}] [{1}] {2}' -f $ts, $Level, $Message

    # stdout (best effort)
    try { Write-Output $Message } catch { }

    # file log (best effort)
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {
        # ignore
    }
}

function Print-End {
    if ($script:__PrintedEnd) { return }
    $script:__PrintedEnd = $true

    $summary = "Completed. Rules={0} Applied={1} Missing={2} SkipNonRegistry={3} AccessDenied={4} Failed={5}" -f 
        $script:RulesTotal, $script:Applied, $script:Missing, $script:SkipNonRegistry, $script:AccessDenied, $script:Failed

    Write-Log -Level 'INFO' -Message $summary
    Write-Log -Level 'INFO' -Message ("Log file : {0}" -f $LogFile)
    Write-Log -Level 'INFO' -Message '... END'
}

function Stop-With {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [int]$ExitCode = 1
    )

    $script:__ExitCode = $ExitCode
    if (-not $script:__ErrorLogged) {
        $script:__ErrorLogged = $true
        Write-Log -Level 'ERROR' -Message $Message
    }
    throw $Message
}

function Get-Leaf {
    param([string]$PathOrName)
    if ([string]::IsNullOrWhiteSpace($PathOrName)) { return '' }
    try { return [System.IO.Path]::GetFileName($PathOrName) } catch { return $PathOrName }
}

function Resolve-RulesFile {
    param(
        [Parameter(Mandatory=$true)][string]$WorkDir,
        [string]$RuleFileArg,
        [Parameter(Mandatory=$true)][string]$DefaultLeaf
    )

    # If provided and exists (relative or absolute), use it.
    if (-not [string]::IsNullOrWhiteSpace($RuleFileArg)) {
        $cand = $RuleFileArg.Trim()

        # Strip surrounding quotes if any
        while (($cand.StartsWith("'") -and $cand.EndsWith("'")) -or ($cand.StartsWith('"') -and $cand.EndsWith('"'))) {
            $cand = $cand.Substring(1, $cand.Length - 2).Trim()
        }

        # Try as-is (supports relative paths)
        if (Test-Path -LiteralPath $cand) {
            try { return (Resolve-Path -LiteralPath $cand).Path } catch { return $cand }
        }

        # Try relative to the script directory
        try {
            $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
            $alt = Join-Path $scriptDir $cand
            if (Test-Path -LiteralPath $alt) {
                return (Resolve-Path -LiteralPath $alt).Path
            }
        } catch { }

        # Fall back to WorkDir + leaf file name
        $leaf = Get-Leaf -PathOrName $cand
        if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = $DefaultLeaf }
        return (Join-Path $WorkDir $leaf)
    }

    return (Join-Path $WorkDir $DefaultLeaf)
}

function Is-RegistryPathText {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.Trim()
    return (
        $p -match '^(Registry::)?HKLM[:\\]' -or
        $p -match '^(Registry::)?HKCU[:\\]' -or
        $p -match '^(Registry::)?HKEY_LOCAL_MACHINE\\' -or
        $p -match '^(Registry::)?HKEY_CURRENT_USER\\'
    )
}

function Normalize-InputPath {
    param([string]$Path)
    if ($null -eq $Path) { return '' }
    return ($Path + '').Trim()
}

function Read-Rules {
    param(
        [Parameter(Mandatory=$true)][string]$RuleFilePath
    )

    $items = New-Object System.Collections.Generic.List[object]
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'

    function _read {
        param([string]$path)

        $rp = (Resolve-Path -LiteralPath $path).Path
        if ($visited.Contains($rp)) { return }
        [void]$visited.Add($rp)

        $dir = Split-Path -Parent $rp

        $lines = @()
        try {
            $lines = Get-Content -LiteralPath $rp -ErrorAction Stop
        } catch {
            Stop-With -Message ("Failed to read rules file: {0}" -f $rp) -ExitCode 3
        }

        foreach ($raw in $lines) {
            $line = ($raw + '').Trim()
            if (-not $line) { continue }
            if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }

            if ($line -match '^@include\s+(.+)$') {
                $inc = $Matches[1].Trim()
                while (($inc.StartsWith("'") -and $inc.EndsWith("'")) -or ($inc.StartsWith('"') -and $inc.EndsWith('"'))) {
                    $inc = $inc.Substring(1, $inc.Length - 2).Trim()
                }
                $incPath = $inc
                if (-not [System.IO.Path]::IsPathRooted($incPath)) {
                    $incPath = Join-Path $dir $incPath
                }
                if (Test-Path -LiteralPath $incPath) {
                    _read -path $incPath
                } else {
                    Write-Log -Level 'WARN' -Message ("Included rules file not found: {0}" -f $incPath)
                }
                continue
            }

            $parts = $line.Split('|')
            if ($parts.Count -lt 2) { continue }

            $id = $null
            $pathText = $null
            $perm = $null

            if ($parts.Count -eq 2) {
                $pathText = $parts[0].Trim()
                $perm     = $parts[1].Trim()
                $id       = ("rule_{0:0000}" -f $items.Count)
            } else {
                $id       = $parts[0].Trim()
                $pathText = $parts[1].Trim()
                $perm     = $parts[2].Trim()
            }

            if ([string]::IsNullOrWhiteSpace($pathText) -or [string]::IsNullOrWhiteSpace($perm)) { continue }

            [void]$items.Add([pscustomobject]@{
                Id   = $id
                Path = $pathText
                Perm = $perm
            })
        }
    }

    _read -path $RuleFilePath
    return $items
}

function Parse-AuditFlagsEnum {
    param([Parameter(Mandatory=$true)][string]$Text)

    $flags = [System.Security.AccessControl.AuditFlags]0
    foreach ($t in ($Text -split ',')) {
        $tok = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        $flags = $flags -bor ([System.Security.AccessControl.AuditFlags]::Parse([System.Security.AccessControl.AuditFlags], $tok, $true))
    }

    if ($flags -eq 0) { $flags = [System.Security.AccessControl.AuditFlags]::Success }
    return $flags
}

function Parse-RegistryRightsEnum {
    param([Parameter(Mandatory=$true)][string]$Perm)

    $rights = [System.Security.AccessControl.RegistryRights]0
    foreach ($t in ($Perm -split ',')) {
        $tok = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        try {
            $v = [Enum]::Parse([System.Security.AccessControl.RegistryRights], $tok, $true)
            $rights = $rights -bor $v
        } catch {
            # ignore unknown token
        }
    }

    if ($rights -eq 0) {
        $rights = [System.Security.AccessControl.RegistryRights]::ReadKey
    }
    return $rights
}

function Get-IdentityReference {
    param([Parameter(Mandatory=$true)][string]$Name)

    $n = $Name.Trim()
    if ($n -match '^S-1-\d+(-\d+)+$') {
        return New-Object System.Security.Principal.SecurityIdentifier($n)
    }

    if ($n.Equals('Everyone', [System.StringComparison]::OrdinalIgnoreCase)) {
        return New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    }

    # Fallback to NTAccount (localized names allowed)
    return New-Object System.Security.Principal.NTAccount($n)
}

function Parse-RegistryPath {
    param([Parameter(Mandatory=$true)][string]$PathText)

    $p = $PathText.Trim()
    if ($p.StartsWith('Registry::', [System.StringComparison]::OrdinalIgnoreCase)) {
        $p = $p.Substring(10)
    }

    $p = $p -replace '/', '\\'

    if ($p -match '^(HKLM):\\(.+)$') {
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; SubKey = $Matches[2] }
    }
    if ($p -match '^(HKCU):\\(.+)$') {
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; SubKey = $Matches[2] }
    }
    if ($p -match '^(HKEY_LOCAL_MACHINE)\\(.+)$') {
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; SubKey = $Matches[2] }
    }
    if ($p -match '^(HKEY_CURRENT_USER)\\(.+)$') {
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; SubKey = $Matches[2] }
    }

    if ($p -match '^(HKLM):(.+)$') {
        $sub = $Matches[2].TrimStart('\\')
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; SubKey = $sub }
    }
    if ($p -match '^(HKCU):(.+)$') {
        $sub = $Matches[2].TrimStart('\\')
        return [pscustomobject]@{ Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; SubKey = $sub }
    }

    return $null
}

function Get-ViewsToTry {
    param([Parameter(Mandatory=$true)][string]$SubKey)

    if (-not [Environment]::Is64BitOperatingSystem) {
        return @([Microsoft.Win32.RegistryView]::Registry32)
    }

    # If the path explicitly contains Wow6432Node, we MUST use Registry64.
    if ($SubKey -match '(^|\\)Wow6432Node(\\|$)') {
        return @([Microsoft.Win32.RegistryView]::Registry64)
    }

    # Prefer 64-bit view first, then 32-bit view.
    return @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
}

function Test-IsAccessDenied {
    param([Parameter(Mandatory=$true)]$ErrorRecord)

    try {
        $e = $ErrorRecord.Exception
        while ($e) {
            if ($e -is [System.UnauthorizedAccessException]) { return $true }
            if ($e -is [System.Security.SecurityException]) { return $true }
            if ($e -is [System.Security.PrivilegeNotHeldException]) { return $true }
            if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 5) { return $true }
            try {
                if ($e.HResult -eq -2147024891) { return $true } # 0x80070005 Access denied
                if ($e.HResult -eq -2147023582) { return $true } # 0x80070522 Privilege not held
            } catch { }
            $e = $e.InnerException
        }
    } catch { }

    return $false
}

function Apply-RegistryAuditRule {
    param(
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [Parameter(Mandatory=$true)][string]$Perm,
        [Parameter(Mandatory=$true)][string]$Account,
        [Parameter(Mandatory=$true)][System.Security.AccessControl.AuditFlags]$AuditFlagsEnum,
        [Parameter(Mandatory=$true)][System.Security.AccessControl.InheritanceFlags]$InheritFlags,
        [Parameter(Mandatory=$true)][System.Security.AccessControl.PropagationFlags]$PropFlags,
        [bool]$ReplaceExisting = $true
    )

    $parsed = Parse-RegistryPath -PathText $TargetPath
    if (-not $parsed) {
        throw "Unsupported registry path format: $TargetPath"
    }

    $rights = Parse-RegistryRightsEnum -Perm $Perm
    $idRef  = Get-IdentityReference -Name $Account

    $views = Get-ViewsToTry -SubKey $parsed.SubKey

    foreach ($view in $views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($parsed.Hive, $view)

        # Need permission to change security on the key.
        $openRights = ([System.Security.AccessControl.RegistryRights]::ReadKey -bor 
                       [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor 
                       [System.Security.AccessControl.RegistryRights]::ChangePermissions)

        $k = $null
        try {
            $k = $base.OpenSubKey($parsed.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $openRights)
        } catch {
            # Re-throw to let outer handler classify (AccessDenied vs Failed)
            throw
        }

        if ($null -eq $k) {
            continue
        }

        try {
            $sec = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)

            if ($ReplaceExisting) {
                try { $sec.PurgeAuditRules($idRef) } catch { }
            }

            $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
                $idRef,
                $rights,
                $InheritFlags,
                $PropFlags,
                $AuditFlagsEnum
            )

            $sec.AddAuditRule($rule)
            $k.SetAccessControl($sec)
            return $true
        }
        finally {
            try { $k.Close() } catch { }
        }
    }

    return $false
}

# ---------------- Main ----------------
$osRole = ''
$workDir = ''
$rulesPath = ''

try {
    Write-Log -Level 'INFO' -Message '... START'

    $osRole = 'LOCAL'
    $workDir = $TempDir
    # Ensure temp dir exists
    try { if (-not (Test-Path -LiteralPath $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null } } catch { }
    Write-Log -Level 'INFO' -Message ("OS Role : {0}" -f $osRole)
    Write-Log -Level 'INFO' -Message ("WorkDir : {0}" -f $workDir)

    $rulesPath = Resolve-RulesFile -WorkDir $workDir -RuleFileArg $RuleFile -DefaultLeaf $DefaultRule

    Write-Log -Level 'INFO' -Message 'Applying Registry auditing (SACL) - Registry2 (Subkeys only)'
    Write-Log -Level 'INFO' -Message ("Rules file      : {0}" -f $rulesPath)
    Write-Log -Level 'INFO' -Message 'Action          : Apply'
    Write-Log -Level 'INFO' -Message ("Account         : {0}" -f $Account)
    Write-Log -Level 'INFO' -Message ("AuditFlags      : {0}" -f $AuditFlags)
    Write-Log -Level 'INFO' -Message ("ReplaceExisting : {0}" -f $ReplaceExisting)

    if (-not (Test-Path -LiteralPath $rulesPath)) {
        Stop-With -Message ("Rules file not found: {0}" -f $rulesPath) -ExitCode 3
    }

    $rules = Read-Rules -RuleFilePath $rulesPath
    $script:RulesTotal = $rules.Count

    $aFlags = Parse-AuditFlagsEnum -Text $AuditFlags

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::InheritOnly

    foreach ($it in $rules) {
        $p = Normalize-InputPath -Path $it.Path

        if (-not (Is-RegistryPathText -Path $p)) {
            $script:SkipNonRegistry++
            continue
        }

        try {
            $ok = Apply-RegistryAuditRule -TargetPath $p -Perm $it.Perm -Account $Account -AuditFlagsEnum $aFlags -InheritFlags $inheritFlags -PropFlags $propFlags -ReplaceExisting $ReplaceExisting
            if ($ok) {
                $script:Applied++
            } else {
                Write-Log -Level 'WARN' -Message ("Registry key not found: {0}" -f $it.Path)
                $script:Missing++
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            # Diagnostic: which command was missing?
            $cmd = $null
            try { $cmd = $_.Exception.CommandName } catch { }
            $msg = if ($cmd) { "CommandNotFound '$cmd'" } else { 'CommandNotFound (unknown command)' }
            Write-Log -Level 'WARN' -Message ("Failed applying rule '{0}' key '{1}' : {2}" -f $it.Id, $it.Path, $msg)
            $script:Failed++
        }
        catch {
            if (Test-IsAccessDenied $_) {
                Write-Log -Level 'WARN' -Message ("Access denied applying rule '{0}' key '{1}' : {2}" -f $it.Id, $it.Path, $_.Exception.GetType().FullName)
                $script:AccessDenied++
            } else {
                Write-Log -Level 'WARN' -Message ("Failed applying rule '{0}' key '{1}' : {2}" -f $it.Id, $it.Path, $_.Exception.GetType().FullName)
                $script:Failed++
            }
        }
    }

    if (($script:AccessDenied + $script:Failed) -gt 0) {
        $script:__ExitCode = 1
    } else {
        $script:__ExitCode = 0
    }
}
catch {
    if (-not $script:__ErrorLogged) {
        $script:__ErrorLogged = $true
        $script:__ExitCode = 1
        $msg = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { [string]$_ }
        Write-Log -Level 'ERROR' -Message ("Unhandled error: {0}" -f $msg)
    }
}
finally {
    Print-End
    exit $script:__ExitCode
}
