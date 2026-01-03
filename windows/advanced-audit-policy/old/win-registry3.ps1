<#
PLURA-Forensic
Registry auditing (SACL) applier for PLURA - Registry3 (This key and subkeys)

Key behavior (sysmon-install.ps1 style):
- Determines OS role (DESKTOP vs SERVER) via Win32_OperatingSystem.ProductType
- Downloads the proper rules from repo.plura.io if needed
  * SERVER : https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-registry3.rules
  * DESKTOP: https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-registry3.rules
- Local rules priority:
  1) Use the given local path if it exists (absolute or relative to current dir)
  2) If not found, try relative to script dir
  3) If not found, try WorkDir (C:\Program Files\PLURA\desktop|server)
  4) If still not found and filename begins with d- or s-, download from repo
- Proxy support:
  HKLM\SOFTWARE\QubitSecurity\PLURA\Proxy
- Uses Write-Output (stdout) + file log under C:\Program Files\PLURA\logs\
- PS 5.1 safe.

Rule format (recommended): id|path|perm|note
Also accepted:
  path|perm
  id|path|perm
Directives:
  @include <file>
Comments:
  # ...   or  ; ...

Notes:
- This script does NOT enable Advanced Audit Policy subcategories (Registry). The OS policy must be enabled separately.
- Requires Administrator or SYSTEM privileges.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RuleFileName,

    [ValidateSet('Apply','List')]
    [string]$Action = 'Apply',

    # Single-target mode (optional)
    [string]$Path,
    [string]$Perm,

    [string]$Account = 'Everyone',
    [string]$AuditFlags = 'Success,Failure',
    [bool]$ReplaceExisting = $true,

    # RULES filter (optional)
    [string[]]$Id,
    [string]$Match
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Constants ----
$PluraRoot  = 'C:\Program Files\PLURA'
$DesktopDir = Join-Path $PluraRoot 'desktop'
$ServerDir  = Join-Path $PluraRoot 'server'
$LogDir     = Join-Path $PluraRoot 'logs'
$LogFile    = Join-Path $LogDir  'win-registry3.log'

$RepoDesktopRuleUrl = 'https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-registry3.rules'
$RepoServerRuleUrl  = 'https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-registry3.rules'
$RepoBaseDesktop    = 'https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/'
$RepoBaseServer     = 'https://repo.plura.io/edr/windows/advanced-audit-policy/server/'

# --- Script root (safe in functions under StrictMode) ---
$script:PLURA_SCRIPT_DIR = if ($PSScriptRoot) { $PSScriptRoot } elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# ---- Output helper (stdout + file) ----
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = '[{0}] [{1}] {2}' -f $ts, $Level, $Message

    # stdout
    Write-Output $Message

    # file log (best effort)
    try {
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch {
        # ignore
    }
}

function Assert-Privileged {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    $isAdmin  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = ($identity.Name -eq 'NT AUTHORITY\SYSTEM')

    if (-not ($isAdmin -or $isSystem)) {
        Write-Log -Level 'ERROR' -Message 'Administrator or SYSTEM privileges are required.'
        exit 1
    }
}

function Get-OsRole {
    # 1=Client(Desktop), 2=Domain Controller(Server), 3=Server
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        switch ([int]$os.ProductType) {
            1 { return 'DESKTOP' }
            2 { return 'SERVER' }
            3 { return 'SERVER' }
            default { return 'UNKNOWN' }
        }
    } catch {
        return 'UNKNOWN'
    }
}

function Is-HttpUrl {
    param([Parameter(Mandatory=$true)][string]$Text)
    return ($Text -match '^\s*https?://')
}

function Normalize-ProxyUri {
    param([Parameter(Mandatory=$true)][string]$Text)

    $t = $Text.Trim()
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }

    if ($t -notmatch '^[a-zA-Z][a-zA-Z0-9+\-.]*://') {
        $t = "http://$t"
    }

    try { return [Uri]$t } catch { return $null }
}

function Get-ProxyFromPluraRegistry {
    $subKey = 'SOFTWARE\\QubitSecurity\\PLURA'
    $valueName = 'Proxy'

    $views = @(
        [Microsoft.Win32.RegistryView]::Registry64,
        [Microsoft.Win32.RegistryView]::Registry32
    )

    foreach ($view in $views) {
        $base = $null
        $key  = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $key  = $base.OpenSubKey($subKey)
            if ($key) {
                $val = $key.GetValue($valueName, $null)
                if ($null -ne $val) {
                    $s = [string]$val
                    if (-not [string]::IsNullOrWhiteSpace($s)) { return $s.Trim() }
                }
            }
        } catch {
            # ignore
        } finally {
            if ($key)  { $key.Dispose() }
            if ($base) { $base.Dispose() }
        }
    }

    return $null
}

function Download-File {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [Parameter(Mandatory=$false)][Uri]$Proxy
    )

    $iwr = Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
    if ($iwr) {
        $params = @{
            Uri         = $Url
            OutFile     = $OutFile
            ErrorAction = 'Stop'
        }

        if ($iwr.Parameters.ContainsKey('UseBasicParsing')) { $params.UseBasicParsing = $true }

        if ($Proxy) {
            $params.Proxy = $Proxy.AbsoluteUri
            if ($iwr.Parameters.ContainsKey('ProxyUseDefaultCredentials')) { $params.ProxyUseDefaultCredentials = $true }
        }

        Invoke-WebRequest @params
        return
    }

    $wc = New-Object System.Net.WebClient
    try {
        if ($Proxy) {
            $p = New-Object System.Net.WebProxy($Proxy.AbsoluteUri, $true)
            $p.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            $wc.Proxy = $p
        }
        $wc.DownloadFile($Url, $OutFile)
    } finally {
        $wc.Dispose()
    }
}

function Normalize-InputPath {
    param([Parameter(Mandatory)][string]$Path)

    $p = $Path.Trim()

    while (($p.StartsWith("'") -and $p.EndsWith("'")) -or ($p.StartsWith('"') -and $p.EndsWith('"'))) {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }

    $p = [regex]::Replace($p, '\$env:([A-Za-z_][A-Za-z0-9_]*)', {
        param($m)
        $name = $m.Groups[1].Value
        $val  = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrEmpty($val)) { $m.Value } else { $val }
    })

    $p = [Environment]::ExpandEnvironmentVariables($p)
    return $p
}

function Resolve-LocalFilePath {
    param(
        [Parameter(Mandatory=$true)][string]$InputPath,
        [Parameter(Mandatory=$true)][string]$WorkDir
    )

    $s = Normalize-InputPath -Path $InputPath

    if ([System.IO.Path]::IsPathRooted($s)) {
        if (Test-Path -LiteralPath $s) { return $s }
        return $null
    }

    $cands = @(
        (Join-Path (Get-Location).Path $s),
        (Join-Path $script:PLURA_SCRIPT_DIR $s),
        (Join-Path $WorkDir $s)
    ) | Select-Object -Unique

    foreach ($c in $cands) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }

    return $null
}

function Resolve-RulesFile {
    param(
        [Parameter(Mandatory=$false)][string]$RuleFileName,
        [Parameter(Mandatory=$true)][string]$DefaultUrl,
        [Parameter(Mandatory=$true)][string]$WorkDir,
        [Parameter(Mandatory=$false)][Uri]$Proxy
    )

    $source = if ([string]::IsNullOrWhiteSpace($RuleFileName)) { $DefaultUrl } else { $RuleFileName.Trim() }

    if (Is-HttpUrl -Text $source) {
        $uri = $null
        try { $uri = [Uri]$source } catch { $uri = $null }
        if (-not $uri) { throw "Invalid rules URL: $source" }

        $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($fileName)) { $fileName = 'audit.rules' }

        $dest = Join-Path $WorkDir $fileName
        Write-Log -Level 'INFO' -Message ("Downloading rules: {0} -> {1}" -f $source, $dest)

        if ($Proxy) { Download-File -Url $source -OutFile $dest -Proxy $Proxy } else { Download-File -Url $source -OutFile $dest }
        return $dest
    }

    $local = Resolve-LocalFilePath -InputPath $source -WorkDir $WorkDir
    if ($local) { return $local }

    $fileName2 = [System.IO.Path]::GetFileName($source)
    if ([string]::IsNullOrWhiteSpace($fileName2)) { throw "Rule file not found: $source" }

    $url = $null
    if ($fileName2 -match '^(?i)d-') {
        $url = $RepoBaseDesktop + $fileName2
    } elseif ($fileName2 -match '^(?i)s-') {
        $url = $RepoBaseServer + $fileName2
    } else {
        throw ("Rule file not found: {0}. If you intended to download, pass an URL or use d-/s- prefixed filename." -f $source)
    }

    $dest2 = Join-Path $WorkDir $fileName2
    Write-Log -Level 'INFO' -Message ("Rules file not found locally. Downloading: {0} -> {1}" -f $url, $dest2)

    if ($Proxy) { Download-File -Url $url -OutFile $dest2 -Proxy $Proxy } else { Download-File -Url $url -OutFile $dest2 }
    return $dest2
}

function Enable-SeSecurityPrivilege {
    if (-not ("PluraPrivilege" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PluraPrivilege {
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

  const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x20;
  const UInt32 TOKEN_QUERY = 0x08;
  const UInt32 SE_PRIVILEGE_ENABLED = 0x02;

  [StructLayout(LayoutKind.Sequential)]
  struct LUID { public UInt32 LowPart; public Int32 HighPart; }

  [StructLayout(LayoutKind.Sequential)]
  struct LUID_AND_ATTRIBUTES { public LUID Luid; public UInt32 Attributes; }

  [StructLayout(LayoutKind.Sequential)]
  struct TOKEN_PRIVILEGES { public UInt32 PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

  public static void EnablePrivilege(string privilegeName) {
    IntPtr token;
    if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

    LUID luid;
    if (!LookupPrivilegeValue(null, privilegeName, out luid))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
    tp.PrivilegeCount = 1;
    tp.Privileges = new LUID_AND_ATTRIBUTES();
    tp.Privileges.Luid = luid;
    tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
      throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  }
}
"@ -Language CSharp -ErrorAction Stop | Out-Null
    }

    try {
        [PluraPrivilege]::EnablePrivilege('SeSecurityPrivilege')
    } catch {
        Write-Log -Level 'WARN' -Message ("Failed to enable SeSecurityPrivilege: {0}" -f $_.Exception.Message)
    }
}

function Is-RegistryPath {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -match '^(HKLM|HKCU|HKCR|HKU|HKCC):\\')
}

function Resolve-RulePath {
    param(
        [Parameter(Mandatory)][string]$BaseFile,
        [Parameter(Mandatory)][string]$ChildPath
    )
    $c = $ChildPath.Trim()
    while (($c.StartsWith("'") -and $c.EndsWith("'")) -or ($c.StartsWith('"') -and $c.EndsWith('"'))) {
        $c = $c.Substring(1, $c.Length - 2).Trim()
    }
    if ([System.IO.Path]::IsPathRooted($c)) { return $c }
    return (Join-Path -Path (Split-Path -Parent $BaseFile) -ChildPath $c)
}

function Read-Rules {
    param([Parameter(Mandatory)][string]$RuleFilePath)

    if (-not (Test-Path -LiteralPath $RuleFilePath)) {
        throw "Rule file not found: $RuleFilePath"
    }

    $items = New-Object System.Collections.Generic.List[object]
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]'

    function _read([string]$file) {
        $full = (Resolve-Path -LiteralPath $file).Path
        if ($seen.Contains($full)) { return }
        [void]$seen.Add($full)

        $ln = 0
        foreach ($raw in Get-Content -LiteralPath $full -Encoding UTF8) {
            $ln++
            $line = $raw.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }

            if ($line -match '^\@include\s+(.+)$') {
                $inc = Resolve-RulePath -BaseFile $full -ChildPath $Matches[1]
                _read $inc
                continue
            }

            $parts = $line.Split('|')
            if ($parts.Count -lt 2) {
                Write-Log -Level 'WARN' -Message ("Invalid rule line (skip): {0}:{1} : {2}" -f $full, $ln, $line)
                continue
            }

            $id   = $null
            $path = $null
            $perm = $null
            $note = ''

            if ($parts.Count -eq 2) {
                $path = $parts[0].Trim()
                $perm = $parts[1].Trim()
                $id = ("rule_{0:0000}" -f $items.Count)
            } elseif ($parts.Count -eq 3) {
                $id   = $parts[0].Trim()
                $path = $parts[1].Trim()
                $perm = $parts[2].Trim()
            } else {
                $id   = $parts[0].Trim()
                $path = $parts[1].Trim()
                $perm = $parts[2].Trim()
                $note = ($parts[3..($parts.Count-1)] -join '|').Trim()
            }

            if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($perm)) {
                Write-Log -Level 'WARN' -Message ("Invalid rule line (missing path/perm): {0}:{1} : {2}" -f $full, $ln, $line)
                continue
            }

            $items.Add([pscustomobject]@{
                Id   = $id
                Path = $path
                Perm = $perm
                Note = $note
                SourceFile = $full
                SourceLine = $ln
            }) | Out-Null
        }
    }

    _read $RuleFilePath
    return $items
}

function Parse-AuditFlags {
    param([string]$AuditFlags = 'Success,Failure')
    $flags = 0
    foreach ($t in ($AuditFlags -split ',')) {
        $tok = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        try {
            $v = [Enum]::Parse([System.Security.AccessControl.AuditFlags], $tok, $true)
            $flags = $flags -bor [int]$v
        } catch {
            throw "Invalid AuditFlags token: '$tok'. Use Success, Failure, or Success,Failure."
        }
    }
    return [System.Security.AccessControl.AuditFlags]$flags
}

function Parse-RegistryRights {
    param([Parameter(Mandatory)][string]$Perm)
    $rights = 0
    foreach ($t in ($Perm -split ',')) {
        $tok = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        try {
            $v = [Enum]::Parse([System.Security.AccessControl.RegistryRights], $tok, $true)
            $rights = $rights -bor [int]$v
        } catch {
            throw "Invalid RegistryRights token: '$tok'."
        }
    }
    return [System.Security.AccessControl.RegistryRights]$rights
}

function Test-IsAccessDenied {
    param([Parameter(Mandatory)]$ErrorRecord)

    try {
        $e = $ErrorRecord.Exception
        while ($e) {
            if ($e -is [System.UnauthorizedAccessException]) { return $true }
            if ($e -is [System.Security.SecurityException]) { return $true }

            try {
                if ($e -is [System.ComponentModel.Win32Exception]) {
                    if ($e.NativeErrorCode -eq 5) { return $true }
                }
            } catch {}

            try {
                if ($e.HResult -eq -2147024891) { return $true } # 0x80070005
            } catch {}

            $e = $e.InnerException
        }
    } catch {}

    return $false
}

function Apply-RegistryAuditRule_KeyAndSubkeys {
    param(
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][string]$Perm
    )

    $t = Normalize-InputPath -Path $TargetPath
    if (-not (Is-RegistryPath -Path $t)) {
        throw ("Registry path required: {0}" -f $t)
    }

    if (-not (Test-Path -Path $t)) {
        throw ("Registry key not found: {0}" -f $t)
    }

    $rights = Parse-RegistryRights -Perm $Perm
    $aFlags = Parse-AuditFlags -AuditFlags $AuditFlags
    $acct   = New-Object System.Security.Principal.NTAccount($Account)

    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $prop    = [System.Security.AccessControl.PropagationFlags]::None

    $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
        $acct, $rights, $inherit, $prop, $aFlags
    )

    $acl = Get-Acl -Path $t -Audit

    if ($ReplaceExisting) {
        try {
            $acl.PurgeAuditRules($acct)
        } catch {
            $existing = $acl.GetAuditRules($true, $false, [System.Security.Principal.NTAccount]) |
                        Where-Object { $_.IdentityReference -eq $acct }
            foreach ($r in $existing) { [void]$acl.RemoveAuditRuleSpecific($r) }
        }
    }

    $acl.AddAuditRule($rule) | Out-Null
    Set-Acl -Path $t -AclObject $acl
}

# ---- Start ----
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

Assert-Privileged

$osRole = Get-OsRole
if ($osRole -eq 'UNKNOWN') {
    Write-Log -Level 'ERROR' -Message 'OS Role is UNKNOWN (failed to determine Win32_OperatingSystem.ProductType). Aborting.'
    exit 2
}

$WorkDir    = if ($osRole -eq 'SERVER') { $ServerDir } else { $DesktopDir }
$DefaultUrl = if ($osRole -eq 'SERVER') { $RepoServerRuleUrl } else { $RepoDesktopRuleUrl }

try {
    if (-not (Test-Path $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Log -Level 'ERROR' -Message ("Failed to create/access WorkDir: {0}" -f $WorkDir)
    exit 3
}

Write-Log -Level 'INFO' -Message ("OS Role : {0}" -f $osRole)
Write-Log -Level 'INFO' -Message ("WorkDir : {0}" -f $WorkDir)

$proxyRaw = $null
$proxyUri = $null
try { $proxyRaw = Get-ProxyFromPluraRegistry } catch { $proxyRaw = $null }

if (-not [string]::IsNullOrWhiteSpace($proxyRaw)) {
    $proxyUri = Normalize-ProxyUri -Text $proxyRaw
    if ($proxyUri) {
        Write-Log -Level 'INFO' -Message ("Proxy detected: {0}" -f $proxyUri.AbsoluteUri)
    } else {
        Write-Log -Level 'WARN' -Message ("Proxy value exists but is invalid. Value='{0}'. Using direct connection." -f $proxyRaw)
    }
} else {
    Write-Log -Level 'INFO' -Message "No proxy configured in HKLM\SOFTWARE\QubitSecurity\PLURA (value 'Proxy')."
}

Enable-SeSecurityPrivilege

try {
    $useRules = $true
    if ([string]::IsNullOrWhiteSpace($RuleFileName)) {
        if (-not [string]::IsNullOrWhiteSpace($Path) -and -not [string]::IsNullOrWhiteSpace($Perm)) {
            $useRules = $false
        }
    }

    if ($useRules) {
        $rulesPath = Resolve-RulesFile -RuleFileName $RuleFileName -DefaultUrl $DefaultUrl -WorkDir $WorkDir -Proxy $proxyUri

        Write-Log -Level 'INFO' -Message "Applying Registry auditing (SACL) - Registry3 (This key and subkeys)"
        Write-Log -Level 'INFO' -Message ("Rules file      : {0}" -f $rulesPath)
        Write-Log -Level 'INFO' -Message ("Action          : {0}" -f $Action)
        Write-Log -Level 'INFO' -Message ("Account         : {0}" -f $Account)
        Write-Log -Level 'INFO' -Message ("AuditFlags      : {0}" -f $AuditFlags)
        Write-Log -Level 'INFO' -Message ("ReplaceExisting : {0}" -f $ReplaceExisting)

        $items = Read-Rules -RuleFilePath $rulesPath

        if ($Id) {
            $idset = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($x in $Id) { [void]$idset.Add($x) }
            $items = $items | Where-Object { $idset.Contains($_.Id) }
        }
        if ($Match) {
            $rx = [regex]::new($Match)
            $items = $items | Where-Object { $rx.IsMatch(("{0}|{1}|{2}|{3}" -f $_.Id,$_.Path,$_.Perm,$_.Note)) }
        }

        if ($Action -eq 'List') {
            $items | Select-Object Id, Path, Perm, Note, SourceFile, SourceLine | Format-Table -AutoSize
            exit 0
        }

        $ruleCount = 0
        $appliedCount = 0
        $missingCount = 0
        $accessDeniedCount = 0
        $failedCount = 0
        $skippedNonRegistryCount = 0

        foreach ($it in $items) {
            $ruleCount++

            $t = Normalize-InputPath -Path $it.Path
            if (-not (Is-RegistryPath -Path $t)) {
                $skippedNonRegistryCount++
                Write-Log -Level 'WARN' -Message ("Skip non-registry path: {0}" -f $t)
                continue
            }

            if (-not (Test-Path -Path $t)) {
                $missingCount++
                Write-Log -Level 'WARN' -Message ("Registry key not found: {0}" -f $t)
                continue
            }

            try {
                Apply-RegistryAuditRule_KeyAndSubkeys -TargetPath $t -Perm $it.Perm
                $appliedCount++
            } catch {
                if (Test-IsAccessDenied -ErrorRecord $_) {
                    $accessDeniedCount++
                    Write-Log -Level 'WARN' -Message ("Access denied applying rule '{0}' key '{1}' : {2}" -f $it.Id, $t, $_.Exception.Message)
                } else {
                    $failedCount++
                    Write-Log -Level 'WARN' -Message ("Failed applying rule '{0}' key '{1}' : {2}" -f $it.Id, $t, $_.Exception.Message)
                }
            }
        }

        Write-Log -Level 'INFO' -Message ("Completed. Rules={0} Applied={1} Missing={2} SkipNonRegistry={3} AccessDenied={4} Failed={5}" -f $ruleCount, $appliedCount, $missingCount, $skippedNonRegistryCount, $accessDeniedCount, $failedCount)
        if (($accessDeniedCount + $failedCount) -gt 0) { exit 1 } else { exit 0 }
    }

    Write-Log -Level 'INFO' -Message "Applying Registry auditing (SACL) - Registry3 (This key and subkeys) - single target"
    Write-Log -Level 'INFO' -Message ("Target Path : {0}" -f $Path)
    Write-Log -Level 'INFO' -Message ("Permissions : {0}" -f $Perm)
    Write-Log -Level 'INFO' -Message ("Account     : {0}" -f $Account)
    Write-Log -Level 'INFO' -Message ("AuditFlags  : {0}" -f $AuditFlags)

    Apply-RegistryAuditRule_KeyAndSubkeys -TargetPath $Path -Perm $Perm
    Write-Log -Level 'INFO' -Message 'Completed successfully.'
    exit 0
}
catch {
    Write-Log -Level 'ERROR' -Message ("Unhandled error: {0}" -f $_.Exception.Message)
    exit 1
}
