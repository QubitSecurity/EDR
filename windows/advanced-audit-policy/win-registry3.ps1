<#
PLURA-Forensic
Windows Registry SACL(Audit ACL) applier for PLURA - Registry3 (This key and subkeys)

- RULES 파일(텍스트)을 입력 받아 레지스트리 키에 SACL(Audit ACL)을 적용/조회합니다.
- 이 스크립트는 "고급 감사 정책(Advanced Audit Policy)" 자체를 켜지 않습니다.
  (Registry 서브카테고리 감사가 켜져 있어야 실제 이벤트가 생성됩니다.)
- Administrator 또는 SYSTEM 권한 실행을 전제로 합니다.

Key behavior (sysmon-install.ps1 스타일):
- OS role(Desktop vs Server)를 Win32_OperatingSystem.ProductType로 판별
- RuleFileName을 지정하지 않으면 OS 역할에 맞는 rules 파일을 repo.plura.io에서 다운로드 후 적용
  * SERVER : https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-registry3.rules
  * DESKTOP: https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-registry3.rules
- RuleFileName이 URL(http/https)이면 다운로드 후 적용
- RuleFileName이 로컬 파일이면 로컬 파일 적용
- 로컬 파일이 없는데 파일명이 'd-audit-registry3.rules' 또는 's-audit-registry3.rules' 이면 해당 rules를 자동 다운로드 후 적용
- Proxy 지원:
  HKLM\SOFTWARE\QubitSecurity\PLURA\Proxy
- 출력은 Write-Output(stdout) + 파일 로그(C:\Program Files\PLURA\logs\win-registry3.log)

Examples:
  # (권장) RuleFileName 생략: OS에 맞는 rules를 자동 다운로드 후 적용
  .\win-registry3.ps1

  # 로컬 rules 파일 지정(예)
  .\win-registry3.ps1 .\d-audit-registry3.rules

  # URL 지정(예)
  .\win-registry3.ps1 https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-registry3.rules

  # rules 목록만 출력
  .\win-registry3.ps1 .\d-audit-registry3.rules List
#>

[CmdletBinding()]
param(
    # Optional override.
    # - If empty: auto-select OS-specific repo URL above and download.
    # - If starts with http/https: treated as URL and downloaded.
    # - Otherwise: treated as local path.
    [Parameter(Mandatory=$false, Position=0)]
    [string]$RuleFileName,

    # 두 번째 인자로 List/Apply 지정 가능
    #   .\win-registry3.ps1 .\d-audit-registry3.rules List
    [Parameter(Mandatory=$false, Position=1)]
    [ValidateSet('Apply','List')]
    [string]$Action = 'Apply',

    # 단일 모드(필요 시 사용)
    [string]$Path,
    [string]$Perm,

    [string]$Account = 'Everyone',
    [string]$AuditFlags = 'Success,Failure',
    [bool]$ReplaceExisting = $true,

    # RULES 모드 필터(선택)
    [string[]]$Id,
    [string]$Match
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Constants ----
$PluraRoot       = 'C:\Program Files\PLURA'
$DesktopDir      = Join-Path $PluraRoot 'desktop'
$ServerDir       = Join-Path $PluraRoot 'server'
$DesktopRulesUrl = 'https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-registry3.rules'
$ServerRulesUrl  = 'https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-registry3.rules'
$DesktopRuleName = 'd-audit-registry3.rules'
$ServerRuleName  = 's-audit-registry3.rules'
$LogDir          = Join-Path $PluraRoot 'logs'
$LogFile         = Join-Path $LogDir 'win-registry3.log'

# ---- Output helper (stdout + file) ----
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = '[{0}] [{1}] {2}' -f $ts, $Level, $Message

    # Agent consoles usually capture stdout.
    Write-Output $Message

    # Best-effort file log.
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

function Get-ScriptDir {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($PSCommandPath) { return (Split-Path -Parent $PSCommandPath) }
    return (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

function Get-OsRole {
    <#
      Returns: DESKTOP | SERVER | UNKNOWN
      Based on Win32_OperatingSystem.ProductType:
        1 = Workstation, 2 = Domain Controller, 3 = Server
      DC는 SERVER로 취급합니다.
    #>
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

    # Accept "host:port" and "http://host:port"
    if ($t -notmatch '^[a-zA-Z][a-zA-Z0-9+\-.]*://') {
        $t = "http://$t"
    }

    try { return [Uri]$t } catch { return $null }
}

function Get-ProxyFromPluraRegistry {
    # Reads HKLM\SOFTWARE\QubitSecurity\PLURA -> Proxy
    # Tries both 64-bit and 32-bit registry views.

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
                    if (-not [string]::IsNullOrWhiteSpace($s)) {
                        return $s.Trim()
                    }
                }
            }
        } catch {
            # ignore and continue to next view
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

        if ($iwr.Parameters.ContainsKey('UseBasicParsing')) {
            $params.UseBasicParsing = $true
        }

        if ($Proxy) {
            $params.Proxy = $Proxy.AbsoluteUri
            if ($iwr.Parameters.ContainsKey('ProxyUseDefaultCredentials')) {
                $params.ProxyUseDefaultCredentials = $true
            }
        }

        Invoke-WebRequest @params
        return
    }

    # Fallback for environments without Invoke-WebRequest
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

function Enable-SeSecurityPrivilege {
    # SACL 수정에 필요한 SeSecurityPrivilege를 토큰에서 활성화합니다.
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
        [PluraPrivilege]::EnablePrivilege("SeSecurityPrivilege")
    } catch {
        Write-Log -Level 'WARN' -Message ("Failed to enable SeSecurityPrivilege: {0}" -f $_.Exception.Message)
    }
}

function Normalize-InputPath {
    param([Parameter(Mandatory)][string]$Path)

    $p = $Path.Trim()

    # remove surrounding quotes repeatedly
    while (($p.StartsWith("'") -and $p.EndsWith("'")) -or ($p.StartsWith('"') -and $p.EndsWith('"'))) {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }

    # Expand $env:NAME occurrences only (safe for paths like C:\$Recycle.Bin)
    $p = [regex]::Replace($p, '\$env:([A-Za-z_][A-Za-z0-9_]*)', {
        param($m)
        $name = $m.Groups[1].Value
        $val  = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrEmpty($val)) { $m.Value } else { $val }
    })

    # Expand %NAME% environment variables
    $p = [Environment]::ExpandEnvironmentVariables($p)

    return $p
}

function Resolve-ExistingRuleFile {
    <#
      Resolve local rules path in a robust way:
        1) As provided (current directory)
        2) Script directory
        3) PLURA OS work directory (desktop/server)
      Returns: full path or $null
    #>
    param(
        [Parameter(Mandatory)][string]$RuleFileName,
        [Parameter(Mandatory)][string]$WorkDir
    )

    $rf = Normalize-InputPath -Path $RuleFileName

    try {
        if (Test-Path -LiteralPath $rf) {
            return (Resolve-Path -LiteralPath $rf).Path
        }
    } catch {}

    # If not rooted, try script dir
    try {
        if (-not [System.IO.Path]::IsPathRooted($rf)) {
            $sd = Get-ScriptDir
            $c2 = Join-Path -Path $sd -ChildPath $rf
            if (Test-Path -LiteralPath $c2) {
                return (Resolve-Path -LiteralPath $c2).Path
            }
        }
    } catch {}

    # Try WorkDir by basename
    try {
        $base = [System.IO.Path]::GetFileName($rf)
        if (-not [string]::IsNullOrWhiteSpace($base)) {
            $c3 = Join-Path -Path $WorkDir -ChildPath $base
            if (Test-Path -LiteralPath $c3) {
                return (Resolve-Path -LiteralPath $c3).Path
            }
        }
    } catch {}

    return $null
}

function Prepare-RuleFile {
    <#
      Ensures the rules file exists locally.
      Returns: absolute path to the rules file.
    #>
    param(
        [Parameter(Mandatory=$false)][string]$RuleFileName,
        [Parameter(Mandatory)][string]$OsRole,
        [Parameter(Mandatory=$false)][Uri]$Proxy
    )

    $WorkDir = if ($OsRole -eq 'SERVER') { $ServerDir } else { $DesktopDir }
    if (-not (Test-Path $WorkDir)) {
        try { New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null } catch {}
    }

    # 1) RuleFileName empty => download default for OS role
    if ([string]::IsNullOrWhiteSpace($RuleFileName)) {
        $url = if ($OsRole -eq 'SERVER') { $ServerRulesUrl } else { $DesktopRulesUrl }
        $out = Join-Path -Path $WorkDir -ChildPath ([System.IO.Path]::GetFileName($url))
        Write-Log -Level 'INFO' -Message ("Downloading default rules for OS({0}): {1}" -f $OsRole, $url)
        Download-File -Url $url -OutFile $out -Proxy $Proxy
        return $out
    }

    # 2) If URL => download
    if (Is-HttpUrl -Text $RuleFileName) {
        $url = $RuleFileName.Trim()
        try {
            $u = [Uri]$url
            $name = [System.IO.Path]::GetFileName($u.AbsolutePath)
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = if ($OsRole -eq 'SERVER') { $ServerRuleName } else { $DesktopRuleName }
            }
        } catch {
            $name = if ($OsRole -eq 'SERVER') { $ServerRuleName } else { $DesktopRuleName }
        }
        $out = Join-Path -Path $WorkDir -ChildPath $name
        Write-Log -Level 'INFO' -Message ("Downloading rules from URL: {0}" -f $url)
        Download-File -Url $url -OutFile $out -Proxy $Proxy
        return $out
    }

    # 3) Local file if exists
    $local = Resolve-ExistingRuleFile -RuleFileName $RuleFileName -WorkDir $WorkDir
    if ($local) {
        return $local
    }

    # 4) If file missing but basename matches expected, download
    $baseName = [System.IO.Path]::GetFileName((Normalize-InputPath -Path $RuleFileName))
    $urlToUse = $null

    if ($baseName -ieq $DesktopRuleName) {
        $urlToUse = $DesktopRulesUrl
    } elseif ($baseName -ieq $ServerRuleName) {
        $urlToUse = $ServerRulesUrl
    } else {
        # fallback to OS role default
        $urlToUse = if ($OsRole -eq 'SERVER') { $ServerRulesUrl } else { $DesktopRulesUrl }
        # also set output name to OS default
        $baseName = [System.IO.Path]::GetFileName($urlToUse)
    }

    $out = Join-Path -Path $WorkDir -ChildPath $baseName
    Write-Log -Level 'WARN' -Message ("Local rules file not found. Downloading: {0}" -f $urlToUse)
    Download-File -Url $urlToUse -OutFile $out -Proxy $Proxy
    return $out
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
    <#
      Rule format (recommended): id|path|perm|note
      Also accepted:
        path|perm
        id|path|perm
      Directives:
        @include <file>
      Comments:
        # ...   or  ; ...
    #>
    param([Parameter(Mandatory)][string]$Rulefile)

    if (-not (Test-Path -LiteralPath $Rulefile)) {
        throw "Rule file not found: $Rulefile"
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

    _read $Rulefile
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
  <#
    Robust AccessDenied detection (safe on non-English OS):
      - Walks exception chain
      - Checks UnauthorizedAccess/SecurityException
      - Checks HResult == E_ACCESSDENIED (0x80070005)
      - Checks Win32Exception NativeErrorCode == 5
  #>
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

  try {
    if ($ErrorRecord.FullyQualifiedErrorId -match '(?i)unauthorized|accessdenied') { return $true }
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
        throw "win-registry3.ps1는 레지스트리 전용입니다: $t"
    }

    if (-not (Test-Path -Path $t)) {
        Write-Log -Level 'WARN' -Message ("Registry key not found: {0}" -f $t)
        return
    }

    $rights = Parse-RegistryRights -Perm $Perm
    $aFlags = Parse-AuditFlags -AuditFlags $AuditFlags
    $acct   = New-Object System.Security.Principal.NTAccount($Account)

# This key and subkeys
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
try {
    try {
        Write-Log -Level 'INFO' -Message ("PowerShell: {0}" -f $PSVersionTable.PSVersion)
    } catch {}

    # TLS 1.2 (common requirement)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    Assert-Privileged
    Enable-SeSecurityPrivilege

    $osRole = Get-OsRole
    if ($osRole -eq 'UNKNOWN') {
        Write-Log -Level 'ERROR' -Message 'OS Role is UNKNOWN (failed to determine Win32_OperatingSystem.ProductType). Aborting.'
        exit 2
    }

    $proxyText = Get-ProxyFromPluraRegistry
    $proxyUri = $null
    if ($proxyText) {
        $proxyUri = Normalize-ProxyUri -Text $proxyText
        if ($proxyUri) {
            Write-Log -Level 'INFO' -Message ("Proxy detected: {0}" -f $proxyUri.AbsoluteUri)
        }
    }

    # If RuleFileName is empty AND Path+Perm provided => single mode
    $isSingleMode = ([string]::IsNullOrWhiteSpace($RuleFileName) -and -not [string]::IsNullOrWhiteSpace($Path) -and -not [string]::IsNullOrWhiteSpace($Perm))

    if ($isSingleMode) {
        Write-Log -Level 'INFO' -Message ("Applying Registry auditing (SACL) - This key and subkeys (single target)")
        Write-Log -Level 'INFO' -Message ("Target Path     : {0}" -f $Path)
        Write-Log -Level 'INFO' -Message ("Permissions     : {0}" -f $Perm)
        Write-Log -Level 'INFO' -Message ("Account         : {0}" -f $Account)
        Write-Log -Level 'INFO' -Message ("AuditFlags      : {0}" -f $AuditFlags)

        Apply-RegistryAuditRule_KeyAndSubkeys -TargetPath $Path -Perm $Perm
        Write-Log -Level 'INFO' -Message "Completed successfully."
        exit 0
    }

    # RULES mode
    $rulePath = Prepare-RuleFile -RuleFileName $RuleFileName -OsRole $osRole -Proxy $proxyUri

    Write-Log -Level 'INFO' -Message ("Applying Registry auditing (SACL) - This key and subkeys")
    Write-Log -Level 'INFO' -Message ("OS Role         : {0}" -f $osRole)
    Write-Log -Level 'INFO' -Message ("Rules file      : {0}" -f $rulePath)
    Write-Log -Level 'INFO' -Message ("Action          : {0}" -f $Action)
    Write-Log -Level 'INFO' -Message ("Account         : {0}" -f $Account)
    Write-Log -Level 'INFO' -Message ("AuditFlags      : {0}" -f $AuditFlags)
    Write-Log -Level 'INFO' -Message ("ReplaceExisting : {0}" -f $ReplaceExisting)

    $items = Read-Rules -Rulefile $rulePath

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

    foreach ($it in $items) {
        $ruleCount++
        $t = Normalize-InputPath -Path $it.Path

        if (-not (Test-Path -Path $t)) {
            $missingCount++
            Write-Log -Level 'WARN' -Message ("Registry key not found: {0}" -f $t)
            continue
        }

        try {
            Apply-RegistryAuditRule_KeyAndSubkeys -TargetPath $t -Perm $it.Perm
            $appliedCount++
        }
        catch {
            if (Test-IsAccessDenied -ErrorRecord $_) {
                $accessDeniedCount++
                Write-Log -Level 'WARN' -Message ("Access denied applying rule '{0}' key '{1}' : {2}" -f $it.Id, $t, $_.Exception.Message)
            } else {
                $failedCount++
                Write-Log -Level 'WARN' -Message ("Failed applying rule '{0}' key '{1}' : {2}" -f $it.Id, $t, $_.Exception.Message)
            }
            continue
        }
    }

    Write-Log -Level 'INFO' -Message ("Completed. Rules={0} Applied={1} Missing={2} AccessDenied={3} Failed={4}" -f $ruleCount, $appliedCount, $missingCount, $accessDeniedCount, $failedCount)
    if (($accessDeniedCount + $failedCount) -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Error $_
    exit 1
}
