<#
PLURA-Forensic
Windows File/Folder SACL(Audit ACL) applier for PLURA

- RULES 파일(텍스트)을 입력 받아 파일/폴더에 SACL(Audit ACL)을 적용/조회합니다.
- 이 스크립트는 "고급 감사 정책(Advanced Audit Policy)" 자체를 켜지 않습니다.
  (File System 서브카테고리 감사가 켜져 있어야 실제 이벤트가 생성됩니다.)
- 본 스크립트는 Administrator 또는 SYSTEM 권한 실행을 전제로 합니다.

Key behavior (sysmon-install.ps1 스타일 적용):
- OS role(Desktop vs Server)를 Win32_OperatingSystem.ProductType로 판별
- RuleFileName을 지정하지 않으면 OS 역할에 맞는 rules 파일을 repo.plura.io에서 다운로드 후 적용
  * SERVER : https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-core.rules
  * DESKTOP: https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-core.rules
- RuleFileName이 URL(http/https)이면 다운로드 후 적용
- Proxy 지원:
  HKLM\SOFTWARE\QubitSecurity\PLURA\Proxy
- 출력은 Write-Output(stdout) + 파일 로그(C:\Program Files\PLURA\logs\file-folder-all-profiles.log)

Examples:
  # (권장) RuleFileName 생략: OS에 맞는 rules를 자동 다운로드 후 적용
  .\file-folder-all-profiles.ps1

  # 로컬 rules 파일 지정
  .\file-folder-all-profiles.ps1 .\d-audit-core.rules

  # URL 지정
  .\file-folder-all-profiles.ps1 https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-core.rules

  # rules 목록만 출력
  .\file-folder-all-profiles.ps1 .\d-audit-core.rules List
#>

[CmdletBinding()]
param(
    # Optional override.
    # - If empty: auto-select OS-specific repo URL above and download.
    # - If starts with http/https: treated as URL and downloaded.
    # - Otherwise: treated as local path.
    [Parameter(Mandatory=$false)]
    [string]$RuleFileName,

    # 두 번째 인자로 List/Apply 지정 가능
    #   .\file-folder-all-profiles.ps1 .\d-audit-core.rules List
    [Parameter(Mandatory=$false)]
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
$DesktopRulesUrl = 'https://repo.plura.io/edr/windows/advanced-audit-policy/desktop/d-audit-core.rules'
$ServerRulesUrl  = 'https://repo.plura.io/edr/windows/advanced-audit-policy/server/s-audit-core.rules'
$LogDir          = Join-Path $PluraRoot 'logs'
$LogFile         = Join-Path $LogDir 'file-folder-all-profiles.log'

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

function Script-Dir {
    return (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

function Normalize-InputPath {
    param([Parameter(Mandatory)][string]$Path)

    $p = $Path.Trim()

    # remove surrounding quotes repeatedly
    while (($p.StartsWith("'") -and $p.EndsWith("'")) -or ($p.StartsWith('"') -and $p.EndsWith('"'))) {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }

    # Expand $env:NAME occurrences only (safe for paths like C:\$Recycle.Bin)
    $p = [regex]::Replace($p, "\$env:([A-Za-z_][A-Za-z0-9_]*)", {
        param($m)
        $name = $m.Groups[1].Value
        $val  = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrEmpty($val)) { $m.Value } else { $val }
    })

    # Expand %NAME% environment variables
    $p = [Environment]::ExpandEnvironmentVariables($p)

    return $p
}

function Resolve-RuleFilePath {
    param(
        [Parameter(Mandatory)][string]$RuleFileName
    )
    $rf = Normalize-InputPath -Path $RuleFileName
    if ([System.IO.Path]::IsPathRooted($rf)) { return $rf }
    return (Join-Path -Path (Script-Dir) -ChildPath $rf)
}

function Resolve-LocalRuleFilePath {
    <#
      Resolve local rules file path in this order:
        1) as-is (current directory)
        2) relative to script directory
        3) relative to WorkDir
      Returns a candidate full/relative path (may not exist).
    #>
    param(
        [Parameter(Mandatory)][string]$RuleSource,
        [Parameter(Mandatory)][string]$WorkDir
    )

    $src = Normalize-InputPath -Path $RuleSource

    if ([System.IO.Path]::IsPathRooted($src)) {
        return $src
    }

    # 1) current directory
    try {
        if (Test-Path -LiteralPath $src) {
            return (Resolve-Path -LiteralPath $src).Path
        }
    } catch { }

    # 2) script directory
    $candScript = Join-Path (Script-Dir) $src
    try {
        if (Test-Path -LiteralPath $candScript) {
            return (Resolve-Path -LiteralPath $candScript).Path
        }
    } catch { }

    # 3) WorkDir
    $candWork = Join-Path $WorkDir $src
    try {
        if (Test-Path -LiteralPath $candWork) {
            return (Resolve-Path -LiteralPath $candWork).Path
        }
    } catch { }

    return $candWork
}

function Resolve-RulesFile {
    <#
      - If RuleSource is URL: download to WorkDir and return downloaded full path
      - If RuleSource is local path and exists: return resolved full path
      - If local path missing and leaf is 'd-audit-core.rules' or 's-audit-core.rules': download matching URL to WorkDir
    #>
    param(
        [Parameter(Mandatory)][string]$RuleSource,
        [Parameter(Mandatory)][string]$WorkDir,
        [Parameter(Mandatory=$false)][Uri]$Proxy
    )

    # URL input
    if (Is-HttpUrl -Text $RuleSource) {
        $uri = $null
        try { $uri = [Uri]$RuleSource } catch { $uri = $null }
        if (-not $uri) {
            throw "Invalid rules URL: $RuleSource"
        }

        $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            $fileName = 'audit-core.rules'
        }

        $dest = Join-Path $WorkDir $fileName

        Write-Log -Level 'INFO' -Message 'Downloading rules file...'
        Write-Log -Level 'INFO' -Message ("  URL : {0}" -f $RuleSource)
        Write-Log -Level 'INFO' -Message ("  DEST: {0}" -f $dest)

        if ($Proxy) {
            Download-File -Url $RuleSource -OutFile $dest -Proxy $Proxy
        } else {
            Download-File -Url $RuleSource -OutFile $dest
        }

        return (Resolve-Path -LiteralPath $dest).Path
    }

    # Local file input
    $candidate = Resolve-LocalRuleFilePath -RuleSource $RuleSource -WorkDir $WorkDir
    if (Test-Path -LiteralPath $candidate) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    # Auto-download for well-known filenames
    $leaf = Split-Path -Leaf (Normalize-InputPath -Path $RuleSource)
    $dlUrl = $null

    if ($leaf -ieq 'd-audit-core.rules') {
        $dlUrl = $DesktopRulesUrl
    } elseif ($leaf -ieq 's-audit-core.rules') {
        $dlUrl = $ServerRulesUrl
    }

    if ($dlUrl) {
        $dest = Join-Path $WorkDir $leaf

        Write-Log -Level 'WARN' -Message ("Rules file not found locally. Will download: {0}" -f $leaf)
        Write-Log -Level 'INFO' -Message ("  URL : {0}" -f $dlUrl)
        Write-Log -Level 'INFO' -Message ("  DEST: {0}" -f $dest)

        if ($Proxy) {
            Download-File -Url $dlUrl -OutFile $dest -Proxy $Proxy
        } else {
            Download-File -Url $dlUrl -OutFile $dest
        }

        return (Resolve-Path -LiteralPath $dest).Path
    }

    throw ("Rule file not found: '{0}'. tried current/script/workdir paths. If you want auto-download, omit RuleFileName or use 'd-audit-core.rules' / 's-audit-core.rules'." -f $RuleSource)
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
        # SYSTEM에서 실패하는 케이스는 드물지만, 실패해도 이후 Set-Acl에서 예외로 잡힙니다.
        Write-Log -Level 'WARN' -Message ("Failed to enable SeSecurityPrivilege: {0}" -f $_.Exception.Message)
    }
}

function Is-RegistryPath {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -match '^(HKLM|HKCU|HKCR|HKU|HKCC):\\')
}

function Contains-Wildcards {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -match '[\*\?\[]')
}

function Expand-FileTargets {
    <#
      Expand file-system wildcard patterns into concrete existing paths.
      - Used only for file-system paths (NOT registry).
      - If the pattern contains wildcards and matches nothing, returns empty array and warns once.
    #>
    param([Parameter(Mandatory)][string]$PathPattern)

    $p = Normalize-InputPath -Path $PathPattern

    if (Is-RegistryPath -Path $p) {
        return @($p)
    }

    if (-not (Contains-Wildcards -Path $p)) {
        return @($p)
    }

    $matches = @()
    try {
        $items = Get-Item -Path $p -Force -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($it in $items) {
                if ($null -ne $it.FullName -and -not [string]::IsNullOrWhiteSpace($it.FullName)) {
                    $matches += $it.FullName
                }
            }
        }
    } catch {
        # ignore
    }

    # de-dup (case-insensitive)
    $unique = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $matches) {
        if ($unique.Add($m)) { $out.Add($m) | Out-Null }
    }

    if ($out.Count -eq 0) {
        Write-Log -Level 'WARN' -Message ("Wildcard pattern matched nothing: {0}" -f $p)
        return @()
    }

    return $out.ToArray()
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

    $rf = Resolve-RuleFilePath -RuleFileName $Rulefile
    if (-not (Test-Path -LiteralPath $rf)) {
        throw "Rule file not found: $rf"
    }

    $items = New-Object System.Collections.Generic.List[object]
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]'

    function _read([string]$file) {
        $file = Resolve-RuleFilePath -RuleFileName $file
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

    _read $rf
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

function Parse-FileSystemRights {
    param([Parameter(Mandatory)][string]$Perm)
    $rights = 0
    foreach ($t in ($Perm -split ',')) {
        $tok = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        try {
            $v = [Enum]::Parse([System.Security.AccessControl.FileSystemRights], $tok, $true)
            $rights = $rights -bor [int]$v
        } catch {
            throw "Invalid FileSystemRights token: '$tok'."
        }
    }
    return [System.Security.AccessControl.FileSystemRights]$rights
}

function Apply-FileAuditRule {
    param(
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][string]$Perm
    )

    $t = Normalize-InputPath -Path $TargetPath

    if (Is-RegistryPath -Path $t) {
        throw "file-folder-all-profiles.ps1는 파일/폴더 전용입니다: $t"
    }

    if (-not (Test-Path -LiteralPath $t)) {
        Write-Log -Level 'WARN' -Message ("File/Folder not found: {0}" -f $t)
        return
    }

    $item = Get-Item -LiteralPath $t -ErrorAction Stop
    $isContainer = $item.PSIsContainer

    $rights = Parse-FileSystemRights -Perm $Perm
    $aFlags = Parse-AuditFlags -AuditFlags $AuditFlags
    $acct   = New-Object System.Security.Principal.NTAccount($Account)

    # "이 폴더 및 파일"(서브폴더 제외):
    # - Folder 자체 적용 + Files 상속(ObjectInherit)
    # - Subfolder는 상속되지 않음(ContainerInherit 미사용)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    if ($isContainer) { $inherit = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit }
    $prop = [System.Security.AccessControl.PropagationFlags]::None

    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        $acct, $rights, $inherit, $prop, $aFlags
    )

    $acl = Get-Acl -LiteralPath $t -Audit

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
    Set-Acl -LiteralPath $t -AclObject $acl
}

# ---- Start ----
try {
    # TLS 1.2 (common requirement)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    # Privilege check
    Assert-Privileged

    # Enable SeSecurityPrivilege for SACL operations
    Enable-SeSecurityPrivilege

    # Determine mode
    $rulesMode = $false
    if (-not [string]::IsNullOrWhiteSpace($RuleFileName)) {
        $rulesMode = $true
    } elseif ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Perm)) {
        # RuleFileName이 없고, single target 입력도 없으면 rules 모드로 동작
        $rulesMode = $true
    }

    if ($rulesMode) {
        # Determine OS role
        $osRole = Get-OsRole
        if ($osRole -eq 'UNKNOWN') {
            Write-Log -Level 'ERROR' -Message 'OS Role is UNKNOWN (failed to determine Win32_OperatingSystem.ProductType). Aborting.'
            exit 2
        }

        # Choose workdir + default rules URL
        if ($osRole -eq 'SERVER') {
            $WorkDir = $ServerDir
            $DefaultRulesSource = $ServerRulesUrl
        } else {
            $WorkDir = $DesktopDir
            $DefaultRulesSource = $DesktopRulesUrl
        }

        # Ensure WorkDir exists
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

        # Determine proxy (PLURA registry)
        $proxyRaw = $null
        $proxyUri = $null
        try { $proxyRaw = Get-ProxyFromPluraRegistry } catch { $proxyRaw = $null }

        if (-not [string]::IsNullOrWhiteSpace($proxyRaw)) {
            $proxyUri = Normalize-ProxyUri -Text $proxyRaw
            if ($proxyUri) {
                Write-Log -Level 'INFO' -Message ("Proxy detected (plura_registry): {0}" -f $proxyUri.AbsoluteUri)
            } else {
                Write-Log -Level 'WARN' -Message ("Proxy value exists but is invalid. Value='{0}'. Using direct connection." -f $proxyRaw)
            }
        } else {
            Write-Log -Level 'INFO' -Message "No proxy configured in HKLM\\SOFTWARE\\QubitSecurity\\PLURA (value 'Proxy')."
        }

        # Resolve rules source
        $rulesSource = $null
        if ([string]::IsNullOrWhiteSpace($RuleFileName)) {
            $rulesSource = $DefaultRulesSource
        } else {
            $rulesSource = $RuleFileName.Trim()
        }

        Write-Log -Level 'INFO' -Message ("Rules Source: {0}" -f $rulesSource)

        # Resolve local rules file path (download if needed)
        $RuleFullPath = $null
        try {
            if ($proxyUri) {
                $RuleFullPath = Resolve-RulesFile -RuleSource $rulesSource -WorkDir $WorkDir -Proxy $proxyUri
            } else {
                $RuleFullPath = Resolve-RulesFile -RuleSource $rulesSource -WorkDir $WorkDir
            }
        } catch {
            Write-Log -Level 'ERROR' -Message ("Failed to resolve/download rules file. Message: {0}" -f $_.Exception.Message)
            exit 6
        }

        Write-Log -Level 'INFO' -Message 'Applying File/Folder auditing (SACL)'
        Write-Log -Level 'INFO' -Message ("Rules file      : {0}" -f $RuleFullPath)
        Write-Log -Level 'INFO' -Message ("Action          : {0}" -f $Action)
        Write-Log -Level 'INFO' -Message ("Account         : {0}" -f $Account)
        Write-Log -Level 'INFO' -Message ("AuditFlags      : {0}" -f $AuditFlags)
        Write-Log -Level 'INFO' -Message ("ReplaceExisting : {0}" -f $ReplaceExisting)

        $items = Read-Rules -Rulefile $RuleFullPath

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
        $targetCount = 0

        foreach ($it in $items) {
            $ruleCount++
            $targets = Expand-FileTargets -PathPattern $it.Path
            foreach ($t in $targets) {
                $targetCount++
                Apply-FileAuditRule -TargetPath $t -Perm $it.Perm
            }
        }

        Write-Log -Level 'INFO' -Message ("Completed successfully. Rules={0} TargetsApplied={1}" -f $ruleCount, $targetCount)
        exit 0
    }

    # ---- Single mode ----
    Write-Log -Level 'INFO' -Message 'Applying File/Folder auditing (SACL) - single target'
    Write-Log -Level 'INFO' -Message ("Target Path : {0}" -f $Path)
    Write-Log -Level 'INFO' -Message ("Permissions : {0}" -f $Perm)
    Write-Log -Level 'INFO' -Message ("Account     : {0}" -f $Account)
    Write-Log -Level 'INFO' -Message ("AuditFlags  : {0}" -f $AuditFlags)

    Apply-FileAuditRule -TargetPath $Path -Perm $Perm
    Write-Log -Level 'INFO' -Message 'Completed successfully.'
    exit 0
}
catch {
    $msg = $null
    try { $msg = $_.Exception.Message } catch { $msg = 'Unknown error' }
    Write-Log -Level 'ERROR' -Message $msg
    Write-Error $_
    exit 1
}
