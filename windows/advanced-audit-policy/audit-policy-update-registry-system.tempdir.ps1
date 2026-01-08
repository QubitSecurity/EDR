<#
PLURA-Forensic
audit-policy-update-registry-system-keys.v3.ps1  (LOCAL Apply only, Registry SACL - Registry1 (This key only))  v2

- Uses LOCAL rules file (no proxy / no download).
- Robust logging compatible with file-folder-all-profiles.ps1 style.
- Uses provider-qualified registry paths (Registry::HKEY_*) to avoid HKLM: drive issues.
#>

param(
  [Parameter(Mandatory=$false, Position=0)]
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
$ConfirmPreference = 'None'

# ---------------- Event / Module Settings ----------------
$LogName  = 'Application'
$EventSrc = 'PLURARegistryAudit'

# Event IDs (58100+)
$EID = @{
    Started      = 58100
    ApplyStart   = 58120
    ApplyDone    = 58121
    Completed    = 58180
    Error        = 58190
}

$PluraRoot = 'C:\Program Files\PLURA'
$TempDir  = Join-Path $PluraRoot 'temp'
$ServerDir = Join-Path $PluraRoot 'server'
$DeskDir   = Join-Path $PluraRoot 'desktop'
$LogDir    = Join-Path $PluraRoot 'logs'
$LogFile   = Join-Path $LogDir 'audit-policy-update-registry-system-keys.log'

# ---------------- Logging module (with robust fallback) ----------------
$script:PLURA_SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

$moduleCandidates = @(
    (Join-Path $script:PLURA_SCRIPT_DIR 'Plura.AppLog.psm1')
    (Join-Path (Join-Path $PluraRoot 'Modules') 'Plura.AppLog.psm1')
) | Where-Object { $_ }

$script:PluraAppLogLoaded = $false
foreach ($m in $moduleCandidates) {
    if (Test-Path -LiteralPath $m) {
        try {
            Import-Module $m -Force -ErrorAction Stop
            $script:PluraAppLogLoaded = $true
            break
        } catch {
            # ignore
        }
    }
}

function Ensure-EventSource {
    param([string]$Source)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            New-EventLog -LogName $LogName -Source $Source | Out-Null
        }
    } catch {
        # ignore
    }
}

function Write-AppEvent {
    param(
      [int]$Id,
      [ValidateSet('Information','Warning','Error')][string]$Type,
      [string]$Msg
    )
    try {
        Ensure-EventSource -Source $EventSrc
        Write-EventLog -LogName $LogName -Source $EventSrc -EventId $Id -EntryType $Type -Message $Msg
    } catch {
        # ignore
    }
}

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
    [Parameter(Mandatory=$true)][string]$Message,
    [int]$EventId = 0
  )
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = '[{0}] [{1}] {2}' -f $ts, $Level, $Message

  try {
    if (-not (Test-Path -LiteralPath $LogDir)) {
      New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
  } catch { }

  switch ($Level) {
    'INFO'  { if ($EventId -gt 0) { Write-AppEvent -Id $EventId -Type Information -Msg $Message } }
    'WARN'  { if ($EventId -gt 0) { Write-AppEvent -Id $EventId -Type Warning     -Msg $Message } }
    'ERROR' { if ($EventId -gt 0) { Write-AppEvent -Id $EventId -Type Error       -Msg $Message } }
  }
}

# ---------------- Helpers ----------------
function Resolve-RulesFile {
  param([string]$WorkDir, [string]$RuleFileArg, [string]$DefaultLeaf)

  if (-not [string]::IsNullOrWhiteSpace($RuleFileArg)) {
    # If provided and exists (relative or absolute), use it.
    if (Test-Path -LiteralPath $RuleFileArg) {
      try { return (Resolve-Path -LiteralPath $RuleFileArg).Path } catch { return $RuleFileArg }
    }
    # Otherwise, fall back to WorkDir + leaf
    try { $leaf = [System.IO.Path]::GetFileName($RuleFileArg) } catch { $leaf = $RuleFileArg }
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = $DefaultLeaf }
    return (Join-Path $WorkDir $leaf)
  }

  return (Join-Path $WorkDir $DefaultLeaf)
}

function Normalize-RegPath {
  param([string]$PathText)

  $p = ($PathText + '').Trim()
  $p = $p -replace '\\\\', '\'

  if ($p -like 'Registry::*') { return $p }

  if ($p -like 'HKLM:\*') {
    $rest = $p.Substring(6)
    return 'Registry::HKEY_LOCAL_MACHINE\' + $rest
  }
  if ($p -like 'HKCU:\*') {
    $rest = $p.Substring(6)
    return 'Registry::HKEY_CURRENT_USER\' + $rest
  }
  if ($p -like 'HKEY_LOCAL_MACHINE\*') {
    $rest = $p.Substring(19)
    return 'Registry::HKEY_LOCAL_MACHINE\' + $rest
  }
  if ($p -like 'HKEY_CURRENT_USER\*') {
    $rest = $p.Substring(17)
    return 'Registry::HKEY_CURRENT_USER\' + $rest
  }

  return $p
}

function Parse-RegistryRights {
  param([string]$RightsText)
  $parts = ($RightsText -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $acc = [System.Security.AccessControl.RegistryRights]0
  foreach ($part in $parts) {
    try { $acc = $acc -bor ([System.Security.AccessControl.RegistryRights]$part) } catch { }
  }
  if ($acc -eq 0) { $acc = [System.Security.AccessControl.RegistryRights]::ReadKey }
  return $acc
}

function Parse-AuditFlags {
  param([string]$Text)
  $parts = ($Text -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $acc = [System.Security.AccessControl.AuditFlags]0
  foreach ($p in $parts) {
    try { $acc = $acc -bor ([System.Security.AccessControl.AuditFlags]$p) } catch { }
  }
  if ($acc -eq 0) { $acc = [System.Security.AccessControl.AuditFlags]::Success }
  return $acc
}

function Enable-SeSecurityPrivilege {
  $src = @'
using System;
using System.Runtime.InteropServices;

public static class Priv
{
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID { public uint LowPart; public int HighPart; }

  [StructLayout(LayoutKind.Sequential)]
  public struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }

  public const int SE_PRIVILEGE_ENABLED = 0x2;
  public const int TOKEN_ADJUST_PRIVILEGES = 0x20;
  public const int TOKEN_QUERY = 0x8;

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
'@

  if (-not ("Priv" -as [type])) {
    Add-Type -TypeDefinition $src -ErrorAction Stop | Out-Null
  }

  $hTok = [IntPtr]::Zero
  $ok = [Priv]::OpenProcessToken((Get-Process -Id $PID).Handle, [Priv]::TOKEN_ADJUST_PRIVILEGES -bor [Priv]::TOKEN_QUERY, [ref]$hTok)
  if (-not $ok) { return }

  $luid = New-Object Priv+LUID
  $ok2 = [Priv]::LookupPrivilegeValue($null, "SeSecurityPrivilege", [ref]$luid)
  if (-not $ok2) { return }

  $tp = New-Object Priv+TOKEN_PRIVILEGES
  $tp.PrivilegeCount = 1
  $tp.Luid = $luid
  $tp.Attributes = [Priv]::SE_PRIVILEGE_ENABLED

  [void][Priv]::AdjustTokenPrivileges($hTok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
}

# ---------------- Main ----------------
$rulesTotal = 0
$applied = 0
$missing = 0
$skipNonRegistry = 0
$accessDenied = 0
$failed = 0

$osRole = ''
$workDir = ''
$rulesPath = ''

try {
  Write-Host '... START'
  $osRole = 'LOCAL'
  $workDir = $TempDir
  # Ensure temp dir exists
  try { if (-not (Test-Path -LiteralPath $workDir)) { New-Item -ItemType Directory -Path $workDir -Force | Out-Null } } catch { }
  Write-Host ("OS Role : {0}" -f $osRole)
  Write-Host ("WorkDir : {0}" -f $workDir)

  $rulesPath = Resolve-RulesFile -WorkDir $workDir -RuleFileArg $RuleFile -DefaultLeaf 's-audit-registry1.rules'

  Write-Host 'Applying Registry auditing (SACL) - Registry1 (This key only)'
  Write-Host ("Rules file      : {0}" -f $rulesPath)
  Write-Host ("Action          : Apply")
  Write-Host ("Account         : {0}" -f $Account)
  Write-Host ("AuditFlags      : {0}" -f $AuditFlags)
  Write-Host ("ReplaceExisting : {0}" -f $ReplaceExisting)

  Write-Log -Level INFO -Message ("START role={0} workdir={1} rules={2}" -f $osRole, $workDir, $rulesPath) -EventId $EID.Started

  if (-not (Test-Path -LiteralPath $rulesPath)) {
    throw ("Rules file not found: {0}" -f $rulesPath)
  }

  Enable-SeSecurityPrivilege

  $lines = Get-Content -LiteralPath $rulesPath -Encoding UTF8
  $entries = @()
  foreach ($ln in $lines) {
    $t = ($ln + '').Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }

    $parts = $t -split '\|', 4
    if ($parts.Count -lt 3) { $skipNonRegistry++; continue }

    $id = $parts[0].Trim()
    $pathTxt = $parts[1].Trim()
    $permTxt = $parts[2].Trim()
    $note = if ($parts.Count -ge 4) { $parts[3].Trim() } else { '' }

    if ($pathTxt -notmatch '^(HKLM:|HKCU:|HKEY_|Registry::)') {
      $skipNonRegistry++
      continue
    }

    $entries += [pscustomobject]@{ Id=$id; Path=$pathTxt; Perm=$permTxt; Note=$note }
  }

  $rulesTotal = $entries.Count
  Write-Log -Level INFO -Message ("Loaded rules={0}" -f $rulesTotal) -EventId $EID.ApplyStart

  $auditFlagsObj = Parse-AuditFlags -Text $AuditFlags

  $inh = [System.Security.AccessControl.InheritanceFlags]::None
  $prop = [System.Security.AccessControl.PropagationFlags]::None

  foreach ($e in $entries) {
    $provPath = Normalize-RegPath -PathText $e.Path

    if (-not (Test-Path -LiteralPath $provPath)) {
      Write-Host ("Registry key not found: {0}" -f $e.Path)
      $missing++
      continue
    }

    try {
      $acl = Get-Acl -LiteralPath $provPath -Audit

      $rightsObj = Parse-RegistryRights -RightsText $e.Perm
      $rule = New-Object System.Security.AccessControl.RegistryAuditRule($Account, $rightsObj, $inh, $prop, $auditFlagsObj)

      if ($ReplaceExisting) { $acl.SetAuditRule($rule) } else { $acl.AddAuditRule($rule) }

      Set-Acl -LiteralPath $provPath -AclObject $acl -Confirm:$false

      $applied++
    } catch [System.UnauthorizedAccessException] {
      Write-Host ("Access denied applying rule '{0}' key '{1}' : {2}" -f $e.Id, $e.Path, $_.Exception.Message)
      $accessDenied++
    } catch {
      Write-Host ("Failed applying rule '{0}' key '{1}' : {2}" -f $e.Id, $e.Path, $_.Exception.Message)
      $failed++
    }
  }

  Write-Log -Level INFO -Message ("DONE rules={0} applied={1} missing={2} accessDenied={3} failed={4}" -f $rulesTotal, $applied, $missing, $accessDenied, $failed) -EventId $EID.ApplyDone

} catch {
  $msg = $_.Exception.Message
  Write-Host ("Unhandled error: {0}" -f $msg)
  Write-Log -Level ERROR -Message $msg -EventId $EID.Error
} finally {
  Write-Host ("Completed. Rules={0} Applied={1} Missing={2} SkipNonRegistry={3} AccessDenied={4} Failed={5}" -f $rulesTotal, $applied, $missing, $skipNonRegistry, $accessDenied, $failed)
  Write-Host ("Log file : {0}" -f $LogFile)
  Write-Log -Level INFO -Message ("COMPLETED rules={0} applied={1} missing={2} skip={3} accessDenied={4} failed={5}" -f $rulesTotal, $applied, $missing, $skipNonRegistry, $accessDenied, $failed) -EventId $EID.Completed
  Write-Host '... END'
}