<#
.SYNOPSIS
  Seed decoys under the real Documents path (even as SYSTEM) and configure auditing.
  Supports clean removal: policy revert (File System subcategory), SACL removal, decoy cleanup.

.DESCRIPTION
  - Resolves the user's "Documents" folder without needing an interactive session.
  - Seeds <Documents>\Client_Contracts with subfolders/files.
  - Enables Advanced Audit Policy (File System subcategory) via GUID (locale-independent).
  - Forces subcategory auditing (SCENoApplyLegacyAuditPolicy=1) and marks the change (marker key).
  - Applies SACL on root (inherit) and retrofits existing children.
  - Logs actions to Windows Application log (Source: "PLURAHoneypotAudit") via Plura.AppLog.psm1 or fallback.
  - -Remove: disables File System subcategory, removes SACL, deletes decoy root, and restores the
             "Force subcategory" switch ONLY if it was set by this script (marker check).

.PARAMETERS
  -TargetUser : Prefer/force this user (e.g., 'harry' or 'DOMAIN\harry' or 'IIS AppPool\DefaultAppPool')
  -TargetPath : Prefer/force this exact root path (e.g., 'C:\Users\DefaultAppPool\Documents\Client_Contracts')
  -Remove     : Revert policy (File System subcategory disable), remove SACL, delete decoys.
  -SelfTest   : Run create→rename(ext)→delete and parse recent 4663 events (locale-agnostic).
  -Status     : Print a short status summary (root path, SCENoApplyLegacyAuditPolicy, SACL rule count) to console.

.NOTES
  Must run as Administrator. PowerShell 5.1 compatible.
#>

param(
  [string]$TargetUser,
  [string]$TargetPath,
  [switch]$Remove = $false,
  [switch]$SelfTest = $false,
  [switch]$Status = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference  = 'Stop'
$ProgressPreference     = 'SilentlyContinue'

# ---------------- Constants ----------------
$RootName   = 'Client_Contracts'                 # Honeypot root folder name under Documents
$AuditSid   = 'S-1-1-0'                          # Everyone
$EventSrc   = 'PLURAHoneypotAudit'               # Application log source
$MarkerKey  = 'HKLM:\SOFTWARE\PLURAHoneypotAudit'
$MarkerName = 'SetLegacyOverride'                # SCENoApplyLegacyAuditPolicy was set by this script

# ---------------- Event / Module Settings ----------------
$LogName = 'Application'
# Event IDs (58000+)
$EID = @{
  Started     = 58000
  SetupStart  = 58001
  SetupDone   = 58002
  RemoveStart = 58010
  RemoveDone  = 58011
  SelfTest    = 58020
  Skipped     = 58040
  Error       = 58090
}

# ---------------- Logging module (with robust fallback) ----------------
$BaseDir = 'C:\Program Files\PLURA'
$moduleCandidates = @(
  Join-Path $PSScriptRoot 'Plura.AppLog.psm1'
  (Join-Path (Join-Path $BaseDir 'Modules') 'Plura.AppLog.psm1')
) | Where-Object { $_ }

foreach ($m in $moduleCandidates) {
  if (Test-Path $m) { Import-Module $m -Force; break }
}

function Ensure-EventSource {
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSrc)) {
      New-EventLog -LogName $LogName -Source $EventSrc
    }
  } catch {}
}

if (-not (Get-Module -Name 'Plura.AppLog')) {
  # Fallback: minimal logger + ensure source
  Ensure-EventSource
  function Write-AppLog {
    param(
      [string]$Level='Information',
      [string]$Message,
      [int]$EventId=50000,
      [string]$LogName='Application',
      [string]$Source=$EventSrc,
      [hashtable]$Data=$null
    )
    try {
      if ($Data) { try { $Message = "$Message`nDATA=" + ($Data | ConvertTo-Json -Compress -Depth 6) } catch {} }
      Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $Level -Message $Message
    } catch {}
  }
  function Write-AppOp {
    param(
      [string]$Op,[string]$Step,
      [ValidateSet('Started','Succeeded','Failed','Skipped','Progress')] [string]$Status='Progress',
      [string]$Message='', [int]$EventId=50000, [hashtable]$Extra=$null,
      [ValidateSet('Information','Warning','Error')] [string]$Level='Information',
      [string]$LogName='Application', [string]$Source=$EventSrc
    )
    $msg  = if ($Message) { $Message } else { "$Op/$Step $Status" }
    $data = @{ op=$Op; step=$Step; status=$Status; whenUtc=(Get-Date).ToUniversalTime().ToString('s')+'Z'; user=(whoami) }
    if ($Extra) { $data.extra = $Extra }
    Write-AppLog -Level $Level -Message $msg -EventId $EventId -LogName $LogName -Source $Source -Data $data
  }
} else {
  # Use module logger and ensure source via module
  Initialize-AppLog -LogName $LogName -Source $EventSrc
}

# ---------------- Admin check ----------------
function Test-IsAdministrator {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) {
  Write-AppOp -Op 'HoneypotAudit' -Step 'precheck' -Status 'Failed' -EventId $EID.Error -Level 'Error' -LogName $LogName -Source $EventSrc `
    -Extra @{ reason='not_admin' }
  throw "Please run PowerShell as Administrator."
}

# ---------------- Registry safe getter (fix for StrictMode) ----------------
function Get-RegistryValueOrNull {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
  try { return (Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop) } catch { return $null }
}

# ---------------- Resolve real Documents (SYSTEM-safe) ----------------
function Get-UserProfilesFromProfileList {
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  $list = @()
  try {
    Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
      $sid = Split-Path $_.PSChildName -Leaf
      try { $path = (Get-ItemProperty -Path $_.PsPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath } catch { $path = $null }
      $name = if ($path -and $path -match '^C:\\Users\\([^\\]+)') { $Matches[1] } else { '' }
      $isServiceLike =
           ($name -match '^(Default($| )|Default User$|DefaultAccount$|defaultuser0$|Guest$|Public$|All Users$|WDAGUtilityAccount$|IIS_.*|.*AppPool.*|\.NET v.*|.*\$$)$') `
           -or ($path -like 'C:\Users\Default*') `
           -or ($path -like 'C:\Windows\*')
      $isSys = ($sid -like 'S-1-5-18' -or $sid -like 'S-1-5-19' -or $sid -like 'S-1-5-20' -or $isServiceLike)
      $list += [pscustomobject]@{ SID=$sid; ProfilePath=$path; IsSystemLike=$isSys }
    }
  } catch {}
  $list
}
function Get-LastLoggedOnUserName {
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData'
  )
  foreach ($k in $keys) {
    try {
      $p = Get-ItemProperty -Path $k -ErrorAction Stop
      foreach ($n in $p.PSObject.Properties.Name) {
        if ($n -match 'LastLoggedOnUser') {
          $v = [string]($p.$n)
          if ($v) { return $v }
        }
      }
    } catch {}
  }
  return $null
}
function Try-TranslateAccountToSid {
  param([string]$Account)
  try {
    if ([string]::IsNullOrWhiteSpace($Account)) { return $null }
    return (New-Object System.Security.Principal.NTAccount($Account)).
           Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch { return $null }
}
function Mount-UserHive {
  param([string]$Sid,[string]$ProfilePath)
  $ntuser = Join-Path $ProfilePath 'NTUSER.DAT'
  if (-not (Test-Path $ntuser)) { return $null }
  $tempName = "_Temp_$($Sid.Replace('-','_'))"
  $hiveRegPathPS = "Registry::HKEY_USERS\$tempName"
  $loaded = Test-Path $hiveRegPathPS
  if (-not $loaded) {
    try { & reg.exe load "HKU\$tempName" "$ntuser" > $null 2>&1; $loaded = $true } catch { $loaded = $false }
  }
  if ($loaded) { return @{ HiveRootPS=$hiveRegPathPS; Name=$tempName; Loaded=$true } }
  return $null
}
function Resolve-DocumentsViaHive {
  param([string]$HiveRootPS,[string]$ProfilePath)
  $key = Join-Path $HiveRootPS 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
  try {
    $val = Get-ItemPropertyValue -Path $key -Name 'Personal' -ErrorAction Stop   # StrictMode-safe
    if ($val) {
      $expanded = $val -replace '%USERPROFILE%',$ProfilePath
      return [Environment]::ExpandEnvironmentVariables($expanded)
    }
  } catch {}
  return (Join-Path $ProfilePath 'Documents')
}
function Resolve-RealDocumentsPath {
  param([string]$TargetUserParam,[string]$TargetPathParam)

  if ($TargetPathParam) {
    $p = $TargetPathParam
    $dir = Split-Path -Parent $p
    if (-not (Test-Path -LiteralPath $dir)) { throw "TargetPath base does not exist: $dir" }
    return $p
  }

  try {
    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    if ($myDocs -and ($myDocs -notmatch '\\systemprofile\\')) { return (Join-Path $myDocs $RootName) }
  } catch {}

  $profilesAll  = Get-UserProfilesFromProfileList
  $profilesNorm = $profilesAll | Where-Object { -not $_.IsSystemLike -and $_.ProfilePath -like 'C:\Users\*' }

  if ($TargetUserParam) {
    $sid = Try-TranslateAccountToSid $TargetUserParam
    if ($sid) {
      $hit = $profilesAll | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
      if ($hit -and $hit.ProfilePath) {
        $mount = Mount-UserHive -Sid $hit.SID -ProfilePath $hit.ProfilePath
        if ($mount) { try { return (Join-Path (Resolve-DocumentsViaHive $mount.HiveRootPS $hit.ProfilePath) $RootName) } finally { & reg.exe unload "HKU\$($mount.Name)" > $null 2>&1 } }
        else { return (Join-Path (Join-Path $hit.ProfilePath 'Documents') $RootName) }
      }
    }
  }

  $llu = Get-LastLoggedOnUserName
  if ($llu) {
    $sid = Try-TranslateAccountToSid $llu
    if ($sid) {
      $hit = $profilesNorm | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
      if ($hit) {
        $mount = Mount-UserHive -Sid $hit.SID -ProfilePath $hit.ProfilePath
        if ($mount) { try { return (Join-Path (Resolve-DocumentsViaHive $mount.HiveRootPS $hit.ProfilePath) $RootName) } finally { & reg.exe unload "HKU\$($mount.Name)" > $null 2>&1 } }
        else { return (Join-Path (Join-Path $hit.ProfilePath 'Documents') $RootName) }
      }
    }
  }

  $candidate = $profilesNorm | Where-Object { Test-Path $_.ProfilePath } | Sort-Object { (Get-Item $_.ProfilePath).LastWriteTime } -Descending | Select-Object -First 1
  if ($candidate) { return (Join-Path (Join-Path $candidate.ProfilePath 'Documents') $RootName) }

  $dirCandidate = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^(Default($| )|Default User$|DefaultAccount$|defaultuser0$|Guest$|Public$|All Users$|WDAGUtilityAccount$|IIS_.*|.*AppPool.*|\.NET v.*|.*\$$)' } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($dirCandidate) { return (Join-Path (Join-Path $dirCandidate.FullName 'Documents') $RootName) }

  throw "Could not resolve a human user's Documents path."
}

# ---------------- Decoys ----------------
function New-TextFile { param([string]$Path,[string]$Content)
  $dir = Split-Path -Parent $Path
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  if (!(Test-Path $Path)) { $Content | Out-File -FilePath $Path -Encoding UTF8 -Force }  # don't rewrite if exists
}
function Create-Decoys { param([string]$RootPath)
  $folders = @{
    Docs     = Join-Path $RootPath "Docs"
    Images   = Join-Path $RootPath "Images"
    Archives = Join-Path $RootPath "Archives"
    Media    = Join-Path $RootPath "Media"
  }
  $folders.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
  New-TextFile (Join-Path $folders.Docs "Project_Plan.docx") "Decoy document."
  New-TextFile (Join-Path $folders.Docs "Budget_2025.xlsx")  "Decoy spreadsheet."
  New-TextFile (Join-Path $folders.Docs "Sales_Review.pptx") "Decoy presentation."
  New-TextFile (Join-Path $folders.Docs "Confidential_Report.pdf") "Decoy PDF."
  New-TextFile (Join-Path $folders.Images "diagram.png") "PNG placeholder"
  New-TextFile (Join-Path $folders.Images "photo.jpg")   "JPG placeholder"
  New-TextFile (Join-Path $folders.Images "icon.gif")    "GIF placeholder"
  New-TextFile (Join-Path $folders.Archives "backup.zip") "ZIP placeholder"
  New-TextFile (Join-Path $folders.Archives "dataset.7z") "7Z placeholder"
  New-TextFile (Join-Path $folders.Archives "legacy.rar") "RAR placeholder"
  New-TextFile (Join-Path $folders.Media "meeting.mp3") "Audio placeholder"
  New-TextFile (Join-Path $folders.Media "training.mp4") "Video placeholder"
  New-TextFile (Join-Path $folders.Media "promo.avi")    "Video placeholder"
}

# ---------------- Privilege enabling for SACL (fixed Add-Type + variable) ----------------
function Enable-Privilege {
  param([Parameter(Mandatory)][string[]]$Names)

  if (-not $env:TEMP -or -not (Test-Path $env:TEMP)) {
    $env:TEMP = Join-Path $env:WINDIR 'Temp'
    $env:TMP  = $env:TEMP
    try { if (-not (Test-Path $env:TEMP)) { New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null } } catch {}
  }

  $cs = @"
using System;
using System.Runtime.InteropServices;

public static class AdjPriv {
  [StructLayout(LayoutKind.Sequential, Pack=1)]
  public struct LUID { public uint LowPart; public int HighPart; }

  [StructLayout(LayoutKind.Sequential, Pack=1)]
  public struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; }

  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
    ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

  [DllImport("kernel32.dll", ExactSpelling=true)]
  public static extern IntPtr GetCurrentProcess();

  [DllImport("kernel32.dll", ExactSpelling=true)]
  public static extern bool CloseHandle(IntPtr hObject);

  public const int SE_PRIVILEGE_ENABLED = 0x00000002;
  public const int TOKEN_QUERY = 0x0008;
  public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;

  public static bool Enable(string privName) {
    IntPtr h;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out h)) return false;

    LUID luid = new LUID();
    if (!LookupPrivilegeValue(null, privName, ref luid)) { CloseHandle(h); return false; }

    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
    tp.PrivilegeCount = 1;
    tp.Luid = luid;
    tp.Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = AdjustTokenPrivileges(h, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    CloseHandle(h);
    return ok;
  }
}
"@

  if (-not ([System.Management.Automation.PSTypeName]'AdjPriv').Type) {
    Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop | Out-Null
  }

  foreach ($n in $Names) { [void][AdjPriv]::Enable($n) }
}

# ---------------- Policy helpers (Advanced Audit Policy + SACL) ----------------
function Mark-SetLegacyOverride {
  try {
    if (-not (Test-Path $MarkerKey)) { New-Item -Path $MarkerKey -Force | Out-Null }
    New-ItemProperty -Path $MarkerKey -Name $MarkerName -Type DWord -Value 1 -Force | Out-Null
  } catch {}
}
function Test-SetLegacyOverride {
  try { $v = Get-RegistryValueOrNull -Path $MarkerKey -Name $MarkerName; return ($v -eq 1) } catch { return $false }
}
function Clear-SetLegacyOverride { try { if (Test-Path $MarkerKey) { Remove-Item $MarkerKey -Recurse -Force } } catch {} }

function Ensure-ForceSubcategory {
  $path='HKLM:\System\CurrentControlSet\Control\Lsa'
  $cur  = Get-RegistryValueOrNull -Path $path -Name 'SCENoApplyLegacyAuditPolicy'
  if ($cur -ne 1) {
    New-ItemProperty -Path $path -Name SCENoApplyLegacyAuditPolicy -Type DWord -Value 1 -Force | Out-Null
    Mark-SetLegacyOverride
  }
}
function Restore-ForceSubcategoryIfMarked {
  if (Test-SetLegacyOverride) {
    try {
      New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Type DWord -Value 0 -Force | Out-Null
      Clear-SetLegacyOverride
    } catch {}
  }
}
function Enable-FileSystemAuditPolicy {
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  & auditpol.exe /set /subcategory:"$guid" /success:enable /failure:enable | Out-Null
}
function Disable-FileSystemAuditPolicy {
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  & auditpol.exe /set /subcategory:"$guid" /success:disable /failure:disable | Out-Null
}

function Get-RightsForAudit {
  $FSR = [System.Security.AccessControl.FileSystemRights]
  $file = [System.Enum]::ToObject($FSR, ([int]$FSR::Delete -bor [int]$FSR::WriteAttributes -bor [int]$FSR::WriteExtendedAttributes))
  $dir  = [System.Enum]::ToObject($FSR, ([int]$FSR::CreateFiles -bor [int]$FSR::AppendData -bor [int]$FSR::CreateDirectories -bor
     [int]$FSR::WriteAttributes -bor [int]$FSR::Delete -bor [int]$FSR::DeleteSubdirectoriesAndFiles))
  [PSCustomObject]@{ FileRights=$file; DirRights=$dir }
}
function Set-RootSacl {
  param([string]$Path,[string]$AuditSid)
  Enable-Privilege -Names 'SeSecurityPrivilege','SeRestorePrivilege','SeBackupPrivilege'
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  $rights  = Get-RightsForAudit
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $audit   = [System.Security.AccessControl.AuditFlags]::Success -bor `
             [System.Security.AccessControl.AuditFlags]::Failure
  $acl = Get-Acl -LiteralPath $Path
  $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
  $combined = $rights.FileRights -bor $rights.DirRights
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $combined, $inherit, $prop, $audit)
  $acl.AddAuditRule($rule) | Out-Null
  Set-Acl -LiteralPath $Path -AclObject $acl
}
function Remove-RootSacl {
  param([string]$Path,[string]$AuditSid)
  Enable-Privilege -Names 'SeSecurityPrivilege','SeRestorePrivilege','SeBackupPrivilege'
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  try {
    $acl = Get-Acl -LiteralPath $Path
    $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
      Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
    Set-Acl -LiteralPath $Path -AclObject $acl
  } catch {}
}
function Retrofit-ChildrenSacl {
  param([string]$Path,[string]$AuditSid)
  Enable-Privilege -Names 'SeSecurityPrivilege','SeRestorePrivilege','SeBackupPrivilege'
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  $rights = Get-RightsForAudit
  $audit  = [System.Security.AccessControl.AuditFlags]::Success -bor `
            [System.Security.AccessControl.AuditFlags]::Failure
  $inheritNone=[System.Security.AccessControl.InheritanceFlags]::None
  $propNone   =[System.Security.AccessControl.PropagationFlags]::None
  $items = Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
  foreach($it in $items){
    try{
      $acl = Get-Acl -LiteralPath $it.FullName
      $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
      $use = if($it.PSIsContainer){ $rights.DirRights } else { $rights.FileRights }
      $ar  = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $use, $inheritNone, $propNone, $audit)
      $acl.AddAuditRule($ar) | Out-Null
      Set-Acl -LiteralPath $it.FullName -AclObject $acl
    } catch {}
  }
}
function Remove-ChildrenSacl {
  param([string]$Path,[string]$AuditSid)
  Enable-Privilege -Names 'SeSecurityPrivilege','SeRestorePrivilege','SeBackupPrivilege'
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  $items = Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
  foreach($it in $items){
    try{
      $acl = Get-Acl -LiteralPath $it.FullName
      $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
      Set-Acl -LiteralPath $it.FullName -AclObject $acl
    } catch {}
  }
}

# ---------------- Self-test (locale-agnostic 4663 parse) ----------------
$AccessCodeMap = @{
  '%%4417' = 'WriteData/AddFile'
  '%%4418' = 'AppendData/CreateSubdir'
  '%%4424' = 'WriteAttributes'
  '%%4433' = 'WriteEA'
  '%%1537' = 'DELETE'
}
function Pretty-Accesses { param([string]$text) if([string]::IsNullOrWhiteSpace($text)){return $null}; ($text -split '[,\s]+' | ? {$_} | % { if ($AccessCodeMap.ContainsKey($_)) { $AccessCodeMap[$_] } else { $_ } }) -join ',' }
function Parse-EventXml { param($Event) $xml=[xml]$Event.ToXml(); $ed=$xml.Event.EventData; $m=@{}; foreach($d in $ed.Data){$m[$d.Name]=$d.'#text'}; [pscustomobject]@{Target=$m['ObjectName'];Accesses=$m['AccessList'];Mask=$m['AccessMask']} }
function Self-Test {
  param([string]$RootPath)

  $since = Get-Date
  $sub = Join-Path $RootPath 'Docs'
  if (!(Test-Path $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
  $p1 = Join-Path $sub '__audit_test.tmp'
  $p2 = Join-Path $sub '__audit_test.RENAMED.pdf'
  "audit" | Out-File -FilePath $p1 -Encoding UTF8 -Force
  Start-Sleep -Milliseconds 250
  Rename-Item $p1 (Split-Path -Leaf $p2)
  Start-Sleep -Milliseconds 250
  Remove-Item $p2 -Force
  Start-Sleep -Seconds 2

  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$RootPath*" }

  $cnt = 0
  foreach($e in $events){
    $p = Parse-EventXml $e
    $acc = Pretty-Accesses $p.Accesses
    if ([string]::IsNullOrWhiteSpace($acc)) { $acc = $p.Accesses }
    $cnt++
  }

  Write-AppOp -Op 'HoneypotAudit' -Step 'selftest' -Status 'Succeeded' -EventId $EID.SelfTest -LogName $LogName -Source $EventSrc `
    -Extra @{ root=$RootPath; events=$cnt; since=$since.ToUniversalTime().ToString('s')+'Z' }
}

# ---------------- Main ----------------
Write-AppOp -Op 'HoneypotAudit' -Step 'start' -Status 'Started' -EventId $EID.Started -LogName $LogName -Source $EventSrc `
  -Extra @{ user=(whoami); targetUser=$TargetUser; targetPath=$TargetPath }

try {
  $ResolvedRoot = Resolve-RealDocumentsPath -TargetUserParam $TargetUser -TargetPathParam $TargetPath
  $Root         = $ResolvedRoot
  $env:PLURA_HONEYPOT_ROOT = $Root   # export for operator convenience

  if ($Remove) {
    Write-AppOp -Op 'HoneypotAudit' -Step 'remove' -Status 'Started' -EventId $EID.RemoveStart -LogName $LogName -Source $EventSrc `
      -Extra @{ root=$Root }

    Disable-FileSystemAuditPolicy

    if (Test-Path -LiteralPath $Root) {
      Remove-ChildrenSacl -Path $Root -AuditSid $AuditSid
      Remove-RootSacl     -Path $Root -AuditSid $AuditSid
      try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    } else {
      Write-AppOp -Op 'HoneypotAudit' -Step 'remove' -Status 'Skipped' -EventId $EID.Skipped -LogName $LogName -Source $EventSrc `
        -Level 'Warning' -Extra @{ reason='root_not_found'; root=$Root }
    }

    Restore-ForceSubcategoryIfMarked
    Write-AppOp -Op 'HoneypotAudit' -Step 'remove' -Status 'Succeeded' -EventId $EID.RemoveDone -LogName $LogName -Source $EventSrc `
      -Extra @{ message='policy reverted; SACL removed; decoys deleted if present'; root=$Root }

    if ($Status) {
      Enable-Privilege -Names 'SeSecurityPrivilege','SeBackupPrivilege','SeRestorePrivilege'
      $acl   = if (Test-Path $Root) { Get-Acl $Root } else { $null }
      $sid   = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
      $rules = if ($acl) { $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ? { $_.IdentityReference -eq $sid } } else { @() }
      $scVal = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
      Write-Host ("Root={0}`nSCENoApplyLegacyAuditPolicy={1}`nSACL(Rules)={2}" -f $Root, $scVal, ($rules.Count))
    }

    return
  }

  Write-AppOp -Op 'HoneypotAudit' -Step 'setup' -Status 'Started' -EventId $EID.SetupStart -LogName $LogName -Source $EventSrc `
    -Extra @{ root=$Root }

  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Create-Decoys -RootPath $Root

  Ensure-ForceSubcategory
  Enable-FileSystemAuditPolicy

  Set-RootSacl          -Path $Root -AuditSid $AuditSid
  Retrofit-ChildrenSacl -Path $Root -AuditSid $AuditSid

  Write-AppOp -Op 'HoneypotAudit' -Step 'setup' -Status 'Succeeded' -EventId $EID.SetupDone -LogName $LogName -Source $EventSrc `
    -Extra @{ message='SACL applied (root+children); File System audit enabled'; root=$Root }

  if ($SelfTest) { Self-Test -RootPath $Root }

  if ($Status) {
    Enable-Privilege -Names 'SeSecurityPrivilege','SeBackupPrivilege','SeRestorePrivilege'
    $acl   = Get-Acl $Root
    $sid   = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
    $rules = $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ? { $_.IdentityReference -eq $sid }
    $scVal = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue
    Write-Host ("Root={0}`nSCENoApplyLegacyAuditPolicy={1}`nSACL(Rules)={2}" -f $Root, $scVal, ($rules.Count))
  }

} catch {
  Write-AppOp -Op 'HoneypotAudit' -Step 'error' -Status 'Failed' -EventId $EID.Error -LogName $LogName -Source $EventSrc -Level 'Error' `
    -Extra @{ error=$_.Exception.Message; hresult=('{0:X}' -f ($_.Exception.HResult)); stack=$_.ScriptStackTrace }
  throw
}
