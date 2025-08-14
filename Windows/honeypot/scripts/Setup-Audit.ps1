<#
.SYNOPSIS
  Apply auditing so CREATE / RENAME (incl. extension change) / DELETE under
  <InteractiveUser>\Documents\Client_Contracts are written to the Security log.

.DESCRIPTION
  - Resolves the real "Documents" of the most-recent human user even when running as SYSTEM/service:
      * Enumerates ProfileList (skips system/default)
      * Tries LogonUI LastLoggedOnUser; else newest plausible C:\Users\<name>
      * If HKU hive not mounted, loads NTUSER.DAT to HKU\_Temp_<SID> temporarily
      * Reads "User Shell Folders\Personal" and expands env vars
  - Enables Advanced Audit Policy → Object Access → File System (Success/Failure) using GUID
  - Forces subcategory auditing (SCENoApplyLegacyAuditPolicy=1)
  - Applies minimal SACL on root (inherit to new items) and retrofits to existing children
  - Optional self-test prints concise, locale-agnostic 4663 lines via Event XML

.NOTES
  Run as Administrator.
  PowerShell 5.1 compatible.
#>

param(
  [switch]$SelfTest = $true
)

# ---------------- User Documents Resolver (same core as Seed-Decoys) ----------------

function Get-UserProfilesFromProfileList {
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
  $list = @()
  try {
    Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
      $sid = Split-Path $_.PSChildName -Leaf
      try { $path = (Get-ItemProperty -Path $_.PsPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath }
      catch { $path = $null }
      $isSys = ($sid -like 'S-1-5-18' -or $sid -like 'S-1-5-19' -or $sid -like 'S-1-5-20' -or
                ($path -like 'C:\Users\Default*') -or ($path -like 'C:\Windows\*'))
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
  param([string]$Account)  # "DOMAIN\User" or "MACHINE\User"
  try {
    if ([string]::IsNullOrWhiteSpace($Account)) { return $null }
    return (New-Object System.Security.Principal.NTAccount($Account)).
           Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch { return $null }
}

function Mount-UserHive {
  param([Parameter(Mandatory)][string]$Sid,[Parameter(Mandatory)][string]$ProfilePath)
  # Returns: @{ HiveRootPS='Registry::HKEY_USERS\_Temp_<SID>'; Name='_Temp_<SID>'; Loaded=$true/$false }
  $ntuser = Join-Path $ProfilePath 'NTUSER.DAT'
  if (-not (Test-Path $ntuser)) { return $null }
  $tempName = "_Temp_$($Sid.Replace('-','_'))"
  $hiveRegPathPS = "Registry::HKEY_USERS\$tempName"

  $loaded = Test-Path $hiveRegPathPS
  if (-not $loaded) {
    try {
      & reg.exe load "HKU\$tempName" "$ntuser" > $null 2>&1
      $loaded = $true
    } catch { $loaded = $false }
  }

  if ($loaded) {
    return @{ HiveRootPS=$hiveRegPathPS; Name=$tempName; Loaded=$true }
  }
  return $null
}

function Resolve-DocumentsViaHive {
  param([Parameter(Mandatory)][string]$HiveRootPS,[Parameter(Mandatory)][string]$ProfilePath)
  $key = Join-Path $HiveRootPS 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
  try {
    $val = (Get-ItemProperty -Path $key -Name Personal -ErrorAction Stop).Personal
    if ($val) {
      $expanded = $val -replace '%USERPROFILE%',$ProfilePath
      $expanded = [Environment]::ExpandEnvironmentVariables($expanded)
      return $expanded
    }
  } catch {}
  return (Join-Path $ProfilePath 'Documents')
}

function Resolve-RealDocumentsPath {
  # 1) Current context MyDocuments
  try {
    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    if (![string]::IsNullOrWhiteSpace($myDocs) -and ($myDocs -notmatch '\\systemprofile\\')) {
      return $myDocs
    }
  } catch {}

  $profiles = Get-UserProfilesFromProfileList | Where-Object { -not $_.IsSystemLike -and $_.ProfilePath -like 'C:\Users\*' }

  # 2) LogonUI hint
  $llu = Get-LastLoggedOnUserName
  if ($llu) {
    $sid = Try-TranslateAccountToSid $llu
    if ($sid) {
      $hit = $profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
      if ($hit) {
        $mount = Mount-UserHive -Sid $hit.SID -ProfilePath $hit.ProfilePath
        if ($mount -and $mount.Loaded) {
          try { return Resolve-DocumentsViaHive -HiveRootPS $mount.HiveRootPS -ProfilePath $hit.ProfilePath }
          finally { try { & reg.exe unload "HKU\$($mount.Name)" > $null 2>&1 } catch {} }
        } else {
          return (Join-Path $hit.ProfilePath 'Documents')
        }
      }
    }
  }

  # 3) Newest folder in C:\Users
  $candidate = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') } |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 1
  if ($candidate) {
    $hit = $profiles | Where-Object { $_.ProfilePath -ieq $candidate.FullName } | Select-Object -First 1
    if ($hit) {
      $mount = Mount-UserHive -Sid $hit.SID -ProfilePath $hit.ProfilePath
      if ($mount -and $mount.Loaded) {
        try { return Resolve-DocumentsViaHive -HiveRootPS $mount.HiveRootPS -ProfilePath $hit.ProfilePath }
        finally { try { & reg.exe unload "HKU\$($mount.Name)" > $null 2>&1 } catch {} }
      } else {
        return (Join-Path $hit.ProfilePath 'Documents')
      }
    } else {
      return (Join-Path $candidate.FullName 'Documents')
    }
  }

  throw "Could not resolve a human user's Documents path. No suitable profile was found."
}

# ---------------- Admin check ----------------
function Test-IsAdministrator {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) { throw "Please run PowerShell as Administrator." }

# ---------------- Policy helpers ----------------

function Ensure-ForceSubcategory {
  # SCENoApplyLegacyAuditPolicy = 1  (Force audit policy subcategory settings)
  Write-Host "[*] Ensuring 'Force subcategory settings' is enabled..." -ForegroundColor Cyan
  $path='HKLM:\System\CurrentControlSet\Control\Lsa'; $name='SCENoApplyLegacyAuditPolicy'
  $cur = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
  if ($cur -ne 1) {
    New-ItemProperty -Path $path -Name $name -Type DWord -Value 1 -Force | Out-Null
    Write-Host "[*] Set $name = 1" -ForegroundColor Green
  } else {
    Write-Host "[*] Already enabled." -ForegroundColor Yellow
  }
}

function Enable-FileSystemAuditPolicy {
  # Locale‑independent: use the well‑known GUID for "File System"
  # GUID: {0CCE921D-69AE-11D9-BED3-505054503030}
  Write-Host "[*] Enabling Advanced Audit Policy (File System via GUID)..." -ForegroundColor Cyan
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  try {
    & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null
  } catch {
    Write-Warning "auditpol /set failed. If a domain GPO enforces audit policy, local changes may be blocked."
  }
}

# Minimal rights for rename/delete and create/file adds
function Get-RightsForAudit {
  $FSR = [System.Security.AccessControl.FileSystemRights]
  $file = [System.Enum]::ToObject($FSR,
    ([int]$FSR::Delete -bor [int]$FSR::WriteAttributes -bor [int]$FSR::WriteExtendedAttributes))
  $dir  = [System.Enum]::ToObject($FSR,
    ([int]$FSR::CreateFiles -bor [int]$FSR::AppendData -bor [int]$FSR::CreateDirectories -bor
     [int]$FSR::WriteAttributes -bor [int]$FSR::Delete -bor [int]$FSR::DeleteSubdirectoriesAndFiles))
  [PSCustomObject]@{ FileRights=$file; DirRights=$dir }
}

function Set-RootSacl {
  param([Parameter(Mandatory)][string]$Path,[string]$AuditSid='S-1-5-11') # Authenticated Users
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  $rights  = Get-RightsForAudit
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $audit   = [System.Security.AccessControl.AuditFlags]::Success -bor `
             [System.Security.AccessControl.AuditFlags]::Failure
  $acl = Get-Acl -LiteralPath $Path
  # remove old rules for same SID to avoid duplicates
  $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
  $combined = $rights.FileRights -bor $rights.DirRights
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $combined, $inherit, $prop, $audit)
  $acl.AddAuditRule($rule) | Out-Null
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Retrofit-ChildrenSacl {
  param([Parameter(Mandatory)][string]$Path,[string]$AuditSid='S-1-5-11')
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
    } catch { Write-Verbose "SACL set failed: $($it.FullName) -> $($_.Exception.Message)" }
  }
}

# ---------------- Locale‑independent Event XML parser (for self-test) ----------------

# Small map for common %% access codes → readable labels
$AccessCodeMap = @{
  '%%4417' = 'WriteData/AddFile'
  '%%4418' = 'AppendData/CreateSubdir'
  '%%4424' = 'WriteAttributes'
  '%%4433' = 'WriteEA'
  '%%1537' = 'DELETE'
}

function Pretty-Accesses($text) {
  if (-not $text) { return $null }
  ($text -split '[,\s]+' | Where-Object {$_} | ForEach-Object {
      if ($AccessCodeMap.ContainsKey($_)) { $AccessCodeMap[$_] } else { $_ }
  }) -join ','
}

function Parse-EventXml {
  param([Parameter(Mandatory)]$Event)
  $xml = [xml]$Event.ToXml()
  $ed  = $xml.Event.EventData
  $map = @{}
  foreach($n in $ed.Data){ $map[$n.Name] = [string]$n.'#text' }
  [pscustomobject]@{
    EventId   = [int]$xml.Event.System.EventID.'#text'
    Target    = $map['ObjectName']
    Accesses  = $map['AccessList']
    Mask      = $map['AccessMask']
    Process   = $map['ProcessName']
    Subject   = $map['SubjectUserName']
    RawMap    = $map
  }
}

function Self-Test {
  param([Parameter(Mandatory)][string]$RootPath)
  Write-Host "[*] Self-test: create -> rename(extension) -> delete..." -ForegroundColor Cyan
  $since = Get-Date
  $sub = Join-Path $RootPath 'Docs'
  if(!(Test-Path $sub)){ New-Item -ItemType Directory -Path $sub -Force | Out-Null }
  $p1 = Join-Path $sub '__audit_test.tmp'
  $p2 = Join-Path $sub '__audit_test.RENAMED.pdf'
  "audit" | Out-File -FilePath $p1 -Encoding UTF8 -Force
  Start-Sleep -Milliseconds 150
  Rename-Item $p1 (Split-Path -Leaf $p2)
  Start-Sleep -Milliseconds 150
  Remove-Item $p2 -Force
  Start-Sleep -Seconds 1
  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$RootPath*" }
  if($events){
    Write-Host "[+] Found $($events.Count) 4663 event(s) since $since" -ForegroundColor Green
    foreach($e in $events){
      $p = Parse-EventXml $e
      $acc = Pretty-Accesses $p.Accesses
      if (-not $acc) { $acc = $p.Accesses }
      ('{0:u}  4663  {1}  Mask={2}' -f $e.TimeCreated, $acc, $p.Mask) | Write-Host
      if($p.Target){ ('   -> ' + $p.Target) | Write-Host }
    }
  } else { Write-Warning "No 4663 events found—check policy/SACL." }
}

# ---------------- Main ----------------

# 0) Resolve the real Documents, then set target root
$DocsPath = Resolve-RealDocumentsPath
$Root = Join-Path $DocsPath 'Client_Contracts'

Write-Host "[*] Target root: $Root" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $Root -Force | Out-Null

# 1) Policy prerequisites
Ensure-ForceSubcategory
Enable-FileSystemAuditPolicy

# 2) SACL on root (inherit to new items)
Set-RootSacl -Path $Root -AuditSid 'S-1-5-11'   # Authenticated Users (use S-1-1-0 for Everyone if desired)
Write-Host "[*] SACL applied to root (will inherit to new items)" -ForegroundColor Green

# 3) Retrofit to existing children (for immediate rename/delete capture)
Write-Host "[*] Retrofitting SACL to existing children..." -ForegroundColor Cyan
Retrofit-ChildrenSacl -Path $Root -AuditSid 'S-1-5-11'
Write-Host "[*] Retrofit complete." -ForegroundColor Green

# 4) (Optional) quick self-test
if ($SelfTest) { Self-Test -RootPath $Root }

Write-Host "`n[+] Audit ready for CREATE / RENAME / DELETE." -ForegroundColor Green
Write-Host "    Path: $Root"
Write-Host "    Tip: verify via:  auditpol /get /subcategory:`"{0CCE921D-69AE-11D9-BED3-505054503030}`""
