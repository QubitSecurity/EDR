<#
.SYNOPSIS
  Seed decoy files under the real Documents path of the most-recent human user
  and configure auditing so CREATE / RENAME (incl. extension change) / DELETE
  are written to the Security log.

.DESCRIPTION
  - Resolves the user's "Documents" path even when running as SYSTEM/service:
      * Enumerates HKLM\...\ProfileList for user SIDs (skips system/default)
      * Uses LogonUI LastLoggedOnUser hint → SID → Profile
      * If HKU hive not mounted, temporarily loads NTUSER.DAT to HKU\_Temp_<SID>
      * Reads "User Shell Folders\Personal" and expands variables
  - Creates <Documents>\<RootName> (default: Client_Contracts) with subfolders and decoy files.
  - Enables Advanced Audit Policy (File System subcategory) using GUID (locale-independent).
  - Forces subcategory auditing (SCENoApplyLegacyAuditPolicy=1).
  - Applies minimal SACL on root (inherit to new items) and retrofits existing children.
  - Optional self-test prints concise, locale-agnostic 4663 lines via Event XML.
  - PowerShell 5.1 compatible.

.PARAMETERS
  -RootName  : Honeypot root folder name under Documents (default: Client_Contracts)
  -AuditSid  : Target SID for auditing (default: S-1-5-11 = Authenticated Users; use S-1-1-0 for Everyone)
  -SelfTest  : Run quick create→rename(ext)→delete and parse recent 4663 (default: true)

.NOTES
  Must run as Administrator (to load/unload user hives and set policy).
#>

param(
  [string]$RootName = 'Client_Contracts',
  [string]$AuditSid = 'S-1-5-11',
  [switch]$SelfTest = $true
)

# ---------------- Helpers: profile / Documents resolution ----------------

function Get-UserProfilesFromProfileList {
  <# Returns objects: @{ SID; ProfilePath; IsSystemLike } #>
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
  <# Read a hint like "DOMAIN\User" from LogonUI #>
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
  <#
    Resolves a human user's Documents path without relying on an active session.
    Strategy:
      1) Current MyDocuments (if not systemprofile)
      2) LogonUI LastLoggedOnUser → SID → Profile → hive read
      3) Newest plausible C:\Users\<name> → hive read if possible
  #>
  # 1) Current context MyDocuments
  try {
    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    if (![string]::IsNullOrWhiteSpace($myDocs) -and ($myDocs -notmatch '\\systemprofile\\')) {
      return $myDocs
    }
  } catch {}

  $profiles = Get-UserProfilesFromProfileList | Where-Object { -not $_.IsSystemLike -and $_.ProfilePath -like 'C:\Users\*' }

  # 2) Use LogonUI hint if available
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

  # 3) Pick newest directory under C:\Users as a heuristic
  $candidate = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') } |
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 1
  if ($candidate) {
    # Try to map back to SID for hive load
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
  $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) { throw "Please run PowerShell as Administrator." }

# ---------------- Decoy generator ----------------
function New-TextFile {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Content)
  $dir = Split-Path -Parent $Path
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Create-Decoys {
  param([Parameter(Mandatory)][string]$RootPath)
  $folders = @{
    Docs     = Join-Path $RootPath "Docs"
    Images   = Join-Path $RootPath "Images"
    Archives = Join-Path $RootPath "Archives"
    Media    = Join-Path $RootPath "Media"
  }
  $folders.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

  # Office-like
  New-TextFile -Path (Join-Path $folders.Docs "Project_Plan.docx") "Decoy document."
  New-TextFile -Path (Join-Path $folders.Docs "Budget_2025.xlsx")   "Decoy spreadsheet."
  New-TextFile -Path (Join-Path $folders.Docs "Sales_Review.pptx")  "Decoy presentation."
  # PDF
  New-TextFile -Path (Join-Path $folders.Docs "Confidential_Report.pdf") "Decoy PDF."
  # Images
  New-TextFile -Path (Join-Path $folders.Images "diagram.png") "PNG placeholder"
  New-TextFile -Path (Join-Path $folders.Images "photo.jpg")   "JPG placeholder"
  New-TextFile -Path (Join-Path $folders.Images "icon.gif")    "GIF placeholder"
  # Archives
  New-TextFile -Path (Join-Path $folders.Archives "backup.zip") "ZIP placeholder"
  New-TextFile -Path (Join-Path $folders.Archives "dataset.7z") "7Z placeholder"
  New-TextFile -Path (Join-Path $folders.Archives "legacy.rar") "RAR placeholder"
  # Multimedia
  New-TextFile -Path (Join-Path $folders.Media "meeting.mp3") "Audio placeholder"
  New-TextFile -Path (Join-Path $folders.Media "training.mp4") "Video placeholder"
  New-TextFile -Path (Join-Path $folders.Media "promo.avi")    "Video placeholder"
}

# ---------------- Policy helpers ----------------

function Ensure-ForceSubcategory {
  # Make sure Advanced Audit Policy subcategory settings override legacy
  $path='HKLM:\System\CurrentControlSet\Control\Lsa'; $name='SCENoApplyLegacyAuditPolicy'
  $cur = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
  if ($cur -ne 1) {
    New-ItemProperty -Path $path -Name $name -Type DWord -Value 1 -Force | Out-Null
  }
}

function Enable-FileSystemAuditPolicy {
  # File System subcategory GUID (locale-independent)
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  try { & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null } catch {}
}

function Get-RightsForAudit {
  # Minimal rights sufficient to capture rename (including extension change) and delete + folder entry modifications
  $FSR = [System.Security.AccessControl.FileSystemRights]
  $file = [System.Enum]::ToObject($FSR, ([int]$FSR::Delete -bor [int]$FSR::WriteAttributes -bor [int]$FSR::WriteExtendedAttributes))
  $dir  = [System.Enum]::ToObject($FSR, ([int]$FSR::CreateFiles -bor [int]$FSR::AppendData -bor [int]$FSR::CreateDirectories -bor
     [int]$FSR::WriteAttributes -bor [int]$FSR::Delete -bor [int]$FSR::DeleteSubdirectoriesAndFiles))
  [PSCustomObject]@{ FileRights=$file; DirRights=$dir }
}

function Set-RootSacl {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$AuditSid)
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

function Retrofit-ChildrenSacl {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$AuditSid)
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

# ---------------- Locale‑independent Event XML parser (for optional self-test) ----------------

$AccessCodeMap = @{
  '%%4417' = 'WriteData/AddFile'
  '%%4418' = 'AppendData/CreateSubdir'
  '%%4424' = 'WriteAttributes'
  '%%4433' = 'WriteEA'
  '%%1537' = 'DELETE'
}

function Pretty-Accesses {
  param([string]$text)
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  ($text -split '[,\s]+' | Where-Object {$_} | ForEach-Object {
      if ($AccessCodeMap.ContainsKey($_)) { $AccessCodeMap[$_] } else { $_ }
  }) -join ','
}

function Parse-EventXml {
  param($Event)
  $xml = [xml]$Event.ToXml()
  $ed  = $xml.Event.EventData
  $map = @{}
  foreach($n in $ed.Data){ $map[$n.Name] = [string]$n.'#text' }
  [pscustomobject]@{
    EventId   = [int]$xml.Event.System.EventID.'#text'
    Target    = $map['ObjectName']
    Accesses  = $map['AccessList']
    Mask      = $map['AccessMask']
  }
}

function Self-Test {
  param([Parameter(Mandatory)][string]$RootPath)
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

  foreach($e in $events){
    $p = Parse-EventXml $e
    $acc = Pretty-Accesses $p.Accesses
    if ([string]::IsNullOrWhiteSpace($acc)) { $acc = $p.Accesses }
    $line = '{0:u}  4663  {1}  Mask={2}' -f $e.TimeCreated, $acc, $p.Mask
    # Write-Output $line
    # if ($p.Target) { Write-Output ('   -> ' + $p.Target) }
  }
}

# ---------------- Main (seed first, then audit) ----------------

$DocsPath = Resolve-RealDocumentsPath
$Root     = Join-Path $DocsPath $RootName

# 1) Seed folders/files
New-Item -ItemType Directory -Path $Root -Force | Out-Null
Create-Decoys -RootPath $Root

# 2) Audit policy + SACL
Ensure-ForceSubcategory
Enable-FileSystemAuditPolicy
Set-RootSacl          -Path $Root -AuditSid $AuditSid
Retrofit-ChildrenSacl -Path $Root -AuditSid $AuditSid

# 3) Optional self-test
if ($SelfTest) { Self-Test -RootPath $Root }
