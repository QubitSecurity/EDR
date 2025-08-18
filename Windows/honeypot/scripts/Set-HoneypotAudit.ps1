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
  - Logs actions to Windows Application log (Source: "HoneypotAudit").
  - -Remove: disables File System subcategory, removes SACL, deletes decoy root, and restores the
             "Force subcategory" switch ONLY if it was set by this script (marker check).

.PARAMETERS
  -Remove   : Revert policy (File System subcategory disable), remove SACL, delete decoys.
  -SelfTest : Run create→rename(ext)→delete and parse recent 4663 events (locale-agnostic).

.NOTES
  Must run as Administrator. PowerShell 5.1 compatible.
#>

param(
  [switch]$Remove = $false,
  [switch]$SelfTest = $false
)

# ---------------- Constants ----------------
$RootName   = 'Client_Contracts'            # Honeypot root folder name under Documents
$AuditSid   = 'S-1-1-0'                     # Everyone
$EventSrc   = 'HoneypotAudit'               # Application log source
$MarkerKey  = 'HKLM:\SOFTWARE\HoneypotAudit'
$MarkerName = 'SetLegacyOverride'           # SCENoApplyLegacyAuditPolicy was set by this script

# ---------------- Logging ----------------
### PLURA-Forensic
function Ensure-EventSource {
  try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSrc)) {
      New-EventLog -LogName Application -Source $EventSrc
    }
  } catch {}
}

### PLURA-Forensic
function Write-AppLog {
  param(
    [string]$Message,
    [ValidateSet('Information','Warning','Error')] [string]$EntryType = 'Information',
    [int]$EventId = 1000
  )
  try { Write-EventLog -LogName Application -Source $EventSrc -EntryType $EntryType -EventId $EventId -Message $Message } catch {}
}

# ---------------- Admin check ----------------
### PLURA-Forensic
function Test-IsAdministrator {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) { throw "Please run PowerShell as Administrator." }
Ensure-EventSource

# ---------------- Resolve real Documents (SYSTEM-safe) ----------------
### PLURA-Forensic
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

### PLURA-Forensic
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

### PLURA-Forensic
function Try-TranslateAccountToSid {
  param([string]$Account)
  try {
    if ([string]::IsNullOrWhiteSpace($Account)) { return $null }
    return (New-Object System.Security.Principal.NTAccount($Account)).
           Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch { return $null }
}

### PLURA-Forensic
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

### PLURA-Forensic
function Resolve-DocumentsViaHive {
  param([string]$HiveRootPS,[string]$ProfilePath)
  $key = Join-Path $HiveRootPS 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
  try {
    $val = (Get-ItemProperty -Path $key -Name Personal -ErrorAction Stop).Personal
    if ($val) {
      $expanded = $val -replace '%USERPROFILE%',$ProfilePath
      return [Environment]::ExpandEnvironmentVariables($expanded)
    }
  } catch {}
  return (Join-Path $ProfilePath 'Documents')
}

### PLURA-Forensic
function Resolve-RealDocumentsPath {
  try {
    $myDocs = [Environment]::GetFolderPath('MyDocuments')
    if ($myDocs -and ($myDocs -notmatch '\\systemprofile\\')) { return $myDocs }
  } catch {}
  $profiles = Get-UserProfilesFromProfileList | Where-Object { -not $_.IsSystemLike -and $_.ProfilePath -like 'C:\Users\*' }
  $llu = Get-LastLoggedOnUserName
  if ($llu) {
    $sid = Try-TranslateAccountToSid $llu
    if ($sid) {
      $hit = $profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
      if ($hit) {
        $mount = Mount-UserHive -Sid $hit.SID -ProfilePath $hit.ProfilePath
        if ($mount) { try { return Resolve-DocumentsViaHive $mount.HiveRootPS $hit.ProfilePath }
                      finally { & reg.exe unload "HKU\$($mount.Name)" > $null 2>&1 } }
        else { return (Join-Path $hit.ProfilePath 'Documents') }
      }
    }
  }
  $candidate = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notin @('Default','Default User','Public','All Users') } |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($candidate) { return (Join-Path $candidate.FullName 'Documents') }
  throw "Could not resolve a human user's Documents path."
}

# ---------------- Decoys ----------------
### PLURA-Forensic
function New-TextFile {
  param([string]$Path,[string]$Content)
  $dir = Split-Path -Parent $Path
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

### PLURA-Forensic
function Create-Decoys {
  param([string]$RootPath)
  $folders = @{
    Docs     = Join-Path $RootPath "Docs"
    Images   = Join-Path $RootPath "Images"
    Archives = Join-Path $RootPath "Archives"
    Media    = Join-Path $RootPath "Media"
  }
  $folders.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
  # Office-like
  New-TextFile (Join-Path $folders.Docs "Project_Plan.docx") "Decoy document."
  New-TextFile (Join-Path $folders.Docs "Budget_2025.xlsx")  "Decoy spreadsheet."
  New-TextFile (Join-Path $folders.Docs "Sales_Review.pptx") "Decoy presentation."
  New-TextFile (Join-Path $folders.Docs "Confidential_Report.pdf") "Decoy PDF."
  # Images
  New-TextFile (Join-Path $folders.Images "diagram.png") "PNG placeholder"
  New-TextFile (Join-Path $folders.Images "photo.jpg")   "JPG placeholder"
  New-TextFile (Join-Path $folders.Images "icon.gif")    "GIF placeholder"
  # Archives
  New-TextFile (Join-Path $folders.Archives "backup.zip") "ZIP placeholder"
  New-TextFile (Join-Path $folders.Archives "dataset.7z") "7Z placeholder"
  New-TextFile (Join-Path $folders.Archives "legacy.rar") "RAR placeholder"
  # Media
  New-TextFile (Join-Path $folders.Media "meeting.mp3") "Audio placeholder"
  New-TextFile (Join-Path $folders.Media "training.mp4") "Video placeholder"
  New-TextFile (Join-Path $folders.Media "promo.avi")    "Video placeholder"
}

# ---------------- Policy helpers ----------------
### PLURA-Forensic
function Mark-SetLegacyOverride {
  try {
    if (-not (Test-Path $MarkerKey)) { New-Item -Path $MarkerKey -Force | Out-Null }
    New-ItemProperty -Path $MarkerKey -Name $MarkerName -Type DWord -Value 1 -Force | Out-Null
  } catch {}
}
function Test-SetLegacyOverride { try { ((Get-ItemProperty -Path $MarkerKey -Name $MarkerName -ErrorAction SilentlyContinue).$MarkerName -eq 1) } catch { $false } }
function Clear-SetLegacyOverride { try { if (Test-Path $MarkerKey) { Remove-Item $MarkerKey -Recurse -Force } } catch {} }

### PLURA-Forensic
function Ensure-ForceSubcategory {
  $path='HKLM:\System\CurrentControlSet\Control\Lsa'
  $cur = (Get-ItemProperty -Path $path -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
  if ($cur -ne 1) {
    New-ItemProperty -Path $path -Name SCENoApplyLegacyAuditPolicy -Type DWord -Value 1 -Force | Out-Null
    Mark-SetLegacyOverride
  }
}

### PLURA-Forensic
function Restore-ForceSubcategoryIfMarked {
  if (Test-SetLegacyOverride) {
    try {
      New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Type DWord -Value 0 -Force | Out-Null
      Clear-SetLegacyOverride
    } catch {}
  }
}

### PLURA-Forensic
function Enable-FileSystemAuditPolicy {
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  & auditpol.exe /set /subcategory:$guid /success:enable /failure:enable | Out-Null
}

### PLURA-Forensic
function Disable-FileSystemAuditPolicy {
  $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
  & auditpol.exe /set /subcategory:$guid /success:disable /failure:disable | Out-Null
}

### PLURA-Forensic
function Get-RightsForAudit {
  # Minimal rights to capture rename/extension change + delete + directory entry modifications
  $FSR = [System.Security.AccessControl.FileSystemRights]
  $file = [System.Enum]::ToObject($FSR, ([int]$FSR::Delete -bor [int]$FSR::WriteAttributes -bor [int]$FSR::WriteExtendedAttributes))
  $dir  = [System.Enum]::ToObject($FSR, ([int]$FSR::CreateFiles -bor [int]$FSR::AppendData -bor [int]$FSR::CreateDirectories -bor
     [int]$FSR::WriteAttributes -bor [int]$FSR::Delete -bor [int]$FSR::DeleteSubdirectoriesAndFiles))
  [PSCustomObject]@{ FileRights=$file; DirRights=$dir }
}

### PLURA-Forensic
function Set-RootSacl {
  param([string]$Path,[string]$AuditSid)
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

### PLURA-Forensic
function Remove-RootSacl {
  param([string]$Path,[string]$AuditSid)
  $sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
  try {
    $acl = Get-Acl -LiteralPath $Path
    $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
      Where-Object { $_.IdentityReference -eq $sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
    Set-Acl -LiteralPath $Path -AclObject $acl
  } catch {}
}

### PLURA-Forensic
function Retrofit-ChildrenSacl {
  param([string]$Path,[string]$AuditSid)
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

### PLURA-Forensic
function Remove-ChildrenSacl {
  param([string]$Path,[string]$AuditSid)
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
  Start-Sleep -Milliseconds 150
  Rename-Item $p1 (Split-Path -Leaf $p2)
  Start-Sleep -Milliseconds 150
  Remove-Item $p2 -Force
  Start-Sleep -Seconds 1

  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$RootPath*" }
  $cnt = 0
  foreach($e in $events){
    $p = Parse-EventXml $e
    $acc = Pretty-Accesses $p.Accesses
    if ([string]::IsNullOrWhiteSpace($acc)) { $acc = $p.Accesses }
    $cnt++
    # 필요하다면 아래 라인을 주석 해제하여 Application 로그에도 요약을 남길 수 있습니다.
    # Write-AppLog -Message ("{0:u} 4663 {1} {2}" -f $e.TimeCreated,$acc,$p.Mask) -EventId 1012
  }
  Write-AppLog -Message ("SelfTest complete: {0} events since {1}" -f $cnt, $since) -EventId 1011
}

# ---------------- Main ----------------
### PLURA-Forensic
try {
  $DocsPath = Resolve-RealDocumentsPath
  $Root     = Join-Path $DocsPath $RootName

  if ($Remove) {
    Write-AppLog -Message "Removal start: root=$Root" -EventId 2000
    Disable-FileSystemAuditPolicy
    Remove-ChildrenSacl -Path $Root -AuditSid $AuditSid
    Remove-RootSacl     -Path $Root -AuditSid $AuditSid
    if (Test-Path $Root) { try { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
    Restore-ForceSubcategoryIfMarked
    Write-AppLog -Message "Removal done: policy reverted (File System disabled), SACL removed, decoys deleted." -EventId 2001
    return
  }

  # Setup / Apply
  Write-AppLog -Message "Setup start: root=$Root" -EventId 1000
  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Create-Decoys -RootPath $Root

  Ensure-ForceSubcategory
  Enable-FileSystemAuditPolicy

  Set-RootSacl          -Path $Root -AuditSid $AuditSid
  Retrofit-ChildrenSacl -Path $Root -AuditSid $AuditSid

  Write-AppLog -Message "Setup done: SACL applied to $Root (and children); File System audit enabled." -EventId 1001

  if ($SelfTest) { Self-Test -RootPath $Root }

} catch {
  Write-AppLog -Message ("Error: " + $_.Exception.Message) -EntryType Error -EventId 9999
  throw
}
