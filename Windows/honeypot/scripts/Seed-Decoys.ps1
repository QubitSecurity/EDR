<#
.SYNOPSIS
  Create honeypot folder tree and decoy files (NO audit changes).

.DESCRIPTION
  - Resolves the real "Documents" of the most-recent human user even when running as SYSTEM/service:
      * Enumerates HKLM\...\ProfileList for user SIDs (skips system/default)
      * Tries LogonUI hint; otherwise picks plausible profile (C:\Users\..., newest)
      * If the user's HKU hive isn't mounted, temporarily loads NTUSER.DAT to HKU\_Temp_<SID>
      * Reads "User Shell Folders\Personal", expands %USERPROFILE% and env vars
  - Creates <ResolvedDocuments>\Client_Contracts with subfolders and decoy files.
  - Uses Registry::HKEY_USERS provider paths (no HKU: drive required).
  - PowerShell 5.1 compatible.

.NOTES
  Must run as Administrator (to load/unload user hives).
#>

param()  # no options

# ---------------- Helpers ----------------

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
      3) Newest plausible C:\Users\<name> → (map to SID if possible) → hive read
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

function New-TextFile {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Content)
  $dir = Split-Path -Parent $Path
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

# ---------------- Main ----------------

$DocsPath = Resolve-RealDocumentsPath
$HoneypotRoot = Join-Path $DocsPath 'Client_Contracts'

# Write-Host "[*] Creating honeypot folder tree: $HoneypotRoot" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $HoneypotRoot -Force | Out-Null

$folders = @{
  Docs     = Join-Path $HoneypotRoot "Docs"
  Images   = Join-Path $HoneypotRoot "Images"
  Archives = Join-Path $HoneypotRoot "Archives"
  Media    = Join-Path $HoneypotRoot "Media"
}
$folders.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

# Write-Host "[*] Creating decoy files..." -ForegroundColor Cyan
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

# Write-Host "`n[+] Decoy files ready." -ForegroundColor Green
# Write-Host "    Path: $HoneypotRoot"
