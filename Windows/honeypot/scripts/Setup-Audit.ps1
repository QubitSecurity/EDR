<# 
.SYNOPSIS
  Configure auditing so CREATE, RENAME (incl. extension change), and DELETE
  under the target path are written to the Security log — locale‑independent.

.DESCRIPTION
  - Target path default: C:\Users\analyst\Documents\Client_Contracts
  - Enables Advanced Audit Policy → Object Access → File System (Success/Failure).
    * ASCII-only auto-detect to avoid encoding issues; or pass -SubcategoryName explicitly.
  - Applies SACL on the root (inherit to new items).
  - Retrofits SACL to existing children via .NET (no icacls/localization problems).
  - SACL rights (minimal but sufficient):
      FILES      : Delete, WriteAttributes, WriteExtendedAttributes
      DIRECTORIES: CreateFiles(AddFile), AppendData, CreateDirectories,
                   WriteAttributes, Delete, DeleteSubdirectoriesAndFiles(DeleteChild)
  - Self-test creates → renames(extension) → deletes a file and prints 4663 summaries
    using XML fields (ObjectName/AccessList/AccessMask) so it is language-agnostic.

.NOTES
  Run PowerShell as Administrator.
#>

param(
  [string]$Root = 'C:\Users\analyst\Documents\Client_Contracts',
  [string]$AuditSid = 'S-1-5-11',     # Authenticated Users (use 'S-1-1-0' for Everyone)
  [string]$SubcategoryName,           # Optional exact localized name; e.g., "파일 시스템"
  [switch]$RetrofitExisting = $true,
  [switch]$SelfTest = $true
)

# ---------- Guards ----------
function Test-IsAdministrator {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdministrator)) { throw "Please run PowerShell as Administrator." }

# ---------- Enable Advanced Audit Policy (ASCII-only, locale-safe) ----------
function Enable-FileSystemAuditPolicy {
  <#
    Enables Advanced Audit Policy → Object Access → File System (Success/Failure).
    Strategy:
      1) If -SubcategoryName provided, use it.
      2) Else try literal "File System".
      3) Else best-effort detection via regex /file.*system/ on auditpol listing.
  #>
  Write-Host "[*] Enabling Advanced Audit Policy (File System)..." -ForegroundColor Cyan

  if ([string]::IsNullOrWhiteSpace($SubcategoryName)) {
    $SubcategoryName = 'File System'
    $list = & auditpol.exe /list /subcategory:* 2>$null

    if ($list -notmatch '(?im)^\s*File System\s*$') {
      $guess = $list | Where-Object { $_ -match '(?i)file\s*.*\s*system' } | Select-Object -First 1
      if ($guess) { $SubcategoryName = $guess.Trim() }
    }
  }

  try {
    & auditpol.exe /set /subcategory:"$SubcategoryName" /success:enable /failure:enable | Out-Null
  } catch {
    Write-Warning "Could not set audit policy for subcategory: $SubcategoryName"
    Write-Warning "Run 'auditpol /list /subcategory:*' and supply -SubcategoryName with the exact label."
  }
}

# ---------- Rights & SACL helpers ----------
function Get-RightsForAudit {
  # Minimal but sufficient rights for create / rename / delete auditing.
  $FSR = [System.Security.AccessControl.FileSystemRights]
  $file = [System.Enum]::ToObject($FSR,
    ([int]$FSR::Delete -bor [int]$FSR::WriteAttributes -bor [int]$FSR::WriteExtendedAttributes))
  $dir  = [System.Enum]::ToObject($FSR,
    ([int]$FSR::CreateFiles -bor [int]$FSR::AppendData -bor [int]$FSR::CreateDirectories -bor
     [int]$FSR::WriteAttributes -bor [int]$FSR::Delete -bor [int]$FSR::DeleteSubdirectoriesAndFiles))
  [PSCustomObject]@{ FileRights=$file; DirRights=$dir }
}

function Set-RootSacl {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$Sid)
  # Apply SACL on root with inheritance (new children).
  $rights  = Get-RightsForAudit
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $audit   = [System.Security.AccessControl.AuditFlags]::Success -bor `
             [System.Security.AccessControl.AuditFlags]::Failure

  $acl = Get-Acl -LiteralPath $Path
  # Remove previous audit rules for the same SID to avoid duplicates/noise.
  $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference -eq $Sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }

  # Combine file+dir rights for inheritance.
  $combined = $rights.FileRights -bor $rights.DirRights
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($Sid, $combined, $inherit, $prop, $audit)
  $acl.AddAuditRule($rule) | Out-Null
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Retrofit-ChildrenSacl {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$Sid)
  # Apply SACL directly to existing children (no inheritance flags).
  $rights = Get-RightsForAudit
  $audit  = [System.Security.AccessControl.AuditFlags]::Success -bor `
            [System.Security.AccessControl.AuditFlags]::Failure
  $inheritNone=[System.Security.AccessControl.InheritanceFlags]::None
  $propNone   =[System.Security.AccessControl.PropagationFlags]::None

  $items = Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
  foreach($it in $items){
    try{
      $acl = Get-Acl -LiteralPath $it.FullName
      # Clean existing rules for same SID
      $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference -eq $Sid } | ForEach-Object { [void]$acl.RemoveAuditRule($_) }
      $use = if($it.PSIsContainer){ $rights.DirRights } else { $rights.FileRights }
      $ar  = New-Object System.Security.AccessControl.FileSystemAuditRule($Sid, $use, $inheritNone, $propNone, $audit)
      $acl.AddAuditRule($ar) | Out-Null
      Set-Acl -LiteralPath $it.FullName -AclObject $acl
    } catch { Write-Verbose "Failed SACL on $($it.FullName): $($_.Exception.Message)" }
  }
}

# ---------- Locale‑independent Event XML parser ----------
function Parse-EventXml {
  param([Parameter(Mandatory)]$Event)  # Get-WinEvent record
  $xml = [xml]$Event.ToXml()
  $ed  = $xml.Event.EventData
  $map = @{}
  foreach($n in $ed.Data){ $map[$n.Name] = [string]$n.'#text' }
  [pscustomobject]@{
    EventId   = [int]$xml.Event.System.EventID.'#text'
    Target    = $map['ObjectName']
    Accesses  = $map['AccessList']      # e.g., "DELETE, WriteAttributes, DeleteChild"
    Mask      = $map['AccessMask']      # e.g., "0x10000"
    Process   = $map['ProcessName']
    Subject   = $map['SubjectUserName']
    RawMap    = $map
  }
}

# ---------- Self test (create → rename extension → delete) ----------
function Self-Test {
  param([Parameter(Mandatory)][string]$Root)
  Write-Host "[*] Self-test: create→rename(extension)→delete..." -ForegroundColor Cyan
  $since = Get-Date

  $sub = Join-Path $Root 'Docs'
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
            Where-Object { $_.Message -like "*$Root*" }

  if($events){
    Write-Host "[+] Found $($events.Count) 4663 event(s) since $since" -ForegroundColor Green
    foreach($e in $events){
      $p = Parse-EventXml $e
      ('{0:u}  4663  {1}  Mask={2}' -f $e.TimeCreated, $p.Accesses, $p.Mask) | Write-Host
      if($p.Target){ ('   -> ' + $p.Target) | Write-Host }
    }
  } else {
    Write-Warning "No 4663 events found—check SACL and audit policy."
  }
}

# ---------- Main ----------
Write-Host "[*] Target root: $Root" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $Root -Force | Out-Null

Enable-FileSystemAuditPolicy

$sid = New-Object System.Security.Principal.SecurityIdentifier $AuditSid
Set-RootSacl -Path $Root -Sid $sid
Write-Host "[*] SACL applied to root (will inherit to new items)" -ForegroundColor Green

if($RetrofitExisting){
  Write-Host "[*] Retrofitting SACL to existing children..." -ForegroundColor Cyan
  Retrofit-ChildrenSacl -Path $Root -Sid $sid
  Write-Host "[*] Retrofit complete." -ForegroundColor Green
}

if($SelfTest){ Self-Test -Root $Root }

Write-Host "`n[+] Audit ready for CREATE / RENAME / DELETE." -ForegroundColor Green
Write-Host "    Path: $Root"
Write-Host "    Tip: verify policy via  auditpol /get /subcategory:\"File System\""
