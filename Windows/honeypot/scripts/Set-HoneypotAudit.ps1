<# 
.SYNOPSIS
  Minimal honeypot under Documents with audit policy + SACL for create/modify.

.NOTES
  Run as Administrator.
  Security logs you’ll see on activity: 4656/4663/4658/4670 (Object Access).
#>

param(
  # Root honeypot path under current user’s Documents
  [string]$HoneypotRoot = Join-Path $env:USERPROFILE "Documents\"
)

# --- Helpers ---------------------------------------------------------------

function New-TextFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Content
    )
    # Simple text content regardless of extension; good enough for decoys.
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Enable-FileSystemAuditPolicy {
    <#
      .SYNOPSIS
        Enables Advanced Audit Policy for File System (success+failure).
      .DESCRIPTION
        Uses auditpol to set: Object Access -> File System : Success, Failure
    #>
    Write-Host "[*] Enabling Advanced Audit Policy for File System..." -ForegroundColor Cyan
    & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

    # Optional hardening: ensure "Object Access" subcats also include Removable Storage if desired.
    # & auditpol.exe /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
}

function Add-AuditRuleToFolder {
    param(
        [Parameter(Mandatory)] [string]$FolderPath
    )
    <#
      .SYNOPSIS
        Adds SACL audit rules to a folder, inheriting to all child files.
      .DETAILS
        Identity: Everyone (S-1-1-0)
        Rights: create/write/append/delete/attr changes
        Inheritance: ContainerInherit + ObjectInherit
        Audit: Success + Failure
    #>
    if (!(Test-Path $FolderPath)) {
        throw "Folder not found: $FolderPath"
    }

    $sidEveryone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
    $ci = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $oi = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $np = [System.Security.AccessControl.PropagationFlags]::None

    # Rights to watch typical ransomware/file tampering behaviors
    $rights = [System.Security.AccessControl.FileSystemRights]::CreateFiles `
            -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
            -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
            -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
            -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes `
            -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes `
            -bor [System.Security.AccessControl.FileSystemRights]::Delete `
            -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

    $auditFlags = [System.Security.AccessControl.AuditFlags]::Success `
                -bor [System.Security.AccessControl.AuditFlags]::Failure

    $acl = Get-Acl -Path $FolderPath
    $sacl = $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier])

    # Build and attach audit rule
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        $sidEveryone, $rights, $ci -bor $oi, $np, $auditFlags
    )

    $modified = $false
    if (-not $sacl | Where-Object {
        $_.IdentityReference -eq $sidEveryone -and
        $_.FileSystemRights -band $rights -and
        $_.AuditFlags -band $auditFlags
    }) {
        $acl.AddAuditRule($auditRule) | Out-Null
        $modified = $true
    }

    if ($modified) {
        # Apply SACL back (needs admin)
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Host "[*] SACL audit rule added to: $FolderPath" -ForegroundColor Green
    }
    else {
        Write-Host "[*] SACL already present on: $FolderPath" -ForegroundColor Yellow
    }
}

# --- 1) Create Documents\Honeypot folder ----------------------------------

Write-Host "[*] Creating honeypot root: $HoneypotRoot" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $HoneypotRoot -Force | Out-Null

$folders = @{
  Docs    = Join-Path $HoneypotRoot "Docs"
  Images  = Join-Path $HoneypotRoot "Images"
  Archives= Join-Path $HoneypotRoot "Archives"
  Media   = Join-Path $HoneypotRoot "Media"
}

$folders.GetEnumerator() | ForEach-Object {
  New-Item -ItemType Directory -Path $_.Value -Force | Out-Null
}

# --- 2) Create decoy files across types -----------------------------------

Write-Host "[*] Creating decoy files..." -ForegroundColor Cyan

# Office-like
New-TextFile -Path (Join-Path $folders.Docs "Project_Plan.docx") "Decoy document for auditing."
New-TextFile -Path (Join-Path $folders.Docs "Budget_2025.xlsx")   "Decoy spreadsheet for auditing."
New-TextFile -Path (Join-Path $folders.Docs "Sales_Review.pptx")  "Decoy presentation for auditing."
# PDF
New-TextFile -Path (Join-Path $folders.Docs "Confidential_Report.pdf") "Decoy PDF for auditing."
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

# Optional: make them look “interesting” to attackers
# (Ransomware often enumerates Documents/Media aggressively.)
# Set-ItemProperty -Path (Join-Path $folders.Docs "Confidential_Report.pdf") -Name IsReadOnly -Value $true

# --- 3) Enable Advanced Audit Policy + attach SACLs -----------------------

Enable-FileSystemAuditPolicy

# Add SACL auditing to the honeypot root so it inherits to all children
Add-AuditRuleToFolder -FolderPath $HoneypotRoot

Write-Host "`n[+] Honeypot ready." -ForegroundColor Green
Write-Host "    Path: $HoneypotRoot"
Write-Host "    Watch Security log for Object Access events (e.g., 4663) on create/modify/delete." 
