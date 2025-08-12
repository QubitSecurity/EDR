<# 
.SYNOPSIS
  Create a simple honeypot under Documents, generate decoy files, and enable auditing (Advanced Audit Policy + SACL).

.DESCRIPTION
  - Creates Documents\Honeypot with subfolders (Docs/Images/Archives/Media).
  - Generates decoy files across Office/PDF/Image/Archive/Media extensions.
  - Enables "Object Access -> File System" advanced audit policy (locale-aware).
  - Adds SACL audit rule (Everyone; create/write/append/delete) with inheritance to all child objects.

.NOTES
  Run as Administrator.
  Relevant Security log events to observe: 4656, 4663, 4658, 4670.

#>

param(
  # Resolve the actual Documents path (handles localization/redirected folders)
  [string]$HoneypotRoot = $(Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Honeypot')
)

# --- Helpers ---------------------------------------------------------------

function Test-IsAdministrator {
    <#
      .SYNOPSIS
        Checks if current PowerShell is elevated.
    #>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-TextFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Content
    )
    # Create parent directory if needed and write UTF-8 text (decoy content).
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Enable-FileSystemAuditPolicy {
    <#
      .SYNOPSIS
        Enable Advanced Audit Policy for File System (success+failure), locale-aware.
      .DETAILS
        Finds the localized subcategory name by querying auditpol.
    #>
    Write-Host "[*] Enabling Advanced Audit Policy for File System..." -ForegroundColor Cyan

    # Query available subcategories (localized)
    $list = & auditpol.exe /list /subcategory:* 2>$null

    # Known localized labels (extend if needed)
    $candidates = @(
        'File System',          # en-US
        '파일 시스템',            # ko-KR
        'ファイル システム',       # ja-JP
        'Dateisystem',          # de-DE (common)
        'Fichier système',      # fr-FR
        'Sistema de archivos'   # es-ES
    )

    $target = $null
    foreach ($c in $candidates) {
        if ($list -match ("(?m)^\s*"+[regex]::Escape($c)+"\s*$")) { $target = $c; break }
    }

    # Fallback heuristic: pick the line that contains both words similar to "file" and "system"
    if (-not $target) {
        $guess = $list | Where-Object { $_ -match '(?i)file|fichier|archivo|datei|ファイル|파일' } |
                         Where-Object { $_ -match '(?i)system|système|sistema|system|システム|시스템' } |
                         Select-Object -First 1
        if ($guess) { $target = $guess.Trim() }
    }

    if (-not $target) {
        Write-Warning "Could not resolve localized subcategory for 'File System'."
        Write-Warning "Run 'auditpol /list /subcategory:*' and set it manually."
        return
    }

    # Apply success+failure
    & auditpol.exe /set /subcategory:"$target" /success:enable /failure:enable | Out-Null
}

function Add-AuditRuleToFolder {
    param([Parameter(Mandatory)] [string]$FolderPath)

    <#
      .SYNOPSIS
        Adds SACL audit rules to a folder, inheriting to all children.
      .DETAILS
        Identity: Everyone (S-1-1-0)
        Rights: create/write/append/delete/attr changes
        Inheritance: ContainerInherit + ObjectInherit
        Audit: Success + Failure
    #>

    if (!(Test-Path $FolderPath)) { throw "Folder not found: $FolderPath" }

    $sidEveryone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"

    # Build rights via integer accumulation to avoid array/bitwise pitfalls.
    $FSR = [System.Security.AccessControl.FileSystemRights]
    $rightsInt = 0
    $rightsInt = $rightsInt -bor [int]$FSR::CreateFiles
    $rightsInt = $rightsInt -bor [int]$FSR::CreateDirectories
    $rightsInt = $rightsInt -bor [int]$FSR::WriteData
    $rightsInt = $rightsInt -bor [int]$FSR::AppendData
    $rightsInt = $rightsInt -bor [int]$FSR::WriteAttributes
    $rightsInt = $rightsInt -bor [int]$FSR::WriteExtendedAttributes
    $rightsInt = $rightsInt -bor [int]$FSR::Delete
    $rightsInt = $rightsInt -bor [int]$FSR::DeleteSubdirectoriesAndFiles
    $rights    = [System.Security.AccessControl.FileSystemRights]$rightsInt

    $inherit   = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                 [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagate = [System.Security.AccessControl.PropagationFlags]::None

    $auditFlags = [System.Security.AccessControl.AuditFlags]::Success -bor `
                  [System.Security.AccessControl.AuditFlags]::Failure

    $acl = Get-Acl -Path $FolderPath
    $existing = $acl.GetAuditRules($true,$true,[System.Security.Principal.SecurityIdentifier]) |
      Where-Object {
        $_.IdentityReference -eq $sidEveryone -and
        ($_.FileSystemRights -band $rights) -eq $rights -and
        ($_.AuditFlags -band $auditFlags) -eq $auditFlags -and
        ($_.InheritanceFlags -band $inherit) -eq $inherit
      }

    if (-not $existing) {
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $sidEveryone, $rights, $inherit, $propagate, $auditFlags
        )
        $acl.AddAuditRule($auditRule) | Out-Null
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Host "[*] SACL audit rule added to: $FolderPath" -ForegroundColor Green
    } else {
        Write-Host "[*] SACL already present on: $FolderPath" -ForegroundColor Yellow
    }
}

# --- Main ------------------------------------------------------------------

if (-not (Test-IsAdministrator)) {
    throw "Please run PowerShell as Administrator."
}

Write-Host "[*] Creating honeypot root: $HoneypotRoot" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $HoneypotRoot -Force | Out-Null

$folders = @{
  Docs     = Join-Path $HoneypotRoot "Docs"
  Images   = Join-Path $HoneypotRoot "Images"
  Archives = Join-Path $HoneypotRoot "Archives"
  Media    = Join-Path $HoneypotRoot "Media"
}

$folders.Values | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }

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

# Enable audit policy and add SACL
Enable-FileSystemAuditPolicy
Add-AuditRuleToFolder -FolderPath $HoneypotRoot

Write-Host "`n[+] Honeypot ready." -ForegroundColor Green
Write-Host "    Path: $HoneypotRoot"
Write-Host "    Check Security log for Object Access events (e.g., 4663) on create/modify/delete."
Write-Host "    Verify policy: auditpol /get /subcategory:\"File System\"  (or the localized name)"
