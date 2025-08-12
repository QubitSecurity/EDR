<# 
.SYNOPSIS
  Create honeypot folder tree and decoy files (no audit changes here).

.DESCRIPTION
  - Creates Documents\Client_Contracts (default) with subfolders.
  - Generates decoy files across Office/PDF/Image/Archive/Media.
  - Does NOT touch Security policy or SACL; safe to run anytime.

.PARAMS
  -HoneypotRoot : Target folder (default: Documents\Client_Contracts)
#>

param(
  [string]$HoneypotRoot = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Client_Contracts')
)

function New-TextFile {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Content)
  $dir = Split-Path -Parent $Path
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

# --- Main ---
Write-Host "[*] Creating honeypot folder tree: $HoneypotRoot" -ForegroundColor Cyan
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

Write-Host "`n[+] Decoy files ready." -ForegroundColor Green
Write-Host "    Path: $HoneypotRoot"
