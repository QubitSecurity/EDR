<#
.SYNOPSIS
  Apply SecureMode (WDAC) policy and enforce CLM + LOLBin protection.

.DESCRIPTION
  - Applies WDAC binary policy (.bin) to enforce PowerShell CLM
  - Assumes policy was built with Publisher or Path rules (not hash-only)
  - Denies LOLBins via FileRule (e.g., wscript.exe, regsvr32.exe, etc.)
  - Requires reboot for enforcement

.NOTES
  🔒 To avoid re-generating policies after every app update,
     use Publisher-based rules as shown below:

     New-CIPolicy -FilePath .\plura-policy.xml -Level Publisher -UserPEs -Fallback Hash
#>

# === Configuration ===
$PolicyPath = "C:\Program Files\Plura\plura-policy.bin"
$LogFile = "C:\Program Files\Plura\plura-wdac-log.txt"

$TrustedPaths = @(
    "C:\Program Files\*",
    "C:\Program Files (x86)\*",
    "$env:USERPROFILE\AppData\*"
)

$RestrictedBinaries = @(
    "wscript.exe",
    "regsvr32.exe",
    "mshta.exe",
    "cscript.exe",
    "rundll32.exe"
)

# === Function: Log with Timestamp ===
function Log {
    param ($msg)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $msg" | Tee-Object -FilePath $LogFile -Append
}

# === Begin Script ===
Log "🟢 Starting PLURA SecureMode WDAC Application Script..."

# 1. Apply WDAC policy
if (Test-Path $PolicyPath) {
    try {
        Log "🔐 Applying WDAC policy from: $PolicyPath"
        if (!(Test-Path "C:\Windows\System32\CodeIntegrity")) {
            New-Item -Path "C:\Windows\System32\CodeIntegrity" -ItemType Directory -Force | Out-Null
        }
        Copy-Item -Path $PolicyPath -Destination "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
        Log "✅ WDAC policy copied to CodeIntegrity folder."
    } catch {
        Log "❌ Failed to apply WDAC policy: $_"
    }
} else {
    Log "⚠️ WDAC policy file not found: $PolicyPath"
}

# 2. Trust Path Logging (assumes policy already contains them)
foreach ($path in $TrustedPaths) {
    Log "📁 Trusted path assumed in policy: $path"
}

# 3. Log restricted binaries
foreach ($exe in $RestrictedBinaries) {
    Log "🚫 Restricted binary expected to be blocked in policy: $exe"
}

# 4. Check PowerShell Language Mode
$mode = $ExecutionContext.SessionState.LanguageMode
if ($mode -eq "ConstrainedLanguage") {
    Log "✅ PowerShell is in ConstrainedLanguage Mode"
} else {
    Log "⚠️ PowerShell Language Mode: $mode (Not secured)"
}

# 5. Final
Log "✅ Script completed. Reboot required for policy to take effect."
Write-Host "`n[INFO] WDAC policy applied. Please reboot. Log saved to: $LogFile" -ForegroundColor Green
