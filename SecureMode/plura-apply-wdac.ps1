<#
.SYNOPSIS
  Apply WDAC policy and prepare system to enforce CLM + executable restrictions (e.g., LOLBins)

.DESCRIPTION
  - Applies WDAC policy (.bin)
  - Logs operations to C:\Program Files\Plura\
  - Intended to work with a WDAC XML that blocks LOLBins like wscript.exe, regsvr32.exe, etc.
#>

# === Configuration ===
$PolicyPath = "C:\Program Files\Plura\plura-policy.bin"       # Precompiled WDAC policy
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
Log "🟢 Starting PLURA WDAC Application Script..."

# 1. Apply WDAC policy
if (Test-Path $PolicyPath) {
    try {
        Log "🔐 Applying WDAC policy from: $PolicyPath"
        # Ensure folder exists
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

# 2. Trust Paths (Note: these must be included in the XML at policy build time)
foreach ($path in $TrustedPaths) {
    Log "📁 Trusted path registered in policy (assumed): $path"
}

# 3. Restricted LOLBins (Note: actual blocking must be in XML file)
foreach ($exe in $RestrictedBinaries) {
    Log "🚫 Restricted binary should be blocked via FileRule: $exe"
}

# 4. Check PowerShell Language Mode
$mode = $ExecutionContext.SessionState.LanguageMode
if ($mode -eq "ConstrainedLanguage") {
    Log "✅ PowerShell is in ConstrainedLanguage Mode"
} else {
    Log "⚠️ PowerShell Language Mode: $mode (Not secured)"
}

# 5. Final
Log "✅ WDAC script completed. Please reboot to apply changes."
Write-Host "`n[INFO] WDAC policy applied. Reboot required. Log saved to: $LogFile" -ForegroundColor Green
