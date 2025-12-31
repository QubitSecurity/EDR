<#
Rootkit Detection Scanner v1.0-rev10 (Windows / PowerShell)

PLURA-Forensic philosophy:
- No log file.
- Print only when FOUND (3 alerts).
- Always prints SCAN RESULT / END blocks (even when nothing is found).

Alerts:
1) [Alert] Hidden Entry Found!
2) [Alert] Suspicious Rootkit Found!
3) [Alert] Backdoor Found!

Exit codes:
  0  : nothing found
  10 : Hidden Entry Found
  20 : Suspicious Rootkit Found
  30 : Backdoor Found
  40 : multiple categories found

Run as Administrator.

Notes:
- Windows user-space cannot "prove" a kernel rootkit with certainty.
  This flags high-risk anomalies (autostart + suspicious drivers + listening from user-writable paths).
#>

[CmdletBinding()]
param(
  [switch]$ShowSystemInfo
)

Set-StrictMode -Version Latest


# ---------------- Noise Reduction (PLURA) ----------------
# Default: reduce common benign noise. Override via environment variables if needed.
#   PLURA_DEBUG=1                                -> show suppression debug lines (stderr)
#   PLURA_TRUSTED_COMPANY_KEYWORDS="Zoom,..."    -> comma-separated
#   PLURA_TRUSTED_SIGNER_KEYWORDS="Zoom,..."     -> comma-separated
#   PLURA_EXCLUDE_MS_WINDOWS_TASK_MISSING=0      -> keep Microsoft\Windows scheduled-task MissingBinary
#   PLURA_EXCLUDE_TRUSTED_WRITABLE=0             -> keep UserWritablePath even when Valid-signed by trusted vendor
#   PLURA_CHECK_WINDOWSAPPS_VERSION_DRIFT=0      -> disable WindowsApps "version drift" suppression

$PLURA_DEBUG = ($env:PLURA_DEBUG -eq "1")

$PLURA_TRUSTED_COMPANY_KEYWORDS = @("Zoom")
if ($env:PLURA_TRUSTED_COMPANY_KEYWORDS) {
  $PLURA_TRUSTED_COMPANY_KEYWORDS = ($env:PLURA_TRUSTED_COMPANY_KEYWORDS -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$PLURA_TRUSTED_SIGNER_KEYWORDS = @("Zoom Video Communications")
if ($env:PLURA_TRUSTED_SIGNER_KEYWORDS) {
  $PLURA_TRUSTED_SIGNER_KEYWORDS = ($env:PLURA_TRUSTED_SIGNER_KEYWORDS -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$PLURA_EXCLUDE_MS_WINDOWS_TASK_MISSING = ($env:PLURA_EXCLUDE_MS_WINDOWS_TASK_MISSING -ne "0")
$PLURA_EXCLUDE_TRUSTED_WRITABLE = ($env:PLURA_EXCLUDE_TRUSTED_WRITABLE -ne "0")
$PLURA_CHECK_WINDOWSAPPS_VERSION_DRIFT = ($env:PLURA_CHECK_WINDOWSAPPS_VERSION_DRIFT -ne "0")

function Write-PluraDebug([string]$msg) {
  if (-not $PLURA_DEBUG) { return }
  try {
    # Write to stderr without creating an ErrorRecord (avoids red Write-Error noise)
    [Console]::Error.WriteLine("[PLURA_DEBUG] " + $msg)
  } catch {
    # Fallback for environments where Console is unavailable
    Write-Host ("[PLURA_DEBUG] " + $msg)
  }
}


function Get-CompanyNameSafe([string]$path) {
  if (-not $path) { return "" }
  if ((Get-FilePresence $path) -ne "Present") { return "" }
  try {
    $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
    return ($vi.CompanyName + "")
  } catch { return "" }
}

function Get-SignerSubjectSafe([string]$path) {
  if (-not $path) { return "" }
  if ((Get-FilePresence $path) -ne "Present") { return "" }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    if ($sig -and $sig.SignerCertificate) { return ($sig.SignerCertificate.Subject + "") }
    return ""
  } catch { return "" }
}

function Test-TrustedSignedVendor([string]$path) {
  # True when:
  #  - file exists
  #  - signature status is Valid
  #  - AND CompanyName or Signer subject contains trusted keyword(s)
  if (-not $path) { return $false }
  if ((Get-FilePresence $path) -ne "Present") { return $false }

  $sigStatus = "Unknown"
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $sigStatus = $sig.Status.ToString()
  } catch { $sigStatus = "Unknown" }

  if ($sigStatus -ne "Valid") { return $false }

  $company = Get-CompanyNameSafe $path
  $signer  = Get-SignerSubjectSafe $path

  foreach ($k in $PLURA_TRUSTED_COMPANY_KEYWORDS) {
    if ($k -and $company -and ($company -like ("*" + $k + "*"))) { return $true }
  }
  foreach ($k in $PLURA_TRUSTED_SIGNER_KEYWORDS) {
    if ($k -and $signer -and ($signer -like ("*" + $k + "*"))) { return $true }
  }
  return $false
}

function Test-WindowsAppsVersionDrift([string]$windowsAppsPath) {
  # Returns: $true  -> another version exists (noise)
  #          $false -> no alternate found
  #          $null  -> cannot verify
  if (-not $windowsAppsPath) { return $false }
  if ($windowsAppsPath -notmatch '\\WindowsApps\\') { return $false }

  $root = Join-Path $env:ProgramFiles "WindowsApps"
  if (-not (Test-Path -LiteralPath $root)) { return $null }

  # Parse: <root>\<pkgDir>\<relSubpath>
  $m = [regex]::Match($windowsAppsPath, '^(?<root>.+\\WindowsApps)\\(?<pkgdir>[^\\]+)\\(?<rel>.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $m.Success) { return $null }

  $pkgdir = $m.Groups["pkgdir"].Value
  $rel    = $m.Groups["rel"].Value

  # Package dir format: Name_Version_Arch__PublisherId
  $m2 = [regex]::Match($pkgdir, '^(?<name>.+)_(?<ver>\d+(?:\.\d+)+)_(?<arch>[^_]+)__(?<pub>.+)$')
  if (-not $m2.Success) { return $null }

  $name = $m2.Groups["name"].Value
  $arch = $m2.Groups["arch"].Value
  $pub  = $m2.Groups["pub"].Value

  $pattern = ($name + "_*_" + $arch + "__" + $pub)

  try {
    $dirs = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop | Where-Object { $_.Name -like $pattern }
    foreach ($d in $dirs) {
      $candidate = Join-Path $d.FullName $rel
      try {
        if (Test-Path -LiteralPath $candidate) { return $true }
      } catch {}
    }
    return $false
  } catch {
    return $null
  }
}

function Should-SuppressHiddenFinding(
  [string]$Kind,
  [string]$Name,
  [string]$FilePath,
  [string]$Reason,
  [string]$Raw,
  [string]$StartMode,
  [string]$State
) {
  # 1) Suppress trusted vendor binaries running from user-writable paths
  if ($Reason -eq "UserWritablePath" -and $PLURA_EXCLUDE_TRUSTED_WRITABLE) {
    if (Test-TrustedSignedVendor $FilePath) {
      Write-PluraDebug ("Suppress UserWritablePath trusted vendor: " + $FilePath)
      return $true
    }
  }

  # 2) Suppress Microsoft\Windows scheduled tasks that reference missing binaries (common benign noise)
  if ($Kind -eq "ScheduledTask" -and $Reason -eq "MissingBinary" -and $PLURA_EXCLUDE_MS_WINDOWS_TASK_MISSING) {
    if ($Name -like '\Microsoft\Windows\*') {
      Write-PluraDebug ("Suppress MS Windows task MissingBinary: " + $Name + " -> " + $FilePath)
      return $true
    }
  }

  # 3) WindowsApps service MissingBinary: second-pass verify (version drift / disabled service)
  if ($Kind -eq "Service" -and $Reason -eq "MissingBinary" -and $FilePath -match '\\WindowsApps\\') {
    if ($StartMode -eq "Disabled" -and $State -ne "Running") {
      Write-PluraDebug ("Suppress WindowsApps disabled service MissingBinary: " + $Name)
      return $true
    }
    if ($PLURA_CHECK_WINDOWSAPPS_VERSION_DRIFT) {
      $drift = Test-WindowsAppsVersionDrift $FilePath
      if ($drift -eq $true) {
        Write-PluraDebug ("Suppress WindowsApps version drift: " + $Name + " -> " + $FilePath)
        return $true
      }
    }
  }

  return $false
}


# ---------------- Helpers ----------------
function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Expand-Env([string]$s) {
  if (-not $s) { return "" }
  try { return [Environment]::ExpandEnvironmentVariables($s) } catch { return $s }
}

function Resolve-WindowsPath([string]$rawPath) {
  if (-not $rawPath) { return "" }

  $p = ($rawPath + "").Trim()
  $p = Expand-Env $p

  # Remove surrounding quotes
  if ($p.StartsWith('"') -and $p.EndsWith('"')) { $p = $p.Trim('"') }

  # Strip NT path prefixes
  if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
  if ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }

  # Convert \SystemRoot\... to C:\Windows\...
  if ($p -match '^(\\SystemRoot\\)(.+)$') {
    $p = Join-Path $env:SystemRoot $Matches[2]
  }

  # Convert "system32\..." or "\system32\..." to C:\Windows\system32\...
  if ($p -match '^[\\]?system32\\') {
    $p = Join-Path $env:SystemRoot ($p.TrimStart('\'))
  }

  # Convert "\Windows\..." (rare) to "C:\Windows\..."
  if ($p -match '^[\\]Windows\\') {
    $p = Join-Path ($env:SystemDrive + "\") ($p.TrimStart('\'))
  }

  return $p
}

function Extract-ExePath([string]$cmdOrPath) {
  # Extract a .exe path from:
  # - "C:\Program Files\App\a.exe" args...
  # - C:\Windows\System32\svchost.exe -k ...
  # - cmd.exe /c ...
  # - %SystemRoot%\System32\cmd.exe ...
  if (-not $cmdOrPath) { return "" }

  $s = ($cmdOrPath + "").Trim()
  $s = Expand-Env $s

  # Quoted path first
  if ($s.StartsWith('"')) {
    $m = [regex]::Match($s, '^"([^"]+)"')
    if ($m.Success) { return (Resolve-WindowsPath $m.Groups[1].Value) }
  }

  # Drive path up to FIRST .exe (allows spaces)
  $m2 = [regex]::Match($s, '^\s*([A-Za-z]:\\.*?\.exe)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m2.Success) { return (Resolve-WindowsPath $m2.Groups[1].Value) }

  # Try again after basic normalization (handles \??\C:\... etc)
  $norm = Resolve-WindowsPath $s
  $m3 = [regex]::Match($norm, '^\s*([A-Za-z]:\\.*?\.exe)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m3.Success) { return (Resolve-WindowsPath $m3.Groups[1].Value) }

  # Token that is just "something.exe": resolve via PATH
  $tok = $s.Split(' ', 2)[0].Trim('"')
  if ($tok -match '^[^\\/:]+\.exe$') {
    $gc = Get-Command $tok -ErrorAction SilentlyContinue
    if ($gc -and $gc.Source) { return (Resolve-WindowsPath $gc.Source) }
  }

  # Last resort: return normalized token
  return (Resolve-WindowsPath $tok)
}

function Get-FilePresence([string]$path) {
  # Present | Missing | AccessDenied
  if (-not $path) { return "Missing" }
  try {
    $null = Get-Item -LiteralPath $path -ErrorAction Stop
    return "Present"
  } catch [System.UnauthorizedAccessException] {
    return "AccessDenied"
  } catch {
    return "Missing"
  }
}

function Get-FileHashSafe([string]$path, [string]$algo) {
  if (-not $path) { return "N/A" }
  if ((Get-FilePresence $path) -eq "Missing") { return "N/A" }
  try {
    return (Get-FileHash -Algorithm $algo -LiteralPath $path -ErrorAction Stop).Hash
  } catch { return "N/A" }
}

function Write-FileDetails([string]$path) {
  if (-not $path) { Write-Host " - File Not Found!"; return }
  $presence = Get-FilePresence $path
  if ($presence -eq "Missing") {
    Write-Host " - File Not Found!"
    return
  }
  if ($presence -eq "AccessDenied") {
    Write-Host " - File Exists (AccessDenied)"
    # still attempt hashes (will likely fail) but keep fields consistent
  }

  try {
    $i = Get-Item -LiteralPath $path -ErrorAction Stop
    Write-Host (" - Modified: {0}" -f $i.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
    Write-Host (" - Created : {0}" -f $i.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"))
  } catch {
    Write-Host " - Modified: N/A"
    Write-Host " - Created : N/A"
  }

  Write-Host (" - MD5: {0}" -f (Get-FileHashSafe $path "MD5"))
  Write-Host (" - SHA256: {0}" -f (Get-FileHashSafe $path "SHA256"))
}

function Test-UserWritablePath([string]$path) {
  if (-not $path) { return $false }
  $p = $path.ToLowerInvariant()

  $tmp = ($env:TEMP + "").ToLowerInvariant()
  $local = ($env:LOCALAPPDATA + "").ToLowerInvariant()
  $roam = ($env:APPDATA + "").ToLowerInvariant()
  $winTemp = (Join-Path $env:SystemRoot "Temp").ToLowerInvariant()

  return (
    ($tmp -and $p.StartsWith($tmp)) -or
    ($winTemp -and $p.StartsWith($winTemp)) -or
    ($local -and $p.StartsWith($local)) -or
    ($roam -and $p.StartsWith($roam)) -or
    $p.StartsWith("c:\users\")
  )
}

function Test-ProbablySystemPath([string]$path) {
  if (-not $path) { return $false }
  $p = $path.ToLowerInvariant()
  $sr = ($env:SystemRoot + "").ToLowerInvariant()
  $pf = ($env:ProgramFiles + "").ToLowerInvariant()
  $pf86 = ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)') + "").ToLowerInvariant()
  $pd = ($env:ProgramData + "").ToLowerInvariant()

  return (
    ($sr -and $p.StartsWith($sr)) -or
    ($pf -and $p.StartsWith($pf)) -or
    ($pf86 -and $p.StartsWith($pf86)) -or
    ($pd -and $p.StartsWith($pd))
  )
}

function Get-SignatureSummary([string]$path) {
  if (-not $path) { return @{ Status="Missing"; IsMicrosoft=$false } }
  if ((Get-FilePresence $path) -eq "Missing") { return @{ Status="Missing"; IsMicrosoft=$false } }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $subj = ($sig.SignerCertificate.Subject + "")
    $isMs = $false
    if ($subj -match "Microsoft") { $isMs = $true }
    return @{ Status=($sig.Status.ToString()); IsMicrosoft=$isMs }
  } catch {
    return @{ Status="Unknown"; IsMicrosoft=$false }
  }
}

# ---------------- Findings ----------------
function Get-HiddenEntryFindings {
  $out = @()

  # Services
  try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
    foreach ($s in $services) {
      $exe = Extract-ExePath ($s.PathName + "")
      $exe = Resolve-WindowsPath $exe
      if (-not $exe) { continue }

      $presence = Get-FilePresence $exe
      $missing = ($presence -eq "Missing")
      $writable = Test-UserWritablePath $exe

      if ($missing -or $writable) {
      $reason = ($(if($missing){"MissingBinary"}else{"UserWritablePath"}))
      if (Should-SuppressHiddenFinding -Kind "Service" -Name ($s.Name + "") -FilePath $exe -Reason $reason -Raw ($s.PathName + "") -StartMode ($s.StartMode + "") -State ($s.State + "")) { continue }
      $out += [pscustomobject]@{
          Kind="Service"
          Name=($s.Name + "")
          Detail=($s.DisplayName + "")
          FilePath=$exe
          Raw=($s.PathName + "")
          StartMode=($s.StartMode + "")
          State=($s.State + "")
          Reason=$reason
        }
      }
    }
  } catch {}

  # Scheduled Tasks (only if available)
  if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
      $tasks = Get-ScheduledTask -ErrorAction Stop
      foreach ($t in $tasks) {
        foreach ($a in $t.Actions) {
          # Only Exec actions have Execute
          if ($a.PSObject.Properties.Match('Execute').Count -eq 0) { continue }
          if (-not $a.Execute) { continue }

          # Execute is the program path (arguments are separate). Still resolve env + allow "cmd.exe" style.
          $exe = Extract-ExePath ($a.Execute + "")
          $exe = Resolve-WindowsPath $exe
          if (-not $exe) { continue }

          $presence = Get-FilePresence $exe
          $missing = ($presence -eq "Missing")
          $writable = Test-UserWritablePath $exe

          if ($missing -or $writable) {
            $reason = ($(if($missing){"MissingBinary"}else{"UserWritablePath"}))
            $taskFullName = ($t.TaskPath + $t.TaskName)
            if (Should-SuppressHiddenFinding -Kind "ScheduledTask" -Name $taskFullName -FilePath $exe -Reason $reason -Raw ($a.Execute + "") -StartMode "" -State "") { continue }
            $out += [pscustomobject]@{
              Kind="ScheduledTask"
              Name=($t.TaskPath + $t.TaskName)
              Detail=""
              FilePath=$exe
              Raw=($a.Execute + "")
              Arguments=($(if ($a.PSObject.Properties.Match("Arguments").Count -gt 0) { ($a.Arguments + "") } else { "" }))
              WorkingDirectory=($(if ($a.PSObject.Properties.Match("WorkingDirectory").Count -gt 0) { ($a.WorkingDirectory + "") } else { "" }))
              Reason=$reason
            }
          }
        }
      }
    } catch {}
  }

  # WMI persistence (EventFilter/Consumer/Binding)
  try {
    $filters   = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
    $consumers = Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction Stop
    $bindings  = Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop

    foreach ($b in $bindings) {
      $f = $filters   | Where-Object { $_.__RELPATH -eq $b.Filter }   | Select-Object -First 1
      $c = $consumers | Where-Object { $_.__RELPATH -eq $b.Consumer } | Select-Object -First 1
      if (-not $c) { continue }

      $cmd = ($c.CommandLineTemplate + "")
      if (-not $cmd) { continue }

      $exe = Extract-ExePath $cmd
      $exe = Resolve-WindowsPath $exe
      if (-not $exe) { continue }

      $presence = Get-FilePresence $exe
      $missing = ($presence -eq "Missing")
      $writable = Test-UserWritablePath $exe
      $nonSystem = -not (Test-ProbablySystemPath $exe)

      if ($missing -or $writable -or $nonSystem) {
        $reason = ($(if($missing){"MissingBinary"}elseif($writable){"UserWritablePath"}else{"NonSystemPath"}))
        $wmiName = ("Filter=" + ($f.Name + "") + " Consumer=" + ($c.Name + ""))
        if (Should-SuppressHiddenFinding -Kind "WMI" -Name $wmiName -FilePath $exe -Reason $reason -Raw $cmd -StartMode "" -State "") { continue }
        $out += [pscustomobject]@{
          Kind="WMI"
          Name=("Filter=" + ($f.Name + "") + " Consumer=" + ($c.Name + ""))
          Detail=("CommandLine=" + $cmd)
          FilePath=$exe
          Raw=$cmd
          Reason=$reason
        }
      }
    }
  } catch {}

  $out | Sort-Object Kind,Name,FilePath -Unique
}

function Get-RootkitDriverFindings {
  $out = @()
  try {
    $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq "Running" }
    foreach ($d in $drivers) {
      $raw = ($d.PathName + "")
      if (-not $raw) { continue }

      # Driver may not be an .exe; still extract a file-ish path
      $p = Resolve-WindowsPath $raw
      $p = Resolve-WindowsPath (Extract-ExePath $p)  # harmless if already path-like

      if (-not $p) { continue }
      if (-not $p.ToLowerInvariant().EndsWith(".sys")) { continue }

      $presence = Get-FilePresence $p
      $missing = ($presence -eq "Missing")
      $writable = Test-UserWritablePath $p
      $nonSystem = -not (Test-ProbablySystemPath $p)

      $susp = $false
      $reason = ""
      $sigStatus = "Unknown"
      $isMs = $false

      if ($missing) { $susp = $true; $reason = "MissingDriverFile" }
      elseif ($writable) { $susp = $true; $reason = "UserWritablePath" }
      elseif ($nonSystem) {
        # Signature check is the slow part: only do it for NON-system paths
        $sig = Get-SignatureSummary $p
        $sigStatus = $sig.Status
        $isMs = $sig.IsMicrosoft
        if ($sigStatus -ne "Valid") { $susp = $true; $reason = "NonSystemPath+UntrustedSignature" }
      }

      if ($susp) {
        if (-not $nonSystem) {
          # If we didn't signature-check, keep consistent fields
          $sigStatus = "Skipped"
          $isMs = $false
        }
        $out += [pscustomobject]@{
          Kind="Driver"
          Name=($d.Name + "")
          Detail=("State=" + ($d.State + "") + " Start=" + ($d.StartMode + ""))
          FilePath=$p
          Raw=($d.PathName + "")
          SigStatus=$sigStatus
          IsMicrosoft=$isMs
          Reason=$reason
        }
      }
    }
  } catch {}

  $out | Sort-Object FilePath,Name -Unique
}

function Get-ListeningSockets {
  $out = @()

  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    try {
      $out = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
          LocalAddress = $_.LocalAddress
          LocalPort    = $_.LocalPort
          OwningProcess= $_.OwningProcess
        }
      }
      return $out
    } catch {}
  }

  # netstat fallback
  try {
    $lines = & netstat.exe -ano -p tcp 2>$null
    foreach ($ln in $lines) {
      if ($ln -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
        $out += [pscustomobject]@{
          LocalAddress = $Matches[1]
          LocalPort    = [int]$Matches[2]
          OwningProcess= [int]$Matches[3]
        }
      }
    }
  } catch {}

  return $out
}

function Get-ProcessPathById([int]$procId) {
  if ($procId -le 0) { return "" }

  try {
    $p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $procId) -ErrorAction Stop
    if ($p -and $p.ExecutablePath) { return (Resolve-WindowsPath ($p.ExecutablePath + "")) }
  } catch {}

  try {
    $p2 = Get-Process -Id $procId -ErrorAction Stop
    try { return (Resolve-WindowsPath ($p2.Path + "")) } catch {}
  } catch {}

  return ""
}

function Get-BackdoorFindings {
  $out = @()
  $listeners = Get-ListeningSockets
  foreach ($l in $listeners) {
    $owningPid = [int]$l.OwningProcess   # DO NOT use $pid / $PID (reserved automatic variable)
    $imgPath = Get-ProcessPathById $owningPid
    if (-not $imgPath) { continue }

    if (Test-UserWritablePath $imgPath) {
      $out += [pscustomobject]@{
        Kind="Listen"
        Name=("PID=" + $owningPid + " " + ($l.LocalAddress + ":" + $l.LocalPort))
        Detail=""
        FilePath=$imgPath
        Reason="ListeningFromUserWritablePath"
      }
    }
  }
  $out | Sort-Object FilePath,Name -Unique
}


function Write-ItemEvidence([string]$path) {
  # Evidence bundle for single output (so analysts don't need extra steps).
  # Includes:
  #  - Presence (Present/Missing/AccessDenied)
  #  - Test-Path result
  #  - File attributes, size
  #  - VersionInfo (Company/Product/FileVersion/OriginalFilename/Description)
  #  - Authenticode signature (Status, Signer subject)
  #  - Hashes (MD5/SHA256)
  if (-not $path) {
    Write-Host " - Presence: Missing"
    Write-Host " - Test-Path: False"
    Write-Host " - File Not Found!"
    return
  }

  $presence = Get-FilePresence $path
  Write-Host (" - Presence: {0}" -f $presence)

  $tp = $false
  try { $tp = Test-Path -LiteralPath $path } catch { $tp = $false }
  Write-Host (" - Test-Path: {0}" -f $tp)

  if ($presence -eq "Missing") {
    Write-Host " - File Not Found!"
    return
  }

  # File timestamps / size / attributes
  try {
    $i = Get-Item -LiteralPath $path -ErrorAction Stop
    Write-Host (" - Modified: {0}" -f $i.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
    Write-Host (" - Created : {0}" -f $i.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"))
    try { Write-Host (" - Size    : {0}" -f $i.Length) } catch {}
    try { Write-Host (" - Attrs   : {0}" -f ($i.Attributes.ToString())) } catch {}
  } catch {
    Write-Host " - Modified: N/A"
    Write-Host " - Created : N/A"
  }

  # Owner (best-effort)
  try {
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    if ($acl -and $acl.Owner) { Write-Host (" - Owner   : {0}" -f $acl.Owner) }
  } catch {}

  # Version info (best-effort)
  try {
    $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
    if ($vi) {
      if ($vi.CompanyName)       { Write-Host (" - Company : {0}" -f $vi.CompanyName) }
      if ($vi.ProductName)       { Write-Host (" - Product : {0}" -f $vi.ProductName) }
      if ($vi.FileVersion)       { Write-Host (" - Version : {0}" -f $vi.FileVersion) }
      if ($vi.OriginalFilename)  { Write-Host (" - Original: {0}" -f $vi.OriginalFilename) }
      if ($vi.FileDescription)   { Write-Host (" - Desc    : {0}" -f $vi.FileDescription) }
    }
  } catch {}

  # Signature (only for existing files; best-effort)
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $sigStatus = $sig.Status.ToString()
    $subj = ""
    try { $subj = ($sig.SignerCertificate.Subject + "") } catch { $subj = "" }
    Write-Host (" - SigStatus: {0}" -f $sigStatus)
    if ($subj) { Write-Host (" - Signer  : {0}" -f $subj) }
  } catch {}

  # Hashes
  Write-Host (" - MD5: {0}" -f (Get-FileHashSafe $path "MD5"))
  Write-Host (" - SHA256: {0}" -f (Get-FileHashSafe $path "SHA256"))
}

# ---------------- Main ----------------
if (-not (Test-IsAdmin)) {
  Write-Host "[ERROR] Run as Administrator"
  exit 1
}

if ($ShowSystemInfo) {
  $os = "Unknown"
  try { $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
  Write-Host "============================================================"
  Write-Host "           Rootkit Detection Scanner v.1.0-rev10 (Windows)"
  Write-Host "============================================================"
  Write-Host (" - Hostname: {0}" -f $env:COMPUTERNAME)
  Write-Host (" - User    : {0}" -f $env:USERNAME)
  Write-Host (" - OS      : {0}" -f $os)
  Write-Host "============================================================"
}

$hidden  = @(Get-HiddenEntryFindings)
$rootkit = @(Get-RootkitDriverFindings)
$backdoor= @(Get-BackdoorFindings)

$exitCodes = @()

Write-Host "============================================================"
Write-Host "                        SCAN RESULT"
Write-Host "============================================================"

if ($hidden.Count -gt 0) {
  $exitCodes += 10
  Write-Host "[Alert] Hidden Entry Found!"
  foreach ($f in $hidden) {
    Write-Host ("[!] FilePath: {0}" -f $f.FilePath)
    Write-Host (" - Source: {0}" -f $f.Kind)
    if ($f.Name)   { Write-Host (" - Name: {0}" -f $f.Name) }
    if ($f.Detail) { Write-Host (" - Detail: {0}" -f $f.Detail) }
    if ($f.Reason) { Write-Host (" - Reason: {0}" -f $f.Reason) }
    Write-ItemEvidence $f.FilePath
  }
}

if ($rootkit.Count -gt 0) {
  $exitCodes += 20
  Write-Host "[Alert] Suspicious Rootkit Found!"
  foreach ($d in $rootkit) {
    Write-Host ("[!] FilePath: {0}" -f $d.FilePath)
    Write-Host (" - Source: Driver")
    if ($d.Name)   { Write-Host (" - Name: {0}" -f $d.Name) }
    if ($d.Detail) { Write-Host (" - Detail: {0}" -f $d.Detail) }
    if ($d.PSObject.Properties.Match("Raw").Count -gt 0 -and $d.Raw) { Write-Host (" - Raw: {0}" -f $d.Raw) }
    Write-Host (" - SigStatus: {0} (Microsoft={1})" -f $d.SigStatus, $d.IsMicrosoft)
    Write-Host (" - Reason: {0}" -f $d.Reason)
    Write-ItemEvidence $d.FilePath
  }
}

if ($backdoor.Count -gt 0) {
  $exitCodes += 30
  Write-Host "[Alert] Backdoor Found!"
  foreach ($b in $backdoor) {
    Write-Host ("[!] FilePath: {0}" -f $b.FilePath)
    Write-Host (" - Source: NetworkListen")
    if ($b.Name)   { Write-Host (" - Name: {0}" -f $b.Name) }
    if ($b.Reason) { Write-Host (" - Reason: {0}" -f $b.Reason) }
    Write-ItemEvidence $b.FilePath
  }
}

if ($exitCodes.Count -eq 0) {
  Write-Host ""
  Write-Host "- Not Found!"
  Write-Host ""
}
Write-Host "============================================================"
Write-Host "                        END"
Write-Host "============================================================"

if ($exitCodes.Count -eq 0) { exit 0 }
if ($exitCodes.Count -ge 2) { exit 40 }
exit ($exitCodes | Sort-Object | Select-Object -Last 1)
