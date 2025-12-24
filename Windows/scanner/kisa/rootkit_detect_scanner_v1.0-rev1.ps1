<#
Rootkit Detection Scanner v1.0-rev2 (Windows / PowerShell)

PLURA-Forensic philosophy:
- No log file.
- Print only when FOUND (3 alerts).
- Quiet when nothing is found.

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
- Windows cannot reliably "prove" a kernel rootkit from user-space alone.
  This script flags high-risk anomalies (autostart + drivers + network listen).
#>

[CmdletBinding()]
param(
  [switch]$ShowSystemInfo
)

Set-StrictMode -Version Latest

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

  $p = $rawPath.Trim()
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
  if (-not $cmdOrPath) { return "" }

  $s = ($cmdOrPath + "").Trim()
  $s = Expand-Env $s

  # Quoted path: "C:\...\app.exe" args...
  if ($s.StartsWith('"')) {
    $m = [regex]::Match($s, '^"([^"]+)"')
    if ($m.Success) { return (Resolve-WindowsPath $m.Groups[1].Value) }
  }

  # Unquoted: C:\...\app.exe args...
  $m2 = [regex]::Match($s, '^\s*([A-Za-z]:\\[^\s"]+?\.exe)\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m2.Success) { return (Resolve-WindowsPath $m2.Groups[1].Value) }

  # First token (could be powershell.exe/cmd.exe without full path)
  $tok = $s.Split(' ', 2)[0]
  $tok = $tok.Trim('"')
  $tok = Resolve-WindowsPath $tok

  # If looks like just "something.exe", try resolve via PATH
  if ($tok -match '^[^\\/:]+\.exe$') {
    $gc = Get-Command $tok -ErrorAction SilentlyContinue
    if ($gc -and $gc.Source) { return $gc.Source }
  }

  return $tok
}

function Get-FileHashSafe([string]$path, [string]$algo) {
  if (-not (Test-Path -LiteralPath $path)) { return "N/A" }
  try {
    return (Get-FileHash -Algorithm $algo -LiteralPath $path -ErrorAction Stop).Hash
  } catch { return "N/A" }
}

function Write-FileDetails([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    Write-Host " - File Not Found!"
    return
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
  $pf86 = ($env:ProgramFiles(x86) + "").ToLowerInvariant()
  return (
    ($sr -and $p.StartsWith($sr)) -or
    ($pf -and $p.StartsWith($pf)) -or
    ($pf86 -and $p.StartsWith($pf86))
  )
}

function Get-SignatureSummary([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    return @{ Status="Missing"; IsMicrosoft=$false; Subject="" }
  }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
    $subj = ($sig.SignerCertificate.Subject + "")
    $isMs = $false
    if ($subj -match "Microsoft") { $isMs = $true }
    return @{ Status=($sig.Status.ToString()); IsMicrosoft=$isMs; Subject=$subj }
  } catch {
    return @{ Status="Unknown"; IsMicrosoft=$false; Subject="" }
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

      $missing = -not (Test-Path -LiteralPath $exe)
      $writable = Test-UserWritablePath $exe

      if ($missing -or $writable) {
        $out += [pscustomobject]@{
          Kind="Service"
          Name=$s.Name
          Detail=($s.DisplayName + "")
          FilePath=$exe
          Reason=($(if($missing){"MissingBinary"}else{"UserWritablePath"}))
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
          $exe = ""
          if ($a.Execute) { $exe = Extract-ExePath ($a.Execute + "") }
          $exe = Resolve-WindowsPath $exe
          if (-not $exe) { continue }

          $missing = -not (Test-Path -LiteralPath $exe)
          $writable = Test-UserWritablePath $exe

          if ($missing -or $writable) {
            $out += [pscustomobject]@{
              Kind="ScheduledTask"
              Name=($t.TaskPath + $t.TaskName)
              Detail=""
              FilePath=$exe
              Reason=($(if($missing){"MissingBinary"}else{"UserWritablePath"}))
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

      # Only flag when the executable is missing OR user-writable OR not under typical system/program paths
      $missing = ($exe -and (-not (Test-Path -LiteralPath $exe)))
      $writable = ($exe -and (Test-UserWritablePath $exe))
      $nonSystem = ($exe -and (-not (Test-ProbablySystemPath $exe)))

      if ($missing -or $writable -or $nonSystem) {
        $out += [pscustomobject]@{
          Kind="WMI"
          Name=("Filter=" + ($f.Name + "") + " Consumer=" + ($c.Name + ""))
          Detail=("CommandLine=" + $cmd)
          FilePath=($exe + "")
          Reason=($(if($missing){"MissingBinary"}elseif($writable){"UserWritablePath"}else{"NonSystemPath"}))
        }
      }
    }
  } catch {}

  # de-dup by filepath + kind + name
  $out | Sort-Object Kind,Name,FilePath -Unique
}

function Get-RootkitDriverFindings {
  $out = @()

  try {
    $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq "Running" }
    foreach ($d in $drivers) {
      $raw = ($d.PathName + "")
      if (-not $raw) { continue }

      $p = Resolve-WindowsPath (Extract-ExePath $raw)

      # Driver paths can be "\SystemRoot\System32\drivers\foo.sys" or "system32\drivers\foo.sys"
      # After Resolve-WindowsPath, it should be a file path.
      if (-not $p) { continue }

      # ensure .sys only
      if (-not $p.ToLowerInvariant().EndsWith(".sys")) { continue }

      $missing = -not (Test-Path -LiteralPath $p)
      $writable = Test-UserWritablePath $p
      $sig = Get-SignatureSummary $p

      # Heuristics:
      # - Strong: missing or user-writable
      # - Medium: non-system path AND signature not Valid
      $nonSystem = -not (Test-ProbablySystemPath $p)
      $badSig = ($sig.Status -ne "Valid")

      $susp = $false
      $reason = ""

      if ($missing) { $susp = $true; $reason = "MissingDriverFile" }
      elseif ($writable) { $susp = $true; $reason = "UserWritablePath" }
      elseif ($nonSystem -and $badSig) { $susp = $true; $reason = "NonSystemPath+UntrustedSignature" }

      if ($susp) {
        $out += [pscustomobject]@{
          Kind="Driver"
          Name=($d.Name + "")
          Detail=("State=" + ($d.State + "") + " Start=" + ($d.StartMode + ""))
          FilePath=$p
          SigStatus=$sig.Status
          IsMicrosoft=$sig.IsMicrosoft
          Reason=$reason
        }
      }
    }
  } catch {}

  $out | Sort-Object FilePath,Name -Unique
}

function Get-ListeningSockets {
  $out = @()

  # Prefer Get-NetTCPConnection if available
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    try {
      $out = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
          LocalAddress = $_.LocalAddress
          LocalPort    = $_.LocalPort
          PID          = $_.OwningProcess
        }
      }
      return $out
    } catch {}
  }

  # Fallback: netstat parsing
  try {
    $lines = & netstat.exe -ano -p tcp 2>$null
    foreach ($ln in $lines) {
      # Example: TCP    0.0.0.0:135     0.0.0.0:0    LISTENING    1234
      if ($ln -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
        $out += [pscustomobject]@{
          LocalAddress = $Matches[1]
          LocalPort    = [int]$Matches[2]
          PID          = [int]$Matches[3]
        }
      }
    }
  } catch {}

  return $out
}

function Get-ProcessPathByPid([int]$pid) {
  if ($pid -le 0) { return "" }

  # Prefer CIM (ExecutablePath is more reliable for services)
  try {
    $p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $pid) -ErrorAction Stop
    if ($p -and $p.ExecutablePath) { return (Resolve-WindowsPath ($p.ExecutablePath + "")) }
  } catch {}

  # Fallback Get-Process
  try {
    $p2 = Get-Process -Id $pid -ErrorAction Stop
    try { return (Resolve-WindowsPath ($p2.Path + "")) } catch {}
  } catch {}

  return ""
}

function Get-BackdoorFindings {
  $out = @()
  $listeners = Get-ListeningSockets
  foreach ($l in $listeners) {
    $pid = [int]$l.PID
    $img = Get-ProcessPathByPid $pid
    if (-not $img) { continue }

    # heuristic: listening + user-writable binary path
    if (Test-UserWritablePath $img) {
      $out += [pscustomobject]@{
        Kind="Listen"
        Name=("PID=" + $pid + " " + ($l.LocalAddress + ":" + $l.LocalPort))
        Detail=""
        FilePath=$img
        Reason="ListeningFromUserWritablePath"
      }
    }
  }
  $out | Sort-Object FilePath,Name -Unique
}

# ---------------- Main ----------------
if (-not (Test-IsAdmin)) {
  Write-Host "[ERROR] Run as Administrator"
  exit 1
}

if ($ShowSystemInfo) {
  try {
    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
  } catch { $os = "Unknown" }
  Write-Host "============================================================"
  Write-Host "           Rootkit Detection Scanner v.1.0-rev2 (Windows)"
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

if ($hidden.Count -gt 0 -or $rootkit.Count -gt 0 -or $backdoor.Count -gt 0) {
  Write-Host "============================================================"
  Write-Host "                        SCAN RESULT"
  Write-Host "============================================================"
}

if ($hidden.Count -gt 0) {
  $exitCodes += 10
  Write-Host "[Alert] Hidden Entry Found!"
  foreach ($f in $hidden) {
    if ($f.FilePath) {
      Write-Host ("[!] FilePath: {0}" -f $f.FilePath)
      Write-Host (" - Source: {0}" -f $f.Kind)
      if ($f.Name)   { Write-Host (" - Name: {0}" -f $f.Name) }
      if ($f.Detail) { Write-Host (" - Detail: {0}" -f $f.Detail) }
      if ($f.Reason) { Write-Host (" - Reason: {0}" -f $f.Reason) }
      Write-FileDetails $f.FilePath
    } else {
      # If we can't extract a path, still keep minimal evidence without breaking the "FilePath-first" convention
      Write-Host ("[!] FilePath: N/A")
      Write-Host (" - Source: {0}" -f $f.Kind)
      if ($f.Name)   { Write-Host (" - Name: {0}" -f $f.Name) }
      if ($f.Detail) { Write-Host (" - Detail: {0}" -f $f.Detail) }
      if ($f.Reason) { Write-Host (" - Reason: {0}" -f $f.Reason) }
    }
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
    Write-Host (" - SigStatus: {0} (Microsoft={1})" -f $d.SigStatus, $d.IsMicrosoft)
    Write-Host (" - Reason: {0}" -f $d.Reason)
    Write-FileDetails $d.FilePath
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
    Write-FileDetails $b.FilePath
  }
}

if ($exitCodes.Count -eq 0) { exit 0 }
if ($exitCodes.Count -ge 2) { exit 40 }
exit ($exitCodes | Sort-Object | Select-Object -Last 1)
