<#
.SYNOPSIS
  Apply Windows Advanced Audit Policy from a simple rules file (auditpolicy.rules).

.DESCRIPTION
  This script replaces the old "auditpolicy.csv + AuditPolicy.cpp" approach.

  - auditpolicy.rules : Desired-state rules (by Subcategory GUID)
  - auditpolicy.ps1   : Applies rules using auditpol.exe, with optional backup/verify

  Rule format (either of the following):

    1) Pipe format (recommended, consistent with other *.rules files)
       id|{GUID}|<SuccessSetting>|<FailureSetting>|note

    2) Whitespace format (legacy / quick)
       {GUID} <SuccessSetting> <FailureSetting>  # optional comment

  Settings:
    enable | disable | keep
    (aliases: on/off, 1/0, yes/no, true/false, -)

  Example (pipe):
    ap_system_integrity|{0CCE9212-69AE-11D9-BED3-505054503030}|enable|enable|시스템/시스템 무결성

Example (whitespace):
    {0CCE9212-69AE-11D9-BED3-505054503030} enable enable  # 시스템/시스템 무결성
    {0CCE9210-69AE-11D9-BED3-505054503030} enable keep    # 시스템/보안 상태 변경

.NOTES
  - Requires Administrator rights.
  - Uses auditpol.exe (built-in on supported Windows versions).

#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [ValidateSet('Apply','Backup','Restore','ExportRules')]
  [string]$Action = 'Apply',

  [string]$BaseDir = (Split-Path -Parent $PSCommandPath),
  [string]$RulesPath = (Join-Path (Split-Path -Parent $PSCommandPath) 'auditpolicy.rules'),

  # Backup output directory (CSV backups will be created here)
  [string]$BackupDir = (Join-Path (Split-Path -Parent $PSCommandPath) 'backup'),

  # If set, write a single stable backup file and do not overwrite it
  [switch]$BackupOnce,

  # If set (and typically used with -BackupOnce), skip applying when a stable backup already exists
  # (mimics the old AuditPolicy.cpp behavior: apply only once)
  [switch]$ApplyOnce,

  # Skip backup entirely (not recommended unless you have other backups)
  [switch]$NoBackup,

  # Verify applied settings by exporting current policy to a temp CSV and checking rule compliance
  [switch]$Verify,

  # Restore requires a backup CSV path
  [string]$RestoreFrom,

  # ExportRules will write a rules file reflecting the CURRENT system policy
  [string]$ExportRulesTo,

  # Log file path (append mode)
  [string]$LogPath = (Join-Path (Split-Path -Parent $PSCommandPath) 'auditpolicy.apply.log'),

  # Batch size for auditpol invocations
  [ValidateRange(1,200)]
  [int]$BatchSize = 25
)

# If BaseDir was specified but RulesPath/BackupDir/LogPath were not explicitly provided,
# treat them as relative to BaseDir (agent/installer friendly).
if (-not $PSBoundParameters.ContainsKey('RulesPath')) { $RulesPath = Join-Path $BaseDir 'auditpolicy.rules' }
if (-not $PSBoundParameters.ContainsKey('BackupDir')) { $BackupDir = Join-Path $BaseDir 'backup' }
if (-not $PSBoundParameters.ContainsKey('LogPath')) { $LogPath = Join-Path $BaseDir 'auditpolicy.apply.log' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
  )
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  Write-Host $line
  try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 } catch { }
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Admin {
  if (Test-IsAdmin) { return }

  Write-Log "Not running as Administrator. Relaunching elevated..." 'WARN'

  # Rebuild argument list from bound parameters so switches like -Verify are preserved.
  $argList = New-Object System.Collections.Generic.List[string]
  $argList.Add('-NoProfile') | Out-Null
  $argList.Add('-ExecutionPolicy') | Out-Null
  $argList.Add('Bypass') | Out-Null
  $argList.Add('-File') | Out-Null
  $argList.Add("`"$PSCommandPath`"") | Out-Null

  foreach ($k in $script:PSBoundParameters.Keys) {
    $v = $script:PSBoundParameters[$k]

    if ($v -is [System.Management.Automation.SwitchParameter]) {
      if ($v.IsPresent) { $argList.Add("-$k") | Out-Null }
      continue
    }

    if ($v -is [bool]) {
      if ($v) { $argList.Add("-$k") | Out-Null }
      continue
    }

    if ($v -is [array]) {
      foreach ($item in $v) {
        $argList.Add("-$k") | Out-Null
        $argList.Add("`"$item`"") | Out-Null
      }
      continue
    }

    if ($null -ne $v -and ($v.ToString().Length -gt 0)) {
      $argList.Add("-$k") | Out-Null
      $argList.Add("`"$v`"") | Out-Null
    }
  }

  # Preserve any additional unbound arguments (rare)
  foreach ($u in $script:args) {
    if ($null -ne $u -and $u.ToString().Length -gt 0) { $argList.Add($u) | Out-Null }
  }

  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argList.ToArray()) | Out-Null
  exit 0
}


function Get-AuditPolPath {
  $p = Join-Path $env:SystemRoot 'System32\auditpol.exe'
  if (-not (Test-Path -LiteralPath $p)) { throw "auditpol.exe not found at $p" }
  return $p
}

function Normalize-Setting {
  param([string]$Value)
  if ($null -eq $Value) { return 'keep' }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    'enable' { 'enable' }
    'on'     { 'enable' }
    '1'      { 'enable' }
    'yes'    { 'enable' }
    'true'   { 'enable' }

    'disable' { 'disable' }
    'off'     { 'disable' }
    '0'       { 'disable' }
    'no'      { 'disable' }
    'false'   { 'disable' }

    'keep' { 'keep' }
    '-'    { 'keep' }
    default { throw "Invalid setting value: '$Value' (allowed: enable|disable|keep)" }
  }
}

function Read-Rules {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Rules file not found: $Path" }

  $rules = New-Object System.Collections.Generic.List[object]
  $lineNo = 0

  foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
    $lineNo++
    $line = $raw.Trim()

    if ($line.Length -eq 0) { continue }
    if ($line.StartsWith('#')) { continue }

    # remove trailing comments (only when '#' is preceded by whitespace)
    $line2 = ($line -split '\s+#', 2)[0].Trim()
    if ($line2.Length -eq 0) { continue }

    $id   = $null
    $note = $null

    if ($line2 -like '*|*') {
      # Pipe format: id|guid|success|failure|note
      $parts = $line2.Split('|')
      if ($parts.Count -lt 4) { throw "Invalid rule (pipe format) at line $lineNo: '$raw'" }

      $id   = $parts[0].Trim()
      $guid = $parts[1].Trim()
      $succ = Normalize-Setting $parts[2]
      $fail = Normalize-Setting $parts[3]
      if ($parts.Count -ge 5) {
        $note = (($parts[4..($parts.Count-1)]) -join '|').Trim()
      }
    } else {
      # Whitespace format: {GUID} success failure
      $parts = $line2 -split '\s+'
      if ($parts.Count -lt 3) { throw "Invalid rule (whitespace format) at line $lineNo: '$raw'" }

      $guid = $parts[0].Trim()
      $succ = Normalize-Setting $parts[1]
      $fail = Normalize-Setting $parts[2]
    }

    if ($guid -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') {
      throw "Invalid GUID format at line $lineNo: '$guid'"
    }

    $rules.Add([pscustomobject]@{
      Line    = $lineNo
      Id      = $id
      Guid    = $guid
      Success = $succ
      Failure = $fail
      Note    = $note
      Raw     = $raw
    }) | Out-Null
  }

  # de-duplicate by GUID (last rule wins)
  $byGuid = @{}
  foreach ($r in $rules) { $byGuid[$r.Guid] = $r }
  return $byGuid.Values | Sort-Object Guid
}


function Ensure-Dir {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Backup-AuditPolicy {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [switch]$Once
  )
  Ensure-Dir $OutDir

  if ($Once) {
    $outFile = Join-Path $OutDir 'auditpolicy.backup.csv'
    if (Test-Path -LiteralPath $outFile) {
      Write-Log "BackupOnce enabled and backup already exists: $outFile" 'INFO'
      return $outFile
    }
  } else {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $outFile = Join-Path $OutDir "auditpolicy.backup.$stamp.csv"
  }

  if ($PSCmdlet.ShouldProcess($outFile, 'auditpol /backup')) {
    Write-Log "Backing up current audit policy to: $outFile" 'INFO'
    $out = & $AuditPol '/backup' "/file:$outFile" 2>&1
    $rc = $LASTEXITCODE
    if ($out) { Write-Log ($out | Out-String).Trim() 'DEBUG' }
    if ($rc -ne 0) { throw "auditpol /backup failed (exit=$rc)" }
  }

  return $outFile
}

function Restore-AuditPolicy {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$FromFile
  )
  if (-not (Test-Path -LiteralPath $FromFile)) { throw "Restore file not found: $FromFile" }
  if ($PSCmdlet.ShouldProcess($FromFile, 'auditpol /restore')) {
    Write-Log "Restoring audit policy from: $FromFile" 'WARN'
    $out = & $AuditPol '/restore' "/file:$FromFile" 2>&1
    $rc = $LASTEXITCODE
    if ($out) { Write-Log ($out | Out-String).Trim() 'DEBUG' }
    if ($rc -ne 0) { throw "auditpol /restore failed (exit=$rc)" }
  }
}

function Invoke-AuditpolSet {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string[]]$Guids,
    [ValidateSet('enable','disable')][string]$SuccessSetting,
    [ValidateSet('enable','disable')][string]$FailureSetting
  )
  if ($Guids.Count -eq 0) { return }
  $subcat = ($Guids -join ',')

  $args = New-Object System.Collections.Generic.List[string]
  $args.Add('/set') | Out-Null
  $args.Add("/subcategory:$subcat") | Out-Null
  if ($PSBoundParameters.ContainsKey('SuccessSetting')) { $args.Add("/success:$SuccessSetting") | Out-Null }
  if ($PSBoundParameters.ContainsKey('FailureSetting')) { $args.Add("/failure:$FailureSetting") | Out-Null }

  $desc = "subcategory=$($Guids.Count) success=$SuccessSetting failure=$FailureSetting"
  if ($PSCmdlet.ShouldProcess($desc, 'auditpol /set')) {
    Write-Log "Applying: $desc" 'INFO'
    $out = & $AuditPol @args 2>&1
    $rc = $LASTEXITCODE
    if ($out) { Write-Log ($out | Out-String).Trim() 'DEBUG' }
    if ($rc -ne 0) { throw "auditpol /set failed (exit=$rc): $desc" }
  }
}

function Split-Batches {
  param([string[]]$Items, [int]$Size)
  $batches = New-Object System.Collections.Generic.List[object]
  for ($i=0; $i -lt $Items.Count; $i += $Size) {
    $end = [Math]::Min($i + $Size - 1, $Items.Count - 1)
    $batches.Add($Items[$i..$end]) | Out-Null
  }
  return $batches
}

function Get-CurrentPolicyMap {
  param([Parameter(Mandatory=$true)][string]$AuditPol)
  $tmp = Join-Path $env:TEMP ("auditpolicy.current.{0}.csv" -f ([Guid]::NewGuid().ToString('N')))
  try {
    & $AuditPol '/backup' "/file:$tmp" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol backup failed" }

    # Import-Csv with local ANSI code page (auditpol backup is locale-dependent)
    $rows = Import-Csv -LiteralPath $tmp -Encoding Default
    if (-not $rows -or $rows.Count -eq 0) { throw "Empty auditpol backup CSV" }

    $cols = $rows[0].PSObject.Properties.Name
    $guidCol = ($cols | Where-Object { $_ -match 'GUID' })[0]
    if (-not $guidCol) { throw "Could not find GUID column in backup CSV" }

    $valueCol = ($cols | Where-Object { $_ -match 'Setting Value|설정 값' })[0]
    if (-not $valueCol) {
      # fallback: last column
      $valueCol = $cols[-1]
    }

    $map = @{}
    foreach ($r in $rows) {
      $g = ($r.$guidCol).Trim()
      $v = [int]($r.$valueCol)
      $map[$g] = $v
    }
    return $map
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue | Out-Null
  }
}

function Test-RuleCompliance {
  param(
    [Parameter(Mandatory=$true)][object[]]$Rules,
    [Parameter(Mandatory=$true)][hashtable]$CurrentMap
  )

  $ok = $true
  foreach ($r in $Rules) {
    if ($r.Success -eq 'keep' -and $r.Failure -eq 'keep') { continue }
    if (-not $CurrentMap.ContainsKey($r.Guid)) {
      Write-Log "Verify: GUID not found in current policy map: $($r.Guid)" 'WARN'
      $ok = $false
      continue
    }
    $val = [int]$CurrentMap[$r.Guid]  # 0=None, 1=Success, 2=Failure, 3=Success+Failure

    $succEnabled = ($val -band 1) -eq 1
    $failEnabled = ($val -band 2) -eq 2

    $succOk = $true
    $failOk = $true
    if ($r.Success -eq 'enable')  { $succOk = $succEnabled }
    if ($r.Success -eq 'disable') { $succOk = -not $succEnabled }
    if ($r.Failure -eq 'enable')  { $failOk = $failEnabled }
    if ($r.Failure -eq 'disable') { $failOk = -not $failEnabled }

    if (-not ($succOk -and $failOk)) {
      Write-Log ("Verify FAIL: {0} success={1} failure={2} (current={3})" -f $r.Guid, $r.Success, $r.Failure, $val) 'ERROR'
      $ok = $false
    } else {
      Write-Log ("Verify OK  : {0} success={1} failure={2} (current={3})" -f $r.Guid, $r.Success, $r.Failure, $val) 'INFO'
    }
  }
  return $ok
}

function Export-RulesFromCurrent {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$OutFile
  )
  $tmp = Join-Path $env:TEMP ("auditpolicy.export.{0}.csv" -f ([Guid]::NewGuid().ToString('N')))
  try {
    & $AuditPol '/backup' "/file:$tmp" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol backup failed" }

    $rows = Import-Csv -LiteralPath $tmp -Encoding Default
    $cols = $rows[0].PSObject.Properties.Name
    $guidCol = ($cols | Where-Object { $_ -match 'GUID' })[0]
    $catCol  = ($cols | Where-Object { $_ -match 'Policy Target|정책 대상' })[0]
    $subCol  = ($cols | Where-Object { $_ -match 'Subcategory|하위 범주' })[0]
    $valCol  = ($cols | Where-Object { $_ -match 'Setting Value|설정 값' })[0]
    if (-not $valCol) { $valCol = $cols[-1] }

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('# auditpolicy.rules (exported from current system)') | Out-Null
    $out.Add('# Rule format: id|subcategory_guid|success|failure|note') | Out-Null
    $out.Add('# Settings: enable | disable | keep') | Out-Null
    $out.Add('') | Out-Null

    foreach ($r in $rows) {
      $g = ($r.$guidCol).Trim()
      $v = [int]($r.$valCol)
      $succ = if (($v -band 1) -eq 1) { 'enable' } else { 'disable' }
      $fail = if (($v -band 2) -eq 2) { 'enable' } else { 'disable' }

      $comment = ''
      if ($catCol -and $subCol) {
        $comment = "  # $($r.$catCol)/$($r.$subCol)"
      } elseif ($subCol) {
        $comment = "  # $($r.$subCol)"
      }

      $gidShort = ($g -replace '[\{\}\-]','').Substring(0,8)
      $rid = "ap_$gidShort"
      $note2 = ''
      if ($catCol -and $subCol) { $note2 = "$($r.$catCol)/$($r.$subCol)" }
      elseif ($subCol) { $note2 = "$($r.$subCol)" }
      $out.Add("$rid|$g|$succ|$fail|$note2") | Out-Null
    }

    $dir = Split-Path -Parent $OutFile
    if ($dir) { Ensure-Dir $dir }
    $out | Set-Content -LiteralPath $OutFile -Encoding UTF8
    Write-Log "Exported current policy to rules file: $OutFile" 'INFO'
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue | Out-Null
  }
}

# -----------------------------
# Main
# -----------------------------
Ensure-Admin
$auditpol = Get-AuditPolPath

Write-Log "Action=$Action BaseDir=$BaseDir RulesPath=$RulesPath BackupDir=$BackupDir" 'INFO'

switch ($Action) {
  'Backup' {
    if ($NoBackup) { throw "-NoBackup cannot be used with Action=Backup" }
    Backup-AuditPolicy -AuditPol $auditpol -OutDir $BackupDir -Once:$BackupOnce | Out-Null
    break
  }

  'Restore' {
    if (-not $RestoreFrom) { throw "Action=Restore requires -RestoreFrom <backup.csv>" }
    Restore-AuditPolicy -AuditPol $auditpol -FromFile $RestoreFrom
    break
  }

  'ExportRules' {
    if (-not $ExportRulesTo) {
      $ExportRulesTo = (Join-Path $BaseDir 'auditpolicy.exported.rules')
    }
    Export-RulesFromCurrent -AuditPol $auditpol -OutFile $ExportRulesTo
    break
  }

  default {
    # Apply
    if ($ApplyOnce) {
      $markerBackup = Join-Path $BackupDir 'auditpolicy.backup.csv'
      if (Test-Path -LiteralPath $markerBackup) {
        Write-Log "ApplyOnce: stable backup exists ($markerBackup). Skipping apply." 'INFO'
        break
      }
    }

    $rules = Read-Rules -Path $RulesPath
    Write-Log "Loaded rules: $($rules.Count)" 'INFO'

    if (-not $NoBackup) {
      Backup-AuditPolicy -AuditPol $auditpol -OutDir $BackupDir -Once:$BackupOnce | Out-Null
    } else {
      Write-Log "Skipping backup (-NoBackup)" 'WARN'
    }

    # Build 4 groups (success enable/disable, failure enable/disable)
    $succEnable = @()
    $succDisable= @()
    $failEnable = @()
    $failDisable= @()

    foreach ($r in $rules) {
      if ($r.Success -eq 'enable')  { $succEnable += $r.Guid }
      if ($r.Success -eq 'disable') { $succDisable += $r.Guid }
      if ($r.Failure -eq 'enable')  { $failEnable += $r.Guid }
      if ($r.Failure -eq 'disable') { $failDisable += $r.Guid }
    }

    foreach ($batch in (Split-Batches -Items $succEnable -Size $BatchSize)) {
      Invoke-AuditpolSet -AuditPol $auditpol -Guids $batch -SuccessSetting enable
    }
    foreach ($batch in (Split-Batches -Items $succDisable -Size $BatchSize)) {
      Invoke-AuditpolSet -AuditPol $auditpol -Guids $batch -SuccessSetting disable
    }
    foreach ($batch in (Split-Batches -Items $failEnable -Size $BatchSize)) {
      Invoke-AuditpolSet -AuditPol $auditpol -Guids $batch -FailureSetting enable
    }
    foreach ($batch in (Split-Batches -Items $failDisable -Size $BatchSize)) {
      Invoke-AuditpolSet -AuditPol $auditpol -Guids $batch -FailureSetting disable
    }

    Write-Log "Apply completed." 'INFO'

    if ($Verify) {
      Write-Log "Verifying rules..." 'INFO'
      $map = Get-CurrentPolicyMap -AuditPol $auditpol
      $ok = Test-RuleCompliance -Rules $rules -CurrentMap $map
      if (-not $ok) { throw "Verification failed: current policy does not match rules" }
      Write-Log "Verification OK." 'INFO'
    }

    break
  }
}

exit 0