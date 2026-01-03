<#
.SYNOPSIS
  Declarative Windows Audit Policy manager (Advanced Audit Policy + auditpol options).

.DESCRIPTION
  This script is the next-step evolution of the old "auditpolicy.csv + AuditPolicy.cpp" approach.

  - auditpolicy.rules : Desired-state rules (declarative)
  - auditpolicy.ps1   : Applies rules using auditpol.exe, with optional backup/verify/evidence

  The rules file supports two kinds of records:

    1) Options (key/value)
       option|<key>|<value>|<note?>

       Recognized keys:
         enforcement = strict|merge
         backup      = once|always|none
         verify      = true|false
         apply_once  = true|false
         batch_size  = <int>
         evidence_export = enable|disable
         evidence_dir    = <path>
         force_subcategory_override = enable|disable|keep
         auditpol.option.<OptionName> = enable|disable
           (CrashOnAuditFail, FullPrivilegeAuditing, AuditBaseObjects, AuditBaseDirectories)

    2) Subcategory rules
       id|{GUID}|<SuccessSetting>|<FailureSetting>|note

       Success/Failure settings:
         enable | disable | keep
         (aliases: on/off, 1/0, yes/no, true/false, -)

  Notes
  - Requires Administrator rights.
  - Uses auditpol.exe (built-in on supported Windows versions).
  - If you manage Advanced Audit Policy via GPO, enable:
      "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
    to prevent legacy category policy from overriding subcategory settings.

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

  # Verify applied settings by exporting current policy and checking rule compliance
  [switch]$Verify,

  # Restore requires a backup CSV path
  [string]$RestoreFrom,

  # ExportRules will write a rules file reflecting the CURRENT system policy
  [string]$ExportRulesTo,

  # Log file path (append mode)
  [string]$LogPath = (Join-Path (Split-Path -Parent $PSCommandPath) 'auditpolicy.apply.log'),

  # Batch size for auditpol invocations
  [ValidateRange(1,200)]
  [int]$BatchSize = 25,

  # Enforcement mode
  # - Strict: apply both enable and disable exactly as declared
  # - Merge : apply only enables (never disables) - useful for gradual rollout
  [ValidateSet('Strict','Merge')]
  [string]$Enforcement = 'Strict',

  # Evidence export (post-apply snapshot)
  [string]$EvidenceDir = (Join-Path (Split-Path -Parent $PSCommandPath) 'evidence'),
  [switch]$EvidenceExport,
  [switch]$NoEvidenceExport,

  # Ignore option|... lines in rules file
  [switch]$IgnoreRuleOptions
)

# If BaseDir was specified but RulesPath/BackupDir/LogPath/EvidenceDir were not explicitly provided,
# treat them as relative to BaseDir (agent/installer friendly).
if (-not $PSBoundParameters.ContainsKey('RulesPath'))    { $RulesPath    = Join-Path $BaseDir 'auditpolicy.rules' }
if (-not $PSBoundParameters.ContainsKey('BackupDir'))    { $BackupDir    = Join-Path $BaseDir 'backup' }
if (-not $PSBoundParameters.ContainsKey('LogPath'))      { $LogPath      = Join-Path $BaseDir 'auditpolicy.apply.log' }
if (-not $PSBoundParameters.ContainsKey('EvidenceDir'))  { $EvidenceDir  = Join-Path $BaseDir 'evidence' }

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

  foreach ($u in $script:args) {
    if ($null -ne $u -and $u.ToString().Length -gt 0) { $argList.Add($u) | Out-Null }
  }

  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argList.ToArray()) | Out-Null
  exit 0
}

function Ensure-Dir {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
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

function Normalize-Bool {
  param([string]$Value, [bool]$Default=$false)
  if ($null -eq $Value) { return $Default }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    '1' { return $true }
    'true' { return $true }
    'yes' { return $true }
    'enable' { return $true }
    'on' { return $true }

    '0' { return $false }
    'false' { return $false }
    'no' { return $false }
    'disable' { return $false }
    'off' { return $false }

    default { return $Default }
  }
}

function Normalize-Enforcement {
  param([string]$Value)
  if ($null -eq $Value) { return 'Strict' }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    'strict' { 'Strict' }
    'merge'  { 'Merge' }
    default  { throw "Invalid enforcement: '$Value' (allowed: strict|merge)" }
  }
}

function Normalize-BackupMode {
  param([string]$Value)
  if ($null -eq $Value) { return 'always' }
  $v = $Value.Trim().ToLowerInvariant()
  switch ($v) {
    'always' { 'always' }
    'once'   { 'once' }
    'none'   { 'none' }
    default  { throw "Invalid backup mode: '$Value' (allowed: once|always|none)" }
  }
}

function Resolve-RelativePath {
  param([Parameter(Mandatory=$true)][string]$Path)
  if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
  return (Join-Path $BaseDir $Path)
}

function Read-FileTextAuto {
  param([Parameter(Mandatory=$true)][string]$Path)

  $bytes = [System.IO.File]::ReadAllBytes($Path)
  if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }

  # BOM-aware decoding (auditpol /backup output is locale-dependent and may be ANSI without BOM)
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    $enc = [System.Text.Encoding]::UTF8
    $offset = 3
  } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
    $enc = [System.Text.Encoding]::Unicode   # UTF-16LE
    $offset = 2
  } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
    $enc = [System.Text.Encoding]::BigEndianUnicode  # UTF-16BE
    $offset = 2
  } else {
    # Many rule files are stored as UTF-8 without BOM (common for Git + PowerShell 7).
    # Try strict UTF-8 first; if it fails, fall back to the system ANSI code page.
    try {
      $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
      $text = $utf8Strict.GetString($bytes)
      $text = $text -replace "`0", ''
      return $text
    } catch {
      $enc = [System.Text.Encoding]::Default
      $offset = 0
    }
  }

  $text = $enc.GetString($bytes, $offset, $bytes.Length - $offset)
  # Defensive cleanup for occasional null bytes
  $text = $text -replace "`0", ''
  return $text
}

function Get-CsvDelimiterFromText {
  param([Parameter(Mandatory=$true)][string]$Text)

  $first = ($Text -split "`r?`n", 2)[0]
  if ($first -match ';' -and $first -notmatch ',') { return ';' }
  return ','
}

function ConvertFrom-CsvText {
  param([Parameter(Mandatory=$true)][string]$Text)

  $t = $Text.Trim()
  if ($t.Length -eq 0) { return @() }

  $delim = Get-CsvDelimiterFromText -Text $t
  $rows = ConvertFrom-Csv -InputObject $t -Delimiter $delim
  return @($rows)
}

function Read-AuditpolCsvFile {
  param([Parameter(Mandatory=$true)][string]$Path)

  $text = Read-FileTextAuto -Path $Path
  return ConvertFrom-CsvText -Text $text
}

function Normalize-GuidString {
  param([string]$GuidText)

  if ($null -eq $GuidText) { return $null }
  $s = $GuidText.ToString().Trim()
  if ($s.Length -eq 0) { return $null }

  try {
    # Accept with/without braces; normalize to "{XXXXXXXX-....}" uppercase
    $g = [Guid]($s.Trim('{}'))
    return ('{' + $g.ToString().ToUpperInvariant() + '}')
  } catch {
    return $null
  }
}

function Detect-AuditpolCsvColumns {
  param([Parameter(Mandatory=$true)][object[]]$Rows)

  if (-not $Rows -or $Rows.Count -eq 0) { throw "Empty CSV rows" }

  $cols = $Rows[0].PSObject.Properties.Name
  if (-not $cols -or $cols.Count -lt 2) { throw "Unexpected CSV format (no columns)" }

  $guidRegex = '^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$'

  # Find the GUID column by scoring values that look like GUIDs.
  $bestGuidCol = $null
  $bestGuidScore = -1
  foreach ($c in $cols) {
    $score = 0
    foreach ($r in $Rows) {
      $v = $r.$c
      if ($null -eq $v) { continue }
      $s = $v.ToString().Trim()
      if ($s -match $guidRegex) { $score++ }
    }
    if ($score -gt $bestGuidScore) {
      $bestGuidScore = $score
      $bestGuidCol = $c
    }
  }

  # Find the numeric "Setting Value" column by scoring integer-like fields.
  $bestValCol = $null
  $bestValScore = -1
  foreach ($c in $cols) {
    if ($c -eq $bestGuidCol) { continue }
    $score = 0
    foreach ($r in $Rows) {
      $v = $r.$c
      if ($null -eq $v) { continue }
      $s = $v.ToString().Trim()
      if ($s -match '^\d+$') { $score++ }
    }
    if ($score -gt $bestValScore) {
      $bestValScore = $score
      $bestValCol = $c
    }
  }
  if (-not $bestValCol) { $bestValCol = $cols[-1] }

  # For notes only: auditpol report format is consistently:
  # Computer Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting, Setting Value
  $policyTargetCol = $null
  $subcategoryCol  = $null
  if ($cols.Count -ge 2) { $policyTargetCol = $cols[1] }
  if ($cols.Count -ge 3) { $subcategoryCol  = $cols[2] }

  return @{
    Cols = $cols
    GuidCol = $bestGuidCol
    ValueCol = $bestValCol
    PolicyTargetCol = $policyTargetCol
    SubcategoryCol = $subcategoryCol
  }
}

function Get-AuditpolOptionValue {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$OptionName
  )

  # Use /r (CSV) and parse numeric value, so we don't depend on localized text like "Enabled/Disabled".
  $raw = & $AuditPol '/get' "/option:$OptionName" '/r' 2>&1
  if ($LASTEXITCODE -ne 0) { throw "auditpol get option failed: $OptionName" }

  $text = ($raw -join "`r`n")
  $rows = ConvertFrom-CsvText -Text $text
  if (-not $rows -or $rows.Count -eq 0) { throw "Unexpected CSV output for option: $OptionName" }

  $info = Detect-AuditpolCsvColumns -Rows $rows
  $valCol = $info.ValueCol
  $vText = $rows[0].$valCol
  if ($null -eq $vText) { return $null }

  $s = $vText.ToString().Trim()
  if ($s -match '^\d+$') { return [int]$s }
  try { return [int]$s } catch { return $null }
}

function Get-AuditpolOptionsMap {
  param([Parameter(Mandatory=$true)][string]$AuditPol)

  $m = @{}
  foreach ($name in @('CrashOnAuditFail','FullPrivilegeAuditing','AuditBaseObjects','AuditBaseDirectories')) {
    try {
      $v = Get-AuditpolOptionValue -AuditPol $AuditPol -OptionName $name
      if ($null -ne $v) { $m["auditpol.option.$name"] = $v }
    } catch {
      Write-Log "WARN: Unable to query auditpol option '$name': $($_.Exception.Message)" 'WARN'
    }
  }
  return $m
}

function Read-Rules {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Rules file not found: $Path" }

  $rules = New-Object System.Collections.Generic.List[object]
  $options = @{}
  $lineNo = 0

    $text = Read-FileTextAuto -Path $Path
  $lines = $text -split "`r?`n"

  foreach ($raw in $lines) {
    $lineNo++
    $line = $raw.Trim()
    if ($line.Length -eq 0) { continue }
    if ($line.StartsWith('#')) { continue }

    # remove trailing comments (only when '#' is preceded by whitespace)
    $line2 = ($line -split '\s+#', 2)[0].Trim()
    if ($line2.Length -eq 0) { continue }

    if ($line2 -like '*|*') {
      $parts = $line2.Split('|')
      if ($parts.Count -lt 2) { continue }

      $recType = $parts[0].Trim().ToLowerInvariant()
      if ($recType -eq 'option' -or $recType -eq '@option') {
        if ($parts.Count -lt 3) { throw "Invalid option record at line $lineNo: '$raw'" }
        $key = $parts[1].Trim()
        $val = $parts[2].Trim()
        if ($key.Length -eq 0) { throw "Empty option key at line $lineNo" }
        $options[$key] = $val
        continue
      }

      # Subcategory rule: id|guid|success|failure|note
      if ($parts.Count -lt 4) { throw "Invalid rule (pipe format) at line $lineNo: '$raw'" }
      $id   = $parts[0].Trim()
      $guid = $parts[1].Trim()
      $succ = Normalize-Setting $parts[2]
      $fail = Normalize-Setting $parts[3]
      $note = $null
      if ($parts.Count -ge 5) {
        $note = (($parts[4..($parts.Count-1)]) -join '|').Trim()
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

      continue
    }

    # Whitespace legacy rule: {GUID} success failure
    $parts = $line2 -split '\s+'
    if ($parts.Count -ge 3 -and $parts[0] -match '^\{[0-9A-Fa-f\-]{36}\}$') {
      $guid = $parts[0].Trim()
      $succ = Normalize-Setting $parts[1]
      $fail = Normalize-Setting $parts[2]
      $rules.Add([pscustomobject]@{
        Line    = $lineNo
        Id      = $null
        Guid    = $guid
        Success = $succ
        Failure = $fail
        Note    = $null
        Raw     = $raw
      }) | Out-Null
      continue
    }

    throw "Unrecognized line at $lineNo: '$raw'"
  }

  # de-duplicate by GUID (last rule wins)
  $byGuid = @{}
  foreach ($r in $rules) { $byGuid[$r.Guid] = $r }

  return [pscustomobject]@{
    Rules = ($byGuid.Values | Sort-Object Guid)
    Options = $options
  }
}

function Apply-RuleOptions {
  param([hashtable]$Options)

  if ($IgnoreRuleOptions) {
    Write-Log "IgnoreRuleOptions enabled: skipping option|... records" 'WARN'
    return
  }

  if (-not $Options) { return }

  # enforcement
  if ($Options.ContainsKey('enforcement') -and -not $script:PSBoundParameters.ContainsKey('Enforcement')) {
    $script:Enforcement = Normalize-Enforcement $Options['enforcement']
    Write-Log "Rule option applied: enforcement=$($script:Enforcement)" 'INFO'
  }

  # batch_size
  if ($Options.ContainsKey('batch_size') -and -not $script:PSBoundParameters.ContainsKey('BatchSize')) {
    try {
      $n = [int]$Options['batch_size']
      if ($n -ge 1 -and $n -le 200) {
        $script:BatchSize = $n
        Write-Log "Rule option applied: batch_size=$n" 'INFO'
      }
    } catch { }
  }

  # apply_once
  if ($Options.ContainsKey('apply_once') -and -not $script:PSBoundParameters.ContainsKey('ApplyOnce')) {
    if (Normalize-Bool $Options['apply_once'] $false) {
      $script:ApplyOnce = $true
      Write-Log "Rule option applied: apply_once=true" 'INFO'
    }
  }

  # backup mode
  if ($Options.ContainsKey('backup') -and -not $script:PSBoundParameters.ContainsKey('NoBackup') -and -not $script:PSBoundParameters.ContainsKey('BackupOnce')) {
    $mode = Normalize-BackupMode $Options['backup']
    switch ($mode) {
      'none' {
        $script:NoBackup = $true
        Write-Log "Rule option applied: backup=none (NoBackup=true)" 'WARN'
      }
      'once' {
        $script:BackupOnce = $true
        Write-Log "Rule option applied: backup=once (BackupOnce=true)" 'INFO'
      }
      'always' {
        # default behavior
        Write-Log "Rule option applied: backup=always" 'INFO'
      }
    }
  }

  # verify
  if ($Options.ContainsKey('verify') -and -not $script:PSBoundParameters.ContainsKey('Verify')) {
    if (Normalize-Bool $Options['verify'] $false) {
      $script:Verify = $true
      Write-Log "Rule option applied: verify=true" 'INFO'
    }
  }

  # evidence
  if ($Options.ContainsKey('evidence_dir') -and -not $script:PSBoundParameters.ContainsKey('EvidenceDir')) {
    $script:EvidenceDir = Resolve-RelativePath $Options['evidence_dir']
    Write-Log "Rule option applied: evidence_dir=$($script:EvidenceDir)" 'INFO'
  }

  if ($Options.ContainsKey('evidence_export') -and -not $script:PSBoundParameters.ContainsKey('EvidenceExport') -and -not $script:PSBoundParameters.ContainsKey('NoEvidenceExport')) {
    $en = Normalize-Setting $Options['evidence_export']
    if ($en -eq 'enable') { $script:EvidenceExport = $true }
    if ($en -eq 'disable') { $script:EvidenceExport = $false }
    Write-Log "Rule option applied: evidence_export=$($script:EvidenceExport)" 'INFO'
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

function Export-AuditPolicySnapshot {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [string]$Prefix = 'auditpolicy.applied'
  )
  Ensure-Dir $OutDir
  $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $outFile = Join-Path $OutDir "$Prefix.$stamp.csv"

  if ($PSCmdlet.ShouldProcess($outFile, 'auditpol /backup (evidence)')) {
    Write-Log "Exporting evidence snapshot to: $outFile" 'INFO'
    $out = & $AuditPol '/backup' "/file:$outFile" 2>&1
    $rc = $LASTEXITCODE
    if ($out) { Write-Log ($out | Out-String).Trim() 'DEBUG' }
    if ($rc -ne 0) { throw "auditpol /backup (evidence) failed (exit=$rc)" }
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

function Invoke-AuditpolSetOption {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][string]$OptionName,
    [ValidateSet('enable','disable')][string]$Value
  )

  $desc = "option=$OptionName value=$Value"
  if ($PSCmdlet.ShouldProcess($desc, 'auditpol /set /option')) {
    Write-Log "Applying: $desc" 'INFO'
    $out = & $AuditPol '/set' "/option:$OptionName" "/value:$Value" 2>&1
    $rc = $LASTEXITCODE
    if ($out) { Write-Log ($out | Out-String).Trim() 'DEBUG' }
    if ($rc -ne 0) { throw "auditpol /set /option failed (exit=$rc): $desc" }
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

function Set-ForceSubcategoryOverride {
  param([ValidateSet('enable','disable','keep')][string]$Mode)

  if ($Mode -eq 'keep') {
    Write-Log "force_subcategory_override=keep (no registry change)" 'INFO'
    return
  }

  $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $name = 'SCENoApplyLegacyAuditPolicy'
  $desired = if ($Mode -eq 'enable') { 1 } else { 0 }

  if ($PSCmdlet.ShouldProcess("$regPath\\$name", "Set to $desired")) {
    try {
      Ensure-Dir $regPath | Out-Null
    } catch { }

    Write-Log "Setting $regPath\\$name = $desired" 'INFO'
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name $name -PropertyType DWord -Value $desired -Force | Out-Null
  }
}

function Get-ForceSubcategoryOverrideValue {
  $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $name = 'SCENoApplyLegacyAuditPolicy'
  try {
    $v = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction Stop).$name
    return [int]$v
  } catch {
    return $null
  }
}

function Apply-AuditpolOptionsFromRules {
  param(
    [Parameter(Mandatory=$true)][string]$AuditPol,
    [Parameter(Mandatory=$true)][hashtable]$Options
  )

  foreach ($k in ($Options.Keys | Where-Object { $_ -like 'auditpol.option.*' })) {
    $optName = $k.Substring('auditpol.option.'.Length)
    $v = Normalize-Setting $Options[$k]
    if ($v -eq 'keep') {
      Write-Log "Skipping auditpol option (keep): $k" 'INFO'
      continue
    }
    if ($v -ne 'enable' -and $v -ne 'disable') {
      throw "Invalid auditpol option value for $k: '$($Options[$k])'"
    }
    Invoke-AuditpolSetOption -AuditPol $AuditPol -OptionName $optName -Value $v
  }
}

function Get-CurrentPolicyMap {
  param([Parameter(Mandatory=$true)][string]$AuditPol)

  $tmp = Join-Path $env:TEMP ("auditpolicy.current.{0}.csv" -f ([Guid]::NewGuid().ToString('N')))
  try {
    & $AuditPol '/backup' "/file:$tmp" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol backup failed" }

    # Locale-safe parsing: do NOT rely on localized headers. Parse by value patterns (GUID/numeric).
    $rows = Read-AuditpolCsvFile -Path $tmp
    if (-not $rows -or $rows.Count -eq 0) { throw "Empty auditpol backup CSV" }

    $info = Detect-AuditpolCsvColumns -Rows $rows
    $guidCol  = $info.GuidCol
    $valueCol = $info.ValueCol

    if (-not $guidCol) { throw "Could not detect GUID column in backup CSV" }
    if (-not $valueCol) { throw "Could not detect Setting Value column in backup CSV" }

    $map = @{}
    foreach ($r in $rows) {
      $gNorm = Normalize-GuidString -GuidText ($r.$guidCol)
      if ($null -eq $gNorm) { continue }

      $v = $null
      try { $v = [int]($r.$valueCol) } catch { continue }
      $map[$gNorm] = $v
    }

    # Add auditpol options via /get /option:<name> /r (CSV), also locale-safe.
    $optMap = Get-AuditpolOptionsMap -AuditPol $AuditPol
    foreach ($k in $optMap.Keys) { $map[$k] = $optMap[$k] }

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

function Test-OptionsCompliance {
  param(
    [Parameter(Mandatory=$true)][hashtable]$Options,
    [Parameter(Mandatory=$true)][hashtable]$CurrentMap
  )

  $ok = $true

  foreach ($k in ($Options.Keys | Where-Object { $_ -like 'auditpol.option.*' })) {
    $expected = Normalize-Setting $Options[$k]
    if ($expected -eq 'keep') { continue }

    if (-not $CurrentMap.ContainsKey($k)) {
      Write-Log "Verify: auditpol option not found in current map: $k" 'WARN'
      $ok = $false
      continue
    }

    $curVal = [int]$CurrentMap[$k]
    $curEnabled = ($curVal -ne 0)

    $expEnabled = ($expected -eq 'enable')
    if ($curEnabled -ne $expEnabled) {
      Write-Log "Verify FAIL: $k expected=$expected currentValue=$curVal" 'ERROR'
      $ok = $false
    } else {
      Write-Log "Verify OK  : $k expected=$expected currentValue=$curVal" 'INFO'
    }
  }

  if ($Options.ContainsKey('force_subcategory_override')) {
    $mode = Normalize-Setting $Options['force_subcategory_override']
    if ($mode -ne 'keep') {
      $cur = Get-ForceSubcategoryOverrideValue
      $cur2 = if ($null -eq $cur) { '(not set)' } else { $cur }
      $exp = if ($mode -eq 'enable') { 1 } else { 0 }
      if ($null -eq $cur -or [int]$cur -ne $exp) {
        Write-Log "Verify FAIL: force_subcategory_override expected=$exp current=$cur2" 'ERROR'
        $ok = $false
      } else {
        Write-Log "Verify OK  : force_subcategory_override expected=$exp current=$cur2" 'INFO'
      }
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

    $rows = Read-AuditpolCsvFile -Path $tmp
    if (-not $rows -or $rows.Count -eq 0) { throw "Empty auditpol backup CSV" }

    $info = Detect-AuditpolCsvColumns -Rows $rows
    $guidCol = $info.GuidCol
    $valCol  = $info.ValueCol

    $catCol  = $info.PolicyTargetCol
    $subCol  = $info.SubcategoryCol

    if (-not $valCol) { $valCol = $rows[0].PSObject.Properties.Name[-1] }

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('# auditpolicy.rules (exported from current system)') | Out-Null
    $out.Add('# Format: option|key|value|note?  OR  id|{GUID}|success|failure|note') | Out-Null
    $out.Add('# Settings: enable|disable|keep') | Out-Null
    $out.Add('') | Out-Null

    # Export force_subcategory_override (registry) if available
    $force = Get-ForceSubcategoryOverrideValue
    if ($null -ne $force) {
      $state = if ([int]$force -ne 0) { 'enable' } else { 'disable' }
      $out.Add("option|force_subcategory_override|$state|exported") | Out-Null
    }

    # Export auditpol options via /get /option (locale-safe, option names are stable)
    $optMap = Get-AuditpolOptionsMap -AuditPol $AuditPol
    foreach ($name in @('CrashOnAuditFail','FullPrivilegeAuditing','AuditBaseObjects','AuditBaseDirectories')) {
      $k = "auditpol.option.$name"
      if ($optMap.ContainsKey($k)) {
        $state = if ([int]$optMap[$k] -ne 0) { 'enable' } else { 'disable' }
        $out.Add("option|$k|$state|exported") | Out-Null
      }
    }

    $out.Add('') | Out-Null

    # Export all subcategory GUID rows
    foreach ($r in $rows) {
      $g2 = $null
      if ($guidCol) { $g2 = Normalize-GuidString -GuidText ($r.$guidCol) }
      if ($null -eq $g2) { continue }

      $v = $null
      try { $v = [int]($r.$valCol) } catch { continue }

      $succ = if (($v -band 1) -eq 1) { 'enable' } else { 'disable' }
      $fail = if (($v -band 2) -eq 2) { 'enable' } else { 'disable' }

      $gidShort = ($g2 -replace '[\{\}\-]','').Substring(0,8)
      $rid = "ap_$gidShort"

      $note = $null
      if ($catCol -and $subCol) { $note = "$($r.$catCol)/$($r.$subCol)" }
      elseif ($subCol) { $note = "$($r.$subCol)" }

      $out.Add("$rid|$g2|$succ|$fail|$note") | Out-Null
    }

    $dir = Split-Path -Parent $OutFile
    if ($dir) { Ensure-Dir $dir }
    $out | Set-Content -LiteralPath $OutFile -Encoding UTF8
    Write-Log "Exported current policy to rules file: $OutFile" 'INFO'
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue | Out-Null
  }
}

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

    $ro = Read-Rules -Path $RulesPath
    $rules = $ro.Rules
    $opts  = $ro.Options

    Write-Log "Loaded rules: $($rules.Count)" 'INFO'
    Write-Log "Loaded option keys: $($opts.Keys.Count)" 'INFO'

    Apply-RuleOptions -Options $opts

    # Explicit CLI overrides for evidence export
    if ($NoEvidenceExport) { $EvidenceExport = $false }

    if ($ApplyOnce) {
      $markerBackup = Join-Path $BackupDir 'auditpolicy.backup.csv'
      if (Test-Path -LiteralPath $markerBackup) {
        Write-Log "ApplyOnce: stable backup exists ($markerBackup). Skipping apply." 'INFO'
        break
      }
    }

    # Backup before making changes
    if (-not $NoBackup) {
      Backup-AuditPolicy -AuditPol $auditpol -OutDir $BackupDir -Once:$BackupOnce | Out-Null
    } else {
      Write-Log "Skipping backup (-NoBackup)" 'WARN'
    }

    # Force subcategory override (registry) if declared
    if ($opts.ContainsKey('force_subcategory_override')) {
      $mode = Normalize-Setting $opts['force_subcategory_override']
      Set-ForceSubcategoryOverride -Mode $mode
    }

    # Apply auditpol /set /option:* from rules
    Apply-AuditpolOptionsFromRules -AuditPol $auditpol -Options $opts

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

    if ($Enforcement -eq 'Merge') {
      Write-Log "Enforcement=Merge: disabling actions will be skipped." 'WARN'
      $succDisable = @()
      $failDisable = @()
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

    if ($EvidenceExport) {
      $eDir = Resolve-RelativePath $EvidenceDir
      Export-AuditPolicySnapshot -AuditPol $auditpol -OutDir $eDir | Out-Null
    }

    if ($Verify) {
      Write-Log "Verifying rules..." 'INFO'
      $map = Get-CurrentPolicyMap -AuditPol $auditpol
      $ok1 = Test-RuleCompliance -Rules $rules -CurrentMap $map
      $ok2 = Test-OptionsCompliance -Options $opts -CurrentMap $map
      if (-not ($ok1 -and $ok2)) { throw "Verification failed: current policy does not match rules" }
      Write-Log "Verification OK." 'INFO'
    }

    break
  }
}

exit 0
