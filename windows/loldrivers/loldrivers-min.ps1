<# 
loldrivers-min.ps1
- Downloads https://www.loldrivers.io/api/drivers.json
- Extracts ONLY: OriginalFilename, sha256, category, created
- Normalizes OriginalFilename: Trim + ToLower
- Removes records with null/empty sha256
- Deduplicates by sha256 keeping the newest created record
- Works on Windows PowerShell 5.1 even when JSON contains duplicate keys like init/INIT (ConvertFrom-Json fails)
#>

param(
  [string]$Uri = "https://www.loldrivers.io/api/drivers.json",
  [ValidateSet("json","csv")]
  [string]$Format = "json",
  [string]$OutFile = ""
)

# ---- TLS (PS 5.1 often needs TLS1.2) ----
try {
  [Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13
} catch {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ---- Helpers: dictionary-safe key lookup (avoid .Contains() overload issues) ----
function Find-DictKey {
  param(
    [Parameter(Mandatory=$true)][System.Collections.IDictionary]$Dict,
    [Parameter(Mandatory=$true)][string]$Name
  )

  # 1) exact (case-sensitive)
  foreach ($k in $Dict.Keys) {
    if ($k -is [string] -and ($k -ceq $Name)) { return $k }
  }

  # 2) case-insensitive
  foreach ($k in $Dict.Keys) {
    if ($k -is [string] -and $k.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $k
    }
  }

  return $null
}

function Get-Value {
  param(
    [Parameter(Mandatory=$true)]$Obj,
    [Parameter(Mandatory=$true)][string[]]$Names
  )

  if ($null -eq $Obj) { return $null }

  # IDictionary (JavaScriptSerializer output)
  if ($Obj -is [System.Collections.IDictionary]) {
    foreach ($n in $Names) {
      $realKey = Find-DictKey -Dict $Obj -Name $n
      if ($null -ne $realKey) {
        $v = $Obj[$realKey]
        if ($null -ne $v -and "$v".Trim().Length -gt 0) { return $v }
      }
    }
    return $null
  }

  # PSObject fallback
  foreach ($n in $Names) {
    $p = $Obj.PSObject.Properties[$n]
    if ($null -ne $p) {
      $v = $p.Value
      if ($null -ne $v -and "$v".Trim().Length -gt 0) { return $v }
    }
  }

  return $null
}

function Get-Any {
  param($obj, [string[]]$names)
  return (Get-Value $obj $names)
}

function Is-ListLike {
  param($x)
  return ($x -is [System.Collections.IEnumerable] -and
          $x -isnot [string] -and
          $x -isnot [System.Collections.IDictionary])
}

function Ensure-WriteFile {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Content
  )
  $full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
  $dir  = Split-Path -Parent $full
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  # Always write (even "[]")
  Set-Content -LiteralPath $full -Value $Content -Encoding UTF8
  return $full
}

# ---- Created date parser (for dedup newest record) ----
function Get-CreatedDate {
  param([string]$s)

  if ([string]::IsNullOrWhiteSpace($s)) { return [datetime]::MinValue }

  # 1) Common: YYYY-MM-DD
  if ($s -match '^\d{4}-\d{2}-\d{2}$') {
    try { return [datetime]::ParseExact($s, 'yyyy-MM-dd', $null) } catch { return [datetime]::MinValue }
  }

  # 2) If string contains a date: pick the latest date in the string
  #    Example: "2013-07-03 ... UTC, 2017-11-30 ... UTC"
  $matches = [regex]::Matches($s, '\d{4}-\d{2}-\d{2}')
  if ($matches.Count -gt 0) {
    $dates = @()
    foreach ($m in $matches) {
      try { $dates += [datetime]::ParseExact($m.Value, 'yyyy-MM-dd', $null) } catch {}
    }
    if ($dates.Count -gt 0) { return ($dates | Sort-Object -Descending | Select-Object -First 1) }
  }

  # 3) Fallback parse
  try { return [datetime]::Parse($s) } catch { return [datetime]::MinValue }
}

# ---- Download ----
try {
  $iw = @{ Uri = $Uri; ErrorAction = "Stop" }
  if ($PSVersionTable.PSVersion.Major -lt 6) { $iw.UseBasicParsing = $true }
  $raw = (Invoke-WebRequest @iw).Content
} catch {
  Write-Error "Failed to download: $Uri`n$($_.Exception.Message)"
  exit 1
}

# ---- Parse WITHOUT ConvertFrom-Json (avoid init/INIT duplicate-key crash) ----
try {
  Add-Type -AssemblyName System.Web.Extensions
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength  = [int]::MaxValue
  $ser.RecursionLimit = 4000
  $data = $ser.DeserializeObject($raw)
} catch {
  Write-Error "Failed to parse JSON with JavaScriptSerializer.`n$($_.Exception.Message)"
  exit 1
}

$outList = New-Object System.Collections.Generic.List[object]

function Add-Row {
  param($sample, $parentCategory, $parentCreated)

  # Output field: OriginalFilename (normalize: Trim + ToLower)
  $orig = Get-Value $sample @("OriginalFilename","originalFilename","original_filename")
  if ($orig) { $orig = $orig.Trim().ToLower() }  # ✅ (1) Trim + (2) ToLower

  $sha  = Get-Value $sample @("sha256","SHA256","Sha256","Hash","hash")

  $cat = Get-Value $sample @("category","Category")
  if (-not $cat) { $cat = $parentCategory }

  $created = Get-Value $sample @("created","Created","Date","date")
  if (-not $created) { $created = $parentCreated }

  # ✅ sha256 null/empty 제외 + OriginalFilename 없는 것도 제외
  if ($sha -and $orig) {
    $outList.Add([pscustomobject]@{
      OriginalFilename = $orig
      sha256          = $sha
      category        = $cat
      created         = $created
    })
  }
}

# ---- Normalize top-level structures ----
if ($data -is [System.Collections.IDictionary]) {

  # Case 1: wrapper has KnownVulnerableSamples
  $samples = Get-Any $data @("KnownVulnerableSamples","knownVulnerableSamples")
  if ($samples) {
    if ($samples -is [System.Collections.IDictionary]) {
      Add-Row $samples $null $null
    } elseif (Is-ListLike $samples) {
      foreach ($s in $samples) { Add-Row $s $null $null }
    }
  }
  else {
    # Case 2: wrapper has drivers/data
    $arr = Get-Any $data @("drivers","data")
    if ($arr -and (Is-ListLike $arr)) {
      foreach ($e in $arr) {
        Add-Row $e (Get-Any $e @("Category","category")) (Get-Any $e @("Created","created"))
      }
    }
  }
}
elseif (Is-ListLike $data) {

  # Case 3: array of categories or samples
  foreach ($entry in $data) {

    if ($entry -is [System.Collections.IDictionary]) {
      $samples = Get-Any $entry @("KnownVulnerableSamples","knownVulnerableSamples")

      if ($samples) {
        $cat = Get-Any $entry @("Category","category")
        $crt = Get-Any $entry @("Created","created")

        if ($samples -is [System.Collections.IDictionary]) {
          Add-Row $samples $cat $crt
        } elseif (Is-ListLike $samples) {
          foreach ($s in $samples) { Add-Row $s $cat $crt }
        }
        continue
      }
    }

    # entry itself is sample-like
    Add-Row $entry (Get-Any $entry @("Category","category")) (Get-Any $entry @("Created","created"))
  }
}

# ---- (3) Deduplicate by sha256 keeping the newest created record ----
$out = $outList |
  Group-Object sha256 |
  ForEach-Object {
    $_.Group |
      Sort-Object @{ Expression = { Get-CreatedDate $_.created }; Descending = $true } |
      Select-Object -First 1
  } |
  Sort-Object OriginalFilename, sha256

# ---- Output ----
if ($Format -eq "csv") {
  if (-not $OutFile) { $OutFile = "loldrivers-min.csv" }
  $full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutFile))
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $full
  Write-Output $full
}
else {
  if (-not $OutFile) {
    $out | ConvertTo-Json -Depth 8
  } else {
    $json = ($out | ConvertTo-Json -Depth 8)
    if ([string]::IsNullOrWhiteSpace($json)) { $json = "[]" }
    $full = Ensure-WriteFile -Path $OutFile -Content $json
    Write-Output $full
  }
}
