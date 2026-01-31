param(
  [string]$Uri = "https://www.loldrivers.io/api/drivers.json",
  [ValidateSet("json","csv")]
  [string]$Format = "json",
  [string]$OutFile = ""
)

# TLS (PS5에서 종종 필요)
try {
  [Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13
} catch {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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

function Get-DictValue {
  param(
    [Parameter(Mandatory=$true)]$Obj,
    [Parameter(Mandatory=$true)][string[]]$Names
  )

  if ($null -eq $Obj) { return $null }

  # IDictionary (JavaScriptSerializer 결과)
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

  # 내용이 비어도 파일은 반드시 생성
  Set-Content -LiteralPath $full -Value $Content -Encoding UTF8
  return $full
}

# Download
try {
  $iw = @{ Uri = $Uri; ErrorAction = "Stop" }
  if ($PSVersionTable.PSVersion.Major -lt 6) { $iw.UseBasicParsing = $true }
  $raw = (Invoke-WebRequest @iw).Content
} catch {
  Write-Error "Failed to download: $Uri`n$($_.Exception.Message)"
  exit 1
}

# Parse WITHOUT ConvertFrom-Json (avoid init/INIT duplicate-key crash)
try {
  Add-Type -AssemblyName System.Web.Extensions
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength   = [int]::MaxValue
  $ser.RecursionLimit  = 4000
  $data = $ser.DeserializeObject($raw)
} catch {
  Write-Error "Failed to parse JSON with JavaScriptSerializer.`n$($_.Exception.Message)"
  exit 1
}

$outList = New-Object System.Collections.Generic.List[object]

function Add-Row {
  param($sample, $parentCategory, $parentCreated)

  $tag = Get-DictValue $sample @(
  "OriginalFilename","originalFilename","original_filename",
  "tag","Tag","Filename","FileName","Name","name"
  )

  $sha = Get-DictValue $sample @("sha256","SHA256","Sha256","Hash","hash")

  $cat = Get-DictValue $sample @("category","Category")
  if (-not $cat) { $cat = $parentCategory }

  $created = Get-DictValue $sample @("created","Created","Date","date")
  if (-not $created) { $created = $parentCreated }

  if ($tag -or $sha) {
    $outList.Add([pscustomobject]@{
      tag      = $tag
      sha256   = $sha
      category = $cat
      created  = $created
    })
  }
}

# ---- Normalize ----
# Helper: get a value from dictionary by possible names
function Get-Any {
  param($obj, [string[]]$names)
  return (Get-DictValue $obj $names)
}

# Case A) top-level is IDictionary wrapper
if ($data -is [System.Collections.IDictionary]) {
  # possible wrappers: KnownVulnerableSamples / drivers / data
  $samples = Get-Any $data @("KnownVulnerableSamples","knownVulnerableSamples")
  if ($samples) {
    if ($samples -is [System.Collections.IDictionary]) {
      Add-Row $samples $null $null
    } elseif (Is-ListLike $samples) {
      foreach ($s in $samples) { Add-Row $s $null $null }
    }
  } else {
    $arr = Get-Any $data @("drivers","data")
    if ($arr -and (Is-ListLike $arr)) {
      foreach ($e in $arr) { Add-Row $e (Get-Any $e @("Category","category")) (Get-Any $e @("Created","created")) }
    }
  }
}
# Case B) top-level is list/array
elseif (Is-ListLike $data) {
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

    # entry 자체가 sample-like
    $cat2 = Get-Any $entry @("Category","category")
    $crt2 = Get-Any $entry @("Created","created")
    Add-Row $entry $cat2 $crt2
  }
}

# Clean / dedupe
$out = $outList |
  Where-Object { $_.tag } |
  Sort-Object tag, sha256, category, created -Unique

# Output
if ($Format -eq "csv") {
  if (-not $OutFile) { $OutFile = "loldrivers-min.csv" }
  $full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutFile))
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $full
  Write-Output $full
} else {
  if (-not $OutFile) {
    $out | ConvertTo-Json -Depth 8
  } else {
    $json = ($out | ConvertTo-Json -Depth 8)
    if ([string]::IsNullOrWhiteSpace($json)) { $json = "[]" }  # <- 비어도 파일 생성
    $full = Ensure-WriteFile -Path $OutFile -Content $json
    Write-Output $full
  }
}
