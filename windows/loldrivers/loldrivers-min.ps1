<# 
loldrivers-min.ps1

목적
- LOLDrivers의 drivers.json(또는 유사한 구조)을 읽어서, 필요한 최소 필드만 추출한 JSON/CSV를 생성합니다.
- Windows PowerShell 5.1에서도 동작하도록 ConvertFrom-Json(중복 키 문제) 대신 JavaScriptSerializer를 사용합니다.

입력/출력
- 오프라인(로컬) 실행: -input 로 drivers.json 경로를 전달
- (옵션) -input 미지정 시 -Uri 로 다운로드

예시
  # 로컬 파일로 처리
  .\loldrivers-min.ps1 -input .\drivers.json -output .\loldrivers-min.json

  # (옵션) 다운로드해서 처리
  .\loldrivers-min.ps1 -Uri 'https://www.loldrivers.io/api/drivers.json' -output .\loldrivers-min.json

  # CSV
  .\loldrivers-min.ps1 -input .\drivers.json -Format csv -output .\loldrivers-min.csv

추출 필드(기본)
- OriginalFilename (정규화: Trim + ToLower) 
  * 원본 JSON에서 Filename/OriginalFilename 등 다양한 키를 자동 인식
- sha256
- category
- created

중요
- sha256 또는 파일명이 비어 있으면 기본적으로 제외합니다(해시 기반 매칭 목적).
#>

[CmdletBinding()]
param(
  # 로컬 입력 파일 (사용자 요청: -input)
  [Alias('input','in')]
  [string]$InputFile = "",

  # 출력 파일 (사용자 요청: -output)
  [Alias('output','out')]
  [string]$OutFile = "",

  # -input 미지정 시 다운로드할 URL
  [string]$Uri = "https://www.loldrivers.io/api/drivers.json",

  [ValidateSet('json','csv')]
  [string]$Format = 'json'
)

# ---- TLS (PS 5.1 often needs TLS1.2) ----
try {
  [Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls13
} catch {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ---- Helpers: dictionary-safe key lookup (avoid case/duplicate key issues) ----
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

  # UTF-8 (no BOM)로 저장: 도구/파서 호환성 개선
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($full, $Content, $utf8NoBom)

  return $full
}

# ---- Read local file with BOM detection (UTF-8/UTF-16) ----
function Read-TextFileAuto {
  param([Parameter(Mandatory=$true)][string]$Path)

  $full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
  if (-not (Test-Path -LiteralPath $full)) {
    throw "Input file not found: $full"
  }

  $bytes = [IO.File]::ReadAllBytes($full)
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    return [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
  }
  elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
  }
  elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
    return [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
  }
  else {
    # 기본은 UTF-8로 가정
    return [Text.Encoding]::UTF8.GetString($bytes)
  }
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

# ---- JSON parser (JavaScriptSerializer) ----
Add-Type -AssemblyName System.Web.Extensions
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$ser.MaxJsonLength  = [int]::MaxValue
$ser.RecursionLimit = 4000

function Parse-JsonLoose {
  param([Parameter(Mandatory=$true)][string]$JsonText)

  # 1차 시도
  try { return $ser.DeserializeObject($JsonText) }
  catch {
    $t = $JsonText.Trim()

    # 케이스 A: 끝에 불필요한 따옴표가 붙은 경우(예: ]")
    if (($t.StartsWith('[') -and $t.EndsWith(']"')) -or ($t.StartsWith('{') -and $t.EndsWith('}"'))) {
      try { return $ser.DeserializeObject($t.Substring(0, $t.Length - 1)) } catch {}
    }

    # 케이스 B: JSON이 "..." 형태(= JSON string)로 감싸져 있는 경우
    if ($t.StartsWith('"') -and $t.EndsWith('"')) {
      try {
        $inner = $ser.DeserializeObject($t)
        if ($inner -is [string]) {
          return $ser.DeserializeObject($inner)
        }
      } catch {}
    }

    throw
  }
}

# ---- Load JSON (local first, else download) ----
try {
  if ($InputFile) {
    Write-Verbose "Reading local file: $InputFile"
    $raw = Read-TextFileAuto -Path $InputFile
  }
  else {
    Write-Verbose "Downloading: $Uri"
    $iw = @{ Uri = $Uri; ErrorAction = 'Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 6) { $iw.UseBasicParsing = $true }
    $raw = (Invoke-WebRequest @iw).Content
  }
} catch {
  Write-Error "Failed to read input. $($_.Exception.Message)"
  exit 1
}

# ---- Parse JSON ----
try {
  $data = Parse-JsonLoose -JsonText $raw
} catch {
  Write-Error "Failed to parse JSON. 입력 파일/내용이 유효한 JSON인지 확인하세요.`n$($_.Exception.Message)"
  exit 1
}

$outList = New-Object System.Collections.Generic.List[object]

function Add-Row {
  param($sample, $parentCategory, $parentCreated)

  # 파일명: OriginalFilename / Filename 등 다양한 키 대응
  $name = Get-Value $sample @(
    'OriginalFilename','originalFilename','original_filename',
    'Filename','FileName','filename',
    'DriverFileName','driverFileName','driver_filename',
    'Name','name'
  )
  if ($name) { $name = $name.Trim().ToLower() }

  $sha  = Get-Value $sample @('sha256','SHA256','Sha256','Hash','hash')

  $cat = Get-Value $sample @('category','Category')
  if (-not $cat) { $cat = $parentCategory }

  $created = Get-Value $sample @('created','Created','Date','date')
  if (-not $created) { $created = $parentCreated }

  # 기본 정책: sha256 또는 파일명이 없으면 제외
  if ($sha -and $name) {
    $outList.Add([pscustomobject]@{
      OriginalFilename = $name
      sha256          = $sha
      category        = $cat
      created         = $created
    })
  }
}

function Process-Entry {
  param($entry, $defaultCategory, $defaultCreated)

  $cat = Get-Value $entry @('Category','category')
  if (-not $cat) { $cat = $defaultCategory }

  $crt = Get-Value $entry @('Created','created','Date','date')
  if (-not $crt) { $crt = $defaultCreated }

  # 1) 엔트리 내부에 Samples 리스트가 있는지(키 이름이 바뀌어도) 최대한 찾기
  $found = $false
  if ($entry -is [System.Collections.IDictionary]) {

    # KnownVulnerableSamples 포함 "*Samples" 키를 전부 스캔
    foreach ($k in $entry.Keys) {
      if ($k -isnot [string]) { continue }
      if ($k -notmatch 'samples$') { continue }

      $v = $entry[$k]
      if ($null -eq $v) { continue }

      if ($v -is [System.Collections.IDictionary]) {
        Add-Row $v $cat $crt
        $found = $true
      }
      elseif (Is-ListLike $v) {
        foreach ($s in $v) { Add-Row $s $cat $crt }
        $found = $true
      }
    }

    # 일부 스키마는 drivers/data 등에 배열이 들어갈 수 있음
    if (-not $found) {
      foreach ($k2 in @('drivers','data')) {
        $arr = Get-Value $entry @($k2)
        if ($arr -and (Is-ListLike $arr)) {
          foreach ($e in $arr) { Process-Entry $e $cat $crt }
          $found = $true
        }
      }
    }
  }

  # 2) Samples 리스트가 없으면 entry 자체가 sample일 수 있음
  if (-not $found) {
    Add-Row $entry $cat $crt
  }
}

# ---- Walk top-level structures ----
if ($data -is [System.Collections.IDictionary]) {
  Process-Entry $data $null $null
}
elseif (Is-ListLike $data) {
  foreach ($entry in $data) { Process-Entry $entry $null $null }
}
else {
  Process-Entry $data $null $null
}

# ---- Deduplicate by sha256 keeping the newest created record ----
$out = $outList |
  Group-Object sha256 |
  ForEach-Object {
    $_.Group |
      Sort-Object @{ Expression = { Get-CreatedDate $_.created }; Descending = $true } |
      Select-Object -First 1
  } |
  Sort-Object OriginalFilename, sha256

# ---- Output ----
if (-not $OutFile) {
  # 출력 파일을 지정하지 않으면(파이프/리다이렉션용) stdout으로
  if ($Format -eq 'csv') {
    $out | ConvertTo-Csv -NoTypeInformation
  } else {
    $out | ConvertTo-Json -Depth 8
  }
  exit 0
}

try {
  if ($Format -eq 'csv') {
    $full = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutFile))
    $dir  = Split-Path -Parent $full
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $out | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $full
    Write-Output $full
  }
  else {
    $json = ($out | ConvertTo-Json -Depth 8)
    if ([string]::IsNullOrWhiteSpace($json)) { $json = '[]' }
    $full = Ensure-WriteFile -Path $OutFile -Content $json
    Write-Output $full
  }
}
catch {
  Write-Error "Failed to write output file. $($_.Exception.Message)"
  exit 1
}
