[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Targets,

    [Parameter(Mandatory = $false)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $false)]
    [string]$CiToolPath = (Join-Path $env:windir 'System32\CiTool.exe')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$PolicyIdFieldNames   = @('Policy ID', 'PolicyID', 'PolicyId', '정책 ID')
$FriendlyFieldNames   = @('Friendly Name', 'FriendlyName', 'Name', '이름')
$CurrentFieldNames    = @('Is Currently Enforced', 'IsCurrentlyEnforced', '현재 적용 중')
$EnforcedFieldNames   = @('Is Enforced', 'IsEnforced', '적용됨')
$AuthorizedFieldNames = @('Is Authorized', 'IsAuthorized', '승인됨')

function Normalize-PolicyGuid {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $text = $Value.Trim()
    $text = $text.Trim('{', '}').Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text.ToLowerInvariant()
}

function Test-TrueValue {
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $false
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [short]) {
        return ([int64]$Value -ne 0)
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }

    switch ($text.Trim().ToLowerInvariant()) {
        'true'  { return $true }
        '1'     { return $true }
        'yes'   { return $true }
        'on'    { return $true }
        default { return $false }
    }
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $text = [System.IO.File]::ReadAllText($Path)
    if (-not [string]::IsNullOrEmpty($text)) {
        if ([int][char]$text[0] -eq 0xFEFF) {
            $text = $text.Substring(1)
        }
    }

    return ($text | ConvertFrom-Json)
}

function Get-ManifestSearchPaths {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PreferredPath
    )

    $list = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        $list.Add($PreferredPath)
    }

    $list.Add('C:\Program Files\PLURA\temp\manifest.json')
    $list.Add('C:\Program Files\PLURA\temp\manifest.min.json')

    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $list.Add((Join-Path $PSScriptRoot 'manifest.json'))
        $list.Add((Join-Path $PSScriptRoot 'manifest.min.json'))
    }

    return $list.ToArray()
}

function Resolve-ManifestPath {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PreferredPath
    )

    foreach ($candidate in (Get-ManifestSearchPaths -PreferredPath $PreferredPath)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'manifest.json 또는 manifest.min.json 을 찾지 못했습니다.'
}

function Get-ManifestItems {
    param(
        [Parameter(Mandatory = $true)]
        $Manifest
    )

    if ($null -eq $Manifest) {
        throw 'manifest 내용이 비어 있습니다.'
    }

    if ($Manifest -is [System.Array]) {
        return @($Manifest)
    }

    $itemsProp = $Manifest.PSObject.Properties['items']
    if ($null -ne $itemsProp -and $null -ne $itemsProp.Value) {
        return @($itemsProp.Value)
    }

    if ($Manifest -is [System.Collections.IEnumerable] -and -not ($Manifest -is [pscustomobject])) {
        return @($Manifest)
    }

    throw 'manifest 구조에서 items 배열을 찾지 못했습니다.'
}

function Split-TargetList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $ordered = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    foreach ($part in ($Value -split ',')) {
        if ([string]::IsNullOrWhiteSpace($part)) {
            continue
        }

        $trimmed = $part.Trim().Trim('"', "'")
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $leaf = [System.IO.Path]::GetFileName($trimmed)
        if ([string]::IsNullOrWhiteSpace($leaf)) {
            $leaf = $trimmed
        }

        $key = $leaf.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $ordered.Add($leaf)
        }
    }

    if ($ordered.Count -eq 0) {
        throw '대상 exe 목록이 비어 있습니다.'
    }

    return $ordered.ToArray()
}

function Get-ItemString {
    param(
        [Parameter(Mandatory = $true)]
        $Item,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Item) {
        return $null
    }

    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($PropertyName) -and $null -ne $Item[$PropertyName]) {
            return [string]$Item[$PropertyName]
        }
    }

    $prop = $Item.PSObject.Properties[$PropertyName]
    if ($null -ne $prop -and $null -ne $prop.Value) {
        return [string]$prop.Value
    }

    return $null
}

function Resolve-ManifestItem {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,

        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $leaf = [System.IO.Path]::GetFileName($Target.Trim())
    $leafLower = $leaf.ToLowerInvariant()
    $stemLower = ([System.IO.Path]::GetFileNameWithoutExtension($leaf)).ToLowerInvariant()

    foreach ($item in $Items) {
        $name = Get-ItemString -Item $item -PropertyName 'name'
        $stem = Get-ItemString -Item $item -PropertyName 'stem'

        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $nameLower = $name.ToLowerInvariant()
            $nameStemLower = ([System.IO.Path]::GetFileNameWithoutExtension($name)).ToLowerInvariant()
            if ($nameLower -eq $leafLower -or $nameStemLower -eq $stemLower) {
                return $item
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($stem)) {
            if ($stem.ToLowerInvariant() -eq $stemLower) {
                return $item
            }
        }
    }

    return $null
}

function Invoke-CiToolAttempt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw ("CiTool.exe 를 찾지 못했습니다: {0}" -f $Path)
    }

    $output = $null
    $exitCode = 0

    try {
        $output = & $Path @Args 2>&1 | Out-String
    }
    catch {
        $output = ($_ | Out-String)
    }

    if ($LASTEXITCODE -is [int]) {
        $exitCode = [int]$LASTEXITCODE
    }

    return [pscustomobject]@{
        Args     = ($Args -join ' ')
        Output   = [string]$output
        ExitCode = $exitCode
    }
}

function Invoke-CiToolBestResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object[]]$ArgumentSets,

        [switch]$AllowEmptyOutput
    )

    $messages = New-Object System.Collections.Generic.List[string]
    $firstSuccess = $null

    foreach ($args in $ArgumentSets) {
        $result = Invoke-CiToolAttempt -Path $Path -Args ([string[]]$args)

        if ($result.ExitCode -eq 0) {
            if ($null -eq $firstSuccess) {
                $firstSuccess = $result
            }

            if ($AllowEmptyOutput -or -not [string]::IsNullOrWhiteSpace($result.Output)) {
                return $result
            }

            $messages.Add(("args='{0}', exit=0, output-empty" -f $result.Args))
            continue
        }

        $trimmed = ''
        if (-not [string]::IsNullOrWhiteSpace($result.Output)) {
            $trimmed = $result.Output.Trim()
        }
        $messages.Add(("args='{0}', exit={1}, output='{2}'" -f $result.Args, $result.ExitCode, $trimmed))
    }

    if ($null -ne $firstSuccess) {
        return $firstSuccess
    }

    throw ("CiTool 실행에 실패했습니다. {0}" -f ($messages -join ' | '))
}

function Invoke-CiToolListPoliciesVerbose {
    param([string]$Path)

    return Invoke-CiToolBestResult -Path $Path -ArgumentSets @(
        @('-lp', '-v'),
        @('--list-policies', '-v'),
        @('-lp')
    ) -AllowEmptyOutput
}

function Invoke-CiToolListPoliciesJson {
    param([string]$Path)

    try {
        return Invoke-CiToolBestResult -Path $Path -ArgumentSets @(
            @('-lp', '-json'),
            @('--list-policies', '-json')
        ) -AllowEmptyOutput
    }
    catch {
        return $null
    }
}

function Parse-CiToolJsonPolicies {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $obj = $Text | ConvertFrom-Json
    if ($null -eq $obj) {
        return @()
    }

    $policiesProp = $obj.PSObject.Properties['Policies']
    if ($null -ne $policiesProp -and $null -ne $policiesProp.Value) {
        return @($policiesProp.Value)
    }

    if ($obj -is [System.Array]) {
        return @($obj)
    }

    return @($obj)
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        $Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name) -and $null -ne $Object[$name]) {
                return $Object[$name]
            }
        }

        $prop = $Object.PSObject.Properties[$name]
        if ($null -ne $prop -and $null -ne $prop.Value) {
            return $prop.Value
        }
    }

    return $null
}

function Get-ObjectPropertyString {
    param(
        [Parameter(Mandatory = $true)]
        $Object,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    $value = Get-ObjectPropertyValue -Object $Object -Names $Names
    if ($null -eq $value) {
        return $null
    }

    return [string]$value
}

function Find-JsonPolicyById {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Policies,

        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    $normalizedTarget = Normalize-PolicyGuid -Value $PolicyId
    foreach ($policy in $Policies) {
        $candidate = Normalize-PolicyGuid -Value (Get-ObjectPropertyString -Object $policy -Names $PolicyIdFieldNames)
        if ($candidate -eq $normalizedTarget) {
            return $policy
        }
    }

    return $null
}

function Test-GuidPrintedInVerbose {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$PolicyId
    )

    $normalized = Normalize-PolicyGuid -Value $PolicyId
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    $pattern = '(?i)\{?' + [regex]::Escape($normalized) + '\}?'
    return [regex]::IsMatch($Text, $pattern)
}

function Resolve-FriendlyName {
    param(
        [AllowNull()]
        $JsonPolicy,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Fallback
    )

    if ($null -ne $JsonPolicy) {
        $friendly = Get-ObjectPropertyString -Object $JsonPolicy -Names $FriendlyFieldNames
        if (-not [string]::IsNullOrWhiteSpace($friendly)) {
            return $friendly
        }
    }

    return $Fallback
}

function Resolve-EffectiveState {
    param(
        [AllowNull()]
        $JsonPolicy,

        [bool]$GuidPrinted
    )

    if ($null -eq $JsonPolicy) {
        return $GuidPrinted
    }

    $current    = Get-ObjectPropertyValue -Object $JsonPolicy -Names $CurrentFieldNames
    $enforced   = Get-ObjectPropertyValue -Object $JsonPolicy -Names $EnforcedFieldNames
    $authorized = Get-ObjectPropertyValue -Object $JsonPolicy -Names $AuthorizedFieldNames

    if (Test-TrueValue -Value $current)    { return $true }
    if (Test-TrueValue -Value $enforced)   { return $true }
    if (Test-TrueValue -Value $authorized) { return $true }

    if ($null -ne $current -or $null -ne $enforced -or $null -ne $authorized) {
        return $false
    }

    return $GuidPrinted
}

try {
    $resolvedManifestPath = Resolve-ManifestPath -PreferredPath $ManifestPath
    $manifest = Read-JsonFile -Path $resolvedManifestPath
    $manifestItems = Get-ManifestItems -Manifest $manifest
    $requestedTargets = Split-TargetList -Value $Targets

    $ciVerbose = Invoke-CiToolListPoliciesVerbose -Path $CiToolPath
    $ciJson = Invoke-CiToolListPoliciesJson -Path $CiToolPath

    $jsonPolicies = @()
    if ($null -ne $ciJson -and -not [string]::IsNullOrWhiteSpace($ciJson.Output)) {
        try {
            $jsonPolicies = Parse-CiToolJsonPolicies -Text $ciJson.Output
        }
        catch {
            $jsonPolicies = @()
        }
    }

    $allMatchedAndEnforced = $true

    foreach ($requestedTarget in $requestedTargets) {
        $item = Resolve-ManifestItem -Items $manifestItems -Target $requestedTarget
        $displayStem = [System.IO.Path]::GetFileNameWithoutExtension($requestedTarget)

        if ($null -eq $item) {
            Write-Output ("{0} 미정의: manifest에서 정책 매핑을 찾지 못했습니다." -f $displayStem)
            $allMatchedAndEnforced = $false
            continue
        }

        $policyIdRaw = Get-ItemString -Item $item -PropertyName 'policyId'
        $policyIdNormalized = Normalize-PolicyGuid -Value $policyIdRaw
        if ([string]::IsNullOrWhiteSpace($policyIdNormalized)) {
            Write-Output ("{0} 미정의: policyId 값이 없습니다." -f $displayStem)
            $allMatchedAndEnforced = $false
            continue
        }

        $stem = Get-ItemString -Item $item -PropertyName 'stem'
        if (-not [string]::IsNullOrWhiteSpace($stem)) {
            $displayStem = $stem
        }

        $friendlyFallback = Get-ItemString -Item $item -PropertyName 'policyName'
        if ([string]::IsNullOrWhiteSpace($friendlyFallback)) {
            $friendlyFallback = ("PLURA WDAC LOLBAS DENY - {0}" -f $displayStem)
        }

        $guidPrinted = Test-GuidPrintedInVerbose -Text $ciVerbose.Output -PolicyId $policyIdNormalized
        $jsonPolicy = $null
        if ($jsonPolicies.Count -gt 0) {
            $jsonPolicy = Find-JsonPolicyById -Policies $jsonPolicies -PolicyId $policyIdNormalized
        }

        $friendlyName = Resolve-FriendlyName -JsonPolicy $jsonPolicy -Fallback $friendlyFallback
        $effective = Resolve-EffectiveState -JsonPolicy $jsonPolicy -GuidPrinted:$guidPrinted

        if ($guidPrinted -and $effective) {
            Write-Output ("{0} 차단: {1} ({2})" -f $displayStem, $policyIdNormalized, $friendlyName)
        }
        elseif ($guidPrinted) {
            Write-Output ("{0} 미적용: {1} ({2})" -f $displayStem, $policyIdNormalized, $friendlyName)
            $allMatchedAndEnforced = $false
        }
        else {
            Write-Output ("{0} 미적용: {1} ({2})" -f $displayStem, $policyIdNormalized, $friendlyName)
            $allMatchedAndEnforced = $false
        }
    }

    if ($allMatchedAndEnforced) {
        exit 0
    }

    exit 1
}
catch {
    Write-Error $_.Exception.Message
    exit 2
}
