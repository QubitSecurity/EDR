[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$OutputPath = '.\repo.plura.io\wdac',

    [Parameter()]
    [string]$Prefix = 'PLURA_WDAC_LOLBAS_DENY',

    [Parameter()]
    [string]$ManifestFileName = 'manifest.json',

    [Parameter()]
    [string]$SourceUrl = 'https://lolbas-project.github.io/api/lolbas.json',

    [Parameter()]
    [string]$SourceJsonPath,

    [Parameter()]
    [switch]$AuditMode,

    [Parameter()]
    [switch]$SkipCipConversion,

    [Parameter()]
    [switch]$CreateDeploymentCopies,

    [Parameter()]
    [string]$DeploymentOutputPath,

    [Parameter()]
    [switch]$CleanOutput,

    [Parameter()]
    [string[]]$IncludeName,

    [Parameter()]
    [switch]$StopOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ConfigCI file-path rule creation is more reliable in Windows PowerShell 5.1.
# If the script is started from PowerShell 7+, relaunch itself in Windows PowerShell.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $winPs = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $winPs)) {
        throw 'Windows PowerShell 5.1 not found. Run this script on a Windows host with ConfigCI available.'
    }

    Write-Host '[INFO] Relaunching in Windows PowerShell 5.1 for ConfigCI compatibility...'

    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($pair in $PSBoundParameters.GetEnumerator()) {
        $name = '-' + $pair.Key
        $value = $pair.Value

        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) {
                $argList += $name
            }
            continue
        }

        if ($null -ne $value) {
            if ($value -is [System.Array] -and -not ($value -is [string])) {
                foreach ($element in $value) {
                    $argList += $name
                    $argList += ('"{0}"' -f ($element.ToString().Replace('"', '""')))
                }
            }
            else {
                $argList += $name
                $argList += ('"{0}"' -f ($value.ToString().Replace('"', '""')))
            }
        }
    }

    $process = Start-Process -FilePath $winPs -ArgumentList $argList -Wait -PassThru
    exit $process.ExitCode
}

function Assert-ConfigCiCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required ConfigCI command not found: $Name"
    }
}

function Convert-ToSafeToken {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $token = [regex]::Replace($Text, '[^A-Za-z0-9_-]', '_')
    $token = [regex]::Replace($token, '_{2,}', '_')
    $token = $token.Trim('_')

    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "Unable to build a safe token from input: $Text"
    }

    return $token
}

function Get-UniqueStemMap {
    param(
        [Parameter(Mandatory)]
        [object[]]$Items
    )

    $groups = @{}
    foreach ($item in $Items) {
        $baseStem = Convert-ToSafeToken -Text ([System.IO.Path]::GetFileNameWithoutExtension([string]$item.Name))
        if (-not $groups.ContainsKey($baseStem)) {
            $groups[$baseStem] = New-Object System.Collections.Generic.List[object]
        }
        $groups[$baseStem].Add($item)
    }

    $map = @{}
    foreach ($key in $groups.Keys) {
        $group = $groups[$key]
        if ($group.Count -eq 1) {
            $map[[string]$group[0].Name] = $key
            continue
        }

        foreach ($item in $group) {
            $fullStem = Convert-ToSafeToken -Text ([string]$item.Name)
            $map[[string]$item.Name] = $fullStem
        }
    }

    return $map
}

function Get-LolbasEntries {
    param(
        [string]$Url,
        [string]$JsonPath
    )

    if ($JsonPath) {
        if (-not (Test-Path -LiteralPath $JsonPath)) {
            throw "SourceJsonPath not found: $JsonPath"
        }
        return (Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }

    Write-Host "[INFO] Downloading LOLBAS data from $Url"
    return (Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 180)
}

function New-DenyRuleForLolbasName {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $denyPattern = "*\$Name"
    return [PSCustomObject]@{
        RuleObject = (New-CIPolicyRule -Deny -FilePathRule $denyPattern)
        RulePattern = $denyPattern
    }
}

function Get-CategoryList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $categories = @()
    foreach ($cmd in @($Entry.Commands)) {
        if ($null -ne $cmd -and $cmd.PSObject.Properties.Name -contains 'Category' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Category)) {
            $categories += [string]$cmd.Category
        }
    }
    return @($categories | Sort-Object -Unique)
}

function Get-TagList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $tags = @()
    foreach ($cmd in @($Entry.Commands)) {
        if ($null -eq $cmd) { continue }
        if (-not ($cmd.PSObject.Properties.Name -contains 'Tags')) { continue }
        foreach ($tag in @($cmd.Tags)) {
            if ($null -eq $tag) { continue }
            foreach ($prop in $tag.PSObject.Properties) {
                $tags += ('{0}:{1}' -f $prop.Name, $prop.Value)
            }
        }
    }
    return @($tags | Sort-Object -Unique)
}

function Get-FullPathList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $paths = @()
    foreach ($p in @($Entry.Full_Path)) {
        if ($null -ne $p -and $p.PSObject.Properties.Name -contains 'Path' -and -not [string]::IsNullOrWhiteSpace([string]$p.Path)) {
            $paths += [string]$p.Path
        }
    }
    return @($paths | Sort-Object -Unique)
}

function Get-PolicyIdFromXml {
    param(
        [Parameter(Mandatory)]
        [string]$XmlPath
    )

    [xml]$xml = Get-Content -LiteralPath $XmlPath -Encoding UTF8
    $policyId = [string]$xml.SiPolicy.PolicyID
    if ([string]::IsNullOrWhiteSpace($policyId)) {
        throw "PolicyID not found in XML: $XmlPath"
    }
    return $policyId
}

function Get-HashIfExists {
    param(
        [string]$Path
    )

    if ($Path -and (Test-Path -LiteralPath $Path)) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }

    return $null
}

Import-Module ConfigCI -ErrorAction Stop
Assert-ConfigCiCommand -Name 'New-CIPolicyRule'
Assert-ConfigCiCommand -Name 'Merge-CIPolicy'
Assert-ConfigCiCommand -Name 'Set-CIPolicyIdInfo'
Assert-ConfigCiCommand -Name 'Set-CIPolicyVersion'
Assert-ConfigCiCommand -Name 'Set-RuleOption'
if (-not $SkipCipConversion) {
    Assert-ConfigCiCommand -Name 'ConvertFrom-CIPolicy'
}

$allowAllPolicy = Join-Path $env:WINDIR 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
if (-not (Test-Path -LiteralPath $allowAllPolicy)) {
    throw "AllowAll.xml not found: $allowAllPolicy"
}

$workingTemplateDir = Join-Path $env:TEMP 'PLURA_WDAC_TEMPLATE'
if (-not (Test-Path -LiteralPath $workingTemplateDir)) {
    New-Item -ItemType Directory -Path $workingTemplateDir -Force | Out-Null
}
$workingAllowAllPolicy = Join-Path $workingTemplateDir 'AllowAll.xml'
Copy-Item -LiteralPath $allowAllPolicy -Destination $workingAllowAllPolicy -Force

$entries = @(Get-LolbasEntries -Url $SourceUrl -JsonPath $SourceJsonPath)
if ($IncludeName -and $IncludeName.Count -gt 0) {
    $wanted = @($IncludeName | ForEach-Object { $_.ToLowerInvariant() })
    $entries = @(
        $entries | Where-Object {
            $n = ([string]$_.Name).ToLowerInvariant()
            $stem = ([System.IO.Path]::GetFileNameWithoutExtension([string]$_.Name)).ToLowerInvariant()
            $wanted -contains $n -or $wanted -contains $stem
        }
    )
}

if ($entries.Count -eq 0) {
    throw 'No LOLBAS entries matched the current filter.'
}

$stemMap = Get-UniqueStemMap -Items $entries

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

if ($CreateDeploymentCopies) {
    if (-not $DeploymentOutputPath) {
        $DeploymentOutputPath = Join-Path $OutputPath 'deploy'
    }
    if (-not (Test-Path -LiteralPath $DeploymentOutputPath)) {
        New-Item -ItemType Directory -Path $DeploymentOutputPath -Force | Out-Null
    }
}

if ($CleanOutput) {
    Get-ChildItem -LiteralPath $OutputPath -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$Prefix*.xml" -or $_.Name -like "$Prefix*.cip" -or $_.Name -eq $ManifestFileName } |
        Remove-Item -Force -ErrorAction Stop

    if ($CreateDeploymentCopies -and (Test-Path -LiteralPath $DeploymentOutputPath)) {
        Get-ChildItem -LiteralPath $DeploymentOutputPath -File -Filter '*.cip' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction Stop
    }
}

$manifestItems = New-Object System.Collections.Generic.List[object]
$successCount = 0
$failureCount = 0
$policyVersion = '{0}.{1}.{2}.0' -f (Get-Date).Year, (Get-Date).Month, (Get-Date).Day

for ($index = 0; $index -lt $entries.Count; $index++) {
    $entry = $entries[$index]
    $name = [string]$entry.Name
    $stem = [string]$stemMap[$name]
    $xmlName = '{0}_{1}.xml' -f $Prefix, $stem
    $cipName = '{0}_{1}.cip' -f $Prefix, $stem
    $xmlPath = Join-Path $OutputPath $xmlName
    $cipPath = Join-Path $OutputPath $cipName
    $policyName = ('{0} - {1}' -f ($Prefix -replace '_', ' '), $stem)

    Write-Host ('[{0}/{1}] {2}' -f ($index + 1), $entries.Count, $name)

    try {
        $denyInfo = New-DenyRuleForLolbasName -Name $name
        $fullPaths = Get-FullPathList -Entry $entry
        $categories = Get-CategoryList -Entry $entry
        $tags = Get-TagList -Entry $entry

        if ($PSCmdlet.ShouldProcess($name, 'Generate WDAC deny XML/CIP')) {
            Merge-CIPolicy -PolicyPaths $workingAllowAllPolicy -OutputFilePath $xmlPath -Rules $denyInfo.RuleObject | Out-Null
            Set-CIPolicyIdInfo -FilePath $xmlPath -ResetPolicyID -PolicyName $policyName | Out-Null
            Set-CIPolicyVersion -FilePath $xmlPath -Version $policyVersion | Out-Null

            if ($AuditMode) {
                Set-RuleOption -FilePath $xmlPath -Option 3 | Out-Null
            }
            else {
                Set-RuleOption -FilePath $xmlPath -Option 3 -Delete | Out-Null
            }

            $policyId = Get-PolicyIdFromXml -XmlPath $xmlPath
            $deployCipName = ('{0}.cip' -f $policyId)
            $deployCipPath = $null

            if (-not $SkipCipConversion) {
                ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath | Out-Null

                if ($CreateDeploymentCopies) {
                    $deployCipPath = Join-Path $DeploymentOutputPath $deployCipName
                    Copy-Item -LiteralPath $cipPath -Destination $deployCipPath -Force
                }
            }

            $manifestItems.Add([PSCustomObject][ordered]@{
                index = $index + 1
                status = 'ok'
                name = $name
                stem = $stem
                description = [string]$entry.Description
                author = [string]$entry.Author
                created = [string]$entry.Created
                categories = $categories
                tags = $tags
                denyPattern = [string]$denyInfo.RulePattern
                sourceEntryUrl = [string]$entry.url
                sourceFullPaths = $fullPaths
                policyName = $policyName
                policyVersion = $policyVersion
                policyId = $policyId
                xml = $xmlName
                xmlSha256 = (Get-HashIfExists -Path $xmlPath)
                cip = $(if ($SkipCipConversion) { $null } else { $cipName })
                cipSha256 = $(if ($SkipCipConversion) { $null } else { Get-HashIfExists -Path $cipPath })
                deployCip = $(if ($CreateDeploymentCopies -and -not $SkipCipConversion) { $deployCipName } else { $null })
                deployCipSha256 = $(if ($deployCipPath) { Get-HashIfExists -Path $deployCipPath } else { $null })
                auditMode = [bool]$AuditMode
            })

            $successCount++
        }
    }
    catch {
        $failureCount++
        $message = $_.Exception.Message
        Write-Warning ("Failed: {0} => {1}" -f $name, $message)

        $manifestItems.Add([PSCustomObject][ordered]@{
            index = $index + 1
            status = 'error'
            name = $name
            stem = $stem
            xml = $xmlName
            cip = $(if ($SkipCipConversion) { $null } else { $cipName })
            error = $message
            auditMode = [bool]$AuditMode
        })

        if ($StopOnError) {
            throw
        }
    }
}

$manifestPath = Join-Path $OutputPath $ManifestFileName
$manifest = [PSCustomObject][ordered]@{
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    source = $(if ($SourceJsonPath) { (Resolve-Path -LiteralPath $SourceJsonPath).Path } else { $SourceUrl })
    prefix = $Prefix
    policyTemplate = $workingAllowAllPolicy
    ruleMode = 'NameAnywhere'
    denyPatternTemplate = '*\\<LOLBAS file name>'
    multiplePolicyFormat = $true
    auditMode = [bool]$AuditMode
    outputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    deploymentOutputPath = $(if ($CreateDeploymentCopies) { (Resolve-Path -LiteralPath $DeploymentOutputPath).Path } else { $null })
    successCount = $successCount
    failureCount = $failureCount
    totalCount = $manifestItems.Count
    items = $manifestItems
}

$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host ''
Write-Host ('Done. success={0}, failed={1}, manifest={2}' -f $successCount, $failureCount, $manifestPath)
if ($CreateDeploymentCopies -and -not $SkipCipConversion) {
    Write-Host ('Deployment CIP copies written to: {0}' -f (Resolve-Path -LiteralPath $DeploymentOutputPath).Path)
}
