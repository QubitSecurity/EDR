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
    [string]$ToggleJsonPath,

    [Parameter()]
    [string]$TemplatePolicyPath,

    [Parameter()]
    [switch]$AllowEmbeddedTemplate = $true,

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
            if ($value.IsPresent) { $argList += $name }
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

function Resolve-DefaultToggleJsonPath {
    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
        $candidate = Join-Path $scriptDir 'toggle-lolbas-exe.json'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    $pwdCandidate = Join-Path (Get-Location).Path 'toggle-lolbas-exe.json'
    if (Test-Path -LiteralPath $pwdCandidate) { return $pwdCandidate }

    return $null
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

function Normalize-FileName {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $value = [string]$Name
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }

    $value = $value.Trim()
    $value = $value -replace '^["'']+', ''
    $value = $value -replace '["'']+$', ''
    $value = $value -replace '[?#].*$', ''

    $parts = @($value -split '[\\/]')
    if ($parts.Count -gt 0) {
        $value = [string]$parts[$parts.Count - 1]
    }

    $value = $value.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }

    return $value.ToLowerInvariant()
}

function Get-FileStem {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $leaf = Normalize-FileName -Name $Name
    if ([string]::IsNullOrWhiteSpace($leaf)) {
        return 'unknown'
    }

    if ($leaf -match '^(.+?)\.([A-Za-z0-9]{1,16})$') {
        return $matches[1]
    }

    return $leaf
}

function Convert-ToArray {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) { return @() }
        if ($InputObject -is [System.Array]) { return @($InputObject) }
        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            return @($InputObject)
        }
        return @($InputObject)
    }
}

function Get-JsonContent {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Resolve-EntryArray {
    param(
        [Parameter(Mandatory)]
        $Data
    )

    if ($null -eq $Data) { return @() }
    if ($Data -is [System.Array]) { return @($Data) }

    foreach ($propName in @('lolbas', 'items', 'data', 'entries', 'results')) {
        if ($Data.PSObject.Properties.Name -contains $propName) {
            return @(Convert-ToArray $Data.$propName)
        }
    }

    if ($Data.PSObject.Properties.Name -contains 'Name') {
        return @($Data)
    }

    return @(Convert-ToArray $Data)
}


function Get-EmbeddedToggleEntries {
    $json = @'
[
  {
    "category": "1",
    "fileName": "ftp.exe"
  },
  {
    "category": "1",
    "fileName": "msdt.exe"
  },
  {
    "category": "1",
    "fileName": "sftp.exe"
  },
  {
    "category": "1",
    "fileName": "wmic.exe"
  },
  {
    "category": "1",
    "fileName": "devicecredentialdeployment.exe"
  },
  {
    "category": "1",
    "fileName": "ecmangen.exe"
  },
  {
    "category": "1",
    "fileName": "finger.exe"
  },
  {
    "category": "1",
    "fileName": "cmdl32.exe"
  },
  {
    "category": "1",
    "fileName": "colorcpl.exe"
  },
  {
    "category": "1",
    "fileName": "wab.exe"
  },
  {
    "category": "1",
    "fileName": "wlrmdr.exe"
  },
  {
    "category": "1",
    "fileName": "winfile.exe"
  },
  {
    "category": "2",
    "fileName": "atbroker.exe"
  },
  {
    "category": "2",
    "fileName": "cmstp.exe"
  },
  {
    "category": "2",
    "fileName": "computerdefaults.exe"
  },
  {
    "category": "2",
    "fileName": "mshta.exe"
  },
  {
    "category": "2",
    "fileName": "pcalua.exe"
  },
  {
    "category": "2",
    "fileName": "certutil.exe"
  },
  {
    "category": "2",
    "fileName": "cscript.exe"
  },
  {
    "category": "2",
    "fileName": "dfsvc.exe"
  },
  {
    "category": "2",
    "fileName": "powershell.exe"
  },
  {
    "category": "2",
    "fileName": "pwsh.exe"
  },
  {
    "category": "2",
    "fileName": "wscript.exe"
  },
  {
    "category": "2",
    "fileName": "regsvr32.exe"
  },
  {
    "category": "2",
    "fileName": "rundll32.exe"
  },
  {
    "category": "2",
    "fileName": "customshellhost.exe"
  },
  {
    "category": "2",
    "fileName": "hh.exe"
  },
  {
    "category": "2",
    "fileName": "mavinject.exe"
  },
  {
    "category": "2",
    "fileName": "powershell_ise.exe"
  },
  {
    "category": "2",
    "fileName": "msxsl.exe"
  },
  {
    "category": "2",
    "fileName": "odbcconf.exe"
  },
  {
    "category": "2",
    "fileName": "offlinescannershell.exe"
  },
  {
    "category": "2",
    "fileName": "pcwrun.exe"
  },
  {
    "category": "2",
    "fileName": "provlaunch.exe"
  },
  {
    "category": "2",
    "fileName": "rasautou.exe"
  },
  {
    "category": "2",
    "fileName": "scriptrunner.exe"
  },
  {
    "category": "2",
    "fileName": "settingsynchost.exe"
  },
  {
    "category": "2",
    "fileName": "unregmp2.exe"
  },
  {
    "category": "2",
    "fileName": "verclsid.exe"
  },
  {
    "category": "2",
    "fileName": "wsreset.exe"
  },
  {
    "category": "2",
    "fileName": "wuauclt.exe"
  },
  {
    "category": "2",
    "fileName": "bitsadmin.exe"
  },
  {
    "category": "2",
    "fileName": "eventvwr.exe"
  },
  {
    "category": "2",
    "fileName": "regasm.exe"
  },
  {
    "category": "2",
    "fileName": "regsvcs.exe"
  },
  {
    "category": "2",
    "fileName": "eudcedit.exe"
  },
  {
    "category": "2",
    "fileName": "expand.exe"
  },
  {
    "category": "2",
    "fileName": "forfiles.exe"
  },
  {
    "category": "2",
    "fileName": "ieexec.exe"
  },
  {
    "category": "2",
    "fileName": "makecab.exe"
  },
  {
    "category": "2",
    "fileName": "msconfig.exe"
  },
  {
    "category": "2",
    "fileName": "presentationhost.exe"
  },
  {
    "category": "2",
    "fileName": "syncappvpublishingserver.exe"
  },
  {
    "category": "3",
    "fileName": "dsdbutil.exe"
  },
  {
    "category": "3",
    "fileName": "ntdsutil.exe"
  },
  {
    "category": "3",
    "fileName": "cmdkey.exe"
  },
  {
    "category": "3",
    "fileName": "createdump.exe"
  },
  {
    "category": "3",
    "fileName": "dump64.exe"
  },
  {
    "category": "3",
    "fileName": "dumpminitool.exe"
  },
  {
    "category": "3",
    "fileName": "procdump.exe"
  },
  {
    "category": "3",
    "fileName": "diskshadow.exe"
  },
  {
    "category": "3",
    "fileName": "esentutl.exe"
  },
  {
    "category": "3",
    "fileName": "vshadow.exe"
  },
  {
    "category": "3",
    "fileName": "adplus.exe"
  },
  {
    "category": "3",
    "fileName": "psr.exe"
  },
  {
    "category": "3",
    "fileName": "rdrleakdiag.exe"
  },
  {
    "category": "3",
    "fileName": "rpcping.exe"
  },
  {
    "category": "3",
    "fileName": "sqldumper.exe"
  },
  {
    "category": "3",
    "fileName": "tttracer.exe"
  },
  {
    "category": "3",
    "fileName": "wbadmin.exe"
  },
  {
    "category": "4",
    "fileName": "addinutil.exe"
  },
  {
    "category": "4",
    "fileName": "aspnet_compiler.exe"
  },
  {
    "category": "4",
    "fileName": "csi.exe"
  },
  {
    "category": "4",
    "fileName": "fsi.exe"
  },
  {
    "category": "4",
    "fileName": "fsianycpu.exe"
  },
  {
    "category": "4",
    "fileName": "te.exe"
  },
  {
    "category": "4",
    "fileName": "installutil.exe"
  },
  {
    "category": "4",
    "fileName": "msbuild.exe"
  },
  {
    "category": "4",
    "fileName": "microsoft.workflow.compiler.exe"
  },
  {
    "category": "4",
    "fileName": "appcert.exe"
  },
  {
    "category": "4",
    "fileName": "bash.exe"
  },
  {
    "category": "4",
    "fileName": "dxcap.exe"
  },
  {
    "category": "4",
    "fileName": "vsdiagnostics.exe"
  },
  {
    "category": "4",
    "fileName": "vsiisexelauncher.exe"
  },
  {
    "category": "4",
    "fileName": "vslaunchbrowser.exe"
  },
  {
    "category": "4",
    "fileName": "visualuiaverifynative.exe"
  },
  {
    "category": "4",
    "fileName": "wfmformat.exe"
  },
  {
    "category": "4",
    "fileName": "wfc.exe"
  },
  {
    "category": "4",
    "fileName": "xsd.exe"
  },
  {
    "category": "4",
    "fileName": "csc.exe"
  },
  {
    "category": "4",
    "fileName": "dotnet.exe"
  },
  {
    "category": "4",
    "fileName": "vbc.exe"
  },
  {
    "category": "4",
    "fileName": "wsl.exe"
  },
  {
    "category": "4",
    "fileName": "coregen.exe"
  },
  {
    "category": "4",
    "fileName": "dnx.exe"
  },
  {
    "category": "4",
    "fileName": "ilasm.exe"
  },
  {
    "category": "4",
    "fileName": "jsc.exe"
  },
  {
    "category": "4",
    "fileName": "devtunnel.exe"
  },
  {
    "category": "4",
    "fileName": "vsjitdebugger.exe"
  },
  {
    "category": "4",
    "fileName": "vstest.console.exe"
  },
  {
    "category": "4",
    "fileName": "windbg.exe"
  },
  {
    "category": "4",
    "fileName": "vsls-agent.exe"
  },
  {
    "category": "5",
    "fileName": "appvlp.exe"
  },
  {
    "category": "5",
    "fileName": "certreq.exe"
  },
  {
    "category": "5",
    "fileName": "bcp.exe"
  },
  {
    "category": "5",
    "fileName": "datasvcutil.exe"
  },
  {
    "category": "5",
    "fileName": "mpiexec.exe"
  },
  {
    "category": "5",
    "fileName": "printbrm.exe"
  },
  {
    "category": "5",
    "fileName": "certoc.exe"
  },
  {
    "category": "5",
    "fileName": "configsecuritypolicy.exe"
  },
  {
    "category": "5",
    "fileName": "dnscmd.exe"
  },
  {
    "category": "5",
    "fileName": "dtutil.exe"
  },
  {
    "category": "5",
    "fileName": "ldifde.exe"
  },
  {
    "category": "5",
    "fileName": "sqlps.exe"
  },
  {
    "category": "5",
    "fileName": "sqltoolps.exe"
  },
  {
    "category": "6",
    "fileName": "runas.exe"
  },
  {
    "category": "6",
    "fileName": "ssh.exe"
  },
  {
    "category": "6",
    "fileName": "mstsc.exe"
  },
  {
    "category": "6",
    "fileName": "shadow.exe"
  },
  {
    "category": "6",
    "fileName": "winrs.exe"
  },
  {
    "category": "6",
    "fileName": "at.exe"
  },
  {
    "category": "6",
    "fileName": "cmd.exe"
  },
  {
    "category": "6",
    "fileName": "icacls.exe"
  },
  {
    "category": "6",
    "fileName": "netsh.exe"
  },
  {
    "category": "6",
    "fileName": "openfiles.exe"
  },
  {
    "category": "6",
    "fileName": "reg.exe"
  },
  {
    "category": "6",
    "fileName": "register-cimprovider.exe"
  },
  {
    "category": "6",
    "fileName": "sc.exe"
  },
  {
    "category": "6",
    "fileName": "schtasks.exe"
  },
  {
    "category": "6",
    "fileName": "takeown.exe"
  },
  {
    "category": "6",
    "fileName": "tscon.exe"
  },
  {
    "category": "6",
    "fileName": "tsdiscon.exe"
  },
  {
    "category": "6",
    "fileName": "wbemtest.exe"
  },
  {
    "category": "6",
    "fileName": "wevtutil.exe"
  },
  {
    "category": "6",
    "fileName": "logoff.exe"
  },
  {
    "category": "6",
    "fileName": "ngen.exe"
  },
  {
    "category": "6",
    "fileName": "pktmon.exe"
  },
  {
    "category": "6",
    "fileName": "qappsrv.exe"
  },
  {
    "category": "6",
    "fileName": "qprocess.exe"
  },
  {
    "category": "6",
    "fileName": "query.exe"
  },
  {
    "category": "6",
    "fileName": "quser.exe"
  },
  {
    "category": "6",
    "fileName": "qwinsta.exe"
  },
  {
    "category": "6",
    "fileName": "rwinsta.exe"
  },
  {
    "category": "6",
    "fileName": "tskill.exe"
  },
  {
    "category": "6",
    "fileName": "msiexec.exe"
  },
  {
    "category": "6",
    "fileName": "pnputil.exe"
  },
  {
    "category": "6",
    "fileName": "regedit.exe"
  },
  {
    "category": "6",
    "fileName": "mmc.exe"
  },
  {
    "category": "6",
    "fileName": "tar.exe"
  },
  {
    "category": "6",
    "fileName": "findstr.exe"
  },
  {
    "category": "7",
    "fileName": "appinstaller.exe"
  },
  {
    "category": "7",
    "fileName": "workfolders.exe"
  },
  {
    "category": "7",
    "fileName": "msedge.exe"
  },
  {
    "category": "7",
    "fileName": "msedge_proxy.exe"
  },
  {
    "category": "7",
    "fileName": "onedrivestandaloneupdater.exe"
  },
  {
    "category": "7",
    "fileName": "winget.exe"
  },
  {
    "category": "7",
    "fileName": "msedgewebview2.exe"
  },
  {
    "category": "7",
    "fileName": "desktopimgdownldr.exe"
  },
  {
    "category": "7",
    "fileName": "imewdbld.exe"
  },
  {
    "category": "7",
    "fileName": "xwizard.exe"
  },
  {
    "category": "8",
    "fileName": "conhost.exe"
  },
  {
    "category": "8",
    "fileName": "explorer.exe"
  },
  {
    "category": "8",
    "fileName": "control.exe"
  }
]
'@
    return @(Resolve-EntryArray -Data ($json | ConvertFrom-Json))
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
        return @(Resolve-EntryArray -Data (Get-JsonContent -Path $JsonPath))
    }

    Write-Host "[INFO] Downloading LOLBAS data from $Url"
    try {
        return @(Resolve-EntryArray -Data (Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 180))
    }
    catch {
        Write-Warning ("Failed to download LOLBAS data: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Get-ToggleEntries {
    param(
        [string]$JsonPath
    )

    if ($JsonPath -and (Test-Path -LiteralPath $JsonPath)) {
        return @(Resolve-EntryArray -Data (Get-JsonContent -Path $JsonPath))
    }

    if ($JsonPath -and -not (Test-Path -LiteralPath $JsonPath)) {
        Write-Warning ("ToggleJsonPath not found. Falling back to embedded list: {0}" -f $JsonPath)
    }

    Write-Host '[INFO] Using embedded toggle-lolbas-exe.json list.'
    return @(Get-EmbeddedToggleEntries)
}

function Get-CategoryList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $categories = New-Object System.Collections.Generic.List[string]

    if ($Entry.PSObject.Properties.Name -contains 'Category' -and -not [string]::IsNullOrWhiteSpace([string]$Entry.Category)) {
        $categories.Add([string]$Entry.Category)
    }

    if ($Entry.PSObject.Properties.Name -contains 'Commands') {
        foreach ($cmd in @(Convert-ToArray $Entry.Commands)) {
            if ($null -eq $cmd) { continue }

            if ($cmd.PSObject.Properties.Name -contains 'Category' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Category)) {
                $categories.Add([string]$cmd.Category)
            }

            if ($cmd.PSObject.Properties.Name -contains 'Categories') {
                foreach ($item in @(Convert-ToArray $cmd.Categories)) {
                    if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                        $categories.Add([string]$item)
                    }
                }
            }
        }
    }

    return @($categories | Sort-Object -Unique)
}

function Get-TagList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $tags = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Entry) {
        return @()
    }

    if (-not ($Entry.PSObject.Properties.Name -contains 'Commands')) {
        return @()
    }

    foreach ($cmd in @(Convert-ToArray $Entry.Commands)) {
        if ($null -eq $cmd) { continue }
        if (-not ($cmd.PSObject.Properties.Name -contains 'Tags')) { continue }

        foreach ($tag in @(Convert-ToArray $cmd.Tags)) {
            if ($null -eq $tag) { continue }

            if ($tag -is [string]) {
                $stringTag = [string]$tag
                if (-not [string]::IsNullOrWhiteSpace($stringTag)) {
                    $tags.Add($stringTag.Trim())
                }
                continue
            }

            if ($tag -is [System.Collections.IDictionary]) {
                foreach ($key in @($tag.Keys)) {
                    $namePart = [string]$key
                    $valuePart = [string]$tag[$key]
                    $joined = ('{0}:{1}' -f $namePart, $valuePart).Trim(':')
                    if (-not [string]::IsNullOrWhiteSpace($joined)) {
                        $tags.Add($joined)
                    }
                }
                continue
            }

            $tagProperties = @()
            try {
                if ($null -ne $tag.PSObject) {
                    $tagProperties = @($tag.PSObject.Properties)
                }
            }
            catch {
                $tagProperties = @()
            }

            if (@($tagProperties).Count -gt 0) {
                foreach ($prop in @($tagProperties)) {
                    if ($null -eq $prop) { continue }
                    $namePart = [string]$prop.Name
                    $valuePart = [string]$prop.Value
                    $joined = ('{0}:{1}' -f $namePart, $valuePart).Trim(':')
                    if (-not [string]::IsNullOrWhiteSpace($joined)) {
                        $tags.Add($joined)
                    }
                }
                continue
            }

            $fallbackTag = [string]$tag
            if (-not [string]::IsNullOrWhiteSpace($fallbackTag)) {
                $tags.Add($fallbackTag.Trim())
            }
        }
    }

    return @($tags | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
}

function Get-FullPathList {
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($propName in @('Full_Path', 'FullPath', 'FullPaths', 'Paths', 'Path')) {
        if (-not ($Entry.PSObject.Properties.Name -contains $propName)) { continue }

        foreach ($p in @(Convert-ToArray $Entry.$propName)) {
            if ($null -eq $p) { continue }

            if ($p -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($p)) {
                    $paths.Add([string]$p)
                }
                continue
            }

            foreach ($candidateProp in @('Path', 'path', 'FullPath', 'full_path')) {
                if ($p.PSObject.Properties.Name -contains $candidateProp -and -not [string]::IsNullOrWhiteSpace([string]$p.$candidateProp)) {
                    $paths.Add([string]$p.$candidateProp)
                }
            }
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

function Test-ScriptLikeFileName {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $leaf = Normalize-FileName -Name $Name
    if ([string]::IsNullOrWhiteSpace($leaf)) { return $false }

    $ext = ''
    if ($leaf -match '(\.[A-Za-z0-9]{1,16})$') {
        $ext = $matches[1].ToLowerInvariant()
    }

    return @('.bat', '.cmd', '.ps1', '.ps1xml', '.psm1', '.psd1', '.psc1', '.psc2', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta') -contains $ext
}

function New-DenyRuleForFileName {
    param(
        [Parameter(Mandatory)]
        [string]$FileName
    )

    $denyPattern = "*\$FileName"
    if (Test-ScriptLikeFileName -Name $FileName) {
        $rule = New-CIPolicyRule -Deny -FilePathRule $denyPattern -ScriptFileNames
    }
    else {
        $rule = New-CIPolicyRule -Deny -FilePathRule $denyPattern
    }

    return [PSCustomObject]@{
        RuleObject = $rule
        RulePattern = $denyPattern
    }
}

function Get-UniqueStemMap {
    param(
        [Parameter(Mandatory)]
        [object[]]$Items
    )

    $groups = @{}
    foreach ($item in $Items) {
        $baseStem = Convert-ToSafeToken -Text (Get-FileStem -Name ([string]$item.FileName))
        if (-not $groups.ContainsKey($baseStem)) {
            $groups[$baseStem] = New-Object System.Collections.Generic.List[object]
        }
        $groups[$baseStem].Add($item)
    }

    $map = @{}
    foreach ($key in $groups.Keys) {
        $group = $groups[$key]
        if ($group.Count -eq 1) {
            $map[[string]$group[0].FileName] = $key
            continue
        }

        foreach ($item in $group) {
            $fullStem = Convert-ToSafeToken -Text ([string]$item.FileName)
            $map[[string]$item.FileName] = $fullStem
        }
    }

    return $map
}

function New-EmbeddedAllowAllPolicy {
    param(
        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    $templateGuid = '{11111111-1111-1111-1111-111111111111}'
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.0.0</VersionEx>
  <BasePolicyID>$templateGuid</BasePolicyID>
  <PolicyID>$templateGuid</PolicyID>
  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
  <Rules>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Advanced Boot Options Menu</Option>
    </Rule>
    <Rule>
      <Option>Enabled:UMCI</Option>
    </Rule>
  </Rules>
  <EKUs />
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FriendlyName="Allow Kernel Drivers" FileName="*" />
    <Allow ID="ID_ALLOW_A_2" FriendlyName="Allow User mode components" FileName="*" />
  </FileRules>
  <Signers />
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Kernel Mode Signing Scenario">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_1" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode Signing Scenario">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_2" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
</SiPolicy>
"@
    $xml | Set-Content -LiteralPath $DestinationPath -Encoding UTF8
    return $DestinationPath
}

function Resolve-AllowAllTemplate {
    param(
        [string]$TemplatePath,
        [switch]$AllowEmbeddedTemplate
    )

    $workingTemplateDir = Join-Path $env:TEMP 'PLURA_WDAC_TEMPLATE'
    if (-not (Test-Path -LiteralPath $workingTemplateDir)) {
        New-Item -ItemType Directory -Path $workingTemplateDir -Force | Out-Null
    }

    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($TemplatePath)) {
        $candidates.Add($TemplatePath)
    }

    $candidates.Add((Join-Path $env:WINDIR 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'))

    $windowsAppsRoot = Join-Path ${env:ProgramFiles} 'WindowsApps'
    if (Test-Path -LiteralPath $windowsAppsRoot) {
        try {
            foreach ($wizardDir in @(Get-ChildItem -LiteralPath $windowsAppsRoot -Directory -Filter 'Microsoft.WDAC.WDACWizard*' -ErrorAction Stop)) {
                $wizardTemplate = Join-Path $wizardDir.FullName 'Templates\AllowAll.xml'
                if (Test-Path -LiteralPath $wizardTemplate) {
                    $candidates.Add($wizardTemplate)
                }
            }
        }
        catch {
            # Ignore WindowsApps access errors and continue to other candidates.
        }
    }

    $errors = New-Object System.Collections.Generic.List[string]
    $dedupCandidates = @($candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    foreach ($candidate in $dedupCandidates) {
        try {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }

            $content = Get-Content -LiteralPath $candidate -Raw -Encoding UTF8
            if ([string]::IsNullOrWhiteSpace($content)) {
                throw "Template file is empty: $candidate"
            }

            $workingCopy = Join-Path $workingTemplateDir 'AllowAll.template.xml'
            $content | Set-Content -LiteralPath $workingCopy -Encoding UTF8
            return [PSCustomObject]@{
                TemplatePath = $workingCopy
                Source = $candidate
                Embedded = $false
            }
        }
        catch {
            $errors.Add(('{0} => {1}' -f $candidate, $_.Exception.Message))
        }
    }

    if ($AllowEmbeddedTemplate) {
        $embeddedPath = Join-Path $workingTemplateDir 'AllowAll.embedded.xml'
        New-EmbeddedAllowAllPolicy -DestinationPath $embeddedPath | Out-Null
        return [PSCustomObject]@{
            TemplatePath = $embeddedPath
            Source = 'embedded'
            Embedded = $true
        }
    }

    throw ("Unable to resolve AllowAll.xml template. Errors:`n - {0}" -f (($errors -join "`n - ")))
}

function Test-RuleOptionTextPresent {
    param(
        [Parameter(Mandatory)]
        [string]$XmlPath,

        [Parameter(Mandatory)]
        [string]$OptionText
    )

    [xml]$xml = Get-Content -LiteralPath $XmlPath -Encoding UTF8
    foreach ($rule in @($xml.SiPolicy.Rules.Rule)) {
        if ($null -eq $rule) { continue }
        $value = [string]$rule.Option
        if ($value -eq $OptionText) {
            return $true
        }
    }

    return $false
}

function Ensure-PolicyRuleOptions {
    param(
        [Parameter(Mandatory)]
        [string]$XmlPath,

        [Parameter(Mandatory)]
        [bool]$AuditMode
    )

    if (-not (Test-RuleOptionTextPresent -XmlPath $XmlPath -OptionText 'Enabled:UMCI')) {
        Set-RuleOption -FilePath $XmlPath -Option 0 | Out-Null
    }

    $hasAudit = Test-RuleOptionTextPresent -XmlPath $XmlPath -OptionText 'Enabled:Audit Mode'
    if ($AuditMode) {
        if (-not $hasAudit) {
            Set-RuleOption -FilePath $XmlPath -Option 3 | Out-Null
        }
    }
    else {
        if ($hasAudit) {
            Set-RuleOption -FilePath $XmlPath -Option 3 -Delete | Out-Null
        }
    }
}

function New-RuleOnlyPolicy {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rules,

        [Parameter(Mandatory)]
        [string]$OutputFilePath
    )

    New-CIPolicy -FilePath $OutputFilePath -Rules $Rules -MultiplePolicyFormat | Out-Null
    return $OutputFilePath
}

function Add-UniqueStrings {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.Collections.IList]$List = $null,

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Values = @()
    )

    if ($null -eq $List) { return }
    if ($null -eq $Values -or $Values.Count -eq 0) { return }

    foreach ($value in @(Convert-ToArray $Values)) {
        if ($null -eq $value) { continue }

        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            foreach ($nested in @(Convert-ToArray $value)) {
                if ($null -eq $nested) { continue }
                $stringValue = [string]$nested
                if ([string]::IsNullOrWhiteSpace($stringValue)) { continue }
                if (-not ($List -contains $stringValue)) {
                    [void]$List.Add($stringValue)
                }
            }
            continue
        }

        $stringValue = [string]$value
        if ([string]::IsNullOrWhiteSpace($stringValue)) { continue }
        if (-not ($List -contains $stringValue)) {
            [void]$List.Add($stringValue)
        }
    }
}

function New-MergedItem {
    param(
        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    return [PSCustomObject]@{
        Key = $FileName
        FileName = $FileName
        DisplayName = $DisplayName
        Description = $null
        Author = $null
        Created = $null
        SourceEntryUrl = $null
        SourceKinds = (New-Object System.Collections.Generic.List[string])
        FullPaths = (New-Object System.Collections.Generic.List[string])
        LolbasCategories = (New-Object System.Collections.Generic.List[string])
        ToggleCategories = (New-Object System.Collections.Generic.List[string])
        Tags = (New-Object System.Collections.Generic.List[string])
        Synthetic = $false
    }
}

function Merge-LolbasAndToggleEntries {
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$LolbasEntries = @(),

        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ToggleEntries = @()
    )

$map = @{}

    if ($null -eq $LolbasEntries) { $LolbasEntries = @() }
    if ($null -eq $ToggleEntries) { $ToggleEntries = @() }

    foreach ($entry in $LolbasEntries) {
        if ($null -eq $entry) { continue }
        if (-not ($entry.PSObject.Properties.Name -contains 'Name')) { continue }

        $rawName = [string]$entry.Name
        if ([string]::IsNullOrWhiteSpace($rawName)) { continue }

        $fileName = Normalize-FileName -Name $rawName
        if ([string]::IsNullOrWhiteSpace($fileName)) { continue }

        if (-not $map.ContainsKey($fileName)) {
            $map[$fileName] = New-MergedItem -FileName $fileName -DisplayName $rawName
        }

        $item = $map[$fileName]
        if ([string]::IsNullOrWhiteSpace([string]$item.Description) -and $entry.PSObject.Properties.Name -contains 'Description') {
            $item.Description = [string]$entry.Description
        }
        if ([string]::IsNullOrWhiteSpace([string]$item.Author) -and $entry.PSObject.Properties.Name -contains 'Author') {
            $item.Author = [string]$entry.Author
        }
        if ([string]::IsNullOrWhiteSpace([string]$item.Created) -and $entry.PSObject.Properties.Name -contains 'Created') {
            $item.Created = [string]$entry.Created
        }
        foreach ($urlProp in @('url', 'URL', 'Url')) {
            if ([string]::IsNullOrWhiteSpace([string]$item.SourceEntryUrl) -and $entry.PSObject.Properties.Name -contains $urlProp) {
                $item.SourceEntryUrl = [string]$entry.$urlProp
            }
        }

        Add-UniqueStrings -List $item.SourceKinds -Values @('lolbas')
        Add-UniqueStrings -List $item.FullPaths -Values (Get-FullPathList -Entry $entry)
        Add-UniqueStrings -List $item.LolbasCategories -Values (Get-CategoryList -Entry $entry)
        Add-UniqueStrings -List $item.Tags -Values (Get-TagList -Entry $entry)
    }

    foreach ($toggle in $ToggleEntries) {
        if ($null -eq $toggle) { continue }

        $rawFileName = $null
        foreach ($nameProp in @('fileName', 'FileName', 'name', 'Name')) {
            if ($toggle.PSObject.Properties.Name -contains $nameProp -and -not [string]::IsNullOrWhiteSpace([string]$toggle.$nameProp)) {
                $rawFileName = [string]$toggle.$nameProp
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($rawFileName)) { continue }

        $fileName = Normalize-FileName -Name $rawFileName
        if ([string]::IsNullOrWhiteSpace($fileName)) { continue }

        if (-not $map.ContainsKey($fileName)) {
            $map[$fileName] = New-MergedItem -FileName $fileName -DisplayName $rawFileName
            $map[$fileName].Synthetic = $true
            $map[$fileName].Description = 'Added from toggle-lolbas-exe.json'
        }

        $item = $map[$fileName]
        Add-UniqueStrings -List $item.SourceKinds -Values @('toggle')

        foreach ($categoryProp in @('category', 'Category')) {
            if ($toggle.PSObject.Properties.Name -contains $categoryProp -and -not [string]::IsNullOrWhiteSpace([string]$toggle.$categoryProp)) {
                Add-UniqueStrings -List $item.ToggleCategories -Values @([string]$toggle.$categoryProp)
            }
        }
    }

    return @(
        $map.Values |
            Sort-Object @{ Expression = { $_.FileName } ; Ascending = $true }
    )
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,

        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $baseUri = New-Object System.Uri(((Resolve-Path -LiteralPath $BasePath).Path.TrimEnd('\') + '\'))
        $pathUri = New-Object System.Uri((Resolve-Path -LiteralPath $Path).Path)
        return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString().Replace('/', '\'))
    }
    catch {
        return $Path
    }
}

Import-Module ConfigCI -ErrorAction Stop
Assert-ConfigCiCommand -Name 'New-CIPolicyRule'
Assert-ConfigCiCommand -Name 'New-CIPolicy'
Assert-ConfigCiCommand -Name 'Merge-CIPolicy'
Assert-ConfigCiCommand -Name 'Set-CIPolicyIdInfo'
Assert-ConfigCiCommand -Name 'Set-CIPolicyVersion'
Assert-ConfigCiCommand -Name 'Set-RuleOption'
if (-not $SkipCipConversion) {
    Assert-ConfigCiCommand -Name 'ConvertFrom-CIPolicy'
}

if (-not $ToggleJsonPath) {
    $ToggleJsonPath = Resolve-DefaultToggleJsonPath
}

$templateInfo = Resolve-AllowAllTemplate -TemplatePath $TemplatePolicyPath -AllowEmbeddedTemplate:$AllowEmbeddedTemplate
Write-Host ('[INFO] AllowAll template: {0}' -f $templateInfo.Source)

$lolbasEntries = @(Get-LolbasEntries -Url $SourceUrl -JsonPath $SourceJsonPath)
if ($null -eq $lolbasEntries) { $lolbasEntries = @() }
$toggleEntries = @(Get-ToggleEntries -JsonPath $ToggleJsonPath)
if ($null -eq $toggleEntries) { $toggleEntries = @() }
$toggleSourceResolved = $(if ($ToggleJsonPath -and (Test-Path -LiteralPath $ToggleJsonPath)) { (Resolve-Path -LiteralPath $ToggleJsonPath).Path } else { 'embedded' })
$entries = @(Merge-LolbasAndToggleEntries -LolbasEntries $lolbasEntries -ToggleEntries $toggleEntries)
Write-Host ('[INFO] Source counts => LOLBAS: {0}, Toggle: {1}, Merged: {2}' -f @($lolbasEntries).Count, @($toggleEntries).Count, @($entries).Count)
if (@($lolbasEntries).Count -eq 0) {
    Write-Warning 'LOLBAS source returned no entries. Continuing with toggle-lolbas-exe.json entries only.'
}
if ($null -eq $entries) { $entries = @() }

if ($IncludeName -and @($IncludeName).Count -gt 0) {
    $wanted = @($IncludeName | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $entries = @(
        $entries | Where-Object {
            $displayName = ([string]$_.DisplayName).ToLowerInvariant()
            $fileName = ([string]$_.FileName).ToLowerInvariant()
            $stem = (Get-FileStem -Name [string]$_.FileName).ToLowerInvariant()
            $wanted -contains $displayName -or $wanted -contains $fileName -or $wanted -contains $stem
        }
    )
}

if (@($entries).Count -eq 0) {
    throw 'No entries matched the current filter.'
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
    Get-ChildItem -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.PSIsContainer -and $_.Name -like "$Prefix*") -or
            (-not $_.PSIsContainer -and $_.Name -eq $ManifestFileName)
        } |
        Remove-Item -Recurse -Force -ErrorAction Stop

    if ($CreateDeploymentCopies -and (Test-Path -LiteralPath $DeploymentOutputPath)) {
        Get-ChildItem -LiteralPath $DeploymentOutputPath -File -Filter '*.cip' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction Stop
    }
}

$rootManifestItems = New-Object System.Collections.Generic.List[object]
$allTargets = New-Object System.Collections.Generic.List[string]
$successCount = 0
$failureCount = 0
$policyVersion = '{0}.{1}.{2}.0' -f (Get-Date).Year, (Get-Date).Month, (Get-Date).Day
$tempWorkRoot = Join-Path $env:TEMP 'PLURA_WDAC_WORK'
if (-not (Test-Path -LiteralPath $tempWorkRoot)) {
    New-Item -ItemType Directory -Path $tempWorkRoot -Force | Out-Null
}

for ($index = 0; $index -lt $entries.Count; $index++) {
    $entry = $entries[$index]
    $fileName = [string]$entry.FileName
    $displayName = [string]$entry.DisplayName
    $stem = [string]$stemMap[$fileName]
    if ([string]::IsNullOrWhiteSpace($stem)) {
        $stem = Convert-ToSafeToken -Text (Get-FileStem -Name $fileName)
    }
    $folderName = '{0}_{1}' -f $Prefix, $stem
    $folderPath = Join-Path $OutputPath $folderName
    $xmlName = '{0}_{1}.xml' -f $Prefix, $stem
    $xmlPath = Join-Path $folderPath $xmlName
    $policyName = '{0}_{1}' -f $Prefix, $stem
    $policyManifestPath = Join-Path $folderPath $ManifestFileName

    Write-Host ('[{0}/{1}] {2}' -f ($index + 1), $entries.Count, $displayName)

    $tempRulePolicyPath = $null

    try {
        if (-not (Test-Path -LiteralPath $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }

        if (-not ($allTargets -contains $fileName)) {
            $allTargets.Add($fileName)
        }

        $denyInfo = New-DenyRuleForFileName -FileName $fileName

        if ($PSCmdlet.ShouldProcess($displayName, 'Generate WDAC deny XML/CIP/manifest')) {
            $tempRulePolicyPath = Join-Path $tempWorkRoot ('rule_{0}_{1}.xml' -f $stem, ([guid]::NewGuid().ToString('N')))
            New-RuleOnlyPolicy -Rules @($denyInfo.RuleObject) -OutputFilePath $tempRulePolicyPath | Out-Null

            Merge-CIPolicy -PolicyPaths @($templateInfo.TemplatePath, $tempRulePolicyPath) -OutputFilePath $xmlPath | Out-Null
            Set-CIPolicyIdInfo -FilePath $xmlPath -ResetPolicyID -PolicyName $policyName | Out-Null
            Set-CIPolicyVersion -FilePath $xmlPath -Version $policyVersion | Out-Null
            Ensure-PolicyRuleOptions -XmlPath $xmlPath -AuditMode ([bool]$AuditMode)

            $policyId = Get-PolicyIdFromXml -XmlPath $xmlPath
            $cipName = ('{0}.cip' -f $policyId)
            $cipPath = Join-Path $folderPath $cipName
            $deployCipPath = $null

            if (-not $SkipCipConversion) {
                ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath | Out-Null

                if ($CreateDeploymentCopies) {
                    $deployCipPath = Join-Path $DeploymentOutputPath $cipName
                    Copy-Item -LiteralPath $cipPath -Destination $deployCipPath -Force
                }
            }

            $policyManifest = [PSCustomObject][ordered]@{
                PolicyId = $policyId
                FriendlyName = $policyName
                BinaryFileName = $cipName
                Targets = @($fileName)
            }
            $policyManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policyManifestPath -Encoding UTF8

            $rootManifestItems.Add([PSCustomObject][ordered]@{
                Index = $index + 1
                Status = 'ok'
                FriendlyName = $policyName
                DisplayName = $displayName
                PolicyId = $policyId
                FolderName = $folderName
                XmlFileName = $xmlName
                BinaryFileName = $cipName
                ManifestFileName = $ManifestFileName
                Targets = @($fileName)
                SourceKinds = @($entry.SourceKinds | Sort-Object)
                ToggleCategories = @($entry.ToggleCategories | Sort-Object)
                LolbasCategories = @($entry.LolbasCategories | Sort-Object)
                Tags = @($entry.Tags | Sort-Object)
                SourceEntryUrl = $entry.SourceEntryUrl
                Synthetic = [bool]$entry.Synthetic
                AuditMode = [bool]$AuditMode
                RelativeFolderPath = $folderName
                RelativeXmlPath = (Join-Path $folderName $xmlName)
                RelativeBinaryPath = (Join-Path $folderName $cipName)
                RelativeManifestPath = (Join-Path $folderName $ManifestFileName)
                XmlSha256 = (Get-HashIfExists -Path $xmlPath)
                CipSha256 = (Get-HashIfExists -Path $cipPath)
                DeploymentBinaryPath = $(if ($deployCipPath) { Get-RelativePath -BasePath $OutputPath -Path $deployCipPath } else { $null })
                Description = $entry.Description
                Author = $entry.Author
                Created = $entry.Created
                FullPaths = @($entry.FullPaths | Sort-Object)
                DenyPattern = $denyInfo.RulePattern
            })

            $successCount++
        }
    }
    catch {
        $failureCount++
        $message = $_.Exception.Message
        Write-Warning ("Failed: {0} => {1}" -f $displayName, $message)

        if (-not (Test-Path -LiteralPath $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }

        $failureManifest = [PSCustomObject][ordered]@{
            PolicyId = $null
            FriendlyName = $policyName
            BinaryFileName = $null
            Targets = @($fileName)
            Status = 'error'
            Error = $message
        }
        $failureManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $policyManifestPath -Encoding UTF8

        $rootManifestItems.Add([PSCustomObject][ordered]@{
            Index = $index + 1
            Status = 'error'
            FriendlyName = $policyName
            DisplayName = $displayName
            PolicyId = $null
            FolderName = $folderName
            XmlFileName = $xmlName
            BinaryFileName = $null
            ManifestFileName = $ManifestFileName
            Targets = @($fileName)
            SourceKinds = @($entry.SourceKinds | Sort-Object)
            ToggleCategories = @($entry.ToggleCategories | Sort-Object)
            LolbasCategories = @($entry.LolbasCategories | Sort-Object)
            Tags = @($entry.Tags | Sort-Object)
            SourceEntryUrl = $entry.SourceEntryUrl
            Synthetic = [bool]$entry.Synthetic
            AuditMode = [bool]$AuditMode
            RelativeFolderPath = $folderName
            RelativeXmlPath = (Join-Path $folderName $xmlName)
            RelativeBinaryPath = $null
            RelativeManifestPath = (Join-Path $folderName $ManifestFileName)
            Description = $entry.Description
            Author = $entry.Author
            Created = $entry.Created
            FullPaths = @($entry.FullPaths | Sort-Object)
            DenyPattern = ('*\' + $fileName)
            Error = $message
        })

        if ($StopOnError) {
            throw
        }
    }
    finally {
        if ($tempRulePolicyPath -and (Test-Path -LiteralPath $tempRulePolicyPath)) {
            Remove-Item -LiteralPath $tempRulePolicyPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$rootManifestPath = Join-Path $OutputPath $ManifestFileName
$rootManifest = [PSCustomObject][ordered]@{
    FriendlyName = $Prefix
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    PolicyVersion = $policyVersion
    Source = $(if ($SourceJsonPath) { (Resolve-Path -LiteralPath $SourceJsonPath).Path } else { $SourceUrl })
    ToggleSource = $toggleSourceResolved
    TemplateSource = $templateInfo.Source
    TemplatePath = $templateInfo.TemplatePath
    TemplateEmbedded = [bool]$templateInfo.Embedded
    RuleMode = 'NameAnywhere'
    DenyPatternTemplate = '*\<fileName>'
    AuditMode = [bool]$AuditMode
    OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
    DeploymentOutputPath = $(if ($CreateDeploymentCopies) { (Resolve-Path -LiteralPath $DeploymentOutputPath).Path } else { $null })
    SuccessCount = $successCount
    FailureCount = $failureCount
    TotalPolicies = $rootManifestItems.Count
    Targets = @($allTargets | Sort-Object)
    Policies = $rootManifestItems
}
$rootManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $rootManifestPath -Encoding UTF8

Write-Host ''
Write-Host ('Done. success={0}, failed={1}, manifest={2}' -f $successCount, $failureCount, $rootManifestPath)
if ($CreateDeploymentCopies -and -not $SkipCipConversion) {
    Write-Host ('Deployment CIP copies written to: {0}' -f (Resolve-Path -LiteralPath $DeploymentOutputPath).Path)
}
