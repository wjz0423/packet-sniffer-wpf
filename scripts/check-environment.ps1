[CmdletBinding()]
param(
    [string]$DotnetPath
)

$ErrorActionPreference = 'Stop'

function Resolve-DotnetPath {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        return $RequestedPath
    }

    $localDotnet = 'D:\dev\dotnet-sdk\dotnet.exe'
    if (Test-Path -LiteralPath $localDotnet) {
        return $localDotnet
    }

    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Details
    )

    $script:results.Add([pscustomobject]@{
            Check   = $Name
            Status  = if ($Passed) { 'PASS' } else { 'MISSING' }
            Details = $Details
        })
}

$dotnet = Resolve-DotnetPath -RequestedPath $DotnetPath
$dotnetVersion = $null
if ($dotnet) {
    try {
        $dotnetVersion = (& $dotnet --version 2>$null).Trim()
    }
    catch {
        $dotnetVersion = $null
    }
}
$dotnetDetails = if ($dotnetVersion) { $dotnetVersion } else { 'Install a current .NET SDK' }
Add-Check '.NET SDK' ($null -ne $dotnetVersion) $dotnetDetails

$os = Get-CimInstance Win32_OperatingSystem
$is64Bit = $os.OSArchitecture -match '64'
Add-Check 'Windows x64' $is64Bit ("$($os.Caption) $($os.OSArchitecture)")

$npcapService = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
$npfService = Get-Service -Name 'npf' -ErrorAction SilentlyContinue
$captureService = if ($npcapService) { $npcapService } elseif ($npfService) { $npfService } else { $null }
$captureServiceDetails = if ($captureService) { $captureService.Status } else { 'Install Npcap' }
Add-Check 'Npcap driver service' ($null -ne $captureService) $captureServiceDetails

$wpcapPaths = @(
    'C:\Windows\System32\Npcap\wpcap.dll',
    'C:\Windows\System32\wpcap.dll'
)
$packetPaths = @(
    'C:\Windows\System32\Npcap\Packet.dll',
    'C:\Windows\System32\Packet.dll'
)
$wpcapPath = $wpcapPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$packetPath = $packetPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$captureLibrariesReady = $null -ne $wpcapPath -and $null -ne $packetPath
$captureLibraryDetails = if ($captureLibrariesReady) {
    "wpcap=$wpcapPath; Packet=$packetPath"
}
else {
    $wpcapDetails = if ($wpcapPath) { $wpcapPath } else { 'none' }
    $packetDetails = if ($packetPath) { $packetPath } else { 'none' }
    "Requires one wpcap.dll and one Packet.dll. Found wpcap=$wpcapDetails, Packet=$packetDetails"
}
Add-Check 'Npcap capture libraries' $captureLibrariesReady $captureLibraryDetails

$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')
$adapterDetails = (($adapters | Select-Object -ExpandProperty Name) -join ', ')
if (-not $adapterDetails) { $adapterDetails = 'No active adapter' }
Add-Check 'Active network adapter' ($adapters.Count -gt 0) $adapterDetails

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Check 'Administrator session' $isAdmin ($(if ($isAdmin) { 'Current process is elevated' } else { 'Npcap installation may require elevation' }))

$results | Format-Table -AutoSize

$requiredChecks = @('.NET SDK', 'Windows x64', 'Npcap driver service', 'Npcap capture libraries', 'Active network adapter')
$failed = $results | Where-Object { $_.Check -in $requiredChecks -and $_.Status -ne 'PASS' }
if ($failed) {
    Write-Output ''
    Write-Output 'Environment is incomplete. Install the missing prerequisites before live capture.'
    exit 1
}

Write-Output ''
Write-Output 'Environment is ready for live capture.'
exit 0
