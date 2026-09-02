<#
.SYNOPSIS
Regression tests for local portable assembly.

.DESCRIPTION
Uses existing, hash-pinned build and engine directories. It copies files but
never executes RouteDeck, the helper, sing-box, Xray, UAC, or TUN.
#>
[CmdletBinding()]
param(
  [Parameter()]
  [string] $BuildRoot,

  [Parameter()]
  [string] $EnginePath,

  [Parameter()]
  [string] $XrayPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
  $BuildRoot = Join-Path $PSScriptRoot '..\src-tauri\target\portable\release'
}
if ([string]::IsNullOrWhiteSpace($EnginePath)) {
  $EnginePath = Join-Path $PSScriptRoot '..\src-tauri\target\release\engine'
}
if ([string]::IsNullOrWhiteSpace($XrayPath)) {
  $XrayPath = Join-Path $PSScriptRoot '..\src-tauri\target\release\xray'
}

function Assert-True([bool] $Condition, [string] $Message) {
  if (-not $Condition) {
    throw "FAIL: $Message"
  }
}

function Invoke-Assembly(
  [string] $Build,
  [string] $Engine,
  [string] $Xray,
  [string] $Target
) {
  $records = [Collections.ArrayList]::new()
  $exitCode = 0
  try {
    & $assembly -BuildRoot $Build -EnginePath $Engine -XrayPath $Xray -TargetRoot $Target *>&1 |
      ForEach-Object { [void] $records.Add($_.ToString()) }
  }
  catch {
    $exitCode = 1
    [void] $records.Add($_.Exception.Message)
  }
  [pscustomobject] @{ ExitCode = $exitCode; Output = ($records -join "`n") }
}

function Assert-Rejected($Result, [string] $Expected) {
  Assert-True ($Result.ExitCode -ne 0) 'invalid portable input was accepted'
  Assert-True ($Result.Output.IndexOf($Expected, [StringComparison]::OrdinalIgnoreCase) -ge 0) `
    "rejection did not mention '$Expected': $($Result.Output)"
}

$assembly = Join-Path $PSScriptRoot 'assemble-portable.ps1'
$resolvedBuild = (Get-Item -LiteralPath $BuildRoot -Force).FullName
$resolvedEngine = (Get-Item -LiteralPath $EnginePath -Force).FullName
$resolvedXray = (Get-Item -LiteralPath $XrayPath -Force).FullName
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('RouteDeck-portable-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($tempRoot) | Out-Null

try {
  $portable = Join-Path $tempRoot 'RouteDeck'
  $success = Invoke-Assembly $resolvedBuild $resolvedEngine $resolvedXray $portable
  Assert-True ($success.ExitCode -eq 0) "valid portable assembly failed: $($success.Output)"

  $expectedTopLevel = @(
    'engine',
    'licenses',
    'routedeck-build.json',
    'routedeck-tun-helper.exe',
    'routedeck.exe',
    'xray'
  ) | Sort-Object
  $actualTopLevel = @(Get-ChildItem -LiteralPath $portable -Force | ForEach-Object Name | Sort-Object)
  Assert-True (($actualTopLevel -join "`n") -ceq ($expectedTopLevel -join "`n")) `
    'portable top-level layout is not exact'
  & (Join-Path $PSScriptRoot 'verify-engine.ps1') -Path (Join-Path $portable 'engine') | Out-Null
  & (Join-Path $PSScriptRoot 'verify-xray.ps1') -Path (Join-Path $portable 'xray') | Out-Null
  Write-Output 'PASS: valid self-contained portable layout'

  $existing = Invoke-Assembly $resolvedBuild $resolvedEngine $resolvedXray $portable
  Assert-Rejected $existing 'target already exists'
  Write-Output 'PASS: existing target is preserved'

  $tamperedBuild = Join-Path $tempRoot 'tampered-build'
  [IO.Directory]::CreateDirectory($tamperedBuild) | Out-Null
  foreach ($name in @('routedeck.exe', 'routedeck-tun-helper.exe', 'routedeck-build.json')) {
    Copy-Item -LiteralPath (Join-Path $resolvedBuild $name) -Destination (Join-Path $tamperedBuild $name)
  }
  $gui = Join-Path $tamperedBuild 'routedeck.exe'
  $stream = [IO.File]::Open($gui, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    $first = $stream.ReadByte()
    [void] $stream.Seek(0, [IO.SeekOrigin]::Begin)
    $stream.WriteByte($first -bxor 1)
  }
  finally {
    $stream.Dispose()
  }
  $tamperedTarget = Join-Path $tempRoot 'tampered-target'
  $tampered = Invoke-Assembly $tamperedBuild $resolvedEngine $resolvedXray $tamperedTarget
  Assert-Rejected $tampered 'SHA-256 does not match'
  Assert-True (-not [IO.Directory]::Exists($tamperedTarget)) 'tampered input created a target'
  Write-Output 'PASS: tampered GUI is rejected before copy'

  $missingXray = Join-Path $tempRoot 'missing-xray'
  [IO.Directory]::CreateDirectory($missingXray) | Out-Null
  Copy-Item -LiteralPath (Join-Path $resolvedXray 'LICENSE') -Destination (Join-Path $missingXray 'LICENSE')
  $missingTarget = Join-Path $tempRoot 'missing-target'
  $missing = Invoke-Assembly $resolvedBuild $resolvedEngine $missingXray $missingTarget
  Assert-Rejected $missing 'required staged file is missing'
  Assert-True (-not [IO.Directory]::Exists($missingTarget)) 'missing Xray input created a target'
  Write-Output 'PASS: incomplete Xray runtime is rejected before copy'

  $stages = @(Get-ChildItem -LiteralPath $tempRoot -Force -Directory -Filter '.routedeck-stage-*')
  Assert-True ($stages.Count -eq 0) 'temporary assembly directory was left behind'
  Write-Output 'PASS: portable assembly regression suite completed'
}
finally {
  if ([IO.Directory]::Exists($tempRoot)) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
