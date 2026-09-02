<#
.SYNOPSIS
Assembles a self-contained local RouteDeck portable directory.

.DESCRIPTION
Copies the locally built GUI/helper pair, the pinned sing-box runtime, the
pinned Xray runtime, and their bundled notices. The script verifies the exact
hashes recorded by the build manifest and engine lock files. It never executes
RouteDeck, either engine, the elevated helper, or an installer.
#>
[CmdletBinding()]
param(
  [Parameter()]
  [string] $BuildRoot,

  [Parameter()]
  [string] $EnginePath,

  [Parameter()]
  [string] $XrayPath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $TargetRoot
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

function Fail([string] $Message) {
  throw "Portable assembly failed: $Message"
}

function Get-Sha256([string] $Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile([string] $Path, [string] $Label) {
  if (-not [IO.File]::Exists($Path)) {
    Fail "$Label is missing: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (-not ($item -is [IO.FileInfo])) {
    Fail "$Label is not a regular file: $Path"
  }
  return $item
}

function Assert-BuildFile($Entry, [string] $ExpectedName, [string] $Root) {
  if ([string] $Entry.path -cne $ExpectedName) {
    Fail "build manifest does not describe $ExpectedName"
  }
  if ([string] $Entry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
    Fail "build manifest has an invalid SHA-256 for $ExpectedName"
  }
  $path = Join-Path $Root $ExpectedName
  $item = Assert-RegularFile $path $ExpectedName
  if ([long] $item.Length -ne [long] $Entry.size) {
    Fail "$ExpectedName size does not match the build manifest"
  }
  if ((Get-Sha256 $item.FullName) -cne [string] $Entry.sha256) {
    Fail "$ExpectedName SHA-256 does not match the build manifest"
  }
  return $item.FullName
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$build = (Get-Item -LiteralPath $BuildRoot -Force).FullName
$engine = (Get-Item -LiteralPath $EnginePath -Force).FullName
$xray = (Get-Item -LiteralPath $XrayPath -Force).FullName
$target = [IO.Path]::GetFullPath($TargetRoot)

foreach ($directory in @(
  [pscustomobject] @{ Path = $build; Label = 'build directory' },
  [pscustomobject] @{ Path = $engine; Label = 'sing-box directory' },
  [pscustomobject] @{ Path = $xray; Label = 'Xray directory' }
)) {
  if (-not [IO.Directory]::Exists($directory.Path)) {
    Fail "$($directory.Label) is missing: $($directory.Path)"
  }
}
if ([IO.File]::Exists($target) -or [IO.Directory]::Exists($target)) {
  Fail "target already exists: $target"
}

$manifestPath = Join-Path $build 'routedeck-build.json'
$manifestItem = Assert-RegularFile $manifestPath 'build manifest'
$manifest = Get-Content -Raw -LiteralPath $manifestItem.FullName | ConvertFrom-Json
if ([int] $manifest.schemaVersion -ne 1) {
  Fail 'unsupported build manifest schema'
}
$files = @($manifest.files)
if ($files.Count -ne 2) {
  Fail 'build manifest must contain exactly the GUI and helper'
}
$guiSource = Assert-BuildFile $files[0] 'routedeck.exe' $build
$helperSource = Assert-BuildFile $files[1] 'routedeck-tun-helper.exe' $build

& (Join-Path $PSScriptRoot 'verify-engine.ps1') -Path $engine | Write-Output
& (Join-Path $PSScriptRoot 'verify-xray.ps1') -Path $xray | Write-Output

$noticeSources = @(
  (Join-Path $repoRoot 'engine\NOTICE.md'),
  (Join-Path $repoRoot 'engine\sing-box.lock.json'),
  (Join-Path $repoRoot 'engine\xray-core.lock.json'),
  (Join-Path $repoRoot 'engine\licenses\manifest.json'),
  (Join-Path $repoRoot 'engine\licenses\cronet-go-LICENSE.txt'),
  (Join-Path $repoRoot 'engine\licenses\naiveproxy-LICENSE.txt'),
  (Join-Path $repoRoot 'engine\licenses\chromium-LICENSE.txt')
)
foreach ($notice in $noticeSources) {
  [void] (Assert-RegularFile $notice 'notice file')
}

$targetParent = [IO.Path]::GetDirectoryName($target)
if ([string]::IsNullOrWhiteSpace($targetParent)) {
  Fail 'target has no parent directory'
}
[IO.Directory]::CreateDirectory($targetParent) | Out-Null
$stage = Join-Path $targetParent ('.routedeck-stage-' + [guid]::NewGuid().ToString('N'))

try {
  [IO.Directory]::CreateDirectory($stage) | Out-Null
  $stageEngine = Join-Path $stage 'engine'
  $stageXray = Join-Path $stage 'xray'
  $stageLicenses = Join-Path $stage 'licenses'
  [IO.Directory]::CreateDirectory($stageEngine) | Out-Null
  [IO.Directory]::CreateDirectory($stageXray) | Out-Null
  [IO.Directory]::CreateDirectory($stageLicenses) | Out-Null

  Copy-Item -LiteralPath $guiSource -Destination (Join-Path $stage 'routedeck.exe')
  Copy-Item -LiteralPath $helperSource -Destination (Join-Path $stage 'routedeck-tun-helper.exe')
  Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $stage 'routedeck-build.json')

  foreach ($name in @('sing-box.exe', 'libcronet.dll', 'LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $engine $name) -Destination (Join-Path $stageEngine $name)
  }
  foreach ($name in @('xray.exe', 'LICENSE')) {
    Copy-Item -LiteralPath (Join-Path $xray $name) -Destination (Join-Path $stageXray $name)
  }
  foreach ($notice in $noticeSources) {
    Copy-Item -LiteralPath $notice -Destination (Join-Path $stageLicenses ([IO.Path]::GetFileName($notice)))
  }

  [void] (Assert-BuildFile $files[0] 'routedeck.exe' $stage)
  [void] (Assert-BuildFile $files[1] 'routedeck-tun-helper.exe' $stage)
  & (Join-Path $PSScriptRoot 'verify-engine.ps1') -Path $stageEngine | Write-Output
  & (Join-Path $PSScriptRoot 'verify-xray.ps1') -Path $stageXray | Write-Output

  Move-Item -LiteralPath $stage -Destination $target
}
finally {
  if ([IO.Directory]::Exists($stage)) {
    Remove-Item -LiteralPath $stage -Recurse -Force
  }
}

[pscustomobject] @{
  PortableRoot = $target
  GuiSha256 = [string] $files[0].sha256
  HelperSha256 = [string] $files[1].sha256
}
