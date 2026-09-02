[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $repoRoot 'src-tauri'
$releaseRoot = Join-Path $tauriRoot 'target\release'
$helperPath = Join-Path $releaseRoot 'routedeck-tun-helper.exe'
$guiPath = Join-Path $releaseRoot 'routedeck.exe'
$hashVariable = 'ROUTEDECK_TUN_HELPER_SHA256'

foreach ($command in @('cargo.exe', 'npm.cmd')) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "Required build command is unavailable: $command"
  }
}

Push-Location $tauriRoot
try {
  & cargo.exe build --locked --release --bin routedeck-tun-helper
  if ($LASTEXITCODE -ne 0) {
    throw 'TUN helper release build failed'
  }
}
finally {
  Pop-Location
}

if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
  throw 'TUN helper build did not produce the fixed sibling executable'
}
$helperHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($helperHash -notmatch '^[0-9a-f]{64}$') {
  throw 'TUN helper SHA-256 is invalid'
}

$previousHash = [Environment]::GetEnvironmentVariable($hashVariable, 'Process')
try {
  [Environment]::SetEnvironmentVariable($hashVariable, $helperHash, 'Process')
  Push-Location $repoRoot
  try {
    & npm.cmd run tauri -- build --no-bundle
    if ($LASTEXITCODE -ne 0) {
      throw 'RouteDeck GUI release build failed'
    }
  }
  finally {
    Pop-Location
  }
}
finally {
  [Environment]::SetEnvironmentVariable($hashVariable, $previousHash, 'Process')
}

if (-not (Test-Path -LiteralPath $guiPath -PathType Leaf)) {
  throw 'RouteDeck GUI build did not produce routedeck.exe'
}
$postBuildHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($postBuildHash -cne $helperHash) {
  throw 'TUN helper changed after its SHA-256 was embedded in the GUI build'
}

[pscustomobject]@{
  Gui = $guiPath
  Helper = $helperPath
  HelperSha256 = $helperHash
}
