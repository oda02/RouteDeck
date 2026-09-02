[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $repoRoot 'src-tauri'
$portableTargetRoot = Join-Path $tauriRoot 'target\portable'
$releaseRoot = Join-Path $portableTargetRoot 'release'
$helperPath = Join-Path $releaseRoot 'routedeck-tun-helper.exe'
$guiPath = Join-Path $releaseRoot 'routedeck.exe'
$manifestPath = Join-Path $releaseRoot 'routedeck-build.json'
$hashVariable = 'ROUTEDECK_TUN_HELPER_SHA256'
$targetVariable = 'CARGO_TARGET_DIR'

foreach ($command in @('cargo.exe', 'npm.cmd')) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "Required build command is unavailable: $command"
  }
}

$previousTarget = [Environment]::GetEnvironmentVariable($targetVariable, 'Process')
[Environment]::SetEnvironmentVariable($targetVariable, $portableTargetRoot, 'Process')
try {
Push-Location $tauriRoot
try {
  # Match the production GUI feature set. A helper built without custom-protocol
  # would not be the exact sibling from the final portable release configuration.
  & cargo.exe build --locked --release --features tauri/custom-protocol --bin routedeck-tun-helper
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
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) {
      throw 'RouteDeck production frontend build failed'
    }
  }
  finally {
    Pop-Location
  }
  Push-Location $tauriRoot
  try {
    # Tauri CLI builds every binary target and would overwrite the helper whose
    # digest we just embedded. Build only the GUI target with the same production
    # custom-protocol feature after the production frontend boundary check.
    & cargo.exe build --locked --release --features tauri/custom-protocol --bin routedeck
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
$guiItem = Get-Item -LiteralPath $guiPath -Force
$helperItem = Get-Item -LiteralPath $helperPath -Force
$guiHash = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered] @{
  schemaVersion = 1
  files = @(
    [ordered] @{
      path = 'routedeck.exe'
      size = [long] $guiItem.Length
      sha256 = $guiHash
    },
    [ordered] @{
      path = 'routedeck-tun-helper.exe'
      size = [long] $helperItem.Length
      sha256 = $helperHash
    }
  )
}
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($manifestPath, $manifestJson + "`n", [Text.UTF8Encoding]::new($false))

$result = [pscustomobject]@{
  Gui = $guiPath
  Helper = $helperPath
  HelperSha256 = $helperHash
  Manifest = $manifestPath
}
}
finally {
  [Environment]::SetEnvironmentVariable($targetVariable, $previousTarget, 'Process')
}

$result
