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
$metadataVariable = 'ROUTEDECK_BUILD_METADATA'
$targetVariable = 'CARGO_TARGET_DIR'

foreach ($command in @('cargo.exe', 'npm.cmd', 'git.exe')) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "Required build command is unavailable: $command"
  }
}

$sourceCommit = (& git.exe -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$') {
  throw 'Could not resolve the source commit for portable build metadata'
}
$trackedChanges = @(& git.exe -C $repoRoot status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
  # Names/status only: never print file contents that may contain local secrets.
  $trackedChanges | ForEach-Object { Write-Output $_ }
  throw 'Portable build metadata requires a clean tracked source tree'
}
$buildMetadata = "RouteDeckBuildCommit=$sourceCommit"

function Assert-BuildMetadata([string] $Path) {
  $binaryText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($Path))
  if ($binaryText.IndexOf($buildMetadata, [StringComparison]::Ordinal) -lt 0) {
    throw "Executable does not contain the expected build metadata: $Path"
  }
}

function Assert-WindowsGuiSubsystem([string] $Path) {
  $stream = [IO.File]::OpenRead($Path)
  $reader = [IO.BinaryReader]::new($stream)
  try {
    if ($reader.ReadUInt16() -ne 0x5A4D) {
      throw "Executable does not have a DOS header: $Path"
    }
    $stream.Position = 0x3C
    $peOffset = $reader.ReadUInt32()
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
      throw "Executable does not have a PE header: $Path"
    }
    $stream.Position = $peOffset + 24
    $optionalMagic = $reader.ReadUInt16()
    if ($optionalMagic -notin @(0x10B, 0x20B)) {
      throw "Executable has an unsupported PE optional header: $Path"
    }
    $stream.Position = $peOffset + 24 + 68
    if ($reader.ReadUInt16() -ne 2) {
      throw "Executable is not linked for the Windows GUI subsystem: $Path"
    }
  }
  finally {
    $reader.Dispose()
    $stream.Dispose()
  }
}

$previousTarget = [Environment]::GetEnvironmentVariable($targetVariable, 'Process')
$previousMetadata = [Environment]::GetEnvironmentVariable($metadataVariable, 'Process')
[Environment]::SetEnvironmentVariable($targetVariable, $portableTargetRoot, 'Process')
[Environment]::SetEnvironmentVariable($metadataVariable, $buildMetadata, 'Process')
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
Assert-BuildMetadata $helperPath
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
Assert-BuildMetadata $guiPath
Assert-WindowsGuiSubsystem $guiPath
$postBuildHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($postBuildHash -cne $helperHash) {
  throw 'TUN helper changed after its SHA-256 was embedded in the GUI build'
}
$guiItem = Get-Item -LiteralPath $guiPath -Force
$helperItem = Get-Item -LiteralPath $helperPath -Force
$guiHash = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered] @{
  schemaVersion = 2
  sourceCommit = $sourceCommit
  buildMetadata = $buildMetadata
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
  [Environment]::SetEnvironmentVariable($metadataVariable, $previousMetadata, 'Process')
}

$result
