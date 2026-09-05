[CmdletBinding()]
param(
  [string] $BuildRoot = (Join-Path $PSScriptRoot '..\src-tauri\target\portable\release'),
  [string] $OutputRoot = (Join-Path $PSScriptRoot '..\artifacts'),
  [string] $NoticesRoot = (Join-Path $PSScriptRoot '..\artifacts\notices')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputRoot)
$versionJson = & node (Join-Path $PSScriptRoot 'release-version.mjs') check
if ($LASTEXITCODE -ne 0) { throw 'Release version validation failed' }
$version = ($versionJson | ConvertFrom-Json).version
$name = "RouteDeck-$version-windows-x64.zip"
$archive = Join-Path $output $name
$checksums = Join-Path $output 'SHA256SUMS.txt'
if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath $checksums)) { throw 'Output already exists; release artifacts are never overwritten' }
$manifestPath = Join-Path $BuildRoot 'routedeck-build.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 2 -or $manifest.sourceCommit -cnotmatch '^[a-f0-9]{40}$' -or
    $manifest.buildMetadata -cne "RouteDeckBuildCommit=$($manifest.sourceCommit)") { throw 'Invalid build provenance' }
$expectedNames = @('routedeck.exe', 'routedeck-tun-helper.exe')
if (@($manifest.files).Count -ne 2) { throw 'Unexpected build file count' }
for ($i = 0; $i -lt 2; $i++) {
  $entry = $manifest.files[$i]
  if ($entry.path -cne $expectedNames[$i] -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Unexpected build file entry' }
  $file = Get-Item -LiteralPath (Join-Path $BuildRoot $expectedNames[$i]) -Force
  if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $entry.size -or
      (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Build file integrity failed' }
}
$guiText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $BuildRoot 'routedeck.exe')))
if (-not $guiText.Contains([string]$manifest.files[1].sha256) -or -not $guiText.Contains([string]$manifest.buildMetadata)) { throw 'GUI does not pin this helper and source' }
$notices = [IO.Path]::GetFullPath($NoticesRoot)
foreach ($notice in @('THIRD-PARTY-NOTICES.txt', 'third-party-inventory.json')) {
  if (-not (Test-Path -LiteralPath (Join-Path $notices $notice) -PathType Leaf)) { throw 'Generate controller dependency notices before packaging' }
}
$sourceName = 'selectors-0.36.1.crate'
$sourcePath = Join-Path $notices "sources\$sourceName"
$inventory = Get-Content -LiteralPath (Join-Path $notices 'third-party-inventory.json') -Raw | ConvertFrom-Json
$sourceEntry = @($inventory.dependencies | Where-Object { $_.name -ceq 'selectors' -and $_.version -ceq '0.36.1' })
if ($sourceEntry.Count -ne 1 -or @($sourceEntry[0].sourceArchives).Count -ne 1 -or
    $sourceEntry[0].sourceArchives[0].name -cne $sourceName -or
    (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceEntry[0].sourceArchives[0].sha256) { throw 'Controller source archive integrity failed' }
[IO.Directory]::CreateDirectory($output) | Out-Null
$stage = Join-Path $output ('.controller-stage-' + [guid]::NewGuid().ToString('N'))
try {
  [IO.Directory]::CreateDirectory($stage) | Out-Null
  foreach ($file in $expectedNames + @('routedeck-build.json')) { Copy-Item -LiteralPath (Join-Path $BuildRoot $file) -Destination (Join-Path $stage $file) }
  Copy-Item -LiteralPath (Join-Path $repoRoot 'docs\portable-release.txt') -Destination (Join-Path $stage 'README.txt')
  Copy-Item -LiteralPath (Join-Path $notices 'THIRD-PARTY-NOTICES.txt') -Destination $stage
  Copy-Item -LiteralPath (Join-Path $notices 'third-party-inventory.json') -Destination (Join-Path $stage 'dependency-inventory.json')
  $sources = Join-Path $stage 'controller-sources'
  [IO.Directory]::CreateDirectory($sources) | Out-Null
  Copy-Item -LiteralPath $sourcePath -Destination $sources
  $pins = Join-Path $stage 'runtime-pins'
  [IO.Directory]::CreateDirectory($pins) | Out-Null
  foreach ($file in @('sing-box.lock.json', 'xray-core.lock.json')) { Copy-Item -LiteralPath (Join-Path $repoRoot "engine\$file") -Destination $pins }
  # Only the explicit controller files enter the archive; engines, .env, runtime
  # sessions, subscriptions and build directories are never copied recursively.
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::CreateFromDirectory($stage, $archive)
  $zip = [IO.Compression.ZipFile]::OpenRead($archive)
  try {
    $allowed = @('routedeck.exe','routedeck-tun-helper.exe','routedeck-build.json','README.txt','THIRD-PARTY-NOTICES.txt','dependency-inventory.json','runtime-pins/sing-box.lock.json','runtime-pins/xray-core.lock.json',"controller-sources/$sourceName")
    $actual = @($zip.Entries | ForEach-Object { $_.FullName.Replace('\','/') })
    if ($actual.Count -ne $allowed.Count -or @(Compare-Object $allowed $actual).Count -ne 0) { throw 'Unexpected archive contents' }
  } finally { $zip.Dispose() }
  $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText($checksums, "$hash  $name`n", [Text.UTF8Encoding]::new($false))
} finally {
  $safeStage = [IO.Path]::GetFullPath($stage)
  if (-not $safeStage.StartsWith($output.TrimEnd('\') + '\.controller-stage-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staging cleanup path' }
  if (Test-Path -LiteralPath $safeStage) { Remove-Item -LiteralPath $safeStage -Recurse -Force }
}
Write-Output "Verified controller archive: $name"
