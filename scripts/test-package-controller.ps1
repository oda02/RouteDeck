$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $testParent ('RouteDeck-package-fixture-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
function Assert-Rejected([scriptblock] $Action, [string] $Message) {
  try { & $Action | Out-Null } catch {
    if ($_.Exception.Message.Contains($Message)) { Write-Output "PASS: $Message"; return }
    throw
  }
  throw "Expected rejection: $Message"
}
try {
  $build = Join-Path $root 'build'
  $notices = Join-Path $root 'notices'
  [IO.Directory]::CreateDirectory($build) | Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $notices 'sources')) | Out-Null
  $helper = Join-Path $build 'routedeck-tun-helper.exe'
  $gui = Join-Path $build 'routedeck.exe'
  [IO.File]::WriteAllText($helper, 'synthetic helper, never executable')
  $helperHash = (Get-FileHash $helper).Hash.ToLowerInvariant()
  $commit = '1' * 40
  $metadata = "RouteDeckBuildCommit=$commit"
  [IO.File]::WriteAllText($gui, "synthetic GUI $metadata $helperHash")
  $entries = @($gui,$helper) | ForEach-Object { @{path=[IO.Path]::GetFileName($_);size=(Get-Item $_).Length;sha256=(Get-FileHash $_).Hash.ToLowerInvariant()} }
  $version = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\package.json') -Raw | ConvertFrom-Json).version
  @{schemaVersion=2;applicationVersion=$version;sourceCommit=$commit;buildMetadata=$metadata;files=@($entries)} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $build 'routedeck-build.json')
  [IO.File]::WriteAllText((Join-Path $build 'must-not-ship.env'), 'synthetic private state')
  [IO.File]::WriteAllText((Join-Path $notices 'THIRD-PARTY-NOTICES.txt'), 'synthetic notices')
  $source = Join-Path $notices 'sources\selectors-0.36.1.crate'
  [IO.File]::WriteAllText($source, 'synthetic source archive, never extracted')
  @{dependencies=@(@{name='selectors';version='0.36.1';sourceArchives=@(@{name='selectors-0.36.1.crate';sha256=(Get-FileHash $source).Hash.ToLowerInvariant()})})} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $notices 'third-party-inventory.json')
  $output = Join-Path $root 'valid'
  & (Join-Path $PSScriptRoot 'package-controller.ps1') -BuildRoot $build -NoticesRoot $notices -OutputRoot $output
  $archive = @(Get-ChildItem $output -Filter '*.zip')
  if ($archive.Count -ne 1) { throw 'Expected one archive' }
  $originalHash = (Get-FileHash $archive[0].FullName).Hash
  Assert-Rejected { & (Join-Path $PSScriptRoot 'package-controller.ps1') -BuildRoot $build -NoticesRoot $notices -OutputRoot $output } 'Output already exists'
  if ((Get-FileHash $archive[0].FullName).Hash -cne $originalHash) { throw 'Existing archive changed' }
  $manifestPath = Join-Path $build 'routedeck-build.json'
  $originalManifest = [IO.File]::ReadAllText($manifestPath)
  $staleManifest = $originalManifest | ConvertFrom-Json
  $staleManifest.applicationVersion = '0.0.0'
  $staleManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath
  Assert-Rejected { & (Join-Path $PSScriptRoot 'package-controller.ps1') -BuildRoot $build -NoticesRoot $notices -OutputRoot (Join-Path $root 'stale-version') } 'Invalid build provenance'
  [IO.File]::WriteAllText($manifestPath, $originalManifest)
  function Copy-Item {
    param([string] $LiteralPath, [string] $Destination, [switch] $Force)
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    if ($LiteralPath.EndsWith('routedeck-tun-helper.exe')) {
      [IO.File]::AppendAllText($Destination, 'fixture corruption during copy')
    }
  }
  Assert-Rejected { & (Join-Path $PSScriptRoot 'package-controller.ps1') -BuildRoot $build -NoticesRoot $notices -OutputRoot (Join-Path $root 'copy-race') } 'Packaged file integrity failed'
  Remove-Item Function:\Copy-Item
  [IO.File]::AppendAllText($helper, 'tampered')
  Assert-Rejected { & (Join-Path $PSScriptRoot 'package-controller.ps1') -BuildRoot $build -NoticesRoot $notices -OutputRoot (Join-Path $root 'tampered') } 'Build file integrity failed'
  if (Test-Path (Join-Path $root 'tampered')) { throw 'Tampered build produced output' }
  Write-Output 'PASS: controller packaging fixtures; explicit archive allow-list excludes extra private state'
} finally {
  $safe = [IO.Path]::GetFullPath($root)
  if (-not $safe.StartsWith($testParent.TrimEnd('\') + '\RouteDeck-package-fixture-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup' }
  Remove-Item -LiteralPath $safe -Recurse -Force
}
