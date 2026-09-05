$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $testParent ('RouteDeck-publish-fixture-' + [guid]::NewGuid().ToString('N'))
$previousTag = $env:RELEASE_TAG
$previousRepo = $env:GH_REPO
$fixturePublishCalls = [Collections.Generic.List[object]]::new()
function gh {
  # Shadow the executable inside this fixture only. No release API is called.
  $fixturePublishCalls.Add(@($args))
  $global:LASTEXITCODE = 0
}
function Assert-PublishRejected([scriptblock] $Action, [string] $Message) {
  $before = $fixturePublishCalls.Count
  try { & $Action } catch {
    if (-not $_.Exception.Message.Contains($Message)) { throw }
    if ($fixturePublishCalls.Count -ne $before) { throw 'Rejected input reached publication' }
    Write-Output "PASS: $Message"
    return
  }
  throw "Expected rejection: $Message"
}
try {
  $scripts = Join-Path $root 'scripts'
  $artifacts = Join-Path $root 'artifacts'
  [IO.Directory]::CreateDirectory($scripts) | Out-Null
  [IO.Directory]::CreateDirectory($artifacts) | Out-Null
  $publisher = Join-Path $scripts 'publish-release.ps1'
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'publish-release.ps1') -Destination $publisher
  $env:GH_REPO = 'oda02/RouteDeck'
  foreach ($version in @('0.2.0','0.3.0-beta.1')) {
    $env:RELEASE_TAG = "v$version"
    [IO.File]::WriteAllText((Join-Path $root 'package.json'), ('{"version":"' + $version + '"}'))
    $name = "RouteDeck-$version-windows-x64.zip"
    $archive = Join-Path $artifacts $name
    [IO.File]::WriteAllText($archive, 'fixture only, never published')
    $hash = (Get-FileHash $archive).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $artifacts 'SHA256SUMS.txt'), "$hash  $name`n")
    & $publisher
    $invocation = $fixturePublishCalls[-1]
    if ($invocation[0] -cne 'release' -or $invocation[1] -cne 'create' -or
        $invocation[2] -cne $env:RELEASE_TAG -or $invocation -notcontains '--verify-tag' -or
        $invocation -contains '--clobber' -or $invocation -contains '--force') { throw 'Unexpected publish command' }
    if ($version.Contains('-')) {
      if ($invocation -notcontains '--prerelease' -or $invocation -notcontains '--latest=false') { throw 'Prerelease would affect stable latest' }
    } elseif ($invocation -notcontains '--latest') { throw 'Stable release not marked latest' }
  }
  $env:RELEASE_TAG = 'v0.3.0-beta.1;echo unsafe'
  Assert-PublishRejected { & $publisher } 'Invalid release tag'
  $env:RELEASE_TAG = 'v0.3.0-beta.1'
  $env:GH_REPO = 'foreign/repository'
  Assert-PublishRejected { & $publisher } 'scoped to oda02/RouteDeck'
  $env:GH_REPO = 'oda02/RouteDeck'
  $env:RELEASE_TAG = 'v0.3.0'
  Assert-PublishRejected { & $publisher } 'Tag and application version disagree'
  $env:RELEASE_TAG = 'v0.3.0-beta.1'
  [IO.File]::AppendAllText($archive, 'corruption')
  Assert-PublishRejected { & $publisher } 'checksum mismatch'
  Write-Output 'PASS: stable/prerelease publication boundary; all GitHub calls mocked'
} finally {
  $env:RELEASE_TAG = $previousTag
  $env:GH_REPO = $previousRepo
  $safe = [IO.Path]::GetFullPath($root)
  if (-not $safe.StartsWith($testParent.TrimEnd('\') + '\RouteDeck-publish-fixture-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup' }
  if (Test-Path -LiteralPath $safe) { Remove-Item -LiteralPath $safe -Recurse -Force }
}
