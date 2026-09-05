[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tag = $env:RELEASE_TAG
if ($tag -cnotmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.([1-9]\d*))?$' -or $tag -cne $tag.Trim()) { throw 'Invalid release tag' }
if ($env:GH_REPO -cne 'oda02/RouteDeck') { throw 'This publisher is scoped to oda02/RouteDeck' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version = (Get-Content -LiteralPath (Join-Path $repo 'package.json') -Raw | ConvertFrom-Json).version
if ($tag -cne "v$version") { throw 'Tag and application version disagree' }
$artifacts = Join-Path $repo 'artifacts'
$archiveName = "RouteDeck-$version-windows-x64.zip"
$inventoryName = 'engine-distribution-inventory.json'
$sumsName = 'SHA256SUMS.txt'
$archive = Join-Path $artifacts $archiveName
$inventoryPath = Join-Path $artifacts $inventoryName
$sums = Join-Path $artifacts $sumsName
$inventoryItem = Get-Item -LiteralPath $inventoryPath -Force -ErrorAction Stop
if ($inventoryItem.PSIsContainer -or $inventoryItem.Length -gt 16777216 -or ($inventoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid engine distribution inventory' }
$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
if ($inventory.schemaVersion -ne 1 -or @($inventory.files).Count -lt 6) { throw 'Invalid engine distribution inventory' }
$inventoryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$assetNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$sourceAssets = [Collections.Generic.List[string]]::new()
$sourceCount = 0
foreach ($file in @($inventory.files)) {
  $path = [string]$file.path
  $allowedDocument = $path -cin @('ENGINE-THIRD-PARTY-NOTICES.txt','SOURCE-CODE.txt')
  $allowedSource = $path -cmatch '^sources/([A-Za-z0-9][A-Za-z0-9._-]*)$'
  $sourceName = if ($allowedSource) { $Matches[1] } else { $null }
  if ((-not $allowedDocument -and -not $allowedSource) -or -not $inventoryPaths.Add($path) -or
      $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
      ($file.size -isnot [int] -and $file.size -isnot [long]) -or $file.size -lt 1 -or $file.size -gt 2147483647) {
    throw 'Invalid engine distribution file contract'
  }
  if ($allowedSource) {
    $sourceCount++
    $name = $sourceName
    if ($name -cin @($archiveName,$inventoryName,$sumsName) -or -not $assetNames.Add($name)) { throw 'Duplicate or reserved source asset name' }
    $asset = Join-Path $artifacts $name
    $item = Get-Item -LiteralPath $asset -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne [long]$file.size -or
        (Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$file.sha256) { throw 'Source asset integrity failed' }
    $sourceAssets.Add($asset)
  }
}
if (-not $inventoryPaths.Contains('ENGINE-THIRD-PARTY-NOTICES.txt') -or -not $inventoryPaths.Contains('SOURCE-CODE.txt') -or $sourceCount -lt 4) { throw 'Engine distribution inventory is incomplete' }
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($archive,$inventoryPath) + @($sourceAssets)) {
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid release asset' }
  $expected.Add($item.Name, (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant())
}
$actual = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in [IO.File]::ReadAllLines($sums)) {
  if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$' -or -not $actual.TryAdd($Matches[2], $Matches[1])) { throw 'Invalid release checksum manifest' }
}
if ($actual.Count -ne $expected.Count) { throw 'Release checksum asset set mismatch' }
foreach ($entry in $expected.GetEnumerator()) {
  if (-not $actual.ContainsKey($entry.Key) -or $actual[$entry.Key] -cne $entry.Value) { throw 'Release asset checksum mismatch' }
}
$notes = Join-Path $artifacts 'release-notes.md'
$downloadLink = "https://github.com/oda02/RouteDeck/releases/download/$tag/$archiveName"
$releaseText = "Скачать приложение: [$archiveName]($downloadLink)`n`n" + @'
Portable для Windows x64: распакуйте весь архив и запустите routedeck.exe. sing-box, Cronet и Xray уже включены; устанавливать движки отдельно не нужно.

The separately attached source archives are optional downloads for inspecting the corresponding external source code. They are not needed to run RouteDeck.

`SHA256SUMS.txt` detects accidental corruption. It is not an independent cryptographic update signature. RouteDeck opens the release page for manual portable replacement and never replaces running files automatically.
'@
[IO.File]::WriteAllText($notes, $releaseText, [Text.UTF8Encoding]::new($false))
$assets = @($archive,$inventoryPath) + @($sourceAssets) + @($sums)
$arguments = @('release','create',$tag) + $assets + @('--repo',$env:GH_REPO,'--verify-tag','--title',"RouteDeck $version",'--notes-file',$notes,'--generate-notes')
if ($version.Contains('-')) { $arguments += @('--prerelease','--latest=false') } else { $arguments += '--latest' }
& gh @arguments
if ($LASTEXITCODE -ne 0) { throw 'Release publication failed; existing assets are preserved' }
