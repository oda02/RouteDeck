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
$updateAssets = @()
if (-not $version.Contains('-')) {
  $descriptor = Join-Path $artifacts 'RouteDeck-update.json'
  $signature = Join-Path $artifacts 'RouteDeck-update.sig'
  foreach ($path in @($descriptor,$signature)) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 262144) { throw 'Invalid update signature assets' }
  }
  & node (Join-Path $PSScriptRoot 'sign-update.mjs') verify $descriptor $archive $version
  if ($LASTEXITCODE -ne 0) { throw 'Update signature verification failed' }
  $update = Get-Content -LiteralPath $descriptor -Raw | ConvertFrom-Json
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($archive)
  try {
    if ($zip.Entries.Count -ne @($update.files).Count) { throw 'Signed update file set mismatch' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $zip.Entries) {
      $expectedFile = @($update.files | Where-Object { $_.path -ceq $entry.FullName })
      if (-not $seen.Add($entry.FullName) -or $expectedFile.Count -ne 1 -or $entry.Length -ne $expectedFile[0].size) { throw 'Signed update file set mismatch' }
      $stream = $entry.Open(); $digest = [Security.Cryptography.SHA256]::Create()
      try {
        $actualHash = [Convert]::ToHexString($digest.ComputeHash($stream)).ToLowerInvariant()
        if ($actualHash -cne $expectedFile[0].sha256) { throw 'Signed update packaged file integrity failed' }
      } finally { $digest.Dispose(); $stream.Dispose() }
    }
  } finally { $zip.Dispose() }
  $updateAssets = @($descriptor,$signature)
}
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($path in @($archive,$inventoryPath) + @($sourceAssets) + $updateAssets) {
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
$sourceTag = "sources-$tag"
$releaseBase = "https://github.com/$($env:GH_REPO)/releases"
$downloadLink = "$releaseBase/download/$tag/$archiveName"
$downloadLabel = 'Скачать RouteDeck для Windows x64 · Portable'
$releaseText = @"
## [$downloadLabel]($downloadLink)

Распакуйте весь ZIP и запустите ``routedeck.exe``. sing-box, Cronet и Xray уже входят в архив.

<details>
<summary>Лицензии, исходный код и SHA-256</summary>

Тексты лицензий входят в ZIP. [Исходный код компонентов этой версии]($releaseBase/tag/$sourceTag) доступен отдельным выпуском.

SHA-256 portable ZIP — ``$($expected[$archiveName])``

</details>
"@
[IO.File]::WriteAllText($notes, $releaseText, [Text.UTF8Encoding]::new($false))
$commit = & git -C $repo rev-parse --verify HEAD
if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Could not resolve the release source commit' }
$previousTag = & gh release list --repo $env:GH_REPO --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName // empty'
if ($LASTEXITCODE -ne 0) { throw 'Could not determine the previous stable release' }
$sourceFiles = @($inventoryPath) + @($sourceAssets)
$sourceNotes = "Исходный код компонентов, входящих в [RouteDeck $version]($releaseBase/tag/$tag). Контрольные суммы файлов указаны в engine-distribution-inventory.json."
$sourceArguments = @('release','create',$sourceTag) + $sourceFiles + @('--repo',$env:GH_REPO,'--target',$commit,'--title',"RouteDeck $version · Исходный код компонентов",'--notes',$sourceNotes,'--prerelease','--latest=false')
& gh @sourceArguments
if ($LASTEXITCODE -ne 0) {
  # A retry can proceed only if the complete companion was already published.
  $remoteJson = & gh api "repos/$($env:GH_REPO)/releases/tags/$sourceTag"
  if ($LASTEXITCODE -ne 0) { throw 'Engine source release publication failed' }
  $remote = $remoteJson | ConvertFrom-Json
  $remoteNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  if ($remote.draft -or -not $remote.prerelease -or $remote.tag_name -cne $sourceTag -or
      @($remote.assets).Count -ne $sourceFiles.Count) {
    throw 'Existing engine source release does not match this build'
  }
  foreach ($asset in $remote.assets) {
    if ($asset.state -ceq 'uploaded') { [void]$remoteNames.Add("$($asset.name):$($asset.digest)") }
  }
  foreach ($path in $sourceFiles) {
    $name = [IO.Path]::GetFileName($path)
    if (-not $remoteNames.Contains("${name}:sha256:$($expected[$name])")) { throw 'Existing engine source release does not match this build' }
  }
}
$sourceCommit = & gh api "repos/$($env:GH_REPO)/commits/$sourceTag" --jq .sha
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cne $commit) { throw 'Engine source tag does not match the release source commit' }
$assets = @("$archive#$downloadLabel") + $updateAssets
$arguments = @('release','create',$tag) + $assets + @('--repo',$env:GH_REPO,'--verify-tag','--title',"RouteDeck $version",'--notes-file',$notes,'--generate-notes')
if ($previousTag -and $previousTag -cne $tag) { $arguments += @('--notes-start-tag',$previousTag) }
if ($version.Contains('-')) { $arguments += @('--prerelease','--latest=false') } else { $arguments += '--latest' }
& gh @arguments
if ($LASTEXITCODE -ne 0) { throw 'Release publication failed; existing assets are preserved' }
