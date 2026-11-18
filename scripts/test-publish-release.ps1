$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $testParent ('RouteDeck-publish-fixture-' + [guid]::NewGuid().ToString('N'))
$previousTag = $env:RELEASE_TAG; $previousRepo = $env:GH_REPO
$nodeExecutable = (Get-Command node.exe).Source
$nodeVerifier = Join-Path $PSScriptRoot 'sign-update.mjs'
$signatureChecks = [Collections.Generic.List[object]]::new()
$fixtureVerifyRejected = $false
# Live signature trust is tested separately with explicit throwaway fixture keys.
# Here only the crypto verdict is mocked; schema/archive and ZIP bytes are real.
function node {
  if ($args[1] -cnotin @('verify','validate')) { throw 'Unexpected publisher Node invocation' }
  if ($args[1] -ceq 'verify') { $signatureChecks.Add(@($args)) }
  if ($args[1] -ceq 'verify' -and $fixtureVerifyRejected) { $global:LASTEXITCODE=1; return }
  & $nodeExecutable $nodeVerifier validate $args[2] $args[3] $args[4]
}
$calls = [Collections.Generic.List[object]]::new()
$commit = 'a' * 40
$sourceCommit = $commit
$remoteSource = $null
$sourceCreateFails = $false
function git {
  if (($args[0] -cne '-C') -or ($args[2..4] -join ' ') -cne 'rev-parse --verify HEAD') { throw 'Unexpected publisher git invocation' }
  $global:LASTEXITCODE = 0
  $commit
}
function gh {
  $calls.Add(@($args)); $global:LASTEXITCODE = 0
  if ($args[0] -ceq 'api') {
    if ($args[1] -ceq "repos/oda02/RouteDeck/commits/sources-$env:RELEASE_TAG") { $sourceCommit }
    elseif ($args[1] -cne "repos/oda02/RouteDeck/releases/tags/sources-$env:RELEASE_TAG") { throw 'Unexpected publisher API request' }
    elseif ($null -eq $remoteSource) { $global:LASTEXITCODE = 1 }
    else { $remoteSource | ConvertTo-Json -Depth 6 }
  } elseif ($args[1] -ceq 'list') {
    if ($args -cnotcontains '--exclude-pre-releases') { throw 'Source releases must be excluded from the changelog base' }
    'v0.1.5'
  } elseif ($args[1] -ceq 'create') {
    if ($args[2].StartsWith('sources-') -and $sourceCreateFails) { $global:LASTEXITCODE = 1 }
  } else { throw 'Unexpected publisher gh invocation' }
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function WriteFile([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function New-Artifacts([string]$Version) {
  Get-ChildItem -LiteralPath $artifacts -Force | Remove-Item -Force
  WriteFile (Join-Path $root 'package.json') ('{"version":"' + $Version + '"}')
  $archiveName = "RouteDeck-$Version-windows-x64.zip"
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::Open((Join-Path $artifacts $archiveName), [IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($path in @('routedeck.exe','routedeck-tun-helper.exe','routedeck-updater.exe','routedeck-build.json','engine/sing-box.exe','engine/libcronet.dll','xray/xray.exe','runtime-pins/sing-box.lock.json','runtime-pins/xray-core.lock.json','ENGINE-THIRD-PARTY-NOTICES.txt','SOURCE-CODE.txt')) {
      $entry = $zip.CreateEntry($path)
      $stream = $entry.Open()
      try { $bytes = [Text.Encoding]::UTF8.GetBytes("synthetic fixture $path"); $stream.Write($bytes,0,$bytes.Length) }
      finally { $stream.Dispose() }
    }
  } finally { $zip.Dispose() }
  if (-not $Version.Contains('-')) {
    & (Join-Path $PSScriptRoot 'write-update-manifest.ps1') -ArchivePath (Join-Path $artifacts $archiveName) -Version $Version
    [IO.File]::WriteAllBytes((Join-Path $artifacts 'RouteDeck-update.sig'), [byte[]](@(7) * 64))
  }
  $files = [Collections.Generic.List[object]]::new()
  foreach ($doc in @('ENGINE-THIRD-PARTY-NOTICES.txt','SOURCE-CODE.txt')) {
    $text = "$doc embedded"; $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    $files.Add([ordered]@{path=$doc;size=[long]$bytes.Length;sha256=$sha})
  }
  foreach ($name in @('sing-box-src.zip','cronet-src.tar.gz','xray-src.zip','licenses-src.zip')) {
    $asset=Join-Path $artifacts $name; WriteFile $asset "$name source fixture"
    $item=Get-Item $asset
    $files.Add([ordered]@{path="sources/$name";size=[long]$item.Length;sha256=(Hash $asset)})
  }
  $inventoryPath=Join-Path $artifacts 'engine-distribution-inventory.json'
  [ordered]@{schemaVersion=1;files=@($files)} | ConvertTo-Json -Depth 5 | Set-Content $inventoryPath -Encoding utf8NoBOM
  $names=@($archiveName,'engine-distribution-inventory.json','sing-box-src.zip','cronet-src.tar.gz','xray-src.zip','licenses-src.zip')
  if (-not $Version.Contains('-')) { $names += @('RouteDeck-update.json','RouteDeck-update.sig') }
  $lines=foreach($name in $names){"$(Hash (Join-Path $artifacts $name))  $name"}
  WriteFile (Join-Path $artifacts 'SHA256SUMS.txt') (($lines -join "`n")+"`n")
}
function Reject([string]$Message,[scriptblock]$Mutation) {
  New-Artifacts '0.2.0'; $env:RELEASE_TAG='v0.2.0'; & $Mutation
  $before=$calls.Count
  try { & $publisher } catch {
    if ($_.Exception.Message -notmatch $Message) { throw }
    if ($calls.Count -ne $before) { throw 'Rejected fixture reached gh' }
    Write-Output "PASS: rejected $Message"; return
  }
  throw "Expected rejection: $Message"
}
try {
  $scripts=Join-Path $root 'scripts'; $artifacts=Join-Path $root 'artifacts'
  New-Item -ItemType Directory -Path $scripts,$artifacts | Out-Null
  $publisher=Join-Path $scripts 'publish-release.ps1'
  Copy-Item (Join-Path $PSScriptRoot 'publish-release.ps1') $publisher
  $env:GH_REPO='oda02/RouteDeck'
  foreach($version in @('0.2.0','0.3.0-beta.1')) {
    New-Artifacts $version; $env:RELEASE_TAG="v$version"; & $publisher
    $call=$calls[-1]
    $sourceCall = $calls[-3]
    $appNames = @("RouteDeck-$version-windows-x64.zip#Скачать RouteDeck для Windows x64 · Portable")
    $sourceNames = @('engine-distribution-inventory.json','sing-box-src.zip','cronet-src.tar.gz','xray-src.zip','licenses-src.zip')
    if ($sourceCall[2] -cne "sources-v$version" -or $sourceCall -cnotcontains '--prerelease' -or $sourceCall -cnotcontains '--latest=false' -or $sourceCall -cnotcontains $commit) { throw 'Bad engine source release semantics' }
    if (($sourceNames -join ',') -cne (($sourceCall[3..7] | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ',') -or $sourceCall[8] -cne '--repo') { throw 'Wrong source asset set' }
    if ($call[2] -cne "v$version" -or $call -cnotcontains '--notes-start-tag' -or $call -cnotcontains 'v0.1.5') { throw 'Bad app release tag or changelog base' }
    $notes = Get-Content -LiteralPath (Join-Path $artifacts 'release-notes.md') -Raw -Encoding utf8
    $download = "https://github.com/oda02/RouteDeck/releases/download/v$version/RouteDeck-$version-windows-x64.zip"
    $sourceLink = "https://github.com/oda02/RouteDeck/releases/tag/sources-v$version"
    if (-not $notes.StartsWith("## [Скачать RouteDeck для Windows x64 · Portable]($download)") -or
        $notes -cnotmatch "(?s)<details>.*$([regex]::Escape($sourceLink)).*</details>" -or
        -not $notes.Contains((Hash (Join-Path $artifacts "RouteDeck-$version-windows-x64.zip")))) { throw 'Release notes are missing the prominent download, source disclosure, or archive digest' }
    if (-not $version.Contains('-')) {
      $appNames += @('RouteDeck-update.json','RouteDeck-update.sig')
      if ($signatureChecks.Count -lt 1) { throw 'Publication skipped signature verification' }
    }
    $firstFlag = [array]::IndexOf($call, '--repo')
    if (($appNames -join ',') -cne (($call[3..($firstFlag - 1)] | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ',')) { throw 'Wrong app asset set' }
    if ($call -contains '--clobber' -or $call -contains '--force' -or $call -notcontains '--verify-tag') { throw 'Unsafe gh invocation' }
    if ($version.Contains('-')) { if ($call -notcontains '--prerelease' -or $call -notcontains '--latest=false') {throw 'Bad prerelease semantics'} }
    elseif ($call -notcontains '--latest') { throw 'Stable release not latest' }
  }
  $sourceCreateFails = $true
  $remoteSource = @{
    draft = $false; prerelease = $true; tag_name = 'sources-v0.3.0-beta.1'
    assets = @(foreach ($name in $sourceNames) { @{ name = $name; digest = "sha256:$(Hash (Join-Path $artifacts $name))"; state = 'uploaded' } })
  }
  & $publisher
  if ($calls[-1][2] -cne 'v0.3.0-beta.1') { throw 'Could not resume after source publication' }
  $remoteSource.assets[0].digest = 'sha256:' + ('f' * 64)
  try { & $publisher; throw 'Accepted mismatched engine source release' } catch {
    if ($_.Exception.Message -cnotmatch 'Existing engine source release does not match this build' -or $calls[-1][0] -cne 'api') { throw }
  }
  $remoteSource = $null
  try { & $publisher; throw 'Published app without a source release' } catch {
    if ($_.Exception.Message -cnotmatch 'Engine source release publication failed' -or $calls[-1][0] -cne 'api') { throw }
  }
  $sourceCreateFails = $false
  $sourceCommit = 'b' * 40
  try { & $publisher; throw 'Published app with a foreign source tag' } catch {
    if ($_.Exception.Message -cnotmatch 'Engine source tag does not match the release source commit' -or $calls[-1][0] -cne 'api') { throw }
  }
  $sourceCommit = $commit
  Reject 'Source asset integrity failed' { Add-Content (Join-Path $artifacts 'licenses-src.zip') 'tampered' }
  Reject 'Update signature verification failed' { $script:fixtureVerifyRejected=$true }
  $fixtureVerifyRejected=$false
  Reject 'Signed update packaged file integrity failed' {
    $path=Join-Path $artifacts 'RouteDeck-update.json'; $manifest=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    $manifest.files[0].sha256='a'*64
    WriteFile $path (($manifest|ConvertTo-Json -Depth 5 -Compress)+"`n")
  }
  Reject 'Cannot find path' { Remove-Item (Join-Path $artifacts 'xray-src.zip') }
  Reject 'Release checksum asset set mismatch' { Add-Content (Join-Path $artifacts 'SHA256SUMS.txt') ('0'*64+'  unknown.zip') }
  Reject 'Invalid release checksum manifest' { $sum=Get-Content (Join-Path $artifacts 'SHA256SUMS.txt'); Set-Content (Join-Path $artifacts 'SHA256SUMS.txt') @($sum+$sum[0]) }
  Reject 'Invalid engine distribution file contract' {
    $p=Join-Path $artifacts 'engine-distribution-inventory.json'; $i=Get-Content $p -Raw|ConvertFrom-Json; $i.files[2].path='sources/../escape.zip'; $i|ConvertTo-Json -Depth 5|Set-Content $p
  }
  Reject 'Invalid engine distribution inventory|Engine distribution inventory is incomplete' {
    $p=Join-Path $artifacts 'engine-distribution-inventory.json'; $i=Get-Content $p -Raw|ConvertFrom-Json; $i.files=@($i.files|Where-Object path -ne 'SOURCE-CODE.txt'); $i|ConvertTo-Json -Depth 5|Set-Content $p
  }
  $env:RELEASE_TAG='v0.2.0;unsafe'; try{&$publisher;throw 'accepted invalid tag'}catch{if($_.Exception.Message-notmatch'Invalid release tag'){throw}}
  $env:RELEASE_TAG='v0.2.0';$env:GH_REPO='foreign/repo';try{&$publisher;throw 'accepted repo'}catch{if($_.Exception.Message-notmatch'scoped'){throw}}
  $env:GH_REPO='oda02/RouteDeck'; $env:RELEASE_TAG='v0.2.1'
  try { & $publisher; throw 'accepted mismatched version' } catch { if ($_.Exception.Message -notmatch 'Tag and application version disagree') { throw } }
  Write-Output 'PASS: full portable publisher assets and stable/prerelease boundary; gh fully mocked'
} finally {
  $env:RELEASE_TAG=$previousTag; $env:GH_REPO=$previousRepo
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith($testParent.TrimEnd('\')+'\RouteDeck-publish-fixture-',[StringComparison]::OrdinalIgnoreCase)){throw'Unsafe fixture cleanup'}
  if(Test-Path $safe){Remove-Item $safe -Recurse -Force}
}
