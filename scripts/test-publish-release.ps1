$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$testParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $testParent ('RouteDeck-publish-fixture-' + [guid]::NewGuid().ToString('N'))
$previousTag = $env:RELEASE_TAG; $previousRepo = $env:GH_REPO
$calls = [Collections.Generic.List[object]]::new()
function gh { $calls.Add(@($args)); $global:LASTEXITCODE = 0 }
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function WriteFile([string]$Path,[string]$Text) { [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function New-Artifacts([string]$Version) {
  Get-ChildItem -LiteralPath $artifacts -Force | Remove-Item -Force
  WriteFile (Join-Path $root 'package.json') ('{"version":"' + $Version + '"}')
  $archiveName = "RouteDeck-$Version-windows-x64.zip"; WriteFile (Join-Path $artifacts $archiveName) 'complete portable fixture'
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
    foreach($name in @("RouteDeck-$version-windows-x64.zip",'engine-distribution-inventory.json','sing-box-src.zip','cronet-src.tar.gz','xray-src.zip','licenses-src.zip','SHA256SUMS.txt')) {
      if (-not (@($call | ForEach-Object { [IO.Path]::GetFileName([string]$_) }) -ccontains $name)) { throw "Missing gh asset $name" }
    }
    if ($call -contains '--clobber' -or $call -contains '--force' -or $call -notcontains '--verify-tag') { throw 'Unsafe gh invocation' }
    if ($version.Contains('-')) { if ($call -notcontains '--prerelease' -or $call -notcontains '--latest=false') {throw 'Bad prerelease semantics'} }
    elseif ($call -notcontains '--latest') { throw 'Stable release not latest' }
  }
  Reject 'Source asset integrity failed' { Add-Content (Join-Path $artifacts 'licenses-src.zip') 'tampered' }
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
