[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'fetch-reviewed-runtimes.ps1') -DestinationRoot ignored
$root = Join-Path ([IO.Path]::GetTempPath()) ('RouteDeck-fetch-fixture-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
function Hash([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
function Make-Zip([string]$path, [hashtable]$entries) {
  Add-Type -AssemblyName System.IO.Compression
  $z=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
  try { foreach($n in $entries.Keys){$e=$z.CreateEntry($n);$s=$e.Open();try{$b=[Text.Encoding]::UTF8.GetBytes($entries[$n]);$s.Write($b,0,$b.Length)}finally{$s.Dispose()}} } finally {$z.Dispose()}
}
function Spec([string]$zip,[string]$name,[string]$text) {
  $bytes=[Text.Encoding]::UTF8.GetBytes($text); $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
  [pscustomobject]@{releaseAsset=[pscustomobject]@{size=(Get-Item $zip).Length;sha256=(Hash $zip);archiveEntries=@([pscustomobject]@{path=$name;size=$bytes.Length})};runtimeFiles=@([pscustomobject]@{path='runtime.exe';archivePath=$name;size=$bytes.Length;sha256=$sha})}
}
try {
  $downloadBytes=[Text.Encoding]::UTF8.GetBytes('bounded fixture'); $downloadSha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($downloadBytes)).ToLowerInvariant()
  $memory=[IO.MemoryStream]::new($downloadBytes); try { Copy-PinnedStream $memory $downloadBytes.Length $downloadSha (Join-Path $root 'download.bin') } finally {$memory.Dispose()}
  $memory=[IO.MemoryStream]::new($downloadBytes); try { try { Copy-PinnedStream $memory ($downloadBytes.Length-1) $downloadSha (Join-Path $root 'oversize.bin'); throw 'accepted oversize stream' } catch { if($_.Exception.Message -notmatch 'exceeded pinned size'){throw} } } finally {$memory.Dispose()}
  $zip=Join-Path $root 'ok.zip'; Make-Zip $zip @{'upstream/runtime.exe'='fixture runtime'}
  $out=Join-Path $root 'out'; Expand-ReviewedRuntimeArchive (Spec $zip 'upstream/runtime.exe' 'fixture runtime') $zip $out
  if ([IO.File]::ReadAllText((Join-Path $out 'runtime.exe')) -cne 'fixture runtime') { throw 'fixture extraction failed' }
  foreach($case in @(
    @{n='extra executable'; entries=@{'upstream/runtime.exe'='fixture runtime';'evil.ps1'='x'}; match='entry count'},
    @{n='traversal'; entries=@{'../runtime.exe'='fixture runtime'}; match='unsafe ZIP'},
    @{n='hash mismatch'; entries=@{'upstream/runtime.exe'='changed runtime'}; match='runtime SHA-256 mismatch'}
  )) {
    $bad=Join-Path $root (($case.n -replace ' ','-')+'.zip'); Make-Zip $bad $case.entries
    try { Expand-ReviewedRuntimeArchive (Spec $bad 'upstream/runtime.exe' 'fixture runtime') $bad (Join-Path $root ([guid]::NewGuid().ToString('N'))); throw "accepted $($case.n)" }
    catch { if ($_.Exception.Message -notmatch $case.match) { throw } }
  }
  Write-Output 'PASS: reviewed runtime fetch extraction fixtures'
} finally { if(Test-Path $root){Remove-Item -LiteralPath $root -Recurse -Force} }
