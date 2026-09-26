[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ArchivePath, [Parameter(Mandatory=$true)][string]$Version)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Version -cnotmatch '^(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})$') { throw 'Update manifests require a stable version' }
$archive = Get-Item -LiteralPath $ArchivePath -Force
if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $archive.Length -lt 1 -or $archive.Length -gt 536870912 -or $archive.Name -cne "RouteDeck-$Version-windows-x64.zip") { throw 'Invalid update archive' }
$descriptor = Join-Path $archive.DirectoryName 'RouteDeck-update.json'
if (Test-Path -LiteralPath $descriptor) { throw 'Update descriptor already exists' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive.FullName)
try {
  $expanded = 0L
  if ($zip.Entries.Count -lt 9 -or $zip.Entries.Count -gt 512) { throw 'Invalid update file count' }
  foreach ($entry in $zip.Entries) {
    $expanded += $entry.Length
    $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
    if ($entry.Length -lt 1 -or $entry.Length -gt 536870912 -or $expanded -gt 1073741824 -or $unixType -notin @(0,0x8000)) { throw 'Invalid update archive entries' }
  }
  $files = @($zip.Entries | Sort-Object -Property FullName | ForEach-Object {
    $entry = $_
    if ($entry.Length -lt 1 -or $entry.Length -gt 536870912) { throw 'Invalid update file size' }
    $stream = $entry.Open(); $digest = [Security.Cryptography.SHA256]::Create()
    try { $hash = [Convert]::ToHexString($digest.ComputeHash($stream)).ToLowerInvariant() }
    finally { $digest.Dispose(); $stream.Dispose() }
    [ordered]@{path=$entry.FullName; size=[long]$entry.Length; sha256=$hash}
  })
} finally { $zip.Dispose() }
$manifest = [ordered]@{ schemaVersion=1; version=$Version; platform='windows-x64'; archive=$archive.Name; size=[long]$archive.Length; sha256=(Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); files=$files }
$body = [Text.UTF8Encoding]::new($false).GetBytes(($manifest | ConvertTo-Json -Depth 5 -Compress) + "`n")
$out = [IO.File]::Open($descriptor, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $out.Write($body,0,$body.Length); $out.Flush($true) } finally { $out.Dispose() }
& node (Join-Path $PSScriptRoot 'sign-update.mjs') validate $descriptor $archive.FullName $Version
if ($LASTEXITCODE -ne 0) { throw 'Full update manifest validation failed' }
