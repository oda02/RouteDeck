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
$archiveName = "RouteDeck-$version-windows-x64.zip"
$archive = Join-Path $repo "artifacts\$archiveName"
$sums = Join-Path $repo 'artifacts\SHA256SUMS.txt'
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ([IO.File]::ReadAllText($sums).Trim() -cne "$hash  $archiveName") { throw 'Release archive checksum mismatch' }
$notes = Join-Path $repo 'artifacts\release-notes.md'
[IO.File]::WriteAllText($notes, @'
Windows x64 portable controller. Includes RouteDeck and its matching on-demand TUN helper.

This archive does not bundle sing-box, Cronet or Xray. For an existing portable installation, close RouteDeck and replace the controller files together, preserving the `engine` and `xray` directories. Preferences and subscriptions remain in the current user's application data directory. First-time runtime setup is described in the included README.

`SHA256SUMS.txt` detects accidental corruption. It is not an independent cryptographic update signature. This version checks for stable GitHub releases and opens the download page; it does not replace running files automatically.
'@, [Text.UTF8Encoding]::new($false))
$arguments = @('release','create',$tag,$archive,$sums,'--repo',$env:GH_REPO,'--verify-tag','--title',"RouteDeck $version",'--notes-file',$notes,'--generate-notes')
if ($version.Contains('-')) { $arguments += @('--prerelease','--latest=false') } else { $arguments += '--latest' }
# gh refuses an existing release; no delete, force, overwrite or clobber option.
& gh @arguments
if ($LASTEXITCODE -ne 0) { throw 'Release publication failed; existing assets are preserved' }
