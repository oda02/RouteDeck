[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $Archive,
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [string] $SourceCommit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($SourceCommit -cnotmatch '^[a-f0-9]{40}$') { throw 'Invalid expected source commit' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Archive).ProviderPath)
try {
  $entries = @($zip.Entries | Where-Object { $_.FullName -ieq 'routedeck-build.json' })
  if ($entries.Count -ne 1 -or $entries[0].FullName -cne 'routedeck-build.json' -or
      $entries[0].Length -lt 1 -or $entries[0].Length -gt 4096) {
    throw 'Invalid packaged build manifest entry'
  }

  $reader = [IO.BinaryReader]::new($entries[0].Open())
  try {
    $bytes = $reader.ReadBytes(4097)
    if ($bytes.Length -ne $entries[0].Length) { throw 'Invalid packaged build manifest length' }
    $manifest = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -AsHashtable -NoEnumerate
    if ($manifest -isnot [Collections.IDictionary] -or
        $manifest['schemaVersion'] -isnot [long] -or $manifest['schemaVersion'] -ne 3 -or
        $manifest['applicationVersion'] -isnot [string] -or $manifest['applicationVersion'] -cne $Version -or
        $manifest['sourceCommit'] -isnot [string] -or $manifest['sourceCommit'] -cne $SourceCommit -or
        $manifest['buildMetadata'] -isnot [string] -or $manifest['buildMetadata'] -cne "RouteDeckBuildCommit=$SourceCommit") {
      throw 'Packaged build manifest does not match the tagged version and source commit'
    }
  } finally {
    $reader.Dispose()
  }
} finally {
  $zip.Dispose()
}
