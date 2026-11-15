[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = Join-Path ([IO.Path]::GetTempPath()) ("RouteDeck-origin-test-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$commit = 'a' * 40
$version = '0.1.5'
$manifest = @{
  schemaVersion = 3
  applicationVersion = $version
  sourceCommit = $commit
  buildMetadata = "RouteDeckBuildCommit=$commit"
}

try {
  $json = $manifest | ConvertTo-Json
  $cases = @(
    @{ Name = 'exact'; Entries = @{ 'routedeck-build.json' = $json }; Accept = $true },
    @{ Name = 'wrong-commit'; Entries = @{ 'routedeck-build.json' = $json.Replace($commit, ('b' * 40)) }; Accept = $false },
    @{ Name = 'wrong-version'; Entries = @{ 'routedeck-build.json' = $json.Replace($version, '0.1.4') }; Accept = $false },
    @{ Name = 'wrong-schema'; Entries = @{ 'routedeck-build.json' = $json.Replace('"schemaVersion": 3', '"schemaVersion": 2') }; Accept = $false },
    @{ Name = 'string-schema'; Entries = @{ 'routedeck-build.json' = $json.Replace('"schemaVersion": 3', '"schemaVersion": "3"') }; Accept = $false },
    @{ Name = 'array-version'; Entries = @{ 'routedeck-build.json' = $json.Replace('"0.1.5"', '["0.1.5"]') }; Accept = $false },
    @{ Name = 'array-commit'; Entries = @{ 'routedeck-build.json' = $json.Replace('"' + $commit + '"', '["' + $commit + '"]') }; Accept = $false },
    @{ Name = 'array-metadata'; Entries = @{ 'routedeck-build.json' = $json.Replace('"RouteDeckBuildCommit=' + $commit + '"', '["RouteDeckBuildCommit=' + $commit + '"]') }; Accept = $false },
    @{ Name = 'array-manifest'; Entries = @{ 'routedeck-build.json' = "[$json]" }; Accept = $false },
    @{ Name = 'wrong-metadata'; Entries = @{ 'routedeck-build.json' = $json.Replace('RouteDeckBuildCommit=', 'Unrelated=') }; Accept = $false },
    @{ Name = 'nested'; Entries = @{ 'nested/routedeck-build.json' = $json }; Accept = $false },
    @{ Name = 'oversized'; Entries = @{ 'routedeck-build.json' = ' ' * 4097 }; Accept = $false },
    @{ Name = 'duplicate'; Entries = @{ 'routedeck-build.json' = $json }; Accept = $false }
  )
  foreach ($case in $cases) {
    $archive = Join-Path $root "$($case.Name).zip"
    $zip = [IO.Compression.ZipFile]::Open($archive, 'Create')
    try {
      foreach ($entry in $case.Entries.GetEnumerator()) {
        $writer = [IO.StreamWriter]::new($zip.CreateEntry($entry.Key).Open())
        try { $writer.Write($entry.Value) } finally { $writer.Dispose() }
      }
      if ($case.Name -ceq 'duplicate') { $null = $zip.CreateEntry('RouteDeck-build.json') }
    } finally {
      $zip.Dispose()
    }

    $message = $null
    try {
      & "$PSScriptRoot/assert-portable-origin.ps1" -Archive $archive -Version $version -SourceCommit $commit
    } catch {
      $message = $_.Exception.Message
    }
    if ($case.Accept -and $message) { throw "Expected $($case.Name) fixture to pass but got $message" }
    if (-not $case.Accept -and $message -cnotmatch '^(Invalid packaged build manifest|Packaged build manifest does not match)') {
      throw "Expected $($case.Name) fixture to fail provenance validation"
    }
  }
  Write-Output 'Portable origin fixtures passed'
} finally {
  foreach ($file in Get-ChildItem -LiteralPath $root -File) {
    Remove-Item -LiteralPath $file.FullName
  }
  Remove-Item -LiteralPath $root
}
