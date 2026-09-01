<#
.SYNOPSIS
Stages the minimal pinned Xray Reality sidecar without executing it.

.DESCRIPTION
Only xray.exe and its MPL-2.0 LICENSE are copied. Geo databases, WinTun,
launcher scripts, and other release files are deliberately not staged.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $ArchivePath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $DigestPath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $Destination,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string] $LockFile = (Join-Path $PSScriptRoot '..\engine\xray-core.lock.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$verifier = Join-Path $PSScriptRoot 'verify-xray.ps1'
$archive = (Get-Item -LiteralPath $ArchivePath -Force).FullName
$digest = (Get-Item -LiteralPath $DigestPath -Force).FullName
$lock = Get-Content -Raw -LiteralPath $LockFile | ConvertFrom-Json
$destinationFull = [IO.Path]::GetFullPath($Destination)

if ([IO.Directory]::Exists($destinationFull)) {
  & $verifier -Path $destinationFull -LockFile $LockFile
  Write-Output "Xray-core $($lock.version) is already staged: $destinationFull"
  return
}
if ([IO.File]::Exists($destinationFull)) {
  throw "Xray staging failed: destination is an existing file: $destinationFull"
}

& $verifier -Path $archive -DigestPath $digest -LockFile $LockFile

$parent = [IO.Path]::GetDirectoryName($destinationFull)
if ([string]::IsNullOrWhiteSpace($parent)) {
  throw "Xray staging failed: destination has no parent directory"
}
[IO.Directory]::CreateDirectory($parent) | Out-Null
$stageName = '.routedeck-xray-stage-' + [guid]::NewGuid().ToString('N')
$stage = Join-Path $parent $stageName
[IO.Directory]::CreateDirectory($stage) | Out-Null

try {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($archive)
  try {
    foreach ($file in @($lock.runtimeFiles)) {
      $relative = [string] $file.path
      if ([IO.Path]::GetFileName($relative) -cne $relative) {
        throw "Xray staging failed: runtime path is not a flat file name: $relative"
      }
      $entry = $zip.GetEntry([string] $file.archivePath)
      if ($null -eq $entry) {
        throw "Xray staging failed: archive entry is missing: $($file.archivePath)"
      }
      $target = Join-Path $stage $relative
      $input = $entry.Open()
      $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $input.CopyTo($output)
      }
      finally {
        $output.Dispose()
        $input.Dispose()
      }
    }
  }
  finally {
    $zip.Dispose()
  }

  & $verifier -Path $stage -LockFile $LockFile
  if ([IO.Directory]::Exists($destinationFull) -or [IO.File]::Exists($destinationFull)) {
    throw "Xray staging failed: destination appeared concurrently: $destinationFull"
  }
  Move-Item -LiteralPath $stage -Destination $destinationFull
  & $verifier -Path $destinationFull -LockFile $LockFile
  Write-Output "Staged Xray-core $($lock.version) Reality sidecar: $destinationFull"
}
finally {
  $stageFull = [IO.Path]::GetFullPath($stage)
  $expectedPrefix = [IO.Path]::GetFullPath((Join-Path $parent '.routedeck-xray-stage-'))
  if ([IO.Directory]::Exists($stageFull) -and $stageFull.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $stageFull -Recurse -Force
  }
}
