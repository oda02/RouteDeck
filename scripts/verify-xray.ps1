<#
.SYNOPSIS
Verifies the pinned official XTLS/Xray-core Windows x64 archive or staged directory.

.DESCRIPTION
Archive verification checks the GitHub API-pinned digest, the separately pinned
.dgst asset, the exact ZIP entry list, and the staged runtime-file hashes. It never
executes xray.exe.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateNotNullOrEmpty()]
  [string] $Path,

  [Parameter()]
  [string] $DigestPath,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string] $LockFile = (Join-Path $PSScriptRoot '..\engine\xray-core.lock.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
  throw "Xray verification failed: $Message"
}

function Assert-Sha256([string] $Value, [string] $Label) {
  if ($Value -cnotmatch '^[0-9a-f]{64}$') {
    Fail "$Label is not a lowercase SHA-256 digest"
  }
}

function Assert-SafeRelativePath([string] $Value, [string] $Label) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOf([char] 0) -ge 0) {
    Fail "$Label is empty or contains a NUL character"
  }
  $normalized = $Value.Replace('\', '/')
  if ($normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:' -or $normalized.Contains(':')) {
    Fail "$Label is rooted or contains a drive/stream separator: $Value"
  }
  foreach ($segment in $normalized.Split('/')) {
    if ([string]::IsNullOrEmpty($segment) -or $segment -in @('.', '..')) {
      Fail "$Label contains an empty or traversal segment: $Value"
    }
    if ($segment.EndsWith('.') -or $segment.EndsWith(' ')) {
      Fail "$Label contains a Windows-ambiguous segment: $Value"
    }
    foreach ($character in $segment.ToCharArray()) {
      if ([int] $character -lt 32 -or '<>:"|?*'.Contains([string] $character)) {
        Fail "$Label contains an invalid Win32 character: $Value"
      }
    }
    $stem = $segment.Split('.')[0].TrimEnd(' ')
    if ($stem -match '^(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])$') {
      Fail "$Label contains a reserved Windows device name: $Value"
    }
  }
  return $normalized
}

function Assert-NoReparsePoint([System.IO.FileSystemInfo] $Item, [string] $Label) {
  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "$Label is a reparse point: $($Item.FullName)"
  }
}

function Get-StreamSha256([System.IO.Stream] $Stream) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
  }
  finally {
    $sha.Dispose()
  }
}

function Get-FileSha256([string] $LiteralPath) {
  $stream = [System.IO.File]::OpenRead($LiteralPath)
  try {
    return Get-StreamSha256 $stream
  }
  finally {
    $stream.Dispose()
  }
}

function Get-RelativePath([System.IO.DirectoryInfo] $Root, [System.IO.FileSystemInfo] $Child) {
  $trim = [char[]] @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $prefix = $Root.FullName.TrimEnd($trim) + [IO.Path]::DirectorySeparatorChar
  if (-not $Child.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "directory entry escaped the verified root: $($Child.FullName)"
  }
  return $Child.FullName.Substring($prefix.Length).Replace('\', '/')
}

function Read-Lock([string] $LiteralPath) {
  $item = Get-Item -LiteralPath $LiteralPath -Force
  if (-not ($item -is [System.IO.FileInfo])) {
    Fail "lock is not a regular file: $LiteralPath"
  }
  Assert-NoReparsePoint $item 'lock file'
  $lock = Get-Content -Raw -LiteralPath $item.FullName | ConvertFrom-Json
  if ([int] $lock.schemaVersion -ne 1 -or [string] $lock.engine -cne 'xray-core') {
    Fail 'unsupported lock schema or engine'
  }
  if ([string] $lock.releaseAsset.name -cne 'Xray-windows-64.zip') {
    Fail 'lock does not name the reviewed Windows x64 asset'
  }
  Assert-Sha256 ([string] $lock.releaseAsset.sha256) 'archive hash in lock'
  if ([string] $lock.releaseAsset.githubApiDigest -cne "sha256:$($lock.releaseAsset.sha256)") {
    Fail 'GitHub API digest does not match the archive SHA-256 pin'
  }
  Assert-Sha256 ([string] $lock.releaseAsset.digestAsset.sha256) 'digest-asset hash in lock'
  if ([string] $lock.releaseAsset.digestAsset.declaredArchiveSha256 -cne [string] $lock.releaseAsset.sha256) {
    Fail '.dgst declaration pin does not match the archive SHA-256 pin'
  }
  if (-not [bool] $lock.releaseCommitVerification.verified -or [string] $lock.releaseCommitVerification.reason -cne 'valid') {
    Fail 'release commit verification is not pinned as valid'
  }
  if ([string] $lock.provenance.license.spdx -cne 'MPL-2.0') {
    Fail 'unexpected source license identifier'
  }
  Assert-Sha256 ([string] $lock.provenance.license.sha256) 'source license hash in lock'
  return $lock
}

function Get-ReviewedEntries($Lock) {
  $entries = @($Lock.releaseAsset.archiveEntries)
  if ($entries.Count -eq 0) { Fail 'lock contains no reviewed archive entries' }
  $result = @{}
  $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $entries) {
    $path = Assert-SafeRelativePath ([string] $entry.path) 'archive entry path in lock'
    if (-not $seen.Add($path)) { Fail "duplicate archive entry path in lock: $path" }
    if ([long] $entry.size -lt 0) { Fail "negative archive entry size: $path" }
    $result[$path] = $entry
  }
  return $result
}

function Get-RuntimeFiles($Lock, $ReviewedEntries) {
  $files = @($Lock.runtimeFiles)
  if ($files.Count -eq 0) { Fail 'lock contains no runtime files' }
  $result = @{}
  $stagedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($file in $files) {
    $path = Assert-SafeRelativePath ([string] $file.path) 'runtime file path'
    $archivePath = Assert-SafeRelativePath ([string] $file.archivePath) 'runtime archive path'
    if ([IO.Path]::GetFileName($path) -cne $path) { Fail "runtime stage path is not a flat file name: $path" }
    if (-not $stagedPaths.Add($path)) { Fail "duplicate runtime file path: $path" }
    if (-not $ReviewedEntries.ContainsKey($archivePath)) { Fail "runtime archive path is not reviewed: $archivePath" }
    if ([long] $file.size -ne [long] $ReviewedEntries[$archivePath].size) { Fail "runtime/archive size pins differ for $path" }
    Assert-Sha256 ([string] $file.sha256) "runtime hash for $path"
    $result[$path] = $file
  }
  return $result
}

function Verify-DigestAsset([string] $LiteralPath, $Lock) {
  if ([string]::IsNullOrWhiteSpace($LiteralPath)) {
    Fail 'the official .dgst path is required when verifying an archive'
  }
  $item = Get-Item -LiteralPath $LiteralPath -Force
  if (-not ($item -is [System.IO.FileInfo])) { Fail ".dgst is not a regular file: $LiteralPath" }
  Assert-NoReparsePoint $item '.dgst asset'
  if ([long] $item.Length -ne [long] $Lock.releaseAsset.digestAsset.size) {
    Fail ".dgst size mismatch: expected $($Lock.releaseAsset.digestAsset.size), got $($item.Length)"
  }
  $hash = Get-FileSha256 $item.FullName
  if ($hash -cne [string] $Lock.releaseAsset.digestAsset.sha256) {
    Fail ".dgst SHA-256 mismatch: expected $($Lock.releaseAsset.digestAsset.sha256), got $hash"
  }
  $text = [System.IO.File]::ReadAllText($item.FullName)
  $matches = [regex]::Matches($text, '(?im)^\s*SHA2-256=\s*([0-9a-f]{64})\s*$')
  if ($matches.Count -ne 1) { Fail '.dgst does not contain exactly one SHA2-256 declaration' }
  $declared = $matches[0].Groups[1].Value.ToLowerInvariant()
  if ($declared -cne [string] $Lock.releaseAsset.sha256) {
    Fail ".dgst declares a different archive SHA-256: $declared"
  }
}

function Verify-Archive([System.IO.FileInfo] $Archive, [string] $Dgst, $Lock, $ReviewedEntries, $RuntimeFiles) {
  Assert-NoReparsePoint $Archive 'Xray archive'
  Verify-DigestAsset $Dgst $Lock

  $stream = [System.IO.File]::Open($Archive.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ([long] $stream.Length -ne [long] $Lock.releaseAsset.size) {
      Fail "archive size mismatch: expected $($Lock.releaseAsset.size), got $($stream.Length)"
    }
    $archiveHash = Get-StreamSha256 $stream
    if ($archiveHash -cne [string] $Lock.releaseAsset.sha256) {
      Fail "archive SHA-256 mismatch: expected $($Lock.releaseAsset.sha256), got $archiveHash"
    }
    [void] $stream.Seek(0, [IO.SeekOrigin]::Begin)
    Add-Type -AssemblyName System.IO.Compression
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
      $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($entry in $zip.Entries) {
        $name = Assert-SafeRelativePath ([string] $entry.FullName) 'archive entry'
        if (-not $seen.Add($name)) { Fail "duplicate archive entry: $name" }
        if (-not $ReviewedEntries.ContainsKey($name)) { Fail "unexpected archive entry: $name" }
        $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
        if ($unixType -eq 0xA000) { Fail "symbolic-link archive entry is not allowed: $name" }
        if ([long] $entry.Length -ne [long] $ReviewedEntries[$name].size) {
          Fail "archive entry size mismatch for ${name}: expected $($ReviewedEntries[$name].size), got $($entry.Length)"
        }
      }
      foreach ($expected in $ReviewedEntries.Keys) {
        if (-not $seen.Contains([string] $expected)) { Fail "required archive entry is missing: $expected" }
      }
      foreach ($runtime in $RuntimeFiles.Values) {
        $entry = $zip.GetEntry([string] $runtime.archivePath)
        if ($null -eq $entry) { Fail "runtime archive entry is missing: $($runtime.archivePath)" }
        $entryStream = $entry.Open()
        try { $actual = Get-StreamSha256 $entryStream } finally { $entryStream.Dispose() }
        if ($actual -cne [string] $runtime.sha256) {
          Fail "runtime SHA-256 mismatch for $($runtime.archivePath): expected $($runtime.sha256), got $actual"
        }
      }
    }
    finally {
      $zip.Dispose()
    }
  }
  catch [System.IO.InvalidDataException] {
    Fail "invalid ZIP archive: $($_.Exception.Message)"
  }
  finally {
    $stream.Dispose()
  }
  Write-Output "Verified Xray-core $($Lock.version) archive and .dgst: $($Archive.FullName)"
}

function Verify-Directory([System.IO.DirectoryInfo] $Directory, $Lock, $RuntimeFiles) {
  Assert-NoReparsePoint $Directory 'Xray stage directory'
  $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($item in $Directory.GetFileSystemInfos()) {
    Assert-NoReparsePoint $item 'Xray stage entry'
    if ($item -is [System.IO.DirectoryInfo]) { Fail "unexpected staged directory: $($item.Name)" }
    $relative = Assert-SafeRelativePath (Get-RelativePath $Directory $item) 'Xray stage entry'
    if (-not $RuntimeFiles.ContainsKey($relative)) { Fail "unexpected staged file: $relative" }
    $expected = $RuntimeFiles[$relative]
    if ([long] $item.Length -ne [long] $expected.size) {
      Fail "staged size mismatch for ${relative}: expected $($expected.size), got $($item.Length)"
    }
    $actual = Get-FileSha256 $item.FullName
    if ($actual -cne [string] $expected.sha256) {
      Fail "staged SHA-256 mismatch for ${relative}: expected $($expected.sha256), got $actual"
    }
    [void] $seen.Add($relative)
  }
  foreach ($expected in $RuntimeFiles.Keys) {
    if (-not $seen.Contains([string] $expected)) { Fail "required staged file is missing: $expected" }
  }
  Write-Output "Verified Xray-core $($Lock.version) staged directory: $($Directory.FullName)"
}

$lock = Read-Lock $LockFile
$reviewedEntries = Get-ReviewedEntries $lock
$runtimeFiles = Get-RuntimeFiles $lock $reviewedEntries
$item = Get-Item -LiteralPath $Path -Force
if ($item -is [System.IO.FileInfo]) {
  Verify-Archive $item $DigestPath $lock $reviewedEntries $runtimeFiles
}
elseif ($item -is [System.IO.DirectoryInfo]) {
  Verify-Directory $item $lock $runtimeFiles
}
else {
  Fail "path is neither a regular file nor a directory: $Path"
}
