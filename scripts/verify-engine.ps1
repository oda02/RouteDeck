<#
.SYNOPSIS
Developer/packaging verification for the pinned sing-box artifact.

.NOTES
This script does not launch the engine and is not RouteDeck's runtime
integrity gate. A path-based verification performed separately from process
creation cannot prevent a time-of-check/time-of-use replacement.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateNotNullOrEmpty()]
  [string] $Path,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string] $LockFile = (Join-Path $PSScriptRoot '..\engine\sing-box.lock.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
  throw "Engine verification failed: $Message"
}

function Assert-SafeRelativePath([string] $Value, [string] $Label) {
  if ([string]::IsNullOrWhiteSpace($Value)) {
    Fail "$Label is empty"
  }

  if ($Value.IndexOf([char] 0) -ge 0) {
    Fail "$Label contains a NUL character"
  }

  $normalized = $Value.Replace('\', '/')
  if ($normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:' -or $normalized.Contains(':')) {
    Fail "$Label is rooted or contains a Windows drive/alternate-data-stream separator: $Value"
  }

  $segments = $normalized.Split('/')
  if ($segments.Count -eq 0) {
    Fail "$Label has no path segments"
  }

  foreach ($segment in $segments) {
    if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..') {
      Fail "$Label contains an empty or traversal segment: $Value"
    }
    if ($segment.EndsWith('.') -or $segment.EndsWith(' ')) {
      Fail "$Label contains a Windows-ambiguous segment: $Value"
    }

    foreach ($character in $segment.ToCharArray()) {
      if ([int] $character -lt 32) {
        Fail "$Label contains a control character: $Value"
      }
      if ('<>:"|?*'.Contains([string] $character)) {
        Fail "$Label contains an invalid Win32 character: $Value"
      }
    }

    # Windows resolves reserved DOS device names even when they have an
    # extension (for example, CON.txt). Trim spaces from the stem as Win32
    # name normalization can otherwise alias a reserved name.
    $stem = $segment.Split('.')[0].TrimEnd(' ')
    $isReservedDevice = $stem -match '^(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])$'
    $superscriptDigits = "$([char] 0x00B9)$([char] 0x00B2)$([char] 0x00B3)"
    $isSuperscriptPort = (
      $stem.Length -eq 4 -and
      (
        $stem.StartsWith('COM', [StringComparison]::OrdinalIgnoreCase) -or
        $stem.StartsWith('LPT', [StringComparison]::OrdinalIgnoreCase)
      ) -and
      $superscriptDigits.Contains([string] $stem[3])
    )
    if ($isReservedDevice -or $isSuperscriptPort) {
      Fail "$Label contains a reserved Windows device name: $Value"
    }
  }

  return $normalized
}

function Assert-Sha256([string] $Value, [string] $Label) {
  if ($Value -cnotmatch '^[0-9a-f]{64}$') {
    Fail "$Label is not a lowercase SHA-256 digest"
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

function Get-ExpectedFiles($Lock) {
  $files = @($Lock.runtimeFiles)
  if ($files.Count -eq 0) {
    Fail 'lock contains no runtime files'
  }

  $paths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $archivePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($file in $files) {
    $file.path = Assert-SafeRelativePath ([string] $file.path) 'runtime file path'
    $file.archivePath = Assert-SafeRelativePath ([string] $file.archivePath) 'archive entry path'
    Assert-Sha256 ([string] $file.sha256) "hash for $($file.path)"
    if ([long] $file.size -lt 0) {
      Fail "negative size for $($file.path)"
    }
    if (-not $paths.Add([string] $file.path)) {
      Fail "duplicate runtime file path in lock: $($file.path)"
    }
    if (-not $archivePaths.Add([string] $file.archivePath)) {
      Fail "duplicate archive entry path in lock: $($file.archivePath)"
    }
  }
  return $files
}

function Assert-NoReparsePoint([System.IO.FileSystemInfo] $Item, [string] $Label) {
  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "$Label is a reparse point: $($Item.FullName)"
  }
}

function Get-DescendantRelativePath(
  [System.IO.DirectoryInfo] $Root,
  [System.IO.FileSystemInfo] $Child
) {
  $trimCharacters = [char[]] @(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
  )
  $rootPrefix = $Root.FullName.TrimEnd($trimCharacters) + [IO.Path]::DirectorySeparatorChar
  $childPath = $Child.FullName
  if (-not $childPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "engine directory entry escaped its verified root: $childPath"
  }
  return $childPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Verify-Directory([System.IO.DirectoryInfo] $Directory, $Files, [string] $Version) {
  Assert-NoReparsePoint $Directory 'engine directory'
  $expectedExecutables = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach ($file in $Files) {
    $relative = [string] $file.path
    $candidate = Join-Path $Directory.FullName ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (-not [System.IO.File]::Exists($candidate)) {
      Fail "required file is missing: $relative"
    }
    $item = Get-Item -LiteralPath $candidate -Force
    Assert-NoReparsePoint $item "runtime file $relative"
    if ([long] $item.Length -ne [long] $file.size) {
      Fail "size mismatch for ${relative}: expected $($file.size), got $($item.Length)"
    }
    $actualHash = Get-FileSha256 $item.FullName
    if ($actualHash -cne [string] $file.sha256) {
      Fail "SHA-256 mismatch for ${relative}: expected $($file.sha256), got $actualHash"
    }
    if ([IO.Path]::GetExtension($relative) -in @('.exe', '.dll')) {
      [void] $expectedExecutables.Add($relative.Replace('\', '/'))
    }
  }

  $pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
  $pending.Push($Directory)
  while ($pending.Count -gt 0) {
    $current = $pending.Pop()
    foreach ($child in $current.GetFileSystemInfos()) {
      Assert-NoReparsePoint $child 'engine directory entry'
      $relative = Get-DescendantRelativePath $Directory $child
      $relative = Assert-SafeRelativePath $relative 'engine directory entry'
      if ($child -is [System.IO.DirectoryInfo]) {
        $pending.Push($child)
        continue
      }
      $extension = [IO.Path]::GetExtension($child.Name)
      if ($extension -notin @('.exe', '.dll')) {
        continue
      }
      if (-not $expectedExecutables.Contains($relative)) {
        Fail "unexpected executable or DLL in engine directory: $relative"
      }
    }
  }

  Write-Output "Verified sing-box $Version directory: $($Directory.FullName)"
}

function Verify-Archive([System.IO.FileInfo] $Archive, $Lock, $Files) {
  Assert-NoReparsePoint $Archive 'engine archive'

  # The archive is untrusted until its complete byte identity is established.
  # Do not construct ZipArchive or enumerate central-directory data before both
  # the exact length and full-file digest match the reviewed lock.
  Assert-Sha256 ([string] $Lock.releaseAsset.sha256) 'archive hash in lock'

  $expectedByArchivePath = @{}
  foreach ($file in $Files) {
    $expectedByArchivePath[[string] $file.archivePath] = $file
  }

  # Keep the same read-only handle open from digesting through ZIP inspection.
  # FileShare.Read prevents a cooperating Windows process from replacing or
  # modifying these bytes between the pre-parse check and enumeration.
  $stream = [System.IO.File]::Open(
    $Archive.FullName,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    if ([long] $stream.Length -ne [long] $Lock.releaseAsset.size) {
      Fail "archive size mismatch: expected $($Lock.releaseAsset.size), got $($stream.Length)"
    }
    $archiveHash = Get-StreamSha256 $stream
    if ($archiveHash -cne [string] $Lock.releaseAsset.sha256) {
      Fail "archive SHA-256 mismatch: expected $($Lock.releaseAsset.sha256), got $archiveHash"
    }
    [void] $stream.Seek(0, [System.IO.SeekOrigin]::Begin)

    Add-Type -AssemblyName System.IO.Compression
    $zip = [System.IO.Compression.ZipArchive]::new(
      $stream,
      [System.IO.Compression.ZipArchiveMode]::Read,
      $true
    )
    try {
      $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($entry in $zip.Entries) {
        $name = Assert-SafeRelativePath ([string] $entry.FullName) 'archive entry'
        if (-not $seen.Add($name)) {
          Fail "duplicate archive entry: $name"
        }
        if (-not $expectedByArchivePath.ContainsKey($name)) {
          Fail "unexpected archive entry: $name"
        }

        $unixFileType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
        if ($unixFileType -eq 0xA000) {
          Fail "symbolic-link archive entry is not allowed: $name"
        }

        $expected = $expectedByArchivePath[$name]
        if ([long] $entry.Length -ne [long] $expected.size) {
          Fail "uncompressed size mismatch for ${name}: expected $($expected.size), got $($entry.Length)"
        }
      }

      foreach ($expectedPath in $expectedByArchivePath.Keys) {
        if (-not $seen.Contains([string] $expectedPath)) {
          Fail "required archive entry is missing: $expectedPath"
        }
      }

      foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        $expected = $expectedByArchivePath[$name]
        $entryStream = $entry.Open()
        try {
          $actualHash = Get-StreamSha256 $entryStream
        }
        finally {
          $entryStream.Dispose()
        }
        if ($actualHash -cne [string] $expected.sha256) {
          Fail "SHA-256 mismatch for archive entry ${name}: expected $($expected.sha256), got $actualHash"
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

  Write-Output "Verified sing-box $($Lock.version) archive: $($Archive.FullName)"
}

$lockItem = Get-Item -LiteralPath $LockFile -Force
if (-not ($lockItem -is [System.IO.FileInfo])) {
  Fail "lock is not a file: $LockFile"
}
Assert-NoReparsePoint $lockItem 'engine lock'
$lock = Get-Content -Raw -LiteralPath $lockItem.FullName | ConvertFrom-Json
if ([int] $lock.schemaVersion -ne 1 -or [string] $lock.engine -cne 'sing-box') {
  Fail 'unsupported lock schema or engine'
}
$files = Get-ExpectedFiles $lock

$item = Get-Item -LiteralPath $Path -Force
if ($item -is [System.IO.DirectoryInfo]) {
  Verify-Directory $item $files ([string] $lock.version)
}
elseif ($item -is [System.IO.FileInfo]) {
  Verify-Archive $item $lock $files
}
else {
  Fail "path is neither a regular file nor a directory: $Path"
}
