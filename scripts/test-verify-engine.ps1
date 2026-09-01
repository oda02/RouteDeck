[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $ArchivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify-engine.ps1'
$sourceLock = Join-Path $repoRoot 'engine\sing-box.lock.json'
$archive = (Get-Item -LiteralPath $ArchivePath -Force).FullName
$pwsh = (Get-Process -Id $PID).Path
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempBase ('RouteDeck-engine-verifier-' + [guid]::NewGuid().ToString('N'))
$safeCleanupPrefix = Join-Path $tempBase 'RouteDeck-engine-verifier-'

function Invoke-Verifier([string] $Target, [string] $LockFile = $sourceLock) {
  $output = & $pwsh -NoProfile -File $verifier -Path $Target -LockFile $LockFile 2>&1
  return [pscustomobject]@{
    ExitCode = $LASTEXITCODE
    Output = ($output | Out-String)
  }
}

function Assert-Pass([string] $Name, [string] $Target, [string] $LockFile = $sourceLock) {
  $result = Invoke-Verifier $Target $LockFile
  if ($result.ExitCode -ne 0) {
    throw "$Name failed unexpectedly:`n$($result.Output)"
  }
  Write-Output "PASS: $Name"
}

function Assert-Rejected(
  [string] $Name,
  [string] $Target,
  [string] $ExpectedMessage,
  [string] $LockFile = $sourceLock
) {
  $result = Invoke-Verifier $Target $LockFile
  if ($result.ExitCode -eq 0) {
    throw "$Name unexpectedly passed"
  }
  if ($result.Output -notmatch [regex]::Escape($ExpectedMessage)) {
    throw "$Name was rejected for the wrong reason. Expected '$ExpectedMessage':`n$($result.Output)"
  }
  Write-Output "PASS: $Name rejected with '$ExpectedMessage'"
}

function New-HostileLock([string] $ArchiveEntryPath, [string] $Name) {
  $lock = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
  $lock.runtimeFiles[0].archivePath = $ArchiveEntryPath
  $path = Join-Path $testRoot "$Name.lock.json"
  $lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
  return $path
}

try {
  New-Item -ItemType Directory -Path $testRoot | Out-Null

  Assert-Pass 'reviewed archive' $archive

  # Keep the exact reviewed length but corrupt central-directory bytes. The
  # expected SHA error proves whole-file identity is checked before ZipArchive
  # construction could report invalid ZIP metadata.
  $sameLengthCorrupt = Join-Path $testRoot 'same-length-corrupt.zip'
  Copy-Item -LiteralPath $archive -Destination $sameLengthCorrupt
  $stream = [IO.File]::Open($sameLengthCorrupt, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    [void] $stream.Seek(-1, [IO.SeekOrigin]::End)
    $lastByte = $stream.ReadByte()
    [void] $stream.Seek(-1, [IO.SeekOrigin]::End)
    $stream.WriteByte([byte] ($lastByte -bxor 1))
  }
  finally {
    $stream.Dispose()
  }
  Assert-Rejected 'pre-parse archive identity' $sameLengthCorrupt 'archive SHA-256 mismatch'

  $hostileCases = @()
  foreach ($device in @('CON', 'NUL', 'PRN', 'AUX', 'CLOCK$', 'CONIN$', 'CONOUT$')) {
    $hostileCases += @{
      Name = 'reserved-' + $device.ToLowerInvariant().Replace('$', '-dollar')
      Path = "engine/$device.notice"
      Message = 'reserved Windows device name'
    }
  }
  foreach ($number in 1..9) {
    foreach ($prefix in @('COM', 'LPT')) {
      $device = "$prefix$number"
      $hostileCases += @{
        Name = 'reserved-' + $device.ToLowerInvariant()
        Path = "engine/$device.config"
        Message = 'reserved Windows device name'
      }
    }
  }
  foreach ($superscript in @('¹', '²', '³')) {
    foreach ($prefix in @('COM', 'LPT')) {
      $device = "$prefix$superscript"
      $hostileCases += @{
        Name = 'reserved-' + $prefix.ToLowerInvariant() + '-superscript-' + $superscript
        Path = "engine/$device.config"
        Message = 'reserved Windows device name'
      }
    }
  }
  $hostileCases += @(
    @{ Name = 'invalid-less-than'; Path = 'engine/bad<name.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'invalid-greater-than'; Path = 'engine/bad>name.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'invalid-quote'; Path = 'engine/bad"name.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'invalid-colon'; Path = 'engine/bad:name.dll'; Message = 'alternate-data-stream' },
    @{ Name = 'invalid-pipe'; Path = 'engine/bad|name.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'invalid-question'; Path = 'engine/bad?.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'invalid-star'; Path = 'engine/bad*.dll'; Message = 'invalid Win32 character' },
    @{ Name = 'control-character'; Path = "engine/bad$([char] 1)name.dll"; Message = 'control character' },
    @{ Name = 'ambiguous-trailing-dot'; Path = 'engine/name.'; Message = 'Windows-ambiguous segment' },
    @{ Name = 'ambiguous-trailing-space'; Path = 'engine/name '; Message = 'Windows-ambiguous segment' },
    @{ Name = 'reserved-trimmed-stem'; Path = 'engine/CON .txt'; Message = 'reserved Windows device name' },
    @{ Name = 'traversal'; Path = '../escape.exe'; Message = 'traversal segment' }
  )

  foreach ($case in $hostileCases) {
    $hostileLock = New-HostileLock $case.Path $case.Name
    Assert-Rejected $case.Name $archive $case.Message $hostileLock
  }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $extractedOuter = Join-Path $testRoot 'extracted'
  [IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractedOuter)
  $lock = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
  $engineDirectory = Join-Path $extractedOuter ([string] $lock.releaseAsset.archiveRoot)
  Assert-Pass 'reviewed extracted directory' $engineDirectory

  $licensePath = Join-Path $engineDirectory 'LICENSE'
  $bytes = [IO.File]::ReadAllBytes($licensePath)
  $bytes[0] = $bytes[0] -bxor 1
  [IO.File]::WriteAllBytes($licensePath, $bytes)
  Assert-Rejected 'same-size extracted-file tamper' $engineDirectory 'SHA-256 mismatch for LICENSE'

  Write-Output 'All engine verifier regression tests passed.'
}
finally {
  $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
  if (
    [IO.Directory]::Exists($resolvedTestRoot) -and
    $resolvedTestRoot.StartsWith($safeCleanupPrefix, [StringComparison]::OrdinalIgnoreCase)
  ) {
    Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
  }
}
