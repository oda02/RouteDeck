[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $ArchivePath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $DigestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify-xray.ps1'
$stager = Join-Path $PSScriptRoot 'stage-xray.ps1'
$sourceLock = Join-Path $repoRoot 'engine\xray-core.lock.json'
$archive = (Get-Item -LiteralPath $ArchivePath -Force).FullName
$digest = (Get-Item -LiteralPath $DigestPath -Force).FullName
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempBase ('RouteDeck-xray-artifact-' + [guid]::NewGuid().ToString('N'))
$safeCleanupPrefix = Join-Path $tempBase 'RouteDeck-xray-artifact-'

function Invoke-CheckedScript([scriptblock] $Action) {
  $records = New-Object System.Collections.ArrayList
  $exitCode = 0
  try {
    & $Action *>&1 | ForEach-Object { [void] $records.Add($_) }
  }
  catch {
    $exitCode = 1
    [void] $records.Add($_)
  }
  return [pscustomobject]@{ ExitCode = $exitCode; Output = ($records | Out-String) }
}

function Assert-Pass([string] $Name, [scriptblock] $Action) {
  $result = Invoke-CheckedScript $Action
  if ($result.ExitCode -ne 0) { throw "$Name failed unexpectedly:`n$($result.Output)" }
  Write-Output "PASS: $Name"
}

function Assert-Rejected([string] $Name, [string] $ExpectedMessage, [scriptblock] $Action) {
  $result = Invoke-CheckedScript $Action
  if ($result.ExitCode -eq 0) { throw "$Name unexpectedly passed" }
  if ($result.Output -notmatch [regex]::Escape($ExpectedMessage)) {
    throw "$Name was rejected for the wrong reason. Expected '$ExpectedMessage':`n$($result.Output)"
  }
  Write-Output "PASS: $Name rejected with '$ExpectedMessage'"
}

function Flip-LastByte([string] $Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    [void] $stream.Seek(-1, [IO.SeekOrigin]::End)
    $value = $stream.ReadByte()
    [void] $stream.Seek(-1, [IO.SeekOrigin]::End)
    $stream.WriteByte([byte] ($value -bxor 1))
  }
  finally {
    $stream.Dispose()
  }
}

try {
  New-Item -ItemType Directory -Path $testRoot | Out-Null

  Assert-Pass 'reviewed archive plus official digest asset' {
    & $verifier -Path $archive -DigestPath $digest -LockFile $sourceLock
  }

  $badDigest = Join-Path $testRoot 'bad.dgst'
  Copy-Item -LiteralPath $digest -Destination $badDigest
  Flip-LastByte $badDigest
  Assert-Rejected 'tampered digest asset' '.dgst SHA-256 mismatch' {
    & $verifier -Path $archive -DigestPath $badDigest -LockFile $sourceLock
  }

  $badArchive = Join-Path $testRoot 'bad.zip'
  Copy-Item -LiteralPath $archive -Destination $badArchive
  Flip-LastByte $badArchive
  Assert-Rejected 'tampered archive before ZIP parsing' 'archive SHA-256 mismatch' {
    & $verifier -Path $badArchive -DigestPath $digest -LockFile $sourceLock
  }

  $hostileLock = Join-Path $testRoot 'hostile.lock.json'
  $lock = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
  $lock.releaseAsset.archiveEntries[1].path = '../xray.exe'
  $lock | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $hostileLock -Encoding UTF8
  Assert-Rejected 'hostile archive path in lock' 'traversal segment' {
    & $verifier -Path $archive -DigestPath $digest -LockFile $hostileLock
  }

  $badApiLock = Join-Path $testRoot 'bad-api.lock.json'
  $lock = Get-Content -Raw -LiteralPath $sourceLock | ConvertFrom-Json
  $lock.releaseAsset.githubApiDigest = 'sha256:' + ('0' * 64)
  $lock | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $badApiLock -Encoding UTF8
  Assert-Rejected 'mismatched GitHub API digest pin' 'GitHub API digest does not match' {
    & $verifier -Path $archive -DigestPath $digest -LockFile $badApiLock
  }

  $stage = Join-Path $testRoot 'stage'
  Assert-Pass 'minimal sidecar staging' {
    & $stager -ArchivePath $archive -DigestPath $digest -Destination $stage -LockFile $sourceLock
  }
  $stagedNames = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object Name | Sort-Object)
  if (($stagedNames -join ',') -cne 'LICENSE,xray.exe') {
    throw "minimal sidecar staging copied unexpected files: $($stagedNames -join ', ')"
  }
  foreach ($excluded in @('geoip.dat', 'geosite.dat', 'wintun.dll', 'xray_no_window.ps1', 'xray_no_window.vbs')) {
    if (Test-Path -LiteralPath (Join-Path $stage $excluded)) {
      throw "minimal sidecar staging copied excluded file: $excluded"
    }
  }
  Write-Output 'PASS: geo data, WinTun, and launcher scripts were not staged'

  Assert-Pass 'idempotent verification of an existing exact stage' {
    & $stager -ArchivePath $archive -DigestPath $digest -Destination $stage -LockFile $sourceLock
  }

  $xray = Join-Path $stage 'xray.exe'
  $stream = [IO.File]::Open($xray, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    $first = $stream.ReadByte()
    [void] $stream.Seek(0, [IO.SeekOrigin]::Begin)
    $stream.WriteByte([byte] ($first -bxor 1))
  }
  finally {
    $stream.Dispose()
  }
  Assert-Rejected 'same-size staged executable tamper' 'staged SHA-256 mismatch' {
    & $verifier -Path $stage -LockFile $sourceLock
  }

  Write-Output 'All Xray artifact verification and staging tests passed.'
}
finally {
  $resolved = [IO.Path]::GetFullPath($testRoot)
  if ([IO.Directory]::Exists($resolved) -and $resolved.StartsWith($safeCleanupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolved -Recurse -Force
  }
}
