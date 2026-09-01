<#
.SYNOPSIS
Fail-closed portable assembly gate for the pinned RouteDeck engine.

.DESCRIPTION
The current reviewed notice manifest is incomplete, so this command verifies
the supplied engine and repository notice evidence, then refuses assembly
before creating the target. It does not execute any engine binary and does not
make a legal-compliance claim.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $EnginePath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $TargetRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
  throw "Portable assembly failed: $Message"
}

function Get-FileSha256([string] $LiteralPath) {
  $stream = [IO.File]::Open(
    $LiteralPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
  )
  try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
      return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
      $sha.Dispose()
    }
  }
  finally {
    $stream.Dispose()
  }
}

function Get-SafeNoticePath([string] $LicenseRoot, [string] $RelativePath) {
  if (
    [string]::IsNullOrWhiteSpace($RelativePath) -or
    $RelativePath.Contains(':') -or
    $RelativePath.Contains('/') -or
    $RelativePath.Contains('\') -or
    $RelativePath -in @('.', '..')
  ) {
    Fail "unsafe notice path in manifest: $RelativePath"
  }
  return Join-Path $LicenseRoot $RelativePath
}

function Assert-ExactPropertyNames($Object, [string[]] $ExpectedNames, [string] $Label) {
  $actual = @($Object.PSObject.Properties.Name | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (
    $actual.Count -ne $expected.Count -or
    (($actual -join "`n") -cne ($expected -join "`n"))
  ) {
    Fail "$Label does not match the reviewed schema"
  }
}

function Assert-SafeTargetPath([string] $Value, [string] $RepositoryRoot) {
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOf([char] 0) -ge 0) {
    Fail 'target path is empty or contains a NUL character'
  }
  if ($Value.StartsWith('\\') -or $Value.StartsWith('//')) {
    Fail 'UNC and device target paths are not supported'
  }
  if (-not [IO.Path]::IsPathRooted($Value)) {
    Fail 'target path must be absolute'
  }
  if ($Value.IndexOfAny([char[]] @('*', '?', '"', '<', '>', '|')) -ge 0) {
    Fail 'target path contains an invalid Win32 character'
  }

  $pathRoot = [IO.Path]::GetPathRoot($Value)
  $remainder = $Value.Substring($pathRoot.Length)
  if ($remainder.Contains(':')) {
    Fail 'target path contains an alternate-data-stream separator'
  }
  foreach ($segment in $remainder.Replace('/', '\').Split('\')) {
    if ($segment -in @('.', '..')) {
      Fail 'target path contains a traversal segment'
    }
  }

  $fullPath = [IO.Path]::GetFullPath($Value)
  $trimCharacters = [char[]] @(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
  )
  $normalized = $fullPath.TrimEnd($trimCharacters)
  $normalizedRoot = ([IO.Path]::GetPathRoot($fullPath)).TrimEnd($trimCharacters)
  if ($normalized -eq $normalizedRoot) {
    Fail 'volume-root target paths are not allowed'
  }

  $broadPaths = @(
    $RepositoryRoot,
    [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile),
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()),
    $env:WINDIR,
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  )
  foreach ($broadPath in $broadPaths) {
    if ([string]::IsNullOrWhiteSpace($broadPath)) {
      continue
    }
    if ($normalized -ieq ([IO.Path]::GetFullPath($broadPath)).TrimEnd($trimCharacters)) {
      Fail 'broad target path is not allowed'
    }
  }

  if ([IO.File]::Exists($fullPath)) {
    Fail 'target path is an existing file'
  }
  if ([IO.Directory]::Exists($fullPath)) {
    $targetItem = Get-Item -LiteralPath $fullPath -Force
    if (($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail 'target directory is a reparse point'
    }
  }

  return $fullPath
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$engineLockPath = Join-Path $repoRoot 'engine\sing-box.lock.json'
$licenseRoot = Join-Path $repoRoot 'engine\licenses'
$manifestPath = Join-Path $licenseRoot 'manifest.json'
$verifierPath = Join-Path $PSScriptRoot 'verify-engine.ps1'

# Validate the caller-supplied target but deliberately do not create or write it
# unless a future reviewed implementation replaces the blocked branch below.
$validatedTargetRoot = Assert-SafeTargetPath $TargetRoot $repoRoot

& $verifierPath -Path $EnginePath -LockFile $engineLockPath | Write-Output

$lock = Get-Content -Raw -LiteralPath $engineLockPath | ConvertFrom-Json
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ([int] $manifest.schemaVersion -ne 1) {
  Fail 'unsupported notice manifest schema'
}
Assert-ExactPropertyNames $manifest @(
  'schemaVersion',
  'reviewedFor',
  'portableAssemblyStatus',
  'legalComplianceClaim',
  'requiredNoticeFiles',
  'blockers'
) 'notice manifest'
Assert-ExactPropertyNames $manifest.reviewedFor @(
  'singBoxVersion',
  'singBoxCommit',
  'cronetGoCommit',
  'naiveProxyCommit'
) 'notice manifest provenance'
if ([bool] $manifest.legalComplianceClaim) {
  Fail 'notice manifest must not claim legal compliance'
}
if (
  [string] $manifest.reviewedFor.singBoxVersion -cne [string] $lock.version -or
  [string] $manifest.reviewedFor.singBoxCommit -cne [string] $lock.releaseCommit -or
  [string] $manifest.reviewedFor.cronetGoCommit -cne [string] $lock.provenance.cronetGo.commit -or
  [string] $manifest.reviewedFor.naiveProxyCommit -cne [string] $lock.provenance.naiveProxy.commit
) {
  Fail 'notice manifest provenance does not match the engine lock'
}

if ([string] $manifest.portableAssemblyStatus -notin @('blocked', 'ready')) {
  Fail 'notice manifest has an unsupported assembly status'
}

$expectedNotices = @(
  [ordered] @{
    path = 'cronet-go-LICENSE.txt'
    size = 675L
    sha256 = '8c7f15b324704ebc1e2b4f35eebeac5dba7516f549a27a67ac5562a584e28204'
    upstreamSize = [long] $lock.provenance.cronetGo.licenseSize
    upstreamSha256 = [string] $lock.provenance.cronetGo.licenseSha256
    normalization = 'repository copy appends one final LF'
    sourceUrl = "https://raw.githubusercontent.com/SagerNet/cronet-go/$($lock.provenance.cronetGo.commit)/LICENSE"
  },
  [ordered] @{
    path = 'naiveproxy-LICENSE.txt'
    size = [long] $lock.provenance.naiveProxy.licenseSize
    sha256 = [string] $lock.provenance.naiveProxy.licenseSha256
    upstreamSize = [long] $lock.provenance.naiveProxy.licenseSize
    upstreamSha256 = [string] $lock.provenance.naiveProxy.licenseSha256
    sourceUrl = [string] $lock.provenance.naiveProxy.licenseUrl
  },
  [ordered] @{
    path = 'chromium-LICENSE.txt'
    size = [long] $lock.provenance.chromium.licenseSize
    sha256 = [string] $lock.provenance.chromium.licenseSha256
    upstreamSize = [long] $lock.provenance.chromium.licenseSize
    upstreamSha256 = [string] $lock.provenance.chromium.licenseSha256
    sourceUrl = [string] $lock.provenance.chromium.sourceUrl
  }
)

$actualNotices = @($manifest.requiredNoticeFiles)
if ($actualNotices.Count -ne $expectedNotices.Count) {
  Fail "notice manifest must contain exactly $($expectedNotices.Count) reviewed files"
}

$noticePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($notice in $actualNotices) {
  $relativePath = [string] $notice.path
  if (-not $noticePaths.Add($relativePath)) {
    Fail "duplicate notice path in manifest: $relativePath"
  }

  $expectedMatches = @($expectedNotices | Where-Object { [string] $_.path -ceq $relativePath })
  if ($expectedMatches.Count -ne 1) {
    Fail "notice path is not in the reviewed set: $relativePath"
  }
  $expectedNotice = $expectedMatches[0]
  Assert-ExactPropertyNames $notice @($expectedNotice.Keys) "notice entry $relativePath"
  foreach ($propertyName in $expectedNotice.Keys) {
    if (
      [string] $notice.PSObject.Properties[$propertyName].Value -cne
      [string] $expectedNotice[$propertyName]
    ) {
      Fail "notice metadata mismatch for ${relativePath}: $propertyName"
    }
  }

  if ([string] $notice.sha256 -cnotmatch '^[0-9a-f]{64}$') {
    Fail "invalid notice hash in manifest: $relativePath"
  }
  $noticePath = Get-SafeNoticePath $licenseRoot $relativePath
  if (-not [IO.File]::Exists($noticePath)) {
    Fail "required notice is missing: $relativePath"
  }
  $item = Get-Item -LiteralPath $noticePath -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "required notice is a reparse point: $relativePath"
  }
  if ([long] $item.Length -ne [long] $notice.size) {
    Fail "required notice size mismatch: $relativePath"
  }
  if ((Get-FileSha256 $item.FullName) -cne [string] $notice.sha256) {
    Fail "required notice SHA-256 mismatch: $relativePath"
  }
}

$expectedLicenseEntries = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[void] $expectedLicenseEntries.Add('manifest.json')
foreach ($expectedNotice in $expectedNotices) {
  [void] $expectedLicenseEntries.Add([string] $expectedNotice.path)
}
foreach ($entry in (Get-Item -LiteralPath $licenseRoot -Force).GetFileSystemInfos()) {
  if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "license directory entry is a reparse point: $($entry.Name)"
  }
  if (-not ($entry -is [IO.FileInfo]) -or -not $expectedLicenseEntries.Contains($entry.Name)) {
    Fail "unexpected entry in the reviewed license directory: $($entry.Name)"
  }
}
if ($expectedLicenseEntries.Count -ne 4) {
  Fail 'internal reviewed notice set cardinality is invalid'
}

$expectedBlockerIds = @(
  'chromium-windows-third-party-notices',
  'sing-box-go-transitive-notices',
  'corresponding-source-review'
)
$actualBlockers = @($manifest.blockers)
if ($actualBlockers.Count -ne $expectedBlockerIds.Count) {
  Fail "notice manifest must contain exactly $($expectedBlockerIds.Count) reviewed blockers"
}
$actualBlockerIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($blocker in $actualBlockers) {
  Assert-ExactPropertyNames $blocker @('id', 'description') 'notice blocker entry'
  $blockerId = [string] $blocker.id
  if (-not $actualBlockerIds.Add($blockerId)) {
    Fail "duplicate notice blocker id: $blockerId"
  }
  if ($blockerId -cnotin $expectedBlockerIds) {
    Fail "unreviewed notice blocker id: $blockerId"
  }
  if ([string]::IsNullOrWhiteSpace([string] $blocker.description)) {
    Fail "notice blocker description is empty: $blockerId"
  }
}
foreach ($expectedBlockerId in $expectedBlockerIds) {
  if (-not $actualBlockerIds.Contains($expectedBlockerId)) {
    Fail "reviewed notice blocker is missing: $expectedBlockerId"
  }
}

if ([string] $manifest.portableAssemblyStatus -cne 'ready') {
  $blockerIds = @($manifest.blockers | ForEach-Object { [string] $_.id }) -join ', '
  Fail "blocked by the reviewed notice manifest ($blockerIds); no target files were written"
}

# Intentionally unreachable while the reviewed manifest is blocked. A future
# change must implement and security-review exact extraction/copy semantics in
# the same commit that establishes a complete notice/source-compliance gate.
Fail 'manifest is marked ready but portable copy semantics are not implemented'
