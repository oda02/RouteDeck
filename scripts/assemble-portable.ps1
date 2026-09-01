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

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$engineLockPath = Join-Path $repoRoot 'engine\sing-box.lock.json'
$licenseRoot = Join-Path $repoRoot 'engine\licenses'
$manifestPath = Join-Path $licenseRoot 'manifest.json'
$verifierPath = Join-Path $PSScriptRoot 'verify-engine.ps1'

# Resolve the caller-supplied target but deliberately do not create or write it
# unless a future reviewed implementation replaces the blocked branch below.
[void] [IO.Path]::GetFullPath($TargetRoot)

& $verifierPath -Path $EnginePath -LockFile $engineLockPath | Write-Output

$lock = Get-Content -Raw -LiteralPath $engineLockPath | ConvertFrom-Json
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ([int] $manifest.schemaVersion -ne 1) {
  Fail 'unsupported notice manifest schema'
}
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

$noticePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($notice in @($manifest.requiredNoticeFiles)) {
  $relativePath = [string] $notice.path
  if (-not $noticePaths.Add($relativePath)) {
    Fail "duplicate notice path in manifest: $relativePath"
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

if ([string] $manifest.portableAssemblyStatus -cne 'ready') {
  $blockerIds = @($manifest.blockers | ForEach-Object { [string] $_.id }) -join ', '
  Fail "blocked by the reviewed notice manifest ($blockerIds); no target files were created"
}

# Intentionally unreachable while the reviewed manifest is blocked. A future
# change must implement and security-review exact extraction/copy semantics in
# the same commit that establishes a complete notice/source-compliance gate.
Fail 'manifest is marked ready but portable copy semantics are not implemented'
