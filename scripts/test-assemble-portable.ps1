<#
.SYNOPSIS
Regression tests for the fail-closed portable assembly compliance gate.

.DESCRIPTION
All mutable fixtures and targets are created beneath one unique directory in
the system temporary directory. The script never executes the engine binary.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $ArchivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool] $Condition, [string] $Message) {
  if (-not $Condition) {
    throw "FAIL: $Message"
  }
}

function Write-JsonFile([string] $Path, $Value) {
  $json = $Value | ConvertTo-Json -Depth 20
  [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

function Invoke-Gate([string] $GatePath, [string] $EnginePath, [string] $TargetRoot) {
  $records = [Collections.ArrayList]::new()
  $exitCode = 0
  try {
    & $GatePath -EnginePath $EnginePath -TargetRoot $TargetRoot *>&1 |
      ForEach-Object { [void] $records.Add($_.ToString()) }
  }
  catch {
    $exitCode = 1
    [void] $records.Add($_.Exception.Message)
  }
  return [pscustomobject] @{
    ExitCode = $exitCode
    Output = ($records -join "`n")
  }
}

function Assert-Rejected(
  [string] $Label,
  [string] $GatePath,
  [string] $EnginePath,
  [string] $TargetRoot,
  [string] $ExpectedText
) {
  $result = Invoke-Gate $GatePath $EnginePath $TargetRoot
  Assert-True ($result.ExitCode -ne 0) "$Label was unexpectedly accepted"
  Assert-True ($result.Output.IndexOf($ExpectedText, [StringComparison]::OrdinalIgnoreCase) -ge 0) `
    "$Label did not report '$ExpectedText'; output: $($result.Output)"
  Write-Output "PASS: $Label"
}

function New-Fixture([string] $SourceRoot, [string] $FixtureRoot) {
  [IO.Directory]::CreateDirectory((Join-Path $FixtureRoot 'scripts')) | Out-Null
  [IO.Directory]::CreateDirectory((Join-Path $FixtureRoot 'engine\licenses')) | Out-Null
  foreach ($relativePath in @(
    'scripts\assemble-portable.ps1',
    'scripts\verify-engine.ps1',
    'engine\sing-box.lock.json',
    'engine\licenses\manifest.json',
    'engine\licenses\cronet-go-LICENSE.txt',
    'engine\licenses\naiveproxy-LICENSE.txt',
    'engine\licenses\chromium-LICENSE.txt'
  )) {
    $destination = Join-Path $FixtureRoot $relativePath
    [IO.File]::Copy((Join-Path $SourceRoot $relativePath), $destination, $false)
  }
  return Join-Path $FixtureRoot 'scripts\assemble-portable.ps1'
}

function Assert-TargetAbsent([string] $Path, [string] $Label) {
  Assert-True (-not [IO.File]::Exists($Path)) "$Label created a target file"
  Assert-True (-not [IO.Directory]::Exists($Path)) "$Label created a target directory"
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gatePath = Join-Path $PSScriptRoot 'assemble-portable.ps1'
$resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath).Path
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$safePrefix = Join-Path $tempBase 'RouteDeck-portable-audit-'
$testRoot = $safePrefix + [guid]::NewGuid().ToString('N')
$junctionPath = $null

Assert-True ($testRoot.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) `
  'unique test root escaped the guarded prefix'
[IO.Directory]::CreateDirectory($testRoot) | Out-Null

try {
  $absentTarget = Join-Path $testRoot 'blocked-absent-target'
  Assert-Rejected 'blocked manifest leaves absent target absent' $gatePath $resolvedArchive `
    $absentTarget 'blocked by the reviewed notice manifest'
  Assert-TargetAbsent $absentTarget 'blocked manifest'

  $existingTarget = Join-Path $testRoot 'blocked-existing-target'
  [IO.Directory]::CreateDirectory($existingTarget) | Out-Null
  $sentinelPath = Join-Path $existingTarget 'sentinel.txt'
  [IO.File]::WriteAllText($sentinelPath, 'route-deck-sentinel', [Text.UTF8Encoding]::new($false))
  $sentinelHash = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash
  $beforeEntries = @((Get-ChildItem -LiteralPath $existingTarget -Force).Name)
  Assert-Rejected 'blocked manifest preserves pre-existing target' $gatePath $resolvedArchive `
    $existingTarget 'blocked by the reviewed notice manifest'
  Assert-True ((Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash -ceq $sentinelHash) `
    'pre-existing sentinel content changed'
  $afterEntries = @((Get-ChildItem -LiteralPath $existingTarget -Force).Name)
  Assert-True (($beforeEntries -join "`n") -ceq ($afterEntries -join "`n")) `
    'pre-existing target entries changed'

  $readyFixture = Join-Path $testRoot 'fixture-ready'
  $readyGate = New-Fixture $repoRoot $readyFixture
  $readyManifestPath = Join-Path $readyFixture 'engine\licenses\manifest.json'
  $readyManifest = Get-Content -Raw -LiteralPath $readyManifestPath | ConvertFrom-Json
  $readyManifest.portableAssemblyStatus = 'ready'
  Write-JsonFile $readyManifestPath $readyManifest
  $readyTarget = Join-Path $testRoot 'ready-target'
  Assert-Rejected 'status-only ready still cannot assemble' $readyGate $resolvedArchive `
    $readyTarget 'copy semantics are not implemented'
  Assert-TargetAbsent $readyTarget 'status-only ready manifest'

  $tamperFixture = Join-Path $testRoot 'fixture-notice-tamper'
  $tamperGate = New-Fixture $repoRoot $tamperFixture
  $tamperedNotice = Join-Path $tamperFixture 'engine\licenses\chromium-LICENSE.txt'
  $tamperedBytes = [IO.File]::ReadAllBytes($tamperedNotice)
  $tamperedBytes[0] = $tamperedBytes[0] -bxor 1
  [IO.File]::WriteAllBytes($tamperedNotice, $tamperedBytes)
  $tamperTarget = Join-Path $testRoot 'tamper-target'
  Assert-Rejected 'notice content tamper is rejected pre-write' $tamperGate $resolvedArchive `
    $tamperTarget 'required notice SHA-256 mismatch'
  Assert-TargetAbsent $tamperTarget 'notice tamper'

  $provenanceFixture = Join-Path $testRoot 'fixture-provenance'
  $provenanceGate = New-Fixture $repoRoot $provenanceFixture
  $provenanceManifestPath = Join-Path $provenanceFixture 'engine\licenses\manifest.json'
  $provenanceManifest = Get-Content -Raw -LiteralPath $provenanceManifestPath | ConvertFrom-Json
  $provenanceManifest.reviewedFor.cronetGoCommit = '0000000000000000000000000000000000000000'
  Write-JsonFile $provenanceManifestPath $provenanceManifest
  $provenanceTarget = Join-Path $testRoot 'provenance-target'
  Assert-Rejected 'provenance mismatch is rejected pre-write' $provenanceGate $resolvedArchive `
    $provenanceTarget 'provenance does not match the engine lock'
  Assert-TargetAbsent $provenanceTarget 'provenance mismatch'

  $sourceFixture = Join-Path $testRoot 'fixture-source-url'
  $sourceGate = New-Fixture $repoRoot $sourceFixture
  $sourceManifestPath = Join-Path $sourceFixture 'engine\licenses\manifest.json'
  $sourceManifest = Get-Content -Raw -LiteralPath $sourceManifestPath | ConvertFrom-Json
  $sourceManifest.requiredNoticeFiles[1].sourceUrl = 'https://example.invalid/substitution'
  Write-JsonFile $sourceManifestPath $sourceManifest
  $sourceTarget = Join-Path $testRoot 'source-target'
  Assert-Rejected 'notice source substitution is rejected pre-write' $sourceGate $resolvedArchive `
    $sourceTarget 'notice metadata mismatch'
  Assert-TargetAbsent $sourceTarget 'notice source substitution'

  $cardinalityFixture = Join-Path $testRoot 'fixture-cardinality'
  $cardinalityGate = New-Fixture $repoRoot $cardinalityFixture
  $cardinalityManifestPath = Join-Path $cardinalityFixture 'engine\licenses\manifest.json'
  $cardinalityManifest = Get-Content -Raw -LiteralPath $cardinalityManifestPath | ConvertFrom-Json
  $cardinalityManifest.requiredNoticeFiles = @($cardinalityManifest.requiredNoticeFiles[0..1])
  Write-JsonFile $cardinalityManifestPath $cardinalityManifest
  $cardinalityTarget = Join-Path $testRoot 'cardinality-target'
  Assert-Rejected 'notice manifest cardinality mismatch is rejected pre-write' `
    $cardinalityGate $resolvedArchive $cardinalityTarget 'must contain exactly 3 reviewed files'
  Assert-TargetAbsent $cardinalityTarget 'notice manifest cardinality mismatch'

  $extraFixture = Join-Path $testRoot 'fixture-extra-notice'
  $extraGate = New-Fixture $repoRoot $extraFixture
  [IO.File]::WriteAllText(
    (Join-Path $extraFixture 'engine\licenses\extra.txt'),
    'unexpected',
    [Text.UTF8Encoding]::new($false)
  )
  $extraTarget = Join-Path $testRoot 'extra-target'
  Assert-Rejected 'extra notice file is rejected pre-write' $extraGate $resolvedArchive `
    $extraTarget 'unexpected entry in the reviewed license directory'
  Assert-TargetAbsent $extraTarget 'extra notice file'

  $missingFixture = Join-Path $testRoot 'fixture-missing-notice'
  $missingGate = New-Fixture $repoRoot $missingFixture
  [IO.File]::Delete((Join-Path $missingFixture 'engine\licenses\naiveproxy-LICENSE.txt'))
  $missingTarget = Join-Path $testRoot 'missing-target'
  Assert-Rejected 'missing notice file is rejected pre-write' $missingGate $resolvedArchive `
    $missingTarget 'required notice is missing'
  Assert-TargetAbsent $missingTarget 'missing notice file'

  Push-Location $testRoot
  try {
    Assert-Rejected 'relative target is rejected' $gatePath $resolvedArchive `
      'relative-target' 'fully qualified local-drive path'
    Assert-TargetAbsent (Join-Path $testRoot 'relative-target') 'relative target'

    $drivePrefix = [IO.Path]::GetPathRoot($testRoot).Substring(0, 2)
    $driveRelativeTarget = $drivePrefix + 'drive-relative-target'
    Assert-Rejected 'drive-relative target is rejected' $gatePath $resolvedArchive `
      $driveRelativeTarget 'fully qualified local-drive path'
    Assert-TargetAbsent (Join-Path $testRoot 'drive-relative-target') 'drive-relative target'
  }
  finally {
    Pop-Location
  }

  $rootRelativeTarget = $testRoot.Substring(2) + '\root-relative-target'
  Assert-Rejected 'root-relative target is rejected' $gatePath $resolvedArchive `
    $rootRelativeTarget 'fully qualified local-drive path'
  Assert-TargetAbsent (Join-Path $testRoot 'root-relative-target') 'root-relative target'

  Assert-Rejected 'broad temp-root target is rejected' $gatePath $resolvedArchive `
    ([IO.Path]::GetTempPath()) 'broad target path is not allowed'

  $volumeRoot = [IO.Path]::GetPathRoot($testRoot)
  Assert-Rejected 'volume-root target is rejected' $gatePath $resolvedArchive `
    $volumeRoot 'volume-root target paths are not allowed'

  $traversalTarget = Join-Path $testRoot 'nested\..\escaped-target'
  Assert-Rejected 'traversal target is rejected' $gatePath $resolvedArchive `
    $traversalTarget 'empty or traversal segment'
  Assert-TargetAbsent (Join-Path $testRoot 'escaped-target') 'traversal target'

  $adsTarget = (Join-Path $testRoot 'safe-target') + ':stream'
  Assert-Rejected 'alternate-data-stream target is rejected' $gatePath $resolvedArchive `
    $adsTarget 'alternate-data-stream separator'

  Assert-Rejected 'device target is rejected' $gatePath $resolvedArchive `
    '\\?\C:\RouteDeck-portable-audit-device' 'UNC and device target paths are not supported'

  $hostileTargets = @(
    [pscustomobject] @{ Label = 'reserved DOS device with extension'; Path = (Join-Path $testRoot 'CON.txt\child'); Expected = 'reserved Windows device name' },
    [pscustomobject] @{ Label = 'reserved superscript DOS device with extension'; Path = (Join-Path $testRoot ("COM$([char] 0x00B9).log\child")); Expected = 'reserved Windows device name' },
    [pscustomobject] @{ Label = 'trailing-dot segment'; Path = (Join-Path $testRoot 'ambiguous.\child'); Expected = 'Windows-ambiguous segment' },
    [pscustomobject] @{ Label = 'trailing-space segment'; Path = (Join-Path $testRoot 'ambiguous \child'); Expected = 'Windows-ambiguous segment' },
    [pscustomobject] @{ Label = 'control-character segment'; Path = (Join-Path $testRoot ("control$([char] 1)segment\child")); Expected = 'control character' },
    [pscustomobject] @{ Label = 'invalid-Win32-character segment'; Path = (Join-Path $testRoot 'invalid<segment\child'); Expected = 'invalid Win32 character' }
  )
  foreach ($hostileTarget in $hostileTargets) {
    Assert-Rejected $hostileTarget.Label $gatePath $resolvedArchive `
      $hostileTarget.Path $hostileTarget.Expected
  }

  $junctionBacking = Join-Path $testRoot 'junction-backing'
  $junctionPath = Join-Path $testRoot 'junction-parent'
  [IO.Directory]::CreateDirectory($junctionBacking) | Out-Null
  try {
    New-Item -ItemType Junction -Path $junctionPath -Target $junctionBacking | Out-Null
    $junctionItem = Get-Item -LiteralPath $junctionPath -Force
    Assert-True (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) `
      'junction fixture is not a reparse point'
    $junctionTarget = Join-Path $junctionPath 'future-portable-target'
    Assert-Rejected 'reparse-point ancestor is rejected' $gatePath $resolvedArchive `
      $junctionTarget 'target path ancestor is a reparse point'
    Assert-TargetAbsent $junctionTarget 'reparse-point ancestor target'
  }
  finally {
    if ($null -ne $junctionPath -and [IO.Directory]::Exists($junctionPath)) {
      [IO.Directory]::Delete($junctionPath, $false)
    }
  }

  Write-Output 'PASS: portable assembly audit suite completed'
}
finally {
  $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
  Assert-True ($resolvedTestRoot.StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) `
    'cleanup target escaped the guarded temporary prefix'
  Assert-True ($resolvedTestRoot -cne $tempBase) 'cleanup target resolved to the broad temp root'
  if ($null -ne $junctionPath -and [IO.Directory]::Exists($junctionPath)) {
    $junctionItem = Get-Item -LiteralPath $junctionPath -Force
    Assert-True (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) `
      'guarded cleanup encountered a non-reparse junction fixture'
    [IO.Directory]::Delete($junctionPath, $false)
  }
  if ([IO.Directory]::Exists($resolvedTestRoot)) {
    Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
  }
}
