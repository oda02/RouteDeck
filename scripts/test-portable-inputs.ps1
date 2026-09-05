$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'portable-inputs.ps1')

function Write-FixtureFile([string] $Path, [string] $Content) {
  $parent = Split-Path -Parent $Path
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function File-Contract([string] $Path, [string] $Name) {
  $item = Get-Item -LiteralPath $Path
  [ordered]@{ path = $Name; size = [long]$item.Length; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Assert-Throws([string] $Name, [scriptblock] $Action, [string] $Pattern) {
  try { & $Action | Out-Null; throw "accepted hostile fixture: $Name" }
  catch {
    if ($_.Exception.Message -like "accepted hostile fixture:*") { throw }
    if ($_.Exception.Message -notmatch $Pattern) { throw "$Name returned unexpected error: $($_.Exception.Message)" }
  }
  Write-Output "PASS: $Name"
}

function New-Fixture([string] $Base, [string] $Name) {
  $caseRoot = Join-Path $Base $Name
  $runtime = Join-Path $caseRoot 'runtime'
  $pins = Join-Path $caseRoot 'pins'
  $distribution = Join-Path $caseRoot 'distribution'
  New-Item -ItemType Directory -Path $runtime,$pins,$distribution -Force | Out-Null

  $definitions = @(
    @{ directory='engine'; lock='sing-box.lock.json'; files=@('sing-box.exe','libcronet.dll','LICENSE') },
    @{ directory='xray'; lock='xray-core.lock.json'; files=@('xray.exe','LICENSE') }
  )
  foreach ($definition in $definitions) {
    $contracts = foreach ($namePart in $definition.files) {
      $path = Join-Path (Join-Path $runtime $definition.directory) $namePart
      Write-FixtureFile $path "$($definition.directory)/$namePart fixture"
      File-Contract $path $namePart
    }
    [ordered]@{ schemaVersion=1; runtimeFiles=@($contracts) } |
      ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $pins $definition.lock) -Encoding utf8NoBOM
  }

  $distributionNames = @('ENGINE-THIRD-PARTY-NOTICES.txt','SOURCE-CODE.txt','sources/sing-box.txt','sources/cronet.txt','sources/xray.txt','sources/licenses.txt')
  $distributionFiles = foreach ($relative in $distributionNames) {
    $path = Join-Path $distribution ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    Write-FixtureFile $path "$relative fixture"
    File-Contract $path $relative
  }
  $inventory = [ordered]@{
    schemaVersion=1
    runtimeLocks=[ordered]@{
      singBoxSha256=(Get-FileHash -LiteralPath (Join-Path $pins 'sing-box.lock.json') -Algorithm SHA256).Hash.ToLowerInvariant()
      xraySha256=(Get-FileHash -LiteralPath (Join-Path $pins 'xray-core.lock.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    files=@($distributionFiles)
  }
  $inventory | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $distribution 'engine-distribution-inventory.json') -Encoding utf8NoBOM
  [pscustomobject]@{ Root=$caseRoot; Runtime=$runtime; Pins=$pins; Distribution=$distribution }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('routedeck-portable-inputs-' + [guid]::NewGuid().ToString('N'))
$resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$resolvedTest = [IO.Path]::GetFullPath($testRoot)
if (-not $resolvedTest.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture root' }
New-Item -ItemType Directory -Path $resolvedTest | Out-Null

try {
  $valid = New-Fixture $resolvedTest 'valid'
  $runtimeFiles = @(Get-PortableRuntimeFiles $valid.Runtime $valid.Pins)
  if (($runtimeFiles.path -join '|') -cne 'engine/sing-box.exe|engine/libcronet.dll|engine/LICENSE|xray/xray.exe|xray/LICENSE') { throw 'runtime paths did not match exact pins' }
  $distributionFiles = @(Get-PortableEngineDistribution $valid.Distribution $valid.Pins)
  if ($distributionFiles.Count -ne 6) { throw 'distribution inventory was not returned exactly' }
  Write-Output 'PASS: exact runtime pins, paths and distribution root bindings'

  $case = New-Fixture $resolvedTest 'duplicate-case'
  $inventoryPath = Join-Path $case.Distribution 'engine-distribution-inventory.json'
  $inventory = Get-Content $inventoryPath -Raw | ConvertFrom-Json
  $duplicate = $inventory.files[2].PSObject.Copy(); $duplicate.path = $duplicate.path.ToUpperInvariant()
  $inventory.files = @($inventory.files) + $duplicate
  $inventory | ConvertTo-Json -Depth 6 | Set-Content $inventoryPath -Encoding utf8NoBOM
  Assert-Throws 'case-insensitive duplicate distribution paths' { Get-PortableEngineDistribution $case.Distribution $case.Pins } 'Unexpected engine distribution path'

  $case = New-Fixture $resolvedTest 'traversal'
  $inventoryPath = Join-Path $case.Distribution 'engine-distribution-inventory.json'
  $inventory = Get-Content $inventoryPath -Raw | ConvertFrom-Json
  $inventory.files[2].path = 'sources/../escape.txt'
  $inventory | ConvertTo-Json -Depth 6 | Set-Content $inventoryPath -Encoding utf8NoBOM
  Assert-Throws 'distribution traversal' { Get-PortableEngineDistribution $case.Distribution $case.Pins } 'Unexpected engine distribution path|Invalid distribution file contract'

  $case = New-Fixture $resolvedTest 'missing-notice'
  $inventoryPath = Join-Path $case.Distribution 'engine-distribution-inventory.json'
  $inventory = Get-Content $inventoryPath -Raw | ConvertFrom-Json
  $inventory.files[0].path = 'sources/replacement.txt'
  $replacement = Join-Path $case.Distribution 'sources/replacement.txt'; Write-FixtureFile $replacement 'replacement fixture'
  $contract = File-Contract $replacement 'sources/replacement.txt'; $inventory.files[0].size=$contract.size; $inventory.files[0].sha256=$contract.sha256
  $inventory | ConvertTo-Json -Depth 6 | Set-Content $inventoryPath -Encoding utf8NoBOM
  Assert-Throws 'missing required notices' { Get-PortableEngineDistribution $case.Distribution $case.Pins } 'notices are missing'

  $case = New-Fixture $resolvedTest 'tampered-source'
  Add-Content -LiteralPath (Join-Path $case.Distribution 'sources/sing-box.txt') -Value 'tampered'
  Assert-Throws 'tampered distribution source' { Get-PortableEngineDistribution $case.Distribution $case.Pins } 'integrity failed'

  $case = New-Fixture $resolvedTest 'late-tampered-source'
  Add-Content -LiteralPath (Join-Path $case.Distribution 'sources/licenses.txt') -Value 'tampered last entry'
  $lateError = $null
  $partial = @(& {
    try { Get-PortableEngineDistribution $case.Distribution $case.Pins }
    catch { $script:lateError = $_.Exception }
  })
  if ($null -eq $lateError -or $lateError.Message -notmatch 'integrity failed') { throw 'late tampering was not rejected' }
  if ($partial.Count -ne 0) { throw "late hostile entry emitted $($partial.Count) partially verified files" }
  Write-Output 'PASS: late hostile distribution entry emits no partial output'

  $case = New-Fixture $resolvedTest 'tampered-runtime'
  Add-Content -LiteralPath (Join-Path $case.Runtime 'engine/sing-box.exe') -Value 'tampered'
  Assert-Throws 'tampered pinned runtime' { Get-PortableRuntimeFiles $case.Runtime $case.Pins } 'integrity failed'

  $case = New-Fixture $resolvedTest 'late-tampered-runtime'
  Add-Content -LiteralPath (Join-Path $case.Runtime 'xray/LICENSE') -Value 'tampered last runtime'
  $lateError = $null
  $partial = @(& {
    try { Get-PortableRuntimeFiles $case.Runtime $case.Pins }
    catch { $script:lateError = $_.Exception }
  })
  if ($null -eq $lateError -or $lateError.Message -notmatch 'integrity failed') { throw 'late runtime tampering was not rejected' }
  if ($partial.Count -ne 0) { throw "late hostile runtime emitted $($partial.Count) partially verified files" }
  Write-Output 'PASS: late hostile runtime entry emits no partial output'

  $case = New-Fixture $resolvedTest 'wrong-lock-binding'
  Add-Content -LiteralPath (Join-Path $case.Pins 'sing-box.lock.json') -Value ' '
  Assert-Throws 'distribution bound to exact runtime lock hash' { Get-PortableEngineDistribution $case.Distribution $case.Pins } 'does not match runtime pins'

  $case = New-Fixture $resolvedTest 'runtime-path'
  $lockPath = Join-Path $case.Pins 'sing-box.lock.json'; $lock = Get-Content $lockPath -Raw | ConvertFrom-Json
  $lock.runtimeFiles[0].path = '../sing-box.exe'; $lock | ConvertTo-Json -Depth 5 | Set-Content $lockPath -Encoding utf8NoBOM
  Assert-Throws 'runtime pin traversal and unexpected filepath' { Get-PortableRuntimeFiles $case.Runtime $case.Pins } 'Unexpected runtime file'

  $case = New-Fixture $resolvedTest 'runtime-duplicate'
  $lockPath = Join-Path $case.Pins 'sing-box.lock.json'; $lock = Get-Content $lockPath -Raw | ConvertFrom-Json
  $lock.runtimeFiles[1].path = 'SING-BOX.EXE'; $lock | ConvertTo-Json -Depth 5 | Set-Content $lockPath -Encoding utf8NoBOM
  Assert-Throws 'case-insensitive duplicate runtime pins' { Get-PortableRuntimeFiles $case.Runtime $case.Pins } 'Unexpected runtime file'

  $case = New-Fixture $resolvedTest 'junction'
  $target = Join-Path $case.Root 'junction-target'; New-Item -ItemType Directory -Path $target | Out-Null
  $junction = Join-Path $case.Distribution 'sources/junction'
  try {
    New-Item -ItemType Junction -Path $junction -Target $target -ErrorAction Stop | Out-Null
    Write-FixtureFile (Join-Path $target 'payload.txt') 'junction payload'
    $payload = Join-Path $target 'payload.txt'; $contract = File-Contract $payload 'sources/junction/payload.txt'
    Assert-Throws 'distribution reparse-point component' { Get-VerifiedDistributionFile $case.Distribution $contract.path $contract.size $contract.sha256 } 'reparse points are forbidden'
  } catch {
    if ($_.Exception.Message -like 'distribution reparse-point component returned*' -or $_.Exception.Message -like 'accepted hostile fixture:*') { throw }
    Write-Output "SKIP: nonprivileged junction unavailable ($($_.Exception.Message))"
  }

  Write-Output 'PASS: portable input hostile fixtures; no executable or network access'
} finally {
  if ([IO.Path]::GetFullPath($resolvedTest).StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedTest -Recurse -Force
  }
}
