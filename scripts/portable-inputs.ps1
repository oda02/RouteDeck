# Read-only validation shared by portable packaging and hostile-input fixtures.
Set-StrictMode -Version Latest

function Get-VerifiedDistributionFile {
  param([string] $Root, [string] $RelativePath, $Size, [string] $Sha256)
  if ($RelativePath -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or
      @($RelativePath.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0 -or
      $Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
      ($Size -isnot [int] -and $Size -isnot [long]) -or $Size -lt 1 -or $Size -gt 2147483647) {
    throw 'Invalid distribution file contract'
  }
  $current = [IO.Path]::GetFullPath($Root)
  foreach ($component in @('') + $RelativePath.Split('/')) {
    if ($component) { $current = Join-Path $current $component }
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Distribution reparse points are forbidden' }
  }
  if ($item.PSIsContainer -or $item.Length -ne $Size -or
      (Get-FileHash -LiteralPath $current -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) {
    throw 'Distribution file integrity failed'
  }
  return $current
}

function Get-PortableRuntimeFiles {
  param([string] $RuntimeRoot, [string] $PinsRoot)
  $results = [Collections.Generic.List[object]]::new()
  foreach ($descriptor in @(
    @{ lock = 'sing-box.lock.json'; directory = 'engine'; files = @('sing-box.exe', 'libcronet.dll', 'LICENSE') },
    @{ lock = 'xray-core.lock.json'; directory = 'xray'; files = @('xray.exe', 'LICENSE') }
  )) {
    $lock = Get-Content -LiteralPath (Join-Path $PinsRoot $descriptor.lock) -Raw | ConvertFrom-Json
    if ($lock.schemaVersion -ne 1 -or @($lock.runtimeFiles).Count -ne $descriptor.files.Count) { throw 'Unexpected runtime pin contract' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $lock.runtimeFiles) {
      if ($descriptor.files -cnotcontains $file.path -or -not $seen.Add($file.path)) { throw 'Unexpected runtime file' }
      $relative = "$($descriptor.directory)/$($file.path)"
      $verified = Get-VerifiedDistributionFile -Root $RuntimeRoot -RelativePath $relative -Size $file.size -Sha256 $file.sha256
      $results.Add([pscustomobject]@{ path = $relative; source = $verified; size = $file.size; sha256 = $file.sha256 })
    }
  }
  return $results
}

function Get-PortableEngineDistribution {
  param([string] $Root, [string] $PinsRoot)
  $results = [Collections.Generic.List[object]]::new()
  $inventoryPath = Join-Path $Root 'engine-distribution-inventory.json'
  $inventoryItem = Get-Item -LiteralPath $inventoryPath -Force
  if ($inventoryItem.Length -gt 16777216 -or ($inventoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid engine distribution inventory' }
  $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
  if ($inventory.schemaVersion -ne 1 -or @($inventory.files).Count -lt 6) { throw 'Invalid engine distribution inventory' }
  foreach ($binding in @(@{file='sing-box.lock.json';key='singBoxSha256'},@{file='xray-core.lock.json';key='xraySha256'})) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $PinsRoot $binding.file) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($inventory.runtimeLocks.($binding.key) -cne $hash) { throw 'Engine distribution does not match runtime pins' }
  }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($file in $inventory.files) {
    if (($file.path -cnotin @('ENGINE-THIRD-PARTY-NOTICES.txt','SOURCE-CODE.txt') -and
         $file.path -cnotmatch '^sources/[A-Za-z0-9][A-Za-z0-9._-]*$') -or -not $seen.Add($file.path)) {
      throw 'Unexpected engine distribution path'
    }
    $verified = Get-VerifiedDistributionFile -Root $Root -RelativePath $file.path -Size $file.size -Sha256 $file.sha256
    $results.Add([pscustomobject]@{ path = $file.path; source = $verified; size = $file.size; sha256 = $file.sha256 })
  }
  if (-not $seen.Contains('ENGINE-THIRD-PARTY-NOTICES.txt') -or -not $seen.Contains('SOURCE-CODE.txt')) { throw 'Engine distribution notices are missing' }
  return $results
}
