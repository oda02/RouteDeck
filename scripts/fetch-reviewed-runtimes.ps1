[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string] $DestinationRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-Fetch([string] $Message) { throw "Runtime fetch failed: $Message" }

function Get-StreamSha256([IO.Stream] $Stream) {
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([Convert]::ToHexString($hash.ComputeHash($Stream))).ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Copy-PinnedStream([IO.Stream] $Source, [long] $Size, [string] $Sha256, [string] $Destination) {
  $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $buffer = [byte[]]::new(65536); $total = 0L
    while (($read = $Source.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $total += $read
      if ($total -gt $Size) { Fail-Fetch 'download exceeded pinned size' }
      $output.Write($buffer, 0, $read)
    }
  } finally { $output.Dispose() }
  if ($total -ne $Size) { Fail-Fetch 'download size differs from pin' }
  $stream = [IO.File]::OpenRead($Destination)
  try { if ((Get-StreamSha256 $stream) -cne $Sha256) { Fail-Fetch 'download SHA-256 differs from pin' } }
  finally { $stream.Dispose() }
}

function Assert-SafeZipName([string] $Name) {
  $normalized = $Name.Replace('\', '/')
  if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized.StartsWith('/') -or
      $normalized.Contains('//') -or $normalized -match '^[A-Za-z]:' -or
      $normalized.Split('/') -contains '..' -or $normalized.IndexOf([char]0) -ge 0) {
    Fail-Fetch "unsafe ZIP entry name: $Name"
  }
  foreach ($segment in $normalized.Split('/')) {
    if ($segment -in @('', '.') -or $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
        $segment.IndexOfAny([char[]]'<>:"|?*') -ge 0 -or
        @($segment.ToCharArray() | Where-Object { [int]$_ -lt 32 }).Count -ne 0 -or
        [IO.Path]::GetFileNameWithoutExtension($segment).TrimEnd(' ', '.').ToUpperInvariant() -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
      Fail-Fetch "unsafe Windows ZIP entry name: $Name"
    }
  }
  return $normalized
}

function Receive-PinnedFile([Uri] $Uri, [long] $Size, [string] $Sha256, [string] $Destination) {
  if ($Uri.Scheme -cne 'https' -or $Size -lt 1 -or $Size -gt 134217728 -or $Sha256 -cnotmatch '^[a-f0-9]{64}$') {
    Fail-Fetch 'invalid pinned download metadata'
  }
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromSeconds(90)
  $response = $null
  try {
    $current = $Uri
    for ($redirects = 0; $redirects -le 5; $redirects++) {
      $response = $client.GetAsync($current, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
      if ([int]$response.StatusCode -notin @(301, 302, 303, 307, 308)) { break }
      if ($redirects -eq 5 -or $null -eq $response.Headers.Location) { Fail-Fetch 'invalid or excessive download redirect' }
      $next = if ($response.Headers.Location.IsAbsoluteUri) { $response.Headers.Location } else { [Uri]::new($current, $response.Headers.Location) }
      if ($next.Scheme -cne 'https' -or $next.Host -notin @('github.com', 'release-assets.githubusercontent.com')) {
        Fail-Fetch 'download redirected outside reviewed GitHub asset hosts'
      }
      $response.Dispose(); $response = $null; $current = $next
    }
    if (-not $response.IsSuccessStatusCode) { Fail-Fetch "download returned HTTP $([int]$response.StatusCode)" }
    $final = $response.RequestMessage.RequestUri
    if ($final.Scheme -cne 'https' -or $final.Host -notin @('github.com', 'release-assets.githubusercontent.com')) {
      Fail-Fetch 'download redirected outside reviewed GitHub asset hosts'
    }
    if ($null -ne $response.Content.Headers.ContentLength -and [long]$response.Content.Headers.ContentLength -ne $Size) {
      Fail-Fetch 'download Content-Length differs from pin'
    }
    $downloadStream = $response.Content.ReadAsStream()
    try {
      Copy-PinnedStream $downloadStream $Size $Sha256 $Destination
    } finally { $downloadStream.Dispose() }
  } finally {
    if ($null -ne $response) { $response.Dispose() }
    $client.Dispose(); $handler.Dispose()
  }
}

function Expand-ReviewedRuntimeArchive($Lock, [string] $ArchivePath, [string] $Destination) {
  $runtime = @($Lock.runtimeFiles)
  if ($runtime.Count -lt 1 -or $runtime.Count -gt 8) { Fail-Fetch 'invalid runtime file count' }
  $reviewed = if ($null -ne $Lock.releaseAsset.PSObject.Properties['archiveEntries']) { @($Lock.releaseAsset.archiveEntries) } else { $runtime }
  if ($reviewed.Count -lt $runtime.Count -or $reviewed.Count -gt 64) { Fail-Fetch 'invalid reviewed ZIP entry count' }
  $allowed = @{}; $totalExpected = 0L
  foreach ($item in $reviewed) {
    $declaredName = if ($null -ne $item.PSObject.Properties['archivePath']) { [string]$item.archivePath } else { [string]$item.path }
    $name = Assert-SafeZipName $declaredName
    if ($allowed.ContainsKey($name)) { Fail-Fetch "duplicate reviewed ZIP entry: $name" }
    $length = [long]$item.size
    if ($length -lt 0) { Fail-Fetch 'negative ZIP entry size' }
    $totalExpected += $length
    if ($totalExpected -gt 268435456) { Fail-Fetch 'reviewed ZIP expands beyond limit' }
    $allowed[$name] = $length
  }
  $wanted = @{}
  foreach ($item in $runtime) {
    $flat = [string]$item.path
    if ([IO.Path]::GetFileName($flat) -cne $flat -or $flat -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { Fail-Fetch 'runtime destination must be a safe flat name' }
    $archiveName = Assert-SafeZipName ([string]$item.archivePath)
    if (-not $allowed.ContainsKey($archiveName) -or [long]$item.size -ne $allowed[$archiveName] -or [string]$item.sha256 -cnotmatch '^[a-f0-9]{64}$') {
      Fail-Fetch 'runtime file is not exactly covered by reviewed ZIP metadata'
    }
    if ($wanted.ContainsKey($archiveName)) { Fail-Fetch 'duplicate runtime archive path' }
    $wanted[$archiveName] = $item
  }
  [IO.Directory]::CreateDirectory($Destination) | Out-Null
  $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ([long]$stream.Length -ne [long]$Lock.releaseAsset.size) { Fail-Fetch 'archive size changed before extraction' }
    if ((Get-StreamSha256 $stream) -cne [string]$Lock.releaseAsset.sha256) { Fail-Fetch 'archive SHA-256 changed before extraction' }
    [void]$stream.Seek(0, [IO.SeekOrigin]::Begin)
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
      if ($zip.Entries.Count -ne $allowed.Count) { Fail-Fetch 'ZIP entry count differs from reviewed metadata' }
      $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($entry in $zip.Entries) {
        $name = Assert-SafeZipName $entry.FullName
        if (-not $seen.Add($name) -or -not $allowed.ContainsKey($name) -or [long]$entry.Length -ne $allowed[$name]) { Fail-Fetch "unexpected ZIP entry: $name" }
        if ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { Fail-Fetch "symbolic-link ZIP entry: $name" }
        if ($wanted.ContainsKey($name)) {
          $spec = $wanted[$name]; $target = Join-Path $Destination ([string]$spec.path)
          $entryStream = $entry.Open(); $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
          try { $entryStream.CopyTo($output) } finally { $output.Dispose(); $entryStream.Dispose() }
          $fileStream = [IO.File]::OpenRead($target)
          try { if ((Get-StreamSha256 $fileStream) -cne [string]$spec.sha256) { Fail-Fetch "runtime SHA-256 mismatch: $name" } }
          finally { $fileStream.Dispose() }
        }
      }
      foreach ($name in $allowed.Keys) { if (-not $seen.Contains($name)) { Fail-Fetch "missing ZIP entry: $name" } }
    } finally { $zip.Dispose() }
  } catch [IO.InvalidDataException] { Fail-Fetch 'invalid ZIP archive' }
  finally { $stream.Dispose() }
}

if ($MyInvocation.InvocationName -eq '.') { return }

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destination = [IO.Path]::GetFullPath($DestinationRoot)
if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { Fail-Fetch 'destination already exists' }
$parent = [IO.Path]::GetDirectoryName($destination)
[IO.Directory]::CreateDirectory($parent) | Out-Null
$stage = Join-Path $parent ('.routedeck-runtime-fetch-' + [guid]::NewGuid().ToString('N'))
try {
  [IO.Directory]::CreateDirectory($stage) | Out-Null
  foreach ($definition in @(
    @{ Lock = 'engine\sing-box.lock.json'; Directory = 'engine'; Url = '^https://github\.com/SagerNet/sing-box/releases/download/v[^/]+/sing-box-[^/]+-windows-amd64\.zip$' },
    @{ Lock = 'engine\xray-core.lock.json'; Directory = 'xray'; Url = '^https://github\.com/XTLS/Xray-core/releases/download/v[^/]+/Xray-windows-64\.zip$' }
  )) {
    $lockPath = Join-Path $repo $definition.Lock
    $lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
    $url = [string]$lock.releaseAsset.url
    if ($url -cnotmatch $definition.Url) { Fail-Fetch 'lock contains an unexpected release asset URL' }
    $archive = Join-Path $stage ([string]$lock.releaseAsset.name)
    Receive-PinnedFile ([Uri]$url) ([long]$lock.releaseAsset.size) ([string]$lock.releaseAsset.sha256) $archive
    $runtimeStage = Join-Path $stage $definition.Directory
    Expand-ReviewedRuntimeArchive $lock $archive $runtimeStage
  }
  foreach ($archive in Get-ChildItem -LiteralPath $stage -File -Filter '*.zip') { Remove-Item -LiteralPath $archive.FullName -Force }
  Move-Item -LiteralPath $stage -Destination $destination
  Write-Output "Fetched and verified pinned runtimes: $destination"
} finally {
  $safe = [IO.Path]::GetFullPath($stage)
  $prefix = [IO.Path]::GetFullPath((Join-Path $parent '.routedeck-runtime-fetch-'))
  if ([IO.Directory]::Exists($safe) -and $safe.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $safe -Recurse -Force }
}
