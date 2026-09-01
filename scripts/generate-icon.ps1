Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$repoRoot = Split-Path -Parent $PSScriptRoot
$iconDirectory = Join-Path $repoRoot "src-tauri\icons"
$pngPath = Join-Path $iconDirectory "icon.png"
$icoPath = Join-Path $iconDirectory "icon.ico"

New-Item -ItemType Directory -Force -Path $iconDirectory | Out-Null

$size = 256
$bitmap = [System.Drawing.Bitmap]::new(
    $size,
    $size,
    [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::FromArgb(255, 13, 15, 14))

$accent = [System.Drawing.Color]::FromArgb(255, 185, 239, 82)
$muted = [System.Drawing.Color]::FromArgb(255, 73, 82, 72)
$routePen = [System.Drawing.Pen]::new($accent, 22)
$routePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$routePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$routePen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$mutedPen = [System.Drawing.Pen]::new($muted, 8)
$mutedPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$mutedPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$nodeBrush = [System.Drawing.SolidBrush]::new($accent)

$graphics.DrawEllipse($mutedPen, 39, 39, 178, 178)
$route = [System.Drawing.Drawing2D.GraphicsPath]::new()
$route.StartFigure()
$route.AddBezier(70, 69, 70, 134, 105, 124, 128, 128)
$route.AddBezier(151, 132, 186, 122, 186, 187, 186, 187)
$graphics.DrawPath($routePen, $route)
$graphics.FillEllipse($nodeBrush, 55, 54, 30, 30)
$graphics.FillEllipse($nodeBrush, 171, 172, 30, 30)

$pngStream = [System.IO.MemoryStream]::new()
$bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngStream.ToArray()
[System.IO.File]::WriteAllBytes($pngPath, $pngBytes)

$icoStream = [System.IO.File]::Create($icoPath)
$writer = [System.IO.BinaryWriter]::new($icoStream)
$writer.Write([uint16]0)
$writer.Write([uint16]1)
$writer.Write([uint16]1)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([byte]0)
$writer.Write([uint16]1)
$writer.Write([uint16]32)
$writer.Write([uint32]$pngBytes.Length)
$writer.Write([uint32]22)
$writer.Write($pngBytes)
$writer.Flush()

$writer.Dispose()
$icoStream.Dispose()
$pngStream.Dispose()
$route.Dispose()
$nodeBrush.Dispose()
$mutedPen.Dispose()
$routePen.Dispose()
$graphics.Dispose()
$bitmap.Dispose()

Write-Output "Generated $pngPath and $icoPath"
