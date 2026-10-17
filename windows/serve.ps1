# Tiny private web server for DocVault on Windows.
# It listens on "localhost" only, so no other computer or phone can reach it, and it
# only serves the app's own files. Your documents never pass through it: they stay
# encrypted inside the browser's storage.
param([string]$Root = (Join-Path $PSScriptRoot '..'), [int]$Port = 8765)

$Root = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
$types = @{
  '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'
  '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.webmanifest' = 'application/manifest+json'
}
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
try { $listener.Start() } catch { Write-Host "Doc Vault server is already running (port $Port)."; exit }
Write-Host "Vedant's Doc Vault is available at http://localhost:$Port/  (only on this PC)"
Write-Host "After installing it from Edge you can close this window."

while ($listener.IsListening) {
  $ctx = $listener.GetContext()
  try {
    $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath.TrimStart('/'))
    if ($rel -eq '') { $rel = 'index.html' }
    $file = [IO.Path]::GetFullPath((Join-Path $Root $rel))
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($file.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) -and $types.ContainsKey($ext) -and (Test-Path $file -PathType Leaf)) {
      $bytes = [IO.File]::ReadAllBytes($file)
      $ctx.Response.ContentType = $types[$ext]
      $ctx.Response.Headers.Add('Cache-Control', 'no-cache')
      $ctx.Response.Headers.Add('X-Content-Type-Options', 'nosniff')
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } else {
      $ctx.Response.StatusCode = 404
    }
  } catch {
    $ctx.Response.StatusCode = 500
  } finally {
    $ctx.Response.Close()
  }
}
