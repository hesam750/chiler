param(
  [string]$Root = (Resolve-Path "."),
  [int]$Port = 8006
)

Add-Type -AssemblyName System.Net.HttpListener
$listener = New-Object System.Net.HttpListener
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "Serving $Root at $prefix"

while ($true) {
  try {
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $res = $ctx.Response
    $relPath = $req.Url.AbsolutePath.TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($relPath)) { $relPath = 'index.html' }
    $fsPath = Join-Path $Root $relPath
    if (-not (Test-Path $fsPath)) {
      $res.StatusCode = 404
      $bytesNF = [System.Text.Encoding]::UTF8.GetBytes("Not Found")
      $res.OutputStream.Write($bytesNF, 0, $bytesNF.Length)
      $res.Close()
      continue
    }
    $ext = [System.IO.Path]::GetExtension($fsPath).ToLower()
    $mime = switch ($ext) {
      '.html' { 'text/html; charset=utf-8' }
      '.css'  { 'text/css' }
      '.js'   { 'application/javascript' }
      '.png'  { 'image/png' }
      '.jpg'  { 'image/jpeg' }
      '.jpeg' { 'image/jpeg' }
      '.svg'  { 'image/svg+xml' }
      '.json' { 'application/json' }
      default { 'application/octet-stream' }
    }
    $bytes = [System.IO.File]::ReadAllBytes($fsPath)
    $res.ContentType = $mime
    $res.ContentLength64 = $bytes.Length
    $res.OutputStream.Write($bytes, 0, $bytes.Length)
    $res.Close()
  }
  catch {
    Write-Warning $_.Exception.Message
  }
}