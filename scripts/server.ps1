param([int]$Port = 8010, [string]$Root = ".")

Add-Type -AssemblyName System.Net
$listener = New-Object System.Net.HttpListener
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "Serving $Root at $prefix"

function Get-ContentType($path) {
  if ($path -like "*.html") { return "text/html" }
  elseif ($path -like "*.css") { return "text/css" }
  elseif ($path -like "*.js") { return "application/javascript" }
  elseif ($path -like "*.json") { return "application/json" }
  elseif ($path -like "*.png") { return "image/png" }
  elseif ($path -like "*.svg") { return "image/svg+xml" }
  elseif ($path -like "*.jpg" -or $path -like "*.jpeg") { return "image/jpeg" }
  else { return "application/octet-stream" }
}

while ($true) {
  $context = $listener.GetContext()
  $req = $context.Request
  $res = $context.Response
  try {
    $localPath = $req.Url.AbsolutePath.TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($localPath)) { $localPath = "index.html" }
    $fsPath = [System.IO.Path]::Combine($Root, $localPath)
    if (-not (Test-Path $fsPath)) {
      $res.StatusCode = 404
      $bytes = [System.Text.Encoding]::UTF8.GetBytes("Not Found: $localPath")
      $res.OutputStream.Write($bytes,0,$bytes.Length)
      $res.Close()
      continue
    }
    $bytes = [System.IO.File]::ReadAllBytes($fsPath)
    $res.ContentType = Get-ContentType $fsPath
    $res.ContentLength64 = $bytes.Length
    $res.OutputStream.Write($bytes, 0, $bytes.Length)
  }
  catch {
    $res.StatusCode = 500
    $err = [System.Text.Encoding]::UTF8.GetBytes("Server error: " + $_.Exception.Message)
    $res.OutputStream.Write($err, 0, $err.Length)
  }
  finally { $res.Close() }
}