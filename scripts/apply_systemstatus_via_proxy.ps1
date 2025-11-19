param(
  [string]$DeviceHost = '169.254.61.68',
  [string]$ProxyHost = 'localhost',
  [int]$ProxyPort = 8006
)

$ErrorActionPreference = 'Stop'

function MakeProxyUrl([string]$innerUrl){
  return ("http://{0}:{1}/proxy?url={2}" -f $ProxyHost, $ProxyPort, [System.Uri]::EscapeDataString($innerUrl))
}

function ProxyGet([string]$innerUrl){
  $url = MakeProxyUrl $innerUrl
  try { return Invoke-WebRequest -UseBasicParsing -Method Get -Uri $url -TimeoutSec 10 } catch { return $_.Exception.Message }
}

Write-Host "=== Apply SystemStatus and Keyboard via Proxy CGI ===" -ForegroundColor Cyan

$w1 = ProxyGet ("http://{0}/cgi-bin/writevar.cgi?var=SystemStatus.Man&value=1" -f $DeviceHost)
$out1 = if($w1 -is [string]){ $w1 } else { $w1.StatusCode }
Write-Host ("WRITE SystemStatus.Man => {0}" -f $out1)

$w2 = ProxyGet ("http://{0}/cgi-bin/writevar.cgi?var=SystemStatus.Enabled&value=1" -f $DeviceHost)
$out2 = if($w2 -is [string]){ $w2 } else { $w2.StatusCode }
Write-Host ("WRITE SystemStatus.Enabled => {0}" -f $out2)

$w3 = ProxyGet ("http://{0}/cgi-bin/writevar.cgi?var=KeybOnOff&value=1" -f $DeviceHost)
$out3 = if($w3 -is [string]){ $w3 } else { $w3.StatusCode }
Write-Host ("WRITE KeybOnOff => {0}" -f $out3)

Start-Sleep -Milliseconds 500

$r1 = ProxyGet ("http://{0}/cgi-bin/readvar.cgi?var=CurrUnitStatus" -f $DeviceHost)
if($r1 -is [string]){ Write-Host ("READ CurrUnitStatus => " + $r1) }
else { Write-Host ("READ CurrUnitStatus => " + ($r1.Content).Trim()) }

$r2 = ProxyGet ("http://{0}/cgi-bin/readvar.cgi?var=KeybOnOff" -f $DeviceHost)
if($r2 -is [string]){ Write-Host ("READ KeybOnOff => " + $r2) }
else { Write-Host ("READ KeybOnOff => " + ($r2.Content).Trim()) }

Write-Host "=== Done ===" -ForegroundColor Green