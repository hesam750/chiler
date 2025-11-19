# Remote On/Off Control Script
# برای کنترل مستقیم دستگاه از طریق RemoteOnOff

param(
  [string]$DeviceHost = '169.254.61.68',
  [string]$Action = ''
)

$ErrorActionPreference = 'Stop'
$base = "http://$DeviceHost/commissioning"

function MakeUri([string]$path, [string]$qs){ $u = "$base/$path"; if($qs){ $u += ('?' + $qs) }; return $u }
function TryPostForm([string]$path, [string]$body){
  $url = MakeUri $path ''
  try { return (& curl.exe -s -X POST $url -H 'Content-Type: application/x-www-form-urlencoded' --data $body) | Out-String } catch { return $_.Exception.Message }
}
function TryGet([string]$path, [string]$qs){
  $url = MakeUri $path $qs
  try { return Invoke-WebRequest -UseBasicParsing -Method Get -Uri $url -TimeoutSec 10 } catch { return $_.Exception.Message }
}
function Show([string]$title, $resp){ if($resp -is [string]){ Write-Host ("{0} -> {1}" -f $title, $resp) } else { Write-Host ("{0} -> Status={1}" -f $title, $resp.StatusCode) } }

function WriteByName([string]$name, [string]$value){
  $n = [System.Uri]::EscapeDataString($name)
  $v = [System.Uri]::EscapeDataString($value)
  Show ('GET var=' + $name + ' val=' + $value) (TryGet 'setvar.csv' ('var=' + $n + '&val=' + $v))
  Show ('POST var=' + $name + ' val=' + $value) (TryPostForm 'setvar.csv' ('var=' + $n + '&val=' + $v))
}

function Set-RemoteOnOff {
    param($value)
    Write-Host ("Setting RemoteOnOff to $value")
    WriteByName "RemoteOnOff" $value
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
    Start-Sleep -Milliseconds 500
}

function Get-DeviceStatus {
    $resp = TryGet 'getvar.csv' 'id=5541'
    if($resp -is [string]){ Write-Host ("READ CurrUnitStatus => " + $resp.Trim()) }
    else { Write-Host ("READ CurrUnitStatus => " + ($resp.Content).Trim()) }
    
    $resp2 = TryGet 'getvar.csv' 'id=5539'
    if($resp2 -is [string]){ Write-Host ("READ CurrRoomTempSetP_Val => " + $resp2.Trim()) }
    else { Write-Host ("READ CurrRoomTempSetP_Val => " + ($resp2.Content).Trim()) }
}

# نمایش وضعیت فعلی
Write-Host "=== Current Device Status ==="
Get-DeviceStatus

# کنترل RemoteOnOff
if ($Action -eq "on") {
    Write-Host "=== Turning Device ON ==="
    Set-RemoteOnOff 1
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ==="
    Get-DeviceStatus
} elseif ($Action -eq "off") {
    Write-Host "=== Turning Device OFF ==="
    Set-RemoteOnOff 0
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ==="
    Get-DeviceStatus
} else {
    Write-Host "Usage: .\remote_on_off_control.ps1 [on|off]"
    Write-Host "   on  - Turn device ON via RemoteOnOff"
    Write-Host "   off - Turn device OFF via RemoteOnOff"
}