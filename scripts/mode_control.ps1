# Mode Control Script
# Control device through UnitMode states (comfort/stop/off)

param(
  [Parameter(Mandatory=$false)]
  [ValidateSet('comfort', 'stop', 'off')]
  [string]$Mode,
  
  [string]$DeviceHost = '169.254.61.68'
)

$ErrorActionPreference = 'Stop'
$base = "http://$DeviceHost/commissioning"

function MakeUri([string]$path, [string]$qs){ 
    $u = "$base/$path"
    if($qs){ $u += ('?' + $qs) }
    return $u 
}

function TryPostForm([string]$path, [string]$body){
    $url = MakeUri $path ''
    try { 
        return (Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing).Content
    } catch { 
        return $_.Exception.Message 
    }
}

function TryGet([string]$path, [string]$qs){
    $url = MakeUri $path $qs
    try { 
        return Invoke-WebRequest -UseBasicParsing -Method Get -Uri $url -TimeoutSec 10 
    } catch { 
        return $_.Exception.Message 
    }
}

function Show([string]$title, $resp){ 
    if($resp -is [string]){ 
        Write-Host ("{0} -> {1}" -f $title, $resp) -ForegroundColor Red
    } else { 
        Write-Host ("{0} -> Status={1}" -f $title, $resp.StatusCode) -ForegroundColor Green
    } 
}

function WriteByName([string]$name, [string]$value){
    $n = [System.Uri]::EscapeDataString($name)
    $v = [System.Uri]::EscapeDataString($value)
    Show ('GET var=' + $name + ' val=' + $value) (TryGet 'setvar.csv' ('var=' + $n + '&val=' + $v))
    Show ('POST var=' + $name + ' val=' + $value) (TryPostForm 'setvar.csv' ('var=' + $n + '&val=' + $v))
}

function Get-DeviceStatus {
    Write-Host "=== Current Device Status ===" -ForegroundColor Cyan
    
    # Device status
    $resp = TryGet 'getvar.csv' 'id=5541'
    if($resp -is [string]){ 
        Write-Host ("CurrUnitStatus -> " + $resp.Trim()) -ForegroundColor Red
    } else { 
        Write-Host ("CurrUnitStatus -> " + ($resp.Content).Trim()) -ForegroundColor Green
    }
    
    # Set temperature
    $resp2 = TryGet 'getvar.csv' 'id=5539'
    if($resp2 -is [string]){ 
        Write-Host ("CurrRoomTempSetP_Val -> " + $resp2.Trim()) -ForegroundColor Red
    } else { 
        Write-Host ("CurrRoomTempSetP_Val -> " + ($resp2.Content).Trim()) -ForegroundColor Green
    }
}

# Show current status
Get-DeviceStatus

# Control through Mode
if ($Mode -eq "comfort") {
    Write-Host "=== Setting Device to COMFORT Mode (ON) ===" -ForegroundColor Green
    
    # First ensure device is on
    WriteByName 'UnitOnOff' '1'
    Start-Sleep -Milliseconds 500
    
    # Set comfort mode
    WriteByName 'UnitMode' 'comfort'
    
    # Save changes
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
    
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ===" -ForegroundColor Cyan
    Get-DeviceStatus
    
} elseif ($Mode -eq "stop" -or $Mode -eq "off") {
    Write-Host "=== Setting Device to $Mode Mode (OFF) ===" -ForegroundColor Yellow
    
    # Set stop mode
    WriteByName 'UnitMode' 'stop'
    
    # Also turn off the device
    WriteByName 'UnitOnOff' '0'
    
    # Save changes
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
    
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ===" -ForegroundColor Cyan
    Get-DeviceStatus
    
} else {
    Write-Host "Usage: .\mode_control.ps1 -Mode [comfort|stop|off]" -ForegroundColor White
    Write-Host "   -Mode comfort  - Set device to comfort mode (ON)" -ForegroundColor Green
    Write-Host "   -Mode stop     - Set device to stop mode (OFF)" -ForegroundColor Yellow
    Write-Host "   -Mode off      - Set device to off mode (OFF)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "   .\mode_control.ps1 -Mode comfort" -ForegroundColor Gray
    Write-Host "   .\mode_control.ps1 -Mode stop" -ForegroundColor Gray
    Write-Host "   .\mode_control.ps1 -Mode off" -ForegroundColor Gray
}