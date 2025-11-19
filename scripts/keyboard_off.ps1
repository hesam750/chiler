# Keyboard Off Control Script
# Sets device to off mode using keyboard control (KeybOnOff variable)
# This will trigger "off by keyboard" status

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("on", "off")]
    [string]$Action = "off",
    
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

# Control through keyboard action
if ($Action -eq "off") {
    Write-Host "=== Setting Device to Off via Keyboard ===" -ForegroundColor Yellow
    
    # Set KeybOnOff to 0 (off by keyboard)
    WriteByName 'KeybOnOff' '0'
    
    # Also set UnitOnOff to 0 for complete shutdown
    WriteByName 'UnitOnOff' '0'
    
    # Save configuration
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
    
    Write-Host "Device set to OFF mode via keyboard control" -ForegroundColor Red
    Write-Host "This should show 'off by keyboard' status" -ForegroundColor Red
}
else {
    Write-Host "=== Setting Device to On via Keyboard ===" -ForegroundColor Yellow
    
    # Set KeybOnOff to 1 (on by keyboard)
    WriteByName 'KeybOnOff' '1'
    
    # Also set UnitOnOff to 1 for complete startup
    WriteByName 'UnitOnOff' '1'
    
    # Save configuration
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
    
    Write-Host "Device set to ON mode via keyboard control" -ForegroundColor Green
}

# Show current status after changes
Write-Host "`n=== Status After Changes ===" -ForegroundColor Cyan
Get-DeviceStatus