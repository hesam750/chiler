# Unified Power Control Script
# کنترل یکپارچه روشن/خاموش برای دکمه‌های مختلف

param(
  [Parameter(Mandatory=$false)]
  [ValidateSet('on', 'off')]
  [string]$Action,
  
  [Parameter(Mandatory=$false)]
  [ValidateSet('UnitOnOff', 'RemoteOnOff')]
  [string]$ControlType = 'UnitOnOff',
  
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

function Set-PowerControl {
    param($value, $controlType)
    
    Write-Host ("Setting {0} to {1}" -f $controlType, $value) -ForegroundColor Yellow
    
    # ارسال درخواست تنظیم مقدار
    $response = TryPostForm 'setvar.csv' ("var=$controlType&val=$value")
    Show ("POST $controlType=$value") $response
    
    # ذخیره تغییرات
    $saveResponse = TryPostForm 'setvar.csv' 'id=8376&value=1'
    Show 'POST SaveData=1' $saveResponse
    
    Start-Sleep -Milliseconds 500
}

function Get-DeviceStatus {
    Write-Host "=== Current Device Status ===" -ForegroundColor Cyan
    
    # وضعیت دستگاه
    $resp = TryGet 'getvar.csv' 'id=5541'
    if($resp -is [string]){ 
        Write-Host ("CurrUnitStatus -> " + $resp.Trim()) -ForegroundColor Red
    } else { 
        Write-Host ("CurrUnitStatus -> " + ($resp.Content).Trim()) -ForegroundColor Green
    }
    
    # دمای تنظیم شده
    $resp2 = TryGet 'getvar.csv' 'id=5539'
    if($resp2 -is [string]){ 
        Write-Host ("CurrRoomTempSetP_Val -> " + $resp2.Trim()) -ForegroundColor Red
    } else { 
        Write-Host ("CurrRoomTempSetP_Val -> " + ($resp2.Content).Trim()) -ForegroundColor Green
    }
}

# نمایش وضعیت فعلی
Get-DeviceStatus

# کنترل قدرت
if ($Action -eq "on") {
    Write-Host "=== Turning Device ON via $ControlType ===" -ForegroundColor Green
    Set-PowerControl 1 $ControlType
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ===" -ForegroundColor Cyan
    Get-DeviceStatus
    
} elseif ($Action -eq "off") {
    Write-Host "=== Turning Device OFF via $ControlType ===" -ForegroundColor Yellow
    Set-PowerControl 0 $ControlType
    Start-Sleep -Seconds 2
    Write-Host "=== New Device Status ===" -ForegroundColor Cyan
    Get-DeviceStatus
    
} else {
    Write-Host "Usage: .\unified_power_control.ps1 -Action [on|off] [-ControlType UnitOnOff|RemoteOnOff]" -ForegroundColor White
    Write-Host "   -Action on     - Turn device ON" -ForegroundColor Green
    Write-Host "   -Action off    - Turn device OFF" -ForegroundColor Yellow
    Write-Host "   -ControlType (optional):" -ForegroundColor White
    Write-Host "      UnitOnOff    - کنترل از طریق UnitOnOff (پیش‌فرض)" -ForegroundColor Gray
    Write-Host "      RemoteOnOff  - کنترل از طریق RemoteOnOff" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "   .\unified_power_control.ps1 -Action on" -ForegroundColor Gray
    Write-Host "   .\unified_power_control.ps1 -Action off -ControlType UnitOnOff" -ForegroundColor Gray
    Write-Host "   .\unified_power_control.ps1 -Action on -ControlType RemoteOnOff" -ForegroundColor Gray
}