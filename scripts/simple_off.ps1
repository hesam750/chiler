# Simple Off Script
# تنظیم ساده حالت Off

param(
    [string]$DeviceHost = '169.254.61.68'
)

$base = "http://$DeviceHost/commissioning"

function Invoke-WebRequestSafe {
    param([string]$url)
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        Write-Host "SUCCESS: $url" -ForegroundColor Green
        return $response.Content.Trim()
    } catch {
        Write-Host "ERROR: $url - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

Write-Host "=== Setting Device to OFF Mode ===" -ForegroundColor Red

# خاموش کردن از طریق SystemStatus.Man
Invoke-WebRequestSafe "$base/setvar.csv?id=9376&value=1"  # SystemStatus.ManAct = 1
Invoke-WebRequestSafe "$base/setvar.csv?id=9375&value=0"  # SystemStatus.Man = 0 (Off)

# خاموش کردن صفحه کلید
Invoke-WebRequestSafe "$base/setvar.csv?id=6897&value=0"  # KeybOnOff = 0

# خاموش کردن واحد
Invoke-WebRequestSafe "$base/setvar.csv?var=UnitOnOff&val=0"

# خاموش کردن ریموت
Invoke-WebRequestSafe "$base/setvar.csv?var=RemoteOnOff&val=0"

# ذخیره تغییرات
Invoke-WebRequestSafe "$base/setvar.csv?id=8376&value=1"  # SaveData = 1

Write-Host "=== Checking Current Status ===" -ForegroundColor Cyan

# بررسی وضعیت فعلی
$status = Invoke-WebRequestSafe "$base/getvar.csv?id=5541"  # CurrUnitStatus
$keyboard = Invoke-WebRequestSafe "$base/getvar.csv?id=6897"  # KeybOnOff
$unit = Invoke-WebRequestSafe "$base/getvar.csv?var=UnitOnOff"

Write-Host "Current Unit Status: $status" -ForegroundColor $(if($status -eq '0') {'Green'} else {'Red'})
Write-Host "Keyboard Status: $keyboard" -ForegroundColor $(if($keyboard -eq '0') {'Green'} else {'Red'})
Write-Host "Unit On/Off: $unit" -ForegroundColor $(if($unit -eq '0') {'Green'} else {'Red'})

Write-Host "=== OFF Mode Applied Successfully ===" -ForegroundColor Green