# Reset digital input status for PGD
$DeviceIP = "169.254.61.68"

Write-Host "Resetting digital input status for PGD..." -ForegroundColor Green
Write-Host "Target: Disable digital input that turned off the device" -ForegroundColor Yellow
Write-Host ""

# 1. First check current status
Write-Host "Current device status:" -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://$DeviceIP/cgi-bin/readvar.cgi?var=CurrUnitStatus" -UseBasicParsing
    $status = $response.Content.Trim()
    Write-Host "CurrUnitStatus = $status" -ForegroundColor $(if ($status -eq "0") { "Red" } else { "Green" })
} catch {
    Write-Host "Error reading device status" -ForegroundColor Red
}

# 2. Try to unlock the system
Write-Host ""
Write-Host "Attempting to unlock system..." -ForegroundColor Cyan

try {
    # Enable manual mode
    $response = Invoke-WebRequest -Uri "http://$DeviceIP/cgi-bin/writevar.cgi?var=SystemStatus.Man&value=1" -UseBasicParsing
    Write-Host "SystemStatus.Man = 1 (Manual mode enabled)" -ForegroundColor Green
    
    # Enable system output
    $response = Invoke-WebRequest -Uri "http://$DeviceIP/cgi-bin/writevar.cgi?var=SystemStatus.Enabled&value=1" -UseBasicParsing
    Write-Host "SystemStatus.Enabled = 1 (System output enabled)" -ForegroundColor Green
    
    # Enable keyboard
    $response = Invoke-WebRequest -Uri "http://$DeviceIP/cgi-bin/writevar.cgi?var=KeybOnOff&value=1" -UseBasicParsing
    Write-Host "KeybOnOff = 1 (Keyboard enabled)" -ForegroundColor Green
    
} catch {
    Write-Host "Error setting system variables" -ForegroundColor Red
}

# 3. Check status again
Write-Host ""
Write-Host "Checking status after configuration..." -ForegroundColor Cyan
Start-Sleep -Seconds 2

try {
    $response = Invoke-WebRequest -Uri "http://$DeviceIP/cgi-bin/readvar.cgi?var=CurrUnitStatus" -UseBasicParsing
    $status = $response.Content.Trim()
    Write-Host "CurrUnitStatus = $status" -ForegroundColor $(if ($status -eq "0") { "Red" } else { "Green" })
    
    if ($status -eq "1") {
        Write-Host "✅ Device successfully turned on!" -ForegroundColor Green
    } else {
        Write-Host "❌ Device is still off. May require physical inspection." -ForegroundColor Red
        Write-Host "   - Check safety sensors" -ForegroundColor Yellow
        Write-Host "   - Check emergency stop button" -ForegroundColor Yellow
        Write-Host "   - Check digital input wiring" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error reading final status" -ForegroundColor Red
}

Write-Host ""
Write-Host "Digital input reset operation completed" -ForegroundColor Magenta