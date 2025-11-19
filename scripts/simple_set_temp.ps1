param(
    [Parameter(Mandatory=$true)]
    [double]$Temperature,
    [string]$DeviceIP = "169.254.61.68"
)

# URL برای تنظیم دما
$setUrl = "http://$DeviceIP/commissioning/setvar.csv?UnitSetP.RoomTempSetP.Comfort=$Temperature"

# URL برای خواندن دما
$readUrl = "http://$DeviceIP/commissioning/getvar.csv?UnitSetP.RoomTempSetP.Comfort"

Write-Host "Setting Comfort temperature to $Temperature°C..."

# ارسال درخواست برای تنظیم دما
try {
    $response = Invoke-WebRequest -Uri $setUrl -Method Get -ErrorAction Stop
    Write-Host "SET Response: $($response.StatusCode)"
    Write-Host "SET Content: $($response.Content)"
} catch {
    Write-Host "SET Error: $($_.Exception.Message)"
}

# کمی تأخیر برای اعمال تغییرات
Start-Sleep -Seconds 2

# خواندن دما برای تأیید تغییر
try {
    $response = Invoke-WebRequest -Uri $readUrl -Method Get -ErrorAction Stop
    Write-Host "READ Response: $($response.StatusCode)"
    Write-Host "READ Content: $($response.Content)"
    
    # تجزیه مقدار دما از پاسخ CSV
    $lines = $response.Content -split "`r`n"
    foreach ($line in $lines) {
        if ($line -match "UnitSetP\.RoomTempSetP\.Comfort") {
            $fields = $line -split ","
            if ($fields.Count -ge 6) {
                $currentTemp = $fields[5]
                Write-Host "Current Comfort Temperature: $currentTemp°C"
                break
            }
        }
    }
} catch {
    Write-Host "READ Error: $($_.Exception.Message)"
}