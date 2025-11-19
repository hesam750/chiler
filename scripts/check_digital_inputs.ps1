# اسکریپت بررسی وضعیت ورودی‌های دیجیتال
$DeviceIP = "169.254.61.68"

Write-Host "بررسی وضعیت ورودی‌های دیجیتال دستگاه..." -ForegroundColor Green
Write-Host "IP دستگاه: $DeviceIP" -ForegroundColor Yellow
Write-Host ""

# بررسی ورودی‌های دیجیتال اصلی
for ($i = 1; $i -le 10; $i++) {
    $var = "DI$i"
    try {
        $url = "http://$DeviceIP/cgi-bin/readvar.cgi?var=$var"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        
        if ($response.StatusCode -eq 200) {
            $value = $response.Content.Trim()
            Write-Host "$var = $value" -ForegroundColor $(if ($value -eq "1") { "Red" } else { "Green" })
        }
    }
    catch {
        Write-Host "$var = خطا در خواندن" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "اگر DIx = 1 باشد، ورودی دیجیتال فعال است و دستگاه را خاموش می‌کند" -ForegroundColor Yellow