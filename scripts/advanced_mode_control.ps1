# Advanced Mode Control Script
# کنترل پیشرفته حالت‌های دستگاه با پشتیبانی از تمام گزینه‌ها
# Created with ❤️ for precise HVAC control

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('comfort', 'economy', 'precomfort', 'stop', 'off', 'auto', 'status')]
    [string]$Mode,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(16, 30)]
    [double]$Temperature,
    
    [string]$DeviceHost = '169.254.61.68',
    
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'
$base = "http://$DeviceHost/commissioning"

# رنگ‌های زیبا برای خروجی
$colors = @{
    success = 'Green'
    error = 'Red'
    warning = 'Yellow'
    info = 'Cyan'
    debug = 'Gray'
    title = 'Magenta'
}

function Write-Color {
    param([string]$message, [string]$color = 'White')
    Write-Host $message -ForegroundColor $color
}

function Write-Title {
    param([string]$title)
    Write-Color "`n=== $title ===" $colors.title
}

function MakeUri {
    param([string]$path, [string]$qs)
    $u = "$base/$path"
    if($qs) { $u += ('?' + $qs) }
    return $u
}

function Invoke-SafeWebRequest {
    param([string]$url, [string]$method = 'Get', [string]$body)
    
    try {
        if ($method -eq 'Post') {
            $result = Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing
        } else {
            $result = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        }
        
        return @{
            Success = $true
            StatusCode = $result.StatusCode
            Content = $result.Content.Trim()
            Raw = $result
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            StatusCode = 0
        }
    }
}

function Get-Variable {
    param([string]$name, [int]$id)
    
    if ($id) {
        $url = MakeUri 'getvar.csv' "id=$id"
        $result = Invoke-SafeWebRequest $url
    } else {
        $encodedName = [System.Uri]::EscapeDataString($name)
        $url = MakeUri 'getvar.csv' "var=$encodedName"
        $result = Invoke-SafeWebRequest $url
    }
    
    if ($result.Success) {
        if ($Verbose) {
            Write-Color "GET $name -> $($result.Content)" $colors.success
        }
        return $result.Content
    } else {
        Write-Color "ERROR: Failed to get $name - $($result.Error)" $colors.error
        return $null
    }
}

function Set-Variable {
    param([string]$name, [string]$value, [int]$id)
    
    if ($id) {
        $url = MakeUri 'setvar.csv' "id=$id&value=$value"
        $result = Invoke-SafeWebRequest $url 'Post'
    } else {
        $encodedName = [System.Uri]::EscapeDataString($name)
        $encodedValue = [System.Uri]::EscapeDataString($value)
        $url = MakeUri 'setvar.csv' "var=$encodedName&val=$encodedValue"
        $result = Invoke-SafeWebRequest $url 'Post'
    }
    
    if ($result.Success) {
        Write-Color "SET $name = $value -> Success" $colors.success
        return $true
    } else {
        Write-Color "ERROR: Failed to set $name = $value" $colors.error
        return $false
    }
}

function Save-Configuration {
    $result = Set-Variable -id 8376 -value '1'  # SaveData
    Start-Sleep -Milliseconds 500
    return $result
}

function Get-DeviceStatus {
    Write-Title "وضعیت فعلی دستگاه"
    
    $statusVars = @(
        @{Name = 'CurrUnitStatus'; ID = 5541},
        @{Name = 'CurrRoomTempSetP_Val'; ID = 5539},
        @{Name = 'SystemStatus.Man'; ID = 9375},
        @{Name = 'SystemStatus.ManAct'; ID = 9376},
        @{Name = 'KeybOnOff'; ID = 6897},
        @{Name = 'UnitOnOff'},
        @{Name = 'RemoteOnOff'},
        @{Name = 'UnitMode'}
    )
    
    $results = @{}
    foreach ($var in $statusVars) {
        if ($var.ID) {
            $value = Get-Variable -name $var.Name -id $var.ID
        } else {
            $value = Get-Variable -name $var.Name
        }
        $results[$var.Name] = $value
    }
    
    Write-Color "`n📊 گزارش وضعیت دستگاه:" $colors.info
    Write-Color "----------------------------" $colors.info
    Write-Color "وضعیت واحد: $($results['CurrUnitStatus'])" $(if($results['CurrUnitStatus'] -eq '0') {$colors.error} else {$colors.success})
    Write-Color "دمای تنظیم شده: $($results['CurrRoomTempSetP_Val'])°C" $colors.success
    Write-Color "حالت دستی: $($results['SystemStatus.Man']) (1=Economy, 2=Pre-Comfort, 3=Comfort)" $colors.info
    Write-Color "فعالیت دستی: $($results['SystemStatus.ManAct'])" $colors.info
    Write-Color "صفحه کلید: $($results['KeybOnOff'])" $colors.info
    Write-Color "واحد روشن/خاموش: $($results['UnitOnOff'])" $colors.info
    Write-Color "ریموت: $($results['RemoteOnOff'])" $colors.info
    Write-Color "حالت واحد: $($results['UnitMode'])" $colors.info
    
    return $results
}

function Set-ComfortMode {
    param([double]$temp)
    
    Write-Title "تنظیم حالت Comfort"
    
    # فعال کردن دستی
    Set-Variable -name 'SystemStatus.ManAct' -value '1' | Out-Null
    Set-Variable -name 'SystemStatus.Man' -value '3' | Out-Null  # Comfort
    
    # روشن کردن دستگاه
    Set-Variable -name 'KeybOnOff' -value '1' | Out-Null
    Set-Variable -name 'UnitOnOff' -value '1' | Out-Null
    Set-Variable -name 'RemoteOnOff' -value '1' | Out-Null
    
    # تنظیم منبع دستی
    Set-Variable -name 'UnitSetP.RoomTempSetP.Source' -value '1' | Out-Null
    Set-Variable -name 'UnitSetP.RoomTempSetP.ManAct' -value '1' | Out-Null
    
    # تنظیم دمای Comfort
    if ($temp) {
        $tempStr = $temp.ToString("0.00").Replace('.', ',')
        Set-Variable -name 'UnitSetP.RoomTempSetP.Comfort' -value $tempStr | Out-Null
        Set-Variable -name 'UnitSetP.RoomTempSetP.Man' -value $tempStr | Out-Null
        Write-Color "🌡️  دمای Comfort تنظیم شد به: $tempStr°C" $colors.success
    }
    
    # تنظیم حالت UnitMode
    Set-Variable -name 'UnitMode' -value 'comfort' | Out-Null
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

function Set-EconomyMode {
    param([double]$temp)
    
    Write-Title "تنظیم حالت Economy"
    
    Set-Variable -name 'SystemStatus.ManAct' -value '1' | Out-Null
    Set-Variable -name 'SystemStatus.Man' -value '1' | Out-Null  # Economy
    
    if ($temp) {
        $tempStr = $temp.ToString("0.00").Replace('.', ',')
        Set-Variable -name 'UnitSetP.RoomTempSetP.Economy' -value $tempStr | Out-Null
        Set-Variable -name 'UnitSetP.RoomTempSetP.Man' -value $tempStr | Out-Null
        Write-Color "🌡️  دمای Economy تنظیم شد به: $tempStr°C" $colors.success
    }
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

function Set-PreComfortMode {
    param([double]$temp)
    
    Write-Title "تنظیم حالت Pre-Comfort"
    
    Set-Variable -name 'SystemStatus.ManAct' -value '1' | Out-Null
    Set-Variable -name 'SystemStatus.Man' -value '2' | Out-Null  # Pre-Comfort
    
    if ($temp) {
        $tempStr = $temp.ToString("0.00").Replace('.', ',')
        Set-Variable -name 'UnitSetP.RoomTempSetP.PreComfort' -value $tempStr | Out-Null
        Set-Variable -name 'UnitSetP.RoomTempSetP.Man' -value $tempStr | Out-Null
        Write-Color "🌡️  دمای Pre-Comfort تنظیم شد به: $tempStr°C" $colors.success
    }
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

function Set-StopMode {
    Write-Title "تنظیم حالت Stop"
    
    Set-Variable -name 'UnitMode' -value 'stop' | Out-Null
    Set-Variable -name 'UnitOnOff' -value '0' | Out-Null
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

function Set-OffMode {
    Write-Title "تنظیم حالت Off"
    
    Set-Variable -name 'SystemStatus.ManAct' -value '1' | Out-Null
    Set-Variable -name 'SystemStatus.Man' -value '0' | Out-Null  # Off
    Set-Variable -name 'KeybOnOff' -value '0' | Out-Null
    Set-Variable -name 'UnitOnOff' -value '0' | Out-Null
    Set-Variable -name 'RemoteOnOff' -value '0' | Out-Null
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

function Set-AutoMode {
    Write-Title "تنظیم حالت Auto"
    
    # غیرفعال کردن کنترل دستی
    Set-Variable -name 'SystemStatus.ManAct' -value '0' | Out-Null
    Set-Variable -name 'UnitSetP.RoomTempSetP.ManAct' -value '0' | Out-Null
    
    # فعال کردن schedulerها
    Set-Variable -name 'Scheduler_OnOffUnit.Scheduler_1.Today.Enabled' -value '1' | Out-Null
    
    Save-Configuration | Out-Null
    Start-Sleep -Seconds 2
}

# نمایش بنر زیبا
Write-Color "`n🎯 ADVANCED MODE CONTROL - CAREL HVAC SYSTEM" $colors.title
Write-Color "🔧 کنترل پیشرفته حالت‌های دستگاه" $colors.info
Write-Color "📡 Device: $DeviceHost" $colors.debug
Write-Color "⏰ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $colors.debug

# اجرای دستور اصلی
switch ($Mode) {
    'status' {
        Get-DeviceStatus
    }
    'comfort' {
        Set-ComfortMode -temp $Temperature
        Get-DeviceStatus
    }
    'economy' {
        Set-EconomyMode -temp $Temperature
        Get-DeviceStatus
    }
    'precomfort' {
        Set-PreComfortMode -temp $Temperature
        Get-DeviceStatus
    }
    'stop' {
        Set-StopMode
        Get-DeviceStatus
    }
    'off' {
        Set-OffMode
        Get-DeviceStatus
    }
    'auto' {
        Set-AutoMode
        Get-DeviceStatus
    }
}

Write-Color "`n✅ عملیات تکمیل شد!" $colors.success
Write-Color "برای اطلاعات بیشتر: .\advanced_mode_control.ps1 -Mode status" $colors.info