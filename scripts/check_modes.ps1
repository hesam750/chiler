# Simple Mode Check Script
# Check device mode status

$DeviceHost = '169.254.61.68'
$base = "http://$DeviceHost/commissioning"

function Get-Var {
    param([string]$name, [int]$id)
    
    if ($id) {
        $url = "$base/getvar.csv?id=$id"
    } else {
        $encodedName = [System.Uri]::EscapeDataString($name)
        $url = "$base/getvar.csv?var=$encodedName"
    }
    
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
        $content = $response.Content.Trim()
        
        if ($content -match 'name,id,desc,type,access,val') {
            if ($content -match '\n(.+)$') {
                $lastLine = $matches[1]
                if ($lastLine -match '"([^"]+)"') {
                    return $matches[1]
                }
            }
        }
        return $content
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

Write-Host "=== Device Mode Status ===" -ForegroundColor Cyan
Write-Host "Device: $DeviceHost" -ForegroundColor Yellow
Write-Host ""

# Check main mode variables
$vars = @(
    @{Name = 'SystemStatus.Man'; ID = 9375; Desc = 'Manual mode (0=Off,1=Economy,2=PreComfort,3=Comfort)'},
    @{Name = 'SystemStatus.ManAct'; ID = 9376; Desc = 'Manual control active'},
    @{Name = 'UnitMode'; Desc = 'Unit mode'},
    @{Name = 'UnitOnOff'; Desc = 'Unit power status'},
    @{Name = 'KeybOnOff'; ID = 6897; Desc = 'Keyboard status'},
    @{Name = 'RemoteOnOff'; Desc = 'Remote control status'},
    @{Name = 'CurrUnitStatus'; ID = 5541; Desc = 'Current unit status'}
)

foreach ($var in $vars) {
    if ($var.ID) {
        $value = Get-Var -id $var.ID
    } else {
        $value = Get-Var -name $var.Name
    }
    
    $color = if ($value -match 'ERROR') { 'Red' } elseif ($value -eq '0') { 'Red' } elseif ($value -eq '1') { 'Green' } else { 'Yellow' }
    
    Write-Host "$($var.Name): " -NoNewline
    Write-Host $value -ForegroundColor $color
    Write-Host "  $($var.Desc)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "=== Instructions ===" -ForegroundColor Magenta
Write-Host "To change mode:" -ForegroundColor White
Write-Host "1. First set SystemStatus.ManAct to 1" -ForegroundColor Yellow
Write-Host "2. Then set SystemStatus.Man to desired value:" -ForegroundColor Yellow
Write-Host "   - 0 = Off" -ForegroundColor Red
Write-Host "   - 1 = Economy" -ForegroundColor Green  
Write-Host "   - 2 = PreComfort" -ForegroundColor Cyan
Write-Host "   - 3 = Comfort" -ForegroundColor Blue
Write-Host "3. Set UnitOnOff to 1" -ForegroundColor Yellow