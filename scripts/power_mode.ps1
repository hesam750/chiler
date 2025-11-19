param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("off","comfort")]
    [string]$Mode,
    [string]$DeviceHost = '169.254.61.68'
)

$ErrorActionPreference = 'Stop'
$base = "http://$DeviceHost/commissioning"

function TryGet([string]$path, [string]$qs){
    $url = "$base/$path"
    if($qs){ $url += ('?' + $qs) }
    try { return Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 } catch { return $_.Exception.Message }
}

function TryPostForm([string]$path, [string]$body){
    $url = "$base/$path"
    try { return (Invoke-WebRequest -Uri $url -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing) } catch { return $_.Exception.Message }
}

function Show([string]$title, $resp){
    if($resp -is [string]){ Write-Host ("{0} -> {1}" -f $title, $resp) -ForegroundColor Red }
    else { Write-Host ("{0} -> Status={1}" -f $title, $resp.StatusCode) -ForegroundColor Green }
}

function TrySetByName([string]$name, [string]$value){
    $n = [System.Uri]::EscapeDataString($name)
    $v = [System.Uri]::EscapeDataString($value)
    Show ('GET var=' + $name + ' value=' + $value) (TryGet 'setvar.csv' ('var=' + $n + '&value=' + $v))
    Show ('GET var=' + $name + ' val='   + $value) (TryGet 'setvar.csv' ('var=' + $n + '&val='   + $v))
    Show ('POST var=' + $name + ' val='  + $value) (TryPostForm 'setvar.csv' ('var=' + $n + '&val=' + $v))
}

function TrySetById([int]$id, [string]$value){
    $v = [System.Uri]::EscapeDataString($value)
    $qs1 = 'id=' + $id + '&value=' + $v
    $qs2 = 'id=' + $id + '&val=' + $v
    Show ('POST id=' + $id + ' value=' + $value) (TryPostForm 'setvar.csv' $qs1)
    Show ('POST id=' + $id + ' val=' + $value) (TryPostForm 'setvar.csv' $qs2)
}

function ReadById([int]$id){
    $r = TryGet 'getvar.csv' ('id=' + $id)
    if($r -is [string]){ return $r }
    return ($r.Content).Trim()
}

function ReadByName([string]$name){
    $n = [System.Uri]::EscapeDataString($name)
    $r = TryGet 'getvar.csv' ('var=' + $n)
    if($r -is [string]){ return $r }
    return ($r.Content).Trim()
}

Write-Host ("=== Applying mode: {0} ===" -f $Mode) -ForegroundColor Green

Write-Host 'Unlocking manufacturer (PwdManuf=4189)' -ForegroundColor DarkCyan
Show 'POST PwdManuf=4189' (TryPostForm 'setvar.csv' 'id=8098&value=4189')

if ($Mode -eq 'off') {
    Write-Host 'Turning device OFF (keyboard + unit + remote)' -ForegroundColor Red
    TrySetById 9376 '1'   # SystemStatus.ManAct
    TrySetById 9375 '0'   # SystemStatus.Man
    TrySetById 6897 '0'   # KeybOnOff
    TrySetByName 'UnitOnOff' '0'
    TrySetByName 'RemoteOnOff' '0'
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
} else {
    Write-Host 'Turning device ON (comfort with manual gating)' -ForegroundColor Cyan
    # Enable keyboard and system outputs
    TrySetById 6897 '1'   # KeybOnOff
    TrySetById 9373 '1'   # SystemStatus.Enabled
    
    # Try multiple power toggles
    TrySetByName 'UnitOnOff' '1'
    TrySetByName 'OnOffUnit' '1'
    TrySetByName 'RemoteOnOff' '1'

    # Ensure manual source and comfort selection
    TrySetByName 'UnitSetP.RoomTempSetP.Source' '1'
    TrySetByName 'UnitSetP.RoomTempSetP.ManAct' '1'
    TrySetById 9376 '1'   # SystemStatus.ManAct
    TrySetById 9375 '3'   # SystemStatus.Man -> Comfort

    # Optionally set UnitMode where supported
    TrySetByName 'UnitMode' 'comfort'

    # Persist changes
    Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')
}

Start-Sleep -Seconds 2

Write-Host '=== Device state after apply ===' -ForegroundColor Green
$s = ReadById 5541
Write-Host ('CurrUnitStatus => ' + $s) -ForegroundColor Yellow
$k = ReadById 6897
Write-Host ('KeybOnOff => ' + $k) -ForegroundColor Yellow
$u = ReadByName 'UnitOnOff'
Write-Host ('UnitOnOff => ' + $u) -ForegroundColor Yellow
$rm = ReadByName 'RemoteOnOff'
Write-Host ('RemoteOnOff => ' + $rm) -ForegroundColor Yellow
$sm = ReadByName 'SystemStatus.Man'
Write-Host ('SystemStatus.Man => ' + $sm) -ForegroundColor Yellow
$sa = ReadByName 'SystemStatus.ManAct'
Write-Host ('SystemStatus.ManAct => ' + $sa) -ForegroundColor Yellow
try { $um = ReadByName 'UnitMode'; Write-Host ('UnitMode => ' + $um) -ForegroundColor Yellow } catch {}