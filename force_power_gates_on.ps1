param(
  [string]$DeviceHost = '169.254.61.68',
  [string]$ProxyHost = 'localhost',
  [int]$ProxyPort = 8005
)

$ErrorActionPreference = 'Stop'

$base = "http://$DeviceHost/commissioning"

function MakeUri([string]$path, [string]$qs){ $u = "$base/$path"; if($qs){ $u += ('?' + $qs) }; return $u }

function TryPostForm([string]$path, [string]$body){
  $url = MakeUri $path ''
  try { $out = (& curl.exe -s -X POST $url -H 'Content-Type: application/x-www-form-urlencoded' --data $body) | Out-String; return $out } catch { return $_.Exception.Message }
}
function TryGet([string]$path, [string]$qs){
  $url = MakeUri $path $qs
  try { $resp = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $url -TimeoutSec 10; return $resp } catch { return $_.Exception.Message }
}

function Show([string]$title, $resp){
  if($resp -is [string]){ Write-Host ("{0} -> {1}" -f $title, $resp) }
  else{ Write-Host ("{0} -> Status={1}" -f $title, $resp.StatusCode) }
}

function ReadVar([int]$id, [string]$name){
  $resp = TryGet 'getvar.csv' ('id=' + $id)
  $content = ''
  if($resp -is [string]){ $content = $resp }
  else { $content = ($resp.Content).Trim() }
  Write-Host ("READ {0} ({1}) => {2}" -f $name, $id, $content)
}

Write-Host '=== BEGIN force_power_gates_on ==='
Write-Host 'Unlock manufacturer'
Show 'POST PwdManuf=4189' (TryPostForm 'setvar.csv' ('id=8098&value=4189'))

# Gates to force OFF (neutralize stops)
$zeroVars = @('RemoteOff','Emergency','Fire','GeneralStop')
# Gates to force ON (enable/run)
$oneVars = @('UnitEnable','MainEnable','RunEnable','StartStop','UnitOnOff','RemoteOnOff')

foreach($name in $zeroVars){
  $enc = [System.Uri]::EscapeDataString($name)
  Show ("GET var={0} val=0" -f $name) (TryGet 'setvar.csv' ('var=' + $enc + '&val=0'))
  Show ("POST var={0} val=0" -f $name) (TryPostForm 'setvar.csv' ('var=' + $enc + '&val=0'))
}

foreach($name in $oneVars){
  $enc = [System.Uri]::EscapeDataString($name)
  Show ("GET var={0} val=1" -f $name) (TryGet 'setvar.csv' ('var=' + $enc + '&val=1'))
  Show ("POST var={0} val=1" -f $name) (TryPostForm 'setvar.csv' ('var=' + $enc + '&val=1'))
}

Show 'POST SaveData=1' (TryPostForm 'setvar.csv' 'id=8376&value=1')

# Verify key readings
ReadVar 5541 'CurrUnitStatus'
ReadVar 5539 'CurrRoomTempSetP_Val'
ReadVar 9424 'UnitSetP.RoomTempSetP.Comfort'

Write-Host '=== END force_power_gates_on ==='