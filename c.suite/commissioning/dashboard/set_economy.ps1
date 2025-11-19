param(
  [string]$Device = 'http://169.254.61.68',
  [string]$ProxyHost = 'localhost',
  [int]$ProxyPort = 8005,
  [string]$EconomyValue = '25.0',
  [switch]$RevertComfort
)

$ErrorActionPreference = 'Stop'

function MakeProxyUrl([string]$pathWithQuery){
  $proxy = "http://{0}:{1}/proxy?url=" -f $ProxyHost, $ProxyPort
  return $proxy + [System.Uri]::EscapeDataString(($Device.TrimEnd('/')) + '/' + $pathWithQuery)
}

function PostVar([int]$id, [string]$value){
  $u = MakeProxyUrl 'commissioning/setvar.csv'
  try {
    $resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $u -Body @{ id = $id; value = $value } -TimeoutSec 12
    Write-Host ("POST id={0} value={1} -> Status={2}" -f $id, $value, $resp.StatusCode)
  } catch {
    Write-Host ("POST id={0} value={1} -> ERR {2}" -f $id, $value, $_.Exception.Message)
  }
}

function ReadVar([int]$id, [string]$name){
  $u = MakeProxyUrl ('commissioning/getvar.csv?id=' + $id)
  try {
    $content = (Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 12).Content
    Write-Host ("READ {0} ({1}) => {2}" -f $name, $id, $content.Trim())
  } catch {
    Write-Host ("READ {0} ({1}) -> ERR {2}" -f $name, $id, $_.Exception.Message)
  }
}

Write-Host 'Unlock manufacturer'
PostVar -id 8098 -value '4189'

Write-Host 'Switch mode to ECONOMY (1)'
PostVar -id 8434 -value '1'
PostVar -id 8436 -value '1'

Start-Sleep -Milliseconds 600

Write-Host ('Write Economy=' + $EconomyValue)
PostVar -id 9425 -value $EconomyValue
$valueComma = $EconomyValue -replace '\.',','
PostVar -id 9425 -value $valueComma

Write-Host 'Save data'
PostVar -id 8376 -value '1'

Start-Sleep -Milliseconds 800

ReadVar -id 9425 -name 'UnitSetP.RoomTempSetP.Economy'
ReadVar -id 5539 -name 'CurrRoomTempSetP_Val'
ReadVar -id 9424 -name 'UnitSetP.RoomTempSetP.Comfort'

if($RevertComfort){
  Write-Host 'Restore mode to COMFORT (3)'
  PostVar -id 8434 -value '3'
  PostVar -id 8436 -value '3'
  PostVar -id 8376 -value '1'
  Start-Sleep -Milliseconds 600
  ReadVar -id 5539 -name 'CurrRoomTempSetP_Val'
  ReadVar -id 9424 -name 'UnitSetP.RoomTempSetP.Comfort'
}

Write-Host 'END set_economy'