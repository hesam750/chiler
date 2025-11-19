param(
  [string]$DeviceHost = '169.254.61.68'
)

$ErrorActionPreference = 'Stop'

$base = "http://$DeviceHost/commissioning"

function MakeUri([string]$path, [string]$qs){ $u = "$base/$path"; if($qs){ $u += ('?' + $qs) }; return $u }
function TryPostForm([string]$path, $body){
  $url = MakeUri $path ''
  try {
    $pairs = @(); foreach($kv in $body.GetEnumerator()){ $pairs += ([System.Uri]::EscapeDataString($kv.Key) + '=' + [System.Uri]::EscapeDataString([string]$kv.Value)) }
    $data = ($pairs -join '&')
    return (& curl.exe -s -X POST $url -H 'Content-Type: application/x-www-form-urlencoded' --data $data) | Out-String
  } catch { return $_.Exception.Message }
}
function TryGet([string]$path, [string]$qs){
  $url = MakeUri $path $qs
  try { return Invoke-WebRequest -UseBasicParsing -Method Get -Uri $url -TimeoutSec 12 } catch { return $_.Exception.Message }
}
function Show([string]$title, $resp){ if($resp -is [string]){ Write-Host ("{0} -> {1}" -f $title, $resp) } else { Write-Host ("{0} -> Status={1}" -f $title, $resp.StatusCode) } }

function GetLines(){ $r = TryGet 'getvar.csv' ''; if($r -is [string]){ return ($r -split "`n") } return ($r.Content -split "`n") }

Write-Host '=== AGGRESSIVE POWER OFF ATTEMPT ==='

# Unlock manufacturer first
Show 'POST PwdManuf=4189' (TryPostForm 'setvar.csv' @{ id = 8098; value = '4189' })
Start-Sleep -Milliseconds 500

$lines = GetLines

# All possible power/control related variables to try
$powerCandidates = @(
  'UnitOnOff', 'OnOff', 'OnOffUnit', 'Power', 'Start', 'Enable', 'UnitEnable',
  'RemoteOnOff', 'RemoteOff', 'KeybOnOff', 'KeyboardOnOff', 'PanelOnOff',
  'SystemOnOff', 'MainOnOff', 'ControlOnOff', 'Operate', 'Operation',
  'Run', 'Running', 'Active', 'Status', 'State', 'Mode', 'Command'
)

# Try each candidate with value 0 (OFF)
foreach($name in $powerCandidates){
  Write-Host ("--- Trying: {0} = 0 ---" -f $name)
  
  # Try both GET and POST methods
  $encName = [System.Uri]::EscapeDataString($name)
  Show ("GET {0}=0" -f $name) (TryGet 'setvar.csv' ("var={0}&val=0" -f $encName))
  Start-Sleep -Milliseconds 300
  
  Show ("POST {0}=0" -f $name) (TryPostForm 'setvar.csv' @{ var = $name; value = '0' })
  Start-Sleep -Milliseconds 300
  
  # Save after each attempt
  Show 'POST SaveData=1' (TryPostForm 'setvar.csv' @{ id = 8376; value = '1' })
  Start-Sleep -Milliseconds 500
  
  # Check if device turned off
  $statusResp = TryGet 'getvar.csv' 'id=5541'
  if($statusResp -is [string]){ 
    Write-Host ("STATUS: {0}" -f $statusResp.Trim())
  } else { 
    Write-Host ("STATUS: {0}" -f ($statusResp.Content).Trim())
  }
  
  Write-Host ''
}

# Final status check
Write-Host '=== FINAL STATUS ==='
$finalStatus = TryGet 'getvar.csv' 'id=5541'
$finalTemp = TryGet 'getvar.csv' 'id=5539'

if($finalStatus -is [string]){ 
  Write-Host ("Final CurrUnitStatus: {0}" -f $finalStatus.Trim())
} else { 
  Write-Host ("Final CurrUnitStatus: {0}" -f ($finalStatus.Content).Trim())
}

if($finalTemp -is [string]){ 
  Write-Host ("Final CurrRoomTempSetP_Val: {0}" -f $finalTemp.Trim())
} else { 
  Write-Host ("Final CurrRoomTempSetP_Val: {0}" -f ($finalTemp.Content).Trim())
}

Write-Host '=== END ==='