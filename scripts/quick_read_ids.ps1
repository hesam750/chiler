param(
  [string]$Device = 'http://169.254.61.68'
)

$ErrorActionPreference = 'Stop'

function ReadId([int]$id){
  $url = ($Device.TrimEnd('/') + '/commissioning/getvar.csv?id=' + $id)
  try {
    $c = (Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 10).Content
    Write-Host $c.Trim()
  } catch {
    Write-Host ("READ ERR id=" + $id + " -> " + $_.Exception.Message)
  }
}

# Common gates and setpoints
$ids = @(8098, 8101, 8103, 6897, 9373, 9376, 9375, 9424, 9425, 9426, 5539, 5541)
foreach($i in $ids){ ReadId $i }