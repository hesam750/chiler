param(
  [string]$Device = 'http://169.254.61.68',
  [double]$Value = 25.0
)

$ErrorActionPreference = 'Stop'

function ReadText([string]$url){ try { return (& curl.exe -s $url) | Out-String } catch { return '' } }
function FindIds([string]$text, [string[]]$names){ $map=@{}; foreach($n in $names){ $pat='"' + [regex]::Escape($n) + '",([0-9]+),'; $m=[regex]::Match($text,$pat); if($m.Success){ $map[$n] = [int]$m.Groups[1].Value } }; return $map }
function PostId([int]$id, [string]$val){ if(-not $id){ return }; $setUrl = ($Device.TrimEnd('/') + '/commissioning/setvar.csv'); & curl.exe -s -X POST $setUrl -H 'Content-Type: application/x-www-form-urlencoded' --data ('id=' + $id + '&value=' + $val) | Out-Null; Write-Host ("POST id=" + $id + " val=" + $val) }
function ReadId([int]$id, [string]$name){ if(-not $id){ Write-Host ("SKIP read " + $name); return }; $getUrl = ($Device.TrimEnd('/') + '/commissioning/getvar.csv?id=' + $id); try { $c = (Invoke-WebRequest -UseBasicParsing -Uri $getUrl -TimeoutSec 10).Content; Write-Host ("READ " + $name + " (" + $id + ") = " + ($c.Trim())) } catch { Write-Host ("READ fail " + $name + " -> " + $_.Exception.Message) } }

Write-Host "=== DIRECT APPLY ECONOMY/PRECOMFORT ===" -ForegroundColor Cyan
Write-Host ("Device: " + $Device)

$all = ReadText ($Device.TrimEnd('/') + '/commissioning/getvar.csv')
if(-not $all){ throw 'Failed to load getvar.csv from device' }

$names = @(
  'Scheduler_OnOffUnit.Scheduler_1.Today.Enabled',
  'Scheduler_OnOffUnit.Scheduler_1.SpecDay.Enabled',
  'Scheduler_OnOffUnit.Scheduler_1.Holiday.Enabled',
  'Scheduler_OnOffUnit.Scheduler_1.VacationsSched.Enabled',
  'SourceControl.CtrlRoomTemp.Source.Select',
  'SourceControl.CtrlRoomTemp.WriteEnable',
  'SourceControl.CtrlRoomTemp.Lock',
  'CurrRoomTempSetP_Economy',
  'CurrRoomTempSetP_PreComfort',
  'CurrRoomTempSetP_Val'
)
$ids = FindIds $all $names

Write-Host "=== DISABLE SCHEDULERS ===" -ForegroundColor Cyan
PostId $ids['Scheduler_OnOffUnit.Scheduler_1.Today.Enabled'] 0
PostId $ids['Scheduler_OnOffUnit.Scheduler_1.SpecDay.Enabled'] 0
PostId $ids['Scheduler_OnOffUnit.Scheduler_1.Holiday.Enabled'] 0
PostId $ids['Scheduler_OnOffUnit.Scheduler_1.VacationsSched.Enabled'] 0

Write-Host "=== UNLOCK SOURCE/WRITE ===" -ForegroundColor Cyan
PostId $ids['SourceControl.CtrlRoomTemp.Source.Select'] 1
PostId $ids['SourceControl.CtrlRoomTemp.WriteEnable'] 1
PostId $ids['SourceControl.CtrlRoomTemp.Lock'] 1

Write-Host "=== APPLY ECONOMY/PRECOMFORT/CURRENT ===" -ForegroundColor Cyan
PostId $ids['CurrRoomTempSetP_Economy'] ([string]$Value)
PostId $ids['CurrRoomTempSetP_PreComfort'] ([string]$Value)
PostId $ids['CurrRoomTempSetP_Val'] ([string]$Value)

Start-Sleep -Milliseconds 600

Write-Host "=== VERIFY ===" -ForegroundColor Cyan
ReadId $ids['CurrRoomTempSetP_Val'] 'CurrRoomTempSetP_Val'
ReadId $ids['CurrRoomTempSetP_Economy'] 'CurrRoomTempSetP_Economy'
ReadId $ids['CurrRoomTempSetP_PreComfort'] 'CurrRoomTempSetP_PreComfort'

Write-Host "=== DONE ===" -ForegroundColor Green