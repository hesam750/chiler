param(
  [string]$Device = 'http://169.254.61.68',
  [double]$TargetValue = 25.0,
  [double]$EconomyValue = $null,
  [double]$PreComfortValue = $null
)

$ErrorActionPreference = 'Stop'
if ($EconomyValue -eq $null) { $EconomyValue = $TargetValue }
if ($PreComfortValue -eq $null) { $PreComfortValue = $TargetValue }

function ReadText([string]$url){ try { return (& curl.exe -s $url) | Out-String } catch { return '' } }
function FindIdExact([string]$text, [string]$name){ $pat='"' + [regex]::Escape($name) + '",([0-9]+),'; $m=[regex]::Match($text,$pat); if($m.Success){ return [int]$m.Groups[1].Value }; return 0 }
function FindIdByContains([string]$text, [string[]]$contains){ foreach($line in ($text -split "`r?`n")){ $ok=$true; foreach($c in $contains){ if($line -notmatch [regex]::Escape($c)){ $ok=$false; break } }; if($ok){ $mid=[regex]::Match($line,'",([0-9]+),"'); if($mid.Success){ return [int]$mid.Groups[1].Value } } }; return 0 }
function PostId([int]$id, [string]$val, [int]$retries=3){ if(-not $id){ return }; $setUrl = ($Device.TrimEnd('/') + '/commissioning/setvar.csv'); for($i=0; $i -lt $retries; $i++){ & curl.exe -s -X POST $setUrl -H 'Content-Type: application/x-www-form-urlencoded' --data ('id=' + $id + '&value=' + $val) | Out-Null; Start-Sleep -Milliseconds 200 }; Write-Host ("POST id=" + $id + " val=" + $val) }
function ReadId([int]$id, [string]$name, [int]$retries=3){ if(-not $id){ Write-Host ("SKIP read " + $name); return }; $getUrl = ($Device.TrimEnd('/') + '/commissioning/getvar.csv?id=' + $id); $content=''; for($i=0; $i -lt $retries; $i++){ try { $content = (Invoke-WebRequest -UseBasicParsing -Uri $getUrl -TimeoutSec 10).Content; if($content){ break } } catch { Start-Sleep -Milliseconds 200 } }; if($content){ Write-Host ("READ " + $name + " (" + $id + ") = " + ($content.Trim())) } else { Write-Host ("READ fail " + $name) } }

Write-Host "=== FORCE ECONOMY/PRECOMFORT (DIRECT DEVICE) ===" -ForegroundColor Cyan
Write-Host ("Device: " + $Device)

$all = ReadText ($Device.TrimEnd('/') + '/commissioning/getvar.csv')
if(-not $all){ throw 'Failed to load getvar.csv from device' }

# Control IDs
$idWriteEnable = (FindIdExact $all 'SourceControl.CtrlRoomTemp.WriteEnable'); if(-not $idWriteEnable){ $idWriteEnable = (FindIdByContains $all @('Ctrl','Room','WriteEnable')) }
$idLock        = (FindIdExact $all 'SourceControl.CtrlRoomTemp.Lock');        if(-not $idLock){        $idLock        = (FindIdByContains $all @('Ctrl','Room','Lock')) }
$idSourceSel   = (FindIdExact $all 'SourceControl.CtrlRoomTemp.Source.Select');if(-not $idSourceSel){ $idSourceSel   = (FindIdByContains $all @('Source','Select','Ctrl','Room')) }

# Setpoint IDs (prefer Room/Temp setpoints)
$idEco         = (FindIdExact $all 'CurrRoomTempSetP_Economy');               if(-not $idEco){         $idEco         = (FindIdByContains $all @('Economy','SetP','Room','Temp')) }
$idPreComfort  = (FindIdExact $all 'CurrRoomTempSetP_PreComfort');            if(-not $idPreComfort){  $idPreComfort  = (FindIdByContains $all @('PreComfort','SetP','Room','Temp')) }
$idCurrentVal  = (FindIdExact $all 'CurrRoomTempSetP_Val');                    if(-not $idCurrentVal){  $idCurrentVal  = (FindIdByContains $all @('Curr','Room','SetP','Val')) }

Write-Host "=== DISABLE SCHEDULERS (best-effort) ===" -ForegroundColor Cyan
$idSchToday = (FindIdExact $all 'Scheduler_OnOffUnit.Scheduler_1.Today.Enabled');     if(-not $idSchToday){ $idSchToday = (FindIdByContains $all @('Scheduler','Today','Enabled')) }
$idSchSpec  = (FindIdExact $all 'Scheduler_OnOffUnit.Scheduler_1.SpecDay.Enabled');   if(-not $idSchSpec){  $idSchSpec  = (FindIdByContains $all @('Scheduler','Spec','Enabled')) }
$idSchHol   = (FindIdExact $all 'Scheduler_OnOffUnit.Scheduler_1.Holiday.Enabled');   if(-not $idSchHol){   $idSchHol   = (FindIdByContains $all @('Scheduler','Holiday','Enabled')) }
$idSchVac   = (FindIdExact $all 'Scheduler_OnOffUnit.Scheduler_1.VacationsSched.Enabled');if(-not $idSchVac){$idSchVac   = (FindIdByContains $all @('Scheduler','Vacations','Enabled')) }

PostId $idSchToday 0; PostId $idSchSpec 0; PostId $idSchHol 0; PostId $idSchVac 0

Write-Host "=== UNLOCK SOURCE/WRITE ===" -ForegroundColor Cyan
PostId $idSourceSel 1
PostId $idWriteEnable 1
PostId $idLock 1

Write-Host "=== APPLY ECONOMY/PRECOMFORT ===" -ForegroundColor Cyan
if($idEco){ PostId $idEco ([string]$EconomyValue) } else { Write-Host 'SKIP Economy (id not found)' }
if($idPreComfort){ PostId $idPreComfort ([string]$PreComfortValue) } else { Write-Host 'SKIP PreComfort (id not found)' }

Start-Sleep -Milliseconds 600

Write-Host "=== VERIFY ===" -ForegroundColor Cyan
ReadId $idCurrentVal 'CurrRoomTempSetP_Val'
ReadId $idEco 'CurrRoomTempSetP_Economy'
ReadId $idPreComfort 'CurrRoomTempSetP_PreComfort'

Write-Host "=== DONE ===" -ForegroundColor Green