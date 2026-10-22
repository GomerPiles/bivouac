$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=10
$videoDiagnostics=@{}
function Write-SetupStep([int]$Code,[bool]$Failed){
 $fact=@{step=$Code;failed=$Failed}
 $fact.video=$videoDiagnostics
 [IO.File]::WriteAllText('C:\Windows\Panther\Unattend\setup-step.json',($fact|ConvertTo-Json -Compress -Depth 8),[Text.UTF8Encoding]::new($false))
}
try{
 # Do not replace a failed/interrupted specialize step with FirstLogon's 10.
 $step=89
 $path=Join-Path $env:SystemRoot 'Panther\Unattend\setup-step.json'
 $item=Get-Item -Force -LiteralPath $path
 if($item.PSIsContainer -or $item.Length -gt 32768 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'specialize status bound or link'}
 $previous=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
 if($previous.step -isnot [int] -or $previous.step -lt 80 -or $previous.step -gt 98 -or $previous.failed -isnot [bool]){throw 'specialize status'}
 $videoDiagnostics=Read-VideoDiagnostics $previous.video
 if($previous.failed -or $previous.step -ne 88){$step=$previous.step;throw 'specialize incomplete'}

 $step=10
 Write-SetupStep $step $false
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$base='C:\ProgramData\Bivouac\Image'
foreach($entry in @(@('HCSRENDER.EXE','hcs-render-probe.exe'),@('HCSVALIDATE.PS1','hcs-spike-validate.ps1'),@('HCSSANITIZE.PS1','hcs-spike-sanitize.ps1'),@('HCSLOGON.PS1','hcs-spike-autologon.ps1'),@('HCSCHECK.PS1','hcs-runner-check.ps1'))) {
 $source=Join-Path $PSScriptRoot $entry[0]
 if(Test-Path -LiteralPath $source -PathType Leaf){Copy-Item -LiteralPath $source -Destination (Join-Path $base $entry[1]) -Force}
}

 function Get-VDDNodes {
  # No PresentOnly: phantom root nodes must be removed too.
  $nodes=@(Get-PnpDevice | Where-Object InstanceId -like 'ROOT\APPSANDBOXVDD\*')
  if($nodes.Count -gt 256){throw 'device bound'}
  return $nodes
 }
 function Get-VDDPackages {
  $packages=@(Get-WindowsDriver -Online -All | Where-Object { [IO.Path]::GetFileName($_.OriginalFileName) -ieq 'AppSandboxVDD.inf' })
  if($packages.Count -gt 256){throw 'package bound'}
  return $packages
 }
 $step=35;Write-SetupStep $step $false
 $videoDiagnostics.first_logon=Get-VideoSnapshot
 Write-SetupStep $step $false
 if(@($videoDiagnostics.first_logon.nodes | Where-Object problem_code -eq 22).Count){
  try{Enable-VideoNodes $videoDiagnostics.first_logon $true}finally{
   $videoDiagnostics.first_logon_enable=$script:videoEnableResult
   $videoDiagnostics.first_logon=Get-VideoSnapshot
   Write-SetupStep $step $false
  }
 }
 $budget=[Diagnostics.Stopwatch]::StartNew()
 do{
  $videoDiagnostics.first_logon=Get-VideoSnapshot
  $started=$false
  foreach($node in $videoDiagnostics.first_logon.nodes){
   if($node.present -eq 1){
    if($node.problem_code -ne 0 -or !($node.devnode_status -band 8)){$started=$false;break}
    $started=$true
   }
  }
  if($started){break};Start-Sleep -Milliseconds 200
 }while($budget.Elapsed.TotalSeconds -lt 30)
 if(!$started){throw 'synthetic video not started'}
 $step=36;Write-SetupStep $step $false
 if(@(Get-VDDNodes).Count){throw 'VDD nodes remain'}
 $step=37;Write-SetupStep $step $false
 if(@(Get-VDDPackages).Count){throw 'VDD packages remain'}
 $step=38;Write-SetupStep $step $false
 if(Test-Path -LiteralPath (Join-Path $env:SystemRoot 'AppSandbox')){throw 'removed component directory remains'}

$step=40;Write-SetupStep $step $false
foreach($name in @('AppSandboxAgent','sshd','ssh-agent')){if(Get-Service -Name $name -ErrorAction SilentlyContinue){throw 'removed service remains'}}
foreach($path in @('C:\ProgramData\ssh','C:\Program Files\OpenSSH','C:\Program Files\OpenSSH-Win64','C:\Windows\System32\OpenSSH')){if(Test-Path -LiteralPath $path){throw 'removed directory remains'}}
if(Get-ScheduledTask -TaskName 'bivouac-hcs-ssh-hostkeys' -ErrorAction SilentlyContinue){throw 'removed task remains'}
foreach($registry in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
 if(!(Test-Path -LiteralPath $registry)){continue}
 $keys=@(Get-ChildItem -LiteralPath $registry);if($keys.Count -gt 4096){throw 'uninstall registry bound'}
 foreach($key in $keys){if((Get-ItemProperty -LiteralPath $key.PSPath).DisplayName -match '^OpenSSH(?:\s|$)'){throw 'removed installer remains'}}
}
$profiles=@(Get-ChildItem -Directory -Force -LiteralPath 'C:\Users');if($profiles.Count -gt 256){throw 'profile bound'}
foreach($profile in $profiles){foreach($name in @('authorized_keys','administrators_authorized_keys')){if(Test-Path -LiteralPath (Join-Path $profile.FullName ('.ssh\'+$name))){throw 'authorization remains'}}}
# Offline driver placement normally makes the first PnP start sufficient.
# Match the reference's recovery only for the GPU-PV driver with error 43.
$step=45;Write-SetupStep $step $false
$drivers=@(Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceClass='DISPLAY'" -OperationTimeoutSec 10)
if($drivers.Count -gt 32){throw 'GPU driver bound'}
foreach($driver in $drivers){
 if($driver.InfName -ine 'vrd.inf'){continue}
 $nodes=@(Get-PnpDevice -InstanceId $driver.DeviceID)
 if($nodes.Count -ne 1){throw 'GPU device identity'}
 $problem=(Get-PnpDeviceProperty -InstanceId $driver.DeviceID -KeyName 'DEVPKEY_Device_ProblemCode').Data
 if($problem -eq 43){
  & (Join-Path $env:SystemRoot 'System32\pnputil.exe') @('/restart-device',$driver.DeviceID) *> $null
  if($LASTEXITCODE -notin @(0,3010)){throw 'GPU device restart'}
 }
}
$step=50;Write-SetupStep $step $false
$agent='C:\Program Files\Bivouac\bivouac.exe'
if(!(Test-Path -LiteralPath $agent -PathType Leaf) -or ((Get-Item -LiteralPath $agent).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'agent installation'}
$user=$env:USERNAME
if($user -notmatch '^[A-Za-z0-9_-]{1,20}$'){throw 'agent account'}
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$action=New-ScheduledTaskAction -Execute $agent -Argument ('guest-agent --user '+$user)
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$settings=New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
if(Get-ScheduledTask -TaskName 'bivouac-guest-agent' -ErrorAction SilentlyContinue){throw 'agent task already exists'}
Register-ScheduledTask -TaskName 'bivouac-guest-agent' -Principal $principal -Action $action -Trigger $trigger -Settings $settings | Out-Null
$step=60;Write-SetupStep $step $false
Start-ScheduledTask -TaskName 'bivouac-guest-agent'

$step=70;Write-SetupStep $step $false
. (Join-Path $PSScriptRoot 'HCSCHECK.PS1')
# Offline inspection admits a template whose only runner residue is regular
# files in _diag (logs from template preparation). Remove them; the runner
# recreates _diag when it starts.
$diag='C:\actions-runner\_diag'
if(Test-Path -LiteralPath $diag){
 $item=Get-Item -Force -LiteralPath $diag
 if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'runner residue'}
 foreach($entry in @(Get-ChildItem -Force -LiteralPath $diag)){
  if($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'runner residue'}
  $null=Remove-Item -Force -LiteralPath $entry.FullName
 }
}
if(!(Assert-CleanRunner 'C:\actions-runner')){
 $runnerZip=Join-Path $PSScriptRoot 'RUNNER.ZIP'
 if(!(Test-Path -LiteralPath $runnerZip -PathType Leaf)){throw 'runner absent'}
 & (Join-Path $PSScriptRoot 'HCSRUNNER.PS1') $runnerZip 'C:\actions-runner'
 if($LASTEXITCODE -or !(Assert-CleanRunner 'C:\actions-runner')){throw 'runner extraction'}
}
foreach($name in @('_work','_diag')){
 $path=Join-Path 'C:\actions-runner' $name
 if(Test-Path -LiteralPath $path){$null=Remove-Item -LiteralPath $path}
}
$step=100;Write-SetupStep $step $false
Set-Content -LiteralPath (Join-Path $base 'hcs-spike-setup-complete.json') -Value '{"ready":true}' -Encoding UTF8
exit 0
}catch{
 try{Write-SetupStep $step $true}catch{}
 # No agent may exist yet. Power off so the host observes failure promptly.
 try{& (Join-Path $env:SystemRoot 'System32\shutdown.exe') @('/s','/t','0') *> $null}catch{}
 exit $step
}
