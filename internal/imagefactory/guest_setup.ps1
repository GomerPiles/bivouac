$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=10
$videoDiagnostics=@{}
function Write-SetupStep([int]$Code,[bool]$Failed){
 $fact=@{step=$Code;failed=$Failed}
 $fact.video=$videoDiagnostics
 [IO.File]::WriteAllText('C:\Windows\Panther\Unattend\setup-step.json',($fact|ConvertTo-Json -Compress -Depth 8),[Text.UTF8Encoding]::new($false))
}
# TASK_CREATE|TASK_DONT_ADD_PRINCIPAL_ACE (0x12) with an interactive-token
# logon (3). The registration cmdlet would add read access for the principal,
# and Task Scheduler lets a task's own user, even unelevated, run a task it
# can read.
function Register-RunnerTask([string]$Xml){
 $s=New-Object -ComObject Schedule.Service
 try{$s.Connect();$f=$s.GetFolder('\')
  try{$null=$f.RegisterTask('bivouac-guest-runner',$Xml,0x12,$null,$null,3,$null)}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($f)}
 }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($s)}
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
 # Verify legacy removal again before installing the agent; sanitation checks it too.
 $appSandbox=Join-Path $env:SystemRoot 'AppSandbox'
 if(Test-Path -LiteralPath $appSandbox){
  $current=$appSandbox
  while($current){if((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'removal path link'};$current=Split-Path -Parent $current}
  $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($appSandbox);$count=0
  while($queue.Count){foreach($entry in @(Get-ChildItem -LiteralPath ($queue.Dequeue()) -Force)){
   $count++;if($count -gt 16384 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'removal bound or link'}
   if($entry.PSIsContainer){$queue.Enqueue($entry.FullName)}
  }}
  Remove-Item -LiteralPath $appSandbox -Recurse -Force
 }
 if(Test-Path -LiteralPath $appSandbox){throw 'removed component directory remains'}

# The inbox client and ssh-agent belong to Windows servicing and remain intact.
$step=39;Write-SetupStep $step $false
$capability=Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if($capability.State -eq 'Installed'){
 $result=Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
 if($result.RestartNeeded){throw 'server capability requires another boot'}
}
if((Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State -ne 'NotPresent'){throw 'server capability remains'}
$step=40;Write-SetupStep $step $false
foreach($name in @('AppSandboxAgent','sshd')){if(Get-Service -Name $name -ErrorAction SilentlyContinue){throw 'removed service remains'}}
foreach($path in @('C:\ProgramData\ssh','C:\Program Files\OpenSSH','C:\Program Files\OpenSSH-Win64')){if(Test-Path -LiteralPath $path){throw 'removed directory remains'}}
foreach($path in @('C:\Windows\System32\OpenSSH\sshd.exe','C:\Program Files\OpenSSH\sshd.exe','C:\Program Files\OpenSSH-Win64\sshd.exe')){if(Test-Path -LiteralPath $path){throw 'server executable remains'}}
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
# Check both tasks before registering either; an existing runner must not
# leave a newly registered agent task behind after refusal.
foreach($taskName in @('bivouac-guest-agent','bivouac-guest-runner')){
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'guest task already exists'}
}
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
# Task Scheduler stores arguments as one string; the account above is a validated identifier.
$action=New-ScheduledTaskAction -Execute $agent -Argument ('guest-agent --user '+$user)
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$settings=New-ScheduledTaskSettingsSet -Priority 4 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'bivouac-guest-agent' -Principal $principal -Action $action -Trigger $trigger -Settings $settings | Out-Null
# Fixed XML applies the DACL at registration, before the task can run.
$runnerUser=[Security.SecurityElement]::Escape(([Security.Principal.WindowsIdentity]::GetCurrent().User.Value))
$runnerXml=@'
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><SecurityDescriptor>O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)</SecurityDescriptor></RegistrationInfo>
<Triggers/>
<Principals><Principal id="Runner"><UserId>RUNNER_USER_SID</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><RunOnlyIfIdle>false</RunOnlyIfIdle><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>4</Priority></Settings>
<Actions Context="Runner"><Exec><Command>C:\Program Files\Bivouac\bivouac.exe</Command><Arguments>guest windows detached</Arguments><WorkingDirectory>C:\ProgramData\Bivouac\Guest</WorkingDirectory></Exec></Actions>
</Task>
'@
$runnerXml=$runnerXml.Replace('RUNNER_USER_SID',$runnerUser)
Register-RunnerTask $runnerXml
$step=60;Write-SetupStep $step $false
Start-ScheduledTask -TaskName 'bivouac-guest-agent'

$step=70;Write-SetupStep $step $false
. (Join-Path $PSScriptRoot 'HCSCHECK.PS1')
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
 # Setup may fail before agent startup. Power off so the host observes failure promptly.
 try{& (Join-Path $env:SystemRoot 'System32\shutdown.exe') @('/s','/t','0') *> $null}catch{}
 exit $step
}
