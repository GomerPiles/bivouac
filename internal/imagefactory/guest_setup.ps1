$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=10
$videoDiagnostics=$null
function Write-SetupStep([int]$Code,[bool]$Failed){
 $fact=@{step=$Code;failed=$Failed}
 if($Code -eq 35 -and $Failed -and $null -ne $videoDiagnostics){$fact.video=$videoDiagnostics}
 [IO.File]::WriteAllText('C:\Windows\Panther\Unattend\setup-step.json',($fact|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
}
try{
 # Do not replace a failed/interrupted specialize step with FirstLogon's 10.
 $step=89
 $path=Join-Path $env:SystemRoot 'Panther\Unattend\setup-step.json'
 $item=Get-Item -Force -LiteralPath $path
 if($item.PSIsContainer -or $item.Length -gt 256 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'specialize status bound or link'}
 $previous=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
 if($previous.step -isnot [int] -or $previous.step -lt 80 -or $previous.step -gt 88 -or $previous.failed -isnot [bool]){throw 'specialize status'}
 if($previous.failed -or $previous.step -ne 88){$step=$previous.step;throw 'specialize incomplete'}

 $step=10
 Write-SetupStep $step $false
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$base=Join-Path $env:SystemRoot 'AppSandbox'
$drivers=Join-Path $base 'drivers'
if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){
 Stop-Service AppSandboxAgent -Force
 (Get-Service AppSandboxAgent).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
}
if(Test-Path -LiteralPath $base){
 if((Get-Item -Force -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'agent directory link'}
}
New-Item -ItemType Directory -Path $base -Force | Out-Null
foreach($file in @('appsandbox-agent.exe','appsandbox-input.exe','appsandbox-displays.exe')) {
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $base $file) -Force
}

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
 $video=@(Get-PnpDevice -Class Display -PresentOnly | Where-Object {
  @((Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds').Data | Where-Object {$_ -like '*DA0A7802*'}).Count -gt 0
 })
 if(!$video.Count -or $video.Count -gt 32){throw 'synthetic video absent or bound'}
 $budget=[Diagnostics.Stopwatch]::StartNew()
 do{
  $started=$true;$videoDiagnostics=$null
  foreach($node in $video){
   $problem=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode').Data
   $status=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_DevNodeStatus').Data
   if($null -eq $problem -or $null -eq $status -or $problem -ne 0 -or !($status -band 8)){
    $started=$false
    if($null -eq $videoDiagnostics -and $null -ne $problem -and $null -ne $status){
     $videoDiagnostics=@{problem_code=[uint32]$problem;devnode_status=[uint32]$status}
    }
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
 if(Test-Path -LiteralPath $drivers){throw 'driver directory remains'}

$step=40;Write-SetupStep $step $false
$msi=Join-Path $PSScriptRoot 'OpenSSH.msi'
if (!(Get-Service sshd -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $msi)) {
 $install=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i',$msi,'/qn','/norestart') -WindowStyle Hidden -Wait -PassThru
 if ($install.ExitCode -notin @(0,3010)) {throw 'setup failed'}
}
if(Get-Service sshd -ErrorAction SilentlyContinue) {Set-Service sshd -StartupType Automatic;Start-Service sshd}
$step=50;Write-SetupStep $step $false
if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Set-Service AppSandboxAgent -StartupType Automatic}
& (Join-Path $base 'appsandbox-agent.exe') @('--install') *> $null
$step=60;Write-SetupStep $step $false
$agent=Get-Service AppSandboxAgent
$agent.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
$agent.Refresh()
if($agent.Status -ne 'Running'){throw 'setup failed'}

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
}catch{try{Write-SetupStep $step $true}catch{};exit $step}
