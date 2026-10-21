$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=10
function Write-SetupStep([int]$Code,[bool]$Failed){
 [IO.File]::WriteAllText('C:\Windows\Panther\Unattend\setup-step.json',(@{step=$Code;failed=$Failed}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
}
try{
 Write-SetupStep $step $false
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$base=Join-Path $env:SystemRoot 'AppSandbox'
$drivers=Join-Path $base 'drivers'
if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Stop-Service AppSandboxAgent -Force}
New-Item -ItemType Directory -Path $drivers -Force | Out-Null
foreach($file in @('appsandbox-agent.exe','appsandbox-input.exe','appsandbox-displays.exe')) {
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $base $file) -Force
}
foreach($file in @('AppSandboxVDD.dll','AppSandboxVDD.inf','AppSandboxVDD.cat','devcon.exe')) {
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $drivers $file) -Force
}
foreach($entry in @(@('HCSRENDER.EXE','hcs-render-probe.exe'),@('HCSVALIDATE.PS1','hcs-spike-validate.ps1'),@('HCSSANITIZE.PS1','hcs-spike-sanitize.ps1'),@('HCSLOGON.PS1','hcs-spike-autologon.ps1'),@('HCSCHECK.PS1','hcs-runner-check.ps1'))) {
 $source=Join-Path $PSScriptRoot $entry[0]
 if(Test-Path -LiteralPath $source -PathType Leaf){Copy-Item -LiteralPath $source -Destination (Join-Path $base $entry[1]) -Force}
}
$step=30;Write-SetupStep $step $false
# Install only into this disposable guest. Use fixed argument arrays.
if(!@(Get-PnpDevice -PresentOnly | Where-Object InstanceId -like 'ROOT\APPSANDBOXVDD\*').Count) {
 & (Join-Path $drivers 'devcon.exe') @('install',(Join-Path $drivers 'AppSandboxVDD.inf'),'Root\AppSandboxVDD') *> $null
}
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
