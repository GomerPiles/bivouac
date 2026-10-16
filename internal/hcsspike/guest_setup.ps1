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
# Install only into this disposable guest. Use fixed argument arrays.
if(!@(Get-PnpDevice -PresentOnly | Where-Object InstanceId -like 'ROOT\APPSANDBOXVDD\*').Count) {
 & (Join-Path $drivers 'devcon.exe') @('install',(Join-Path $drivers 'AppSandboxVDD.inf'),'Root\AppSandboxVDD') *> $null
}
$msi=Join-Path $PSScriptRoot 'OpenSSH.msi'
if (!(Get-Service sshd -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $msi)) {
 $install=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i',$msi,'/qn','/norestart') -WindowStyle Hidden -Wait -PassThru
 if ($install.ExitCode -notin @(0,3010)) {exit 1}
}
if(Get-Service sshd -ErrorAction SilentlyContinue) {Set-Service sshd -StartupType Automatic;Start-Service sshd}
if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Set-Service AppSandboxAgent -StartupType Automatic}
& (Join-Path $base 'appsandbox-agent.exe') @('--install') *> $null
$agent=Get-Service AppSandboxAgent
$agent.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
$agent.Refresh()
if($agent.Status -ne 'Running'){exit 1}
Set-Content -LiteralPath (Join-Path $base 'hcs-spike-setup-complete.json') -Value '{"ready":true}' -Encoding UTF8
