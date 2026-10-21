$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 $base=Join-Path $env:SystemRoot 'AppSandbox'
 $drivers=Join-Path $base 'drivers'
 foreach($path in @($base,$drivers)){
  if(Test-Path -LiteralPath $path){$item=Get-Item -Force -LiteralPath $path;if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){exit 1}}
 }
 if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Stop-Service AppSandboxAgent -Force}
 New-Item -ItemType Directory -Path $drivers -Force|Out-Null
 function Copy-MissingPinned([string]$Name,[string]$Directory){
  $source=Join-Path $PSScriptRoot $Name;$target=Join-Path $Directory $Name
  if(Test-Path -LiteralPath $target){
   $item=Get-Item -Force -LiteralPath $target
   if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash){throw 'existing component differs'}
  }else{Copy-Item -LiteralPath $source -Destination $target}
 }
 foreach($file in @('appsandbox-agent.exe','appsandbox-input.exe','appsandbox-displays.exe')){Copy-MissingPinned $file $base}
 foreach($file in @('AppSandboxVDD.dll','AppSandboxVDD.inf','AppSandboxVDD.cat','devcon.exe')){Copy-MissingPinned $file $drivers}
 foreach($entry in @(@('HCSRENDER.EXE','hcs-render-probe.exe'),@('HCSVALIDATE.PS1','hcs-spike-validate.ps1'),@('HCSSANITIZE.PS1','hcs-spike-sanitize.ps1'),@('HCSLOGON.PS1','hcs-spike-autologon.ps1'),@('HCSCHECK.PS1','hcs-runner-check.ps1'))){
  $target=Join-Path $base $entry[1]
  if(Test-Path -LiteralPath $target){throw 'factory helper already present'}
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $entry[0]) -Destination $target
 }
 $vdd=@(Get-PnpDevice -PresentOnly|Where-Object InstanceId -like 'ROOT\APPSANDBOXVDD\*')
 if(!$vdd.Count){
  & (Join-Path $drivers 'devcon.exe') @('install',(Join-Path $drivers 'AppSandboxVDD.inf'),'Root\AppSandboxVDD') *> $null
  if($LASTEXITCODE -notin @(0,1)){exit 1}
 }elseif(@($vdd|Where-Object Status -ne 'OK').Count){exit 1}
 $vdd=@(Get-PnpDevice -PresentOnly|Where-Object InstanceId -like 'ROOT\APPSANDBOXVDD\*')
 if(!$vdd.Count){exit 1}
 foreach($device in $vdd){
  $inf=(Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath').Data
  if($inf -notmatch '^(oem[0-9]+|appsandboxvdd)\.inf$'){exit 1}
  if((Get-FileHash -LiteralPath (Join-Path 'C:\Windows\INF' $inf) -Algorithm SHA256).Hash -ine (Get-FileHash -LiteralPath (Join-Path $drivers 'AppSandboxVDD.inf') -Algorithm SHA256).Hash){exit 1}
 }
 $msi=Join-Path $PSScriptRoot 'OpenSSH.msi'
 if(!(Get-Service sshd -ErrorAction SilentlyContinue)){
  # An incomplete existing install must be investigated, not overwritten.
  foreach($path in @('C:\Program Files\OpenSSH\sshd.exe','C:\Windows\System32\OpenSSH\sshd.exe')){if(Test-Path -LiteralPath $path){exit 1}}
  if(!(Test-Path -LiteralPath $msi -PathType Leaf)){exit 1}
  $install=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i',$msi,'/qn','/norestart') -WindowStyle Hidden -Wait -PassThru
  if($install.ExitCode -notin @(0,3010)){exit 1}
 }
 $sshService=Get-CimInstance Win32_Service -Filter "Name='sshd'"
 $sshBinary=$sshService.PathName.Trim('"')
 if($sshBinary -notin @('C:\Program Files\OpenSSH\sshd.exe','C:\Windows\System32\OpenSSH\sshd.exe')){exit 1}
 foreach($path in @((Split-Path -Parent $sshBinary),$sshBinary)){
  if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1}
 }
 if((Get-AuthenticodeSignature -LiteralPath $sshBinary).Status -ne 'Valid'){exit 1}
 Set-Service sshd -StartupType Automatic;Start-Service sshd
 $agent=Get-Service AppSandboxAgent -ErrorAction SilentlyContinue
 if(!$agent){
  & (Join-Path $base 'appsandbox-agent.exe') @('--install') *> $null
  if($LASTEXITCODE){exit 1}
 }else{
  $definition=Get-CimInstance Win32_Service -Filter "Name='AppSandboxAgent'"
  if($definition.PathName.Trim('"') -ine (Join-Path $base 'appsandbox-agent.exe')){exit 1}
  Set-Service AppSandboxAgent -StartupType Automatic;Start-Service AppSandboxAgent
 }
 $agent=Get-Service AppSandboxAgent
 $agent.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))
 $agent.Refresh();if($agent.Status -ne 'Running'){exit 1}
 . (Join-Path $PSScriptRoot 'HCSCHECK.PS1')
 if(!(Assert-CleanRunner 'C:\actions-runner')){
  $runnerZip=Join-Path $PSScriptRoot 'RUNNER.ZIP'
  if(!(Test-Path -LiteralPath $runnerZip -PathType Leaf)){exit 1}
  & (Join-Path $PSScriptRoot 'HCSRUNNER.PS1') $runnerZip 'C:\actions-runner'
  if($LASTEXITCODE -or !(Assert-CleanRunner 'C:\actions-runner')){exit 1}
 }
 foreach($name in @('_work','_diag')){
  $path=Join-Path 'C:\actions-runner' $name
  if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path}
 }
 Set-Content -LiteralPath (Join-Path $base 'hcs-spike-setup-complete.json') -Value '{"ready":true}' -Encoding UTF8
 exit 0
}catch{exit 1}
