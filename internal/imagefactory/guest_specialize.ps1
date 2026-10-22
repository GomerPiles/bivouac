$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=80
$videoDiagnostics=@{}
function Write-SetupStep([int]$Code,[bool]$Failed){
 [IO.File]::WriteAllText('C:\Windows\Panther\Unattend\setup-step.json',(@{step=$Code;failed=$Failed;video=$videoDiagnostics}|ConvertTo-Json -Compress -Depth 8),[Text.UTF8Encoding]::new($false))
}
try {
 Write-SetupStep $step $false
 if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Set-Service AppSandboxAgent -StartupType Disabled}
 New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Name BypassNRO -Value 1 -PropertyType DWord -Force | Out-Null

 $step=81;Write-SetupStep $step $false
 if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){
  Stop-Service AppSandboxAgent -Force
  (Get-Service AppSandboxAgent).WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
 }
 $base=Join-Path $env:SystemRoot 'AppSandbox'
 $drivers=Join-Path $base 'drivers'
 if(Test-Path -LiteralPath $base){
  if((Get-Item -Force -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'agent directory link'}
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
 $pnp=Join-Path $env:SystemRoot 'System32\pnputil.exe'
 $step=82;Write-SetupStep $step $false
 foreach($node in @(Get-VDDNodes)){
  $ids=@((Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds').Data)
  if('ROOT\APPSANDBOXVDD' -notin $ids){throw 'device identity'}
  & $pnp @('/remove-device',$node.InstanceId) *> $null
  if($LASTEXITCODE -notin @(0,3010)){throw 'device removal'}
 }
 $step=83;Write-SetupStep $step $false
 foreach($package in @(Get-VDDPackages)){
  if($package.Driver -notmatch '^oem[0-9]+\.inf$'){throw 'package identity'}
  & $pnp @('/delete-driver',$package.Driver,'/uninstall','/force') *> $null
  if($LASTEXITCODE -notin @(0,3010)){throw 'package removal'}
 }
 $step=84;Write-SetupStep $step $false
 if(Test-Path -LiteralPath $drivers){
  $directory=Get-Item -Force -LiteralPath $drivers
  if($directory.FullName -ine [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'AppSandbox\drivers')) -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'driver directory identity'}
  $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($directory.FullName);$count=0
  while($pending.Count){
   foreach($entry in @(Get-ChildItem -LiteralPath ($pending.Dequeue()) -Force)){
    $count++;if($count -gt 4096 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'driver directory bound or link'}
    if($entry.PSIsContainer){$pending.Enqueue($entry.FullName)}
   }
  }
  Remove-Item -LiteralPath $drivers -Recurse -Force
 }
 $step=85;Write-SetupStep $step $false
 $videoDiagnostics.specialize_before=Get-VideoSnapshot
 Write-SetupStep $step $false
 if(!$videoDiagnostics.specialize_before.node_count){throw 'synthetic video absent'}
 try{Enable-VideoNodes $videoDiagnostics.specialize_before $false}finally{
  $videoDiagnostics.specialize_enable=$script:videoEnableResult
  $videoDiagnostics.specialize_after=Get-VideoSnapshot
  Write-SetupStep $step $false
 }
 if(!$videoDiagnostics.specialize_enable.returned){throw 'synthetic video enable failed'}
 # Windows setup's following boot settles PnP changes; do not reboot here.
 $step=88;Write-SetupStep $step $false

} catch {
 try{Write-SetupStep $step $true}catch{};exit $step
}
