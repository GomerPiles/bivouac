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
 function Remove-BoundedTree([string]$Path){
  if(!(Test-Path -LiteralPath $Path)){return}
  $current=$Path
  while($current){if((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'removal path link'};$current=Split-Path -Parent $current}
  $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($Path);$count=0
  while($queue.Count){foreach($entry in @(Get-ChildItem -LiteralPath ($queue.Dequeue()) -Force)){
   $count++;if($count -gt 16384 -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'removal bound or link'}
   if($entry.PSIsContainer){$queue.Enqueue($entry.FullName)}
  }}
  Remove-Item -LiteralPath $Path -Recurse -Force
 }
 function Remove-FixedService([string]$Name){
  $service=Get-Service -Name $Name -ErrorAction SilentlyContinue
  if(!$service){return}
  if($service.Status -ne 'Stopped'){Stop-Service -Name $Name -Force;$service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))}
  & (Join-Path $env:SystemRoot 'System32\sc.exe') @('delete',$Name) *> $null
  if($LASTEXITCODE){throw 'service deletion'}
 }
 New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Name BypassNRO -Value 1 -PropertyType DWord -Force | Out-Null

 $step=81;Write-SetupStep $step $false
 Remove-FixedService 'AppSandboxAgent'
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
 Remove-BoundedTree (Join-Path $env:SystemRoot 'AppSandbox')
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
 $step=90;Write-SetupStep $step $false
 $uninstalls=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
 $products=0
 foreach($registry in $uninstalls){
  if(!(Test-Path -LiteralPath $registry)){continue}
  $keys=@(Get-ChildItem -LiteralPath $registry);if($keys.Count -gt 4096){throw 'uninstall registry bound'}
  foreach($key in $keys){
   $product=Get-ItemProperty -LiteralPath $key.PSPath
   if($product.DisplayName -notmatch '^OpenSSH(?:\s|$)'){continue}
   if($key.PSChildName -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'){throw 'uninstall product code'}
   $products++;if($products -gt 8){throw 'uninstall product bound'}
   $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/x',$key.PSChildName,'/qn','/norestart') -WindowStyle Hidden -Wait -PassThru
   if($process.ExitCode -notin @(0,1605,3010)){throw 'uninstall failed'}
  }
 }
 $step=86;Write-SetupStep $step $false
 # MSI uninstall owns its services first; remove only leftover server state.
 Remove-FixedService 'sshd'
 $step=91;Write-SetupStep $step $false
 foreach($path in @('C:\Program Files\OpenSSH','C:\Program Files\OpenSSH-Win64')){Remove-BoundedTree $path}
 $step=92;Write-SetupStep $step $false
 Remove-BoundedTree 'C:\ProgramData\ssh'
 $step=93;Write-SetupStep $step $false
 $profiles=@(Get-ChildItem -Directory -Force -LiteralPath 'C:\Users');if($profiles.Count -gt 256){throw 'profile bound'}
 foreach($profile in $profiles){
  foreach($name in @('authorized_keys','administrators_authorized_keys')){
   $path=Join-Path $profile.FullName ('.ssh\'+$name)
   if(Test-Path -LiteralPath $path){Remove-BoundedTree $path}
  }
 }
 $step=94;Write-SetupStep $step $false
 $oldTask=Get-ScheduledTask -TaskName 'bivouac-hcs-ssh-hostkeys' -ErrorAction SilentlyContinue
 if($oldTask){Unregister-ScheduledTask -TaskName 'bivouac-hcs-ssh-hostkeys' -Confirm:$false}
 $step=88;Write-SetupStep $step $false

} catch {
 try{Write-SetupStep $step $true}catch{};exit $step
}
