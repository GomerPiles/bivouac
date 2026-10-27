$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
# Read only the fresh guest. No service, Defender, registry or host policy changes.
$facts=[ordered]@{
 identity=(Get-Content -LiteralPath 'C:\ProgramData\Bivouac\SandboxLab\identity.json' -Raw | ConvertFrom-Json)
 windows_build=[uint32][Environment]::OSVersion.Version.Build
 defender=[ordered]@{command_present=$false;observed=$false;service_enabled=$false;realtime_enabled=$false;tamper_protected=$false}
 services=[ordered]@{}
 tools=[ordered]@{}
 windows_sdk_versions=@()
}
if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){
 $facts.defender.command_present=$true
 try{
  $status=Get-MpComputerStatus -ErrorAction Stop
  $facts.defender.observed=$true
  $facts.defender.service_enabled=[bool]$status.AMServiceEnabled
  $facts.defender.realtime_enabled=[bool]$status.RealTimeProtectionEnabled
  $facts.defender.tamper_protected=[bool]$status.IsTamperProtected
 }catch{}
}
foreach($name in @('WinDefend','WSearch','wuauserv','SysMain','Sense')){
 $service=Get-Service -Name $name -ErrorAction SilentlyContinue
 $facts.services[$name]=[ordered]@{present=($null -ne $service);running=($service -and $service.Status -eq 'Running')}
}
$commands=[ordered]@{pwsh='pwsh.exe';git='git.exe';'7zip'='7z.exe';cmake='cmake.exe';ninja='ninja.exe';python='python.exe';node='node.exe';dotnet='dotnet.exe';llvm='clang.exe'}
foreach($name in $commands.Keys){$facts.tools[$name]=[bool](Get-Command $commands[$name] -CommandType Application -ErrorAction SilentlyContinue)}
$facts.tools['runner_node']=Test-Path -LiteralPath 'C:\actions-runner\externals\node24\bin\node.exe' -PathType Leaf
$facts.tools['msvc']=$false
$facts.tools['msbuild']=$false
$vswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if(Test-Path -LiteralPath $vswhere -PathType Leaf){
 $install=& $vswhere @('-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath')
 if($LASTEXITCODE -eq 0 -and $install -is [string] -and $install -match '^C:\\'){
  $toolsets=Join-Path $install 'VC\Tools\MSVC'
  if(Test-Path -LiteralPath $toolsets -PathType Container){
   foreach($version in @(Get-ChildItem -LiteralPath $toolsets -Directory | Select-Object -First 16)){
    if((Test-Path -LiteralPath (Join-Path $version.FullName 'bin\Hostx64\x64\cl.exe') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $version.FullName 'include\vector') -PathType Leaf)){$facts.tools['msvc']=$true}
   }
  }
  $facts.tools['msbuild']=Test-Path -LiteralPath (Join-Path $install 'MSBuild\Current\Bin\MSBuild.exe') -PathType Leaf
 }
}
$sdk='C:\Program Files (x86)\Windows Kits\10'
$include=Join-Path $sdk 'Include'
if(Test-Path -LiteralPath $include -PathType Container){
 foreach($version in @(Get-ChildItem -LiteralPath $include -Directory | Select-Object -First 16)){
  if($version.Name -notmatch '^\d+\.\d+\.\d+\.\d+$'){continue}
  if((Test-Path -LiteralPath (Join-Path $version.FullName 'um\Windows.h') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $sdk ('Lib\'+$version.Name+'\um\x64\kernel32.lib')) -PathType Leaf)){
   $facts.windows_sdk_versions+=@($version.Name)
  }
 }
}
$facts.tools['windows_sdk']=$facts.windows_sdk_versions.Count -gt 0
$facts | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath 'C:\BivouacReport\baseline.json' -Encoding ASCII
