param($data)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 if($env:COMPUTERNAME -ine $data.name -or $env:USERNAME -ine $data.user){exit 1}
 $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
 if($setup.SystemSetupInProgress -ne 0 -or $setup.OOBEInProgress -ne 0){exit 1}
 function Assert-Ordinary([string]$Path){
  if(Test-Path -LiteralPath $Path){if((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}
 }
 $base='C:\ProgramData\Bivouac\Image'
 foreach($path in @('C:\Windows',$base,'C:\ProgramData','C:\actions-runner')){Assert-Ordinary $path}
 if(!(Test-Path -LiteralPath 'C:\actions-runner\bin\Runner.Listener.exe' -PathType Leaf)){exit 1}
 # The template has recreated this directory after removal; it must not ship.
 if(Test-Path -LiteralPath (Join-Path $env:SystemRoot 'AppSandbox')){exit 31}
 foreach($path in @('C:\actions-runner\.runner','C:\actions-runner\.credentials','C:\actions-runner\.credentials_rsaparams','C:\actions-runner\_work','C:\actions-runner\_diag')){if(Test-Path -LiteralPath $path){exit 1}}
 $probeBase='C:\ProgramData\Bivouac\Image\Probe'
 Assert-Ordinary $probeBase
 $entries=@(Get-ChildItem -Force -LiteralPath $probeBase)
 if($entries.Count -ne 2){exit 1}
 foreach($entry in $entries){if($entry.PSIsContainer -or $entry.Name -notin @('render.exe','render.json')){exit 1};Assert-Ordinary $entry.FullName}
 if((Get-FileHash -LiteralPath (Join-Path $probeBase 'render.exe') -Algorithm SHA256).Hash -ine $data.probe_sha256){exit 1}
 $reportPath=Join-Path $probeBase 'render.json'
 if((Get-Item -LiteralPath $reportPath).Length -gt 4096){exit 1}
 $observed=Get-Content -LiteralPath $reportPath -Raw|ConvertFrom-Json
 if(!$observed.hardware_d3d11 -or !$observed.presented -or !$observed.pixel_readback -or $observed.stage -ne 7 -or $observed.hresult -ne 0){exit 1}
 foreach($name in @('render.exe','render.json')){Remove-Item -Force -LiteralPath (Join-Path $probeBase $name)}
 Remove-Item -LiteralPath $probeBase
 $secretHelper=Join-Path $base 'hcs-spike-autologon.ps1'
 if((Get-FileHash -LiteralPath $secretHelper -Algorithm SHA256).Hash -ine $data.autologon_sha256){throw 'Autologon helper integrity differs'}
 . $secretHelper
 $random=New-Object byte[] 32
 $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
 try{$rng.GetBytes($random)}finally{$rng.Dispose()}
 $password='Bv!'+[Convert]::ToBase64String($random)
 $secure=[Security.SecureString]::new()
 $characters=$password.ToCharArray()
 try{foreach($character in $characters){$secure.AppendChar($character)};$secure.MakeReadOnly()}finally{[Array]::Clear($characters,0,$characters.Length)}
 try{Set-LocalUser -Name $data.user -Password $secure}finally{$secure.Dispose()}
 $logon=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
 try{
  $logon.SetValue('AutoAdminLogon','1')
  $logon.SetValue('DefaultUserName',$data.user)
  $logon.SetValue('DefaultDomainName',$env:COMPUTERNAME)
  if([SpikeAutoLogonSecret]::Store($password) -ne 0){throw 'Cannot protect clone autologon credential'}
  $logon.DeleteValue('DefaultPassword',$false)
  $logon.DeleteValue('AutoLogonCount',$false)
 }finally{$logon.Dispose();$password=$null;[Array]::Clear($random,0,$random.Length)}
 foreach($path in @('C:\Windows\Panther\Unattend\unattend.xml','C:\Windows\Panther\Unattend\specialize.ps1','C:\Windows\Panther\Unattend\setup-step.json','C:\Windows\Panther\unattend.xml','C:\Windows\System32\Sysprep\unattend.xml')){
  $parent=Split-Path -Parent $path;Assert-Ordinary $parent;Assert-Ordinary $path
  if(Test-Path -LiteralPath $path -PathType Leaf){Remove-Item -Force -LiteralPath $path}
 }
 # No adapter delivery belongs in an image. The build agent logs separately;
 # delete its open, delete-shared log before scheduling shutdown.
 foreach($directory in @('C:\ProgramData\Bivouac\Guest','C:\ProgramData\Bivouac\Agent')){
  Assert-Ordinary $directory
  if(Test-Path -LiteralPath $directory){
   $entries=@(Get-ChildItem -Force -LiteralPath $directory)
   if($entries.Count -gt 8){exit 1}
   foreach($entry in $entries){
    if($entry.PSIsContainer -or $entry.Name -notin @('agent.log','agent.log.1','.receive.lock')){exit 1}
    Assert-Ordinary $entry.FullName;Remove-Item -Force -LiteralPath $entry.FullName
   }
   if($directory -like '*\Guest'){Remove-Item -LiteralPath $directory}
  }
 }
 if(!(Get-ScheduledTask -TaskName 'bivouac-guest-agent' -ErrorAction SilentlyContinue)){exit 1}
 $marker=Join-Path $base 'hcs-spike-prepared.json';Assert-Ordinary $marker
 if(Test-Path -LiteralPath $marker){exit 1}
 $metadata=[ordered]@{name=$data.name;user=$data.user;probe_sha256=$data.probe_sha256;validation_sha256=$data.validation_sha256;autologon_sha256=$data.autologon_sha256}
 [IO.File]::WriteAllText($marker,($metadata|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
 # Keep the agent's logon task for the next cold boot.
 & 'C:\Windows\System32\shutdown.exe' @('/s','/t','5','/d','p:0:0') *> $null
 if($LASTEXITCODE){exit 1}
 [Console]::Out.Write('sanitized-shutdown-scheduled');[Console]::Out.Flush()
 exit 0
}catch{exit 1}
