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
 $base='C:\Windows\AppSandbox'
 foreach($path in @('C:\Windows',$base,'C:\ProgramData','C:\ProgramData\ssh','C:\actions-runner',"$HOME\.ssh")){Assert-Ordinary $path}
 if(!(Test-Path -LiteralPath 'C:\actions-runner\bin\Runner.Listener.exe' -PathType Leaf)){exit 1}
 foreach($path in @('C:\ProgramData\Bivouac','C:\actions-runner\.runner','C:\actions-runner\.credentials','C:\actions-runner\.credentials_rsaparams','C:\actions-runner\_work','C:\actions-runner\_diag')){if(Test-Path -LiteralPath $path){exit 1}}
 $probeBase='C:\ProgramData\BivouacHcsSpike'
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
 foreach($path in @('C:\Windows\Panther\Unattend\unattend.xml','C:\Windows\Panther\Unattend\specialize.ps1','C:\Windows\Panther\unattend.xml','C:\Windows\System32\Sysprep\unattend.xml',"$HOME\.ssh\authorized_keys",'C:\ProgramData\ssh\administrators_authorized_keys')){
  $parent=Split-Path -Parent $path;Assert-Ordinary $parent;Assert-Ordinary $path
  if(Test-Path -LiteralPath $path -PathType Leaf){Remove-Item -Force -LiteralPath $path}
 }
 $ssh='C:\ProgramData\ssh'
 $sshdConfig=Join-Path $ssh 'sshd_config';Assert-Ordinary $sshdConfig
 [IO.File]::WriteAllText($sshdConfig,"ListenAddress 127.0.0.1`r`nPasswordAuthentication no`r`nKbdInteractiveAuthentication no`r`nPubkeyAuthentication yes`r`nStrictModes yes`r`nSubsystem sftp sftp-server.exe`r`nMatch Group administrators`r`n AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`r`n",[Text.UTF8Encoding]::new($false))
 $startup='$ErrorActionPreference=''Stop''
$ProgressPreference=''SilentlyContinue''
$service=Get-Service sshd
$agent=Get-Service AppSandboxAgent
if($service.StartType -ne ''Disabled'' -or $service.Status -ne ''Stopped'' -or $agent.StartType -ne ''Disabled'' -or $agent.Status -ne ''Stopped''){exit 1}
foreach($name in @(''ssh_host_rsa_key'',''ssh_host_rsa_key.pub'',''ssh_host_ecdsa_key'',''ssh_host_ecdsa_key.pub'',''ssh_host_ed25519_key'',''ssh_host_ed25519_key.pub'')){
 $path=Join-Path ''C:\ProgramData\ssh'' $name
 if(Test-Path -LiteralPath $path){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1};Remove-Item -Force -LiteralPath $path}
}
& ''C:\Program Files\OpenSSH\ssh-keygen.exe'' @(''-A'') *> $null
if($LASTEXITCODE){exit 1}
foreach($name in @(''ssh_host_rsa_key'',''ssh_host_ecdsa_key'',''ssh_host_ed25519_key'')){if(!(Test-Path -LiteralPath (Join-Path ''C:\ProgramData\ssh'' $name) -PathType Leaf)){exit 1}}
Set-Service sshd -StartupType Manual
Start-Service sshd
Set-Service AppSandboxAgent -StartupType Manual
Start-Service AppSandboxAgent
'
 $startupPath=Join-Path $base 'hcs-spike-startup.ps1';Assert-Ordinary $startupPath
 [IO.File]::WriteAllText($startupPath,$startup,[Text.UTF8Encoding]::new($false))
 $taskName='bivouac-hcs-ssh-hostkeys'
 if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){exit 1}
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Windows\AppSandbox\hcs-spike-startup.ps1'
 $trigger=New-ScheduledTaskTrigger -AtStartup
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Principal $principal -Action $action -Trigger $trigger -Settings $settings|Out-Null
 # The upstream agent can re-enable sshd, so it must also stay stopped until
 # the boot task has generated server keys and started SSH.
 Set-Service AppSandboxAgent -StartupType Disabled
 Set-Service sshd -StartupType Disabled
 foreach($name in @('ssh_host_rsa_key','ssh_host_rsa_key.pub','ssh_host_ecdsa_key','ssh_host_ecdsa_key.pub','ssh_host_ed25519_key','ssh_host_ed25519_key.pub')){
  $path=Join-Path $ssh $name;Assert-Ordinary $path
  if(Test-Path -LiteralPath $path -PathType Leaf){Remove-Item -Force -LiteralPath $path}
 }
 $marker=Join-Path $base 'hcs-spike-prepared.json';Assert-Ordinary $marker
 if(Test-Path -LiteralPath $marker){exit 1}
 $metadata=[ordered]@{name=$data.name;user=$data.user;probe_sha256=$data.probe_sha256;validation_sha256=$data.validation_sha256;autologon_sha256=$data.autologon_sha256}
 [IO.File]::WriteAllText($marker,($metadata|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
 # No further SSH process may run after removing host keys: OpenSSH can regenerate
 # missing keys when it spawns another server process. Shutdown uses this session.
 & 'C:\Windows\System32\shutdown.exe' @('/s','/t','5','/d','p:0:0') *> $null
 if($LASTEXITCODE){exit 1}
 [Console]::Out.Write('sanitized-shutdown-scheduled');[Console]::Out.Flush()
 exit 0
}catch{exit 1}
