package winrunner

// This runs before an external NIC is attached. SSH/agent availability alone
// does not prove that unattended setup and the intended console logon finished.
const PreflightScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$incoming=Get-Content -Raw -LiteralPath (Join-Path $HOME 'bivouac-config.json') | ConvertFrom-Json
if($env:COMPUTERNAME -ine $incoming.native_name -or $env:USERNAME -ine $incoming.user){throw 'Guest identity differs'}
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class BivouacBootConsole {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool WTSQuerySessionInformation(IntPtr server,uint session,int info,out IntPtr buffer,out int bytes);
 [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr buffer);
}
'@
$deadline=[DateTime]::UtcNow.AddMinutes(10)
$stable=0
while([DateTime]::UtcNow -lt $deadline){
 $session=[BivouacBootConsole]::WTSGetActiveConsoleSessionId()
 $matched=$false;$buffer=[IntPtr]::Zero;$bytes=0
 if($session -ne 0 -and $session -ne [uint32]::MaxValue){
  try{if([BivouacBootConsole]::WTSQuerySessionInformation([IntPtr]::Zero,$session,5,[ref]$buffer,[ref]$bytes)){$matched=([Runtime.InteropServices.Marshal]::PtrToStringUni($buffer) -ieq $incoming.user)}}finally{if($buffer -ne [IntPtr]::Zero){[BivouacBootConsole]::WTSFreeMemory($buffer)}}
 }
 $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
 $explorer=@(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session)
 if($matched -and $setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0 -and $explorer.Count){$stable++}else{$stable=0}
 if($stable -ge 5){[ordered]@{ready=$true;session=$session} | ConvertTo-Json -Compress;exit 0}
 Start-Sleep -Milliseconds 500
}
throw 'Guest console preflight timed out'
`

// This script is fixed code. All instance settings arrive in a JSON file,
// never interpolated into PowerShell, an SSH command, or a task argument.
const ControlScript = `param([ValidateSet('prepare','start','status','stop','diag')][string]$Mode)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$base='C:\ProgramData\Bivouac\Guest'
$helper='C:\ProgramData\Bivouac\Guest\bivouac.exe'
function Protect-Directory([string]$path) {
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetSecurityDescriptorSddlForm(('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')'))
  Set-Acl -LiteralPath $path -AclObject $acl
}
function Register-Interactive([string]$name,[string]$operation) {
  switch($operation) {
    'probe' {$arguments='guest windows probe'}
    'listener' {$arguments='guest windows listener'}
    'cancel' {$arguments='guest windows cancel'}
    default {throw 'Invalid task operation'}
  }
  $principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
  $action=New-ScheduledTaskAction -Execute $helper -Argument $arguments -WorkingDirectory $base
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Days 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Principal $principal -Action $action -Settings $settings -Force | Out-Null
}
function Wait-File([string]$path,[int]$seconds) {
  $until=[DateTime]::UtcNow.AddSeconds($seconds)
  while(!(Test-Path -LiteralPath $path)) {
    if([DateTime]::UtcNow -gt $until){throw 'Interactive guest operation timed out'}
    Start-Sleep -Milliseconds 200
  }
}
if($Mode -eq 'prepare') {
  $incoming=Get-Content -Raw -LiteralPath (Join-Path $HOME 'bivouac-config.json') | ConvertFrom-Json
  if($env:COMPUTERNAME -ine $incoming.native_name -or $env:USERNAME -ine $incoming.user){throw 'Guest identity differs'}
  if(Test-Path -LiteralPath (Join-Path $base 'config.json')) {
    $previous=Get-Content -Raw -LiteralPath (Join-Path $base 'config.json') | ConvertFrom-Json
    if($previous.runner_name -cne $incoming.runner_name -or $previous.controller_id -cne $incoming.controller_id){throw 'Guest bootstrap belongs to another instance'}
  }
  Protect-Directory $base
  Copy-Item -LiteralPath (Join-Path $HOME 'bivouac-helper.exe') -Destination $helper -Force
  Copy-Item -LiteralPath (Join-Path $HOME 'bivouac-config.json') -Destination (Join-Path $base 'config.json') -Force
  $adapters=@(Get-NetAdapter | Where-Object {$_.MacAddress -ieq $incoming.mac})
  if($adapters.Count -ne 1){throw 'Owned guest adapter missing or ambiguous'}
  $adapter=$adapters[0]
  Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled
  Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $incoming.address -PrefixLength $incoming.prefix -DefaultGateway $incoming.gateway | Out-Null
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @('1.1.1.1','8.8.8.8')
  if($incoming.archive) {
    $archive=Join-Path $HOME 'bivouac-runner.zip'
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ine $incoming.archive_sha256){throw 'Runner package hash differs'}
    if(Test-Path -LiteralPath $incoming.runner_dir){throw 'Archive provisioning requires a fresh runner directory'}
    Expand-Archive -LiteralPath $archive -DestinationPath $incoming.runner_dir
    Remove-Item -LiteralPath $archive
  }
  if(!(Test-Path -LiteralPath (Join-Path $incoming.runner_dir 'bin\Runner.Listener.exe'))){throw 'Generic official runner is not installed'}
  if((Test-Path -LiteralPath (Join-Path $incoming.runner_dir '.runner')) -or (Test-Path -LiteralPath (Join-Path $incoming.runner_dir '.credentials'))){throw 'Baseline contains a configured runner'}
  Register-Interactive 'bivouac-probe' 'probe'
  Register-Interactive 'bivouac-runner' 'listener'
  Register-Interactive 'bivouac-cancel' 'cancel'
  Start-ScheduledTask -TaskName 'bivouac-probe'
  Wait-File (Join-Path $base 'desktop.json') 45
  Get-Content -Raw -LiteralPath (Join-Path $base 'desktop.json')
  exit 0
}
if(!(Test-Path -LiteralPath (Join-Path $base 'config.json'))){throw 'Guest was not prepared'}
switch($Mode) {
  'start' {
    if((Test-Path -LiteralPath (Join-Path $base 'listener.json')) -or (Test-Path -LiteralPath (Join-Path $base 'runner.exit'))){throw 'Listener launch is single-use'}
    if(!(Test-Path -LiteralPath (Join-Path $base 'jit'))){throw 'Private JIT input is missing'}
    Start-ScheduledTask -TaskName 'bivouac-runner'
    Wait-File (Join-Path $base 'listener.json') 45
    'started'
  }
  'status' { & $helper guest windows status; if($LASTEXITCODE -ne 0){throw 'Guest status failed'} }
  'stop' {
    if(Test-Path -LiteralPath (Join-Path $base 'runner.exit')){exit 0}
    if(!(Test-Path -LiteralPath (Join-Path $base 'listener.json'))){exit 0}
    Start-ScheduledTask -TaskName 'bivouac-cancel'
    Wait-File (Join-Path $base 'cancelled') 30
    'cancel requested'
  }
  'diag' { & $helper guest windows diagnostics; if($LASTEXITCODE -ne 0){throw 'Guest diagnostics failed'} }
}
`
