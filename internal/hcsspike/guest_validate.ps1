param($data)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=17
Write-SpikeStep 17
try {
 if($env:COMPUTERNAME -ine $data.name -or $env:USERNAME -ine $data.user) {exit 11}
 $step=19
 Write-SpikeStep 19
 Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public static class SpikeConsole {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode)] public static extern bool WTSQuerySessionInformation(IntPtr server,uint session,int info,out IntPtr buffer,out int bytes);
 [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr buffer);
}
"@
 $step=20
 Write-SpikeStep 20
 $until=[DateTime]::UtcNow.AddMinutes(3)
 $stable=0
 while([DateTime]::UtcNow -lt $until) {
  $session=[SpikeConsole]::WTSGetActiveConsoleSessionId()
  $matched=$false;$buffer=[IntPtr]::Zero;$size=0
  if($session -ne 0 -and $session -ne [uint32]::MaxValue) {
   try {if([SpikeConsole]::WTSQuerySessionInformation([IntPtr]::Zero,$session,5,[ref]$buffer,[ref]$size)) {$matched=([Runtime.InteropServices.Marshal]::PtrToStringUni($buffer) -ieq $data.user)}}finally{if($buffer -ne [IntPtr]::Zero){[SpikeConsole]::WTSFreeMemory($buffer)}}
  }
  $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
  $explorer=@(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session)
  if((!$data.require_setup -or (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'AppSandbox\hcs-spike-setup-complete.json'))) -and $matched -and $setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0 -and $explorer.Count){$stable++}else{$stable=0}
  if($stable -ge 5){break}
  Start-Sleep -Milliseconds 500
 }
 if($stable -lt 5){exit 12}
 $base='C:\ProgramData\BivouacHcsSpike'
 if(Test-Path -LiteralPath $base){exit 13}
 $step=21
 Write-SpikeStep 21
 New-Item -ItemType Directory -Path $base | Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath $base -AclObject $acl
 $step=22
 Write-SpikeStep 22
 $probe=Join-Path $base 'render.exe'
 [IO.File]::WriteAllBytes($probe,[Convert]::FromBase64String($data.probe))
 if((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ine $data.sha256){exit 14}
 $step=23
 Write-SpikeStep 23
 $task='bivouac-hcs-spike-render'
 if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){exit 15}
 $principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
 $action=New-ScheduledTaskAction -Execute $probe -WorkingDirectory $base
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $task -Principal $principal -Action $action -Settings $settings | Out-Null
 try {
  $step=24
  Write-SpikeStep 24
  Start-ScheduledTask -TaskName $task
  $result=Join-Path $base 'render.json'
  $until=[DateTime]::UtcNow.AddSeconds(50)
  while(!(Test-Path -LiteralPath $result)) {if([DateTime]::UtcNow -gt $until){exit 16};Start-Sleep -Milliseconds 200}
  $step=25
  Write-SpikeStep 25
  $observed=Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
  # Emit only fixed booleans/numbers; no guest-controlled text or filesystem dump.
  [ordered]@{guest_ready=$true;desktop_ready=($observed.desktop_ready -eq $true);hardware_d3d11=($observed.hardware_d3d11 -eq $true);presented=($observed.presented -eq $true);pixel_readback=($observed.pixel_readback -eq $true);stage=[uint32]$observed.stage;hresult=[uint32]$observed.hresult;vendor_id=[uint32]$observed.vendor_id;device_id=[uint32]$observed.device_id} | ConvertTo-Json -Compress
 } finally {Unregister-ScheduledTask -TaskName $task -Confirm:$false}
 exit 0
} catch {exit $step}
