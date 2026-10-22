param($data)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$rotated=$false
$step=17
try {
 if($env:COMPUTERNAME -ine $data.name -or $env:USERNAME -ine $data.user) {exit 11}
 $step=19
 Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public static class SpikeConsole {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode)] public static extern bool WTSQuerySessionInformation(IntPtr server,uint session,int info,out IntPtr buffer,out int bytes);
 [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr buffer);
}
"@
 $step=20
 $consoleBudget=[Diagnostics.Stopwatch]::StartNew()
 $stable=0
 while($consoleBudget.Elapsed.TotalSeconds -lt 180) {
  $session=[SpikeConsole]::WTSGetActiveConsoleSessionId()
  $matched=$false;$buffer=[IntPtr]::Zero;$size=0
  if($session -ne 0 -and $session -ne [uint32]::MaxValue) {
   try {if([SpikeConsole]::WTSQuerySessionInformation([IntPtr]::Zero,$session,5,[ref]$buffer,[ref]$size)) {$matched=([Runtime.InteropServices.Marshal]::PtrToStringUni($buffer) -ieq $data.user)}}finally{if($buffer -ne [IntPtr]::Zero){[SpikeConsole]::WTSFreeMemory($buffer)}}
  }
  $setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
  $explorer=@(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session)
  if((!$data.require_setup -or (Test-Path -LiteralPath (Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-setup-complete.json'))) -and $matched -and $setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0 -and $explorer.Count){$stable++}else{$stable=0}
  if($stable -ge 5){break}
  Start-Sleep -Milliseconds 500
 }
 if($stable -lt 5){exit 12}
 $base='C:\ProgramData\Bivouac\Image\Probe'
 if(Test-Path -LiteralPath $base){exit 13}
 $step=21
 New-Item -ItemType Directory -Path $base | Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath $base -AclObject $acl
 if($data.prepared -eq $true){
  $marker=Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-prepared.json'
  if(!(Test-Path -LiteralPath $marker -PathType Leaf) -or ((Get-Item -LiteralPath $marker).Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-Item -LiteralPath $marker).Length -gt 4096){exit 21}
  $image=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
  if($image.name -ine $data.name -or $image.user -ine $data.user -or $image.probe_sha256 -ine $data.sha256 -or $image.validation_sha256 -ine $data.script_sha256 -or $image.autologon_sha256 -ine $data.autologon_sha256){exit 21}
  $secretHelper=Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-spike-autologon.ps1'
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
  try{if([SpikeAutoLogonSecret]::Store($password) -ne 0){throw 'Cannot protect clone autologon credential'}
  $logon.DeleteValue('DefaultPassword',$false)}finally{$logon.Dispose();$password=$null;[Array]::Clear($random,0,$random.Length)}
  $rotated=$true
 }
 $step=22
 $probe=Join-Path $base 'render.exe'
 Copy-Item -LiteralPath (Join-Path 'C:\ProgramData\Bivouac\Image' 'hcs-render-probe.exe') -Destination $probe
 if((Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash -ine $data.sha256){exit 14}
 # Read only fixed display/GPU-PV readiness facts. Never emit PnP identities,
 # device names, driver paths, or arbitrary WMI/PowerShell diagnostics.
 $step=26
 $gpuStatus=[ordered]@{valid=$false;display_count=0;virtual_count=0;problem_code=0}
 $gpuBudget=[Diagnostics.Stopwatch]::StartNew()
 do {
  try {
   $nodes=@(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Display'" -OperationTimeoutSec 10)
   $drivers=@(Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceClass='DISPLAY'" -OperationTimeoutSec 10)
   if($nodes.Count -gt 32 -or $drivers.Count -gt 32){throw 'device bound'}
   $virtual=@($drivers | Where-Object InfName -ieq 'vrd.inf')
   $problem=0
   foreach($driver in $virtual){
    $matching=@($nodes | Where-Object DeviceID -ieq $driver.DeviceID)
    if($matching.Count -ne 1 -or $null -eq $matching[0].ConfigManagerErrorCode -or $matching[0].ConfigManagerErrorCode -gt 255){throw 'device status'}
    $problem=[Math]::Max($problem,[int]$matching[0].ConfigManagerErrorCode)
   }
   $gpuStatus=[ordered]@{valid=$true;display_count=$nodes.Count;virtual_count=$virtual.Count;problem_code=$problem}
  }catch{$gpuStatus=[ordered]@{valid=$false;display_count=0;virtual_count=0;problem_code=0};break}
  if($gpuStatus.virtual_count -gt 0 -and $gpuStatus.problem_code -eq 0){break}
  Start-Sleep -Milliseconds 500
 }while($gpuBudget.Elapsed.TotalSeconds -lt 30)
 # Inline so the existing script pin covers the interactive topology probe.
 $step=28
 $topologyScript=@'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 Add-Type -ReferencedAssemblies @('System.Windows.Forms','System.Drawing') -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
public sealed class DesktopFacts {
 public bool topology_valid,virtual_equals_primary,probe_foreground,probe_on_primary,probe_input_received,security_window_found,security_on_primary;
 public uint active_display_count,primary_display_count,primary_width,primary_height,primary_adapter_kind;
}
public static class DesktopProbe {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Display {
  public uint cb;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string name;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string description;
  public uint flags;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string id;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=128)] public string key;
 }
 [StructLayout(LayoutKind.Sequential)] struct Rect { public int left,top,right,bottom; }
 [StructLayout(LayoutKind.Sequential)] struct Keyboard { public ushort vk,scan; public uint flags,time; public UIntPtr extra; }
 [StructLayout(LayoutKind.Sequential)] struct Mouse { public int x,y; public uint data,flags,time; public UIntPtr extra; }
 [StructLayout(LayoutKind.Explicit)] struct InputUnion { [FieldOffset(0)] public Keyboard keyboard; [FieldOffset(0)] public Mouse mouse; }
 [StructLayout(LayoutKind.Sequential)] struct Input { public uint type; public InputUnion value; }
 delegate bool WindowCallback(IntPtr window,IntPtr data);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool EnumDisplayDevices(string device,uint index,ref Display display,uint flags);
 [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
 [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
 [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window,out Rect bounds);
 [DllImport("user32.dll")] static extern uint SendInput(uint count,Input[] input,int size);
 [DllImport("user32.dll")] static extern bool EnumWindows(WindowCallback callback,IntPtr data);
 [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent,WindowCallback callback,IntPtr data);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll")] static extern bool PostMessage(IntPtr window,uint message,IntPtr wparam,IntPtr lparam);
 static bool Inside(IntPtr window,Rectangle area) {
  Rect r; return GetWindowRect(window,out r) && r.right>r.left && r.bottom>r.top && r.left>=area.Left && r.top>=area.Top && r.right<=area.Right && r.bottom<=area.Bottom;
 }
 static void Pump(int milliseconds) {
  Stopwatch budget=Stopwatch.StartNew();
  while(budget.ElapsedMilliseconds<milliseconds) { Application.DoEvents(); Thread.Sleep(20); }
 }
 static bool SecurityProcess(IntPtr window) {
  uint pid; GetWindowThreadProcessId(window,out pid);
  if(pid==0 || pid>Int32.MaxValue) return false;
  try { using(Process p=Process.GetProcessById((int)pid)) { return String.Equals(p.ProcessName,"SecHealthUI",StringComparison.OrdinalIgnoreCase); } } catch { return false; }
 }
 static IntPtr SecurityWindow() {
  IntPtr found=IntPtr.Zero; int count=0;
  EnumWindows(delegate(IntPtr window,IntPtr unused) {
   if(++count>1024) return false;
   if(!IsWindowVisible(window)) return true;
   bool match=SecurityProcess(window); int children=0;
   if(!match) EnumChildWindows(window,delegate(IntPtr child,IntPtr ignored) { if(++children>1024) return false; match=SecurityProcess(child); return !match; },IntPtr.Zero);
   if(match) { found=window; return false; } return true;
  },IntPtr.Zero);
  return found;
 }
 static uint PrimaryAdapterKind(string hardware,string deviceKey) {
  // Adapter entries expose their hardware ID directly. Consult the driver
  // registry key only when that ID is empty; never override a supplied ID.
  if(String.IsNullOrEmpty(hardware)) {
   const string prefix=@"\Registry\Machine\";
   if(deviceKey!=null && deviceKey.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)) {
    using(RegistryKey key=Registry.LocalMachine.OpenSubKey(deviceKey.Substring(prefix.Length))) {
     hardware=key==null ? null : key.GetValue("MatchingDeviceId") as string;
    }
   }
  }
  if(!String.IsNullOrEmpty(hardware) && hardware.Length<=1024) {
   if(hardware.IndexOf("DA0A7802",StringComparison.OrdinalIgnoreCase)>=0) return 1;
   if(String.Equals(hardware,@"ROOT\APPSANDBOXVDD",StringComparison.OrdinalIgnoreCase)) return 2;
  }
  return 3;
 }
 public static DesktopFacts Run() {
  SetProcessDPIAware();
  DesktopFacts facts=new DesktopFacts(); Screen primary=Screen.PrimaryScreen;
  if(primary==null) throw new InvalidOperationException();
  bool finished=false;
  for(uint i=0;i<32;i++) {
   Display d=new Display(); d.cb=(uint)Marshal.SizeOf(typeof(Display));
   if(!EnumDisplayDevices(null,i,ref d,0)) { finished=true; break; }
   if((d.flags&1)==0 || (d.flags&8)!=0) continue;
   facts.active_display_count++;
   if((d.flags&4)!=0) {
    facts.primary_display_count++;
    if(!String.Equals(d.name,primary.DeviceName,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException();
    facts.primary_adapter_kind=PrimaryAdapterKind(d.id,d.key);
   }
  }
  if(!finished || primary.Bounds.Width<=0 || primary.Bounds.Height<=0 || primary.Bounds.Width>65536 || primary.Bounds.Height>65536) throw new InvalidOperationException();
  facts.primary_width=(uint)primary.Bounds.Width; facts.primary_height=(uint)primary.Bounds.Height;
  facts.virtual_equals_primary=SystemInformation.VirtualScreen.Equals(primary.Bounds);
  using(Form window=new Form()) {
   window.Text="Bivouac display probe"; window.StartPosition=FormStartPosition.Manual; window.KeyPreview=true;
   window.Size=new Size(Math.Min(320,primary.WorkingArea.Width),Math.Min(200,primary.WorkingArea.Height));
   window.Location=new Point(primary.WorkingArea.Left+(primary.WorkingArea.Width-window.Width)/2,primary.WorkingArea.Top+(primary.WorkingArea.Height-window.Height)/2);
   bool received=false; window.KeyDown+=delegate(object sender,KeyEventArgs e) { if(e.KeyCode==Keys.F24) received=true; };
   window.Show(); window.BringToFront(); window.Activate(); SetForegroundWindow(window.Handle); Pump(500);
   facts.probe_foreground=GetForegroundWindow()==window.Handle;
   facts.probe_on_primary=Inside(window.Handle,primary.WorkingArea);
   if(facts.probe_foreground) {
    Input down=new Input(); down.type=1; down.value.keyboard.vk=0x87;
    Input up=down; up.value.keyboard.flags=2;
    bool sent=SendInput(2,new Input[]{down,up},Marshal.SizeOf(typeof(Input)))==2;
    Stopwatch inputBudget=Stopwatch.StartNew();
    while(!received && inputBudget.ElapsedMilliseconds<2000) Pump(20);
    facts.probe_input_received=sent && received;
   }
   window.Close();
  }
  IntPtr security=IntPtr.Zero;
  try {
   ProcessStartInfo start=new ProcessStartInfo("windowsdefender:"); start.UseShellExecute=true;
   using(Process launched=Process.Start(start)) { }
   Stopwatch securityBudget=Stopwatch.StartNew();
   while(security==IntPtr.Zero && securityBudget.ElapsedMilliseconds<15000) { Pump(200); security=SecurityWindow(); }
   facts.security_window_found=security!=IntPtr.Zero;
   facts.security_on_primary=security!=IntPtr.Zero && Inside(security,primary.Bounds);
  } catch { /* Windows Security facts are diagnostic, never a gate. */ }
  finally { if(security!=IntPtr.Zero) PostMessage(security,0x10,IntPtr.Zero,IntPtr.Zero); }
  facts.topology_valid=true; return facts;
 }
}
"@
 $facts=[DesktopProbe]::Run()
 # No PresentOnly: phantom VDD nodes count too.
 $nodes=@(Get-PnpDevice | Where-Object { $_.Class -eq 'Display' -or $_.InstanceId -like 'ROOT\APPSANDBOXVDD\*' })
 if($nodes.Count -gt 256){throw 'device bound'}
 $vdd=0;$hyperv=0;$enabled=$true;$started=$true
 foreach($node in $nodes){
  $ids=@((Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds').Data)
  if($node.InstanceId -like 'ROOT\APPSANDBOXVDD\*' -or 'ROOT\APPSANDBOXVDD' -in $ids){$vdd++}
  if(@($ids | Where-Object {$_ -like '*DA0A7802*'}).Count){
   $hyperv++
   $problem=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode').Data
   $status=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_DevNodeStatus').Data
   if($null -eq $problem -or $problem -eq 22){$enabled=$false}
   if($null -eq $problem -or $null -eq $status -or $problem -ne 0 -or !($status -band 8)){$started=$false}
  }
 }
 $facts | Add-Member -NotePropertyName vdd_node_count -NotePropertyValue ([uint32]$vdd)
 $facts | Add-Member -NotePropertyName hyperv_video_enabled -NotePropertyValue ([bool]($hyperv -gt 0 -and $enabled))
 $facts | Add-Member -NotePropertyName hyperv_video_started -NotePropertyValue ([bool]($hyperv -gt 0 -and $started))
 $json=$facts | ConvertTo-Json -Compress
 if([Text.Encoding]::UTF8.GetByteCount($json) -gt 4096){throw 'report bound'}
 [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'topology.pending'),$json,[Text.UTF8Encoding]::new($false))
 Move-Item -LiteralPath (Join-Path $PSScriptRoot 'topology.pending') -Destination (Join-Path $PSScriptRoot 'topology.json')
 exit 0
} catch {exit 29}
'@
 $topologyPath=Join-Path $base 'topology.ps1'
 [IO.File]::WriteAllText($topologyPath,$topologyScript,[Text.UTF8Encoding]::new($false))
 $topologyTask='bivouac-hcs-spike-topology'
 if(Get-ScheduledTask -TaskName $topologyTask -ErrorAction SilentlyContinue){exit 28}
 $principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
 # Task Scheduler exposes a structured action field; every argument is fixed.
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -STA -File C:\ProgramData\Bivouac\Image\Probe\topology.ps1' -WorkingDirectory $base
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $topologyTask -Principal $principal -Action $action -Settings $settings | Out-Null
 try {
  Start-ScheduledTask -TaskName $topologyTask
  $result=Join-Path $base 'topology.json'
  $budget=[Diagnostics.Stopwatch]::StartNew()
  while(!(Test-Path -LiteralPath $result)){
   if($budget.Elapsed.TotalSeconds -gt 50){exit 29}
   $info=Get-ScheduledTaskInfo -TaskName $topologyTask
   if($info.LastRunTime -gt (Get-Date).AddMinutes(-1) -and $info.LastTaskResult -eq 29){exit 29}
   Start-Sleep -Milliseconds 200
  }
  if((Get-Item -LiteralPath $result).Length -gt 4096){exit 29}
  $topology=Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
 } finally {
  Stop-ScheduledTask -TaskName $topologyTask -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $topologyTask -Confirm:$false
  foreach($name in @('topology.ps1','topology.json','topology.pending')){
   $path=Join-Path $base $name
   if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
  }
 }
 $step=23
 $task='bivouac-hcs-spike-render'
 if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){exit 15}
 $principal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
 $action=New-ScheduledTaskAction -Execute $probe -WorkingDirectory $base
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $task -Principal $principal -Action $action -Settings $settings | Out-Null
 try {
  $step=24
  Start-ScheduledTask -TaskName $task
  $result=Join-Path $base 'render.json'
  $probeBudget=[Diagnostics.Stopwatch]::StartNew()
  while(!(Test-Path -LiteralPath $result)) {if($probeBudget.Elapsed.TotalSeconds -gt 50){exit 16};Start-Sleep -Milliseconds 200}
  $step=25
  if((Get-Item -LiteralPath $result).Length -gt 4096){exit 25}
  $observed=Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
  # Emit only fixed booleans/numbers; no guest-controlled text or filesystem dump.
  $report=[ordered]@{credential_rotated=[bool]$rotated;guest_ready=$true;desktop_ready=($observed.desktop_ready -eq $true);hardware_d3d11=($observed.hardware_d3d11 -eq $true);presented=($observed.presented -eq $true);pixel_readback=($observed.pixel_readback -eq $true);stage=[uint32]$observed.stage;hresult=[uint32]$observed.hresult;vendor_id=[uint32]$observed.vendor_id;device_id=[uint32]$observed.device_id;adapter_count=[uint32]$observed.adapter_count;hardware_adapter_count=[uint32]$observed.hardware_adapter_count;default_vendor_id=[uint32]$observed.default_vendor_id;default_device_id=[uint32]$observed.default_device_id;gpu_device_diagnostics_valid=[bool]$gpuStatus.valid;display_device_count=[uint32]$gpuStatus.display_count;virtual_render_device_count=[uint32]$gpuStatus.virtual_count;virtual_render_problem_code=[uint32]$gpuStatus.problem_code}
  foreach($field in @('topology_valid','virtual_equals_primary','hyperv_video_enabled','hyperv_video_started','probe_foreground','probe_on_primary','probe_input_received','security_window_found','security_on_primary')){
   if($topology.$field -isnot [bool]){exit 29}
   $report[$field]=[bool]$topology.$field
  }
  foreach($field in @('active_display_count','primary_display_count','primary_width','primary_height','primary_adapter_kind','vdd_node_count')){
   $report[$field]=[uint32]$topology.$field
  }
  $report=$report | ConvertTo-Json -Compress -Depth 3
  if([Text.Encoding]::UTF8.GetByteCount($report) -gt 8192){exit 25}
  [Console]::Out.Write($report)
  [Console]::Out.Flush()
 } finally {Unregister-ScheduledTask -TaskName $task -Confirm:$false}
 exit 0
} catch {exit $step}
