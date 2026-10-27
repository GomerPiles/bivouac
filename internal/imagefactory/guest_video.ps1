# Shared by specialize and FirstLogon; definitions only, no host operations.
function Initialize-VideoRegistry {
 if('BivouacVideoRegistry' -as [type]){return}
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
public static class BivouacVideoRegistry {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
 static extern int RegOpenKeyEx(SafeRegistryHandle parent, string name, uint options, int access, out SafeRegistryHandle key);
 // The two fixed OS aliases (CurrentControlSet / Hardware Profiles\Current)
 // are intentional. Every device-controlled path component is opened without
 // following registry links and checked; the device keys stay pinned for writes.
 // REG_OPTION_OPEN_LINK: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/d5ce9dcc-1f90-4f5a-b076-cc1d2c9b4195
 static RegistryKey Open(RegistryKey parent, string name, bool write, bool optional) {
  SafeRegistryHandle handle;
  int rc=RegOpenKeyEx(parent.Handle,name,8,write ? 3 : 1,out handle);
  if(rc!=0){if(handle!=null)handle.Dispose();if(optional && rc==2)return null;throw new InvalidOperationException("registry open");}
  var key=RegistryKey.FromHandle(handle);
  try {if(Array.Exists(key.GetValueNames(),v=>String.Equals(v,"SymbolicLinkValue",StringComparison.OrdinalIgnoreCase)))throw new InvalidOperationException("registry link");return key;}
  catch {key.Dispose();throw;}
 }
 static RegistryKey Device(RegistryKey root,string[] parts,bool write,bool optional) {
  RegistryKey current=null;
  try {foreach(var part in parts){var next=Open(current ?? root,part,write,optional);if(current!=null)current.Dispose();current=next;if(next==null)return null;}return current;}
  catch {if(current!=null)current.Dispose();throw;}
 }
 static uint[] Flags(RegistryKey key,string name,bool clear) {
  if(key==null || !Array.Exists(key.GetValueNames(),v=>String.Equals(v,name,StringComparison.OrdinalIgnoreCase)))return new uint[]{0,0};
  if(key.GetValueKind(name)!=RegistryValueKind.DWord)throw new InvalidOperationException("registry flags type");
  uint flags=unchecked((uint)(int)key.GetValue(name));
  if(clear && (flags&1)!=0)key.SetValue(name,unchecked((int)ClearDisabled(flags)),RegistryValueKind.DWord);
  return new uint[]{1,flags};
 }
 public static uint ClearDisabled(uint flags){return flags&~1u;}
 public static uint[] Read(string id,bool clear) {
  if(id==null || id.Length>512)throw new InvalidOperationException("device identity");
  string[] parts=id.Split('\\');
  if(parts.Length!=3)throw new InvalidOperationException("device identity");
  foreach(var part in parts)if(part=="." || part==".." || !System.Text.RegularExpressions.Regex.IsMatch(part,@"\A[A-Za-z0-9_&{}.+#-]{1,200}\z"))throw new InvalidOperationException("device identity");
  using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))
  using(var global=machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum",false)) {
   if(global==null)throw new InvalidOperationException("device root");
   using(var device=Device(global,parts,clear,false)) {
    var ids=device.GetValue("HardwareID") as string[];
    if(ids==null || ids.Length>64 || !Array.Exists(ids,v=>v!=null && v.IndexOf("DA0A7802",StringComparison.OrdinalIgnoreCase)>=0))throw new InvalidOperationException("device hardware identity");
    using(var profile=machine.OpenSubKey(@"SYSTEM\CurrentControlSet\Hardware Profiles\Current\System\CurrentControlSet\Enum",false))
    using(var config=profile==null ? null : Device(profile,parts,clear,true)) {
     // Check both value types before changing either one. Never create keys or values.
     var a=Flags(device,"ConfigFlags",false);var b=Flags(config,"CSConfigFlags",false);
     if(clear){Flags(device,"ConfigFlags",true);Flags(config,"CSConfigFlags",true);}
     return new uint[]{a[0],a[1],b[0],b[1]};
    }
   }
  }
 }
}
'@ | Out-Null
}
function Get-VideoNodes {
 # No class or PresentOnly filter: include every matching phantom node too.
 $nodes=@(Get-PnpDevice | Where-Object {
  $ids=@((Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data)
  @($ids | Where-Object {$_ -like '*DA0A7802*'}).Count -gt 0
 } | Sort-Object InstanceId)
 if($nodes.Count -gt 32){throw 'video device bound'}
 $script:videoSnapshotIDs=@($nodes.InstanceId)
 return $nodes
}
function Get-VideoSnapshot {
 Initialize-VideoRegistry
 $nodes=@(Get-VideoNodes);$facts=@()
 foreach($node in $nodes){
  $flags=[BivouacVideoRegistry]::Read($node.InstanceId,$false)
  $present=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_IsPresent').Data
  $problem=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_ProblemCode').Data
  $status=(Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName 'DEVPKEY_Device_DevNodeStatus').Data
  if($null -eq $present -or $null -eq $problem -or $null -eq $status){throw 'video properties unavailable'}
  $facts+=@{present=[uint32][bool]$present;problem_code=[uint32]$problem;devnode_status=[uint32]$status;config_flags_present=$flags[0];config_flags=$flags[1];csconfig_flags_present=$flags[2];csconfig_flags=$flags[3]}
 }
 return @{node_count=[uint32]$nodes.Count;nodes=@($facts)}
}
function Enable-VideoNodes($Snapshot,[bool]$OnlyDisabled){
 Initialize-VideoRegistry
 $script:videoEnableResult=@{returned=[uint32]0;attempts=@()}
 $expected=@($script:videoSnapshotIDs)
 $nodes=@(Get-VideoNodes)
 if($nodes.Count -ne $Snapshot.node_count){throw 'video identity changed'}
 for($i=0;$i -lt $nodes.Count;$i++){if($nodes[$i].InstanceId -cne $expected[$i]){throw 'video identity changed'}}
 $attempts=@();$allReturned=[uint32]1
 for($i=0;$i -lt $nodes.Count;$i++){
  if($OnlyDisabled -and $Snapshot.nodes[$i].problem_code -ne 22){continue}
  $attempt=@{node_index=[uint32]$i;flags_cleared=[uint32]0;pnputil_started=[uint32]0;pnputil_exit_code=[uint32]0;fallback_attempted=[uint32]0;fallback_succeeded=[uint32]0;returned=[uint32]0}
  $attempts+=$attempt
  # Publish partial results even if a registry or supported API operation fails.
  $script:videoEnableResult=@{returned=[uint32]0;attempts=@($attempts)}
  $null=[BivouacVideoRegistry]::Read($nodes[$i].InstanceId,$true)
  $attempt.flags_cleared=[uint32]1
  try{
   & (Join-Path $env:SystemRoot 'System32\pnputil.exe') @('/enable-device',$nodes[$i].InstanceId) *> $null
   $attempt.pnputil_started=[uint32]1
   $attempt.pnputil_exit_code=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$LASTEXITCODE),0)
  }catch{}
  if($attempt.pnputil_started -eq 1 -and $attempt.pnputil_exit_code -in @(0,3010)){$attempt.returned=[uint32]1}
  else{
   $attempt.fallback_attempted=[uint32]1
   try{Enable-PnpDevice -InstanceId $nodes[$i].InstanceId -Confirm:$false -ErrorAction Stop | Out-Null;$attempt.fallback_succeeded=[uint32]1;$attempt.returned=[uint32]1}catch{$allReturned=[uint32]0}
  }
 }
 $script:videoEnableResult=@{returned=$allReturned;attempts=@($attempts)}
}
