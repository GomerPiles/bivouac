$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$image=$null;$partition=$null;$disk=$null;$phaseCode=10;$aclError=0
function Assert-EmptyAnswerDirectory([string]$Path) {
 if(!(Test-Path -LiteralPath $Path)){return}
 $item=Get-Item -LiteralPath $Path -Force
 if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @(Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1).Count){throw 'Embedded answer directory must be empty and ordinary'}
}
try {
 $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
 if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit $phaseCode}
 $data=[Console]::In.ReadToEnd() | ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){exit $phaseCode}
 $child=Join-Path $data.root $data.instance_id
 $expectedDisk=Join-Path $child 'disk.vhdx'
 if($data.disk -cne $expectedDisk -or ((Get-Item -LiteralPath $child).Attributes -band [IO.FileAttributes]::ReparsePoint) -or ((Get-Item -LiteralPath $expectedDisk).Attributes -band [IO.FileAttributes]::ReparsePoint)){exit $phaseCode}
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw | ConvertFrom-Json
 if($marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){exit $phaseCode}
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){exit $phaseCode}
 $phaseCode=20
 $null=Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public static class SpikeOfflineAnswer {
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenHive(string path,out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORGetValue(IntPtr hive,string key,string value,out uint type,byte[] data,ref uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("advapi32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint SetNamedSecurityInfo(string path,int kind,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("kernel32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern IntPtr LocalFree(IntPtr memory);
 public static uint ProtectDirectory(string path,string text) {
  IntPtr descriptor;uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out size))return (uint)Marshal.GetLastWin32Error();
  try{bool present,defaulted;IntPtr dacl;if(!GetSecurityDescriptorDacl(descriptor,out present,out dacl,out defaulted))return (uint)Marshal.GetLastWin32Error();if(!present || dacl==IntPtr.Zero)return 87;return SetNamedSecurityInfo(path,1,0x80000004,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);}finally{LocalFree(descriptor);}
 }
 public static bool NoExplicitAnswer(string path) {
  IntPtr hive;uint error=OROpenHive(path,out hive);if(error!=0)return false;
  try{uint type=0,size=0;error=ORGetValue(hive,"Setup","UnattendFile",out type,null,ref size);if(error==2)return true;if(error!=0 || type!=1 || size>2)return false;byte[] data=new byte[size];error=ORGetValue(hive,"Setup","UnattendFile",out type,data,ref size);return error==0 && Array.TrueForAll(data,b=>b==0);}finally{ORCloseHive(hive);}
 }
}
"@
 $mount=Join-Path $child 'setup-private\mount'
 if(Test-Path -LiteralPath $mount){exit $phaseCode}
 New-Item -ItemType Directory -Path $mount | Out-Null
 $access=$mount+'\'
 try {
  $phaseCode=30
  $image=Mount-DiskImage -ImagePath $expectedDisk -Access ReadWrite -NoDriveLetter -PassThru
  $disk=$image | Get-Disk
  if($disk.IsReadOnly -or $disk.IsOffline){throw 'Owned child is not online read-write'}
  $partitions=@(Get-Partition -DiskNumber $disk.Number | Where-Object Guid -eq $data.windows_guid)
  if($data.windows_guid -notmatch '^\{[0-9a-fA-F-]{36}\}$' -or $partitions.Count -ne 1){throw 'Windows partition identity'}
  $partition=$partitions[0]
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access
  $phaseCode=40
  foreach($relative in @('Windows','Windows\Setup','Windows\System32','Windows\System32\config','Windows\System32\config\SYSTEM','Program Files','ProgramData')){
   $path=Join-Path $mount $relative
   if(!(Test-Path -LiteralPath $path) -or ((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Expected child Windows path unavailable'}
  }
  $phaseCode=50
  $system=Join-Path $mount 'Windows\System32\config\SYSTEM'
  if((Get-Item -LiteralPath $system).Length -gt 256MB -or ![SpikeOfflineAnswer]::NoExplicitAnswer($system)){throw 'Offline explicit answer pointer must be absent'}
  # Only an absent or empty embedded answer directory is accepted;
  # any existing parent must be ordinary before examining its children.
  $phaseCode=60
  $answerDirectory=Join-Path $mount 'Windows\Panther\Unattend'
  Assert-OfflinePath $mount $answerDirectory
  Assert-EmptyAnswerDirectory $answerDirectory
  $phaseCode=61
  Initialize-OfflineSetupDirectories $mount
  $phaseCode=62
  # Apply only the protected DACL; PowerShell Set-Acl can also touch audit/owner
  # sections inherited from the guest image, which are outside this operation.
  $aclError=[SpikeOfflineAnswer]::ProtectDirectory($answerDirectory,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  if($aclError -ne 0){throw 'Cannot protect child answer directory'}
  $phaseCode=63
  foreach($entry in @(@('specialize.ps1',$data.specialize),@('unattend.xml',$data.unattend))){
   $file=Join-Path $answerDirectory $entry[0]
   $content=[Text.Encoding]::UTF8.GetBytes($entry[1])
   $output=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$output.Write($content,0,$content.Length);$output.Flush($true)}finally{$output.Dispose();[Array]::Clear($content,0,$content.Length)}
  }
  $phaseCode=64
  Install-OfflineAgent $mount $data.agent $data.agent_sha256
  $phaseCode=65
  Copy-OfflineDrivers $mount (Join-Path $child 'drivers') ($data.driver_plan | ConvertFrom-Json)
  $phaseCode=66
  $encryption=Set-OfflineEncryptionPolicy $mount
  if($encryption -ne 0){$phaseCode=66000+[int]$encryption;throw 'offline device encryption policy'}
 } finally {
  if($image){try{if($partition){$null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access}}finally{$null=Dismount-DiskImage -ImagePath $expectedDisk}}
 }
 $phaseCode=70
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){exit $phaseCode}
 exit 0
} catch {
 if($phaseCode -eq 62 -and $aclError -gt 0 -and $aclError -le 65535){exit (10000+[int]$aclError)}
 # Offline payload failures report the failing line of this fixed script
 # (offline payload followed by staging), never error text: phase*100000+line.
 $line=$_.InvocationInfo.ScriptLineNumber
 if($phaseCode -in @(64,65) -and $line -gt 0 -and $line -lt 100000){exit ($phaseCode*100000+[int]$line)}
 exit $phaseCode
}
