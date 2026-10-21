$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$image=$null;$disk=$null;$partition=$null
try {
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){exit 1}
 $child=Join-Path $data.root $data.instance_id
 $expectedDisk=Join-Path $child 'disk.vhdx'
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw|ConvertFrom-Json
 if($data.disk -cne $expectedDisk -or $marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){exit 1}
 foreach($path in @($child,$expectedDisk)){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1}}
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){exit 1}
 Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class FactoryInspection {
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] public static extern uint OROpenHive(string path,out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] public static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORGetValue(IntPtr hive,string key,string value,out uint type,byte[] data,ref uint size);
 public static uint Number(IntPtr hive,string key,string value) {uint type,size=4;byte[] data=new byte[4];uint error=ORGetValue(hive,key,value,out type,data,ref size);return error==0 && type==4 && size==4?BitConverter.ToUInt32(data,0):uint.MaxValue;}
 public static string State(IntPtr hive) {uint type,size=256;byte[] data=new byte[256];uint error=ORGetValue(hive,"Microsoft\\Windows\\CurrentVersion\\Setup\\State","ImageState",out type,data,ref size);if(error!=0 || type!=1 || size>256 || size<2)return "unknown";return Encoding.Unicode.GetString(data,0,(int)size).TrimEnd('\0')=="IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE"?"generalized_to_oobe":"other";}
 public static string Pointer(IntPtr hive) {uint type,size=0;uint error=ORGetValue(hive,"Setup","UnattendFile",out type,null,ref size);if(error==2)return "absent";if(error!=0 || type!=1 || size>2)return "present_or_unknown";byte[] data=new byte[size];error=ORGetValue(hive,"Setup","UnattendFile",out type,data,ref size);return error==0 && Array.TrueForAll(data,b=>b==0)?"empty":"present_or_unknown";}
}
"@
 $mount=Join-Path $child 'inspect-mount'
 if(Test-Path -LiteralPath $mount){exit 1}
 New-Item -ItemType Directory -Path $mount|Out-Null
 $access=$mount+'\'
 $facts=[ordered]@{system_hive_error=[uint32]::MaxValue;software_hive_error=[uint32]::MaxValue;system_setup_in_progress=[uint32]::MaxValue;oobe_in_progress=[uint32]::MaxValue;setup_phase=[uint32]::MaxValue;image_state_kind='unknown';unattend_pointer_kind='present_or_unknown';answer_directory_empty=$false;panther_answer_present=$false}
 try {
  $image=Mount-DiskImage -ImagePath $expectedDisk -Access ReadOnly -NoDriveLetter -PassThru
  $disk=$image|Get-Disk
  $partition=Get-Partition -DiskNumber $disk.Number|Sort-Object Size -Descending|Select-Object -First 1
  Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access
  foreach($relative in @('Windows','Windows\Panther','Windows\System32','Windows\System32\config','Windows\System32\config\SYSTEM','Windows\System32\config\SOFTWARE')){
   $path=Join-Path $mount $relative
   if(!(Test-Path -LiteralPath $path) -or ((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'child Windows path'}
  }
  $system=Join-Path $mount 'Windows\System32\config\SYSTEM'
  $software=Join-Path $mount 'Windows\System32\config\SOFTWARE'
  if((Get-Item -LiteralPath $system).Length -gt 256MB -or (Get-Item -LiteralPath $software).Length -gt 256MB){throw 'hive bound'}
  $hive=[IntPtr]::Zero
  $facts.system_hive_error=[FactoryInspection]::OROpenHive($system,[ref]$hive)
  if($facts.system_hive_error -eq 0){try{
   $facts.system_setup_in_progress=[FactoryInspection]::Number($hive,'Setup','SystemSetupInProgress')
   $facts.oobe_in_progress=[FactoryInspection]::Number($hive,'Setup','OOBEInProgress')
   $facts.setup_phase=[FactoryInspection]::Number($hive,'Setup','SetupPhase')
   $facts.unattend_pointer_kind=[FactoryInspection]::Pointer($hive)
  }finally{[void][FactoryInspection]::ORCloseHive($hive)}}
  $hive=[IntPtr]::Zero
  $facts.software_hive_error=[FactoryInspection]::OROpenHive($software,[ref]$hive)
  if($facts.software_hive_error -eq 0){try{$facts.image_state_kind=[FactoryInspection]::State($hive)}finally{[void][FactoryInspection]::ORCloseHive($hive)}}
  $answer=Join-Path $mount 'Windows\Panther\Unattend'
  if(!(Test-Path -LiteralPath $answer)){$facts.answer_directory_empty=$true}else{
   $item=Get-Item -Force -LiteralPath $answer
   $facts.answer_directory_empty=($item.PSIsContainer -and !($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and !@(Get-ChildItem -Force -LiteralPath $answer|Select-Object -First 1).Count)
  }
  $facts.panther_answer_present=Test-Path -LiteralPath (Join-Path $mount 'Windows\Panther\unattend.xml')
 }finally{
  if($image){try{if($partition){Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access}}finally{Dismount-DiskImage -ImagePath $expectedDisk}}
 }
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){exit 1}
 Remove-Item -LiteralPath $mount
 [Console]::Out.Write(($facts|ConvertTo-Json -Compress));exit 0
}catch{exit 1}
