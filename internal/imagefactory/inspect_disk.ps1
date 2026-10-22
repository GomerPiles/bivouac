$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$image=$null;$disk=$null;$partition=$null;$step=10;$code=0
$facts=[ordered]@{failure_step=0;system_hive_error=[uint32]::MaxValue;software_hive_error=[uint32]::MaxValue;sam_hive_error=[uint32]::MaxValue;system_setup_in_progress=[uint32]::MaxValue;oobe_in_progress=[uint32]::MaxValue;setup_phase=[uint32]::MaxValue;image_state_kind='unknown';unattend_pointer_kind='present_or_unknown';answer_directory_empty=$false;panther_answer_present=$false;panther_answer=$null;agent_service=$null;sshd_service=$null;executables=@{};vdd_present=$null;vdd_package_present=$null;runner_state='invalid';runner_residue=@{};runner_version='';bivouac_present=$false;bivouac_subdirectories=@();guest_state_present=$false;guest_user_exists=$null;guest_setup_step=0;guest_setup_failed=$false}
try {
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){throw 'identity'}
 $child=Join-Path $data.root $data.instance_id
 $expectedDisk=Join-Path $child 'disk.vhdx'
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw|ConvertFrom-Json
 if($data.disk -cne $expectedDisk -or $marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){throw 'ownership'}
 foreach($path in @($child,$expectedDisk)){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){throw 'attached'}
 $step=20
 $null=Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class FactoryInspection {
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenKey(IntPtr hive,string key,out IntPtr opened);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseKey(IntPtr key);
 public static bool Exists(IntPtr hive,string key) {IntPtr opened;uint error=OROpenKey(hive,key,out opened);if(error==2)return false;if(error!=0)throw new InvalidOperationException();try{return true;}finally{ORCloseKey(opened);}}
 public static string Text(IntPtr hive,string key,string value) {uint type,size=2048;byte[] data=new byte[2048];uint error=ORGetValue(hive,key,value,out type,data,ref size);if(error!=0 || (type!=1 && type!=2) || size<2 || size>2048) return "";return Encoding.Unicode.GetString(data,0,(int)size).TrimEnd('\0');}
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] public static extern uint OROpenHive(string path,out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] public static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORGetValue(IntPtr hive,string key,string value,out uint type,byte[] data,ref uint size);
 public static uint Number(IntPtr hive,string key,string value) {uint type,size=4;byte[] data=new byte[4];uint error=ORGetValue(hive,key,value,out type,data,ref size);return error==0 && type==4 && size==4?BitConverter.ToUInt32(data,0):uint.MaxValue;}
 public static string State(IntPtr hive) {uint type,size=256;byte[] data=new byte[256];uint error=ORGetValue(hive,"Microsoft\\Windows\\CurrentVersion\\Setup\\State","ImageState",out type,data,ref size);if(error!=0 || type!=1 || size>256 || size<2)return "unknown";return Encoding.Unicode.GetString(data,0,(int)size).TrimEnd('\0')=="IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE"?"generalized_to_oobe":"other";}
 public static string Pointer(IntPtr hive) {uint type,size=0;uint error=ORGetValue(hive,"Setup","UnattendFile",out type,null,ref size);if(error==2)return "absent";if(error!=0 || type!=1 || size>2)return "present_or_unknown";byte[] data=new byte[size];error=ORGetValue(hive,"Setup","UnattendFile",out type,data,ref size);return error==0 && Array.TrueForAll(data,b=>b==0)?"empty":"present_or_unknown";}
}
"@
 $mount=Join-Path $child 'inspect-mount'
 if(Test-Path -LiteralPath $mount){throw 'mount path'}
 $null=New-Item -ItemType Directory -Path $mount
 $access=$mount+'\'
 try {
  $step=30
  $image=Mount-DiskImage -ImagePath $expectedDisk -Access ReadWrite -NoDriveLetter -PassThru
  $disk=$image|Get-Disk
  $partition=Get-Partition -DiskNumber $disk.Number|Sort-Object Size -Descending|Select-Object -First 1
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access
  if($data.mode -eq 'setup'){
   $step=90;Read-SetupStep $mount $facts
  }else{
   $step=40
   foreach($relative in @('Windows','Windows\Panther','Windows\System32','Windows\System32\config','Windows\System32\config\SYSTEM','Windows\System32\config\SOFTWARE')){
    $path=Join-Path $mount $relative
    if(!(Test-Path -LiteralPath $path) -or ((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'child Windows path'}
   }
   $system=Join-Path $mount 'Windows\System32\config\SYSTEM'
   $software=Join-Path $mount 'Windows\System32\config\SOFTWARE'
   if((Get-Item -LiteralPath $system).Length -gt 256MB){throw 'system hive bound'}
   $hive=[IntPtr]::Zero
   $facts.system_hive_error=[FactoryInspection]::OROpenHive($system,[ref]$hive)
   if($facts.system_hive_error -eq 0){try{
    $facts.system_setup_in_progress=[FactoryInspection]::Number($hive,'Setup','SystemSetupInProgress')
    $facts.oobe_in_progress=[FactoryInspection]::Number($hive,'Setup','OOBEInProgress')
    $facts.setup_phase=[FactoryInspection]::Number($hive,'Setup','SetupPhase')
    $facts.unattend_pointer_kind=[FactoryInspection]::Pointer($hive)
    try{
     $current=[FactoryInspection]::Number($hive,'Select','Current')
     if($current -lt 1 -or $current -gt 999){throw 'control set'}
     $control='ControlSet'+$current.ToString('000')
     foreach($service in @(@('AppSandboxAgent','agent_service'),@('sshd','sshd_service'))){try{
     $key=$control+'\Services\'+$service[0]
     $fact=@{present=[FactoryInspection]::Exists($hive,$key);image_path='';image_path_redacted=$false}
     if($fact.present){
      $value=[FactoryInspection]::Text($hive,$key,'ImagePath')
      # Preserve ordinary service ImagePath data, never arbitrary arguments
      # that could contain a credential or a signed URL.
      Set-PublicImagePath $value $fact
     }
     $facts[$service[1]]=$fact
     }catch{}}
     $facts.vdd_present=[FactoryInspection]::Exists($hive,($control+'\Enum\ROOT\APPSANDBOXVDD'))
    }catch{}
   }finally{[void][FactoryInspection]::ORCloseHive($hive)}}
   $step=50
   $hive=[IntPtr]::Zero
   $facts.software_hive_error=[FactoryInspection]::OROpenHive($software,[ref]$hive)
   if($facts.software_hive_error -eq 0){try{$facts.image_state_kind=[FactoryInspection]::State($hive)}finally{[void][FactoryInspection]::ORCloseHive($hive)}}
   $step=60
   $answer=Join-Path $mount 'Windows\Panther\Unattend'
   if(!(Test-Path -LiteralPath $answer)){$facts.answer_directory_empty=$true}else{
    $item=Get-Item -Force -LiteralPath $answer
    $facts.answer_directory_empty=($item.PSIsContainer -and !($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and !@(Get-ChildItem -Force -LiteralPath $answer|Select-Object -First 1).Count)
   }
   try{$facts.panther_answer_present=Test-Path -LiteralPath (Join-Path $mount 'Windows\Panther\unattend.xml')}catch{}
   Read-PantherAnswerFacts $mount $data.guest_user $facts
   $step=70;Read-FactoryFiles $mount $facts
   $step=80
   if($data.guest_user -notmatch '^[a-zA-Z0-9_-]{1,20}$'){throw 'guest user'}
   try{
    $sam=Join-Path $mount 'Windows\System32\config\SAM'
    if(!(Test-OrdinaryFilePath $sam)){throw 'SAM unavailable'}
    $hive=[IntPtr]::Zero
    $facts.sam_hive_error=[FactoryInspection]::OROpenHive($sam,[ref]$hive)
    if($facts.sam_hive_error -eq 0){try{$facts.guest_user_exists=[FactoryInspection]::Exists($hive,('SAM\Domains\Account\Users\Names\'+$data.guest_user))}finally{[void][FactoryInspection]::ORCloseHive($hive)}}
   }catch{$facts.guest_user_exists=$null}
  }
 }finally{
  if($image){try{if($partition){$null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access}}finally{$null=Dismount-DiskImage -ImagePath $expectedDisk}}
 }
 $step=95
 if((Get-DiskImage -ImagePath $expectedDisk).Attached){throw 'still attached'}
 $null=Remove-Item -LiteralPath $mount
}catch{$code=$step;$facts.failure_step=$step}
[Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT')
[Console]::Out.WriteLine(($facts|ConvertTo-Json -Compress -Depth 8))
exit $code
