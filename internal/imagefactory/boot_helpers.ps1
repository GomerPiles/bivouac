# Helpers for the owned, freshly applied disk only. No host boot files or store.
function Assert-BootPath([string]$Root,[string]$Path){
 if(!$Path.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'boot path outside volume'}
 $relative=$Path.Substring($Root.Length+1);$current=$Root
 foreach($name in $relative.Split('\')){
  if(!$name -or $name -in @('.','..')){throw 'boot path component'}
  $current=Join-Path $current $name
  if((Test-Path -LiteralPath $current) -and ((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'boot path link'}
 }
}
function Copy-BootFiles([string]$Windows,[string]$ESP){
 $required=@('Windows\Boot\EFI\bootmgfw.efi','Windows\Boot\EFI\bootmgr.efi','Windows\Boot\EFI\memtest.efi','Windows\Boot\EFI\SecureBootRecovery.efi','Windows\Boot\EFI\boot.pnd.stl','Windows\Boot\Fonts\wgl4_boot.ttf','Windows\Boot\Resources\bootres.dll','Windows\System32\winload.efi')
 foreach($name in $required){$path=Join-Path $Windows $name;Assert-BootPath $Windows $path;if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw 'required boot source absent'}}
 $plan=@();$dirs=@('EFI','EFI\Boot','EFI\Microsoft','EFI\Microsoft\Boot','EFI\Microsoft\Recovery')
 [long]$bytes=0;$entries=0
 foreach($name in @('Windows\Boot\EFI\bootmgfw.efi','Windows\Boot\EFI\boot.pnd.stl')){$bytes+=(Get-Item -LiteralPath (Join-Path $Windows $name)).Length}
 # EFI_EX is a sibling excluded by the fixed EFI/Fonts/Resources source roots.
 foreach($tree in @(@('EFI',''),@('Fonts','Fonts'),@('Resources','Resources'))){
  if($tree[1]){$dirs+='EFI\Microsoft\Boot\'+$tree[1]}
  $source=Join-Path $Windows ('Windows\Boot\'+$tree[0])
  $queue=[Collections.Generic.Queue[object]]::new();$queue.Enqueue(@($source,$tree[1],0))
  while($queue.Count){
   $row=$queue.Dequeue();Assert-BootPath $Windows $row[0]
   if($row[2] -gt 8){throw 'boot directory depth'}
   foreach($item in @(Get-ChildItem -Force -LiteralPath $row[0])){
    $entries++;if($entries -gt 4096 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'boot tree link or bound'}
    $relative=$item.Name;if($row[1]){$relative=$row[1]+'\'+$relative}
    $target='EFI\Microsoft\Boot\'+$relative
    if($item.PSIsContainer){$dirs+=$target;$queue.Enqueue(@($item.FullName,$relative,($row[2]+1)))}else{
     $bytes+=$item.Length;if($item.Length -gt 32MB -or $bytes -gt 160MB -or $plan.Count -ge 2048){throw 'boot files bound'}
     $plan+=@{source=$item.FullName;target=$target;length=$item.Length}
    }
   }
  }
 }
 $efi=Join-Path $ESP 'EFI';Assert-BootPath $ESP $efi
 if(Test-Path -LiteralPath $efi){throw 'boot destination already exists'}
 # Validate the entire source inventory before publishing any files.
 foreach($name in $dirs){$path=Join-Path $ESP $name;Assert-BootPath $ESP $path;$null=New-Item -ItemType Directory -Path $path -Force}
 foreach($file in $plan){
  Assert-BootPath $Windows $file.source;$target=Join-Path $ESP $file.target;Assert-BootPath $ESP $target
  [IO.File]::Copy($file.source,$target,$false)
  if((Get-Item -LiteralPath $target).Length -ne $file.length){throw 'boot copy incomplete'}
 }
 [IO.File]::Copy((Join-Path $Windows 'Windows\Boot\EFI\bootmgfw.efi'),(Join-Path $ESP 'EFI\Boot\bootx64.efi'),$false)
 # The ESP is new: the pending revocation policy becomes the active boot.stl.
 [IO.File]::Copy((Join-Path $Windows 'Windows\Boot\EFI\boot.pnd.stl'),(Join-Path $ESP 'EFI\Microsoft\Boot\boot.stl'),$true)
}
function Initialize-BootRegistry{
 if('FactoryBoot' -as [type]){return}
 $null=Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class FactoryBoot {
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenHive(string path,out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenKey(IntPtr hive,string path,out IntPtr key);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseKey(IntPtr key);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORGetValue(IntPtr hive,string key,string value,out uint type,byte[] data,ref uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OREnumKey(IntPtr key,uint index,StringBuilder name,ref uint length,IntPtr cls,IntPtr clsLength,IntPtr time);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCreateKey(IntPtr key,string sub,string cls,uint options,IntPtr security,out IntPtr created,out uint disposition);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSetValue(IntPtr key,string name,uint type,byte[] value,uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSaveHive(IntPtr hive,string path,uint major,uint minor);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool MoveFileEx(string from,string to,uint flags);
 static byte[] Read(IntPtr hive,string key,string value,uint expected) {
  uint type,size=4096;byte[] data=new byte[4096];
  if(ORGetValue(hive,key,value,out type,data,ref size)!=0 || type!=expected || size>4096)return null;
  Array.Resize(ref data,(int)size);return data;
 }
 static byte[] Element(IntPtr h,string id,string element) {return Read(h,"Objects\\"+id+"\\Elements\\"+element,"Element",3);}
 static string StringElement(IntPtr h,string id,string element) {return Text(Read(h,"Objects\\"+id+"\\Elements\\"+element,"Element",1));}
 static string Text(byte[] b) {return b!=null && b.Length>=2 && b.Length%2==0 && b[b.Length-1]==0 && b[b.Length-2]==0?Encoding.Unicode.GetString(b,0,b.Length-2):"";}
 static bool Exists(IntPtr h,string id) {IntPtr k;uint e=OROpenKey(h,"Objects\\"+id,out k);if(e!=0)return false;ORCloseKey(k);return true;}
 static bool Same(byte[] a,byte[] b) {if(a==null || b==null || a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 // Plain GPT partition device, confirmed against a bootable offline store.
 // No nested VHD/file-path device is valid inside the resulting guest.
 public static byte[] PartitionDevice(Guid disk,Guid part) {
  if(disk==Guid.Empty || part==Guid.Empty)throw new ArgumentException();
  byte[] b=new byte[88];b[0x10]=6;b[0x18]=0x48;
  part.ToByteArray().CopyTo(b,0x20);disk.ToByteArray().CopyTo(b,0x38);return b;
 }
 static bool Device(byte[] b,Guid disk,Guid part) {return Same(b,PartitionDevice(disk,part));}
 // Mutations affect the in-memory offline hive only until the complete new
 // hive is saved to a fresh sibling and atomically replaces the owned store.
 // Codes: 1 open, 2 occupied sibling, 3 missing parent, 4 existing element,
 // 5 create, 6 value, 7 save, 8 replace, 9 identity, 10 unexpected failure.
 public static uint WriteDevices(string path,string loader,string disk,string esp,string windows) {
  string next=path+".plain-gpt";IntPtr h=IntPtr.Zero;
  try{
   Guid d,e,w,l;
   if(!Guid.TryParse(disk,out d) || !Guid.TryParse(esp,out e) || !Guid.TryParse(windows,out w) || !Guid.TryParse(loader,out l) || d==Guid.Empty || e==Guid.Empty || w==Guid.Empty || l==Guid.Empty || e==w || l==new Guid("{9dea862c-5cdd-4e70-acc1-f32b344d4795}"))return 9;
   if(System.IO.File.Exists(next) || System.IO.Directory.Exists(next))return 2;
   IntPtr opened;if(OROpenHive(path,out opened)!=0)return 1;h=opened;
   string[] ids={"{9dea862c-5cdd-4e70-acc1-f32b344d4795}",loader,loader};
   string[] names={"11000001","11000001","21000001"};
   // Preflight every absence before making any in-memory change.
   for(int i=0;i<3;i++){
    IntPtr parent;if(OROpenKey(h,"Objects\\"+ids[i]+"\\Elements",out parent)!=0)return 3;
    try{IntPtr existing;uint error=OROpenKey(parent,names[i],out existing);
     if(error==0){ORCloseKey(existing);return 4;}if(error!=2)return 4;
    }finally{ORCloseKey(parent);}
   }
   for(int i=0;i<3;i++){
    IntPtr parent;if(OROpenKey(h,"Objects\\"+ids[i]+"\\Elements",out parent)!=0)return 3;
    try{IntPtr key;uint disposition;
     uint error=ORCreateKey(parent,names[i],null,0,IntPtr.Zero,out key,out disposition);
     if(error!=0)return 5;
     try{
      if(disposition!=1)return 4;
      byte[] value=PartitionDevice(d,i==0?e:w);
      if(ORSetValue(key,"Element",3,value,(uint)value.Length)!=0)return 6;
     }finally{ORCloseKey(key);}
    }finally{ORCloseKey(parent);}
   }
   // ORSaveHive refuses an existing destination. The source hive is closed
   // before same-volume REPLACE_EXISTING|WRITE_THROUGH rename; never /import.
   if(ORSaveHive(h,next,6,1)!=0)return 7;
   ORCloseHive(h);h=IntPtr.Zero;
   if(!MoveFileEx(next,path,9))return 8;
   return 0;
  }catch{return 10;}finally{if(h!=IntPtr.Zero)ORCloseHive(h);}
 }
 static string[] Names(IntPtr hive,string path) {
  IntPtr key;uint open=OROpenKey(hive,path,out key);
  if(open==2)return new string[0];if(open!=0)throw new InvalidOperationException();
  var found=new System.Collections.Generic.List<string>();
  try{for(uint i=0;i<128;i++){
   StringBuilder name=new StringBuilder(64);uint length=64;uint e=OREnumKey(key,i,name,ref length,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
   if(e==259)return found.ToArray();if(e!=0)throw new InvalidOperationException();
   found.Add(name.ToString());
  }throw new InvalidOperationException();}finally{ORCloseKey(key);}
 }
 static bool Equal(string a,string b) {return String.Equals(a,b,StringComparison.OrdinalIgnoreCase);}
 static bool Number(IntPtr h,string id,string element,ulong expected) {return Same(Element(h,id,element),BitConverter.GetBytes(expected));}
 static uint Schema(IntPtr h,string id,string[] allowed) {
  var set=new System.Collections.Generic.HashSet<string>(allowed,StringComparer.OrdinalIgnoreCase);
  foreach(string name in Names(h,"Objects\\"+id+"\\Elements")){
   uint element;
   if(name.Length!=8 || !UInt32.TryParse(name,System.Globalization.NumberStyles.AllowHexSpecifier,System.Globalization.CultureInfo.InvariantCulture,out element))return 27;
   // Class 4 is BCDBoot merge-template data, never a finished-store element.
   if((element&0xf0000000)==0x40000000)return 14;
   if(!set.Contains(name))return 27;
  }return 0;
 }
 // Numeric verification codes are stable diagnostic facts; no hive data leaves.
 public static uint Verify(string path,string loader,string disk,string esp,string windows,string locale) {
  IntPtr h;if(OROpenHive(path,out h)!=0)return 1;
  try{
   string manager="{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
   if(!Exists(h,manager))return 2;
   if(!Exists(h,loader))return 5;
   string[] objects=Names(h,"Objects");
   if(objects.Length!=2 || !Array.Exists(objects,id=>Equal(id,manager)) || !Array.Exists(objects,id=>Equal(id,loader)))return 13;
   if(!Same(Read(h,"Objects\\"+manager+"\\Description","Type",4),BitConverter.GetBytes((uint)0x10100002)))return 25;
   if(!Same(Read(h,"Objects\\"+loader+"\\Description","Type",4),BitConverter.GetBytes((uint)0x10200003)))return 26;
   uint schema=Schema(h,manager,new string[]{"11000001","12000002","12000004","12000005","23000003","24000001","25000004"});
   if(schema!=0)return schema;
   schema=Schema(h,loader,new string[]{"11000001","12000002","12000004","12000005","16000009","16000060","17000077","21000001","22000002","25000020","250000c2"});
   if(schema!=0)return schema;
   if(!String.Equals(StringElement(h,manager,"23000003"),loader,StringComparison.OrdinalIgnoreCase))return 3;
   if(!String.Equals(StringElement(h,manager,"12000002"),@"\EFI\Microsoft\Boot\bootmgfw.efi",StringComparison.OrdinalIgnoreCase))return 4;
   if(!String.Equals(StringElement(h,loader,"12000002"),@"\Windows\system32\winload.efi",StringComparison.OrdinalIgnoreCase))return 6;
   if(!String.Equals(StringElement(h,loader,"22000002"),@"\Windows",StringComparison.OrdinalIgnoreCase))return 7;
   if(!Device(Element(h,manager,"11000001"),new Guid(disk),new Guid(esp)))return 8;
   if(!Device(Element(h,loader,"11000001"),new Guid(disk),new Guid(windows)))return 9;
   if(!Device(Element(h,loader,"21000001"),new Guid(disk),new Guid(windows)))return 10;
   if(!Same(Element(h,loader,"16000009"),new byte[]{0}))return 11;
   byte[] order=Read(h,"Objects\\"+manager+"\\Elements\\24000001","Element",7);
   if(order==null || !Equal(Encoding.Unicode.GetString(order),loader+"\0\0"))return 15;
   if(!Number(h,manager,"25000004",0))return 16;
   if(!Equal(StringElement(h,manager,"12000005"),locale))return 17;
   if(!Equal(StringElement(h,loader,"12000005"),locale))return 18;
   if(!Number(h,loader,"25000020",0))return 19;
   if(!Number(h,loader,"250000c2",1))return 20;
   if(!Same(Element(h,loader,"16000060"),new byte[]{1}))return 21;
   if(!Number(h,loader,"17000077",0x15000075))return 22;
   if(StringElement(h,manager,"12000004")!="Windows Boot Manager")return 23;
   if(StringElement(h,loader,"12000004")!="Windows")return 24;
   return 0;
  }catch{return 12;}finally{ORCloseHive(h);}
 }
}
"@
}
function Test-BootStore([string]$Store,$Data){Initialize-BootRegistry;return [FactoryBoot]::Verify($Store,$Data.loader_guid,$Data.disk_guid,$Data.esp_guid,$Data.windows_guid,$Data.locale)}
function Set-BootDevices([string]$Store,$Data){
 if(Get-Item -Force -LiteralPath ($Store+'.plain-gpt') -ErrorAction SilentlyContinue){return [uint32]2}
 Initialize-BootRegistry;return [FactoryBoot]::WriteDevices($Store,$Data.loader_guid,$Data.disk_guid,$Data.esp_guid,$Data.windows_guid)
}
function Set-BootStore([string]$Store,$Data){
 if(Test-Path -LiteralPath $Store){throw 'boot store already exists'}
 # /createstore explicitly names the new, non-system store. All subsequent
 # calls use /store; no command can fall back to the host's system store.
 $commands=@(,@('/createstore',$Store))
 $edits=@(
  @('/create','{bootmgr}','/d','Windows Boot Manager'),
  @('/create',$Data.loader_guid,'/d','Windows','/application','osloader'),
  @('/set','{bootmgr}','path','\EFI\Microsoft\Boot\bootmgfw.efi'),
  @('/set','{bootmgr}','locale',$Data.locale),
  @('/timeout','0'),
  @('/displayorder',$Data.loader_guid),
  @('/default',$Data.loader_guid),
  @('/set',$Data.loader_guid,'path','\Windows\system32\winload.efi'),
  @('/set',$Data.loader_guid,'systemroot','\Windows'),
  @('/set',$Data.loader_guid,'locale',$Data.locale),
  @('/set',$Data.loader_guid,'nx','OptIn'),
  @('/set',$Data.loader_guid,'bootmenupolicy','Standard'),
  @('/set',$Data.loader_guid,'recoveryenabled','No'),
  @('/set',$Data.loader_guid,'isolatedcontext','Yes'),
  @('/set',$Data.loader_guid,'allowedinmemorysettings','0x15000075')
 )
 foreach($edit in $edits){$commands+=,(@('/store',$Store)+$edit)}
 $tool=Join-Path $env:SystemRoot 'System32\bcdedit.exe';$number=0
 foreach($command in $commands){
  $number++;$code=Invoke-ImageTool $tool $command
  if($code -ne 0){Emit-Result @{boot_failure=$true;bcdedit_command=$number;bcdedit_exit=[int64]$code};throw 'store command failed'}
 }
}
