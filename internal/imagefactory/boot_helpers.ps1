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
 $required=@('Windows\Boot\EFI\bootmgfw.efi','Windows\Boot\EFI\bootmgr.efi','Windows\Boot\EFI\memtest.efi','Windows\Boot\EFI\SecureBootRecovery.efi','Windows\Boot\EFI\boot.pnd.stl','Windows\Boot\Fonts\wgl4_boot.ttf','Windows\Boot\Resources\bootres.dll','Windows\System32\winload.efi','Windows\System32\config\BCD-Template')
 foreach($name in $required){$path=Join-Path $Windows $name;Assert-BootPath $Windows $path;if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw 'required boot source absent'}}
 $plan=@();$dirs=@('EFI','EFI\Boot','EFI\Microsoft','EFI\Microsoft\Boot','EFI\Microsoft\Recovery')
 [long]$bytes=0;$entries=0
 foreach($name in @('Windows\Boot\EFI\bootmgfw.efi','Windows\Boot\EFI\boot.pnd.stl','Windows\System32\config\BCD-Template')){$bytes+=(Get-Item -LiteralPath (Join-Path $Windows $name)).Length}
 foreach($tree in @(@('EFI',''),@('Fonts','Fonts'),@('Resources','Resources'))){
  if($tree[1]){$dirs+='EFI\Microsoft\Boot\'+$tree[1]}
  $source=Join-Path $Windows ('Windows\Boot\'+$tree[0])
  $queue=[Collections.Generic.Queue[object]]::new();$queue.Enqueue(@($source,$tree[1],0))
  while($queue.Count){
   $row=$queue.Dequeue();Assert-BootPath $Windows $row[0]
   if($row[2] -gt 8){throw 'boot directory depth'}
   foreach($item in @(Get-ChildItem -Force -LiteralPath $row[0])){
    $entries++;if($entries -gt 4096 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -ieq 'EFI_EX'){throw 'boot tree link or bound'}
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
 $template=Join-Path $Windows 'Windows\System32\config\BCD-Template'
 if((Get-Item -LiteralPath $template).Length -gt 8MB){throw 'boot template bound'}
 [IO.File]::Copy($template,(Join-Path $ESP 'EFI\Microsoft\Boot\BCD'),$false)
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
 static int Occurrences(byte[] data,byte[] value) {int count=0;for(int i=0;i+value.Length<=data.Length;i++){bool ok=true;for(int j=0;j<value.Length;j++)if(data[i+j]!=value[j]){ok=false;break;}if(ok)count++;}return count;}
 // Device blobs are bounded REG_BINARY. Require both unique GPT identities,
 // never a drive-letter substring or localized bcdedit enumeration.
 static bool Device(byte[] b,Guid disk,Guid part) {return b!=null && b.Length>=48 && Occurrences(b,disk.ToByteArray())==1 && Occurrences(b,part.ToByteArray())==1;}
 static string[] Loaders(IntPtr hive) {
  IntPtr key;if(OROpenKey(hive,"Objects",out key)!=0)throw new InvalidOperationException("template=1");
  var found=new System.Collections.Generic.List<string>();
  try{for(uint i=0;i<128;i++){
   StringBuilder name=new StringBuilder(64);uint length=64;uint e=OREnumKey(key,i,name,ref length,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
   if(e==259)return found.ToArray();if(e!=0)throw new InvalidOperationException("template=2 code="+e);
   Guid guid;if(!Guid.TryParse(name.ToString(),out guid))throw new InvalidOperationException("template=6");
   byte[] type=Read(hive,"Objects\\"+name+"\\Description","Type",4);
   if(type!=null && type.Length==4 && BitConverter.ToUInt32(type,0)==0x10200003)found.Add(guid.ToString("B"));
  }throw new InvalidOperationException();}finally{ORCloseKey(key);}
 }
 public static string[] TemplateLoaders(string path) {
  IntPtr h;uint error=OROpenHive(path,out h);if(error!=0)throw new InvalidOperationException("template=7 code="+error);
  try{string[] ids=Loaders(h);if(ids.Length==0)throw new InvalidOperationException("template=3");if(!Exists(h,"{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}"))throw new InvalidOperationException("template=4");return ids;}finally{ORCloseHive(h);}
 }
 // Numeric verification codes are stable diagnostic facts; no hive data leaves.
 public static uint Verify(string path,string loader,string disk,string esp,string windows) {
  IntPtr h;if(OROpenHive(path,out h)!=0)return 1;
  try{
   string manager="{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
   if(!Exists(h,manager))return 2;
   if(!String.Equals(StringElement(h,manager,"23000003"),loader,StringComparison.OrdinalIgnoreCase))return 3;
   if(!String.Equals(StringElement(h,manager,"12000002"),@"\EFI\Microsoft\Boot\bootmgfw.efi",StringComparison.OrdinalIgnoreCase))return 4;
   string[] loaders=Loaders(h);
   if(!Exists(h,loader) || loaders.Length!=1 || loaders[0]!=loader)return 5;
   if(!String.Equals(StringElement(h,loader,"12000002"),@"\Windows\system32\winload.efi",StringComparison.OrdinalIgnoreCase))return 6;
   if(!String.Equals(StringElement(h,loader,"22000002"),@"\Windows",StringComparison.OrdinalIgnoreCase))return 7;
   if(!Device(Element(h,manager,"11000001"),new Guid(disk),new Guid(esp)))return 8;
   if(!Device(Element(h,loader,"11000001"),new Guid(disk),new Guid(windows)))return 9;
   if(!Device(Element(h,loader,"21000001"),new Guid(disk),new Guid(windows)))return 10;
   if(!Same(Element(h,loader,"16000009"),new byte[]{0}))return 11;
   return 0;
  }catch{return 12;}finally{ORCloseHive(h);}
 }
}
"@
}
function Get-TemplateLoaders([string]$Store){Initialize-BootRegistry;return [FactoryBoot]::TemplateLoaders($Store)}
function Test-BootStore([string]$Store,$Data){Initialize-BootRegistry;return [FactoryBoot]::Verify($Store,$Data.loader_guid,$Data.disk_guid,$Data.esp_guid,$Data.windows_guid)}
function Set-BootStore([string]$Store,$Data){
 $old=@(Get-TemplateLoaders $Store)
 $commands=@(
  @('/create',$Data.loader_guid,'/d','Windows','/application','osloader'),
  @('/set','{bootmgr}','device',('partition='+$Data.letter+':')),
  @('/set','{bootmgr}','path','\EFI\Microsoft\Boot\bootmgfw.efi'),
  @('/set','{bootmgr}','locale',$Data.locale),
  @('/set','{bootmgr}','timeout','0'),
  @('/set','{bootmgr}','displayorder',$Data.loader_guid),
  @('/set','{bootmgr}','default',$Data.loader_guid),
  @('/set',$Data.loader_guid,'device',('partition='+$Data.windows_letter+':')),
  @('/set',$Data.loader_guid,'osdevice',('partition='+$Data.windows_letter+':')),
  @('/set',$Data.loader_guid,'path','\Windows\system32\winload.efi'),
  @('/set',$Data.loader_guid,'systemroot','\Windows'),
  @('/set',$Data.loader_guid,'locale',$Data.locale),
  @('/set',$Data.loader_guid,'inherit','{bootloadersettings}'),
  @('/set',$Data.loader_guid,'nx','OptIn'),
  @('/set',$Data.loader_guid,'bootmenupolicy','Standard'),
  @('/set',$Data.loader_guid,'recoveryenabled','No')
 )
 foreach($id in $old){$commands+=,@('/delete',$id)}
 $tool=Join-Path $env:SystemRoot 'System32\bcdedit.exe';$number=0
 foreach($command in $commands){
  $number++;$code=Invoke-ImageTool $tool (@('/store',$Store)+$command)
  if($code -ne 0){Emit-Result @{boot_failure=$true;bcdedit_command=$number;bcdedit_exit=[int64]$code};throw 'store command failed'}
 }
}
