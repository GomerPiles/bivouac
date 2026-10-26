# Only the caller's mounted, owned child SYSTEM hive is accepted.
function Initialize-OfflineEncryption {
 if('FactoryEncryption' -as [type]){return}
 $null=Add-Type -TypeDefinition @"
using System;using System.IO;using System.Runtime.InteropServices;
public static class FactoryEncryption {
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenHive(string path,out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseKey(IntPtr key);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORGetValue(IntPtr h,string key,string name,out uint type,byte[] bytes,ref uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint OROpenKey(IntPtr h,string key,out IntPtr opened);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCreateKey(IntPtr h,string key,string cls,uint options,IntPtr security,out IntPtr created,out uint disposition);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSetValue(IntPtr key,string name,uint type,byte[] bytes,uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSaveHive(IntPtr h,string path,uint major,uint minor);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool MoveFileEx(string from,string to,uint flags);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("advapi32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint SetNamedSecurityInfo(string path,int kind,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("kernel32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern IntPtr LocalFree(IntPtr memory);
 // 0 saved sibling, 11 already 1; other numbers refuse without replacing.
 public static uint Prepare(string path){
  IntPtr h=IntPtr.Zero;
  try{
   if(File.Exists(path+".prevent-encryption") || Directory.Exists(path+".prevent-encryption"))return 9;
   IntPtr opened;if(OROpenHive(path,out opened)!=0)return 1;h=opened;
   uint type,size=4;byte[] bytes=new byte[4];
   if(ORGetValue(h,"Select","Current",out type,bytes,ref size)!=0 || type!=4 || size!=4)return 2;
   uint current=BitConverter.ToUInt32(bytes,0);if(current<1 || current>999)return 2;
   string control="ControlSet"+current.ToString("000")+"\\Control";string key=control+"\\BitLocker";
   size=4;uint error=ORGetValue(h,key,"PreventDeviceEncryption",out type,bytes,ref size);
   if(error==0){return type==4 && size==4 && BitConverter.ToUInt32(bytes,0)==1?(uint)11:(uint)3;}
   if(error!=2)return 4;
   IntPtr parent;if(OROpenKey(h,control,out parent)!=0)return 5;
   try{
    IntPtr child;uint disposition;if(ORCreateKey(parent,"BitLocker",null,0,IntPtr.Zero,out child,out disposition)!=0)return 5;
    try{if(ORSetValue(child,"PreventDeviceEncryption",4,BitConverter.GetBytes((uint)1),4)!=0)return 6;}finally{ORCloseKey(child);}
   }finally{ORCloseKey(parent);}
   if(ORSaveHive(h,path+".prevent-encryption",6,1)!=0)return 7;
   return 0;
  }catch{return 10;}finally{if(h!=IntPtr.Zero)ORCloseHive(h);}
 }
 public static uint Dacl(string path,string sddl,bool protect){
  IntPtr sd;uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out sd,out size))return 12;
  try{bool present,defaulted;IntPtr dacl;if(!GetSecurityDescriptorDacl(sd,out present,out dacl,out defaulted) || !present || dacl==IntPtr.Zero)return 12;return SetNamedSecurityInfo(path,1,protect?0x80000004u:0x20000004u,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero)==0?(uint)0:(uint)12;}finally{LocalFree(sd);}
 }
 static bool RemoveTransactionLogs(string path) {
  try {
   var logs=new System.Collections.Generic.List<string>();
   foreach(string log in new string[]{path+".LOG1",path+".LOG2"}) {
    if(!System.IO.File.Exists(log) && !System.IO.Directory.Exists(log))continue;
    if(logs.Count>=16 || (System.IO.File.GetAttributes(log)&(System.IO.FileAttributes.Directory|System.IO.FileAttributes.ReparsePoint))!=0)return false;
    logs.Add(log);
   }
   foreach(string log in logs)System.IO.File.Delete(log);
   return true;
  }catch{return false;}
 }
 public static uint Commit(string path){if(!MoveFileEx(path+".prevent-encryption",path,9))return 8;return RemoveTransactionLogs(path)?(uint)0:(uint)13;}
}
"@
}
function Set-OfflineEncryptionPolicy([string]$Mount){
 $path=Join-Path $Mount 'Windows\System32\config\SYSTEM';$next=$path+'.prevent-encryption'
 Assert-OfflinePath $Mount $path;Assert-OfflinePath $Mount $next
 if(Get-Item -Force -LiteralPath $next -ErrorAction SilentlyContinue){return [uint32]9}
 $acl=Get-Acl -LiteralPath $path
 Initialize-OfflineEncryption
 $code=[FactoryEncryption]::Prepare($path)
 if($code -eq 11){return [uint32]0}
 if($code -ne 0){return $code}
 try{
  $code=[FactoryEncryption]::Dacl($next,$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access),$acl.AreAccessRulesProtected)
  if($code -ne 0){return $code}
  Set-OfflineOwner $next ($acl.GetOwner([Security.Principal.SecurityIdentifier]))
 }catch{return [uint32]12}
 return [FactoryEncryption]::Commit($path)
}
