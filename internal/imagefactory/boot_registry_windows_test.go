//go:build windows

package imagefactory

import (
	"encoding/json"
	"strings"
	"testing"
)

// Exercise the production offreg reader against ordinary synthetic hive files.
// Neither registry mounting, bcdedit, storage APIs nor elevation is involved.
func TestBootRegistryVerification(t *testing.T) {
	start := strings.Index(bootHelpers, "@\"\n") + 3
	end := strings.Index(bootHelpers[start:], "\n\"@") + start
	if start < 3 || end < start {
		t.Fatal("offline boot bindings absent")
	}
	input, _ := json.Marshal(map[string]string{"root": t.TempDir(), "bindings": bootHelpers[start:end]})
	script := bootHelpers + "\ntry{\n" + `
$ErrorActionPreference='Stop'
$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
Initialize-BootRegistry
$null=Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class BootHiveFixture {
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCreateHive(out IntPtr hive);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseHive(IntPtr hive);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCreateKey(IntPtr key,string sub,string cls,uint options,IntPtr security,out IntPtr created,out uint disposition);
 [DllImport("offreg.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORCloseKey(IntPtr key);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSetValue(IntPtr key,string name,uint type,byte[] value,uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint ORSaveHive(IntPtr hive,string path,uint major,uint minor);
 const string Manager="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",Loader="{66666666-6666-4666-8666-666666666666}",Disk="{00112233-4455-6677-8899-aabbccddeeff}",ESP="{01234567-89ab-cdef-8012-3456789abcde}",Windows="{fedcba98-7654-3210-8123-456789abcdef}";
 static void Check(uint e){if(e!=0)throw new InvalidOperationException("fixture code="+e);}
 static void Value(IntPtr h,string key,string name,uint type,byte[] value){
  IntPtr k=h;
  try{foreach(string part in key.Split('\\')){
   IntPtr next;uint disposition;Check(ORCreateKey(k,part,null,0,IntPtr.Zero,out next,out disposition));
   if(k!=h)ORCloseKey(k);k=next;
  }Check(ORSetValue(k,name,type,value,(uint)value.Length));}finally{if(k!=h)ORCloseKey(k);}
 }
 static void Element(IntPtr h,string id,string element,uint type,byte[] value){Value(h,"Objects\\"+id+"\\Elements\\"+element,"Element",type,value);}
 static void Text(IntPtr h,string id,string element,string value){Element(h,id,element,1,Encoding.Unicode.GetBytes(value+"\0"));}
 static void Number(IntPtr h,string id,string element,ulong value){Element(h,id,element,3,BitConverter.GetBytes(value));}
 static void List(IntPtr h,string id,string element,string value){Element(h,id,element,7,Encoding.Unicode.GetBytes(value+"\0\0"));}
 static void Object(IntPtr h,string id,uint type){Value(h,"Objects\\"+id+"\\Description","Type",4,BitConverter.GetBytes(type));}
 static byte[] Device(string part){
  byte[] b=new byte[88];b[16]=6;
  b[24]=0x48;new Guid(part).ToByteArray().CopyTo(b,32);new Guid(Disk).ToByteArray().CopyTo(b,56);return b;
 }
 public static void Seed(string path,int fault){
  IntPtr h;Check(ORCreateHive(out h));
  try{
   if(fault!=68){
    if(fault!=50){
     string name=fault==51?"OTHER":fault==67?"bcd00000000":"BCD00000000";
     byte[] bytes=Encoding.Unicode.GetBytes(name+(fault==65?"\0\0":"\0"));
     Value(h,"Description","KeyName",fault==52?(uint)2:(uint)1,bytes);
    }
    if(fault!=53 && fault!=60)Value(h,"Description","System",fault==55?(uint)3:(uint)4,fault==56?new byte[8]:BitConverter.GetBytes(fault==54?(uint)0:fault==64?(uint)2:(uint)1));
    if(fault==57 || fault==60 || (fault>=61 && fault<=63))Value(h,"Description","FirmwareModified",fault==62?(uint)3:(uint)4,fault==63?new byte[8]:BitConverter.GetBytes(fault==61?(uint)0:(uint)1));
    if(fault==58)Value(h,"Description","Unexpected",4,BitConverter.GetBytes((uint)1));
    if(fault==59)Value(h,"Description\\Unexpected","Value",4,BitConverter.GetBytes((uint)1));
   }
   bool noDevices=(fault>=44 && fault<=47) || fault==53 || fault==57 || fault==60;
   if(fault!=2)Object(h,Manager,fault==25?(uint)0x10200003:(uint)0x10100002);
   if(fault!=5)Object(h,Loader,fault==26?(uint)0x10200004:(uint)0x10200003);
   if(fault==13)Object(h,"{77777777-7777-4777-8777-777777777777}",0x10200004);
   if(fault==37)Object(h,"malformed",0);
   // Missing objects must not be reintroduced through their element keys.
   if(fault!=2){
    Text(h,Manager,"23000003",fault==3?ESP:Loader);
    Text(h,Manager,"12000002",fault==4?@"\other.efi":@"\EFI\Microsoft\Boot\bootmgfw.efi");
    if(!noDevices)Element(h,Manager,"11000001",3,Device(fault==8?Windows:ESP));
    Text(h,Manager,"12000004",fault==23?"Other":"Windows Boot Manager");
    Text(h,Manager,"12000005",fault==17?"fr-FR":"en-US");
    List(h,Manager,"24000001",fault==15?Loader+"\0"+ESP:Loader);
    Number(h,Manager,"25000004",fault==16?(ulong)1:(ulong)0);
    if(fault==38)Element(h,Manager,"11000001",1,Device(ESP));
    if(fault==39)Element(h,Manager,"11000001",3,new byte[4097]);
    if(fault==40){byte[] wrong=Device(ESP);wrong[32]^=1;Element(h,Manager,"11000001",3,wrong);}
    if(fault==41)Text(h,Manager,"24000001",Loader);
   }
   if(fault!=5){
    Text(h,Loader,"12000002",fault==6?@"\wrong.efi":@"\Windows\system32\winload.efi");
    Text(h,Loader,"22000002",fault==7?@"\Other":@"\Windows");
    if(!noDevices)Element(h,Loader,"11000001",3,Device(fault==9?ESP:Windows));
    if(!noDevices)Element(h,Loader,"21000001",3,Device(fault==10?ESP:Windows));
    Element(h,Loader,"16000009",3,new byte[]{fault==11?(byte)1:(byte)0});
    Text(h,Loader,"12000004",fault==24?"Other":"Windows");
    Text(h,Loader,"12000005",fault==18?"fr-FR":"en-US");
    Number(h,Loader,"25000020",fault==19?(ulong)1:(ulong)0);
    Number(h,Loader,"250000c2",fault==20?(ulong)0:(ulong)1);
    Element(h,Loader,"16000060",3,new byte[]{fault==21?(byte)0:(byte)1});
    Number(h,Loader,"17000077",fault==22?(ulong)0x15000076:(ulong)0x15000075);
    if(fault==42)Element(h,Loader,"17000077",3,new byte[16]);
   }
   if(fault==14)Number(h,Manager,"45000001",1);
   if(fault==27)List(h,Loader,"14000006",ESP);
   if(fault>=28 && fault<=35){string[] ids={"42000002","45000001","47000005","47000006"};Number(h,fault<32?Manager:Loader,ids[(fault-28)%4],1);}
   if(fault==36)Number(h,Manager,"4fffffff",1);
   if(fault==43)Number(h,Manager,"invalid",1);
   if(fault>=45 && fault<=47){int i=fault-45;Element(h,i==0?Manager:Loader,i==2?"21000001":"11000001",3,Device(i==0?ESP:Windows));}
   if(fault==48){byte[] nested=new byte[374];Device(ESP).CopyTo(nested,100);Element(h,Manager,"11000001",3,nested);}
   if(fault>=100 && fault<364){
    int i=(fault-100)/88,offset=(fault-100)%88;byte[] changed=Device(i==0?ESP:Windows);changed[offset]^=1;
    Element(h,i==0?Manager:Loader,i==2?"21000001":"11000001",3,changed);
   }
   if(fault>=2000 && fault<2028){
    int index=fault-2000;byte[] bytes=index<24?Encoding.Unicode.GetBytes("BCD00000000\0"):new byte[]{1,0,0,0};
    bytes[index<24?index:index-24]^=1;
    Value(h,"Description",index<24?"KeyName":"System",index<24?(uint)1:(uint)4,bytes);
   }
   Check(ORSaveHive(h,path,6,1));
  }finally{ORCloseHive(h);}
 }
}
"@
for($code=0;$code -le 43;$code++){
 $path=Join-Path $data.root ('bcd'+$code)
 if($code -ne 1){[BootHiveFixture]::Seed($path,$code)}
 $before='';if($code -ne 1){$before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
 $disk='{00112233-4455-6677-8899-aabbccddeeff}';if($code -eq 12){$disk='invalid'}
 $result=[FactoryBoot]::Verify($path,'{66666666-6666-4666-8666-666666666666}',$disk,'{01234567-89ab-cdef-8012-3456789abcde}','{fedcba98-7654-3210-8123-456789abcdef}','en-US')
 $expected=$code
 if($code -ge 28 -and $code -le 36){$expected=14}
 if($code -eq 37){$expected=13};if($code -in @(38,39,40)){$expected=8}
 if($code -eq 41){$expected=15};if($code -eq 42){$expected=22};if($code -eq 43){$expected=27}
 if($result -ne $expected){throw ('code={0} got={1}' -f $expected,$result)}
 if($code -ne 1 -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before){throw 'hive changed'}
}
for($code=100;$code -lt 364;$code++){
 $path=Join-Path $data.root ('changed'+$code);[BootHiveFixture]::Seed($path,$code)
 $result=[FactoryBoot]::Verify($path,'{66666666-6666-4666-8666-666666666666}','{00112233-4455-6677-8899-aabbccddeeff}','{01234567-89ab-cdef-8012-3456789abcde}','{fedcba98-7654-3210-8123-456789abcdef}','en-US')
 if($result -ne (8+[int][math]::Floor(($code-100)/88))){throw 'device byte mutation accepted'}
}
$nested=Join-Path $data.root 'nested';[BootHiveFixture]::Seed($nested,48)
if([FactoryBoot]::Verify($nested,'{66666666-6666-4666-8666-666666666666}','{00112233-4455-6677-8899-aabbccddeeff}','{01234567-89ab-cdef-8012-3456789abcde}','{fedcba98-7654-3210-8123-456789abcdef}','en-US') -ne 8){throw 'nested VHD-like device accepted'}
# Actual offline mutation/save/atomic replacement on ordinary fixture files.
$loader='{66666666-6666-4666-8666-666666666666}';$disk='{00112233-4455-6677-8899-aabbccddeeff}';$esp='{01234567-89ab-cdef-8012-3456789abcde}';$windows='{fedcba98-7654-3210-8123-456789abcdef}'
foreach($fault in (@(50..65)+@(67..68)+@(2000..2027))){
 $path=Join-Path $data.root ('description'+$fault);[BootHiveFixture]::Seed($path,$fault)
 $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 $expected=28;$result=[FactoryBoot]::Verify($path,$loader,$disk,$esp,$windows,'en-US')
 if($result -ne $expected){throw 'invalid Description verification accepted'}
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before){throw 'verification changed Description'}
}
foreach($fault in @(44,53,57,60,50,51,52,54,55,56,58,59,61,62,63,64,65,67,68)){
 $path=Join-Path $data.root ('description-write'+$fault);[BootHiveFixture]::Seed($path,$fault)
 $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 $expected=11;if($fault -in @(44,53,57,60)){$expected=0}
 $result=[FactoryBoot]::WriteDevices($path,$loader,$disk,$esp,$windows)
 if($result -ne $expected){throw ('description write case={0} expected={1} result={2}' -f $fault,$expected,$result)}
 if($expected -eq 0){
  if([FactoryBoot]::Verify($path,$loader,$disk,$esp,$windows,'en-US') -ne 0){throw 'system marking not verified'}
 }elseif((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before -or (Test-Path -LiteralPath ($path+'.plain-gpt'))){throw 'Description refusal changed store'}
}
foreach($mode in @('success','missing','sibling file','sibling directory','missing parent','manager exists','device exists','osdevice exists','identity')){
 $path=Join-Path $data.root $mode
 $seed=44;$expected=0;$diskArgument=$disk
 switch($mode){
  'missing' {$expected=1}
  'sibling file' {$expected=2;[IO.File]::WriteAllText(($path+'.plain-gpt'),'preserve')}
  'sibling directory' {$expected=2;$null=New-Item -ItemType Directory -Path ($path+'.plain-gpt')}
  'missing parent' {$expected=3;$seed=2}
  'manager exists' {$expected=4;$seed=45}
  'device exists' {$expected=4;$seed=46}
  'osdevice exists' {$expected=4;$seed=47}
  'identity' {$expected=9;$diskArgument='invalid'}
 }
 if($mode -ne 'missing'){[BootHiveFixture]::Seed($path,$seed)}
 $before='';if(Test-Path -LiteralPath $path){$before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
 $result=[FactoryBoot]::WriteDevices($path,$loader,$diskArgument,$esp,$windows)
 if($result -ne $expected){throw ('write expected={0} got={1}' -f $expected,$result)}
 if($mode -eq 'success'){
  if([FactoryBoot]::Verify($path,$loader,$disk,$esp,$windows,'en-US') -ne 0 -or (Test-Path -LiteralPath ($path+'.plain-gpt'))){throw 'write verification or rename'}
  $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  if([FactoryBoot]::WriteDevices($path,$loader,$disk,$esp,$windows) -ne 4){throw 'write repeated existing elements'}
 }
 if($before -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before){throw 'refusal changed source store'}
 if($mode -eq 'sibling file' -and [IO.File]::ReadAllText(($path+'.plain-gpt')) -ne 'preserve'){throw 'sibling overwritten'}
}
foreach($code in @(5,6,7,8,10,12,13)){
 $name='FactoryBootFault'+$code
 $binding=$data.bindings.Replace('public static class FactoryBoot {',('public static class '+$name+' {'))
 $helpers=' static uint FailValue(){return 5;} static bool FailMove(){return false;} static uint FailCreate(out IntPtr key,out uint disposition){key=IntPtr.Zero;disposition=0;return 5;} static uint ThrowValue(){throw new InvalidOperationException();} '
 $binding=$binding.Replace(('public static class '+$name+' {'),('public static class '+$name+' {'+$helpers))
 switch($code){
  5 {$binding=$binding.Replace('ORCreateKey(parent,names[i],null,0,IntPtr.Zero,out key,out disposition)','FailCreate(out key,out disposition)')}
  6 {$binding=$binding.Replace('ORSetValue(key,"Element",3,value,(uint)value.Length)','FailValue()')}
  7 {$binding=$binding.Replace('ORSaveHive(h,next,6,1)','FailValue()')}
  8 {$binding=$binding.Replace('MoveFileEx(next,path,9)','FailMove()')}
  10 {$binding=$binding.Replace('ORSetValue(key,"Element",3,value,(uint)value.Length)','ThrowValue()')}
  12 {$binding=$binding.Replace('ORSetValue(description,"System",4,new byte[]{1,0,0,0},4)','FailValue()')}
  13 {$binding=$binding.Replace('ORDeleteValue(description,"FirmwareModified")','FailValue()')}
 }
 $null=Add-Type -TypeDefinition $binding
 $path=Join-Path $data.root ('write-failure'+$code);[BootHiveFixture]::Seed($path,44)
 $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 $type=[type]$name
 $result=$type::WriteDevices($path,$loader,$disk,$esp,$windows)
 if($result -ne $code -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before){throw 'native write failure changed source'}
 if($code -eq 8 -and [FactoryBoot]::Verify(($path+'.plain-gpt'),$loader,$disk,$esp,$windows,'en-US') -ne 0){throw 'failed replacement lost saved store'}
}
[Console]::Out.Write('verified')
}catch{[Console]::Out.Write(('fixture_line={0} expected={1} result={2} case={3} fault={4} compiler={5}' -f $_.InvocationInfo.ScriptLineNumber,[int]$expected,[int]$result,[int]$code,[int]$fault,([regex]::Match($_.Exception.Message,'CS(\d+)').Groups[1].Value)))}
`
	if got := runTestPS(t, script, input); got != "verified" {
		t.Fatal("offline hive verification", got)
	}
}

func TestPlainGPTDeviceGolden(t *testing.T) {
	// Independent golden Windows GUID byte order and all required zero bytes.
	expected := strings.Repeat("00", 16) + "06000000000000004800000000000000" +
		"67452301ab89efcd80123456789abcde" + strings.Repeat("00", 8) +
		"33221100554477668899aabbccddeeff" + strings.Repeat("00", 16)
	input, _ := json.Marshal(map[string]string{"golden": expected})
	script := bootHelpers + `
$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
Initialize-BootRegistry
$b=[FactoryBoot]::PartitionDevice([Guid]'{00112233-4455-6677-8899-aabbccddeeff}',[Guid]'{01234567-89ab-cdef-8012-3456789abcde}')
if($b.Length -ne 88 -or [BitConverter]::ToString($b).Replace('-','').ToLowerInvariant() -cne $d.golden){throw 'partition golden differs'}
$refused=$false;try{$null=[FactoryBoot]::PartitionDevice([Guid]::Empty,[Guid]::NewGuid())}catch{$refused=$true}
if(!$refused){throw 'empty disk accepted'}
$refused=$false;try{$null=[FactoryBoot]::PartitionDevice([Guid]::NewGuid(),[Guid]::Empty)}catch{$refused=$true}
if(!$refused){throw 'empty partition accepted'}
[Console]::Out.Write('golden')`
	if got := runTestPS(t, script, input); got != "golden" {
		t.Fatal("plain GPT device golden")
	}
}
