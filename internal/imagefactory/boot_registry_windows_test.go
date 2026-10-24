//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"testing"
)

// Exercise the production offreg reader against ordinary synthetic hive files.
// Neither registry mounting, bcdedit, storage APIs nor elevation is involved.
func TestBootRegistryVerification(t *testing.T) {
	input, _ := json.Marshal(map[string]string{"root": t.TempDir()})
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
 static void Object(IntPtr h,string id,uint type){Value(h,"Objects\\"+id+"\\Description","Type",4,BitConverter.GetBytes(type));}
 static byte[] Device(string part){
  byte[] b=new byte[88];b[16]=6;
  new Guid(Disk).ToByteArray().CopyTo(b,32);new Guid(part).ToByteArray().CopyTo(b,56);return b;
 }
 public static void Seed(string path,int fault){
  IntPtr h;Check(ORCreateHive(out h));
  try{
   if(fault!=2)Object(h,Manager,0x10100002);
   if(fault!=5)Object(h,Loader,0x10200003);
   Object(h,"{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}",0x20200003);
   if(fault==12)Object(h,"{77777777-7777-4777-8777-777777777777}",0x10200003);
   if(fault==16)Object(h,"malformed",0);
   // Missing objects must not be reintroduced through their element keys.
   if(fault!=2){
    Text(h,Manager,"23000003",fault==3?ESP:Loader);
    Text(h,Manager,"12000002",fault==4?@"\other.efi":@"\EFI\Microsoft\Boot\bootmgfw.efi");
    Element(h,Manager,"11000001",3,Device(fault==8?Windows:ESP));
    if(fault==13)Element(h,Manager,"11000001",3,new byte[4097]);
    if(fault==14){byte[] wrong=Device(ESP);wrong[32]^=1;Element(h,Manager,"11000001",3,wrong);}
    if(fault==15)Element(h,Manager,"11000001",1,Device(ESP));
   }
   if(fault!=5){
    Text(h,Loader,"12000002",fault==6?@"\wrong.efi":@"\Windows\system32\winload.efi");
    Text(h,Loader,"22000002",fault==7?@"\Other":@"\Windows");
    Element(h,Loader,"11000001",3,Device(fault==9?ESP:Windows));
    Element(h,Loader,"21000001",3,Device(fault==10?ESP:Windows));
    Element(h,Loader,"16000009",3,new byte[]{fault==11?(byte)1:(byte)0});
   }
   Check(ORSaveHive(h,path,6,1));
  }finally{ORCloseHive(h);}
 }
}
"@
for($code=0;$code -le 16;$code++){
 $path=Join-Path $data.root ('bcd'+$code)
 if($code -ne 1){[BootHiveFixture]::Seed($path,$code)}
 $before='';if($code -ne 1){$before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
 $result=[FactoryBoot]::Verify($path,'{66666666-6666-4666-8666-666666666666}','{00112233-4455-6677-8899-aabbccddeeff}','{01234567-89ab-cdef-8012-3456789abcde}','{fedcba98-7654-3210-8123-456789abcdef}')
 $expected=$code;if($code -eq 12){$expected=5}
 if($code -in @(13,14,15)){$expected=8};if($code -eq 16){$expected=12}
 if($result -ne $expected){throw ('code={0} got={1}' -f $expected,$result)}
 if($code -eq 0){if([FactoryBoot]::TemplateLoaders($path)[0] -ne '{66666666-6666-4666-8666-666666666666}'){throw 'template'}}
 if($code -ne 1 -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before){throw 'hive changed'}
}
[Console]::Out.Write('verified')
}catch{[Console]::Out.Write(('fixture_line={0}' -f $_.InvocationInfo.ScriptLineNumber))}
`
	if got := runTestPS(t, script, input); got != "verified" {
		t.Fatal("offline hive verification", got)
	}
}

func TestCleanupRejectsUnrecordedLetters(t *testing.T) {
	for _, frame := range []string{
		`{"retained_letters":["X"]}`,
		`{"retained_letters":["Z","Z"]}`,
		`{"retained_letters":["Z","Y","X"]}`,
		`{"retained_letters":null}`,
	} {
		r := &record{TemporaryLetter: "Z", WindowsTemporaryLetter: "Y", StorageIntents: fixtureCleanupIntents()}
		if e := detachOwnedWith(t.Context(), r, func(_ context.Context, _ string, _ any, _ bool) ([]byte, error) {
			return []byte(frame), nil
		}); e == nil {
			t.Fatal("unrecorded cleanup letter accepted")
		}
	}
}
