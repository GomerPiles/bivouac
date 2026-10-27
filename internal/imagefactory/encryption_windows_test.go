//go:build windows

package imagefactory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOfflineDeviceEncryption(t *testing.T) {
	input, _ := json.Marshal(map[string]string{"root": t.TempDir()})
	script := offlineEncryption + offlinePayload + `
$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
Initialize-OfflineEncryption
$null=Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public static class EncryptionFixture {
 [DllImport("offreg.dll")] static extern uint ORCreateHive(out IntPtr h);
 [DllImport("offreg.dll")] static extern uint ORCloseHive(IntPtr h);
 [DllImport("offreg.dll")] static extern uint ORCloseKey(IntPtr h);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode)] static extern uint OROpenHive(string path,out IntPtr h);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode)] static extern uint ORCreateKey(IntPtr h,string key,string cls,uint options,IntPtr security,out IntPtr next,out uint disposition);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode)] static extern uint ORSetValue(IntPtr h,string name,uint type,byte[] data,uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode)] static extern uint ORGetValue(IntPtr h,string key,string name,out uint type,byte[] data,ref uint size);
 [DllImport("offreg.dll",CharSet=CharSet.Unicode)] static extern uint ORSaveHive(IntPtr h,string path,uint major,uint minor);
 static void Check(uint code){if(code!=0)throw new InvalidOperationException();}
 static void Put(IntPtr h,string path,string name,uint type,uint value){
  IntPtr k=h;
  try{foreach(string part in path.Split('\\')){
   IntPtr next;uint disposition;Check(ORCreateKey(k,part,null,0,IntPtr.Zero,out next,out disposition));if(k!=h)ORCloseKey(k);k=next;
  }if(name!=null)Check(ORSetValue(k,name,type,BitConverter.GetBytes(value),4));}
  finally{if(k!=h)ORCloseKey(k);}
 }
 public static void Seed(string path,int mode){
  IntPtr h;Check(ORCreateHive(out h));
  try{
   Put(h,"Select","Current",4,mode==4?(uint)0:(uint)2);
   Put(h,"ControlSet002\\Control",null,4,0);
   Put(h,"ControlSet001\\Control\\BitLocker","PreventDeviceEncryption",4,0);
   if(mode>=1 && mode<=3)Put(h,"ControlSet002\\Control\\BitLocker","PreventDeviceEncryption",mode==3?(uint)1:(uint)4,mode==1?(uint)1:(uint)0);
   Check(ORSaveHive(h,path,6,1));
  }finally{ORCloseHive(h);}
 }
 public static uint Read(string path,int control){
  IntPtr h;Check(OROpenHive(path,out h));
  try{uint type,size=4;byte[] data=new byte[4];Check(ORGetValue(h,"ControlSet"+control.ToString("000")+"\\Control\\BitLocker","PreventDeviceEncryption",out type,data,ref size));if(type!=4 || size!=4)throw new InvalidOperationException();return BitConverter.ToUInt32(data,0);}finally{ORCloseHive(h);}
 }
}

"@
foreach($mode in 0..7){
 $mount=Join-Path $d.root ([string]$mode);$parent=Join-Path $mount 'Windows\System32\config';$null=New-Item -ItemType Directory -Path $parent
 $path=Join-Path $parent 'SYSTEM';[EncryptionFixture]::Seed($path,[math]::Min($mode,4))
 if($mode -ge 5){[EncryptionFixture]::Seed((Join-Path $parent 'other'),0);Remove-Item -LiteralPath $path;Move-Item -LiteralPath (Join-Path $parent 'other') -Destination $path}
 if($mode -eq 5){[IO.File]::WriteAllText(($path+'.prevent-encryption'),'preserve')}
 if($mode -eq 6){$null=New-Item -ItemType Directory -Path ($path+'.prevent-encryption')}
 foreach($suffix in @('.LOG1','.LOG2','.LOG3','.other.LOG1')){[IO.File]::WriteAllText(($path+$suffix),'preserve')}
 if($mode -eq 7){Remove-Item -LiteralPath ($path+'.LOG2');$null=New-Item -ItemType Directory -Path ($path+'.LOG2')}
 $before=(Get-FileHash -LiteralPath $path).Hash;$acl=Get-Acl -LiteralPath $path;$sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access);$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier])
 $code=Set-OfflineEncryptionPolicy $mount
 $expected=0;if($mode -in @(2,3)){$expected=3};if($mode -eq 4){$expected=2};if($mode -in @(5,6)){$expected=9};if($mode -eq 7){$expected=13}
 if($code -ne $expected){throw ('case={0} code={1}' -f $mode,$code)}
 if($mode -in @(0,1)){
  if([EncryptionFixture]::Read($path,2) -ne 1 -or [EncryptionFixture]::Read($path,1) -ne 0){throw 'wrong control set policy'}
  $a=Get-Acl -LiteralPath $path
  if($a.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $sddl -or !$a.GetOwner([Security.Principal.SecurityIdentifier]).Equals($owner)){throw 'hive security changed'}
  if(Test-Path -LiteralPath ($path+'.prevent-encryption')){throw 'saved sibling remains'}
  foreach($suffix in @('.LOG1','.LOG2')){
   if($mode -eq 0 -and (Test-Path -LiteralPath ($path+$suffix))){throw 'replaced SYSTEM log remains'}
   if($mode -eq 1 -and [IO.File]::ReadAllText(($path+$suffix)) -cne 'preserve'){throw 'already-one hive log removed'}
  }
  if($mode -eq 0){[IO.File]::WriteAllText(($path+'.LOG1'),'preserve')}
  $before=(Get-FileHash -LiteralPath $path).Hash
  if((Set-OfflineEncryptionPolicy $mount) -ne 0){throw 'already one refused'}
  if((Get-FileHash -LiteralPath $path).Hash -ne $before){throw 'already one rewrote hive'}
 }
 if(($mode -notin @(0,7)) -and (Get-FileHash -LiteralPath $path).Hash -ne $before){throw 'refusal or already-one changed source'}
 foreach($suffix in @('.LOG1','.LOG3','.other.LOG1')){if([IO.File]::ReadAllText(($path+$suffix)) -cne 'preserve'){throw 'unreplaced or foreign log changed'}}
 if($mode -eq 7 -and [EncryptionFixture]::Read($path,2) -ne 1){throw 'log refusal lost replacement'}
}
[Console]::Out.Write('encryption')`
	if got := runTestPS(t, script, input); got != "encryption" {
		t.Fatal("offline device encryption", got)
	}
}

func TestBitLockerGuestDiagnostics(t *testing.T) {
	start := strings.Index(guestValidate, "function Read-BitLockerDiagnostics")
	if start < 0 {
		t.Fatal("diagnostic function absent")
	}
	end := strings.Index(guestValidate[start:], "\n}\n")
	if end < 0 {
		t.Fatal("diagnostic function boundary")
	}
	for _, mode := range []string{"encrypted", "unavailable", "failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			input, _ := json.Marshal(map[string]string{"mode": mode})
			script := guestValidate[start:start+end+3] + `
$ErrorActionPreference='Stop';$d=[Console]::In.ReadToEnd()|ConvertFrom-Json
function Get-CimInstance {param($Namespace,$ClassName,$Filter,$OperationTimeoutSec)
 if($d.mode -eq 'unavailable'){throw 'fixture unavailable'}
 if($Namespace -cne 'root\CIMV2\Security\MicrosoftVolumeEncryption' -or $ClassName -cne 'Win32_EncryptableVolume' -or $Filter -cne "DriveLetter='C:'"){throw 'scope'}
 return [pscustomobject]@{Fixed=1}
}
function Invoke-CimMethod {param($InputObject,$MethodName,$OperationTimeoutSec)
 $code=0;if($d.mode -eq 'failure'){$code=5}
 return [pscustomobject]@{ReturnValue=$code;ConversionStatus=1;ProtectionStatus=1}
}
[Console]::Out.Write((Read-BitLockerDiagnostics|ConvertTo-Json -Compress))`
			var result struct{ Conversion, Protection uint32 }
			if json.Unmarshal([]byte(runTestPS(t, script, input)), &result) != nil {
				t.Fatal("diagnostic report")
			}
			want := uint32(1)
			if mode != "encrypted" {
				want = ^uint32(0)
			}
			if result.Conversion != want || result.Protection != want {
				t.Fatal("BitLocker diagnostic values")
			}
		})
	}
}
