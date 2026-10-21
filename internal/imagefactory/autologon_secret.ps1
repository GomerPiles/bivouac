$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;
public static class SpikeAutoLogonSecret {
 [StructLayout(LayoutKind.Sequential)] struct Unicode {public ushort Length,MaximumLength;public IntPtr Buffer;}
 [StructLayout(LayoutKind.Sequential)] struct Attributes {public uint Length;public IntPtr Root,ObjectName;public uint Flags;public IntPtr Descriptor,Quality;}
 [DllImport("advapi32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint LsaOpenPolicy(IntPtr system,ref Attributes attributes,uint access,out IntPtr policy);
 [DllImport("advapi32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint LsaStorePrivateData(IntPtr policy,ref Unicode name,ref Unicode value);
 [DllImport("advapi32.dll"),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern uint LsaClose(IntPtr policy);
 public static uint Store(string password) {
  if(password==null || password.Length==0 || password.Length>512)return 87;
  var a=new Attributes();a.Length=(uint)Marshal.SizeOf(typeof(Attributes));IntPtr policy;
  uint error=LsaOpenPolicy(IntPtr.Zero,ref a,0x20,out policy);if(error!=0)return error;
  var name=new Unicode();var secret=new Unicode();
  try {
   string label="DefaultPassword";name.Length=(ushort)(label.Length*2);name.MaximumLength=(ushort)(name.Length+2);name.Buffer=Marshal.StringToHGlobalUni(label);
   secret.Length=(ushort)(password.Length*2);secret.MaximumLength=(ushort)(secret.Length+2);secret.Buffer=Marshal.StringToHGlobalUni(password);
   return LsaStorePrivateData(policy,ref name,ref secret);
  } finally {if(secret.Buffer!=IntPtr.Zero)Marshal.ZeroFreeGlobalAllocUnicode(secret.Buffer);if(name.Buffer!=IntPtr.Zero)Marshal.FreeHGlobal(name.Buffer);LsaClose(policy);}
 }
}
"@
