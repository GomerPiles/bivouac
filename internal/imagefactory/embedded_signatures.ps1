# Read the PE certificate table, never a catalog. Trust verification is pinned
# to embedded signature zero, with UI/revocation/network retrieval disabled.
function Initialize-EmbeddedSignature {
 if('FactoryEmbeddedSignature' -as [type]){return}
 $null=Add-Type -ReferencedAssemblies System.Security.dll -TypeDefinition @"
using System;using System.IO;using System.Runtime.InteropServices;using System.Security.Cryptography;using System.Security.Cryptography.Pkcs;
public static class FactoryEmbeddedSignature {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct FileInfo {public uint size;[MarshalAs(UnmanagedType.LPWStr)]public string path;public IntPtr file;public IntPtr subject;}
 [StructLayout(LayoutKind.Sequential)] struct Settings {public uint size,index,flags,secondary,verified;public IntPtr policy;}
 [StructLayout(LayoutKind.Sequential)] struct TrustData {public uint size;public IntPtr callback,sip;public uint ui,revocation,choice;public IntPtr info;public uint state;public IntPtr stateData;public IntPtr url;public uint flags,context;public IntPtr signatures;}
 [DllImport("wintrust.dll",ExactSpelling=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)] static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
 static uint U32(byte[] b,int offset){if(offset<0 || offset>b.Length-4)throw new InvalidDataException();return BitConverter.ToUInt32(b,offset);}
 static ushort U16(byte[] b,int offset){if(offset<0 || offset>b.Length-2)throw new InvalidDataException();return BitConverter.ToUInt16(b,offset);}
 public static uint Issuer(string issuer){
  foreach(string part in issuer.Split(',')){
   string cn=part.Trim();
   if(cn=="CN=Microsoft Windows Production PCA 2011")return 1;
   if(cn=="CN=Windows UEFI CA 2023")return 2;
   if(cn=="CN=Microsoft Windows Production PCA 2026")return 3;
  }return 4;
 }
 static void CMS(byte[] value,int depth,ref uint count,ref uint issuer){
  if(depth>4 || count>=16)throw new InvalidDataException();
  SignedCms cms=new SignedCms();cms.Decode(value);
  if(cms.ContentInfo.ContentType.Value!="1.3.6.1.4.1.311.2.1.4" || cms.SignerInfos.Count!=1 || cms.SignerInfos[0].Certificate==null)throw new InvalidDataException();
  if(count==0){cms.CheckSignature(true);issuer=Issuer(cms.SignerInfos[0].Certificate.Issuer);}
  count++;if(count>16)throw new InvalidDataException();
  foreach(CryptographicAttributeObject attribute in cms.SignerInfos[0].UnsignedAttributes){
   if(attribute.Oid.Value=="1.3.6.1.4.1.311.2.4.1")foreach(AsnEncodedData nested in attribute.Values)CMS(nested.RawData,depth+1,ref count,ref issuer);
  }
 }
 // Parsing alone identifies the primary embedded signer; Inspect additionally
 // validates the Authenticode PE digest/chain through WinVerifyTrust.
 public static uint[] Parse(byte[] b){
  try{
   if(b==null || b.Length<256 || b.Length>32*1024*1024 || U16(b,0)!=0x5a4d)return new uint[]{0,0};
   uint pe=U32(b,0x3c);if(pe>1048576 || pe>b.Length-24 || U32(b,(int)pe)!=0x4550)return new uint[]{0,0};
   int optional=(int)pe+24;int size=U16(b,(int)pe+20);ushort magic=U16(b,optional);
   int directories=magic==0x20b?112:magic==0x10b?96:0;
   if(directories==0 || size<directories+40 || optional>b.Length-size || U32(b,optional+directories-4)<5)return new uint[]{0,0};
   uint offset=U32(b,optional+directories+32),length=U32(b,optional+directories+36);
   if(offset<optional+size || (offset&7)!=0 || length<8 || length>4*1024*1024 || offset>b.Length-length)return new uint[]{0,0};
   int current=(int)offset,end=current+(int)length;uint count=0,issuer=0;
   while(current<end){
    if(end-current<8)throw new InvalidDataException();
    uint sizeCert=U32(b,current);
    if(sizeCert<8 || sizeCert>end-current || U16(b,current+4)!=0x200 || U16(b,current+6)!=2)throw new InvalidDataException();
    byte[] cms=new byte[sizeCert-8];Array.Copy(b,current+8,cms,0,cms.Length);CMS(cms,0,ref count,ref issuer);
    int next=current+(((int)sizeCert+7)&~7);if(next>end)throw new InvalidDataException();
    for(int i=current+(int)sizeCert;i<next;i++)if(b[i]!=0)throw new InvalidDataException();
    current=next;
   }return new uint[]{issuer,count};
  }catch{return new uint[]{0,0};}
 }
 static bool Trusted(string path,IntPtr handle){
  IntPtr file=IntPtr.Zero,settings=IntPtr.Zero;
  TrustData data=new TrustData();
  try{
   FileInfo info=new FileInfo{size=(uint)Marshal.SizeOf(typeof(FileInfo)),path=path,file=handle};
   file=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfo)));Marshal.StructureToPtr(info,file,false);
   Settings signature=new Settings{size=(uint)Marshal.SizeOf(typeof(Settings)),index=0,flags=1};
   settings=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Settings)));Marshal.StructureToPtr(signature,settings,false);
   data=new TrustData{size=(uint)Marshal.SizeOf(typeof(TrustData)),ui=2,revocation=0,choice=1,info=file,state=1,flags=0x1010,signatures=settings};
   Guid action=new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
   try{return WinVerifyTrust(new IntPtr(-1),ref action,ref data)==0;}
   finally{data.state=2;WinVerifyTrust(new IntPtr(-1),ref action,ref data);}
  }finally{
   if(settings!=IntPtr.Zero)Marshal.FreeHGlobal(settings);
   if(file!=IntPtr.Zero){Marshal.DestroyStructure(file,typeof(FileInfo));Marshal.FreeHGlobal(file);}
  }
 }
 public static uint[] Inspect(string path){
  try{using(FileStream f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
   if(f.Length<256 || f.Length>32*1024*1024)return new uint[]{0,0};
   byte[] bytes=new byte[(int)f.Length];int read=0;
   while(read<bytes.Length){int n=f.Read(bytes,read,bytes.Length-read);if(n==0)throw new EndOfStreamException();read+=n;}
   uint[] result=Parse(bytes);
   if(result[0]!=0 && !Trusted(path,f.SafeFileHandle.DangerousGetHandle()))result[0]=0;
   return result;
  }}catch{return new uint[]{0,0};}
 }
 public static bool SameFiles(string first,string second){
  using(FileStream a=new FileStream(first,FileMode.Open,FileAccess.Read,FileShare.Read))
  using(FileStream b=new FileStream(second,FileMode.Open,FileAccess.Read,FileShare.Read)){
   if(a.Length!=b.Length || a.Length<1 || a.Length>32*1024*1024)return false;
   byte[] x=new byte[65536],y=new byte[65536];int n;
   while((n=a.Read(x,0,x.Length))!=0){
    int read=0;while(read<n){int m=b.Read(y,read,n-read);if(m==0)return false;read+=m;}
    for(int i=0;i<n;i++)if(x[i]!=y[i])return false;
   }return b.ReadByte()==-1;
  }
 }
}
"@
}
function Get-EmbeddedSignature([string]$Path){
 Initialize-EmbeddedSignature
 $result=[FactoryEmbeddedSignature]::Inspect($Path)
 return @{issuer=[uint32]$result[0];signatures=[uint32]$result[1]}
}
function Test-BootFileMatch([string]$First,[string]$Second){Initialize-EmbeddedSignature;return [FactoryEmbeddedSignature]::SameFiles($First,$Second)}
