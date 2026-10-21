$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 $data=[Console]::In.ReadToEnd() | ConvertFrom-Json
 $null=Add-Type -TypeDefinition @"
using System;using System.IO;using System.Text;using System.Runtime.InteropServices;using System.Runtime.InteropServices.ComTypes;
public static class SpikeISO {
 [DllImport("ole32.dll")] static extern int CreateStreamOnHGlobal(IntPtr h,bool delete,out IStream stream);
 public static IStream Text(string text) {IStream s;Marshal.ThrowExceptionForHR(CreateStreamOnHGlobal(IntPtr.Zero,true,out s));byte[] b=Encoding.UTF8.GetBytes(text);try{s.Write(b,b.Length,IntPtr.Zero);s.Seek(0,0,IntPtr.Zero);return s;}finally{Array.Clear(b,0,b.Length);}}
 public static void Save(object source,string path) {IStream s=(IStream)source;byte[] b=new byte[65536];IntPtr n=Marshal.AllocHGlobal(4);try{using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){while(true){s.Read(b,b.Length,n);int count=Marshal.ReadInt32(n);if(count==0)break;f.Write(b,0,count);}f.Flush(true);}}finally{Array.Clear(b,0,b.Length);Marshal.FreeHGlobal(n);}}
}
"@
 $image=New-Object -ComObject IMAPI2FS.MsftFileSystemImage
 $image.FileSystemsToCreate=3
 $image.VolumeName='HCSSETUP'
 $image.Root.AddTree($data.assets,$false)
 $stream=[SpikeISO]::Text($data.unattend)
 $image.Root.AddFile('Autounattend.xml',$stream)
 $result=$image.CreateResultImage()
 [SpikeISO]::Save($result.ImageStream,$data.destination)
 exit 0
} catch {exit 1}
