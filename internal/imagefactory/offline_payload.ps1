# Mounted-volume operations only; callers own the disk mount and child proof.
function Set-OfflineOwner([string]$Path,[Security.Principal.SecurityIdentifier]$Owner) {
 if((Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Equals($Owner)){return}
 if(!('BivouacOfflineOwner' -as [type])){
  Add-Type -TypeDefinition @"
using System;using System.Diagnostics;using System.Runtime.InteropServices;using System.Security.Principal;
public static class BivouacOfflineOwner {
 [StructLayout(LayoutKind.Sequential)] struct Privilege {public uint count;public uint low;public int high;public uint attributes;}
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out long luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privilege state,uint length,out Privilege previous,out uint returned);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfo(string path,int kind,uint info,byte[] owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static uint Set(string path,SecurityIdentifier owner) {
  byte[] sid=new byte[owner.BinaryLength];owner.GetBinaryForm(sid,0);
  uint result=SetNamedSecurityInfo(path,1,1,sid,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
  if(result==0)return 0;
  // A guest repository is normally owned by TrustedInstaller. An elevated
  // administrator has SeRestorePrivilege, but it must be enabled explicitly.
  IntPtr token;if(!OpenProcessToken(Process.GetCurrentProcess().Handle,0x28,out token))return (uint)Marshal.GetLastWin32Error();
  try {
   long luid;if(!LookupPrivilegeValue(null,"SeRestorePrivilege",out luid))return (uint)Marshal.GetLastWin32Error();
   Privilege next=new Privilege{count=1,low=(uint)luid,high=(int)(luid>>32),attributes=2};Privilege previous;uint length;
   if(!AdjustTokenPrivileges(token,false,ref next,(uint)Marshal.SizeOf(typeof(Privilege)),out previous,out length))return (uint)Marshal.GetLastWin32Error();
   uint error=(uint)Marshal.GetLastWin32Error();if(error!=0)return error;
   try{return SetNamedSecurityInfo(path,1,1,sid,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);}
   finally{Privilege ignored;uint returned;AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(Privilege)),out ignored,out returned);}
  }finally{CloseHandle(token);}
 }
}
"@
 }
 $ownerError=[BivouacOfflineOwner]::Set($Path,$Owner)
 if($ownerError -ne 0){throw ('guest owner assignment '+$ownerError)}
}
function Assert-OfflinePath([string]$Root,[string]$Path) {
 $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
 $pathValue=[IO.Path]::GetFullPath($Path)
 if(!$pathValue.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase) -and $pathValue -ine $rootPath){throw 'offline path boundary'}
 $current=$pathValue
 # The root is the volume access path this build mounted, itself a mount
 # point (a reparse point); every component below it must be ordinary.
 while($current.Length -gt $rootPath.Length){
  if(Test-Path -LiteralPath $current){
   if((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'offline link'}
  }
  $current=Split-Path -Parent $current
 }
}
function New-OfflineDirectory([string]$Root,[string]$Path) {
 Assert-OfflinePath $Root $Path
 if(!(Test-Path -LiteralPath $Path)){New-Item -ItemType Directory -Path $Path -Force | Out-Null}
 if(!(Get-Item -LiteralPath $Path).PSIsContainer){throw 'offline directory'}
}
function Copy-OfflineDrivers([string]$Mount,[string]$Snapshot,$Plan) {
 $system=Join-Path $Mount 'Windows\System32'
 New-OfflineDirectory $Mount $system
 foreach($relative in @('HostDriverStore','HostDriverStore\FileRepository')){
  $path=Join-Path $system $relative
  Assert-OfflinePath $Mount $path
  if(!(Test-Path -LiteralPath $path)){
   $owner=(Get-Acl -LiteralPath (Split-Path -Parent $path)).GetOwner([Security.Principal.SecurityIdentifier])
   New-OfflineDirectory $Mount $path
   Set-OfflineOwner $path $owner
  }
 }
 $repository=Join-Path $system 'HostDriverStore\FileRepository'
 $parentACL=Get-Acl -LiteralPath $repository
 $count=0;[long]$bytes=0;$names=@{}
 foreach($driver in $Plan){
  if($driver.name -notmatch '^[A-Za-z0-9_.-]{1,160}$' -or $driver.name -in @('.','..') -or $names.ContainsKey($driver.name)){throw 'driver directory name'}
  $names[$driver.name]=$true
  $source=Join-Path $Snapshot ([string]$count);$count++
  if($count -gt 8){throw 'driver count'}
  Assert-OfflinePath $Snapshot $source
  # Verify the exact snapshot inventory, so missing files and unexpected links
  # cannot become an apparently successful partial installation.
  # Relative names come from the walk itself: enumeration reports long names,
  # so slicing FullName by an 8.3-spelled root's length would misname entries.
  $files=@{};$directories=@{};$queue=[Collections.Generic.Queue[object]]::new();$queue.Enqueue(@($source,''));$entries=0
  while($queue.Count){$row=$queue.Dequeue();foreach($item in @(Get-ChildItem -LiteralPath $row[0] -Force)){
   $entries++;if($entries -gt 16384 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'snapshot link or bound'}
   $relative=$item.Name;if($row[1]){$relative=$row[1]+'\'+$item.Name}
   if($item.PSIsContainer){$directories[$relative]=$true;$queue.Enqueue(@($item.FullName,$relative))}else{$files[$relative]=$item}
  }}
  $expected=@($driver.files.PSObject.Properties)
  if(!$expected.Count -or $expected.Count -gt 8192 -or $files.Count -ne $expected.Count -or $directories.Count -ne @($driver.directories).Count){throw 'partial snapshot'}
  foreach($directory in $driver.directories){if(!$directories.ContainsKey($directory)){throw 'partial directory'}}
  $target=Join-Path $repository $driver.name;$temporary=$target+'.bivouac-staging';$replaced=$target+'.bivouac-replaced'
  # Existing driver trees are replaced whole after snapshot verification.
  # Only factory staging names must be absent; never merge payload trees.
  foreach($path in @($target,$temporary,$replaced)){Assert-OfflinePath $Mount $path}
  foreach($path in @($temporary,$replaced)){if(Test-Path -LiteralPath $path){throw 'existing driver staging'}}
  if((Test-Path -LiteralPath $target) -and !(Get-Item -Force -LiteralPath $target).PSIsContainer){throw 'driver target is not a directory'}
  try {
   New-OfflineDirectory $Mount $temporary
   # Only owner and inherited guest permissions come from the guest parent.
   # No host ACL is ever copied. New files inherit from the temporary tree.
   $acl=Get-Acl -LiteralPath $temporary
   $acl.SetAccessRuleProtection($false,$false)
   foreach($rule in @($acl.Access)){if(!$rule.IsInherited){[void]$acl.RemoveAccessRuleSpecific($rule)}}
   Set-Acl -LiteralPath $temporary -AclObject $acl
   Set-OfflineOwner $temporary ($parentACL.GetOwner([Security.Principal.SecurityIdentifier]))
   foreach($directory in $driver.directories){New-OfflineDirectory $temporary (Join-Path $temporary $directory)}
   foreach($entry in $expected){
    if(!$files.ContainsKey($entry.Name) -or $entry.Value -notmatch '^[0-9a-f]{64}$'){throw 'snapshot inventory'}
    $inputFile=$files[$entry.Name];$bytes+=$inputFile.Length;if($bytes -gt 2GB){throw 'driver bytes'}
    if((Get-FileHash -LiteralPath $inputFile.FullName -Algorithm SHA256).Hash -ine $entry.Value){throw 'snapshot hash'}
    $outputFile=Join-Path $temporary $entry.Name;Assert-OfflinePath $temporary $outputFile
    [IO.File]::Copy($inputFile.FullName,$outputFile,$false)
    if((Get-FileHash -LiteralPath $outputFile -Algorithm SHA256).Hash -ine $entry.Value){throw 'offline driver hash'}
    Set-OfflineOwner $outputFile ($parentACL.GetOwner([Security.Principal.SecurityIdentifier]))
   }
   foreach($directory in $driver.directories){$path=Join-Path $temporary $directory;Set-OfflineOwner $path ($parentACL.GetOwner([Security.Principal.SecurityIdentifier]))}
   # Rename on the mounted volume publishes only the complete verified tree.
   # An existing tree moves aside first and returns if publication fails.
   if(Test-Path -LiteralPath $target){
    [IO.Directory]::Move($target,$replaced)
    try{[IO.Directory]::Move($temporary,$target)}catch{[IO.Directory]::Move($replaced,$target);throw}
   } else {[IO.Directory]::Move($temporary,$target)}
  } finally {
   if(Test-Path -LiteralPath $temporary){Assert-OfflinePath $Mount $temporary;Remove-Item -LiteralPath $temporary -Recurse -Force}
   if((Test-Path -LiteralPath $replaced) -and (Test-Path -LiteralPath $target)){Assert-OfflinePath $Mount $replaced;Remove-Item -LiteralPath $replaced -Recurse -Force}
  }
 }
}
function Install-OfflineAgent([string]$Mount,[string]$Source,[string]$Hash) {
 $directory=Join-Path $Mount 'Program Files\Bivouac'
 Assert-OfflinePath $Mount $directory
 if(Test-Path -LiteralPath $directory){throw 'agent install already exists'}
 New-OfflineDirectory $Mount $directory
 $acl=[Security.AccessControl.DirectorySecurity]::new()
 $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;0x1200a9;;;BU)')
 Set-Acl -LiteralPath $directory -AclObject $acl
 $target=Join-Path $directory 'bivouac.exe'
 [IO.File]::Copy($Source,$target,$false)
 $fileACL=[Security.AccessControl.FileSecurity]::new()
 $fileACL.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BU)')
 Set-Acl -LiteralPath $target -AclObject $fileACL
 if($Hash -notmatch '^[0-9a-f]{64}$' -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $Hash){throw 'agent hash'}
 $image=Join-Path $Mount 'ProgramData\Bivouac\Image'
 New-OfflineDirectory $Mount $image
 $private=[Security.AccessControl.DirectorySecurity]::new();$private.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath (Split-Path -Parent $image) -AclObject $private
 Set-Acl -LiteralPath $image -AclObject $private
}
