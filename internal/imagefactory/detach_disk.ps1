$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Get-MountedDeviceMapping([string]$Letter){
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\MountedDevices')
 if(!$key){throw 'mount-manager state unavailable'}
 try{return ,($key.GetValue(('\DosDevices\'+$Letter+':'),$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))}finally{$key.Dispose()}
}
function Test-GPTLetterMapping($Mapping,[string]$ESPGuid){
 # GPT mount-manager data is exactly the ASCII prefix and Windows GUID bytes.
 # Anything else belongs to another device and must not retain this workspace.
 if($Mapping -isnot [byte[]] -or $Mapping.Length -ne 24){return $false}
 $guid=[Guid]::Empty
 if(![Guid]::TryParse($ESPGuid,[ref]$guid)){throw 'recorded ESP identity unavailable'}
 $expected=[Text.Encoding]::ASCII.GetBytes('DMIO:ID:')+$guid.ToByteArray()
 for($i=0;$i -lt $expected.Length;$i++){if($Mapping[$i] -ne $expected[$i]){return $false}}
 return $true
}
function Test-RecordedLetterMapping([string]$Letter,[string]$ESPGuid){
 # Read only: retain an owned stale mapping for operator resolution. Registry
 # uncertainty also retains it; known foreign mappings are left alone.
 return Test-GPTLetterMapping (Get-MountedDeviceMapping $Letter) $ESPGuid
}
try{
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){exit 1}
 $child=Join-Path $data.root $data.instance_id
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw|ConvertFrom-Json
 if($data.disk -cne (Join-Path $child 'disk.vhdx') -or $marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){exit 1}
 if((Get-Item -Force -LiteralPath $child).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1}
 $intents=$data.storage_intents|ConvertFrom-Json
 foreach($entry in @(@('disk.vhdx','child_attach'),@('source.vhdx','base_attach'),@('install.iso','iso_mount'))){
  $path=Join-Path $child $entry[0]
  if(!$intents.($entry[1])){continue}
  if(!(Test-Path -LiteralPath $path)){continue}
  if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1}
  $image=Get-DiskImage -ImagePath $path
  if($image.Attached){
   if($entry[0] -ne 'install.iso'){
    $disks=@($image|Get-Disk);if($disks.Count -ne 1 -or $image.DevicePath -ine ('\\.\PhysicalDrive'+$disks[0].Number)){exit 1}
    $parts=@()
    if($disks[0].PartitionStyle -ne 'RAW' -and $disks[0].NumberOfPartitions -ne 0){$parts=@(Get-Partition -DiskNumber $disks[0].Number)}
    foreach($part in $parts){
     foreach($access in @($part.AccessPaths)){
      $owned=$false
      $paths=@()
      if($entry[0] -eq 'source.vhdx'){
       if($intents.windows_access){$paths+='base-windows'}
       if($intents.esp_access){$paths+='base-esp'}
      }else{
       if($intents.inspection_access){$paths+='inspect-mount'}
       if($intents.staging_access){$paths+='setup-private\mount'}
      }
      foreach($name in $paths){if($access -ieq ((Join-Path $child $name)+'\')){$owned=$true}}
      if($entry[0] -eq 'source.vhdx' -and $intents.temporary_letter -and $data.temporary_letter -cmatch '^[D-Z]$' -and $access -ieq ($data.temporary_letter+':\')){
       if(!$data.esp_guid -or $part.Guid -ine $data.esp_guid -or $part.GptType -ine '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'){exit 1};$owned=$true
      }
      if($owned){$null=Remove-PartitionAccessPath -DiskNumber $disks[0].Number -PartitionNumber $part.PartitionNumber -AccessPath $access}
     }
    }
   }
   $null=Dismount-DiskImage -ImagePath $path
  }
  if((Get-DiskImage -ImagePath $path).Attached){exit 1}
 }
 $retained=''
 if($intents.temporary_letter){
  if($data.temporary_letter -cnotmatch '^[D-Z]$'){exit 1}
  try{if(Test-RecordedLetterMapping $data.temporary_letter $data.esp_guid){$retained=$data.temporary_letter}}catch{$retained=$data.temporary_letter}
 }
 [Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT')
 [Console]::Out.WriteLine((@{retained_letter=$retained}|ConvertTo-Json -Compress))
 exit 0
}catch{exit 1}
