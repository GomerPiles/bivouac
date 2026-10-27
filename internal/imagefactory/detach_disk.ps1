$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
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
      if($owned){$null=Remove-PartitionAccessPath -DiskNumber $disks[0].Number -PartitionNumber $part.PartitionNumber -AccessPath $access}
     }
    }
   }
   $null=Dismount-DiskImage -ImagePath $path
  }
  if((Get-DiskImage -ImagePath $path).Attached){exit 1}
 }
 [Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT')
 [Console]::Out.WriteLine('{}')
 exit 0
}catch{exit 1}
