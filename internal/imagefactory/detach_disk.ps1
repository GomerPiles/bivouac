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
    foreach($part in @(Get-Partition -DiskNumber $disks[0].Number)){
     foreach($access in @($part.AccessPaths)){
      $owned=$false
      foreach($name in @('base-windows','base-esp','inspect-mount','setup-private\mount')){if($access -ieq ((Join-Path $child $name)+'\')){$owned=$true}}
      if($entry[0] -eq 'source.vhdx' -and $intents.temporary_letter -and $data.temporary_letter -cmatch '^[D-Z]$' -and $access -ieq ($data.temporary_letter+':\')){
       if($part.GptType -ine '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'){exit 1};$owned=$true
      }
      if($owned){$null=Remove-PartitionAccessPath -DiskNumber $disks[0].Number -PartitionNumber $part.PartitionNumber -AccessPath $access}
     }
    }
   }
   $null=Dismount-DiskImage -ImagePath $path
  }
  if((Get-DiskImage -ImagePath $path).Attached){exit 1}
 }
 exit 0
}catch{exit 1}
