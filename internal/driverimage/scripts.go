package driverimage

// Fixed code only. Workspace identity, disk and inventory arrive on stdin.
const prepareScript = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$image=$null;$disk=$null;$partition=$null;$access=$null
$step=10
$fileIndex=0;$ownerValidated=$false
function Test-GPUFile([string]$Path,$Expected){
 $stream=[IO.File]::OpenRead($Path)
 try{
  if($stream.Length -ne $Expected.size){return $false}
  $hash=[Security.Cryptography.SHA256]::Create()
  try{return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant() -ceq $Expected.sha256}finally{$hash.Dispose()}
 }finally{$stream.Dispose()}
}
try {
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 $workspace=[IO.Path]::GetFullPath($data.Workspace)
 if((Split-Path -Leaf $workspace) -cnotmatch '^bivouac-gpu-[0-9a-f]{32}$'){throw 'workspace'}
 if($data.Disk -cne (Join-Path $workspace 'disk.vhdx')){throw 'disk'}
 foreach($path in @($workspace,$data.Disk,(Join-Path $workspace 'owner.json'))){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}
 $owner=Get-Content -LiteralPath (Join-Path $workspace 'owner.json') -Raw|ConvertFrom-Json
 if($owner.workspace -cne $workspace -or $owner.key -cnotmatch '^[0-9a-f]{64}$'){throw 'ownership'}
 $ownerValidated=$true
 if((Get-DiskImage -ImagePath $data.Disk).Attached){throw 'attached'}
 $mount=Join-Path $workspace 'mount'
 if(Test-Path -LiteralPath $mount){throw 'mount exists'}
 $null=New-Item -ItemType Directory -Path $mount
 $access=$mount+'\'
 try {
  $step=20
  $image=Mount-DiskImage -ImagePath $data.Disk -Access ReadWrite -NoDriveLetter -PassThru
  $disk=$image|Get-Disk
  if($disk.IsReadOnly -or $disk.IsOffline){throw 'disk state'}
  $partition=Get-Partition -DiskNumber $disk.Number | Sort-Object Size -Descending | Select-Object -First 1
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access
  $step=30
  foreach($relative in @('Windows','Windows\System32')){
   $item=Get-Item -Force -LiteralPath (Join-Path $mount $relative)
   if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Windows directory'}
  }
  $store=Join-Path $mount 'Windows\System32\HostDriverStore'
  foreach($directory in @($store,(Join-Path $store 'FileRepository'))){
   if(!(Test-Path -LiteralPath $directory)){$null=New-Item -ItemType Directory -Path $directory}
   $item=Get-Item -Force -LiteralPath $directory
   if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'driver store'}
  }
  foreach($package in $data.Packages){
   $step=40
   if($package.name -cnotmatch '^[A-Za-z0-9_.-]{1,200}$'){throw 'package'}
   $source=Join-Path (Join-Path $workspace 'payload') $package.name
   $target=Join-Path (Join-Path $store 'FileRepository') $package.name
   if(!(Test-Path -LiteralPath $target)){$null=New-Item -ItemType Directory -Path $target}
   $targetItem=Get-Item -Force -LiteralPath $target
   if(!$targetItem.PSIsContainer -or ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'package directory'}
   foreach($file in $package.files){
    $fileIndex++
    $step=50
    $parts=@($file.path -split '[/\\]')
    if(!$parts.Count){throw 'relative path'}
    $destination=$target
    for($index=0;$index -lt $parts.Count;$index++){
     $part=$parts[$index]
     if(!$part -or $part -in @('.','..') -or $part.Contains(':') -or $part.TrimEnd(' ','.') -cne $part){throw 'relative path'}
     $destination=Join-Path $destination $part
     if($index -lt $parts.Count-1 -and !(Test-Path -LiteralPath $destination)){$null=New-Item -ItemType Directory -Path $destination}
     if(Test-Path -LiteralPath $destination){if((Get-Item -Force -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'destination link'}}
    }
    $from=Join-Path $source $file.path
    $step=52
    if(!(Test-GPUFile $from $file)){throw 'source checksum'}
    $step=53
    Copy-Item -LiteralPath $from -Destination $destination -Force
    $step=60
    if(!(Test-GPUFile $destination $file)){throw 'destination checksum'}
   }
  }
 }finally{
  if($image){try{if($partition){$null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $access}}finally{$null=Dismount-DiskImage -ImagePath $data.Disk}}
 }
 $step=80
 if((Get-DiskImage -ImagePath $data.Disk).Attached){throw 'detach'}
 $null=Remove-Item -LiteralPath $mount
 exit 0
}catch{
 if($ownerValidated){[IO.File]::WriteAllText((Join-Path $workspace 'failure.json'),(@{stage=$step;file_index=$fileIndex;hresult=$_.Exception.HResult}|ConvertTo-Json -Compress))}
 exit $step
}
`
