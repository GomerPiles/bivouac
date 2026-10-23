$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$step=10
function Emit-Result($Value){[Console]::Out.WriteLine('BIVOUAC_IMAGE_RESULT');[Console]::Out.WriteLine(($Value|ConvertTo-Json -Compress -Depth 5))}
function Invoke-ImageTool([string]$Path,[string[]]$Arguments){& $Path @Arguments *> $null;return [int]$LASTEXITCODE}
function Get-MountedDeviceNames{
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\MountedDevices')
 if(!$key){throw 'mount-manager state unavailable'}
 try{return $key.GetValueNames()}finally{$key.Dispose()}
}
function Get-ReservedDriveLetters{
 foreach($name in @(Get-MountedDeviceNames)){if($name -match '^\\DosDevices\\([D-Z]):$'){$Matches[1]}}
}
$espType='{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}';$msrType='{e3c9e316-0b5c-4db8-817d-f92df00215ae}';$basicType='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
# Numbers only: partition type codes (1 ESP, 2 MSR, 3 basic data, 0 other),
# MiB offsets/sizes and whether each GUID is the one created in that slot.
function Get-LayoutShape($Parts,$Expected){
 $rows=@()
 for($i=0;$i -lt $Parts.Count;$i++){
  $t=0;if($Parts[$i].GptType -ieq $espType){$t=1}elseif($Parts[$i].GptType -ieq $msrType){$t=2}elseif($Parts[$i].GptType -ieq $basicType){$t=3}
  $match=$i -lt $Expected.Count -and $Parts[$i].Guid -and $Parts[$i].Guid -ieq $Expected[$i].Guid
  $rows+=[ordered]@{type=$t;offset_mib=[uint64][math]::Floor($Parts[$i].Offset/1MB);size_mib=[uint64][math]::Floor($Parts[$i].Size/1MB);guid_match=[bool]$match}
 }
 return [ordered]@{layout_failure=$true;partition_count=[uint32]$Parts.Count;partitions=$rows}
}
function Get-BootIssuer([string]$Path){
 $signature=Get-AuthenticodeSignature -LiteralPath $Path
 if($signature.Status -ne 'Valid' -or !$signature.SignerCertificate){throw 'invalid boot signature'}
 $issuer=$signature.SignerCertificate.Issuer
 if($issuer -match '(?:^|,\s*)CN=Microsoft Windows Production PCA 2011(?:,|$)'){return 'windows_production_pca_2011'}
 if($issuer -match '(?:^|,\s*)CN=Windows UEFI CA 2023(?:,|$)'){return 'windows_uefi_ca_2023'}
 throw 'unsupported boot issuer'
}
try{
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){throw 'identity'}
 $child=Join-Path $data.root $data.instance_id
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw|ConvertFrom-Json
 if($marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){throw 'ownership'}
 $iso=Join-Path $child 'install.iso';$source=Join-Path $child 'source.vhdx'
 foreach($path in @($child,$iso)){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}
 if($data.mode -eq 'media'){
  $step=20
  if((Get-DiskImage -ImagePath $iso).Attached){throw 'already mounted'}
  $image=Mount-DiskImage -ImagePath $iso -Access ReadOnly -NoDriveLetter -PassThru
  $volumes=@($image|Get-Volume)
  if($volumes.Count -ne 1 -or $volumes[0].DriveLetter){throw 'media volume'}
  $used=@(Get-Volume|Where-Object DriveLetter|ForEach-Object {[string]$_.DriveLetter})
  $used+=@(Get-PSDrive -PSProvider FileSystem|ForEach-Object {$_.Name})
  $used+=@(Get-ReservedDriveLetters)
  $letter=$null;foreach($candidate in [char[]]'ZYXWVUTSRQPONMLKJIHGFED'){if([string]$candidate -notin $used){$letter=[string]$candidate;break}}
  if(!$letter){throw 'temporary letter unavailable'}
  Emit-Result @{volume=$volumes[0].Path;letter=$letter};exit 0
 }
 if((Get-Item -Force -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'base link'}
 $step=30
 if($data.mode -eq 'layout'){
  if((Get-DiskImage -ImagePath $source).Attached){throw 'already attached'}
  $null=Mount-DiskImage -ImagePath $source -Access ReadWrite -NoDriveLetter -PassThru
 }
 $image=Get-DiskImage -ImagePath $source
 $disks=@($image|Get-Disk)
 if(!$image.Attached -or $disks.Count -ne 1){throw 'attachment identity'}
 $disk=$disks[0]
 # The image-path lookup and Storage association must agree with the physical
 # path returned by the attached virtual disk. Never enumerate/select disk 0.
 if($image.DevicePath -ine ('\\.\PhysicalDrive'+$disk.Number)){throw 'physical identity'}
 $backing=Get-DiskImage -DevicePath $image.DevicePath
 if($backing.ImagePath -ine $source){throw 'backing path identity'}
 $located=@(Get-Disk -Number $disk.Number)
 if($located.Count -ne 1 -or $located[0].Path -ine $disk.Path){throw 'Storage identity'}
 $win=Join-Path $child 'base-windows';$esp=Join-Path $child 'base-esp'
 if($data.mode -eq 'layout'){
  $step=40
  if($disk.PartitionStyle -ne 'RAW' -or $disk.LogicalSectorSize -ne 512 -or @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count){throw 'nonempty base'}
  if($disk.IsOffline){$null=Set-Disk -Number $disk.Number -IsOffline $false}
  $null=Initialize-Disk -Number $disk.Number -PartitionStyle GPT
  # GPT initialization can add its own MSR first. Remove only that, so the
  # owned disk gets Microsoft's recommended ESP, MSR, Windows order.
  $autoMSR=$false
  $initial=@(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)
  if($initial.Count -gt 1 -or ($initial.Count -eq 1 -and $initial[0].GptType -ine $msrType)){throw 'unexpected initial partition'}
  if($initial.Count -eq 1){
   $null=Remove-Partition -DiskNumber $disk.Number -PartitionNumber $initial[0].PartitionNumber -Confirm:$false
   if(@(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count){throw 'initial MSR remains'}
   $autoMSR=$true
  }
  $step=41
  $ep=New-Partition -DiskNumber $disk.Number -Size 200MB -GptType $espType
  $null=Format-Volume -Partition $ep -FileSystem FAT32 -Confirm:$false
  $step=42
  $mp=New-Partition -DiskNumber $disk.Number -Size 16MB -GptType $msrType
  $step=43
  $wp=New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType $basicType
  $null=Format-Volume -Partition $wp -FileSystem NTFS -Confirm:$false
  $step=44
  $parts=@(Get-Partition -DiskNumber $disk.Number | Sort-Object Offset)
  $expected=@($ep,$mp,$wp)
  $types=@($espType,$msrType,$basicType)
  $layoutOK=$parts.Count -eq 3
  for($i=0;$layoutOK -and $i -lt 3;$i++){
   if(!$parts[$i].Guid -or $parts[$i].Guid -ine $expected[$i].Guid -or $parts[$i].GptType -ine $types[$i] -or $parts[$i].Size -ne $expected[$i].Size -or $parts[$i].Offset -ne $expected[$i].Offset){$layoutOK=$false}
   if($i -gt 0 -and $parts[$i].Offset -lt ($parts[$i-1].Offset+$parts[$i-1].Size)){$layoutOK=$false}
  }
  if($layoutOK -and ($parts[0].Size -ne 200MB -or $parts[1].Size -ne 16MB -or $parts[2].Size -le 0)){$layoutOK=$false}
  if(!$layoutOK){Emit-Result (Get-LayoutShape $parts $expected);throw 'unexpected partition layout'}
  $step=46
  foreach($path in @($win,$esp)){if(Test-Path -LiteralPath $path){throw 'access path exists'};$null=New-Item -ItemType Directory -Path $path}
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $wp.PartitionNumber -AccessPath ($win+'\')
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $ep.PartitionNumber -AccessPath ($esp+'\')
  $disk=Get-Disk -Number $disk.Number
  Emit-Result @{disk_guid=$disk.Guid;esp_guid=$ep.Guid;msr_guid=$mp.Guid;windows_guid=$wp.Guid;automatic_msr_removed=$autoMSR};exit 0
 }
 if($disk.Guid -ine $data.disk_guid){throw 'disk GUID'}
 $wp=@(Get-Partition -DiskNumber $disk.Number|Where-Object Guid -eq $data.windows_guid)
 $ep=@(Get-Partition -DiskNumber $disk.Number|Where-Object Guid -eq $data.esp_guid)
 if($wp.Count -ne 1 -or $ep.Count -ne 1 -or ($win+'\') -notin $wp[0].AccessPaths -or ($esp+'\') -notin $ep[0].AccessPaths){throw 'partition identity'}
 if($data.mode -eq 'apply'){
  $step=50
  if($data.index -notmatch '^[1-9][0-9]{0,2}$' -or $data.kind -notin @('wim','esd','swm')){throw 'image identity'}
  $volumes=@(Get-DiskImage -ImagePath $iso|Get-Volume)
  if($volumes.Count -ne 1 -or $volumes[0].Path -cne $data.volume){throw 'media mount changed'}
  $install=Join-Path $data.volume ('sources\install.'+$data.kind)
  $dism=Join-Path $env:SystemRoot 'System32\dism.exe'
  $dismArgs=@('/Apply-Image',('/ImageFile:'+$install),('/Index:'+$data.index),('/ApplyDir:'+$win),'/CheckIntegrity',('/LogPath:'+(Join-Path $child 'apply.log')))
  if($data.kind -eq 'swm'){$dismArgs+=('/SWMFile:'+(Join-Path $data.volume 'sources\install*.swm'))}
  if((Invoke-ImageTool $dism $dismArgs) -ne 0){throw 'apply failed'}
  $v=(Get-Item -LiteralPath $dism).VersionInfo
  Emit-Result @{dism_version=('{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart)};exit 0
 }
 if($data.mode -eq 'boot'){
  $step=60
  if($data.letter -cnotmatch '^[D-Z]$' -or (Get-Volume|Where-Object DriveLetter -eq $data.letter) -or (Get-PSDrive -PSProvider FileSystem|Where-Object Name -eq $data.letter) -or $data.letter -in @(Get-ReservedDriveLetters)){throw 'letter unavailable'}
  $access=$data.letter+':\'
  $null=Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $ep[0].PartitionNumber -AccessPath $access
  try{
   $bcdboot=Join-Path $env:SystemRoot 'System32\bcdboot.exe'
   $bootArgs=@((Join-Path $win 'Windows'),'/s',($data.letter+':'),'/f','UEFI','/offline','/nofirmwaresync')
   if((Invoke-ImageTool $bcdboot $bootArgs) -ne 0){throw 'bcdboot failed'}
   foreach($name in @('EFI\Boot\bootx64.efi','EFI\Microsoft\Boot\bootmgfw.efi','EFI\Microsoft\Boot\BCD')){if(!(Test-Path -LiteralPath (Join-Path $esp $name) -PathType Leaf)){throw 'boot artifact absent'}}
   $issuers=@{fallback=(Get-BootIssuer (Join-Path $esp 'EFI\Boot\bootx64.efi'));microsoft=(Get-BootIssuer (Join-Path $esp 'EFI\Microsoft\Boot\bootmgfw.efi'))}
   if($issuers.fallback -ne 'windows_production_pca_2011' -or $issuers.microsoft -ne 'windows_production_pca_2011'){throw 'boot issuer differs from offline non-bootex selection'}
   $v=(Get-Item -LiteralPath $bcdboot).VersionInfo
   $bootVersion=('{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart)
  }finally{$null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $ep[0].PartitionNumber -AccessPath $access}
  # Apply-time policy only: no recovery partition; the factory does not register
  # WinRE. Windows setup may subsequently configure it on the Windows volume.
  Emit-Result @{bcdboot_version=$bootVersion;boot_issuers=$issuers};exit 0
 }
 if($data.mode -eq 'detach'){
  $step=70
  $null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $wp[0].PartitionNumber -AccessPath ($win+'\')
  $null=Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $ep[0].PartitionNumber -AccessPath ($esp+'\')
  $null=Dismount-DiskImage -ImagePath $source
  $null=Dismount-DiskImage -ImagePath $iso
  if((Get-DiskImage -ImagePath $source).Attached -or (Get-DiskImage -ImagePath $iso).Attached){throw 'detach incomplete'}
  Emit-Result @{};exit 0
 }
 throw 'unknown mode'
}catch{exit $step}
