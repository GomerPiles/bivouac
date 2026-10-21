$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try{
 $data=[Console]::In.ReadToEnd()|ConvertFrom-Json
 if($data.instance_id -cnotmatch '^[0-9a-f]{32}$'){exit 1}
 $child=Join-Path $data.root $data.instance_id
 $marker=Get-Content -LiteralPath (Join-Path $child 'owner.json') -Raw|ConvertFrom-Json
 $disk=Join-Path $child 'disk.vhdx'
 if($data.disk -cne $disk -or $marker.build_id -cne $data.instance_id -or $marker.workspace -cne $child){exit 1}
 foreach($path in @($child,$disk)){if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 1}}
 if((Get-DiskImage -ImagePath $disk).Attached){$null=Dismount-DiskImage -ImagePath $disk}
 if((Get-DiskImage -ImagePath $disk).Attached){exit 1}
 exit 0
}catch{exit 1}
