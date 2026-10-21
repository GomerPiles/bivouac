function Assert-CleanRunner([string]$Runner) {
 if(!(Test-Path -LiteralPath $Runner)){return $false}
 $directory=Get-Item -Force -LiteralPath $Runner
 if(!$directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'runner directory'}
 foreach($entry in @(Get-ChildItem -Force -LiteralPath $Runner)){
  if($entry.Name -eq '.runner' -or $entry.Name -like '.credentials*'){throw 'configured runner'}
  if($entry.Name -in @('_work','_diag')){
   if(!$entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @(Get-ChildItem -Force -LiteralPath $entry.FullName | Select-Object -First 1).Count){throw 'runner residue'}
  }
 }
 foreach($part in @('bin','bin\Runner.Listener.exe','config.cmd','run.cmd')){
  $path=Join-Path $Runner $part
  if(!(Test-Path -LiteralPath $path)){throw 'runner incomplete'}
  $item=Get-Item -Force -LiteralPath $path
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($part -eq 'bin' -and !$item.PSIsContainer) -or ($part -ne 'bin' -and ($item.PSIsContainer -or $item.Length -eq 0))){throw 'runner incomplete'}
 }
 return $true
}
