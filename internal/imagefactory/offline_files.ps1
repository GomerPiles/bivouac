# Public filesystem facts only. Do not read runner registration files, policy
# backup contents, authorized keys or credentials.
function Set-PublicImagePath([string]$Value,$Fact){
 if($Value -match '^"?([A-Za-z]:\\[^"\r\n]*?\.exe)"?(?:\s+(.*))?$'){
  $binary=$Matches[1];$arguments=$Matches[2]
  if(!$arguments -or $arguments -in @('--service','-D')){$Fact.image_path=$Value}else{$Fact.image_path=$binary;$Fact.image_path_redacted=$true}
 }else{$Fact.image_path_redacted=$true}
}
function Read-FactoryFiles([string]$Root,$Facts) {
 function Assert-Ordinary([string]$Path){if(Test-Path -LiteralPath $Path){if((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'link'}}}
 foreach($relative in @('Windows','Windows\AppSandbox','Windows\AppSandbox\drivers','ProgramData','ProgramData\Bivouac','actions-runner')){Assert-Ordinary (Join-Path $Root $relative)}
 $base=Join-Path $Root 'Windows\AppSandbox'
 $Facts.executables=@{}
 if(Test-Path -LiteralPath $base){
  $files=@(Get-ChildItem -Force -LiteralPath $base -Filter '*.exe')
  if($files.Count -gt 32){throw 'executable count'}
  foreach($file in $files){
   if($file.PSIsContainer -or $file.Name -notmatch '^[a-zA-Z0-9_.-]{1,128}\.exe$' -or $file.Length -gt 64MB){throw 'executable bound'}
   Assert-Ordinary $file.FullName
   $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   $hash=[Security.Cryptography.SHA256]::Create()
   try{$Facts.executables[$file.Name]=[BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$stream.Dispose()}
  }
 }
 $Facts.vdd_package_present=Test-Path -LiteralPath (Join-Path $base 'drivers\AppSandboxVDD.inf') -PathType Leaf
 $runner=Join-Path $Root 'actions-runner'
 $Facts.runner_state='absent'
 if(Test-Path -LiteralPath $runner){
  $Facts.runner_state='configured'
  try{if(Assert-CleanRunner $runner){$Facts.runner_state='unconfigured'}}catch{}
  $listener=Join-Path $runner 'bin\Runner.Listener.exe'
  if(Test-Path -LiteralPath $listener -PathType Leaf){
   Assert-Ordinary (Join-Path $runner 'bin');Assert-Ordinary $listener
   $version=(Get-Item -LiteralPath $listener).VersionInfo.ProductVersion
   if($version -match '^\d{1,4}\.\d{1,4}\.\d{1,4}$'){$Facts.runner_version=$version}
  }
 }
 $bivouac=Join-Path $Root 'ProgramData\Bivouac'
 $Facts.bivouac_present=Test-Path -LiteralPath $bivouac
 $Facts.bivouac_subdirectories=@()
 if($Facts.bivouac_present){
  $directories=@(Get-ChildItem -Force -Directory -LiteralPath $bivouac)
  if($directories.Count -gt 32){throw 'directory count'}
  foreach($directory in $directories){if($directory.Name -notmatch '^[a-zA-Z0-9_.-]{1,128}$'){throw 'directory name'};$Facts.bivouac_subdirectories+= $directory.Name}
 }
 $Facts.guest_state_present=Test-Path -LiteralPath (Join-Path $bivouac 'Guest')
}

function Read-SetupStep([string]$Root,$Facts){
 $path=Join-Path $Root 'Windows\Panther\Unattend\setup-step.json'
 if(!(Test-Path -LiteralPath $path)){return}
 foreach($relative in @('Windows','Windows\Panther','Windows\Panther\Unattend','Windows\Panther\Unattend\setup-step.json')){
  if((Get-Item -Force -LiteralPath (Join-Path $Root $relative)).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'setup path'}
 }
 $item=Get-Item -Force -LiteralPath $path
 if($item.PSIsContainer -or $item.Length -gt 256){throw 'setup status bound'}
 $status=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($status.step -isnot [int] -or $status.step -lt 10 -or $status.step -gt 100 -or $status.failed -isnot [bool]){throw 'setup status'}
 $Facts.guest_setup_step=[uint32]$status.step;$Facts.guest_setup_failed=$status.failed
}
