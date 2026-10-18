param([string]$ArchivePath,[string]$Destination)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try {
 $runner=$Destination
 if(Test-Path -LiteralPath $runner){exit 1}
 New-Item -ItemType Directory -Path $runner|Out-Null
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $archive=[IO.Compression.ZipFile]::OpenRead($ArchivePath)
 try{
  if($archive.Entries.Count -gt 20000){exit 1}
  $total=[int64]0
  foreach($entry in $archive.Entries){
   $total+=$entry.Length
   if($entry.Length -lt 0 -or $entry.Length -gt 1GB -or $total -gt 4GB -or (($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000){exit 1}
   if($entry.FullName.Contains(':')){exit 1}
   $target=[IO.Path]::GetFullPath((Join-Path $runner $entry.FullName))
   if(!$target.StartsWith(($runner+'\'),[StringComparison]::OrdinalIgnoreCase)){exit 1}
   if($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')){New-Item -ItemType Directory -Path $target -Force|Out-Null;continue}
   $parent=Split-Path -Parent $target
   if(!(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}
   $input=$entry.Open();$output=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$input.CopyTo($output);if($output.Length -ne $entry.Length){exit 1}}finally{$output.Dispose();$input.Dispose()}
  }
 }finally{$archive.Dispose()}
 if(!(Test-Path -LiteralPath (Join-Path $runner 'bin\Runner.Listener.exe') -PathType Leaf)){exit 1}
 exit 0
}catch{exit 1}
