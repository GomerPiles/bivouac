# Public filesystem facts only. Do not read runner registration files, policy
# backup contents, authorized keys or credentials.
function Test-OrdinaryFilePath([string]$Path){
 try{return !((Get-Item -Force -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)}catch{return $false}
}
function Read-RunnerFacts([string]$Runner,$Facts){
 $Facts.runner_state='invalid';$Facts.runner_residue=@{}
 if(!(Test-Path -LiteralPath $Runner)){$Facts.runner_state='absent';return}
 $directory=Get-Item -Force -LiteralPath $Runner
 if(!$directory.PSIsContainer -or !(Test-OrdinaryFilePath $Runner)){return}
 $configured=$false;$residue=$false;$invalid=$false
 foreach($entry in Get-ChildItem -Force -LiteralPath $Runner){
  if($entry.Name -eq '.runner' -or $entry.Name -like '.credentials*'){$configured=$true}
  if($entry.Name -in @('_work','_diag')){
   if(!$entry.PSIsContainer -or !(Test-OrdinaryFilePath $entry.FullName)){$invalid=$true;continue}
   $fact=@{entries=@();omitted_names=0;truncated=$false}
   foreach($child in Get-ChildItem -Force -LiteralPath $entry.FullName){
    $residue=$true
    if($child.Name -notmatch '^[A-Za-z0-9_. -]{1,128}$'){$fact.omitted_names++;continue}
    if($fact.entries.Count -ge 64){$fact.truncated=$true;continue}
    $fact.entries+=@{name=$child.Name;directory=[bool]$child.PSIsContainer}
   }
   $Facts.runner_residue[$entry.Name]=$fact
  }
 }
 if($configured){$Facts.runner_state='configured';return}
 if($invalid){return}
 $Facts.runner_state='incomplete'
 foreach($part in @('bin','bin\Runner.Listener.exe','config.cmd','run.cmd')){
  $path=Join-Path $Runner $part
  if(!(Test-Path -LiteralPath $path)){return}
  $item=Get-Item -Force -LiteralPath $path
  if(!(Test-OrdinaryFilePath $path)){$Facts.runner_state='invalid';return}
  if(($part -eq 'bin' -and !$item.PSIsContainer) -or ($part -ne 'bin' -and ($item.PSIsContainer -or $item.Length -eq 0))){return}
 }
 $Facts.runner_state=if($residue){'residue'}else{'unconfigured'}
}
function Read-FactoryFiles([string]$Root,$Facts) {
 # These paths guard the Guest-state refusal; unknown access fails closed.
 foreach($relative in @('ProgramData','ProgramData\Bivouac')){
  $path=Join-Path $Root $relative
  if((Test-Path -LiteralPath $path) -and !(Test-OrdinaryFilePath $path)){throw 'guest state path'}
 }
 $bivouac=Join-Path $Root 'ProgramData\Bivouac'
 $Facts.guest_state_present=Test-Path -LiteralPath (Join-Path $bivouac 'Guest')
 Read-RunnerFacts (Join-Path $Root 'actions-runner') $Facts
 $agentDirectory=Join-Path $Root 'Program Files\Bivouac'
 $agent=Join-Path $agentDirectory 'bivouac.exe'
 foreach($path in @((Join-Path $Root 'Program Files'),$agentDirectory)){
  if((Test-Path -LiteralPath $path) -and !(Test-OrdinaryFilePath $path)){throw 'agent install path'}
 }
 # Any existing install directory, even incomplete, refuses template reuse.
 $Facts.agent_present=Test-Path -LiteralPath $agentDirectory
 $Facts.agent_task_present=Test-Path -LiteralPath (Join-Path $Root 'Windows\System32\Tasks\bivouac-guest-agent')
 $Facts.runner_task_present=Test-Path -LiteralPath (Join-Path $Root 'Windows\System32\Tasks\bivouac-guest-runner')
 $Facts.agent_sha256=''
 if(Test-Path -LiteralPath $agent){
  $file=Get-Item -Force -LiteralPath $agent
  if($file.PSIsContainer -or $file.Length -gt 128MB -or !(Test-OrdinaryFilePath $agent)){throw 'agent install file'}
  $Facts.agent_sha256=(Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant()
 }
 # Runner version and names below are informational public metadata.
 $runner=Join-Path $Root 'actions-runner'
 try{if((Test-OrdinaryFilePath $runner) -and (Test-OrdinaryFilePath (Join-Path $runner 'bin'))){
  $listener=Join-Path $runner 'bin\Runner.Listener.exe'
  if((Test-Path -LiteralPath $listener -PathType Leaf) -and (Test-OrdinaryFilePath $listener)){
   $version=(Get-Item -LiteralPath $listener).VersionInfo.ProductVersion
   if($version -match '^\d{1,4}\.\d{1,4}\.\d{1,4}$'){$Facts.runner_version=$version}
  }
 }}catch{}
 try{$Facts.bivouac_present=Test-Path -LiteralPath $bivouac}catch{}
 $Facts.bivouac_subdirectories=@()
 try{if($Facts.bivouac_present){
  foreach($directory in (Get-ChildItem -Force -Directory -LiteralPath $bivouac|Select-Object -First 32)){
   if($directory.Name -match '^[a-zA-Z0-9_.-]{1,128}$'){$Facts.bivouac_subdirectories+=$directory.Name}
  }
 }}catch{}
}
function Read-PantherAnswerFacts([string]$Root,[string]$GuestUser,$Facts){
 try{
  $path=Join-Path $Root 'Windows\Panther\unattend.xml'
  $item=Get-Item -Force -LiteralPath $path
  if($item.PSIsContainer -or $item.Length -gt 1MB -or !(Test-OrdinaryFilePath $path)){return}
  $settings=New-Object Xml.XmlReaderSettings
  $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=1MB
  $reader=[Xml.XmlReader]::Create($path,$settings)
  try{$xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null;$xml.Load($reader)}finally{$reader.Dispose()}
  $fact=@{specialize_pass=$false;oobe_system_pass=$false;guest_local_account=$false;autologon_present=$false;autologon_guest_user=$false}
  foreach($pass in $xml.SelectNodes('/*[local-name()="unattend"]/*[local-name()="settings"]')){
   if($pass.GetAttribute('pass') -eq 'specialize'){$fact.specialize_pass=$true}
   if($pass.GetAttribute('pass') -eq 'oobeSystem'){$fact.oobe_system_pass=$true}
  }
  foreach($name in $xml.SelectNodes('//*[local-name()="LocalAccount"]/*[local-name()="Name"]')){if($name.InnerText -eq $GuestUser){$fact.guest_local_account=$true}}
  foreach($autologon in $xml.SelectNodes('//*[local-name()="AutoLogon"]')){
   $fact.autologon_present=$true
   foreach($name in $autologon.SelectNodes('./*[local-name()="Username"]')){if($name.InnerText -eq $GuestUser){$fact.autologon_guest_user=$true}}
  }
  $Facts.panther_answer=$fact
 }catch{}
}

function Read-SetupStep([string]$Root,$Facts){
 $path=Join-Path $Root 'Windows\Panther\Unattend\setup-step.json'
 if(!(Test-Path -LiteralPath $path)){return}
 foreach($relative in @('Windows','Windows\Panther','Windows\Panther\Unattend','Windows\Panther\Unattend\setup-step.json')){
  if((Get-Item -Force -LiteralPath (Join-Path $Root $relative)).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'setup path'}
 }
 $item=Get-Item -Force -LiteralPath $path
 if($item.PSIsContainer -or $item.Length -gt 32768){throw 'setup status bound'}
 $status=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($status.step -isnot [int] -or $status.step -lt 10 -or $status.step -gt 100 -or $status.failed -isnot [bool]){throw 'setup status'}
 $Facts.guest_setup_step=[uint32]$status.step;$Facts.guest_setup_failed=$status.failed
 if($null -ne $status.video){
  $Facts.guest_setup_video=Read-VideoDiagnostics $status.video
 }
}
