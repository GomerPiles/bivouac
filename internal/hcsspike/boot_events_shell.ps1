$report.shell_start_ms=$null;$report.shell_ready_ms=$null
try{$report.log_enabled=[bool](Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop).IsEnabled}catch{}
try{
 if(!$report.clock_stable -or !$report.log_enabled){throw 'unavailable'}
 $made=@(Read-BootEvents @{LogName='Microsoft-Windows-TaskScheduler/Operational';FilterXPath="*[System[EventID=129] and EventData[Data[@Name='TaskName']='\bivouac-hcs-ssh-hostkeys']]"}|Where-Object {$_.TimeCreated.ToUniversalTime() -ge $boot})
 if($made.Count -ne 1){throw 'identity'}
 $f=Event-Fields $made[0]
 if($f.TaskName -cne '\bivouac-hcs-ssh-hostkeys' -or $f.ProcessID -notmatch '^[1-9][0-9]{0,9}$'){throw 'identity'}
 $target=[uint32]::Parse($f.ProcessID)
 $items=@(Read-BootEvents @{FilterHashtable=@{LogName='Microsoft-Windows-PowerShell/Operational';Id=@(40961,40962);StartTime=$boot}}|Where-Object ProcessId -eq $target)
 foreach($entry in @(@(40961,'shell_start_ms'),@(40962,'shell_ready_ms'))){
  $found=@($items|Where-Object Id -eq $entry[0]);if($found.Count -gt 1){throw 'duplicate'}
  if($found.Count -eq 1){$report[$entry[1]]=Event-Milliseconds $found[0]}
 }
 $report.query_complete=$true
}catch{}
try{if($report.clock_stable -and !(Test-BootClock)){$report.clock_stable=$false}}catch{$report.clock_stable=$false}
if(!$report.clock_stable){$report.shell_start_ms=$null;$report.shell_ready_ms=$null}
[Console]::Out.Write(($report|ConvertTo-Json -Compress))
