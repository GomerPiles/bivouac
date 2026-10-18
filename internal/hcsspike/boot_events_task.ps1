$report.task_start_ms=$null;$report.process_created_ms=$null;$report.action_start_ms=$null
try{
 $report.log_enabled=[bool](Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction Stop).IsEnabled
 if(!$report.clock_stable -or !$report.log_enabled){throw 'unavailable'}
 $items=@(Read-BootEvents @{LogName='Microsoft-Windows-TaskScheduler/Operational';FilterXPath="*[System[(EventID=100 or EventID=129 or EventID=200)] and EventData[Data[@Name='TaskName']='\bivouac-hcs-ssh-hostkeys']]"}|Where-Object {$_.TimeCreated.ToUniversalTime() -ge $boot})
 $matched=@($items|Where-Object {(Event-Fields $_).TaskName -ceq '\bivouac-hcs-ssh-hostkeys'})
 foreach($entry in @(@(100,'task_start_ms'),@(129,'process_created_ms'),@(200,'action_start_ms'))){
  $found=@($matched|Where-Object Id -eq $entry[0]);if($found.Count -gt 1){throw 'duplicate'}
  if($found.Count -eq 1){$report[$entry[1]]=Event-Milliseconds $found[0]}
 }
 $report.query_complete=$true
}catch{}
try{if($report.clock_stable -and !(Test-BootClock)){$report.clock_stable=$false}}catch{$report.clock_stable=$false}
if(!$report.clock_stable){$report.task_start_ms=$null;$report.process_created_ms=$null;$report.action_start_ms=$null}
[Console]::Out.Write(($report|ConvertTo-Json -Compress))
