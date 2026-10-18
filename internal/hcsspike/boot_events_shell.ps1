$report.engine_ready_ms=$null;$report.shell_start_ms=$null;$report.shell_ready_ms=$null
try{
 if(!$report.clock_stable){throw 'clock'}
 $engines=@(Read-BootEvents @{FilterHashtable=@{LogName='Windows PowerShell';Id=400;StartTime=$boot}}|Where-Object {([string]$_.Properties[2].Value).Contains('hcs-spike-startup.ps1')})
 if($engines.Count -ne 1 -or $engines[0].ProcessId -lt 1){throw 'identity'}
 $report.engine_ready_ms=Event-Milliseconds $engines[0]
 $targetPID=$engines[0].ProcessId
 $report.log_enabled=[bool](Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop).IsEnabled
 if(!$report.log_enabled){throw 'unavailable'}
 $items=@(Read-BootEvents @{FilterHashtable=@{LogName='Microsoft-Windows-PowerShell/Operational';Id=@(40961,40962);StartTime=$boot}}|Where-Object ProcessId -eq $targetPID)
 foreach($entry in @(@(40961,'shell_start_ms'),@(40962,'shell_ready_ms'))){
  $found=@($items|Where-Object Id -eq $entry[0]);if($found.Count -gt 1){throw 'duplicate'}
  if($found.Count -eq 1){$report[$entry[1]]=Event-Milliseconds $found[0]}
 }
 $report.query_complete=$true
}catch{}
try{if($report.clock_stable -and !(Test-BootClock)){$report.clock_stable=$false}}catch{$report.clock_stable=$false}
if(!$report.clock_stable){$report.engine_ready_ms=$null;$report.shell_start_ms=$null;$report.shell_ready_ms=$null}
[Console]::Out.Write(($report|ConvertTo-Json -Compress))
