$r=$report
$r.uptime_at_query_ms=$null;$r.event_clock_at_query_ms=$null;$r.clock_sample_span_ms=$null
$r.console_event_count=$null;$r.task_process_is_powershell=$null
try{
 if(!$r.clock_stable){throw 'clock'}
 $u=[Environment]::TickCount;$e=([DateTime]::UtcNow-$boot).TotalMilliseconds;$v=[Environment]::TickCount
 if($u -lt 1 -or $v -lt $u -or $v -gt 600000 -or $v-$u -gt 20 -or $e -lt 0 -or $e -gt 600000){throw 'bound'}
 $r.uptime_at_query_ms=$u;$r.event_clock_at_query_ms=[uint64]$e;$r.clock_sample_span_ms=$v-$u
 $r.console_event_count=@(Read-BootEvents @{FilterHashtable=@{LogName='Microsoft-Windows-PowerShell/Operational';Id=@(40961,40962);StartTime=$boot}}).Count
 $made=@(Read-BootEvents @{LogName='Microsoft-Windows-TaskScheduler/Operational';FilterXPath="*[System[EventID=129] and EventData[Data[@Name='TaskName']='\bivouac-hcs-ssh-hostkeys']]"}|Where-Object {$_.TimeCreated.ToUniversalTime() -ge $boot})
 if($made.Count -eq 1){$f=Event-Fields $made[0];if($f.TaskName -ceq '\bivouac-hcs-ssh-hostkeys'){$r.task_process_is_powershell=$f.Path -ieq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'}}
}catch{}
try{if($r.clock_stable -and !(Test-BootClock)){$r.clock_stable=$false}}catch{$r.clock_stable=$false}
if(!$r.clock_stable){$r.uptime_at_query_ms=$null;$r.event_clock_at_query_ms=$null;$r.clock_sample_span_ms=$null}
[Console]::Out.Write(($r|ConvertTo-Json -Compress))
