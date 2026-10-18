$ErrorActionPreference='Stop'
function Read-BootEvents($filter){
 $issues=@();$items=@(Get-WinEvent @filter -MaxEvents 129 -ErrorAction SilentlyContinue -ErrorVariable issues)
 if($items.Count -gt 128){throw 'bound'}
 foreach($issue in $issues){if(!$issue.FullyQualifiedErrorId.StartsWith('NoMatchingEventsFound')){throw 'query'}}
 return $items
}
function Event-Fields($item){
 $fields=@{};foreach($node in ([xml]$item.ToXml()).Event.EventData.Data){$fields[[string]$node.Name]=[string]$node.InnerText};return $fields
}
function Event-Milliseconds($item){
 if($null -eq $item){return $null}
 $span=([DateTime]$item.TimeCreated).ToUniversalTime().Subtract($boot).TotalMilliseconds
 if($span -lt 0 -or $span -gt 600000){throw 'time bound'};return [uint64]$span
}
function Test-BootClock{
 return (@(Read-BootEvents @{FilterHashtable=@{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=1}}|Where-Object {$_.RecordId -gt $bootEvent.RecordId -or $_.TimeCreated.ToUniversalTime() -ge $boot}).Count -eq 0)
}
$report=[ordered]@{boot_marker=0;clock_stable=$false;log_enabled=$false;query_complete=$false}
$boot=$null
try{
 $bootEvent=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1 -ErrorAction Stop
 $boot=[DateTimeOffset]::Parse((Event-Fields $bootEvent).StartTime).UtcDateTime
 $report.boot_marker=[uint64]$boot.Ticks
 $report.clock_stable=Test-BootClock
}catch{}
