# Untrusted setup facts: copy fixed numeric fields only, never guest text.
function Read-VideoNumber($Value,[uint64]$Maximum){
 if(($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt 0 -or $Value -gt $Maximum){throw 'video number'}
 return [uint32]$Value
}
function Read-VideoDiagnostics($Video){
 $result=@{}
 if($null -eq $Video){return $result}
 foreach($stage in @('specialize_before','specialize_after','first_logon')){
  $source=$Video.$stage
  if($null -eq $source){continue}
  $count=Read-VideoNumber $source.node_count 32
  if($source.nodes -isnot [array] -or $source.nodes.Count -ne $count){throw 'video node count'}
  $nodes=@()
  foreach($node in $source.nodes){
   $fact=@{}
   foreach($field in @('present','config_flags_present','csconfig_flags_present')){$fact[$field]=Read-VideoNumber $node.$field 1}
   foreach($field in @('problem_code','devnode_status','config_flags','csconfig_flags')){$fact[$field]=Read-VideoNumber $node.$field ([uint32]::MaxValue)}
   $nodes+=$fact
  }
  $result[$stage]=@{node_count=$count;nodes=@($nodes)}
 }
 foreach($stage in @('specialize_enable','first_logon_enable')){
  $source=$Video.$stage
  if($null -eq $source){continue}
  $returned=Read-VideoNumber $source.returned 1
  if($source.attempts -isnot [array] -or $source.attempts.Count -gt 32){throw 'video attempt count'}
  $attempts=@();$seen=@{}
  foreach($attempt in $source.attempts){
   $index=Read-VideoNumber $attempt.node_index 31
   if($seen.ContainsKey($index)){throw 'duplicate video attempt'};$seen[$index]=$true
   $fact=@{node_index=$index;pnputil_exit_code=(Read-VideoNumber $attempt.pnputil_exit_code ([uint32]::MaxValue))}
   foreach($field in @('flags_cleared','pnputil_started','fallback_attempted','fallback_succeeded','returned')){$fact[$field]=Read-VideoNumber $attempt.$field 1}
   $attempts+=$fact
  }
  $result[$stage]=@{returned=$returned;attempts=@($attempts)}
 }
 return $result
}
