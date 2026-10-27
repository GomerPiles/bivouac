$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$facts=@{stage=0;failed=$false}
try {
 $facts.stage=1
 foreach($dir in @('C:\Program Files\Bivouac','C:\ProgramData\Bivouac','C:\ProgramData\Bivouac\Agent','C:\ProgramData\Bivouac\Guest','C:\ProgramData\Bivouac\SandboxLab')){
  if(Test-Path -LiteralPath $dir){throw 'existing lab directory'}
  New-Item -ItemType Directory -Path $dir | Out-Null
  & 'C:\Windows\System32\icacls.exe' @($dir,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F') *> $null
  if($LASTEXITCODE -ne 0){throw 'lab ACL'}
 }
 $record=Get-Content -LiteralPath 'C:\BivouacBootstrap\record.json' -Raw | ConvertFrom-Json
 $record.phase='started'
 $record.boot=[guid]::NewGuid().ToString()
 $record | ConvertTo-Json -Compress | Set-Content -LiteralPath 'C:\ProgramData\Bivouac\SandboxLab\identity.json' -Encoding ASCII
 Copy-Item -LiteralPath 'C:\BivouacBootstrap\sandbox-lab.exe' -Destination 'C:\Program Files\Bivouac\sandbox-lab.exe'
 Copy-Item -LiteralPath 'C:\BivouacBootstrap\bivouac.exe' -Destination 'C:\Program Files\Bivouac\bivouac.exe'
 $facts.stage=2
 $settings=Get-Content -LiteralPath 'C:\BivouacBootstrap\settings.json' -Raw | ConvertFrom-Json
 if($settings.runner_sha256 -notmatch '^[0-9a-f]{64}$'){throw 'digest shape'}
 if((Get-FileHash -LiteralPath 'C:\BivouacBootstrap\runner.zip' -Algorithm SHA256).Hash -ine $settings.runner_sha256){throw 'runner digest'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 [IO.Compression.ZipFile]::ExtractToDirectory('C:\BivouacBootstrap\runner.zip','C:\actions-runner')
 $facts.stage=3
 $mode='agent'
 if($settings.secure_probe){$mode='agent-secure'}
 if($settings.network_probe){$mode='agent-tcp'}
 if($settings.reverse_probe){$mode='agent-reverse'}
 $action=New-ScheduledTaskAction -Execute 'C:\Program Files\Bivouac\sandbox-lab.exe' -Argument $mode
 $principal=New-ScheduledTaskPrincipal -UserId 'WDAGUtilityAccount' -LogonType Interactive -RunLevel Highest
 $taskSettings=New-ScheduledTaskSettingsSet -Priority 4 -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName 'bivouac-sandbox-lab-agent' -Principal $principal -Action $action -Settings $taskSettings | Out-Null
 Start-ScheduledTask -TaskName 'bivouac-sandbox-lab-agent'
 if($settings.network_probe -and !$settings.reverse_probe){
  $deadline=[DateTime]::UtcNow.AddSeconds(30)
  while(!(Test-Path -LiteralPath 'C:\BivouacReport\tcp.json')){
   if([DateTime]::UtcNow -gt $deadline){throw 'TCP readiness'}
   Start-Sleep -Milliseconds 200
  }
  $tcp=Get-Content -LiteralPath 'C:\BivouacReport\tcp.json' -Raw | ConvertFrom-Json
  if($tcp.port -isnot [int] -or $tcp.port -lt 1 -or $tcp.port -gt 65535){throw 'TCP port'}
  # This changes only the disposable guest. Client certificates remain
  # mandatory; no host firewall rule or shared switch setting is changed.
  New-NetFirewallRule -DisplayName 'bivouac-sandbox-lab-control' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $tcp.port -Program 'C:\Program Files\Bivouac\sandbox-lab.exe' -Profile Any | Out-Null
 }
 $facts.stage=4
 $facts.smoke=& 'C:\Program Files\Bivouac\sandbox-lab.exe' @('smoke') | ConvertFrom-Json
 if($LASTEXITCODE -ne 0){throw 'direct smoke'}
 $facts.stage=5
} catch {$facts.failed=$true}
$facts | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath 'C:\BivouacReport\boot.json' -Encoding ASCII
