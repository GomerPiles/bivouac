$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$facts=@{stage=0;complete=$false;failed=$false;exit_code=-1;bootstrap_verified=$false;files=0;bytes=0;elapsed_ms=0;frames=@();errors=@{file_missing=$false;file_load=$false;io=$false;access_denied=$false;not_supported=$false;web=$false;invalid_operation=$false}}
$clock=[Diagnostics.Stopwatch]::StartNew()
$begun=Get-Date
try {
 $facts.identity=Get-Content -LiteralPath 'C:\ProgramData\Bivouac\SandboxLab\identity.json' -Raw | ConvertFrom-Json
 $facts.stage=1
 $bootstrap='C:\Program Files\Bivouac\vs_buildtools.exe'
 Copy-Item -LiteralPath 'C:\BivouacBootstrap\vs_buildtools.exe' -Destination $bootstrap
 if((Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash -ine '4aad1082e180f558598c346eb105b465b4908148cb9f7f0511aa1105620e0c30'){throw 'bootstrap pin'}
 $signature=Get-AuthenticodeSignature -LiteralPath $bootstrap
 if($signature.Status -ne 'Valid' -or $null -eq $signature.TimeStamperCertificate -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'Microsoft Corporation'){throw 'bootstrap signature'}
 $facts.bootstrap_verified=$true
 $facts.stage=2
 $layout='C:\VSLayout'
 if(Test-Path -LiteralPath $layout){throw 'fresh layout required'}
 # Fixed guest-only invocation: this never runs the installer on the host.
 # The supported component selector includes compiler tools for x64/x86;
 # recommended workloads, ATL, MFC, ARM and Spectre libraries are not selected.
 $setupArgs=@('--layout','C:\VSLayout','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.Windows11SDK.26100','--lang','en-US','--quiet','--wait','--norestart')
 $process=Start-Process -FilePath $bootstrap -ArgumentList $setupArgs -PassThru -WindowStyle Hidden
 try {
  try{$process.PriorityClass=[Diagnostics.ProcessPriorityClass]::BelowNormal}catch{}
  if(!$process.WaitForExit(240000)){throw 'layout deadline'}
  $facts.exit_code=[int64]$process.ExitCode
 } finally {$process.Dispose()}
 $facts.stage=3
 if($facts.exit_code -ne 0){throw 'layout exit'}
 foreach($name in @('Catalog.json','ChannelManifest.json','Layout.json','vs_buildtools.exe')){
  if(!(Test-Path -LiteralPath (Join-Path $layout $name) -PathType Leaf)){throw 'layout metadata'}
 }
 foreach($file in @(Get-ChildItem -LiteralPath $layout -File -Recurse)){
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'layout link'}
  $facts.files++
  $facts.bytes+=$file.Length
  if($facts.files -gt 20000 -or $facts.bytes -gt 20GB){throw 'layout bound'}
 }
 Copy-Item -LiteralPath $layout -Destination 'C:\BivouacReport\msvc-layout' -Recurse
 $facts.complete=$true
 $facts.stage=4
} catch {$facts.failed=$true}
# Raw setup logs can contain URLs. Inspect them only inside the guest and emit
# a fixed vocabulary of error classes, never log lines, paths or URLs.
try {
 $texts=@()
 foreach($file in @(Get-ChildItem -LiteralPath $env:TEMP -Filter 'dd_*' -File | Where-Object {$_.LastWriteTime -ge $begun -and $_.Length -le 2MB} | Select-Object -First 16)){
  $texts+=Get-Content -LiteralPath $file.FullName -Raw
 }
 foreach($event in @(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1026;StartTime=$begun} -MaxEvents 4 -ErrorAction SilentlyContinue)){$texts+=$event.Message}
 $combined=$texts -join "`n"
 foreach($match in @([regex]::Matches($combined,'(?m)^\s*at\s+((?:System|Microsoft)\.[A-Za-z0-9_.+<>`]{1,180})\(') | Select-Object -First 16)){
  $facts.frames+=$match.Groups[1].Value
 }
 foreach($pair in @(@('file_missing','FileNotFoundException'),@('file_load','FileLoadException'),@('io','IOException'),@('access_denied','UnauthorizedAccessException'),@('not_supported','NotSupportedException'),@('web','WebException'),@('invalid_operation','InvalidOperationException'))){
  $facts.errors[$pair[0]]=$combined.Contains($pair[1])
 }
} catch {}
$facts.elapsed_ms=$clock.ElapsedMilliseconds
$facts | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath 'C:\BivouacReport\msvc-layout-result.json' -Encoding ASCII
