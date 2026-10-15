# Run inside an explicitly selected App Sandbox Windows guest, never on the host.
param(
    [ValidateSet('Apply','Verify','Restore')][string]$Action='Verify',
    [Parameter(Mandatory)][string]$ExpectedVMName,
    [ValidateSet('ImagePreparation','DisposableValidation')][string]$TargetMode='ImagePreparation',
    # Must match the provider's appsandbox.runner_dir and provider name;
    # otherwise the enrollment checks below would inspect the wrong place.
    [string]$RunnerDir='C:\actions-runner',
    [string]$ProviderName='windows'
)
$ErrorActionPreference='Stop'
$WarningPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
if($ExpectedVMName -cnotmatch '^bivouac-[a-z2-7]{7}$' -or $env:COMPUTERNAME -ine $ExpectedVMName -or !(Test-Path -LiteralPath 'C:\Windows\AppSandbox' -PathType Container)) {throw 'An explicitly selected App Sandbox guest is required'}
# Same rules as the provider's runner_dir validation: a dedicated C:\ path
# outside the Windows directory, without traversal or control characters.
$runnerLower=$RunnerDir.ToLowerInvariant()
if($RunnerDir.Length -le 3 -or !$runnerLower.StartsWith('c:\') -or $RunnerDir -match '[\x00-\x1f]' -or $RunnerDir.Contains('..') -or
   $runnerLower.TrimEnd('\') -eq 'c:\windows' -or $runnerLower.StartsWith('c:\windows\')) {throw 'RunnerDir must be the dedicated absolute C:\ runner directory'}
# Same rule as provider names: 1-31 letters, digits or inner hyphens.
if($ProviderName -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,29}[A-Za-z0-9])?$') {throw 'ProviderName is not a valid provider name'}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Guest administrator privileges required; no elevation is attempted'}
$guest='C:\ProgramData\Bivouac\Guest'
if(Test-Path -LiteralPath (Join-Path $guest 'job.json')) {throw 'An accepted CI job prevents image-policy changes'}
$registered=(Test-Path -LiteralPath (Join-Path $RunnerDir '.runner')) -or (Test-Path -LiteralPath (Join-Path $RunnerDir '.credentials')) -or (Test-Path -LiteralPath (Join-Path $guest 'config.json'))
if($TargetMode -eq 'ImagePreparation' -and $registered) {throw 'Image preparation requires a clean unenrolled guest; never export an enrolled runner'}
if($TargetMode -eq 'DisposableValidation') {
    $cfg=Get-Content -LiteralPath (Join-Path $guest 'config.json') -Raw | ConvertFrom-Json
    $runnerPattern='^bivouac-'+[regex]::Escape($ProviderName)+'-[a-f0-9]{8}$'
    if($cfg.native_name -cne $ExpectedVMName -or $cfg.runner_name -cnotmatch $runnerPattern -or $cfg.runner_dir -ine $RunnerDir) {throw 'Disposable validation identity differs'}
}
$root='C:\ProgramData\Bivouac\ImagePolicy'
$backup=Join-Path $root 'original.json'
$policy='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
$preferenceNames=@('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning')
# These are the documented ADMX registry mappings. Script scanning uses its
# supported Defender preference, rather than an undocumented registry setting.
$policyNames=@('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection')
$taskPath='\Microsoft\Windows\Windows Defender\'
$taskName='Windows Defender Scheduled Scan'
function Read-PolicyState {
    $mp=Get-MpComputerStatus
    $prefs=Get-MpPreference
    $search=Get-Service -Name WSearch
    $scan=Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    $policiesPresent=$true
    foreach($name in $policyNames) {
        $value=Get-ItemProperty -LiteralPath $policy -Name $name -ErrorAction SilentlyContinue
        if(!$value -or $value.$name -ne 1) {$policiesPresent=$false}
    }
    [ordered]@{
        TamperProtected=[bool]$mp.IsTamperProtected
        RealtimeEnabled=[bool]$mp.RealTimeProtectionEnabled
        BehaviorEnabled=[bool]$mp.BehaviorMonitorEnabled
        IOAVEnabled=[bool]$mp.IoavProtectionEnabled
        RealTimeDisabled=[bool]$prefs.DisableRealtimeMonitoring
        BehaviorDisabled=[bool]$prefs.DisableBehaviorMonitoring
        IOAVDisabled=[bool]$prefs.DisableIOAVProtection
        ScriptDisabled=[bool]$prefs.DisableScriptScanning
        PolicyPresent=$policiesPresent
        SearchStopped=($search.Status -eq 'Stopped')
        SearchDisabled=($search.StartType -eq 'Disabled')
        ScheduledScanDisabled=(!$scan -or !$scan.Settings.Enabled)
    }
}
function Restore-Policy {
    $saved=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    if($saved.VMName -cne $ExpectedVMName) {throw 'Policy backup belongs to a different guest'}
    foreach($entry in $saved.Registry) {
        if($entry.Present) {
            New-Item -Path $policy -Force | Out-Null
            New-ItemProperty -LiteralPath $policy -Name $entry.Name -Value ([int]$entry.Value) -PropertyType DWord -Force | Out-Null
        } else {Remove-ItemProperty -LiteralPath $policy -Name $entry.Name -ErrorAction SilentlyContinue}
    }
    Set-MpPreference -DisableRealtimeMonitoring ([bool]$saved.Preferences.DisableRealtimeMonitoring) -DisableBehaviorMonitoring ([bool]$saved.Preferences.DisableBehaviorMonitoring) -DisableIOAVProtection ([bool]$saved.Preferences.DisableIOAVProtection) -DisableScriptScanning ([bool]$saved.Preferences.DisableScriptScanning)
    Set-Service -Name WSearch -StartupType $saved.SearchStartup
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch' -Name DelayedAutoStart -Value ([int]$saved.SearchDelayed) -PropertyType DWord -Force | Out-Null
    if($saved.SearchRunning) {Start-Service -Name WSearch} else {Stop-Service -Name WSearch}
    if($saved.ScanPresent) {
        if($saved.ScanEnabled) {Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName | Out-Null} else {Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName | Out-Null}
    }
}
if($Action -eq 'Restore') {
    Restore-Policy
    Read-PolicyState | ConvertTo-Json -Compress
    return
}
if($Action -eq 'Apply') {
    if((Get-MpComputerStatus).IsTamperProtected) {throw 'Turn Tamper Protection off through the guest Windows Security UI first'}
    foreach($name in $preferenceNames) {if(!(Get-Command Set-MpPreference).Parameters.ContainsKey($name)) {throw 'Required Defender preference unavailable'}}
    if(!(Test-Path -LiteralPath $backup)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $prefs=Get-MpPreference
        $registry=@(foreach($name in $policyNames) {
            $value=Get-ItemProperty -LiteralPath $policy -Name $name -ErrorAction SilentlyContinue
            [ordered]@{Name=$name;Present=($null -ne $value);Value=if($value){[int]$value.$name}else{0}}
        })
        $search=Get-Service -Name WSearch
        $delayed=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch' -Name DelayedAutoStart -ErrorAction SilentlyContinue
        $scan=Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        [ordered]@{VMName=$ExpectedVMName;Registry=$registry;Preferences=@{DisableRealtimeMonitoring=[bool]$prefs.DisableRealtimeMonitoring;DisableBehaviorMonitoring=[bool]$prefs.DisableBehaviorMonitoring;DisableIOAVProtection=[bool]$prefs.DisableIOAVProtection;DisableScriptScanning=[bool]$prefs.DisableScriptScanning};SearchStartup=$search.StartType.ToString();SearchRunning=($search.Status -eq 'Running');SearchDelayed=if($delayed){[int]$delayed.DelayedAutoStart}else{0};ScanPresent=($null -ne $scan);ScanEnabled=if($scan){[bool]$scan.Settings.Enabled}else{$false}} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backup -Encoding UTF8
    } else {
        $saved=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
        if($saved.VMName -cne $ExpectedVMName) {throw 'Policy backup belongs to a different guest'}
    }
    try {
        New-Item -Path $policy -Force | Out-Null
        foreach($name in $policyNames) {New-ItemProperty -LiteralPath $policy -Name $name -Value 1 -PropertyType DWord -Force | Out-Null}
        Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true
        if(Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue) {Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName | Out-Null}
        Set-Service -Name WSearch -StartupType Disabled
        Stop-Service -Name WSearch
        (Get-Service -Name WSearch).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
    } catch {
        Restore-Policy
        throw 'Image policy application failed; original settings restored'
    }
}
$deadline=[DateTime]::UtcNow.AddSeconds(20)
do {
    $state=Read-PolicyState
    $ready=!$state.TamperProtected -and !$state.RealtimeEnabled -and !$state.BehaviorEnabled -and !$state.IOAVEnabled -and $state.RealTimeDisabled -and $state.BehaviorDisabled -and $state.IOAVDisabled -and $state.ScriptDisabled -and $state.PolicyPresent -and $state.SearchStopped -and $state.SearchDisabled -and $state.ScheduledScanDisabled
    if($ready) {$state | ConvertTo-Json -Compress;return}
    Start-Sleep -Milliseconds 250
} while([DateTime]::UtcNow -lt $deadline)
if($Action -eq 'Apply') {Restore-Policy}
throw 'Image policy verification failed; no verified baseline should be promoted'
