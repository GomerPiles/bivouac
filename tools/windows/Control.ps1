# Portable interactive controls; this does not install a login task or VM engine.
param(
    [Parameter(Mandatory)][ValidateSet('On','Off','Drain','Stop','Status')][string]$Action,
    [string]$HomeDirectory=$PSScriptRoot
)
$ErrorActionPreference='Stop'

function Assert-ManagerLaunchContext {
    # Hidden windows and redirected streams do not detach a child from its
    # parent's Windows job. Closing an IDE/agent can otherwise kill the manager
    # while its native Windows guests remain alive and consume host resources.
    if (!('BivouacManagerContext' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BivouacManagerContext {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
}
'@
    }
    $inJob=$false
    $self=[Diagnostics.Process]::GetCurrentProcess().Handle
    if (![BivouacManagerContext]::IsProcessInJob($self,[IntPtr]::Zero,[ref]$inJob)) {
        throw 'Cannot verify an independent manager launch context; run CI On from its desktop shortcut'
    }
    if ($inJob) {
        throw 'Cannot start a persistent manager inside a Windows process job; run CI On from its desktop shortcut, or use the explicitly installed login task'
    }
}

$HomeDirectory=[IO.Path]::GetFullPath($HomeDirectory)
$manifest=Get-Content -LiteralPath (Join-Path $HomeDirectory 'portable.json') -Raw | ConvertFrom-Json
$binary=[IO.Path]::GetFullPath((Join-Path $HomeDirectory $manifest.binary))
if (!$binary.StartsWith($HomeDirectory+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
    (Get-FileHash -LiteralPath $binary).Hash -ne $manifest.sha256) { throw 'Portable executable identity differs' }
$env:BIVOUAC_HOME=$HomeDirectory
if ($Action -ne 'On') {
    & $binary $Action.ToLowerInvariant()
    if ($LASTEXITCODE) { throw 'Bivouac control command failed' }
    return
}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the manager as your ordinary interactive user' }
$recordPath=Join-Path $HomeDirectory 'manager-launch.json'
$live=$false
$record=$null
if (Test-Path -LiteralPath $recordPath) {
    $record=Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json -DateKind String
    $process=Get-Process -Id $record.PID -ErrorAction SilentlyContinue
    if ($process) {
        if ($process.Path -ne $binary -or $process.StartTime.ToUniversalTime().ToString('o') -ne $record.StartedUTC -or $record.SHA256 -ne $manifest.sha256) {
            $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
            if ([DateTime]::Parse($record.StartedUTC).ToUniversalTime() -ge $boot) {
                throw 'Recorded PID identity differs; inspect it before starting another manager'
            }
        } else {
            $live=$true
        }
    }
}
if (!$live) {
    # Check before doctor, mode changes, stale-PID archival, or process launch.
    # A live manager can still receive mode commands from a contained shell.
    Assert-ManagerLaunchContext
    # Prove the actual manager lock is free; a stale/reused PID is not authority.
    $lockPath=Join-Path $HomeDirectory 'state\daemon.lock'
    $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    try { $lock.Lock(0,1); $lock.Unlock(0,1) } finally { $lock.Dispose() }
    $pidPath=Join-Path $HomeDirectory 'state\daemon.pid'
    if (Test-Path -LiteralPath $pidPath) {
        $oldPID=(Get-Content -LiteralPath $pidPath -Raw).Trim()
        if (!$record -or $oldPID -ne [string]$record.PID) { throw 'Unrecognized daemon PID record; inspect recovery' }
        # Preserve evidence and clear only this stale control hint; never VM journals.
        $stamp=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        Move-Item -LiteralPath $pidPath -Destination (Join-Path $HomeDirectory ('state\daemon.pid.stale-'+$stamp))
    }
    $check=@(& $binary doctor --github 2>&1)
    $code=$LASTEXITCODE
    $check | Write-Output
    if ($code -and $manifest.engine_startup -and @($check | Where-Object {"$_" -match '^FAIL appsandbox .*privileged broker unavailable'}).Count) {
        $startup=[IO.Path]::GetFullPath((Join-Path $HomeDirectory $manifest.engine_startup))
        if (!$startup.StartsWith($HomeDirectory+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Engine startup helper must be inside this home' }
        # The elevated helper and its progress record live in the protected
        # engine directory, never in this user-writable home. It is fixed: a
        # manifest in the home must not choose what runs elevated.
        $engineDirectory=[IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'),'bivouac','engines')
        if ($manifest.engine_directory -and ![string]::Equals([IO.Path]::GetFullPath([string]$manifest.engine_directory),$engineDirectory,[StringComparison]::OrdinalIgnoreCase)) {
            throw ('engine_directory must be '+$engineDirectory+'; remove it from portable.json')
        }
        $requested=[DateTime]::UtcNow
        & $startup -EngineDirectory $engineDirectory
        $progressPath=Join-Path $engineDirectory 'engine-startup.json'
        for ($attempt=0; $attempt -lt 30; $attempt++) {
            Start-Sleep -Seconds 3
            $check=@(& $binary doctor 2>&1)
            $code=$LASTEXITCODE
            if (!$code) { break }
            if (Test-Path -LiteralPath $progressPath) {
                $progress=Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json -DateKind String
                # Ignore a record left by an earlier attempt.
                $fresh=$progress.AtUTC -and [DateTime]::Parse($progress.AtUTC).ToUniversalTime() -ge $requested
                if ($fresh -and $progress.Stage -eq 'failed') { throw ('VM engine startup failed: '+$progress.Error) }
            }
        }
        if (!$code) { $check=@(& $binary doctor --github 2>&1); $code=$LASTEXITCODE }
        $check | Write-Output
    }
    if ($code) {
        $failures=@($check | Where-Object {"$_" -match '^FAIL '}) -join '; '
        throw ('CI prerequisites failed: '+$failures+'. See the FAIL lines above; existing VM journals are preserved.')
    }
}
& $binary on
if ($LASTEXITCODE) { throw 'Bivouac On failed' }
if ($live) { return }
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$process=Start-Process -FilePath $binary -ArgumentList @('run') -WorkingDirectory $HomeDirectory -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $HomeDirectory ('logs\manager-'+$stamp+'.stdout.log')) `
    -RedirectStandardError (Join-Path $HomeDirectory ('logs\manager-'+$stamp+'.stderr.log'))
[ordered]@{Executable=$binary;SHA256=$manifest.sha256;PID=$process.Id;StartedUTC=$process.StartTime.ToUniversalTime().ToString('o');Phase='started'} |
    ConvertTo-Json | Set-Content -LiteralPath $recordPath
Write-Output ('Bivouac manager started: '+$process.Id)
for ($attempt=0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Milliseconds 250
    $process.Refresh()
    if ($process.HasExited) { throw ('Bivouac exited during startup/recovery; inspect '+(Join-Path $HomeDirectory 'logs\bivouac.log')+'. Journals were retained.') }
    $statusPath=Join-Path $HomeDirectory 'state\status.json'
    if (Test-Path -LiteralPath $statusPath) {
        $snapshot=Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        if ($snapshot.pid -eq $process.Id) { Write-Output ('CI phase: '+$snapshot.phase); break }
    }
}
