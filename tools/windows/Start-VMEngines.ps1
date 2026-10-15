# Explicit VM engine prerequisite startup, run through Explorer with
# Administrator consent (Start-VMEnginePrompt.ps1 requests it).
#
# Install this script, engines.json, broker-options.json and the pinned
# bivouac executable in one administrator-protected engine directory. Every
# input that parameterizes a privileged action comes from that directory, and
# every file this script writes goes there. The ordinary user's BIVOUAC_HOME
# (engines.json "Home") is writable by the unprivileged manager: it is only
# read, and its contents can only make this script refuse to start.
#
# Without -Execute the script is read-only and reports the intended action.
param([switch]$Execute)

# Load modules only from this PowerShell installation. The user's module path
# is writable by the unprivileged side and must not supply cmdlets here.
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
$ErrorActionPreference = 'Stop'

$engineDirectory = $PSScriptRoot
$progressPath = [IO.Path]::Combine($engineDirectory, 'engine-startup.json')
# Progress is written only once the engine directory is proven protected;
# writing as administrator into a user-controlled folder could be redirected.
$progressWritable = $false

function Save-Stage([string]$Stage, [string]$Message) {
    if (!$Execute -or !$progressWritable) { return }
    $record = [ordered]@{ Stage = $Stage; AtUTC = [DateTime]::UtcNow.ToString('o') }
    if ($Message) { $record.Error = $Message }
    $record | ConvertTo-Json | Set-Content -LiteralPath $progressPath
}

# Principals trusted to hold mutation rights over protected paths.
$trustedSids = @(
    'S-1-5-32-544', # BUILTIN\Administrators
    'S-1-5-18',     # NT AUTHORITY\SYSTEM
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # NT SERVICE\TrustedInstaller
)

# Mirrors checkProtected in internal/provider/appsandbox/native_windows.go.
# A protected path is not a reparse point, is owned by a trusted principal,
# and grants no other principal rights to rewrite, replace or re-permission
# it. With -Ancestor only rights that could rename or replace the protected
# entry below matter; creating unrelated children is allowed.
function Assert-Protected {
    param([Parameter(Mandatory)][string]$Path, [switch]$Ancestor)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Protected path is a reparse point: $Path"
    }
    $binary = (Get-Acl -LiteralPath $Path).GetSecurityDescriptorBinaryForm()
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($binary, 0)
    if ($descriptor.Owner.Value -notin $trustedSids) {
        throw "Protected path owner must be Administrators, SYSTEM or TrustedInstaller: $Path"
    }
    if ($null -eq $descriptor.DiscretionaryAcl) {
        throw "Protected path requires an explicit access policy: $Path"
    }
    # GENERIC_ALL, WRITE_DAC, WRITE_OWNER and FILE_DELETE_CHILD.
    $mutation = 0x10000000 -bor 0x00040000 -bor 0x00080000 -bor 0x00000040
    $full = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetPathRoot($full) -ne $full) {
        # DELETE on any entry but a volume root allows renaming the chain.
        $mutation = $mutation -bor 0x00010000
    }
    if (!$Ancestor) {
        # GENERIC_WRITE, FILE_WRITE_DATA (add file), FILE_APPEND_DATA (add
        # subdirectory), FILE_WRITE_EA and FILE_WRITE_ATTRIBUTES.
        $mutation = $mutation -bor 0x40000000 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x100
    }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.AceFlags.HasFlag([Security.AccessControl.AceFlags]::InheritOnly)) { continue }
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback) {
            throw "Unsupported access entry on protected path: $Path"
        }
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) { continue }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {
            throw "Unsupported access entry on protected path: $Path"
        }
        if (($ace.AccessMask -band $mutation) -eq 0) { continue }
        if ($ace.SecurityIdentifier.Value -notin $trustedSids) {
            throw "Protected path grants mutation rights to another principal: $Path"
        }
    }
}

# A protected file or directory plus every ancestor up to its volume root.
function Assert-ProtectedChain([string]$Path) {
    if (![IO.Path]::IsPathFullyQualified($Path) -or $Path.StartsWith('\\')) {
        throw "Protected path must be local and absolute: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    Assert-Protected -Path $full
    $current = [IO.Path]::GetDirectoryName($full)
    while ($current) {
        Assert-Protected -Path $current -Ancestor
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Read-ProtectedJson([string]$Path) {
    Assert-ProtectedChain $Path
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -DateKind String
}

# Files under the ordinary user's home only gate refusal. Errors use a fixed
# message so a redirected path cannot copy protected content into progress.
function Read-UntrustedJson([string]$Path, [string]$Label) {
    try {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 1MB) { throw }
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -DateKind String
    } catch {
        throw "Cannot read $Label; inspect recovery"
    }
}

# Opens a pinned executable for reading while denying writers and deletion,
# then hashes it through that handle. Keep the handle open until the process
# has started, so the verified bytes are the bytes that run.
function Open-PinnedExecutable([string]$Path, [string]$Sha256) {
    if ($Sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "Executable pin is not a SHA-256 digest: $Path" }
    Assert-ProtectedChain $Path
    # Libraries are loaded from the executable's folder: it must not admit new files.
    Assert-Protected -Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path)))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $digest = [Convert]::ToHexString($hasher.ComputeHash($stream)) } finally { $hasher.Dispose() }
        if ($digest -ne $Sha256.ToUpperInvariant()) { throw "Native executable pin differs: $Path" }
    } catch {
        $stream.Dispose()
        throw
    }
    return $stream
}

# Mirrors sweepStaging and stagingFiles in internal/provider/crosvm/backend.go.
# A Linux Create that crashed before its rename leaves '.creating-<id>' holding
# only marker files; the backend sweeps it when it next opens, after this
# helper. It never holds a disk or process. Anything else is not staging.
function Test-LinuxStaging([IO.DirectoryInfo]$Directory) {
    if ($Directory.Name -cnotmatch '^\.creating-[0-9a-f]{8}$' -or
        $Directory.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { return $false }
    $markers = @('owner.json.new', '.bivouac-owner.json.new', 'owner.json', '.bivouac-owner.json')
    foreach ($entry in Get-ChildItem -LiteralPath $Directory.FullName -Force) {
        if ($entry -isnot [IO.FileInfo] -or $entry.Name -cnotin $markers -or
            $entry.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { return $false }
    }
    return $true
}

# Mirrors the broker's check of the App Sandbox discovery file and the vms.cfg
# beside it, so an unprotected App Sandbox data folder is refused before
# anything starts, including in the read-only mode. The daemon rewrites the
# discovery file on start: until it is ready (-Present) a missing file is
# allowed, but the folder and its ancestors must already be protected.
function Assert-AppSandboxData([string]$Discovery, [switch]$Present) {
    try {
        if (![IO.Path]::IsPathFullyQualified($Discovery) -or $Discovery.StartsWith('\\')) {
            throw "Protected path must be local and absolute: $Discovery"
        }
        $folder = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Discovery))
        foreach ($path in @($Discovery, [IO.Path]::Combine($folder, 'vms.cfg'))) {
            if ($Present -or (Test-Path -LiteralPath $path)) { Assert-ProtectedChain $path }
        }
        for ($current = $folder; $current; $current = [IO.Path]::GetDirectoryName($current)) {
            Assert-Protected -Path $current -Ancestor
        }
    } catch {
        throw ('App Sandbox data folder is not administrator-protected; see the migration prerequisites in operations.md. ' + $_.Exception.Message)
    }
}

$pinned = @()
try {
    # Verify this script, its folder and this PowerShell before trusting any
    # input. A misplaced copy outside a protected folder refuses to run.
    Assert-ProtectedChain $PSCommandPath
    Assert-Protected -Path $engineDirectory
    Assert-ProtectedChain ([IO.Path]::Combine($PSHOME, 'pwsh.exe'))
    Assert-Protected -Path $PSHOME
    $progressWritable = $true
    Save-Stage 'helper-started'

    $manifest = Read-ProtectedJson ([IO.Path]::Combine($engineDirectory, 'engines.json'))
    $optionsPath = [IO.Path]::Combine($engineDirectory, 'broker-options.json')
    $options = Read-ProtectedJson $optionsPath
    if ([string]$manifest.Broker -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.exe$') {
        throw 'Broker must name an executable inside the engine directory'
    }
    $brokerPath = [IO.Path]::Combine($engineDirectory, $manifest.Broker)
    $userHome = [string]$manifest.Home
    if (![IO.Path]::IsPathFullyQualified($userHome) -or $userHome.StartsWith('\\')) {
        throw 'Engine manifest Home must be the absolute ordinary-user BIVOUAC_HOME'
    }

    # Ownership binding: manager state, storage owner marker and broker
    # options must all name the controller this manifest was set up for.
    $state = Read-UntrustedJson ([IO.Path]::Combine($userHome, 'state', 'instances.json')) 'manager state'
    $owner = Read-UntrustedJson $manifest.OwnerFile 'storage owner marker'
    if ($state.controller_id -ne $manifest.Controller -or $owner.OwnerId -ne $manifest.OwnerId -or $options.controller_id -ne $manifest.Controller) {
        throw 'Owned engine binding differs; inspect recovery before starting'
    }

    Assert-AppSandboxData $options.discovery

    # Pin both executables before anything is started.
    try {
        $daemonStream = Open-PinnedExecutable $manifest.Daemon $manifest.DaemonSHA256
    } catch {
        throw ('App Sandbox installation is not administrator-protected or not the pinned build; see the migration prerequisites in operations.md. ' + $_.Exception.Message)
    }
    $pinned += $daemonStream
    $brokerStream = Open-PinnedExecutable $brokerPath $manifest.BrokerSHA256
    $pinned += $brokerStream

    # Retained instances must predate this boot and match their protected
    # native records exactly. They are left for manager reconciliation.
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    $recordsPath = [IO.Path]::Combine($options.root, 'records')
    $linuxPath = [IO.Path]::Combine($userHome, 'native', 'linux')
    $ownedNames = @()
    foreach ($property in $state.instances.PSObject.Properties) {
        $instance = $property.Value
        if ($property.Name -notmatch '^[a-f0-9]{8}$' -or $instance.id -ne $property.Name -or
            $instance.name -ne ('bivouac-' + $instance.provider + '-' + $instance.id) -or
            [DateTime]::Parse($instance.created_at).ToUniversalTime() -ge $boot) {
            throw 'Retained instance is not from before this host boot; inspect recovery'
        }
        $windowsRecord = [IO.Path]::Combine($recordsPath, $instance.id + '.json')
        $linuxDirectory = [IO.Path]::Combine($linuxPath, $instance.id)

        if ($instance.phase -eq 'deregistering') {
            # Registration-only records stay for the manager's retry loop once
            # their guest is provably gone from before this boot.
            if (!$instance.guest_deleted_at -or [DateTime]::Parse($instance.guest_deleted_at).Year -lt 2000 -or
                [DateTime]::Parse($instance.guest_deleted_at).ToUniversalTime() -ge $boot) {
                throw 'Deleted guest proof does not predate this host boot'
            }
            if ($instance.provider -eq 'windows') {
                if ((Test-Path -LiteralPath ([IO.Path]::Combine($options.root, $instance.id))) -or (Test-Path -LiteralPath $windowsRecord)) {
                    throw 'Deleted Windows instance still has native reservations'
                }
            } elseif ($instance.provider -eq 'linux') {
                if (Test-Path -LiteralPath $linuxDirectory) { throw 'Deleted Linux instance still has native reservations' }
            } else {
                throw 'Unknown deregistering provider'
            }
            continue
        }

        if ($instance.provider -eq 'windows') {
            $record = Get-Content -LiteralPath $windowsRecord -Raw | ConvertFrom-Json
            if ($record.clone.meta.controller_id -ne $manifest.Controller -or $record.clone.meta.instance_id -ne $instance.id -or
                $record.clone.runner_name -ne $instance.name -or
                $record.clone.storage_parent -ne [IO.Path]::Combine($options.root, $instance.id) -or
                $record.clone.template -ne $options.baseline) {
                throw 'Retained Windows ownership differs'
            }
            $ownedNames += $record.clone.native_name
        } elseif ($instance.provider -eq 'linux') {
            $record = (Read-UntrustedJson ([IO.Path]::Combine($linuxDirectory, 'owner.json')) 'Linux owner record').record
            $native = Read-UntrustedJson ([IO.Path]::Combine($linuxDirectory, 'native.json')) 'Linux native record'
            if ($record.meta.controller_id -ne $manifest.Controller -or $record.meta.instance_id -ne $instance.id -or
                $record.name -ne $instance.name -or $record.directory -ne $linuxDirectory -or
                [DateTime]::FromFileTimeUtc($native.supervisor.created) -ge $boot -or
                ($native.vm.created -and [DateTime]::FromFileTimeUtc($native.vm.created) -ge $boot)) {
                throw 'Retained Linux ownership differs'
            }
        } else {
            throw 'Unknown retained provider'
        }
    }

    # Every native reservation must belong to a retained manager record.
    $instances = @($state.instances.PSObject.Properties.Value)
    $windowsIDs = @($instances | Where-Object provider -eq 'windows' | ForEach-Object id)
    $linuxIDs = @($instances | Where-Object provider -eq 'linux' | ForEach-Object id)
    foreach ($file in Get-ChildItem -LiteralPath $recordsPath -File) {
        if ($file.Extension -ne '.json' -or $file.BaseName -notin $windowsIDs) { throw 'Unmatched protected record; inspect recovery' }
    }
    foreach ($directory in Get-ChildItem -LiteralPath $options.root -Directory | Where-Object Name -ne 'records') {
        if ($directory.Name -notin $windowsIDs) { throw 'Unmatched protected instance; inspect recovery' }
    }
    if (Test-Path -LiteralPath $linuxPath) {
        foreach ($directory in Get-ChildItem -LiteralPath $linuxPath -Directory -Force) {
            if ($directory.Name -cnotin $linuxIDs -and !(Test-LinuxStaging $directory)) { throw 'Unmatched Linux instance; inspect recovery' }
        }
    }

    if (!$Execute) {
        [ordered]@{
            Action            = 'Start absent App Sandbox and protected broker; preserve pre-boot journals for manager reconciliation'
            Controller        = $manifest.Controller
            RetainedInstances = $instances.Count
            Stops             = 0
            VMsStarted        = 0
            StartupInstalled  = $false
        } | ConvertTo-Json
        return
    }

    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator consent required'
    }
    # App Sandbox image operations fail inside an inherited process job; the
    # Explorer launch context has none.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BivouacEngineContext {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
}
'@
    $inJob = $false
    $self = [Diagnostics.Process]::GetCurrentProcess().Handle
    if (![BivouacEngineContext]::IsProcessInJob($self, [IntPtr]::Zero, [ref]$inJob) -or $inJob) {
        throw 'Explorer launch context required'
    }

    # Never stop or replace running work.
    $active = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq 'crosvm.exe' -or
        ($_.Name -in @('pwsh.exe', 'powershell.exe') -and $_.CommandLine -match '(Lifecycle\.ps1|Crosvm\.Controller\.ps1)') -or
        ($_.Name -like 'bivouac*' -and $_.CommandLine -match '(^|\s)run(\s|$)')
    })
    if ($active.Count) { throw 'A manager or VM is active; this helper will not stop it' }

    $daemon = @(Get-CimInstance Win32_Process | Where-Object Name -eq 'AppSandbox.exe')
    if ($daemon.Count -gt 1 -or ($daemon.Count -eq 1 -and $daemon[0].ExecutablePath -ne $manifest.Daemon)) {
        throw 'App Sandbox identity differs'
    }
    if (!$daemon.Count) {
        Save-Stage 'starting-daemon'
        $process = Start-Process -FilePath $manifest.Daemon -ArgumentList @('--headless') -WorkingDirectory ([IO.Path]::GetDirectoryName($manifest.Daemon)) -WindowStyle Hidden -PassThru
        [ordered]@{
            Executable = $manifest.Daemon
            SHA256     = $manifest.DaemonSHA256
            PID        = $process.Id
            StartedUTC = $process.StartTime.ToUniversalTime().ToString('o')
        } | ConvertTo-Json | Set-Content -LiteralPath ([IO.Path]::Combine($engineDirectory, 'daemon-launch.json'))
    }

    # Inspect with the pinned broker executable, never a home-supplied one.
    $ready = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $json = & $brokerPath appsandbox inspect --discovery $options.discovery 2>$null
        if ($LASTEXITCODE -eq 0) {
            $inventory = ($json -join "`n") | ConvertFrom-Json
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (!$ready) { throw 'App Sandbox API not ready; leave daemon running for inspection' }
    # The broker would refuse these files; refuse before launching it.
    Assert-AppSandboxData $options.discovery -Present
    $unexpected = @($inventory.foreign_vms | Where-Object {
        $_.running -or $_.building -or ($_.name -like 'bivouac-*' -and $_.name -notin $ownedNames)
    })
    if ($unexpected.Count) { throw 'Native inventory contains an active or unowned VM; leave engine running for inspection' }

    $brokers = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'bivouac*' -and $_.CommandLine -match 'appsandbox\s+broker' })
    if ($brokers.Count) { throw 'A broker already runs; inspect it rather than replace it' }

    # Start-Process joins -ArgumentList elements with spaces and does not quote
    # them. Every element is therefore a plain token: the options file is named
    # relative to the protected working directory, which the broker resolves
    # and checks again before reading it.
    $brokerArguments = @('appsandbox', 'broker', '--config', 'broker-options.json', '--credential', [string]$manifest.Credential)
    foreach ($argument in $brokerArguments) {
        if ($argument -cnotmatch '^[A-Za-z0-9._-]+$') { throw 'Broker arguments must be plain tokens' }
    }
    $logs = [IO.Path]::Combine($engineDirectory, 'logs')
    if (!(Test-Path -LiteralPath $logs)) { New-Item -ItemType Directory -Path $logs | Out-Null }
    Assert-Protected -Path $logs
    $stamp = Get-Date -Format yyyyMMdd-HHmmss
    Save-Stage 'starting-broker'
    $process = Start-Process -FilePath $brokerPath -ArgumentList $brokerArguments -WorkingDirectory $engineDirectory -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput ([IO.Path]::Combine($logs, 'broker-' + $stamp + '.stdout.log')) `
        -RedirectStandardError ([IO.Path]::Combine($logs, 'broker-' + $stamp + '.stderr.log'))
    [ordered]@{
        OwnerId    = $manifest.OwnerId
        Controller = $manifest.Controller
        Executable = $brokerPath
        SHA256     = $manifest.BrokerSHA256
        PID        = $process.Id
        StartedUTC = $process.StartTime.ToUniversalTime().ToString('o')
        Phase      = 'started'
    } | ConvertTo-Json | Set-Content -LiteralPath ([IO.Path]::Combine($engineDirectory, 'broker-launch.json'))
    Write-Output 'VM engines started. Run CI On from your ordinary desktop user.'
    Save-Stage 'started'
} catch {
    Save-Stage 'failed' $_.Exception.Message
    throw
} finally {
    foreach ($stream in $pinned) { $stream.Dispose() }
}
