# Experimental Windows provider

This implementation has passed trusted local/live validation and an explicit
operator-approved cutover for normal trusted jobs. The Go broker passed generic image export, fresh clone/reset, hardware
GPU/window/input, public connectivity, controlled host-denial/broker-loss checks,
interactive Actions jobs, live manager crash/adoption, graceful Off and immediate
Stop disposal. See `status.md` for validated behaviour and remaining isolation limits.
Login startup is optional and uninstalled by default. No automatic elevation
is installed.

## Operator prerequisites

- App Sandbox 0.1.9 running in an operator-approved elevated launch context.
  The provider never starts it. On this host, launching image conversion
  through Explorer succeeded where the development application's inherited
  process context caused BCDBoot failures. Its installation folder and its
  `%ProgramData%\AppSandbox` data folder must meet the protected-storage rules
  below; see the [App Sandbox prerequisites](operations.md#windows-development-boundary)
  for moving and correcting them.
- An immutable generic Windows template with autologin and App Sandbox's
  key-enabled HvSocket SSH agent. Do not include configured runners, repository
  state, credentials, or project dependencies.
- Protected storage for disposable instances and the baseline. Administrators,
  SYSTEM or TrustedInstaller must own them; unprivileged write/delete/ACL rights
  and reparse points are rejected. Ancestors must not permit replacing the protected chain.
  Administrator ownership alone is insufficient: inherited Modify permissions
  on a data drive can still allow normal users to rename ancestors.
  Prepare a separate protected storage chain; do not broadly harden production
  CI directories without checking their existing controller requirements.
- Generic tools matching the desired image: Git, PowerShell 7, compiler/SDK
  toolchain, and gzip/zstd on the machine PATH. No project-specific installation.
  An unconfigured Actions Runner 2.338.0 may be baked in, or delivered as the
  locally cached official ZIP with its SHA-256 pinned in config.
- System OpenSSH and the native App Sandbox private SSH key accessible to the
  manager's user. The App private key stays in host Credential Manager.

Create an isolated `BIVOUAC_HOME`; initialize its state with `doctor`. Use that
controller ID in the separately protected broker options:

```json
{
  "root": "D:\\RunnerVMs\\Instances",
  "controller_id": "example-controller",
  "baseline": "ci-template",
  "baseline_disk": "D:\\RunnerVMs\\Templates\\disk.vhdx",
  "baseline_sha256": "<64 hexadecimal digits>",
  "discovery": "C:\\ProgramData\\AppSandbox\\host.json",
  "guest_user": "ciuser",
  "max_cpu": 4,
  "max_memory_mb": 8192,
  "max_disk_gb": 80,
  "max_instances": 1
}
```

Run the following through the operator's elevated launch context, as the same
Windows account that runs the ordinary manager. The capability is placed in
that account's native credential store; it is not printed or written to JSON:

```text
bivouac appsandbox broker --config broker-options.json --credential windows-broker
```

The broker refuses to start unless the options file, the App Sandbox discovery
file and its `vms.cfg`, with their ancestors, meet the protected-storage rules
above; these values bound the ordinary manager, so it must not be able to edit
them. Keep the options, the elevated startup helper and the pinned executable
in the protected engine directory described in
[`operations.md`](operations.md#windows-development-boundary).

The normal manager's configuration includes:

```toml
[providers.windows]
type = "appsandbox"
labels = ["self-hosted", "Windows", "X64", "bivouac-windows-experimental"]
idle_pool = 1
max_instances = 1

[providers.windows.appsandbox]
experimental = true
broker_secret = "windows-broker"
baseline = "ci-template"
cpu = 4
memory_gb = 8
disk_gb = 80
gpu = true
runner_dir = 'C:\actions-runner'
# Optional: otherwise the baseline must contain an unconfigured runner.
# runner_archive = 'D:\Packages\actions-runner-win-x64-2.338.0.zip'
# runner_sha256 = "<64 hexadecimal digits>"
```

Use `github.demand = "jit"`, the organization registration URL, App IDs and a
credential-store item. The shared App needs organization self-hosted runners
write permission; do not change or revoke it. `doctor --github` in JIT mode
checks access without registering a runner. `bivouac on` records the mode;
`bivouac run` runs the ordinary manager in a terminal. Drain/stop/off use the
existing portable modes.

## CI image scanning and indexing policy

For the operator-selected disposable CI image,
[`Set-RunnerImagePolicy.ps1`](../tools/windows/Set-RunnerImagePolicy.ps1)
disables Defender real-time, behavior, download/attachment and script scanning,
the Defender scheduled scan, and Windows Search indexing. It uses documented
[Defender policy mappings](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus)
plus supported Defender preferences. It does not uninstall Defender or change
the host, firewall, Windows Update, network isolation or disk durability.

Run it as administrator **inside a clean App Sandbox preparation guest**, with
that guest's exact native name:

```powershell
.\Set-RunnerImagePolicy.ps1 -Action Apply -ExpectedVMName <native-vm-name>
.\Set-RunnerImagePolicy.ps1 -Action Verify -ExpectedVMName <native-vm-name>
```

Pass `-RunnerDir` and `-ProviderName` when `runner_dir` or the provider name
differ from the defaults (`C:\actions-runner`, `windows`); the enrollment
checks inspect exactly that directory and runner name pattern.
Tamper Protection must already be off through the guest Windows Security UI.
The tool refuses host execution and enrolled image-preparation guests. An
explicit `-TargetMode DisposableValidation` permits an idle recorded runner for
testing; it does not make that enrolled VM suitable for export. `-Action Restore`
restores saved guest preferences, policy values, Search startup/running state
and scheduled-scan state. A failed Apply attempts the same restoration. Do not
run the tool while a job is accepted or concurrently with another image change.

Keep the original baseline untouched. After applying the policy to a clean
preparation guest, reboot it and verify again. Seal a separate generalized,
credential-free candidate using the image preparation procedure. Remove the
guest-specific policy backup before sealing; rollback after sealing uses the
original immutable image, not a preparation guest's backup. Validate Verify in
a fresh clone, with its new native name, before admitting jobs. Verify again
after Windows/Defender servicing. Passing an immediate in-place check is not
evidence of reboot, generalization or clone persistence.

Promotion requires a new template/path/hash binding in both the normal manager
and privileged broker options. The live broker pins the old file identity,
size, modification time and hash; it cannot accept an in-place edit or hot
switch. Drain accepted jobs before an operator-approved broker restart, retain
the old image and exact old configurations for rollback, and validate a fresh
normal runner before retaining the new configuration. The current API has no
template export or broker baseline-reload operation. Without permission for
host elevation, leave image promotion pending rather than stopping the broker
or modifying the pinned image.

The protected storage root also persists the complete broker options in
`broker.json`. A changed baseline with that old binding is rejected as another
configuration. Rebind it explicitly only with the broker stopped, both normal
and protected instance journals empty, and no active native VM. Verify the old
binding first, preserve its exact bytes, and restore it along with the old
broker options and native template registry during rollback. Never rewrite this
binding while instances remain or use deletion to bypass an ownership mismatch.

## Transparent caching

Enable the same optional download accelerator as on macOS:

```toml
[cache]
enabled = true
release_proxy = true
max_gb = 20
max_object_mb = 2048
```

Windows-hosted providers default `listen = "127.0.0.1:0"` and
`guest_host = "127.0.0.1"`; other addresses are rejected. Guests reach only the
cache handler through a loopback SSH listener bound to their existing verified
transport. Keep host/LAN NIC denial unchanged. The native guest SSH service must
permit loopback remote forwarding; do not expose forwarding on a VM interface.

Both adapters install the shared Actions v2 Node preload and optional public
GitHub release proxy inside disposable guests. Windows changes only the runner
guest's machine root trust using its existing administrator account; Linux
changes only the clone's system trust. This avoids requesting protected
CurrentUser root consent over SSH. Proxy certificates include a signed CRL at
the guest's own cache endpoint so Windows retains default revocation checks.
Nothing is installed into the host or baseline. Cache settings/capabilities
travel on SSH stdin and are excluded from diagnostics. Workflow cache keys,
metadata and upstream authorization stay on GitHub. `store_uploads` would route
saves through the host relay; it is not yet validated on Windows hosts, so leave
it off. Cache setup failure removes the
partial adapter before normal runner startup. A lost host service falls back
upstream with the same limits documented for macOS; an in-flight transfer can
still fail and depend on caller retries.

The cache starts/stops with the manager and retains its bounded LRU store between
jobs. Foreground operation and Off require no startup task, proxy VM or firewall
exception. Validate cold/warm Actions restores and release downloads in fresh
clones, manager/cache outage, grant revocation, host/private-network denial, and
absence of capabilities in logs before treating parity as complete. Containers
with separate environments/trust need their own guest integration; this does not
claim OCI image caching.

## Optional startup

Foreground operation needs no login task. If desired, run `bivouac install`
from an ordinary, non-elevated shell, with the intended `BIVOUAC_HOME` set.
It registers a per-user Task Scheduler entry using a limited interactive token.
It does not change CI mode, start a VM, change PATH, create aliases, install a
service, or arrange elevated App Sandbox/broker startup. `on` can then request
that installed task; without installation, start `run` yourself. At login the
task waits 30 seconds before starting; prerequisites must already be available.
If they are unavailable, the manager fails closed and needs an explicit retry
after the operator starts them. The task is not a guarantee of unattended reboot
recovery while privileged prerequisites remain manually managed.

Use `bivouac uninstall` with the same home to remove only its matching login
task. It leaves active work alone; use Off or Stop to manage that work separately.
CI mode defaults to Off and is independent of whether startup is installed.

## Validation and cleanup

Keep production controllers, guests and labels unchanged. First validate the
new provider without GitHub: two fresh clones, hardware rendering, default
desktop/input, public DNS/HTTPS, and denial of host/gateway/private-peer/IPv6
services. Check source IP/MAC changes, dynamic host interfaces, broker loss,
partial creation/deletion and restart reconciliation. Verify both clone
sentinels and native policies, not saved Ready status.

Only after those gates pass, send one trusted test job to a separate test
label, then exercise cancellation and crash recovery. Finish with no
disposable VM, endpoint, switch, runner registration, or retained reservation.
The baseline hash must remain unchanged.

Off lets an accepted job finish before disposing the guest and exiting. Stop
signals the owned interactive runner and reclaims resources promptly. The official
runner reports this shutdown as a failed job, even when the step was canceled:
[`StepsRunner` in runner 2.338.0](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Worker/StepsRunner.cs#L134-L139).
This path does not perform a GitHub-side workflow cancellation or require broader
shared App permissions. Validate resource disposal and GitHub reporting separately.

Generalized images can expose SSH before OOBE and the intended console logon
finish. The guest preflight runs over HvSocket with no NIC attached, checks setup
state and the intended console user's Explorer, then permits network preparation.
The later interactive scheduled-task probe still verifies the default input
desktop. Do not substitute a fixed boot delay or native SSH-ready flag for these
checks, or repair/reopen a quarantined port to finish bootstrap.

The Windows job-start hook uses `.ps1`; the official runner rejects `.cmd` for
[job hooks](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/run-scripts).
It must capture the accepted job identity successfully before project steps run,
so an unobserved job cannot be treated as an idle runner during recovery.

The broker's periodic guard supplements fixed kernel policy. A live temporary
interface-addition check proved quarantine, blocked traffic and no automatic
reopening after interface removal. The broker now derives admission failure from
retained quarantine/cleanup records instead of a permanent process latch. Keep
normal manager cleanup running: after the affected owned guest, network and
record are removed, the next full successful guard pass restores admission
without broker restart. A fresh guest builds and verifies current host policy;
the quarantined guest is never reopened. Cleanup failure, an unreadable journal
or an incomplete/canceled guard pass keeps admission closed. Automatic admission
recovery has fake-backed regression coverage; live interface-change validation
of that recovery is still pending. Handling is still not atomic, and forced
broker loss removes its monitor. These limits do not establish that untrusted
workflows are isolated. A WSL private-peer comparison remained unreachable even
with the guest's deny layer removed and scoped peer ingress allowed; it is
inconclusive and needs an external reachable owner-controlled peer. Observed
guest MAC changes without a reachable spoofed control are similarly inconclusive.
The subsequent external Mac comparison passed TCP/UDP denial with normal and
secondary IPv4 sources: four controls reached the peer with only the owned deny
layer removed, and were denied before/after restoration. Source-MAC controls
still remained unreachable without that layer, so that gate stays open.
Do not bypass a failed ownership, ACL or native policy check.

### Opt-in native failure tests

`TestWindowsNativeFailureRecovery` is excluded from default tests. It needs the
`integration` build tag, explicit elevation, and
`BIVOUAC_WINDOWS_NATIVE_TEST_CONFIG` pointing to separate broker options. The
controller must be `windows-native-failure-validation`, the protected root's
basename `FailureInstances`, and the instance ceiling one. Bind it to an
immutable generic template; set `BIVOUAC_WINDOWS_NATIVE_TEST_HELPER` to the
matching Windows guest helper. Leave all managers Off and native guests stopped.
The test refuses existing reservations or active/prefixed foreign native VMs.

Build the test executable before seeking elevation, then run only
`TestWindowsNativeFailureRecovery` with a 25-minute timeout. It creates at most
one unenrolled, GPU-disabled clone at a time. Fault decorators lose responses
after real create/delete/attach operations, fail network cleanup before dispatch,
and fail policy verification and blocking. Cases reopen the protected journal,
prove marker recovery and ownership refusal, retain partial cleanup, and require
a hard stop when an owned port cannot be blocked. No GitHub credential, runner
registration, workflow, baseline mutation, or startup installation is involved.

Stop after the first failed case. Scoped cleanup uses only the recorded native
identity; uncertain cleanup retains its reservation for inspection. Do not erase
the journal or recursively remove VM storage to make the test pass. Confirm both
native inventory and protected records are empty afterward. Ordinary fake-backed
tests exercise the same response-loss and restart boundaries without elevation.

### Manual host reboot validation

Startup remains uninstalled for this check. After fault tests and cleanup pass,
record the host boot time, durable Off mode, baseline hash, and both ownership
journals for one fresh, ready **unenrolled** GPU clone. Keep its isolated network
intent and exact native identifiers. Confirm there is no accepted job or runner
registration before the operator reboots manually.

After login, verify that the boot time changed, Off persisted and no manager
started automatically. Start the approved native daemon and broker manually;
retain the same storage/controller binding and rotate the broker capability.
The broker must permit cleanup even when old network policy cannot be verified.
Run the ordinary manager in Off mode to reconcile and dispose of the retained
clone. A stopped networked clone must be discarded, never restarted with its old
binding. Confirm the VM, network endpoint/switch and both journals are gone.
Then validate a new clone's hardware rendering, window/input and native network
policy, delete it, and verify the immutable baseline hash again. Record observed
results separately from this procedure; process-crash tests do not prove host
reboot recovery.
