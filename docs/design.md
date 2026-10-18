# Design

Bivouac runs each GitHub Actions job in a disposable guest on a personal
machine and discards the guest afterwards. This document owns the
architecture, the provider contract, the lifecycle state machine, the
security model, and durable decisions. Keep it aligned with the code.

## Architecture

```
cmd/bivouac          CLI; `biv` is a symlink to the same binary
internal/manager     control-mode loop, scale set pollers, instance lifecycle, budgets, reconcile
internal/provider    provider contract; vz/ (macOS), appsandbox/ and crosvm/ (Windows host experiments), fake/
internal/vm          the VM store, VM manifests, Tart-format import, and the Virtualization.framework helper (`vm run`)
internal/guestagent  in-guest command agent over vsock, and its host client
internal/engine      bounded opaque container API streams between disposable guests
internal/github      scale set client wrapper (actions/scaleset) and test fake
internal/state       durable instance records and controller ID (atomic JSON)
internal/control     mode file, pid file, status snapshot (CLI <-> daemon)
internal/config      one TOML file, validated, no secrets
internal/secret      credential store (Keychain; native Windows Credential Manager)
internal/diag        diagnostics collection with redaction
internal/perf        bounded numeric host/guest performance sampling
internal/cache       bounded objects, authenticated download service, guest client
internal/redact      credential redaction applied at every sink
internal/install     optional launchd LaunchAgent (macOS) / limited per-user login task (Windows)
```

The daemon (`bivouac run`) is one process. The CLI talks to it through
files in the state directory: a durable `mode` file, `daemon.pid` (the CLI
sends SIGUSR1 so the daemon re-reads the mode now, but only while a
nonblocking shared-lock probe shows the daemon lock held; a stale PID is
never signalled), and `status.json` the
daemon rewrites on every change. No sockets or HTTP until the localhost API
milestone.

### Locations

| | macOS | Windows (planned) |
| --- | --- | --- |
| Config | `~/Library/Application Support/bivouac/config.toml` | `%APPDATA%\bivouac\config.toml` |
| State | `~/Library/Application Support/bivouac/state/` | `%LOCALAPPDATA%\bivouac\state\` |
| Logs, diagnostics | `~/Library/Logs/bivouac/`, `.../diagnostics/` | `%LOCALAPPDATA%\bivouac\logs\` |

`BIVOUAC_HOME` overrides all three for tests and side-by-side validation.

## Control modes

The mode is durable and survives reboots. `on`, `drain`, `stop`, and `off`
write it and nudge the daemon.

| Mode | Session | Guest launches | Active jobs | Daemon afterwards |
| --- | --- | --- | --- | --- |
| on | open | within local budgets | run | polling |
| drain | open | none | finish, guests disposed | idle, stays running |
| stop | open | none | cancelled now, guests destroyed | idle, stays running |
| off | closed | | finish, guests disposed | exits; stays down across reboots |

The session stays open in drain and stop to preserve pending assignments
and receive job-completion messages (see "Routing" below).

Foreground operation requires no login item. Startup is uninstalled by default;
only the explicit `install` command opts in, without changing durable CI mode.
No build, doctor, provider operation, or `on` command installs it implicitly.
Aliases and PATH edits are not performed by installation.

The optional LaunchAgent has `RunAtLoad` and `KeepAlive.SuccessfulExit=false`: at
login the daemon starts, reconciles, and exits at once if the mode is off.
`on` kickstarts it. So `off` leaves nothing running. The agent runs with
`ProcessType` Interactive: as a Background process launchd throttled the
VM children so much that guests never answered the agent in time.
One daemon holds an exclusive lock in the state directory; a second copy
exits after retrying for 2 s, longer than any liveness probe holds its
shared lock. `vz cleanup` holds the same lock while it runs.
`AbandonProcessGroup=true` prevents launchd from killing VM helpers
when the controller crashes, so reconciliation can adopt the live guest.
The LaunchAgent has one label and runs the default layout, so with
`BIVOUAC_HOME` set, macOS install, uninstall, and kickstart refuse; such a
home runs in the foreground only.

On Windows the optional Task Scheduler entry uses the installing user's
interactive token and `LeastPrivilege`, a user-specific logon trigger, no
execution time limit, and three one-minute retries on failure. Task names are
derived from the user SID and state directory, so validation homes stay separate.
A durable ownership record and the native definition must agree before update,
start or removal; updates record both old and pending definitions for recovery.
The action carries the installation's `BIVOUAC_HOME` explicitly, because scheduler
environment inheritance differs from a shell. The login entry refuses an elevated
manager. Removing it does not stop an active manager or VM. Privileged App Sandbox
and its broker remain explicit operator prerequisites; this task never installs
or launches an elevated engine, service, or broker.

The portable Windows `Control.ps1` launcher checks native process-job membership
before starting an absent manager. A hidden window is not an independent
lifetime: a manager inherits its launcher's Windows job, and a development app
can close that job while native App Sandbox guests survive. A contained or
unverifiable launch is refused before prerequisite checks, stale-PID archival,
or mode changes. Use the ordinary desktop shortcut or the explicitly installed
login task. Mode commands to an already running manager remain available from
contained shells. No startup task or elevated process is installed implicitly.

## Demand: runner scale sets

One scale set per provider entry, named by `scaleset` in the config and
prefixed `bivouac-`. The daemon long-polls in every mode except off. The
poll header reports the total runner ceiling (active plus available
slots), with a minimum of one. It must not report free slots: zero-capacity
polls left new jobs stranded even after capacity returned. Polls are
bounded to 65 s and log capacity, outcome, and duration. Local budgets and
mode independently gate launches; drain and stop may receive assignments
but leave them queued until on. Per message:

1. Bind `JobStarted`/`JobCompleted` to instances by runner name.
2. Acquire `JobAvailable` requests up to current capacity plus idle
   registered runners.
3. Start guests until active instances reach
   `statistics.TotalAssignedJobs`, within capacity. Statistics, never
   message counts, drive scaling.
4. Retire idle registered runners beyond `TotalAssignedJobs -
   TotalRunningJobs` after a short grace. Each is deregistered before its
   guest stops; a busy rejection keeps it for the job it just received.

A session that ends reconnects after 1 s, doubling to at most a minute
while sessions fail; one successful poll resets the delay.

### Routing (observed on github.com, 2026-10-11)

- A job queued while a session with capacity is open arrives as
  `JobAssigned` at once; no `JobAvailable`/acquire step was seen.
- With nonzero total capacity, a job queued while off was already counted
  in the next session's initial statistics and delivered as `JobAssigned`.
- Jobs queued against a zero-capacity poll were stranded after capacity
  returned, across replacement sessions, and despite idle sweep runners.
  The 65 s poll bound did not fix this; logs showed normal ~50 s empty
  responses. Reporting nonzero total capacity fixed fresh-job routing.
- (2026-10-17) A scale set created with extra labels received `JobAssigned`
  for arrays its labels cover, with or without `self-hosted` and without
  naming the scale set; an array with a label it lacked stayed queued.
  Label updates returned success but changed nothing.
- After a controller crash, the existing session can cause temporary 409
  conflicts. A live guest is adopted independently; polling retries until
  GitHub expires the dead session (128Ã¢â‚¬â€œ129 s in the crash tests). A job
  queued during that conflict window was assigned after the adopted job
  completed, then passed in a fresh guest without operator intervention.

Sweeps are a defensive check for label-routed work. After each session
open, and whenever a runner starts a run the scale set did not assign,
bivouac starts a sweep
runner: a registered runner with no assigned job. While a sweep is pending
or waiting, no additional assigned-job guests start. The sweep can serve
an assignment received while it boots. A sweep
that finds nothing retires after `sweep_idle_timeout` (default 90 s);
one that ran a job is followed by another sweep.

Scale set labels: the name is always a label. Optional `scaleset_labels`
add labels, including `self-hosted`, so workflows can use a `runs-on` array
instead of the name. GitHub fixes labels when it creates a scale set and
silently ignores later updates, so bivouac never updates them. It reads the
labels back after creation; any difference from the config is logged at
session open and fails `doctor --github`. To change labels, delete the scale
set while off; the next session creates it again.

## Demand: REST JIT fallback

`demand = "jit"` maintains each provider's positive `idle_pool` while on.
It creates ordinary ephemeral runners through GitHub's REST
`generate-jitconfig` endpoint, using the same App, guest bootstrap,
budgets, and teardown. Workflows use the configured label array, including
an isolated `bivouac-` label. No scale-set session is opened. Idle on keeps
warm guests; idle drain/stop/off leaves none. Running jobs consume budget,
so a full host may temporarily have fewer idle runners than the target.
Idle expiration replaces a waiting guest; startup failures delay pool
replenishment for 30 s.

Drain/off withdraw an idle registration before stopping its guest. A
busy-runner deletion rejection protects a job accepted during that race;
its official runner finishes normally. Stop still cancels immediately.
Creation checks the mode before registration and before listener launch.
Job identity comes from a minimal official job-start hook: only run ID,
repository, and job name reach a private guest file and status. The hook
never terminates the VM. Scale-set messages remain authoritative in the
primary mode.

REST App JWTs and cached installation tokens stay in memory; HTTP errors
exclude response bodies. Registration is never retried after an ambiguous
transport failure: cleanup looks up the recorded name before releasing the
record. HTTP 404 from the runner DELETE confirms a missing runner;
authentication failures and busy errors retain it.
An instance with scale-set ID zero belongs to REST mode. Changing demand
mode with retained records is refused; finish cleanup before switching.
Organization and repository endpoints are implemented; only organization
registration against github.com has been validated live.

## Instance lifecycle

Names: `bivouac-<provider>-<id>` for the guest and the runner. The state
record is written before the engine or GitHub learns the name.

```
creating -> booting -> ready -> listening -> running -> finished
    \          \         \          \            \
     +----------+---------+----------+------------+--> collecting -> destroying -> deregistering -> (record removed)
failed (recorded error) ------------------------------^
```

Teardown always: collect diagnostics if the guest runs (bounded to 60 s),
stop, delete only with proven ownership, deregister the runner ID, remove
the record. Each provider and GitHub call has its own deadline; daemon
shutdown does not cancel a teardown in progress. The
runner's exit ends the instance; JIT runners run exactly one job.
Stop first signals the official runner and allows at most 30 s for it to
report cancellation. The worker itself can spend 7.5 s on SIGINT and
2.5 s on SIGTERM before killing a stubborn step; the remaining grace
allows its result to reach GitHub. Guest deletion proceeds even if that grace expires.
Failed deletion or deregistration keeps the record and retries every 5 s,
including after restart. A recorded name whose guest lacks our metadata
(macOS `Exists && !Owned`, or `ErrNotOwned` from App Sandbox and Crosvm)
retries with backoff up to 5 min and does not hold drain, stop, or off;
its record stays for a later start. After the provider confirms VM absence, persist
`deregistering` and `guest_deleted_at` before releasing VM, CPU, and memory
capacity. Status separates these pending registrations from active guests.
An uncertain deletion, failed state write, or unowned guest keeps its
reservation. Recovery retries deregistration without repeating VM operations.
Only successful deletion, REST HTTP 404, or the SDK's typed missing-runner error confirms
deregistration. HTTP error text and request IDs are not missing-runner
signals. A dead runner cannot enforce its workflow timeout; observed
GitHub terminal status arrived five minutes after the configured execution
limit. Registration cleanup continues until deregistration succeeds;
healthy queued work can use the released host capacity. A scale-set poll
still counts pending registrations in its remote runner ceiling and job
accounting, and requests one recovery sweep per retained cleanup record
after a failed deregistration attempt, for label-routed work that lacks an assignment.

Budgets end an instance early: `job_timeout` from creation, `idle_timeout`
listening without a job, surplus retirement from statistics.

Runner status probes are bounded to 15 s. After a typed guest transport
failure (SSH, or a failed guest agent command against a running owned macOS VM), the
listening/active watcher retains the guest for at most 60 s from
the start of the first failed probe. Retry delays start at the normal 2 s poll
interval, double to at most 10 s, and are clipped to the remaining grace and
readiness/job budget. A successful probe resets the consecutive-failure window
and logs recovery; it does not restart or register a runner. Controller shutdown
still leaves the guest for adoption, and Stop remains effective during backoff.
Guest absence/exit, ownership or native isolation errors, invalid status,
SSH authentication/key/configuration failures and unknown provider errors remain
immediate retirement reasons. Each retry repeats current provider proof; the
independent native guards continue to enforce policy throughout the grace.

Windows-hosted OpenSSH failures retain only an exit code and a fixed diagnostic
category. Up to 8 KiB of stderr is inspected in memory and cleared; no raw stderr,
stdout from a failed command, arguments or stdin enter errors/logs/state. Exit
255 receives bounded transport grace unless its diagnostic identifies a terminal
failure. An unclassified 255 is ambiguous (OpenSSH can also pass through a remote
255); grace bounds that uncertainty. Other command exits remain terminal.
Overlong stderr fails immediately because truncation cannot exclude a terminal
key/authentication error. Probe timing, first-failure classification and recovery
counts are logged without retaining guest-controlled output. This tolerance
applies to status watching, not replay of JIT delivery or other mutations;
startup reconciliation still requires positive live-runner proof for adoption.

### Host and guest performance observations

The controller logs one host resource summary at startup and about once a minute:
physical memory total/used/available, overall CPU busy percentage and an array
by logical processor. CPU is measured between counter reads; the first sample
explicitly marks its CPU interval unavailable. Sampling failure does not affect
admission, teardown or native isolation. macOS uses read-only Mach CPU/VM
counters and `hw.memsize`, with purego calling libSystem without cgo. Each read
owns and releases its Mach allocation and host port; there are no mutable global
bindings. The page-size output uses pointer-sized `vm_size_t`, with an adjacent
guard checked after the native call. Mach port names and natural counters remain
32-bit; using a 32-bit page-size output corrupts adjacent Go memory. Native
regressions exercise this boundary alongside repeated JSON encoding and GC.
Available physical memory is an estimate of free plus inactive pages;
speculative pages are already in free pages and are not counted twice. Used
memory is total minus that estimate, including compressed memory's physical
footprint. It is not Activity Monitor's memory pressure or a Windows commit
limit. CPU counters cover each logical processor, including Apple's efficiency
and performance cores without assigning topology labels.

Windows also reads system committed bytes, the current commit limit and the OS
commit peak since boot via read-only `K32GetPerformanceInfo`, separately from
physical RAM. Commit headroom is the current limit minus committed bytes; the
limit can change when pagefiles resize. Five-second guest samples retain the
job's peak committed bytes, maximum commit percentage against each sample's
contemporaneous limit, and minimum headroom. The OS peak since boot is explicitly
separate from the sampled job peak and can reveal spikes between observations,
but cannot attribute an earlier peak to this job. Optional query failures keep
CPU/physical-memory telemetry and the latest successful commit reading, timestamp
and sample count. Host logs mark missing commit samples explicitly. Linux commit
accounting is not implemented; its different overcommit semantics must not be
presented as a Windows allocation limit. No privilege adjustment, pagefile change,
VM resource change or admission policy change is involved.

The Windows, Linux and macOS guest listeners own a small sampler goroutine, joined on
listener exit. It starts after the existing job-start hook records the accepted
job, samples every five seconds, and keeps only the latest observation plus
duration-weighted CPU averages, sampled CPU peaks, per-logical-processor averages
and peaks, peak physical memory used and minimum available memory. The private
`performance.json` remains bounded by 256 logical processors and is atomically
replaced, rather than appended. No process names, arguments, environment values,
host identifiers or credentials are collected. Only validated numeric fields
are re-encoded at both the guest archive producer and host extraction boundary;
invalid optional reports are skipped without losing official runner diagnostics.

The official runner's job-start hook prints a memory/capacity snapshot in
GitHub's Set up runner log. Its job-completed hook prints two compact resource
summary lines in Complete runner; it allows at most two seconds for a final
sample. Hooks report unavailable intervals honestly and telemetry errors cannot
fail the job. Optional completion-hook installation failure leaves normal runner
startup intact. No detached logging process, extra service, host endpoint or
workflow change is needed. Hook output on a lost guest may be unavailable, while
its last retained report remains eligible for normal diagnostics.

The macOS provider copies the native manager binary into each disposable clone as a private
helper, independently of whether caching is enabled. Its listener wrapper starts
the official runner in the same Aqua session, records the actual listener PID
for existing cancellation, preserves its exit code and joins sampling at exit.
The existing shell hook still records job identity; the helper's job marker only
starts numeric sampling. Partial helper installation is removed before falling
back to the official listener. Optional telemetry errors cannot fail a job.
It archives the optional report alongside the runner log; extraction validates
and re-encodes numeric fields, skipping malformed reports while retaining logs.

Disk space uses read-only filesystem queries on the controller's state directory
and each guest's configured runner installation directory (including its default
work directory). Windows reports caller-available capacity/free bytes via
`GetDiskFreeSpaceEx`; Linux uses filesystem blocks and availability excluding
reserved blocks. Guest hooks include capacity, latest available space and the
minimum available space over successful five-second samples, without extra log
lines. A capacity change resets the disk summary. A failed disk query preserves
CPU/memory telemetry and marks disk sampling unavailable; previously sampled
guest disk values are explicitly the latest successful reading. Host disk logs
identify only the controller filesystem, not all VM/cache/mount volumes. No
paths, volume identifiers, filenames, directory scans, throughput or latency
counters are collected. Separate mounts under the work directory and Linux
inode exhaustion are outside this summary.

These are whole-guest and whole-host measurements, not per-step attribution or
proof of OOM. Memory used means total minus OS-reported available memory; Linux
availability includes reclaimable memory and CPU busy excludes I/O wait.
Physical availability alone does not establish allocation headroom: Windows can
exhaust its commit limit while physical RAM remains available. Commit pressure
does not itself prove paging or identify the process causing an allocation failure.
CPU indices are logical processors, not physical-core topology. Peaks are observed
five-second intervals/points and can miss shorter spikes. Counter regression,
read failure or CPU topology changes reset the applicable CPU baseline/averages.

Capacity per provider is the minimum of: host `max_instances` minus active;
provider `max_instances`; the engine's host limit (Apple: two macOS guests)
minus running unowned guests in bivouac's VM store, or `foreign_slots`,
whichever is larger, and minus every guest of ours on any vz provider (vz
providers must agree on both settings). Other tools' guests are invisible to
bivouac, so `foreign_slots` reserves their slots; CPU and memory left after `reserve_*` and the guests already
running. A foreign guest named like an active record (an unprovable App
Sandbox or Crosvm record) counts once, through its record, and is not
reported as unmanaged. New provisioning pauses at `budget.max_pending_cleanup` deleted
guests awaiting deregistration (default 2). Total tracked records are also
bounded by `max_instances + max_pending_cleanup - 1`; concurrent losses
can exceed the admission threshold but cannot exceed this record bound.
With one VM and the default threshold, one busy registration allows a
replacement; a second loss pauses provisioning until cleanup succeeds.
Setting the threshold to 1 preserves the former conservative capacity
behavior. These limits affect new admissions, never interrupt healthy jobs.

## Recovery

On every start the daemon reconciles before polling:

- A record whose guest runs with a live runner is adopted and watched.
- Any other record is torn down (stop, delete, deregister, remove).
- A record whose status cannot be proven (not owned, corrupt, or no answer
  within the provider deadline) keeps its record, reservation, and guest,
  gets a recorded error, and waits for a later start. The rest continue.
- A guest with our prefix and our marker but no record is an orphan:
  deleted, its runner name deregistered if registered.
- A guest with our prefix but another marker, or no marker, is reported in
  `status` as unmanaged and never touched.

Reconciliation bounds each provider and GitHub call like teardown does.
When the daemon itself is stopped (signal, `uninstall`), active guests keep
running; the next start adopts or cleans them.

## Provider contract

`provider.Provider` is designed against the macOS VM runtime and the App Sandbox
headless API. Launch options are argument arrays or structured fields,
never shell strings. Capabilities are explicit: GPU mode, desktop session,
display transport, engine host limit.

Capabilities may also advertise `OperationTimeout`, a longer per-call bound
for Status, Stop and Delete than the manager's 2-minute default.

Methods: `Create` (clone from baseline, write metadata), `Start` (launch log
to a writer), `WaitReady`, `StartRunner` (JIT config over stdin or a 0600
file, never argv), `RunnerStatus`, `Status`, `Stop` (graceful then forced),
`StopRunner` (bounded cancellation through the official runner),
`Delete` (refuses without our metadata), `List` (owned and foreign),
`CollectDiagnostics`.

### macOS (`vz` provider)

Each VM is a directory in bivouac's VM store
(`~/Library/Application Support/bivouac/vms`, or `vms` under `BIVOUAC_HOME`):
`disk.img`, `nvram.bin`, and `vm.json`, bivouac's versioned manifest. The
manifest is the core model: the machine (OS, CPU and memory with their
minimums, MAC, default display, macOS hardware model and machine identifier)
and the guest contract (guest agent protocol version, runner directory,
passwordless sudo). `bivouac vz import` turns a Tart-format VM into one,
cloning its disk and NVRAM and converting `config.json`; the operator vouches
for the guest contract. Other sources only need to write a manifest. Clones
live beside their baseline so APFS can share blocks. Agent sockets live in
the store's hidden `.run` directory, named by a hash of the VM name, so their
path fits `sun_path` whatever the name.

- Baseline check: Create, the container preflight and `doctor` refuse a
  baseline without a manifest, of the wrong OS, without a runner directory
  (runner guests), or whose agent protocol differs from this binary's.
- Clone: `clonefile` of disk and NVRAM under a hidden staging name, a
  manifest with a fresh locally administered MAC and the configured CPU and
  memory (at least the manifest's minimums), then a rename into place
  (milliseconds). Then `bivouac.json` with controller and instance IDs.
- Run: `bivouac vm run --dir <vm> --agent-port <port> --agent-socket <path>
  [--input] [--share <dir>] [--softnet Ã¢â‚¬Â¦] [--display WxH[@PPI]]
  [--disk-sync full|fsync|none]`, from the executable signed with
  `com.apple.security.virtualization`. The helper builds the VM with purego
  bindings to Virtualization.framework (graphics device, virtio disk, NAT or
  Softnet network, entropy, balloon, vsock; keyboard and pointer for runner
  guests; no console, audio, or clipboard). It holds an fcntl lock on the
  manifest for the VM's life and reads the manifest only through it; the
  provider reads running state and the helper's PID from that lock. A
  manifest is never rewritten once its VM is in place. The
  helper is not bound to the daemon's lifetime and has its own process
  group; its output is the launch log file. The exact command line is in
  the launch log and diagnostics.
- Guest agent: the helper serves its agent socket (0600) and
  proxies each connection to the guest's vsock port, where
  `bivouac guest-agent` runs one command per connection: request, stdin
  frames, stdout frames, exit status. Guest stderr is dropped. A closed
  connection kills the command. Output still held open by a background child
  10 s after the command exits is reported as a failure, never as success.
  The agent accepts only the host's context ID, and its LaunchAgent abandons
  its process group, so an agent restart leaves a started runner alone.
- Ready: the agent runs `true`. Only an unreachable agent is retried; an
  agent of another protocol version names its own, and readiness fails at
  once. The bootstrap script is then copied to `/tmp/bivouac-guest`, and
  its `session` mode must report `Aqua`, or readiness fails.
- Every guest command caps stdout (status 4 KiB, otherwise 64 KiB) and fails
  when the cap is exceeded. Errors never include guest output.
- Every guest operation first checks the prefix and our marker.
- Runner: `/tmp/bivouac-guest start <runner_dir>` with the JIT config on
  stdin. The guest agent is a LaunchAgent limited to the auto-login user's
  Aqua session, so the runner starts there (SSH logins land in Background).
  The script exports `ACTIONS_RUNNER_INPUT_JITCONFIG` and runs the
  preinstalled official `bin/Runner.Listener run` once, retaining its PID
  for bounded cancellation.
- Status: the script reports `absent`, `starting`, `listening`, `running`,
  or `exited <code>` from the pid and the runner log. A failed status command
  is a retryable transport failure while the VM runs; only `absent` or a
  stopped or missing VM confirms exit.
- Stop: only a lock holder whose arguments are `vm run --dir <this VM>` is
  signalled; any other holder is refused. SIGTERM powers the VM off at
  once: a macOS guest ignores a shutdown request, and the clone is deleted
  anyway. SIGKILL after the timeout ends a hung helper, and the framework
  ends a VM whose owning process exits. Clones refuse a running baseline.
- Machine options: `[providers.*.vz.machine]` (runner guests) and
  `[providers.*.vz.containers.machine]` (the engine VM) hold typed, validated
  options mapped to framework settings: `display` (width, height, optional
  ppi; macOS guests), `disk_sync` (`full`, `fsync`, or `none`, which ignores
  guest flushes and suits only disposable clones), and
  `nested_virtualization`. There is no raw passthrough. Options are checked
  against the baseline's OS when a guest is created: the framework offers
  nesting only to Linux guests (today the engine VM, giving its containers
  `/dev/kvm` inside the VM boundary), never to macOS guests. The daemon and
  `doctor` refuse nesting on a host without it (it needs an M3 or newer chip
  and macOS 15).
- Diagnostics: `_diag` and the runner log stream out as tar through the
  agent, are redacted before reaching disk, and are capped at 1024 entries
  and 128 MiB extracted.
- Delete: requires the `bivouac-` prefix, a name different from the
  baseline, a marker whose controller ID matches, and no lock holder.

The runner package is baked into the baseline; `doctor` reports its version.
A host-cached package copied at boot is a later option if baseline updates
lag runner releases.

### Windows foundation and App Sandbox (experimental integration)

The Windows host foundation uses a nonblocking `LockFileEx` byte-range lock,
released by the kernel on process exit. It does not unlink stale lock files
or use a PID file to decide who owns a lock; a crash before PID persistence
therefore cannot admit a second controller. CLI liveness probes that lock
with a nonblocking shared lock; it is only a status hint, never authority
to stop a process. Probes and releases call `UnlockFileEx` before closing,
because release on close may be delayed. Mode changes still use durable files and polling.
Physical-memory budgets use `GlobalMemoryStatusEx` through pure-Go Windows
calls rather than reporting memory as unknown on every Windows host.

Windows state/control readers open with `FILE_SHARE_DELETE`; replacement uses
Go's `os.Root.Rename` POSIX semantics on supported Windows filesystems. Readers
retain the old snapshot as the next one replaces its directory entry. A reader
without delete sharing can still block replacement: report the failure, clean
the temporary file, and retain the committed ownership record. Never delete the
destination first or claim that sharing errors are safe to ignore.

Credential Manager is the Windows default store. Generic items named
`bivouac/<item>` persist for the same user across logon sessions on the same
computer (`CRED_PERSIST_LOCAL_MACHINE`, not all machine users). Pure-Go calls to
`CredReadW`, `CredWriteW`, `CredDeleteW`, and `CredFree` avoid subprocesses and
temporary plaintext files. Item names are bounded ASCII identifiers; blobs are
limited to the documented 2,560 bytes. Oversized keys fail rather than being
truncated, split, or written to disk. Cancellation is checked before synchronous
native dispatch; installation must use the same user as the credential owner.

`internal/provider/appsandbox` implements read-only v1 inspection against
the bundled App Sandbox 0.1.9 SDK contract. Discovery must name literal
`http://127.0.0.1:<port>` and a bounded nonempty bearer token; no DNS, ambient
HTTP proxy, or redirect is used. The live product identity is checked on open.
Responses are bounded; errors omit response bodies, redirect URLs, and token
values. Inspection exposes version, host capacity/storage, VM storage/status,
templates, snapshot trees, SSH forwarding, and the agent's passive display
readiness. Every inspected VM and template is foreign. SSH forwarding readiness
requires the native key-enabled state and literal loopback; it proves neither
ownership nor desktop readiness. An unreachable
endpoint produces an error and never triggers daemon or guest startup.

Windows runtime integration is now implemented behind
`appsandbox.experimental = true`. Credential-free live validation has passed
hardware desktop/GPU, controlled host-denial/broker-loss checks, fresh-image reset
and trusted Actions lifecycle/crash validation. Optional ordinary-user login
installation is implemented; privileged startup packaging, recovery of guests
retained across reboot and broader isolation gates remain pending. No service installation is required by default.
NAT or Slirp networking is not evidence of host/private-LAN isolation. The
experimental configuration must use a separate test label until those gates pass.

The normal-user manager holds GitHub credentials and resource reservations.
An operator-started elevated localhost broker holds a separate, protected
ownership journal and owns clone creation, HCN networking, VFP policy, and
deletion. Its per-run capability lives in the same user's Credential Manager.
The authenticated API permits only fixed lifecycle operations; there is no
arbitrary administrator command, filesystem, template, or route API.
Creation records intent and markers before the native API, uses an isolated
storage parent and `networkMode=0`, and never retries an ambiguous mutation.
Before requesting any network attachment, the manager uses authenticated
HvSocket SSH for a fixed guest console preflight. It waits for unattended setup
to finish and for the intended user's console session and Explorer to be ready.
Native agent/SSH availability can precede OOBE completion; attaching a NIC during
that interval can leave its VFP layer vulnerable to a setup port reset. This
preflight changes no network and carries no runner credentials. The later
interactive task still proves the default input desktop before JIT admission.
The protected broker enforces its own instance/resource bounds independently
of the manager. All retained disk/network reservations must disappear before
the journal is released. The baseline is pinned by native registry binding,
SHA-256, file identity, size, and modification time.

An administrator-protected engine directory (default
`%ProgramFiles%\bivouac\engines`) holds the elevated helper, `engines.json`
and `broker-options.json`; the helper reads every privileged input from there,
never from `BIVOUAC_HOME`. Protected means owned by Administrators, SYSTEM or
TrustedInstaller, no reparse point, and no other principal with write, delete
or permission rights, with ancestors that cannot rename it. The broker refuses
to start unless its `--config`, the App Sandbox discovery file and `vms.cfg`,
and their ancestors, are protected. The helper refuses earlier, before starting
anything, when the App Sandbox data folder or the pinned daemon's installation
folder breaks the same rules, and re-checks both files before launching the
broker. Each broker lifecycle sequence runs under
`WithoutCancel`, bounded to 150 s, so a dropped client cannot cut it short; the
client's 3-minute response header timeout outlasts it rather than reporting an
unknown outcome. The provider advertises a 3.5-minute `OperationTimeout`, which
the manager uses for Status, Stop and Delete instead of its 2-minute default. `List` reports a record the broker cannot prove as a prefixed
foreign guest that holds a slot, instead of failing the inventory. A record whose
marker or parent is gone mid-cleanup is finished only after native and child
absence are confirmed.

Open decision: the elevated helper starts from the user's desktop session
through UAC consent, so code already running as that user can influence its
environment (for example `DOTNET_STARTUP_HOOKS`, or `PSModulePath` through
`HKCU\Environment`) or raise its own consent prompt. Same-account UAC is not a
security boundary. A complete fix is an administrator-registered task or
service with a clean environment.

The broker verifies its dedicated switch/endpoint/VM-port identity and exact
stateless VFP denial rules before allowing public IPv4. IPv6 is denied.
The normal manager verifies again before guest setup, JIT delivery, and runner
status. An independent ten-second broker guard quarantines policy failures,
blocks the owned port, and stops the owned VM if blocking fails. It verifies
and blocks journalled ports even when App Sandbox is unavailable, but stops
only a VM whose identity it proved. An incomplete pass blocks admission until
the next fully successful pass. Quarantined guests and retained network-cleanup
records keep admission blocked, including after their VM has stopped or vanished.
Once normal owned cleanup removes those records, a successful guard pass restores
admission automatically in the same broker. Fresh guests build and verify the
current host-interface policy; failed guests are never repaired or resumed.
Canceled or unreadable guard passes cannot clear the admission gate.
Interface-change handling is polled rather than atomic: dynamic-interface,
private-peer, MAC-change and host-reboot behavior are still live validation gates. Existing manual prototype results
do not establish that the new Go adapter passes those gates.

System OpenSSH connects only through the native owned VM's loopback HvSocket
forward. A per-instance known-host file accepts the first key only after
native ownership proof and pins subsequent connections. No host folder is
mounted. Fixed bootstrap code and JSON settings are transferred separately;
JIT bytes arrive over authenticated SSH stdin and enter a private guest file,
never host files or command arguments.
The official runner starts once through an interactive guest scheduled task,
with rebuilt machine/user PATH and a default-input-desktop probe. A fixed Go
guest adapter records listener PID, executable and process creation time;
cancellation rechecks that identity before signaling its console.
Stop causes official runner shutdown, which reports a failed job even when it
cancels the running step. It does not invoke GitHub's workflow cancellation API
or expand shared App permissions. Off instead lets accepted work finish normally.
Diagnostics arrive over a bounded base64 stream and ZIP extraction rejects
unsafe paths/expansion before redacting every host sink.
The generic baseline may contain an unconfigured runner, or each clone may
receive a hash-pinned official runner ZIP. It contains no project setup.
PowerShell 7, Git and compiler installation belong to generic image preparation,
not a project workflow. See `docs/windows.md` for the operator setup and gates.

The operator-selected Windows CI image policy disables Defender scanning and
Windows Search indexing inside disposable guests. Provision it in a clean,
unenrolled preparation guest with the explicit guest-only policy tool; verify
actual settings after reboot, generalization and a fresh clone before promotion.
Tamper Protection remains an operator Windows Security UI prerequisite. Neither
the manager nor baseline promotion implicitly changes host security. The policy
does not relax native isolation, disk durability or credential-free image rules.
Retain the old immutable image for rollback. A new baseline requires privileged
broker restart with a new pinned template/path/hash and an explicit update to
the empty storage root's binding, not an in-place image edit or implicit
elevation. Immediate disposable-guest validation does not establish that this
image promotion has occurred.

The 0.1.9 API is HTTP/JSON over an elevated single-owner daemon, rather than
JSON on a per-job CLI process. `create` auto-starts; snapshots require a stopped
VM; writable branches are created when starting an existing snapshot. Those
branches are not independent clones. Windows create-from-template is supported;
arbitrary VM/snapshot cloning and arbitrary ownership metadata are not exposed.
The pinned 0.1.9 source accepts an explicit `diskDirectory` at creation and
reports that parent directory in native VM status; the child is `<parent>/<name>`.
It rejects an existing child, so the provider persists intent before
creation and bind its child marker to the recorded parent and native metadata.
Template inventory has no storage field and cannot establish ownership alone.
Template creation forces networking and GPU off; subsequent clones can select
GPU mode. Windows native names are limited to 15 characters, requiring a durable
mapping to the longer logical runner name. `NativeName` encodes the entire
four-byte instance ID as seven base32 characters after `bivouac-`; the logical
runner name is separate. `PlanClone` validates immutable creation intent and
derives a dedicated storage parent per instance. `CheckClone` requires the
controller's durable intent, identical parent/child markers, and matching fresh
native metadata. These helpers perform no native mutations. The storage root
and marker reads are protected by the privileged adapter; matching
paths alone are insufficient. A native `networkMode=0` is only the creation
setting, and cannot prove the absence of an externally attached NIC.
The new lifecycle methods must repeat the independent-instance, network and
desktop/GPU checks through their own adapter before production use. Native
auto-start stays offline; policy is verified before admitting a job.
The existing production registry is not a validation environment.

Native NAT uses shared App Sandbox networks and does not apply a guest egress
ACL. The current API exposes no dedicated network/policy selector. Do not modify
shared networks used by foreign guests; a provider needs isolation before the
auto-start path, through a validated native integration or controlled transport.

An isolated Windows prototype creates a dedicated HCN ICS switch and endpoint,
then places its own stateless VFP layer on that VM's port. IPv4 remote-address
denials and an IPv6 blanket denial passed host TCP/UDP tests with positive
controls and guest source-address changes, while retaining public DNS/HTTPS.
Keep this layer separate from Windows' service-owned firewall layer: observed
automatic host loopback rules took precedence over its explicit block rules
even with loopback reported disabled. The broker now applies this recipe as
described above. Private-peer and lifecycle tests remain necessary; no
production isolation guarantee is inferred from the prototype.

### Direct HCS Windows spike

`cmd/hcs-spike` and `internal/hcsspike` are an isolated experiment, not a
registered CI provider. A direct HCS launcher can create an offline Windows
amd64 VM with a differencing disk, post-start GPU-PV assignment and fixed
HvSocket guest-agent/SSH initialization, without an App Sandbox host daemon.
It retains the upstream guest service/display-driver dependency and requires
an independent unenrolled image. Optional hash-pinned setup assets support an
offline generalized template: Windows IMAPI builds a per-trial setup ISO using
an in-memory answer file, a random local guest password and fixed guest code.
When rendering is requested, the ISO also carries the pinned public native
probe and fixed validation script; guest setup copies them to fixed paths.
The ISO is created in an administrator/SYSTEM-only child directory before HCS
grants the owned VM access, and is removed with the disposable child. The guest
password never enters configuration, journal, command arguments or diagnostics.
Before native create dispatch, fixed elevated Storage code mounts only the new
child and writes the same answer plus a fixed specialization script into an
absent or empty
`Windows\Panther\Unattend` directory with administrator/SYSTEM permissions.
The native DACL-only update preserves owner/group and does not request audit
changes. Specialization invokes the staged script by a short fixed path, within
Windows' 259-character synchronous-command limit; first-logon command fields
have a separate 1024-character limit. Tests check the emitted XML values.
This outranks a cached template answer; nonempty directories, reparse paths and
an explicit offline `SYSTEM\Setup\UnattendFile` pointer are refused. The
pointer check uses the system offline-registry library read-only, without loading
hives into the live registry. The child is detached before HCS starts. No baseline
is mounted or modified by provisioning. A prepared runtime image omits setup
assets and declares its expected `guest_computer_name`; when omitted, the guest
name remains the generated native name. An explicit prepared name is rejected
with generalized setup assets. Native ownership still requires the fresh HCS
name, owner, runtime ID and journal, independently of the guest Windows name. Removable-media discovery uses `Autounattend.xml`; the
ordinary-token media test inspects its name in the ISO's Joliet directory.

An optional hash-pinned standalone native C++ probe runs only inside the guest,
through a small fixed SSH bootstrap and an interactive guest scheduled task.
The command stays below the Windows default shell limit: trusted embedded code
and metadata arrive in separate fields of a small length-prefixed stdin JSON
entry request. The guest verifies the staged validation script against the host
build's embedded hash and the native probe against its configured hash. Four
little-endian bytes describe the UTF-8 payload, read in chunks of at most 4096
bytes with a fixed allocation bound. Execution depends on neither stdin EOF nor
a huge console text line. Without a rendering probe, separate bounded fixed command/stdin round trips
distinguish authentication from execution. With the probe, the actual authenticated
framed desktop request proves both, avoiding two redundant round trips. All fit
inside the guest budget. A timeout closes
the owned SSH client instead of replaying a command. Fixed numeric failure
stages replace raw guest errors. The stderr sink drains arbitrary text and
retains only allowlisted phase numbers; after parsing the input frame, progress
is also recorded inside the disposable guest for stopped-clone inspection.
Offline probe reports are re-encoded as bounded fixed booleans/numbers. The setup marker is written only after the
agent service reaches Running and optional pinned runner extraction completes. Native C++ supplies the Windows Direct3D COM ABI
without adding cgo to the Go host.
Readiness requires setup completion, the intended console user's Explorer and
Default input desktop. The probe enumerates at most 32 DXGI adapters and
explicitly selects hardware for D3D11 (software adapters are rejected), successful windowed presentation, and matching red/green pixels in
both a staging texture and the composited desktop. Only fixed booleans/numbers
cross back to the host; SSH code is fixed and all instance data arrives on stdin.

`check` (DLL export resolution/token report), `plan` (pure configuration/JSON)
and `headroom` (numeric host resources and trial-root filesystem space) support
ordinary-token execution. Headroom queries touch neither images nor VM/CI state.
Native preparation and creation recheck fixed reserves: at least 10 GiB physical
availability, 6 GiB commit headroom, 8 GiB volume space and two logical CPUs beyond
the guest. For larger guests, memory minima grow to guest RAM plus 6 GiB physical
and 2 GiB commit. Missing counters refuse admission; cleanup stays available.
A two-second watcher cancels only the isolated trial when available physical
memory falls below 6 GiB, commit headroom below 2 GiB, volume space below 8 GiB,
or counters become unavailable. Normal ownership-checked cleanup still runs.
These checks do not reserve resources against other host users. Native
trial/cleanup require explicit administrator startup, a separate protected
`HCS-Spike` root, immutable image hash, journal/child/native ownership proof,
and bounded resources. They never request elevation or use the installed broker.
No NIC, GitHub registration, CI configuration or production lifecycle is involved.
Driver-only shares use copies inside the recorded disposable child. Payloads
must be administrator-protected before HCS grants the recorded VM account
access. Their exact post-grant security descriptors and file identities are
pinned and rechecked before creation; the VM's required payload access does
not relax the separate administrator-only journal/marker rules. Ephemeral
SSH keys stay in memory. The trial owns its HCS handles and terminates on last
handle close; it does not promise the manager's adoption behaviour. Cleanup
requires confirmed native absence before removing disks and retains uncertain
records. An explicit `--retain-failed-storage` trial flag still terminates and
confirms native absence before retaining a failed child's journal/storage for
operator-approved read-only inspection. It reports `native_absent` and
`storage_retained`; an ambiguous create never confirms absence or permits such
inspection. Normal `cleanup` rechecks proofs/absence and removes retained files.
Child-only staging, offline HCS running state, GPU assignment and explicit
native/storage cleanup are validated. Setup/OOBE completion, the guest agent,
reported display-driver readiness, ephemeral authenticated SSH, fixed command
execution and small framed-stdin delivery are also live validated. The large
bulk transfer still stalls after receiving its length header. Media delivery
of the public validation assets with small SSH metadata, setup/console readiness,
Default input desktop and interactive native-probe execution pass live. Driver
destinations require `C:\Windows\System32\HostDriverStore\FileRepository`.
The complete guarded trial passes with that path: setup/console readiness,
authenticated SSH, hardware D3D11, presentation and GPU/desktop pixel readback
(stage 7, HRESULT 0). The guest writes and flushes JSON directly to the console;
the host accepts the strict report over SSH. Numeric diagnostics confirm one
GPU-PV device without a problem code after 136 copied driver files. Native
absence and automatic child/journal cleanup are confirmed. Parse failures expose
only byte counts and numeric offsets. Forced termination can leave the stopped
disk without files already observed live; read-only inspection does not override
a completed live check. Input, process-loss recovery and networking/isolation
remain unverified.
Trial reports include host-monotonic stage timings for baseline verification,
preparation, HCS lifecycle, guest/SSH initialization, console/GPU waits and
rendering. The validated-desktop milestone excludes cleanup; total includes it.
Nested details overlap their lifecycle spans and are not additive. Numeric
checkpoint receipt intervals include possible transport buffering. Guest wait
budgets use monotonic stopwatches. First-logon animation is disabled during
disposable-child specialization by default, preserving every other policy value
and all readiness checks. Prepared images bake the same setting during their
build. Live timing and any performance gain remain unverified.

The image pipeline has a generalized source and a derived prepared runtime
image. `build-image` completes specialization/OOBE, driver/service installation,
the CI user's profile, optional pinned runner extraction and stable desktop once.
It validates hardware rendering, sanitizes the guest, then requires successful
acknowledged guest OS shutdown, a native successful `GracefulExit` and native
absence before capture. The prepared image is a
differencing disk over its recorded standalone generalized source, not generalized
again. Both source and derived disk remain immutable. Each job trial uses a new
child, native owner/runtime, firmware state and in-memory SSH client identity.
No unattended setup, package installation, driver copy or registration repeats.
`RUNNER.ZIP` extraction rejects escaping paths, streams, symlinks, duplicates and
bounded expansion overflow; no runner executes during the build.

Sanitation refuses runner registration/work/diagnostic state, removes the fixed
probe output, cached answer files and authorized SSH keys, and removes server
host keys. A fixed guest SYSTEM startup task generates fresh server keys before
starting sshd. Password authentication is disabled; SSH binds only loopback and
is reached through the owned runtime's HvSocket. The image retains a randomized
local account credential with autologon stored as an LSA private secret, not a
plaintext Winlogon value. Prepared storage is administrator/SYSTEM-only with VM
worker read access; ordinary-user read access is refused. Every prepared clone
rotates the local password and autologon secret after stable console logon and
before readiness admission. No GitHub/JIT credentials or host private keys are
baked in. This offline spike attaches no NIC and admits no jobs.

Publication uses an exclusive owned build directory under a protected sibling
`HCS-Images` root. Only a clean, sanitized, validated and confirmed-absent source
can be copied. The runtime config precedes an atomically published, hash-pinned
manifest binding image, flat parent, build owner, guest identity and public asset
hashes. Interrupted unpublished output is removable only with its exact owner
marker; published images are never removed by trial cleanup. Parent resolution
is checked through read-only virtdisk metadata. A session hashes and pins both
image files once with handles denying writes/deletion until all trials finish.
`trial --repetitions 1..5` runs sequential fresh clones, stopping on any error or
retained state. Each report carries its instance ID and whether verification was
reused; no persistent hash cache substitutes for an open immutable-file pin.

Ordinary-token tests cover ancestry, pin lifetimes, bounded capture, graceful
shutdown requirements, guest LSA binding compilation, extraction safety and
credential/report gates. Prepared-image building, sanitation, cloned autologon,
server-key renewal and cold boot timings still require explicit elevated live
validation. The experiment is not wired into the manager/provider contract.
The optional `trial --boot-only` mode skips guest initialization and tests only
HCS running state, GPU assignment and cleanup against an independent template
copy. It does not establish that Windows completed setup or entered a desktop.
See [`hcs-spike.md`](hcs-spike.md) for prerequisites and the elevated trial gate.

## Optional containers on macOS

`providers.<name>.vz.containers` opts a macOS runner into a disposable
Linux/arm64 engine VM, from a Tart-format baseline, for the same job. The
host selects a local Linux baseline, Docker or Podman, explicit CPU/memory,
and a built Linux/arm64 bivouac helper. The macOS runtime already provides
clone, ownership metadata, process lifetime control, and guest execution
independent of guest IP connectivity. Lima, Docker Desktop, Podman machine, and QEMU are
not interchangeable launch options; none is attached to a personal daemon.
Other VM backends need their own isolation, ownership, transport, and recovery
validation before being supported. M1 does not need nested virtualization:
the Linux engine is a sibling of the macOS runner on the physical host.
The installed Lima engine templates import the default home-directory mount
and forward their API sockets onto the host. Installed Podman machine defaults
also include host directory mounts and connection selection. Those convenience
defaults cannot be used for untrusted jobs; a future adapter would have to
replace them and prove host/LAN isolation independently. QEMU alone does not
provide the existing ownership/guest-agent lifecycle integration.

The manager records both names, the engine choice, and the total pair resource
reservation before cloning. The companion is `<runner-name>-engine` and has
the same controller/instance IDs plus a parent link in its marker. It
has no GitHub registration. Both existing baselines must be local arm64 VMs
with the expected OS. The Linux baseline must already provide a working
`bivouac guest-agent` (systemd unit) and rootful Docker or Podman API socket. The macOS baseline
must already provide the selected client. Bivouac installs no package or tool.
The Linux helper is cross-built alongside the host binary and transferred
through stdin; it is not a host share.

Both guests launch with a fixed Softnet policy, no host shares or extra disks,
and audio/clipboard/input sharing disabled. Admission requires Softnet's
`--block`/`@host` capabilities and a noninteractive privilege probe. Missing
baselines, helpers, capabilities, or privileges fail before cloning; failed
launches never fall back to NAT or another backend. Operator-controlled host
privilege provisioning is outside bivouac. The policy explicitly blocks
`@host`, private/reserved IPv4, and locally attached public addresses/subnets;
it supplies no allow rules or port forwards. Softnet 0.19 drops guest IPv6.
Only necessary DHCP/ARP control traffic is retained. Guests use public DNS
resolvers because the host gateway DNS exception is blocked too. The host
cache and bootstrap-share options are incompatible with this mode.

Source investigation: the installed-version [Softnet VM filter](https://github.com/openai/softnet/blob/0.19.0/lib/proxy/vm.rs)
applies explicit blocks before its default global-address, gateway, and DNS
exceptions. Its Ethernet dispatch accepts ARP/IPv4 only. The VM helper runs
Softnet through its `--vm-fd` interface: a datagram socket pair, Softnet's
end as its stdin,
`--vm-fd 0 --vm-mac-address <mac> --block <policy>`, directly when SUID root
or through `sudo -n` otherwise. Linux agent availability in a particular
baseline still requires a live check.

The macOS helper exposes a mode-0600 Unix socket in a mode-0700 guest directory.
The runner gets `DOCKER_HOST` and `CONTAINER_HOST` pointing only there. A
detached host supervisor attaches a guest agent stream to that helper and
multiplexes opaque binary streams to fixed agent commands in the Linux companion.
The Linux helper opens only `/var/run/docker.sock` or
`/run/podman/podman.sock`. Frames contain connection IDs and bytes, never
destinations, paths, or commands. There is no host network listener, daemon
socket, client credential configuration, or workspace mount. Container API
traffic and guest transport stderr are discarded from host logging and
diagnostics. Up to 16 connections use 32 KiB frames and eight data credits
per direction; malformed frames close the transport and stalled clients cannot
grow queues without a bound. HTTP upgrades and half-closes remain opaque.

The supervisor verifies the durable record and both markers before connecting,
before every new engine stream, and before stopping anything. It watches
record/VM presence and the effective host network policy, polling once per
second with bounded VM-status calls. Transport loss, engine loss, or a changed
policy retires the pair; no reconnect to a personal or replacement daemon is
attempted. This monitor is not an atomic firewall update when a new public
interface appears: keep host public interfaces stable during jobs, and validate
network transitions before claiming that scenario safe. Private ranges and
`@host` remain blocked independently of the monitor.

Controller crashes leave the supervisor and pair running for adoption. Composite
status reports existence until **both** VMs are absent. Stop/delete require the
name prefix, recorded pair, and matching IDs/links in all existing markers;
partial deletion or uncertain ownership retains capacity and cleanup retries.
Pair resource reservations stay at their admitted size across config changes.
Missing-record pairs are reported unmanaged and never swept by generic orphan
cleanup. Changing container topology or engine with retained records is refused.

Remote-engine semantics apply: build contexts and `docker cp` travel through
the API, bind paths refer to the disposable Linux guest, and published ports
stay inside that guest. No macOS-workspace bind mounts, automatic service-port
forwarding, x86 emulation, or GitHub Linux container-job semantics are promised.
Baseline DNS automation must not restore private resolvers. Live baseline,
VSOCK, engine, egress, privileged-container, and crash/cleanup validation remains
required; offline stream tests do not establish untrusted-CI readiness.

### Linux GPU provider on Windows (experimental)

The `crosvm` provider shares the manager/state/budget/GitHub interfaces while
launching a separate Linux/amd64 WHPX guest with gfxstream. It freezes the
generic raw baseline, explicit CPU/memory, random loopback SSH port and host
network snapshot before creating a QCOW overlay. Two independent markers and
native backing metadata authorize lifecycle operations. A detached Go
supervisor contains all VM/device processes in a named kill-on-close Windows
job, assigned atomically by `PROC_THREAD_ATTRIBUTE_JOB_LIST`. Its ownership
journal precedes child creation. Controller loss permits adoption; supervisor
loss retires the process group. Recovery confirms the recorded supervisor is
absent, queries/terminates only its journalled job and verifies child absence
before disk deletion. A reused PID (another creation time or image name)
proves the recorded process exited. Uncertain launches, contradictory process
identities, unmarked directories or unknown files retain the record and
reservation and are listed as unmanaged. Overlay admission conservatively
reserves full possible raw-sized growth, metadata, capped native logs and host
disk headroom.

Raw baseline contents are operator-managed and are not hashed. Admission checks
regular-file size, freezes the configured path and verifies each QCOW overlay's
exact backing metadata. The runtime, kernel and initrd retain digest checks in
explicit operator prerequisite checks (`doctor`), not per-VM creation or launch.
Earlier full-image checks in both manager creation and supervisor startup read
the complete 100 GiB image twice per job, adding about two minutes. They are
removed entirely rather than replaced with session caching or image locks.

The pinned native Slirp build filters Ethernet traffic before creating host
sockets. It denies private/reserved IPv4, connected host prefixes and IPv6;
only observed loopback-originated SSH reply tuples receive a bounded gateway
exception. Public guest DNS avoids Slirp's private resolver; the clone's active
NetworkManager profile ignores DHCP DNS so systemd-resolved cannot restore it.
The host network snapshot is the canonical set of effective IPv4 deny prefixes,
not raw interface identities; prefixes covered by broader denial are dropped
before hashing and launch, so private App Sandbox NIC churn does not change
admission. Every supervisor checks it once per second and retires on a change,
including broader masks and public prefixes; dynamic public-interface
transitions remain a non-atomic live validation gate.
No arbitrary flags, host shares, port publishing or host cache exception exists.

The static Linux helper configures only the disposable clone. An unconfigured
official runner and generic Docker/virtio/CDI runtime come from the immutable
baseline. JIT input arrives over authenticated SSH stdin, is consumed once,
and is never staged on the host. PID/start-time/executable proof protects
listener cancellation. Logs and ZIP diagnostics are bounded and redacted.
Windowed jobs own their compositor inside the guest/container; hardware
rendering plus wl_shm/Pixman presentation does not imply direct scanout or
a logged-in desktop capability. See `docs/crosvm.md` for setup and gates.

## Optional download caching

An owner-authorized follow-up adds a portable, bounded opaque-object store
and a TLS service in the existing daemon. Cache bytes live outside ownership
state, under the platform cache directory. Completed objects have SHA-256
descriptors, are checked before serving, and are evicted by last use.
Checks run outside the store lock; only readers of the fill that just hashed
the bytes skip them. Each fill reserves exactly the length its upstream HEAD
declared; unknown or oversized lengths are not stored. Committed bytes plus
reserved concurrent fills cannot exceed the configured limit, and nothing is
evicted unless eviction can make room. Active readers retain their disk
reservation until close; eviction skips them on every OS. Metadata is bounded
to 4096 objects, including fills.
Interrupted or corrupt objects are discarded. Archives are never
extracted on the host, and no host directory is shared with a guest.

On macOS the service binds every interface by default, because the vmnet
bridge may not exist until a guest runs; TLS and per-guest capabilities gate
access. The macOS adapter is installed in each owned
clone, leaving the baseline unchanged. A Node preload observes only successful Actions v2 cache download
responses. GitHub still handles authentication, branch/ref matching, cache
versions, metadata, and uploads. Bivouac stores downloaded archives, not a
second cache-key database. Each new read validates its fresh signed URL with
an upstream HEAD, including on a local hit; expired or denied capabilities
cannot expose cached bytes. Object identity excludes URL query credentials.
A lease request carries only that URL. HEAD on a lease answers from the
lease's upstream metadata without filling; the 15-minute write bound starts
after a fill completes.

`cache.release_proxy` optionally adds a general GitHub release proxy. A
loopback bridge in the guest accepts standard HTTP proxy clients and carries
the guest capability over TLS to the host service. The guest bootstrap installs
the temporary root in its system keychain and provides trust bundles for curl,
Git, and Node. Only the owned disposable clone changes; the host and baseline
trust stores stay intact. No project lockfile is read and no curl is replaced.
The bridge accepts TLS or HTTP inside CONNECT; HTTP is translated to verified
HTTPS upstream. This covers clients that do not nest TLS in their proxy tunnel.
The capability goes only to the host proxy: in CONNECT headers, or on plain-HTTP
forward requests. It never travels inside a tunnel or on direct fallback.
The root is name-constrained to the three intercepted hosts (and their
subdomains) and the service address. The constraint is non-critical, for
verifiers that do not support it.

CONNECT to `github.com`, `release-assets.githubusercontent.com`, and
`objects.githubusercontent.com` terminates TLS using fixed-host leaf certificates.
The proxy can see requests on these hosts, including uncached authenticated
requests, but never persists their headers or bodies. Other public HTTPS
destinations use opaque tunnels. Every host-side connection uses public-only
DNS admission and normal upstream certificate validation. Each guest has at
most 32 tunnels, closed on revocation, expiry, or daemon shutdown. Tunnel
requests cannot change authority to reach another host.

Only release-asset GETs without `Authorization` are cache candidates. Cookies, ranges,
conditional requests, and caller cache directives bypass storage. Signed
`release-assets`/`objects` URLs qualify even when they serve a private
repository's asset, for example after an authenticated API redirect, so those
bytes are stored on host disk. Each read still needs its own fresh signed URL
to pass the upstream HEAD, so a guest without a valid capability gets nothing.
Every candidate
gets a fresh upstream HEAD, including hits; its strong ETag and length identify
the bytes without persisting query credentials. Private/no-store, varying,
encoded, cookie-setting, oversized, or unidentifiable responses pass upstream.
Fills use If-Match and verify identity and length before atomic commit. The
cache's SHA-256 checks local integrity; project/tool verification remains intact.

The guest bridge uses direct upstream transport when the host is unavailable
before CONNECT succeeds, and retries failed idempotent forward downloads directly.
It does not replay ambiguous uploads. A transfer already inside a tunnel can fail
if the service disappears; the caller's retry behavior applies. The Actions
adapter separately returns to upstream when lease creation is unavailable, and
failed archive fills redirect to their original signed URLs.

TLS keys, guest capabilities, and signed URLs exist only in memory on the
host; private bootstrap files exist only in the disposable guest and are
excluded from diagnostics. Capabilities are revoked after confirmed guest
deletion; leases are bounded per guest and expire no later than the upstream
SAS. TLS identities rotate on daemon restart. Existing guests retain their
upstream paths if their old cache endpoint disappears. This accelerates
restores; it does not reduce GitHub cache uploads, storage, or metadata calls.

The store and HTTP service use pure Go and portable filesystem/network APIs.

The service owns constant-space numeric request/byte counters for archive
downloads and the release proxy, both per active guest capability and for the
controller session. Hits/misses classify resolved cache GETs; bytes count actual
response-body bytes accepted by the client writer, including partial ranges.
Conditional reads can count as hits with zero body bytes. Bypasses and transfer
failures are separate; failed fills redirected upstream have no observable
fallback body bytes. HEAD, cache-service metadata and opaque tunnels are
excluded, and concurrent coalesced reads count as hits. Proxy bypass totals
include uncached forwarded GETs, not only release assets. These are delivered
bytes, not unique stored bytes, total upstream traffic or a bandwidth benchmark.

The per-minute controller summary adds store totals: objects, committed and
reserved bytes, capacity evictions and evicted bytes, invalidations, and
startup-discarded files. Store, fill and delivery events carry fixed reason
categories, HTTP statuses, byte counts and an object label, never URLs, keys,
object hashes or raw transport/filesystem errors. The label is a truncated
HMAC of the object identity under a random per-session key: it links one
session's events for an object without letting a log reader confirm a guessed
URL or asset. A fill also requires the upstream GET's ETag to match the
lease's HEAD. A lost SSH cache transport is reported, with its guest, only
when requests were in progress; an idle loss is ordinary guest deletion.

The existing authenticated TLS service exposes a fixed numeric-only `/metrics`
read for the calling guest's capability. Revocation/expiry prevents reads and
capability rotation resets that guest's counters. Session totals reset with the
daemon. Windows/Linux/macOS completed hooks print one best-effort cache summary line
with a one-second query bound; absent cache configuration adds no line, and
unavailable metrics never fail jobs. Controller summaries appear about once a
minute and on cache-service shutdown. No object keys, paths, request headers,
URLs, capabilities or response content enter summaries or persistent state.
The macOS provider uses the same private `cache-config.json` filename in its guest directory;
summary reads accept the bootstrap's literal host IP as well as SSH loopback,
verify TLS and grant authorization, refuse redirects and never use ambient
proxy settings. This works with Actions caching alone or the optional release
proxy. The existing controller-session counters already serve both transports.

Transparent Actions v2 restores and public GitHub release caching are required
for Windows host parity with macOS, including its Windows and Linux guests.
Provider adapters own guest delivery, trust installation, network reachability,
and native launch setup; implementation alone is not live validation.

Windows-hosted providers use a guest-loopback listener on the existing owned SSH
transport. The host terminates TLS and serves only the cache HTTP handler through
SSH channels; it does not relay arbitrary guest connections to host TCP sockets.
The SSH host key must already be pinned by normal guest preparation, and the
provider repeats ownership/network verification before cache setup or JIT.
No NIC allow rule, host trust change, host directory share, external service or
automatic privileged startup is needed. Host cache configuration is restricted
to literal IPv4 loopback. Each grant records its guest endpoint so archive leases
remain reachable through the same transport. TLS identity and capabilities stay
in memory on the host; bootstrap reaches only the disposable guest over stdin.

The shared Node preload is used by all three adapters. Windows installs temporary
machine root trust inside the clone and exports its logical root collection
for OpenSSL clients. Guest administrator access avoids the interactive protected
CurrentUser root-store consent that fails over SSH. Proxy leaf certificates name
the granting guest's cache endpoint for a signed revocation list, so Schannel
keeps its default revocation checks. The fixed `/ca.crl` GET/HEAD endpoint serves
only public PKI bytes, renews before expiration and contains no capability or
archive data. It uses the same TLS/SSH transport and opens no additional listener.
Linux installs clone-only root trust and uses its system
bundle. Runner children inherit the Actions preload, standard proxy settings and
curl/Git/Node trust paths without workflow edits. The release bridge lives in the
existing guest listener process. Confirmed VM deletion revokes the grant and
closes its SSH transport; manager/service loss closes transports and leaves
normal upstream fallback in the guest. Off shuts down the cache with the manager,
while its bounded opaque store persists across jobs/restarts. Startup stays opt-in.
Docker/other containers with independent environments/trust stores need explicit
guest integration; ambient runner variables do not establish interception there.

The SSH library is pinned to `golang.org/x/crypto v0.58.0`. Its channel connections
lack socket deadlines, so a bounded, backpressured local pipe supplies the
deadlines required for HTTP CONNECT hijacking. No host TCP listener is added by
that adapter. Tests exercise real SSH handshakes/channels and CONNECT, not just
fake provider calls. npm, Cargo, rustup, and OCI registries may later add explicit
cache policies against this store; their traffic is not automatically eligible
because it uses the proxy. Writable shared package directories and the unrelated
localhost management API and UI remain deferred.

## Security model

- No secrets in config, state, logs, or diagnostics. The App private key
  lives in the credential store under the item the config names.
- JIT configs are generated per guest, delivered over stdin, consumed once,
  never on a command line or in a file that outlives startup.
- Every log and diagnostics sink passes through `redact`: GitHub tokens,
  JWTs, PEM blocks, authorization headers, signed URL parameters, and long
  base64 runs. Streams hold at most 64 KiB without a newline, then flush at
  whitespace, quote, `<`, `>` or `&`; an unbroken longer run is masked whole.
  The macOS launch log is the exception: the VM helper (and Softnet) write
  host-side status there through an inherited descriptor, neither redacted
  nor bounded, because the helper must outlive the daemon. The guest console
  is never attached, so no guest output reaches it.
- Guests get no host directories except the optional read-only bootstrap
  share. Host credentials never enter a guest.
- Cleanup deletes only prefixed guests carrying our marker; baselines,
  Tartelet's clones, and unrelated VMs are never touched.
- The GitHub App needs only organization "Self-hosted runners: Read and
  write" (scale sets, JIT configs, runner removal).

## Decisions

- Bivouac runs macOS guests itself (purego bindings to
  Virtualization.framework, no cgo) instead of through the Tart CLI, so
  users install no VM tool for the little of Tart bivouac used. The provider
  is named `vz` after the engine; "Tart-format" names only an import format,
  and bivouac keeps its own VM store. Bivouac's manifest, not Tart's
  `config.json`, describes each VM, so images from other tools need only a
  manifest, and machine options are typed fields rather than launch flags.
  Tart's guest agent exits on hosts that are not Tart, so baselines carry
  `bivouac guest-agent` as an Aqua LaunchAgent. Runner bootstrap through an
  Aqua guest agent was verified with real windowed Metal rendering and app
  lifecycle, focus, and input tests in a headless guest.
- Control through files and a signal rather than a socket, until the
  localhost API milestone.
- `security` CLI for Keychain instead of cgo bindings: one static binary.
  Reads parse `find-generic-password -g`, whose `0x` marker separates
  hex-rendered values from literals; `-w` prints unmarked hex for values
  with nonprintable bytes, which makes a hex-looking secret ambiguous.
- `actions/scaleset` pinned at v0.4.0; its listener package is not used
  because the manager needs to acquire jobs itself.
- Deferred: localhost management HTTP API and UI, Linux host provider,
  Actions storage optimisation.
