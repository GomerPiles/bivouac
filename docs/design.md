# Design

Bivouac runs each GitHub Actions job in a disposable guest on a personal
machine and discards the guest afterwards. This document owns the
architecture, the provider contract, the lifecycle state machine, the
security model, and durable decisions. Keep it aligned with the code.

## Architecture

```
cmd/bivouac          CLI; `biv` is a symlink to the same binary
internal/manager     control-mode loop, scale set pollers, instance lifecycle, budgets, reconcile
internal/provider    provider contract; vz/ (macOS), crosvm/ and hcsvm/ (Windows hosts), fake/
internal/vm          the VM store, VM manifests, Tart-format import, and the Virtualization.framework helper (`vm run`)
internal/guestagent  in-guest command agent over vsock, and its host client
internal/engine      bounded opaque container API streams between disposable guests
internal/github      scale set client wrapper (actions/scaleset) and test fake
internal/state       durable instance records and controller ID (atomic JSON)
internal/control     mode file, pid file, status snapshot (CLI <-> daemon)
internal/config      one TOML file, validated, no secrets
internal/secret      credential store (Keychain; native Windows Credential Manager)
internal/diag        diagnostics collection with redaction, bounded guest archive extraction
internal/command     argument-array subprocesses with bounded output and classified OpenSSH failures
internal/netpolicy   IPv4 egress denials shared by Windows-hosted providers
internal/macnetwork  public-only macOS host/interface/route socket admission
internal/rootnet     bounded rootless Ethernet, DHCP/DNS and TCP/UDP forwarding
internal/cachelink   fixed virtual cache endpoint and cache-only descriptor broker
internal/dnsproxy    validated DNS envelopes and fixed-resolver parent capability
internal/winhost     Windows host checks: protected storage, private staging, system OpenSSH
internal/hcs         typed Host Compute Service binding for direct Windows guests
internal/hvsock      cancellable, deadline-aware Hyper-V socket dialer
internal/vmhost      privileged VM host core: HCS guests, differencing disks, ownership journal
internal/winrunner   Windows guest runner adapter (`guest windows`), fixed Go modes
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
manager. Removing it does not stop an active manager or VM. The VM host service
is installed separately by an administrator; the login task never installs or
launches an elevated engine or service.

The portable Windows `Control.ps1` launcher checks native process-job membership
before starting an absent manager. A hidden window is not an independent
lifetime: a manager inherits its launcher's Windows job, and a development app
can close that job while native guests survive. A contained or
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
  GitHub expires the dead session (128–129 s in the crash tests). A job
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
(macOS `Exists && !Owned`, or `ErrNotOwned` from HCS and Crosvm)
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

The macOS provider uploads the current host binary once per disposable clone
at `/tmp/bivouac-helper`, shared by telemetry, optional caching and the macOS
side of optional container pairs. It removes the runtime leaf before uploading
so a stale symlink cannot redirect the write into the baseline agent.
The baseline agent need only match the guest protocol; helper delivery does
not depend on its binary version or filesystem ownership.

Its listener wrapper starts
the official runner in the same Aqua session, records the actual listener PID
for existing cancellation, preserves its exit code and joins sampling at exit.
The existing shell hook still records job identity; the helper's job marker only
starts numeric sampling. Partial helper installation is removed before falling
back to the official listener. Optional telemetry errors cannot fail a job.
An unavailable helper disables optional cache setup; a cache failure
removes only cache assets, preserving the helper used by telemetry or the relay.
Container readiness installs the macOS helper once before relay startup and
never overwrites it at runner start; its Linux companion receives its own Linux
helper. No running guest agent, baseline or host binary is modified.
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
running. A foreign guest named like an active record (an unprovable
Crosvm record) counts once, through its record, and is not
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

`provider.Provider` is implemented by the macOS VM runtime and the Windows HCS
and Crosvm runtimes. Launch options are argument arrays or structured fields,
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

The optional `provider.Activator` interface owns host runtime activation.
`Activate(ctx)` idempotently starts or checks a runtime for this provider;
`Deactivate(ctx)` stops a runtime it can control only once no caller has
instances, and leaves operator-owned foreground runtimes alone. Each call
has a 3-minute bound. Before startup reconciliation the manager synchronously
activates only providers with retained guest records; failure aborts startup.
Deregistering records need only GitHub cleanup and do not require activation.
In On without guest records, activation is asynchronous, so a failed runtime
does not prevent other providers from running. An inactive Activator without
guest records may fail inventory without aborting reconciliation; other
inventory errors still fail startup. Cancellation during startup activation
returns the context error, without reporting an activation startup failure.

After startup, On starts one manager-owned activation worker per inactive
provider, with at least 30 seconds after failure before retry. The manager
owns activation state under its lock, separately from idle-pool retries.
Inactive providers have no admission capacity, and `launch` enforces the gate
for pools, assignments and sweeps; pollers keep receiving job messages and
other providers continue. Status reports `starting host runtimes` until all
are active. The last activation error appears in status until activation
succeeds. Drain and stop keep runtimes running, but every transition into On
revalidates activation (a cheap Info check when already serving). Failed List
calls invalidate active providers and wake the loop for reactivation. A worker
started before a later On transition cannot satisfy that new activation check.

Off stops pollers, cancels and joins lifecycles and activation workers, and
deactivates every Activator, including ones this daemon never activated. It publishes
`releasing host runtimes` before release and `exiting` only afterwards, so
`off --wait` includes release. Release failures are logged and still allow
exit; activation state becomes inactive. Context cancellation cancels and
joins workers but never deactivates: guests remain for adoption.

### macOS (`vz` provider)

Managed runners use a rootless gVisor stack in a dedicated Seatbelt child of
one VM helper. A private datagram socket pair attaches through
`VZFileHandleNetworkDeviceAttachment`; netstack terminates TCP/UDP and opens
admitted host sockets. No host interface, vmnet, privileged service or network
configuration change is needed. Link/child failure ends the VM; there is no NAT
fallback. A separately selected trusted lab NAT control never receives runner
credentials. Dependencies are pinned in `go.mod`/`go.sum`; networking stays pure Go.

Before consuming guest frames, the child activates deny-by-default Seatbelt:
only outbound IPv4 TCP/UDP and routing-table sysctl reads are allowed, followed
by an explicit `localhost:*` outbound denial for currently configured local
addresses, rather than all of 127/8 (socket admission independently denies 127/8). File access, exec, inbound listeners
and Mach services (including Keychain) are denied. The deprecated native APIs
are a compatibility prerequisite: missing APIs, policy-read, sandbox activation
or proof failures close launch/adoption. The child remains trusted admission code.

The credential-free child receives attachment, owner-lifetime and numeric-report
FDs, a preconnected cache broker, and a separate DNS capability socket. The cache
broker accepts only a closed service enum and returns connected stream FDs for
fixed per-VM payload/CRL handlers; it accepts no destination, path or command.
DNS correlation IDs allow bounded concurrent requests and cancellation without
serializing cache setup. Cancelled workers retain their parent slot until exit. Parent workers have deadlines and independent bounds;
DNS and cache failure do not disable each other. No VM handle, App key, cache TLS
credential or filesystem right is delegated. Existing and transferred FD I/O
requires no broader sandbox rule. Readiness precedes VM boot; owner-pipe EOF
stops the child, and adoption proves the owned helper, child relationship and
kernel Mach denial. Controller loss leaves the helper/guest alive for adoption.

Each VM, including each container-pair member, has its own link and settings.
`192.0.2.1`/`192.0.2.2` are virtual gateway/lease identities, never host aliases.
The clone MAC and source IPv4 are fixed. DHCP/ARP provide only this guest's lease,
router, DNS and MTU; ARP claims only the gateway, with the guest neighbor pinned
for duplicate-address detection. IPv6, VLANs, unknown L2, fragments and outbound
ICMP are dropped. IPv6 requires scoped route/address admission, NDP/RA and
sandbox rights together; ICMP requires a separately admitted echo translator.

`internal/macnetwork` admission excludes special/private IPv4, host interface
prefixes, explicit gateways and non-default routed prefixes. Internet defaults,
ICMP-redirect dynamic routes and ephemeral cloned routes are excluded.
Split-default VPNs can conservatively deny public access. Unknown policy denies
access. Snapshots last at most 250 ms; refresh failure replaces success with
denial, and existing public flows close when denied. This is a non-atomic
observation window. Public services leading back to host/LAN through NAT, reverse
proxies or tunnels remain reachable unless their destination appears in denied
routes. Networks represented only by Internet defaults cannot be classified as LAN.

Virtual UDP/TCP DNS uses a fixed-function capability: the child validates and
rebuilds one QUERY/IN question, with empty Answer/Authority and at most one OPT.
Transfers, other opcodes, TSIG/SIG(0), extra records and trailing data are refused;
unsupported EDNS versions receive BADVERS.
OPT retains only bounded UDP size and DO; ECS, cookies and unknown options go.
The parent repeats validation and selects only its configured resolvers: primary
nameservers from `/etc/resolv.conf`, refreshed per operation, or operator IPv4
`dns_servers` overrides. Parent sockets may use IPv4/IPv6 loopback or LAN DNS.
There is no public-resolver fallback. Scoped/per-domain macOS resolvers and
`/etc/resolver/*` are not consulted. The cache uses `net.DefaultResolver` system
routing unless the same override is configured; vz providers must agree on
overrides because the cache client is shared.

All DNS types pass through except IPv6 advertisements: AAAA queries get empty
NOERROR; AAAA records and HTTPS/SVCB address hints are removed. A hint named in
`mandatory` makes its record unusable and it is dropped. A denied Answer A makes
the whole response NXDOMAIN; denied Authority/Additional A glue is dropped.
CNAME chains and TTLs otherwise survive. Changed RRsets lose covering RRSIGs and
AD is cleared. Unmodified upstream wire bytes are retained, avoiding unsafe
repacking of opaque RDATA. Upstream IDs/questions are validated, RCODEs retained,
temporary SERVFAIL/REFUSED responses try the next resolver, and TCP responses
are bounded to 65535 bytes. Guest UDP honors EDNS up to 4096 (512 without it); truncation sets TC and retains only question/OPT. Direct guest port
53 traffic still follows ordinary socket admission.

Guests can drive bounded concurrent queries at primary resolvers without rate
limiting, and see internal TXT/PTR/other DNS metadata.
Opaque RDATA is not inspected; destination socket admission is the isolation
boundary. Operators avoiding this disclosure choose public `dns_servers`.
Baselines must use DHCP networking/DNS. Cache egress requires all resolved
addresses to be admitted before selecting an IPv4 destination.

One configurable general ceiling (default 4096) counts public TCP/UDP, pending
TCP handshakes and cache payload streams. Reserved DNS capacity (32..256, derived
from the ceiling) and 32 CRL operations remain independent of payload pressure.
TCP idle expiry defaults to 24 h and UDP to 60 s; DNS/NTP UDP closes after one
reply. TCP EOF propagates half-close in both directions; errors, cancellation,
idle expiry and policy revocation close the flow. After FIN, inactivity expiry is
`min(tcp_idle_timeout, 15m)`. Guest UDP reads are MTU-bounded; upstream reads hold
full 65507-byte datagrams for netstack fragmentation toward the guest. Native UDP
readers wait for readiness before borrowing buffers and return them after each
read/forward operation, so idle flows retain no relay payload buffer.

`network.memory_mb` defaults to 1024 MiB. Each public/cache TCP send and receive
maximum is `L = clamp(budget_bytes / (2 * max_flows), 128 KiB, 4 MiB)`, including
the initial buffer sizes. General TCP data buffers can therefore occupy at most
`2 * max_flows * L`: 1 GiB at defaults. Reserved DNS/CRL TCP buffers add at most
72 MiB at defaults; two 32 KiB copy buffers per public/cache/CRL relay add up to
258 MiB. Concurrent UDP reads/forwards can additionally borrow up to
`max_flows * (65507 + min(65507, MTU-28) + 1)` bytes (about 262 MiB at MTU 1500,
320 MiB at the default 16384, 512 MiB at 65535), sharing the general ceiling with TCP. Pools can retain
returned buffers until GC. These are payload-buffer bounds, not a whole-process
RSS cap: endpoint/packet queues, DNS messages, connection metadata, goroutines
and the Go runtime add memory; host kernel socket buffers are outside the child.
The 128 KiB floor can exceed a small configured sizing target (65536 flows imply
16 GiB of general TCP buffers at that floor). Helper, child and controller check
FD headroom;
insufficient limits fail clearly before VM launch.

Only TCP `192.0.2.1:7443` selects the cache payload capability. The configurable
host endpoint bound defaults to 256; the parent independently bounds grants and
relays by that setting plus its reserved CRL budget. Guest bridge and stack add
no equal payload cap. Each host listener accepts only its guest's grants/leases.
TLS, upstream restrictions, expiry and revocation stay mandatory. CRLs use only
GET/HEAD `/ca.crl` at `192.0.2.1:7444`, with independent stack/broker/listener
capacity and proxy bypass. VSOCK carries only a six-byte port announcement and
lifetime; losing it closes the guest loopback listener and streams. Cache outage
permits direct public fallback through mandatory admission. Container-engine
VSOCK remains separate. Cache TCP disables Nagle and shares the budget-derived
buffer ceiling with public forwarding. Local benchmarks do not establish guest speed.

MTU is configurable from 1500 to 65535, default 16384, chosen from live guest
adoption and noisy bidirectional throughput measurements. The TCP sizing budget
remains 1024 MiB independently of MTU. A non-1500 MTU needs the macOS 13
attachment API; launches fail clearly without it. Container-pair Linux engine
members stay at 1500 until their DHCP MTU adoption is validated. Large guest UDP datagrams above the real
path MTU are fragmented by the host; ICMP fragmentation-needed messages do not
reach the guest. TCP is terminated in the stack, so its upstream leg negotiates
its own segment sizes. VZ attachment, stack IP MTU, DHCP option 26 and Ethernet
bounds agree;
channel/read buffers hold IP MTU plus 14, up to 65549 bytes. Truncated datagrams
fail the attachment. Both socket ends prove 1 MiB send/4 MiB receive buffers and
exchange a full-MTU datagram before handoff. No host-wide socket tuning occurs.
The nonblocking ordered FIFO has byte budgets of `4096*1514` for data and
`256*1514` for control, plus frame-count bounds. ACK, ARP, DHCP, DNS and CRL traffic
retain reserved capacity; overflow is explicit loss recoverable by TCP.

The child emits fixed numeric reports only: flow/DNS refusal and failure
counters, plus active public TCP (including pending dials), UDP and cache-payload
gauges sampled together under the slot-accounting lock. Reserved DNS/CRL
operations do not enter these gauges. The helper logs changed snapshots at most
once per minute and a final snapshot at exit. Its 1 MiB cap reserves terminal-line space. No addresses,
names, packet contents or arbitrary child text reach these reports.

Before credentials, JIT, status or adoption, durable state, provider metadata and
live lock-holder arguments prove `--rootless-network` and the policy ID. Both
container-pair members require proof. Old NAT/Softnet/unsandboxed helpers are
refused; proven-owner cleanup still works. Drain old jobs before owner-controlled
migration; no installed binary, VM, baseline, label or privilege changes implicitly.
Read-only bootstrap shares remain an explicit opt-in for ordinary runners;
container pairs prohibit shares. Graphics, input and typed machine options remain.

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
  [--input] --rootless-network [--display WxH[@PPI]]
  [--disk-sync full|fsync|none]`, from the executable signed with
  `com.apple.security.virtualization`. The helper builds the VM with purego
  bindings to Virtualization.framework (graphics device, virtio disk,
  rootless network for managed macOS runners, entropy, balloon, vsock; keyboard and pointer for runner
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
  Its LaunchAgent uses `ProcessType=Interactive`: the default process class
  throttles low-priority I/O during boot, delaying agent startup and inherited
  runner commands. The agent and runner remain in the auto-login user's Aqua
  session with the same permissions and VM resource limits.
- Ready: the agent runs `true`. DHCP supplies the isolated lease and virtual DNS service without guest sudo.
  Live rootless proof precedes private setup and runner registration. Only an unreachable agent is retried; an
  agent of another protocol version names its own, and readiness fails at
  once. The bootstrap script is then copied to `/tmp/bivouac-guest`, and
  its `session` mode must report `Aqua`, or readiness fails.
- Every guest command caps stdout (status 4 KiB, otherwise 64 KiB) and fails
  when the cap is exceeded. Errors never include guest output. Ordinary commands
  discard stderr; explicit lab diagnostics capture a bounded, sink-redacted
  prefix separately from fixed error classes and numeric exit codes.
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

Structured `startup stage` records use the daemon's redacted sink and
host-monotonic durations, with provider and guest identity, fixed stage names,
milliseconds and success even on failure. The manager records JIT generation
and official listener readiness for every provider. The macOS provider adds
clone, VM-helper launch, agent availability, script delivery, Aqua verification,
helper upload, optional cache setup and JIT delivery; container pairs also time
companion agent/helper preparation and DNS setup. No command arguments, stdin,
guest output, credential material or raw errors enter these records. The sink
is supplied at provider construction. Existing manager clone/boot/registration
totals retain their meaning, and adoption repeats neither helper delivery nor
registration. See [operations](operations.md) for stage definitions.

### Windows host foundation

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

### Windows guests through HCS

Bivouac drives the Host Compute Service (`internal/hcs`) directly.
The runtime provider reaches guests only through bivouac's guest agent over
HvSocket. It requests only `guestagent.ServiceID`; there is no SSH, App Sandbox
protocol, PowerShell readiness path or host-key pin. Old images are unsupported;
rollback uses the previous manager binary, VM host service binary and image. The image factory and vmhost lab
batch use the same bivouac agent and service ID.
HCS synthetic video supplies the desktop display alongside GPU-PV rendering.

The Windows `guest-agent --user <account>` transport uses protocol version 1 on service
`54f2299e-45e4-4605-b3ed-03d3d5fbea6a`, with a parent-only HvSocket listener
and no IP listener. At startup and each connection it requires the configured
account's SID, the active nonzero console session, and an elevated full or
unsplit token. The image's protected logon task must pin that account; commands
inherit the agent's token, session, desktop and environment. Each command starts
atomically in a hidden kill-on-close job without permission to break away. All
descendants die with it. The runner is dispatched through a separate on-demand
task, independent of the agent task and command jobs. Guest-local logs contain fixed categories
and numbers only, capped at 1 MiB plus one rotation.

Listener Accept/open failures close the failed listener and re-listen in-process
with exponential backoff from 100 ms to 5 s, cancellable on shutdown. Existing
commands keep their context during listener recovery. A failed per-connection
session check sends one bounded fixed refusal and closes only that connection.
A successful check resets refusal history. The agent exits after at least five
consecutive refusals spanning 10 seconds within a 30-second window; older
windows reset. The scheduled task's three one-minute retries are a backstop for
process failure, rather than the listener recovery mechanism. Recovery after an
actual crash and survival across task/agent restarts remain live gates.

Its `guest-agent receive <name> <size> <sha256>` mode accepts only the helper,
configuration and runner archive names in the protected guest directory.
It verifies up to 1 GiB before atomic publication, refuses links/alternate
streams and the `launched` marker, and uses delete-on-close temporary files.
The adapter must hold the same exclusive `.receive.lock` while writing that
marker. The host dialer uses cancellable 3-second attempts and 500 ms pauses.
The per-service connect descriptor admits SYSTEM, Administrators and the creating
manager's account. Every process of an admitted host account has authority to
execute commands as the configured guest administrator. Account identity is the
authentication boundary, equivalent to the macOS agent's 0600 socket; neither
transport authenticates individual processes within that account. No key
deployment, host-key pins or per-guest secrets remain. The
image installs the matching agent at `guestagent.WindowsPath`
(`C:\Program Files\Bivouac\bivouac.exe`); the factory registers its logon task.

The provider delivers its matching Windows adapter and uses its Go `preflight`,
`prepare`, `start`, `stop`, `clock` and `cache-listen` modes. The receiver
contract is the fixed allowlist, exact size and SHA-256; the adapter contract
is the fixed argv, stdin and bounded JSON/UTC/base64 outputs described here.
`guestagent.WindowsContract` independently numbers the Windows agent CLI,
receiver and adapter-mode semantics relied on by the provider. Change it when
those semantics change; framing `Version` is independent and remains shared
with macOS. The factory manifest records `windows_contract` and the agent hash.
The VM host reads each protected adjacent manifest and reports `image_contracts`
in Info (zero for missing, unreadable or invalid metadata). Doctor and activation
require the exact local WindowsContract before readiness or guest creation.
The protocol version is proved before any delivery. Host adapter and provider
come from the same build; there is no legacy script or task-mode compatibility.

- `preflight` reads `bivouac-config.json` in the protected guest directory,
  checks computer/user identity, console ownership, completed setup/OOBE,
  Explorer in that session, its own console session and the Default input
  desktop. Five consecutive observations 500 ms apart are required within
  ten minutes. Its small JSON proof includes `ready`, `session`, `desktop`.
- `prepare` holds the receiver's directory guard and exclusive lock, refuses
  another recorded instance or an existing launch marker, and installs the
  delivered helper/config as `bivouac.exe` and `config.json` for existing
  listener/hook modes. It selects exactly one MAC and uses fixed netsh argv
  for static IPv4, DHCP disablement, gateway and public DNS. Archive mode
  verifies SHA-256 and extracts only into a fresh directory: at most 512 MiB
  compressed, 65,536 entries, 512 MiB per file and 2 GiB expanded. Absolute
  paths, traversal, Windows path aliases, duplicate paths and special/link
  entries are refused. A failed extraction is not reused. The generic runner
  must be present and unconfigured; desktop proof needs no scheduled task.
- `start` checks the runner task definition, single-use state and bounded
  private JIT input while holding the receiver lock. It publishes `launch-mode`
  (`listener`, or `lab-probe` in the lab) by flushed temporary file and rename,
  then creates and flushes `launched` before invoking system `schtasks.exe`
  with `/Run /TN bivouac-guest-runner` as an argument array. Failed or uncertain
  dispatch retains the marker and is never replayed. Startup waits at most
  45 s for a live recorded listener identity; scheduler acceptance alone is
  insufficient. `stop` takes no receive lock, so it can run during start's
  wait. It first creates and flushes an exclusive `cancelled` record
  (an existing record is fine), including when no listener exists. It then cancels the
  recorded official listener using PID/creation-time/path and console rechecks.
  Exited or never-launched listeners need no signal. The trampoline and helper
  both check cancellation before creating their child; the helper records
  `runner.exit` when cancelled before listener creation. After publishing
  `listener.json`, the helper checks cancellation again and signals its own
  official listener through the same identity-checked console cancellation
  path, then records its exit. Stop publishes cancellation before reading
  `listener.json`; at least one side sees the other in either interleaving.
  A double Ctrl+C is accepted when both sides signal: `cancelled` records
  intent and `requested` is written only after signaling, so both senders can
  observe the empty marker before either acts. Checking that text would not
  atomically assign sender ownership. Repeated-signal behavior remains a live gate.
  Provider failure
  teardown destroys the VM after failed or uncertain startup.
- Installed `guest windows detached` validates the configured autologon account's
  SID, elevation, active console session and its own `WinSta0\Default` desktop.
  The account is resolved from the published image's public machine Winlogon
  `DefaultUserName` and `DefaultDomainName` configuration, never delivered
  configuration or environment identity. The trampoline queries no task definition
  or security descriptor.
  An interactive logon by another account breaks both autologon and runner start.
  It pins the guest directory without taking the receive lock (start holds it
  while waiting). An absent `launched` consumes nothing. It exact-matches
  `launch-mode`, claims `detached.claim` with exclusive creation and checks
  `cancelled`. It opens the delivered helper through the pinned directory,
  rejecting links, and starts its `guest windows listener` mode with fixed argv,
  `DETACHED_PROCESS`, hidden window, NUL streams and the guest working directory.
  The lab token selects the installed agent's harmless probe instead. The
  trampoline waits and propagates its child's exit code. The supervisor,
  official listener (with its own cancellation console), worker and job steps
  belong to the runner task's tree.
- `clock` accepts one bounded UTC RFC3339 line on stdin and uses
  `SetSystemTime` directly, returning current UTC. It has no local-time/DST
  conversion. The provider refuses a corrected clock more than 5 s from host UTC.
- `cache-listen` binds only `127.0.0.1:0`, publishes `cache-port.json` and
  emits the same `{ "port": <number> }` JSON line before engine frames on
  stdout. The host consumes exactly that bounded line, uses the port in the
  cache bootstrap URL, and calls `engine.Relay` with limit 64, dialing an
  in-process connection to the shared TLS cache handler for each guest connection.
  The guest uses `engine.Listen` with that same limit until stream closure.
  Container relays retain limit 16.
  Cache setup/removal files and the agent protocol remain unchanged; this
  adds no automatic reconnection or NIC exception.

HCS and Windows networking refuse ordinary tokens, so the work splits in two:

- The manager stays unprivileged. It holds GitHub credentials and budgets, and
  it handles everything a guest can influence: transport, runner status, cache
  traffic and diagnostics.
- A small VM host runs elevated. It creates and removes compute systems,
  per-job differencing disks, each VM's network endpoint and firewall policy,
  and the network guard described below. Its ownership journal lives in an
  administrator-only `%ProgramData%` directory. It accepts a fixed set of operations on a local
  named pipe whose DACL admits only the accounts named in its
  administrator-protected configuration. It never receives GitHub
  credentials, job data or guest output.
- Each HvSocket service's descriptor admits SYSTEM, Administrators and the
  manager's account. The manager therefore connects to guests itself, and
  guest traffic never passes through the elevated process. A live test
  confirmed that an unelevated account is refused services it was not
  granted.

The pipe (`\\.\pipe\bivouac-vmhost`) carries one bounded JSON request per
connection: info, create, status, destroy or list.

- Authorization:
  - The client dials at identification level. After reading the request,
    the VM host impersonates the client on a dedicated thread to learn its
    account, and refuses accounts outside its configuration.
  - Anonymous callers are refused.
  - The DACL grants accounts read and write data only. It never grants
    create-instance, so no account can serve the name.
  - The client refuses a pipe whose owner is neither SYSTEM nor
    Administrators, so a process that squats on the name is not trusted.
    The VM host sets the owner to Administrators explicitly. Only a token
    holding Administrators or SYSTEM as an owner-eligible group (elevated or
    SYSTEM, not a UAC-filtered token), or holding SeRestorePrivilege, can
    assign either. An unelevated client cannot open a SYSTEM service's
    process token, so the server process itself is not inspected.
- Each guest belongs to the account that created it. Status, destroy and list
  see only that account's guests.
- A create names a configured image, not a path. The VM host sets each
  HvSocket service's descriptor to the caller's account.
- The VM host reserves instance, CPU and memory capacity against its
  configured limits before any HCS call. Info reports the shared totals, so
  every manager budgets against the same host.
- A create whose outcome is unknown, or whose cleanup after a failure did not
  finish, keeps its reservation until a later VM host's Recover settles it.
  That Recover is bounded to 2 minutes, so a guest that never settles cannot
  hold the VM host's startup.

The `hcs` provider (`internal/provider/hcsvm`) is the manager's half.

- **Create** asks the VM host to create, start and GPU-assign the guest. It
  labels the guest with the controller and instance IDs, which Status and
  List check. The VM host returns only this account's guests. **Stop** and
  **Delete** both destroy the disposable guest.
- **Guest commands:** a per-guest dialer uses the current runtime ID. Every
  command owns one agent connection; closing it kills that bounded command
  and ordinary descendants. Transport failures get the manager's bounded grace;
  version refusal is terminal with fixed unavailable text. Adoption repeats
  current ownership/running proof and dials again, without any pin file.
- **Readiness** first proves the agent with a fixed `version` command, retrying
  transient failures within the readiness bound. Dial attempts are capped at
  3 s with 500 ms pauses; each proof command is bounded to 15 s. Then it receives
  configuration, helper and optional runner archive; runs the delivered
  `bivouac-helper.exe` preflight and prepare; and calls installed `bivouac.exe`
  clock with host UTC on stdin. Every later adapter command uses
  `C:\ProgramData\Bivouac\Guest\bivouac.exe`. Status remains one bounded agent
  command at the existing approximately 2 s polling interval.
- **JIT** bytes travel only on agent stdin. Neither JIT delivery nor start is
  replayed after an uncertain outcome.
- **Startup measurements:** each readiness call emits one Info record with
  fixed numeric millisecond spans and a fixed failure stage when applicable.
  Host-monotonic create-relative milestones exist only when this provider
  observed Create; they are not persisted or reconstructed after adoption.
  The network lab retains the same report, including partial failures. Launch
  separately measures cache setup, JIT delivery and process start; the first
  existing status poll observing listening or running records JIT-to-listening
  once. Observations contain no guest text, identity or credential material
  and add no measurement-only guest commands or polls. See
  [operations](operations.md#direct-hcs-vm-host) for field semantics.
- **Network:** every create asks for an isolated endpoint. The lease (address,
  gateway, prefix and MAC) goes to the guest in its runner configuration.
  WaitReady still refuses a guest without a lease, because its runner could
  not reach GitHub.
- **Cache:** after readiness and before JIT delivery, a dedicated agent Duplex
  command exports a guest-loopback listener without using the guest NIC or
  relaxing HCN/VFP isolation. It outlives its bounded attachment context and
  closes on relay loss, grant revocation or service shutdown. Commands and cache
  use independent connections. TLS/HTTP timeouts and header limits are unchanged.
  Setup uses
  the shared Windows adapter with the bootstrap on stdin, cleared after use.
  Failed setup revokes the grant and removes partial guest settings before
  upstream fallback; uncertain cleanup refuses JIT. Confirmed deletion or
  absence revokes the grant, and provider Close closes its cache transports.
  Transport loss uses upstream fallback without reattachment.

The official runner starts once through the separate runner task's supervisor, with
rebuilt machine/user PATH and a default-input-desktop probe. The guest adapter
records listener PID, executable and process creation time; cancellation
rechecks that identity before signaling its console. Stop requests official
runner shutdown, which reports a failed job without calling GitHub's workflow
cancellation API. Off lets accepted work finish normally. A baseline may contain
an unconfigured runner, or each clone receives a hash-pinned official runner ZIP.
Diagnostics use bounded base64 and ZIP extraction that rejects unsafe paths and
expansion before redacting host sinks. No host directory is mounted. The
detached listener is intended to survive the start request and agent/manager
restarts. Survival across actual agent/task restarts remains a live gate.
Status, diagnostics, clock and other ordinary commands remain tied to their
connections.

The VM host runs either as an optional Windows service or as an elevated
foreground `bivouac vmhost run` (one UAC prompt per start). Nothing installs the
service implicitly. An administrator installs it explicitly, which needs no
reboot. Installation grants the configured accounts start and stop rights on
that one service, so mode changes never need elevation. The service starts from
the service manager with a clean environment. It does not inherit the ordinary
manager's environment.

The HCS provider implements `Activator`. It checks the serving host's image
and CPU/memory limits using the same observational check as doctor. If the
pipe is unavailable it starts the installed service, waits through SCM
StartPending/StopPending, then waits for pipe readiness after startup recovery.
Readiness timeouts retain the last Info error; a service that stops during
readiness fails activation promptly.
Without the service, the operator must run an elevated foreground VM host.
The manager reserves the configured HCS CPU/memory in each instance record;
Create refuses an explicit spec that disagrees with its configured image or size.

Off stops the service only after Info positively reports zero guest
reservations across all callers. Deactivation waits through pending service
states and Running-before-pipe startup recovery within its bound. It returns
once the service is stopped, or checks Info before issuing Stop. Unknown
inventory at timeout or retained failed-cleanup reservations leave it running
with a logged reason, retaining the last wait failure in timeout errors.
The check/stop window is accepted because the configured accounts are
bivouac's own and this daemon is exiting. A foreground VM host is never
stopped. Drain, stop and manager signal shutdown keep the runtime active;
manual service start/stop commands remain available.

Guests are created with `ShouldTerminateOnLastHandleClosed`, and the VM host
holds their handles:

- A manager crash leaves guests running for adoption.
- If the VM host exits, its guests and their network guard end together. On
  its next start, it confirms each journalled guest is absent and then removes
  that guest's disk and network.
- Upgrading the VM host therefore requires draining first.

The VM host touches a system it opened by name only once its properties
prove it ours (ID, owner, VM type and journalled runtime ID). Its own creating
handle, proven right after create, is trusted for cleanup even when that proof
later fails: after a failed start HCS reports the same system as an unowned
`Container` with no runtime ID. Closing that handle ends the guest, and
absence is still confirmed by name before its storage and network are removed.

The guest's RTC holds host local time and the image reads it in its own time
zone; the creation document has no time-sync channel. The image factory keeps
the install image's time zone and RTC handling, so the provider's `WaitReady` sets the
guest clock from the host's UTC time, sent on stdin to a fixed command, and
refuses a guest still more than 5 s off. GitHub rejects a runner token from a
skewed clock. The clock is set through local time, so in the guest's
fall-back hour it can land an hour off; the check then refuses the guest
rather than accept it. Likewise, the Windows runner launcher gives the runner
a process-scope `RemoteSigned` execution
policy when neither the CurrentUser nor the LocalMachine scope sets one that
allows local scripts and none is inherited, because the runner dot-sources a
script file for its hooks and every `powershell` step. A Group Policy setting
outranks it and is left as it is.

Guest networking (`internal/hostnet`) gives each guest its own HCN ICS switch
and an endpoint on a dedicated
/28 from 10.251.0.0/16, with a MAC derived from its name. An owned stateless
VFP layer on its port denies the host's interface prefixes and all IPv6, and
allows public IPv4. This layer stays separate from Windows' service-owned
firewall layer: automatic host loopback rules in that layer took precedence
over explicit block rules even with loopback reported disabled. Native NAT
alone does not establish host or private-network isolation.

- **Plan:** fresh native IDs, the subnet and a snapshot of the host's
  effective denial are journalled with the intent, before any native
  mutation. A new plan avoids every journalled subnet. Other guests' switches
  are private prefixes that are already denied, so they do not change the
  snapshot.
- **Create:** the switch and endpoint exist before the compute system, and the
  endpoint is the creation document's only NIC.
- **Protect:** if the switch port already exists after create, the VM host
  installs and verifies the layer before start. Otherwise it does so right
  after start, before the guest is reported. The guest's timings record which
  path ran. Either way, the started guest's runtime ID must match the
  endpoint's VM binding. So far the port has appeared only at start, so a
  guest runs for about a second before its layer is in place.
- **Invariant:** nothing untrusted reaches a guest before its layer is
  verified. Ordering guarantees this, not timing:
  - The VM host reports a create only after the layer is installed and
    verified, and the provider sends nothing to the guest before that.
  - Until then only the pinned image runs, from a fresh differencing disk and
    fresh firmware state.
  - Its firmware could try network boot only if that disk failed to boot. Such
    a guest never becomes ready, so it receives nothing and is discarded.
    Pinning the firmware's boot entry to the disk (`BootThis` with
    `StopOnBootFailure`) made HCS refuse to start the guest, so it is not used.

  The window after start is accepted on these terms. A change that lets
  anything untrusted run earlier must close the window first. Examples are
  reusing a guest or disk across jobs, or a guest agent that takes input
  before readiness.
- **Teardown:** the endpoint and switch are deleted only after the compute
  system is confirmed absent and its port is disconnected, retrying while it
  stays connected. The disconnected port itself remains until its endpoint is
  deleted. A native network that does not match its plan is retained.
- **Guard:** every 10 s the VM host reproves each networked guest: switch,
  endpoint, runtime binding, connected port, VFP rules, and an unchanged host
  denial.
  - A failing guest is quarantined. Its port is blocked, or the guest is
    destroyed if blocking fails. It reports stopped until its owner destroys
    it.
  - Admission stays closed while a pass fails or any guest is quarantined. It
    reopens only after a pass that checked every networked guest successfully.
    A canceled pass changes nothing.
  - The guard polls. It does not react atomically to an interface change.

Off and Stop release all guest CPU, memory and GPU. When the VM host is
installed as a service, Off also stops it, leaving the host free for other GPU
work. An optional warm spare keeps one booted, unregistered guest ready while
On. It is a durable runtime setting like the mode, so it can be switched without
editing configuration.

Bivouac never enables Windows features, installs host drivers, changes boot
configuration or requests a reboot. Hyper-V's compute and network services
must already be present.

Prepared images are built once by the image factory (`internal/imagefactory`,
`bivouac image`) from pinned Windows install media and published as a
single standalone VHDX. At runtime they are pinned by file identity, protected
ACL and deny-write handles, not hashed per job.

- **Media and base disk:** `iso` and required `iso_sha256` replace template
  paths and owner records. The source is pinned by a deny-write/delete handle
  while copying and hashing into the protected workspace. Only that copy is
  mounted, read-only without a drive letter. A bounded pure-Go UDF reader
  inventories exactly one install.wim, unencrypted install.esd, or complete
  install*.swm set; metadata comes from the uncompressed UTF-16LE WIM XML
  resource, never localized DISM text. DTDs, malformed XML, unknown flags,
  excessive sizes and incomplete/mismatched split sets refuse. Selection uses
  EditionID `Professional` by default and x64 Client; an explicit image index
  overrides the edition. XML INDEX must equal its 1-based position so selection
  matches DISM. Display names are sanitized, bounded information.
  Pinned file inputs (ISO, runner ZIP, render probe and factory executable)
  need not be administrator-protected: copyPinned hashes exactly the bytes it
  writes into the protected workspace in one pass, rejects a mismatch, and
  only then permits use. Input handles deny write/delete while open. This
  deliberately replaces source-ACL checks for all pinned file imports;
  driver-directory validation remains separate.
- **Disk layout:** the factory creates a dynamic VHDX (default 127 GiB,
  bounded 64-256 GiB) with 512-byte sectors. Before GPT initialization it
  cross-checks the mounted image's physical device, Storage disk path and
  reverse device-to-owned-VHDX association. Windows generates the disk and
  partition GUIDs once; later child inspection/staging selects the recorded
  Windows partition GUID. Layout: 200 MiB FAT32 ESP, 16 MiB MSR, NTFS Windows
  using the rest, no recovery partition. DISM applies the selected index with
  `/CheckIntegrity` and `/SWMFile` for split media. The factory does not register
  WinRE at apply time and creates no recovery partition; Windows setup may
  subsequently register WinRE on the Windows volume. The manifest records
  this apply-time policy, not the installed guest's final WinRE state.
  BCDBoot uses `/s` with a journalled temporary ESP letter, `/f UEFI`,
  `/offline` and `/nofirmwaresync` to select boot files explicitly and disable
  host firmware synchronization;
  `/bootex` is omitted for the existing MicrosoftWindows firmware template;
  the reference image's normal EFI boot manager has a 2011-PCA signer.
  The final table must be exactly three partitions in offset order with the
  recorded GUIDs, ESP/MSR/basic-data types and expected sizes; automatic extra
  partitions refuse. The fallback EFI loader, Microsoft loader and BCD store
  must exist. Both loaders must have valid Authenticode signatures from the
  expected 2011 issuer. The manifest records fixed issuer names and BCDBoot's
  version alongside DISM's version.
  The base and ISO are detached before the differencing child is created.
  Disk/partition GUIDs remain shared by clones; they are not randomized on
  host attachment. TPM-bound BitLocker protectors are not supported.
- **Ownership and cleanup:** ISO mount, base/child attachment, access paths and
  temporary letter have durable intents before creation. Partitions share the
  owned base attachment's lifetime; their GUIDs are recorded in the layout.
  Fixed host helper processes and their DISM/BCDBoot descendants are atomically
  assigned to a private kill-on-close job named in the Global namespace from
  the durable workspace identity. Cancellation joins those processes only;
  WMI providers and storage-service operations run outside that job and may
  still be in flight. Cleanup from another session refuses a surviving named
  worker. It proves guest absence, removes only recorded access paths on the
  owned attachments (including RAW/partitionless bases), confirms detach, then
  removes workspace files. Storage uncertainty retains the workspace.
  Temporary-letter selection excludes live letters and every mount-manager
  reservation, including absent devices; boot rechecks reservations before use.
  After detach/reboot, only a GPT mapping with the exact DMIO:ID: prefix and
  recorded ESP GUID bytes retains the workspace for operator resolution.
  Unreadable mount-manager state also retains it. Cleanup reports retained_letter;
  known foreign mappings remain untouched and do not retain the workspace.
  No provider service journal or CI mode is touched. Applied-image TOTALBYTES,
  ISO size and child/flatten headroom replace the template-copy space estimate.
- **Inspection gate:** before boot, the child must be generalized to OOBE,
  with no answer-file pointer, an absent/empty embedded answer directory,
  no runner, agent installation, either guest task or bivouac job state. The reference
  install image's pristine hives satisfy the existing setup-state gates.
  `image inspect` instead hashes and inventories media without mounts, disk
  creation or HCS. Facts are public; answer-file values are never reported.
- **Offline staging:** the factory installs its own executable at
  `guestagent.WindowsPath`, recording SHA-256 and `guestagent.Version` in the
  manifest. The installation grants SYSTEM, Administrators and TrustedInstaller
  full control and Users read/execute, without inherited user write access.
  A bounded, protected snapshot of each configured GPU driver tree is copied
  into `Windows\System32\HostDriverStore\FileRepository\<directory name>`.
  Exact file/directory inventories and SHA-256 checks refuse links, incomplete
  or changed snapshots. A temporary sibling is renamed only after verification;
  ownership and inherited ACLs come from the guest repository, never the host.
  Existing destination trees are refused. Install media remains read-only.
- **Build:** one elevated foreground process boots the child with GPU-PV,
  no NIC or Plan9 shares, and only `guestagent.ServiceID` with the base
  SYSTEM/Administrators descriptor. Validation, runner check and sanitation
  use bounded agent commands with fixed PowerShell argument arrays and framed
  stdin, exclusively during build/lab work. Their bootstrap discards incidental
  pipeline and host streams and suppresses progress; deliberate Console writes
  use UTF-8 without a BOM. Guest script exit codes become the PowerShell process
  exit code; terminating errors remain step 18. Without an explicit exit, the
  last native exit code is propagated, or zero if none was set.
  Validation decodes the entire bounded stdout as one
  JSON value with the expected types, without extracting or repairing bytes.
  Decode errors contain only numeric shape facts, never guest text.
  The render probe has an explicit 180-second wait during first-boot factory
  validation (`require_setup`), and 50 seconds otherwise; its task execution
  limit exceeds that wait by 30 seconds. Probe failures emit at most 2 KiB of
  fixed numeric/boolean facts: task state/result, console-session render count
  and CPU time, present display/GPU-PV state, Explorer age and elapsed/budget
  seconds. Observation flags distinguish unavailable facts from zero. Failed
  validation errors append only a strictly decoded, complete schema; malformed,
  oversized or unexpected output adds no guest bytes to errors.
  After a preparation failure on the proven running guest, cleanup requests
  guest shutdown through fixed agent argv, allowing at most 60 seconds total
  for the request and native exit observation (request capped at 10 seconds),
  then performs the existing terminate/absence cleanup. Refusal or timeout
  cannot suppress termination or turn the build into success. This gives guest
  event logs a chance to flush; successful flushing remains a live gate.
  The build checks hardware D3D11, presentation and pixel readback, requires
  graceful shutdown, flattens the child and writes the manifest last.
- **Setup assets:** a pinned render probe is required; `RUNNER.ZIP` is the
  only setup asset and is required for every install-media build.
  No legacy agent, helper, display-driver or OpenSSH installer is accepted.
  Bivouac build scripts, helpers, markers and temporary probes live under
  protected `C:\ProgramData\Bivouac\Image`.
  The pinned prebuilt render probe still writes its report to the hard-coded
  `C:\ProgramData\BivouacHcsSpike\render.json`. Validation creates that temporary
  directory with the same protected ACL as `Image\Probe`, refusing an existing
  directory. It moves the ordinary, link-free report (at most 4 KiB) into
  `Image\Probe\render.json` and removes the spike directory. Render-step cleanup
  runs on failure too; sanitation refuses a leftover spike directory. This path
  bridge goes away when the Go render probe replaces the prebuilt executable.
- **Specialize:** before FirstLogon, stop/delete the legacy agent service,
  remove every legacy VDD device (including phantom nodes) and its driver
  package, and delete the entire legacy component directory with bounded
  traversal that refuses links. Uninstall registered OpenSSH MSI products first
  using bounded display-name/product-code lookup and fixed msiexec arguments,
  then stop/delete the leftover sshd service and delete MSI program directories,
  server state, authorization files and the old host-key boot task.
  Every removal has a numbered failure step. Synthetic video enable retains
  the existing identity checks, ConfigFlags handling and numeric diagnostics.
- **FirstLogon:** remove the installed `OpenSSH.Server~~~~0.0.1.0` capability
  through Windows servicing. A requested reboot fails closed for operator review;
  no partially serviced image is published. Verify no sshd service, server
  executable (including the inbox server location), server state or authorization
  remains. Keep the inbox OpenSSH client directory and ssh-agent service intact:
  they supply no listener and are owned by Windows servicing. Preserve specialize
  failures, retry synthetic video problem 22 once and verify component
  removal/video startup. Recover error 43 only
  on `vrd.inf` GPU-PV display devices with a bounded device restart. The
  reference copy path used disable/enable for those devices after an online
  copy; offline placement precedes initial device startup. Its optional GL,
  Vulkan and NVIDIA runtime provisioning is not reproduced by the driver-only
  factory. D3D11 validation does not establish those other APIs.
  Register `bivouac-guest-agent` for the configured user's logon with Interactive,
  Highest, priority 4 (normal), three one-minute failure restarts and no execution
  time limit.
  The action executes the installed binary's `guest-agent --user <user>`
  directly; start the task for the build session. No PowerShell runs in the
  persistent task action.
  Also register `bivouac-guest-runner`, refusing either existing task. Its one
  Exec action is the installed binary's `guest windows detached`, working in
  the guest directory, for the same InteractiveToken/Highest principal. It has
  no triggers, priority 4, PT0S time limit, IgnoreNew, on-demand execution
  enabled, no restart policy and no idle, network or battery conditions.
  Fixed registration XML sets the task DACL to SYSTEM and Administrators full
  control, owner Administrators (a registration that gave Administrators only
  read/execute was refused in a live build). The factory registers it through
  COM with `TASK_DONT_ADD_PRINCIPAL_ACE`: Task Scheduler otherwise adds read
  access for the task's principal, and a task's own user may run a task it can
  read even from a filtered token. Task Scheduler stores the DACL unprotected,
  so it also inherits the root task folder's SYSTEM and Administrators
  entries. The self-test requires explicit SYSTEM and Administrators full
  control and accepts inherited entries for those two only (any access); any
  other principal, explicit or inherited, is refused. The opt-in lab proves
  that a same-account SAFER normal-user token at medium integrity can read the
  agent task but can neither read nor start the runner task, while an
  elevated start is accepted. The agent logon task keeps Task Scheduler's
  default read entry for its principal, so a filtered process of the account
  can start it; that only launches the fixed, administrator-protected agent
  binary, which is normally already running (IgnoreNew), and is accepted. The
  existing guest-directory user full-control ACE remains; narrowing it is
  outside this change.
- **Launch safety:** before writing `launch-mode` or the single-use `launched`
  marker, structurally validate the runner task's bounded XML from
  `schtasks /Query /XML`. Runtime performs no PowerShell or descriptor query.
  Installation self-test verifies the current task-object security descriptor
  at factory preparation and publication. Runtime trusts that published
  descriptor: each clone uses an immutable image with its own differencing
  disk, and only bivouac code runs before start. A runtime trampoline check
  cannot establish who triggered an already elevated task and adds no security.
  Principal names resolve to SIDs;
  extra actions (including non-Exec actions), triggers, restart policies and
  execution constraints refuse launch. No localized output or racy run-state
  precheck is used. Failure returns fixed text without consuming input or
  markers. Missing XML settings use schema defaults where those match the
  required values: on-demand/enabled true, idle/network conditions false,
  IgnoreNew and no restart policy. Priority 4, PT0S and both battery flags
  false must be explicit because their defaults differ. Duplicate or malformed
  explicit settings refuse launch. The claim and existing helper launch-once
  record enforce single use.
  The lab shares this dispatch path and requires the same probe and sleeping
  grandchild to survive both task End/Run and agent kill/Run, each with a fresh
  request/completion ID and a new validated agent identity. Cycles execute in
  the probe itself. SID/elevation/session/desktop predicates and normal
  priorities for probe and grandchild gate the run. Job membership and
  immediate-job agent presence are baseline-only diagnostics (true/false/unknown;
  failed queries and incomplete PID lists are unknown and never end the probe).
  They do not gate survival and are not recomputed against a terminated agent.
  A fixed gate stage identifies progress. Immediate-job absence does not
  establish absence from shared ancestor jobs.
- **Sanitation:** rotate the console password into the LSA autologon secret;
  remove answer/setup residue, temporary probes, disposable Guest state and
  agent logs, launch-mode/claim/cancellation records and lab residue; retain
  both tasks. Refuse sanitation unless the runner task is Ready (never Running,
  Queued or unknown). Agent logs use separate protected
  `C:\ProgramData\Bivouac\Agent` storage with delete-shared files, so sanitation
  can remove build logs without interrupting the command transport. No SSH
  configuration or host-key generation is part of sanitation or runtime boot.
- **Inspection/manifest:** offline inspection refuses an existing agent
  installation, either guest task or Guest directory. Public agent presence/hash/task
  facts replace legacy service and package facts; legacy VDD presence remains
  informational. The manifest records media/asset/output/agent hashes, selected image metadata,
  host DISM/BCDBoot versions, options, verified boot issuer generations,
  apply-time WinRE policy, disk/partition GUIDs and
  effective guest Secure Boot/TPM facts. Publication requires Secure Boot on
  and TPM present (readiness is recorded). It also records agent
  Windows contract, guest identity, driver INF versions, probe/validation/autologon pins
  and bounded topology observations, plus public task facts for both definitions.
  Installation self-test runs at preparation and again before sanitation;
  its fixed `autologon_account_matches` predicate requires the Winlogon account
  SID, runner task principal SID and agent token SID to agree. Publication and
  the VM host's manifest reader require both task proofs and this predicate,
  which the manifest records without account identifiers.
  Per-file staging inventories are build-local
  and excluded from bounded durable records.
- **Single-display invariant:** exactly one attached-to-desktop display must
  be primary. The hash-pinned validation script carries an inline topology
  probe launched by an interactive scheduled task in the console user's
  session, alongside the existing render task. It records active/primary
  counts, primary dimensions, virtual-screen equality, adapter hardware-ID
  classification (1 synthetic, 2 VDD, 3 other/unresolved), all VDD nodes,
  and Hyper-V video enabled/started facts. Classification uses the adapter's
  `DISPLAY_DEVICE.DeviceID`, falling back to the driver key's `MatchingDeviceId`
  only when that ID is empty. A disposable window tests foreground,
  primary work-area containment and receipt of a SendInput key. A bounded
  `windowsdefender:` launch records Windows Security's top-level window and
  primary-display containment, then closes it. No names, IDs, titles or other
  guest text enter the report, which remains bounded to 8 KiB.
  Factory publication requires the single primary to use Hyper-V
  video, no VDD nodes, enabled/started synthetic video, and all existing render
  gates. Every desktop lab run also requires those topology gates and all
  probe-window checks. Windows Security observations are diagnostic only.
- The image's time zone and execution policy are inherited from install media.
- Admission does not yet compare the host GPU driver with the one the image
  was built with; rebuild the image after a host driver update.

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

Both guests launch with their own rootless network stack, no host shares or extra disks,
and audio/clipboard/input sharing disabled. Admission checks local baselines/helpers and rootless policy availability.
Missing prerequisites fail before cloning, and launch failure never falls back
to NAT. No host privilege provisioning is required. Both live helper argument
arrays prove the rootless transport. DHCP supplies filtered virtual DNS through the parent resolver capability;
no guest DNS reconfiguration is performed. The host cache remains disabled for
this optional topology; bootstrap shares remain prohibited.

The VM helper owns the stack and its datagram attachment. Any link/stack failure
ends that helper and VM; there is no privileged external filter to lose or adopt.
The container relay still carries only bounded opaque API streams over VSOCK.

The supervisor verifies the durable record and both markers before connecting,
before every new engine stream, and before stopping anything. It watches
record/VM presence and rootless helper proof, polling once per second with bounded VM-status
calls. Transport loss, engine loss, or failed ownership/transport proof retires
the pair; no reconnect to a personal or replacement daemon is
attempted. Rootless socket admission and per-flow revalidation handle network changes;
the relay does not end healthy jobs merely because interface addresses changed.
Network transition races remain documented above.

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
before hashing and launch, so private VM NIC churn does not change
admission. Every supervisor checks it once per second and retires on a change,
including broader masks and public prefixes; dynamic public-interface
transitions remain a non-atomic live validation gate.
No arbitrary flags, host shares, port publishing or host cache exception exists.

The static Linux helper configures only the disposable clone. An unconfigured
official runner and generic Docker/virtio/CDI runtime come from the immutable
baseline. JIT input arrives over authenticated SSH stdin, is consumed once,
and is never staged on the host. PID/start-time/executable proof protects
listener cancellation. Logs and ZIP diagnostics are bounded and redacted.

Linux readiness fingerprints `/usr/local/libexec/bivouac-guest` without executing
it. A fixed stdin script verifies root ownership, mutation bits and absence of
links on every ancestor and the helper. Only an exact SHA-256 match with the
selected host helper permits reuse; missing, stale or untrusted helpers are
uploaded afresh. A trusted fingerprint mismatch emits a warning. SSH transport
failure refuses readiness. Bootstrap installs one private runtime helper, used
by later operations and adoption without a second listener-start copy.

Public DNS is checked before repair: the persistent eth0 NetworkManager profile,
its live upstream set and the resolver must agree on the two selected public
resolvers. DHCP DNS is ignored for IPv4/IPv6, with no configured IPv6 DNS. A
resolved loopback stub requires verified live public upstreams. Correct state
causes no writes or reapply; each repair is re-read. Images without NetworkManager
require a regular unmanaged resolver file. Native network policy still applies.

Startup observations are bounded numeric durations, stage codes and reuse/change
booleans. Host spans use monotonic clocks; guest systemd activation timestamps are
boot milestones, not host elapsed times or dependency-chain measurements.

The explicit image factory requires a fresh bootstrap bound to the exact guest,
controller, boot and helper hash, before JIT delivery. It refuses enrollment,
nonempty job work, worker logs, links and unknown runner diagnostics. It installs
the protected helper and DNS, removes factory SSH host keys and the random seed
(after stopping seed persistence), and empties machine-id with D-Bus following it.
SSH host keys regenerate before ssh.service on cold boot. Only proven bootstrap
files are removed; public provenance and the designated SSH authorization key
remain. Host private keys and GitHub credentials must never enter the image.

Capture requires acknowledged clean shutdown, natural exit code zero, an empty
recorded native job, current ownership/backing proof and supervisor/VM absence.
Forced stops and ambiguous outcomes refuse capture. A single converter writes
into a fresh external directory whose parent is resolved through the filesystem;
geometry verification and flush precede publication of the provenance manifest.
Partial output is unpublishable; owned source cleanup runs independently of
capture success. This factory IO adds no hashing or conversion to ordinary boot.
Factory/reuse validation discards its sanitized guest; only fresh cold clones
can establish distinct machine and SSH identities. See `docs/crosvm.md` for
commands, resource guards and validation prerequisites.

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

On macOS the service uses literal loopback TLS identity. The provider starts a
fixed guest helper through its owned VSOCK command channel. It opens a bounded
guest-loopback TCP listener, publishes its decimal port, and forwards only to
the synthetic cache endpoint. Payloads traverse virtual Ethernet, the sandboxed
stack's cache-only FD capability, and the private per-VM Unix listener. Neither
guest traffic nor descriptor requests can select host addresses, sockets, paths
or commands. The host terminates TLS in the existing authenticated handler;
each listener admits only its owner's grants/leases. Revocation closes its
control, listener, HTTP requests and hijacked CONNECT tunnels. The six-byte
listener-port handshake is bounded; no guest-controlled handshake text enters
errors. No guest NIC exception or LAN cache listener is needed. The adapter
changes only the disposable clone. A Node preload observes only successful Actions v2 download
lookups and, with upload storage, cache creations. GitHub still handles
authentication, branch/ref matching, cache versions and metadata. Bivouac
stores archives, not a second cache-key database. Each new read validates its fresh signed URL with
an upstream HEAD, including on a local hit; expired or denied capabilities
cannot expose cached bytes. Object identity excludes URL query credentials.
A lease request carries only that URL. HEAD on a lease answers from the
lease's upstream metadata without filling.
The preload retains each rewritten download's original signed URL only in the
Node process, with at most 4096 mappings. When full it leaves new lookups public
instead of discarding an in-flight reader's recovery source. A failed local
request, aborted/failed body or rejected lease switches subsequent SDK retries
to that source, preserving byte ranges. Local rejections remain retryable.
Public retries drop cache authentication, proxy authentication, private-hop CA
and explicit local TLS identity, and use normal origin trust through mandatory
network isolation. No signed URL or mapping is persisted or logged.


A plain GET that starts a fill, of an archive or a release, receives bytes as
they arrive, except the last, which waits until the body ends at the declared
length; ranged and concurrent readers wait for the verified object. Fills
belong to the service: a guest that disconnects leaves its fill running, and a
retry joins it. Shutdown cancels fills and waits for every fill, reader, relay
and commit with store files open. An attempt ends after a minute waiting on upstream, not at a
total deadline; the fill then resumes from its offset with an If-Match range
request, up to three times. Upload relays stream every request body to Azure.

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
DNS admission and normal upstream certificate validation. For macOS, every
resolved address must additionally lie outside the current host/route
policy, and IPv6 is refused. HTTP connection reuse is retained. Each new request checks
the actual connected peer, including a pooled connection, before sending; long
streams/tunnels check the shared policy snapshot on every I/O. Routing changes still have
a non-atomic observation window, including a pending dial. Each guest has at
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
adapter separately returns to upstream when lease creation is unavailable. A
fill that fails before its first byte sends the guest upstream (an archive to
its signed URL, a release forwarded); later, the response ends early, like a
failed direct download.

TLS keys, guest capabilities, and signed URLs exist only in memory on the
host; private bootstrap files exist only in the disposable guest and are
excluded from diagnostics. Capabilities are revoked after confirmed guest
deletion; leases are bounded per guest and expire no later than the upstream
SAS. TLS identities rotate on daemon restart. Existing guests retain their
upstream paths if their old cache endpoint disappears. This accelerates
restores; it does not reduce GitHub cache uploads, storage, or metadata calls.

`cache.store_uploads` (default off) keeps a copy of each Actions save, so the
next restore does not download what was just uploaded. The preload replaces the
creation response's signed upload URL with a host relay URL. The host sends
each Put Blob, Put Block and Put Block List to Azure itself, appending only the
operation's own parameters to the signed query, and stages the bytes it sent.
When Azure accepts the commit, the staged blocks in committed order become the
object that a restore's HEAD identifies by blob path, ETag and size; if Azure
accepts a block list before the host has all of it, nothing is stored. The
host never accepts guest bytes on any other path. A guest holding the signed
URL can still write blocks to Azure directly, so the copy can differ from
Azure's blob, but only for an entry that guest can write, whose readers already
accept its bytes. A guest that can only read an entry cannot place it locally.
Relay requests need the relay ID and the guest's own token: the official action logs
the ID in debug output; the relay ID is not an authorization capability.

Staging counts against cache capacity, evicting idle objects as needed, and an
upload that does not fit is relayed without a copy. Staged files use the fill
prefix, so startup discards them; revocation and shutdown discard them too.
Commits run after the response, belong to the service, which cancels and joins
them, and may finish after the guest exits. A request the relay cannot carry,
an unknown or revoked relay, or a lost host gets a 503 marker or a connection
error. The storage SDK retries both, and the preload sends that upload's retries
straight to Azure, so a relay failure falls back instead of failing the save.
The marker ends the relay and frees its staging at once.

The relay depends on details GitHub and Azure do not document: the
`CreateCacheEntry` field names, the SDK's three upload operations and its
retries on 503. A change there shows as fewer `relayed` saves or more
`fallbacks`, not as failed saves; the validation fixture checks both.

The store and HTTP service use pure Go and portable filesystem/network APIs.

The service owns constant-space numeric request/byte counters for archive
downloads and the release proxy, both per active guest capability and for the
controller session. Hits/misses classify resolved cache GETs; bytes count actual
response-body bytes accepted by the client writer, including partial ranges.
Conditional reads can count as hits with zero body bytes. Bypasses and transfer
failures are separate; failed fills redirected upstream have no observable
fallback body bytes, and a streamed fill that fails counts its delivered bytes
as a failed miss. HEAD, cache-service metadata and opaque tunnels are
excluded, and concurrent coalesced reads count as hits. Proxy bypass totals
include uncached forwarded GETs, not only release assets. These are delivered
bytes, not unique stored bytes, total upstream traffic or a bandwidth benchmark.
Upload storage counts saves relayed, stored (with bytes), skipped (carried or
refused without a complete copy) and sent back to direct upload (`fallbacks`);
none count as restore hits.

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
summary reads accept the bootstrap's literal loopback IP,
verify TLS and grant authorization, refuse redirects and never use ambient
proxy settings. This works with Actions caching alone or the optional release
proxy. The existing controller-session counters already serve both transports.

Transparent Actions v2 restores and public GitHub release caching are required
for Windows host parity with macOS, including its Windows and Linux guests.
Provider adapters own guest delivery, trust installation, network reachability,
and native launch setup; implementation alone is not live validation.

Windows-hosted providers use a guest-loopback listener: HCS exports it through
the bivouac agent Duplex/engine relay, while Crosvm retains its existing SSH
transport and pinned host key. The host terminates TLS and serves only the cache
HTTP handler through these streams; it never relays arbitrary guest connections
to host TCP sockets. Each provider repeats current admission proof before cache
setup or JIT. HCS
checks ownership and running state (quarantine reports stopped); its VM host
verifies the deny layer during create and reproves it every 10 s, without a
new synchronous policy check.
No NIC allow rule, host trust change, host directory share, external service or
automatic privileged startup is needed. Host cache configuration is restricted
to literal IPv4 loopback. Each grant records its guest endpoint so archive leases
remain reachable through the same transport. TLS identity and capabilities stay
in memory on the host; bootstrap reaches only the disposable guest over stdin.

The shared Node preload is used by every guest adapter. Windows installs temporary
machine root trust inside the clone and exports its logical root collection
for OpenSSL clients. Guest administrator access avoids the interactive protected
CurrentUser root-store consent that fails over SSH. Proxy leaf certificates name
the granting guest's cache endpoint for a signed revocation list, so Schannel
keeps its default revocation checks. The fixed `/ca.crl` GET/HEAD endpoint serves
only public PKI bytes, renews before expiration and contains no capability or
archive data. It uses the same cache transport and opens no additional listener.
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
  The macOS launch log is the exception: the VM helper writes
  host-side status there through an inherited descriptor, neither redacted
  nor bounded, because the helper must outlive the daemon. The guest console
  is never attached, so no guest output reaches it.
- Ordinary macOS runners may explicitly opt into read-only bootstrap shares; container pairs prohibit host shares.
  Host credentials never enter a guest.
- With `cache.store_uploads`, a guest's signed upload URLs reach host memory
  and the host forwards its saves; it stores only what it sent and Azure
  committed, and needs the guest's token on every relay request.
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
- Actions saves are kept by relaying them (`store_uploads`). Reading each
  archive back after the save doubled the transfer and gave up on slow links;
  a copy sent by the guest could differ from what it uploaded. GitHub remains
  the authority for every entry; local copies only avoid a download.
- Deferred: localhost management HTTP API and UI, Linux host provider,
  reducing GitHub-side Actions cache storage.
