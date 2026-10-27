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
internal/linuxguest  transport-neutral Linux runner runtime, execution profiles and image sanitation
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
internal/winguest    prepared Windows guest client: App Sandbox guest agent setup, SSH over HvSocket
internal/winrunner   Windows guest runner adapter (`guest windows`) and its fixed control scripts
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
- A record whose retained clone contract or status cannot be proven (unreadable
  manifest, changed guest OS, not owned, corrupt, or no answer within the deadline)
  keeps its record, reservation, and guest, gets a recorded error, and waits for
  a later start. The rest continue.
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
The VM helper supplies these fixed host capability paths for either guest OS;
without an attached per-VM listener they fail closed. Linux guest cache setup
remains a separate adapter step. TLS, upstream restrictions, expiry and revocation
stay mandatory. CRLs use only
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
container pairs prohibit shares. Launch device selection uses the clone manifest:
Darwin keeps input devices; Linux has none. Typed machine options remain.

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

- Host runtime check: daemon startup checks socket-path capacity, the signed
  host executable, rootless host policy and requested nested-virtualization
  support before reconciliation. It never opens a baseline or Linux guest helper.
  Missing, changed or invalid admission inputs block only new instances, leaving
  retained-clone inventory, runner adoption and ownership-checked cleanup usable.
- Baseline admission: Create, container preflight and `doctor` refuse a baseline
  without a manifest, of the wrong guest OS, without a runner directory
  (either runner OS), or whose agent protocol differs from this binary's.
  Linux engine images still need no runner directory. Linux runner helper
  admission validates a static ARM64 ELF executable. Provider construction
  receives `vz.guest_os` (`darwin` by default, or `linux`) and `vz.helper` for
  Linux. Linux requires explicit CPU/memory and prohibits Darwin display/share/
  slot options and companion engines; its baseline still must be supplied.
  Guest-root provisioning uses a Go recipe registry, currently Ubuntu 24.04
  ARM64/VZ only; the future baseline builder will reuse it unchanged. An omitted
  Linux baseline will later resolve once during configuration preparation to a
  bivouac-built recipe image; admission and instance specs consume that name.
- Clone: `clonefile` of disk and NVRAM under a hidden staging name, a
  manifest with a fresh locally administered MAC and the configured CPU and
  memory (at least the manifest's minimums), then a rename into place
  (milliseconds). Then `bivouac.json` with exact provider, controller and
  instance IDs. Ownership requires the matching provider-name prefix and marker;
  another provider's clones remain foreign. Linux clones consume no Apple
  macOS slot only when their validated manifests prove Linux. Unknown/corrupt
  manifests count conservatively. Reconciliation validates retained clone OS
  before provider operations; replacing the baseline cannot change that OS.
- Run: `bivouac vm run --dir <vm> --agent-port <port> --agent-socket <path>
  [--input] --rootless-network [--display WxH[@PPI]]
  [--disk-sync full|fsync|none]`, from the executable signed with
  `com.apple.security.virtualization`. The helper builds the VM with purego
  bindings to Virtualization.framework (graphics device, virtio disk,
  rootless network for managed guests, entropy, balloon, vsock; keyboard and
  pointer for Darwin runner guests; no console, audio, or clipboard). It holds an fcntl lock on the
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
  once. Guest preparation selects from the clone's manifest, independently of
  the current baseline. Darwin copies its bootstrap to `/tmp/bivouac-guest` and
  requires its `session` mode to report `Aqua`. Linux checks `Linux/aarch64` and
  a non-root agent, then verifies the prepared root-owned helper's SHA-256 before
  executing it. There is no Linux-on-vz upload fallback: a mismatch requires a
  rebuilt baseline. Preparation uses `linuxguest.VZ`, preserving DHCP DNS.
  JIT/status/cancel/diagnostics use the shared runtime over the guest agent, with
  fresh durable ownership and live rootless proof before each operation.
  Adoption uses the clone and installed runtime helper, without reopening the
  baseline or host helper. VM status/stop/delete remain generic.
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
  nesting only to Linux guests (runners or engine VMs, giving their containers
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
The first increment changes only the host: guests still boot an image that
contains App Sandbox's guest agent and display driver. A later increment
replaces them with a bivouac guest agent over HvSocket, along with OpenSSH and
the PowerShell boot steps they need.

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
- **Guest sessions:** each session generates an in-memory SSH identity and
  deploys it through the image's guest agent, whose connection stays open.
  It then authenticates SSH over HvSocket.
  - The guest's host key fingerprint is public, and is pinned beside
    manager state. A manager that reconnects, for example after a restart,
    refuses a different key.
  - A transport failure drops the session, and the next probe reconnects.
    These failures are retryable for the manager's bounded grace;
    authentication and host-key failures are terminal.
- **Readiness** delivers files by scp to fixed names: first the shared
  winrunner preflight, then its control script, the configuration and this
  executable as the guest adapter. Runner status and diagnostics call the
  adapter directly, without PowerShell, because status runs every few
  seconds.
- **JIT** bytes travel only on SSH stdin.
- **Network:** every create asks for an isolated endpoint. The lease (address,
  gateway, prefix and MAC) goes to the guest in its runner configuration.
  WaitReady still refuses a guest without a lease, because its runner could
  not reach GitHub.
- **Cache:** after readiness and before JIT delivery, a dedicated SSH client
  authenticates over HvSocket with the command session's in-memory identity and
  host-key pin. It serves the shared cache handler through a guest-loopback
  listener without using the guest NIC or relaxing HCN/VFP isolation. Cache
  revocation and command cancellation close independent clients. Setup uses
  the shared Windows adapter with the bootstrap on stdin, cleared after use.
  Failed setup revokes the grant and removes partial guest settings before
  upstream fallback; uncertain cleanup refuses JIT. Confirmed deletion or
  absence revokes the grant, and provider Close closes its cache transports.
  Transport loss uses upstream fallback without reattachment.

The official runner starts once through an interactive scheduled task, with
rebuilt machine/user PATH and a default-input-desktop probe. The guest adapter
records listener PID, executable and process creation time; cancellation
rechecks that identity before signaling its console. Stop requests official
runner shutdown, which reports a failed job without calling GitHub's workflow
cancellation API. Off lets accepted work finish normally. A baseline may contain
an unconfigured runner, or each clone receives a hash-pinned official runner ZIP.
Diagnostics use bounded base64 and ZIP extraction that rejects unsafe paths and
expansion before redacting host sinks. No host directory is mounted.

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
the template's time zone and RTC handling, so the provider's `WaitReady` sets the
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
`bivouac image`) from a generalized App Sandbox template and published as a
single standalone VHDX. At runtime they are pinned by file identity, protected
ACL and deny-write handles, not hashed per job.

- **Template safety:** the source template is immutable; the factory only reads
  it. It copies the template into its own protected
  workspace, hashing as it copies, and builds on a differencing child of the
  copy. Mounts, VM access grants and the boot touch only files the build
  created.
- **Inspection gate:** before anything boots, an offline inspection of the
  child must show a template generalized to OOBE with no answer-file pointer,
  no configured runner and no bivouac job state. Its facts are public and
  recorded; answer-file values and file contents are never read into them.
- **Build:** one elevated foreground process boots the child with GPU-PV and
  no NIC. Windows setup runs from a generated answer file and setup media
  with pinned App Sandbox components. The guest agent copies the host's GPU
  driver into the image, so runtime guests decline driver copies. The build
  checks hardware rendering, sanitizes (no registration, setup files or
  authorized keys; a fresh random console password held only as the LSA
  autologon secret; fresh SSH host keys on each guest's boot) and requires a
  graceful exit. It then flattens child and copy into the output and writes
  the manifest last.
- **Manifest:** source, asset and output hashes, the guest identity the
  provider needs, the host GPU driver versions the image was built with, and
  the lab batch's probe, validation and autologon pins.
- The image's guest content matches the spike-built image's, so the
  provider and the lab batch accept either. It still holds App Sandbox's
  guest agent, OpenSSH and the PowerShell boot task, and its time zone and
  execution policy are the template's.
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

### Shared Linux guest runtime

`internal/linuxguest` owns Linux operation dispatch, runner preparation, JIT,
listener/status/cancel/diagnostics, cache integration, helper fingerprinting and
image sanitation. Providers own transport and VM lifetime; Crosvm keeps SSH and
its upload fallback. The CLI dispatches `guest linux` directly to this package.

A required execution profile travels in bounded preparation stdin and is saved
with the per-boot identity. Every subsequent command validates that record.
Image preparation must match the saved profile; its bounded receipt and public
root-owned provenance record carry the same profile. A reused prepared helper
checks that provenance before creating bootstrap state. Unknown, missing or
mismatched profiles fail closed. Producers and consumers change together; old
helpers fail the selected helper hash and use Crosvm's existing upload fallback.

`crosvm-public-dns-ssh` preserves fixed public resolvers on `eth0`, exact
persistent/active/resolver checks, public-DNS reuse reports, GPU/CDI checks and
SSH host-key regeneration units. `vz-dhcp` delegates DNS to the virtual DHCP
lease without editing guest network profiles or resolver files, and installs
no SSH units or SSH host-key sanitation. Its `dns_dhcp` observation records
that delegation, not proof of public-DNS reuse or live virtual DNS reachability;
`dns_reused` and `dns_prepared` remain false. Machine identity and random seed
sanitation are shared. Runtime and prepared helper paths stay unchanged.
The vz Linux adapter uses this profile over the guest agent. JIT is bounded to
128 KiB, status to 4 KiB, and diagnostic ZIP streams to 32 MiB compressed;
extraction uses the shared path-checked, redacting sink. Linux runners are
headless, advertise no GPU/desktop, and require `/opt/actions-runner`. Crosvm's
SSH runtime, profile and fallback remain unchanged.

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

Darwin and Linux-on-vz share the same endpoint/listener/grant/CRL transport.
Linux starts the endpoint with its already pinned runtime helper and sends
bootstrap over the guest agent to `linuxguest` cache setup. The shared guest
adapter owns preload/proxy/CA environment and listener lifetime. Without the
manifest's sudo contract, both guest OSes receive archive-only grants and the
host rejects their release-proxy requests. Each grant records
its release authority at issuance, bounded by `cache.release_proxy`; bootstrap
reflects that authority. Enabling the service feature cannot upgrade an issued
archive-only grant. Archive caching remains available. Darwin skips Keychain
setup and removes stale proxy files. Setup failure synchronously revokes the grant, then requires
successful fixed-helper removal before JIT fallback. Failed removal refuses
launch. Confirmed deletion/absence revokes; uncertain deletion retains the grant.
Service/controller loss closes transport and leaves public fallback through
mandatory isolation. Virtual CRL traffic bypasses guest proxy payload slots.
No second Linux helper is uploaded.

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

Windows-hosted providers use a guest-loopback listener on the existing owned SSH
transport. The host terminates TLS and serves only the cache HTTP handler through
SSH channels; it does not relay arbitrary guest connections to host TCP sockets.
The SSH host key must already be pinned by normal guest preparation, and the
provider repeats its current admission proof before cache setup or JIT. HCS
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
