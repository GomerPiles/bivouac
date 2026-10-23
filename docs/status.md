# Status

Bivouac runs real CI for a downstream project on a macOS host and a
Windows host (HCS Windows guests and Crosvm Linux GPU guests). This
page records what is validated live, what only tests cover, and the open
gates. No provider is ready for untrusted (for example fork) pull requests.
Rootless macOS networking has disposable-guest evidence below; the complete
production migration gates remain open.

The HCS provider, image factory and vmhost lab use bivouac's guest agent over
HvSocket. The Windows adapter has unit coverage for preflight, preparation,
start/stop, clock setting, bounded delivery/extraction and the 64-connection
cache relay. These agent-runtime source changes are not deployed or validated
live; rollback uses the previous manager, VM host service and image together.
Console/OOBE readiness remains a live gate for the agent-served guest.
In-process listener re-listening and bounded consecutive session refusals have unit coverage only.
MSI-before-leftover uninstall and OpenSSH server-capability removal, preserving the inbox client and ssh-agent, have unit coverage only.
Recovery after an actual agent crash remains unverified.
ISO-based agent lab images reach completed setup and topology validation, but
render-probe validation times out; a successful factory build and agent-image
timing run remain open gates.

Windows contract 2 requires the agent logon task and separate on-demand runner
task. Installation self-test checks both task definitions and the runner's
current security descriptor at preparation and publication. Installation and
manifest admission also require a fixed autologon-account/runner-principal/
agent-token SID equality predicate. Runtime start checks
structural task XML only; the trampoline checks native context without task
queries. Tests cover schema defaults, task-query failure facts, mode-before-marker
ordering, claims, injected context refusals, helper hard-link/junction refusal,
stop during a locked start, and both listener/cancellation interleavings.
The listener checks cancellation before creation and after identity publication.
Factory registration, sanitation and manifest admission have unit coverage.

The opt-in vmhost lab gates on loopback refusal, both-task installation facts,
probe SID/elevation/console/desktop context, normal probe/grandchild priority,
a same-account SAFER normal-user token reading the agent task but refused
reading or starting the runner task (elevated start accepted), the same probe
and grandchild surviving both restart paths, and new agent identities. Cycles
run inside the probe with matching fresh request/completion IDs. Job
membership is baseline-only diagnostic data; failed queries report unknown.
These gates passed live on a contract-2 image built from install media with
the factory changes stacked on this branch.

Still unverified live: refusal for the real UAC-filtered token (the lab uses a
SAFER token with no more access), premature/duplicate activation, cancellation during startup (helper console attach), console
visibility/focus, scheduler latency, environment/session selection, task End
descendant behavior and restart-on-failure with a surviving child. Native
networking, UTC correction, cancellation/result reporting and cache behavior on
agent-served guests also remain live gates. Sibling-guest negative testing is
outside this phase's loopback and host-account authorization scope.
The accepted double Ctrl+C when stop and the helper both signal still needs live validation.

The factory's pinned prebuilt render-probe output-path bridge has script/fixture
coverage only. Fresh-image render validation and sanitation remain live gates.

## Checks

Local Windows checks cover `gofmt`, `go vet ./...`, `golangci-lint`,
`go build ./...`, `go test -race ./...`, cgo-disabled builds for macOS
arm64/amd64, Windows amd64 and Linux amd64, and PowerShell 5.1/7 parsing.
HCS/vmhost also pass vet with the `integration` tag; this does not run their
opt-in live labs. The guest-agent, runner-task and install-media image changes
were checked without `-race` (no cgo on that host); hosted CI runs the rest.
Local macOS rootless checks pass `gofmt`, normal/integration `go vet`,
`golangci-lint`, full race tests, a host build, and Windows
amd64/Linux arm64 cross-builds. Hosted CI checks each PR revision on macOS,
Ubuntu and Windows.
Unit tests and cross-builds do not establish live provider behavior.

## macOS

Managed macOS networking uses gVisor in a credential-free Seatbelt child, with
fail-closed ownership/readiness/adoption proof and no NAT fallback. Socket
admission denies private, special, host and explicitly routed local IPv4;
IPv6, fragments and ICMP are unsupported. Ordinary read-only bootstrap shares
are opt-in; container pairs prohibit them. Defaults: 4096 general flows, 24 h
TCP and 60 s UDP idle (15 min after half-close), 256 cache connections,
`memory_mb = 1024` (128 KiB TCP buffers per direction) and MTU 16384.

Validated in disposable guests:

- DHCP MTU adoption at 1500, 9000, 16384 and 65535 with no queue drops; 16384
  gave the most consistent local raw TCP (about 1.7× MTU 1500, single runs).
- Host-resolver DNS: A, empty AAAA, TXT and NXDOMAIN.
- Public forwarding and download, owned-host-listener denial, cold/warm cache,
  cache-outage fallback and network-child loss retiring the VM.
- Flow ceiling: excess connects are refused and counted as `flow_limit` while
  reserved DNS keeps answering. A freshly booted guest holds about 130–160
  flows of its own, so ceilings far below that fail from background traffic.
- On the previous rootless revision, not repeated since: host/metadata/IPv6
  denials, Aqua/AppKit input, Metal readback, cache saturation and fresh-state
  cleanup.

Real scale-set jobs on an isolated home and test scale set passed on this
code, one guest at a time: a downstream project's macOS jobs, controller
SIGKILL with adoption of the live guest, and every cache fixture mode except
soak (save, restore, mixed, outage, interrupt, oversize and caching
disabled). Saves relayed and stored with no fallbacks, restores hit locally,
and stopping the controller mid-transfer let jobs finish directly.

Covered by tests only: TCP half-close, counter logging, refusal counters and
gauges, parent-brokered DNS envelope/filtering, limit and MTU plumbing. Native
Seatbelt tests deny loopback and bound host interfaces with positive controls;
hosted macOS CI shows denial of loopback and non-loopback aliases added before
or after sandbox activation.

Known limits: DNS uses primary `/etc/resolv.conf` resolvers or overrides, not
scoped macOS DNS, and guests can see internal DNS metadata through them, with
bounded but unrated query concurrency. Large guest UDP datagrams may fragment on
the real path without ICMP feedback. Public NAT/tunnel endpoints and the
non-atomic 250 ms route observation window remain admission limitations.
Seatbelt APIs are deprecated: repeat sandbox and guest gates after macOS upgrades.

Open: cache and idle limits under sustained load, ICMP, compositor
presentation/capture, host hardware input, owner-controlled private and
routed-public peers, Docker pulls and live container pairs (engine members
stay at MTU 1500 until their adoption is validated). No untrusted-workload
readiness or production migration is claimed. Production observations below
describe the earlier NAT/cache transport.

Bivouac runs macOS guests itself (Virtualization.framework through
purego, its own guest agent). Production runs on this runtime from an
imported baseline with the guest agent, with the release proxy and upload
storage on. Validated on this runtime with real scale-set jobs:

- Jobs run in the Aqua session of a fresh guest (sentinel check), back to
  back, through assigned-job and sweep runners.
- Release-proxy cache cold and warm, with guest resource and cache summaries
  in the job log; diagnostics with `_diag` and the performance report; no credential patterns in state, logs, or diagnostics.
- Drain, stop, and off mid-job; controller SIGKILL with adoption of the live
  guest; guest loss (helper killed), whose runner cleanup retried until
  GitHub released the busy runner.
- The real-guest integration test (helper arguments, VM lock, cleanup
  refusing the baseline).
- Scale set label arrays: github.com kept extra labels (including
  `self-hosted`) set at creation and assigned matching array jobs to the
  session; verified with a session probe, not a guest.
- Timings: clone 1–6 ms, boot to guest agent 22–31 s, JIT to listening
  5–10 s, teardown 1.3–1.8 s (power-off).

Passed on the earlier Tart CLI runtime but not yet repeated on this one:
the REST JIT fallback (idle pool of one), off/on with queued work, and retained
cleanup across restart. Compositor presentation/capture and host-to-guest
hardware input remain unverified; current AppKit focus/input and Metal readback
evidence is described above.

Tests only: the `vz` provider name and bivouac's own VM store with hashed
agent socket paths; VM manifests, `vz import`, baseline rejection, and the
machine options (validated by the framework in the signed CI test; nested
virtualization is validated only on a host that supports it, and none has
run it yet); a guest agent of another protocol version fails readiness at
once; the daemon refuses to start from an executable without the
virtualization entitlement; macOS CI signs a test binary and has the
framework validate every helper device combination (skipped where the host
cannot virtualize).

The guest LaunchAgent uses `ProcessType=Interactive`. Six interleaved cold-boot
pairs on one host/image (2 CPUs/4 GiB, host disk caches retained) measured median
boot-to-Aqua/script readiness of 26.47 s versus 44.16 s with the default class.
Two fresh guests also passed registered ephemeral-runner smoke checks for Aqua,
fresh state, child execution, exit propagation, file I/O, listener survival
across an agent restart, and numeric start/completion telemetry. These checks do
not establish full workload performance or an end-to-end runner speedup.

Tests cover a single shared helper upload, partial-copy cleanup, cache failure
fallback, container-pair helper preservation, and provider-independent manager
JIT/listener stage logging. The simplified upload path has not been benchmarked
on live guests. The startup changes are deployed to the installed controller;
the LaunchAgent policy is not in the source baseline.

Open:

- Rootless container-pair networking and privileged-container behavior on
  this runtime.
- Host reboot persistence of drain, stop, and off.
- Repository-scoped registration, custom runner groups, GHES, pools larger
  than one, multiple providers, and simultaneous failures.
- Docker/Podman engine companions are implemented but not validated: they
  need a Linux baseline with the guest agent, public-only network checks
  from guests and privileged containers, and crash/loss/accounting tests.
- Production cutover from Tartelet.

Linux ARM64 runner guests on vz use rootless networking, non-root agent checks,
pinned prepared helpers, the VZ DHCP runtime profile and the host cache.
Validated live on Apple Silicon:

- The Go recipe provisioned an official Ubuntu 24.04 ARM64 cloud image (NoCloud
  seed); the image imported and passed `doctor`.
- The opt-in fixture passed on two cold clones: distinct machine IDs, prepared
  provenance, rootless proof, DHCP virtual DNS, public HTTPS, host-listener
  denial with positive controls, Docker pulls, cache endpoint/CRL, outage
  fallback and cleanup.
- A downstream project's arm64 suite passed under the scale set. A following
  job saw no guest or container state from the previous one. `actions/cache`
  restores went through the host cache: cold miss, then a warm hit.
- After SIGKILL of the controller mid-job, the restart adopted the running guest;
  the job and the next one completed.

Those runs predate per-grant release authority and the cloud-init preflight,
which have offline coverage only. Release-proxy trust with guest sudo, Linux
and Darwin providers under one controller, network changes during a job, and
private-peer probes remain open. The Linux-only provisioning and runtime tests
run in hosted Ubuntu CI, not in local macOS checks. The default-baseline
builder and deny-list consolidation are follow-ups.

## Shared Linux runtime

The transport-neutral `internal/linuxguest` runtime supplies explicit Crosvm
public-DNS/SSH and VZ DHCP profiles. Contract tests cover profile binding, DNS
reports, helper pins and sanitation receipts. Crosvm has no new live evidence
after the extraction.

## Windows host controls

Native process tests reproduce a hidden portable-launch child being killed
when its enclosing Windows job closes. The portable launcher now refuses a new
manager from such a job before mutating mode or control records; its context
guard is exercised in an isolated job using stock Windows PowerShell. This
launcher change is not deployed to the installed controller.

The limited login task registered and ran on demand in live validation.
Real-logon and reboot behavior remain unverified. Native credential-store
round trips are opt-in and are not part of ordinary local tests.

## Windows: direct HCS (Windows guests)

The guest bootstrap used to discard a pinned script's nonzero exit code, so a
validation step failure surfaced as an empty, invalid topology report.
PowerShell 5.1 tests reproduce that and cover the fix, which propagates script
exit codes. Agent-backed lab validation now exposes the render wait failure
as step 16 rather than an invalid topology report.

Agent-backed no-NIC ISO lab images complete setup, reach a stable desktop and
pass the topology probe, but the render probe produces no report within the
previous 50-second wait (step 16). Offline evidence shows the GPU-PV and
synthetic display devices started without a reported GPU problem; it does not
identify where the prebuilt render probe stalls. First-boot validation now
allows 180 seconds, emits bounded numeric failure facts and attempts bounded
graceful shutdown before termination to preserve event logs. These changes
have local tests only; render completion, failure observations and event-log
flushing still need a separately authorized live build.

The runtime and factory agent switch is code-complete with fake-agent, offline-copy and relay tests;
live validation is pending a matching image. Tests cover exact receive metadata,
readiness ordering, command/output bounds, terminal protocol refusal, transient
recovery, adoption without pins, unchanged status/diagnostics decoding, TLS cache
requests, fallback cleanup and revocation. The historical live results below
describe the previous App Sandbox/SSH runtime, not validation of this switch.

Startup timing records and the network lab's matching per-run readiness report
have fake-host/transport unit coverage, including partial failures, numeric-only
spans, clock skew and first-observed listening. They have not been collected
from live guests; interleaved baseline distributions remain an operator gate.

The pieces built so far:

- The typed HCS binding.
- The cancellable HvSocket dialer.
- The VM host core.
- The prepared-guest client.

They passed one lab batch while production CI kept running. That was five cold
boots, with no network adapter, from a prepared image that still contains App
Sandbox's guest components. Every guest:

- Was created, started and given GPU-PV.
- Initialized the guest agent and authenticated SSH over HvSocket.
- Rendered hardware D3D11 and passed the presentation and pixel checks.
- Rotated its credential and presented its own SSH host key.
- Was terminated, confirmed absent and removed.

The same batch showed:

- An unelevated process reached the HvSocket service its account was granted
  and was refused access to the other one.
- Lazily committed memory boots and renders with GPU-PV and commits only about
  0.1 GiB at start. Its steady-state saving was not measured, because
  production CI was active during that run.
- A flattened single-file image (18.9 GB, written in 7 s) boots the same way.

| Spans (host clock) | 2 CPU, 4 GiB | 4 CPU, 8 GiB |
| --- | --- | --- |
| Disk, create, start, GPU | 0.4-1.0 s | 0.6 s |
| Agent reachable | 25.4-26.3 s | 15.2-15.3 s |
| Validated desktop | 37.4-39.0 s | 27.2-27.3 s |
| Teardown to confirmed absence | 0.2-0.4 s | 0.3 s |

With 4 CPUs, the image's PowerShell boot task runs its first statement at
5.6-5.8 s guest uptime instead of 21.3-21.7 s. The earlier gap of about 18.6 s
was therefore CPU contention during boot, not a fixed wait. In that earlier
window, the task's SSH host-key generation takes 5.6-5.8 s instead of
0.6-1.7 s.

Desktop validation takes about 11 s. Its own console, GPU and render waits
account for about 5 s of that; the rest is PowerShell work in the image.

Built since, covered by tests only: the VM host's authorized pipe API, the
optional service and its install and control commands, and the `hcs` provider.
The previous provider adopted guests by label, pinned host keys, reconnected after
transport loss and delivered files by scp. A real named-pipe
test covers caller identification, refusal of anonymous callers and refusal
of an unprivileged server; the service has since run live (below).

Guest networking passed lab batch 2 (`TestLabNetworkBatch`) with Windows CI
Off. It ran two networked production-sized cold boots (4 CPU, 8 GiB, GPU)
through an in-process foreground VM host and the `hcs` provider. Every run:

- Was created and started with its switch, endpoint and deny layer in 4.5-5.1 s.
- Passed WaitReady, which applied the lease and proved the console and default
  desktop, 28-29 s after create.
- Reached public DNS, HTTPS, TCP and UDP DNS.
- Timed out on the gateway's DNS proxy and on host listeners at the gateway,
  the LAN source address and the switch adapter's IPv6 link-local address.
  Public IPv6 was unreachable. Each listener was reachable from the host and
  saw no other connection.
- Was still running after two guard passes, so its layer survived boot,
  readiness and the probes.
- Was deleted in 1.3 s, with the switch adapter gone.

| Spans (host clock) | Run 1 | Run 2 |
| --- | --- | --- |
| Switch and endpoint | 0.57 s | 0.71 s |
| HCS create | 0.55 s | 0.29 s |
| Start | 0.58 s | 0.40 s |
| Deny layer after start | 0.97 s | 0.92 s |

In both runs the switch port appeared only at start, so the layer was
installed about 1 s after the guest began running, not before its first
instruction. Design accepts that window because nothing untrusted reaches the
guest before the layer is verified.

An earlier attempt passed the same network checks but could not delete the
network: hostnet waited for the stopped guest's port to vanish, which it does
not do until its endpoint is deleted. After the fix, Recover settled that
leftover in 0.85 s.

A failed start is cleaned up (lab batch `failed-start`, no network or GPU).
A second disk whose file does not exist made HCS refuse start with HRESULT
0x80070002. Afterwards the creating handle's properties reported the owner
mismatched, system type `Container` and no runtime ID, so they no longer proved
the guest. Create closed that handle, confirmed absence and removed the
journal and storage. Excess vCPUs are not a start
failure: HCS refuses them at create.

The VM host service runs live. It was installed elevated from a protected
directory with one UAC prompt and no reboot. The ordinary account then
started and stopped it with the installer's rights (about 0.3 s each), and
the pipe answered about 20 ms after start with an empty journal. The client
trusts the pipe by its owner because an unelevated client cannot open a
SYSTEM service's process token. The installed service predates the explicit
`O:BA` owner and serves with its default owner, which is also
Administrators. A foreground `vmhost run` with the explicit owner has not run
live. Called directly, the provider's
`Activate` started the stopped service and saw it serve in 0.27 s, and
`Deactivate` found no guests and stopped it in 0.25 s. Both were no-ops when
repeated.

GitHub jobs ran end to end on HCS guests, with production CI Off. An
isolated home used REST JIT demand, its own `bivouac-` label and one 4 CPU,
8 GiB GPU guest, and drove the installed service from a live daemon:

- `bivouac on` started the stopped service and filled the pool. A guest was
  listening 47-51 s after create (clone 5-7 s, boot 28-30 s, JIT
  registration and listener 12-15 s).
- Two jobs passed on two different guests. Hooks ran, checkout worked, the
  host GPU appeared through GPU-PV, `api.github.com` answered, and the second
  job found no trace of the first. Each finished guest was deregistered and
  deleted in about 2 s, and a replacement was listening within a minute.
- `bivouac off --wait` deregistered and deleted the idle guest, stopped the
  service and exited in 5-14 s. The guest's switch adapter was gone, and every
  runner was deregistered.
- The first attempts found two guest problems, both fixed:
  - The guest clock ran an hour ahead, so GitHub refused the runner's token.
    The image reads its RTC (host local time) in its own time zone, and no
    time-sync channel corrects it. WaitReady now sets the clock from the host.
  - The image's default execution policy refused the runner's hook and step
    scripts. The runner now gets a process-scope RemoteSigned policy on such
    a guest.

The previously validated HCS guests used the host cache through a dedicated authenticated HvSocket SSH
client. The adapter sets up before JIT, removes partial settings before any
fallback, refuses the launch when that removal is uncertain, and revokes on
confirmed deletion, confirmed absence or provider shutdown. It passed the
cache validation fixture live with production's Windows cache settings
(release proxy, no upload storage), each run on a fresh guest:

- `save`: two concurrent archive saves passed upstream, and the release
  proxy served its second download from the first.
- First `restore`: both archives (216 MiB) filled from upstream, and the
  release downloads hit the cache the previous guest filled.
- Second `restore`: both archives and both releases hit locally, with no
  misses or failures.

Loss fallback, `outage`, `interrupt` and upload storage have not run on HCS
guests.

The earlier, replaced copy-based image factory built an image from an App Sandbox template.
The following measurements describe that earlier pipeline, not ISO builds.
`image inspect` first copied the 29.5 GB template in 20 s and found it
generalized to OOBE. The only runner residue was one log from template
preparation in `_diag`, which that earlier setup removed. The build took 3 minutes:

- 20 s copying the template;
- 1 min 47 s from boot to a validated desktop with hardware D3D11;
- 19 s clean shutdown;
- 25 s flattening and hashing.

The template was only read. The installed VM host service then ran the new
binary and served the new image at production limits (1 guest, 10 CPU,
9216 MiB). The isolated JIT home repeated the end-to-end and cache checks with
production CI Off, on three jobs, each on a fresh guest:

- Guests booted in 21.5-24.3 s (28-30 s on the spike's image) and listened
  37-40 s after create.
- Every job saw the AMD GPU through GPU-PV and reached `api.github.com`.
- `save`, `restore`, `restore` passed as before. The first restore filled both
  archives (216 MiB) upstream; the second hit both locally, and every release
  download hit.
- `bivouac off --wait` exited in 11 s, with the service stopped, no guest
  adapter left and every runner deregistered.

Production Windows CI now runs on the `hcs` provider: the same scale set,
labels and size (10 CPU, 9 GiB, GPU), with Linux unchanged on crosvm. CI On
started the VM host service. The first real Windows job ran beside a Linux
job and succeeded: listening 46 s after create (clone 7 s, boot 21 s, JIT
registration 7 s), teardown 1.8 s, runner deregistered.

Open:

- `Deactivate` refusing to stop a VM host that holds guests (unit-tested
  only).
- A foreground `vmhost run` with the explicit pipe owner. (The installed
  service's binary was updated in place while stopped, with no reinstall.)
- Isolation controls that batch 2 did not cover:
  - A control with the deny layer removed. Without it, a refused host
    listener does not rule out the host firewall; the gateway's DNS proxy is
    the stronger evidence.
  - An owner-controlled private peer.
  - Guest source-address and MAC changes.
  - Host interface changes while a guest runs.
- Longer and heavier jobs over time, and recovery after a daemon or host
  restart with HCS guests.
- Install-media factory paths not yet live: owned VHDX identity, partition/apply,
  BCDBoot/firmware trust, no-NIC setup, guest Secure Boot/TPM, a failed build's
  cleanup and `image cleanup`, and the lab batch on a factory-built
  image. Admission does not compare the host GPU driver with the image's.
- The warm spare.
- Agent images built by this branch contain no legacy guest components and have
  not been built or validated live. Offline ownership/ACLs, specialize service/MSI
  removal, logon task/session readiness, error-43 recovery, sanitation and the
  lab's granted/ungranted agent checks remain live gates. The provider in this branch does not run images built
  before it; rollback uses the previous manager/service/image trio.

## Windows: Crosvm (Linux GPU guests)

The pinned Crosvm runtime predates the `192.88.99.0/24` RESERVED entry;
enforcement is unaffected because the provider supplies it in the host-prefix
inventory. Rebuild at the next runtime pin.

Validated live:

- The manager runs unprivileged once WHPX is available. A patched runtime
  admits only public IPv4 before libslirp opens host sockets; host TCP/UDP
  probes, spoofed sources and MACs, and fragments are denied, with positive
  controls.
- Vulkan through gfxstream. Real jobs ran GPU, windowed, and CPU suites in
  fresh guests; file and container sentinels proved the reset.
- A controller crash mid-job: the supervisor and VM survived and were
  adopted. Off mid-job lets the job finish and cleans up.

Prepared-helper/DNS reuse, startup timing and explicit sanitized image capture
are implemented and validated with trusted workloads. Three fresh 2-CPU/2-GiB
prepared clones reached readiness in 10.7-12.3 s; two sequential smoke jobs reached
listening in 18.0-19.0 s with fresh-state, GPU/CDI, Docker, DNS/HTTPS and cleanup
checks. Prepared-image adoption and supervisor-loss cleanup are validated.
The CLI sanitation-mode correction, configurable trial reserves and canonical
capture-output check have regression coverage; live validation of those fixes
remains pending. Production deployment of the prepared image remains pending.

Open: private peers, NIC reconfiguration and dynamic interfaces, a cleanup
soak, resource accounting with foreign managers, clean-room runtime
packaging, and login installation. The interface guard is periodic. The
patched runtime must be rebuilt with the fail-closed filter; reused-PID,
breakaway and log-cap retirement are untested on Windows.

## Caching

Actions v2 archive restores and public GitHub release downloads are
validated live on macOS, HCS Windows and Crosvm Linux guests: cold and warm
hits. Direct fallback after cache loss is validated on macOS and Crosvm;
HCS loss fallback remains open. Windows and Linux guests reach the cache over
SSH on guest loopback. Not covered: container images, npm/Cargo/rustup,
private releases, and GHES; tools with their own trust stores need setup.

Categorized store, fill and delivery diagnostics passed isolated Windows-host
jobs; object labels and in-flight SSH loss reports are covered by tests only.
SSH revocation tests cover accepted guest sockets still awaiting forwarding.

The macOS adapter additionally rejects current host/route prefixes
and IPv6 through its cache proxy. Windows-hosted adapters still do not use the
host's dynamic interface prefixes for cache admission; their native guest NIC
denial does not cover those host-side proxy connections.

Upload storage (`store_uploads`) passed every fixture mode live on isolated
macOS guests, with production cache limits (4 GiB, 512 MiB objects). The host
relayed and stored single-request and block uploads (24 and 192 MiB); a fresh
guest's first restores were local hits, taking 15-19 s against 100 s with
storage off; restores overlapped uploads. With the controller stopped while
both relays were open, the saves finished directly and restored intact. Outage,
oversize (relayed without a copy), storage off and caching disabled behaved as
documented. In an earlier run of this code one relayed upload fell back
mid-upload with an upstream transport error; its save finished directly.
Windows and Linux guests are unvalidated; leave upload storage off on
Windows hosts. Production's first job on it stored a relayed save and hit
locally on two restores.

Misses stream as they fill, and a stalled upstream resumes from its offset.
Isolated macOS jobs with production cache limits passed with storage on
(relayed saves, including block lists, restored locally), storage off (24 and
192 MiB restores and a release miss streamed) and the controller stopped
mid-job (transfers finished directly). Not yet deployed to production, where
misses still wait for the whole fill.

The cause of a downstream project's earlier Linux release miss and two archive
fill fallbacks is unknown; legacy logs could not distinguish eviction,
invalidation and upstream change.

## Telemetry

Host and guest CPU, memory, disk, and (Windows) commit summaries appear in
controller logs and job hooks as numeric-only reports. Validated live on
Windows and Linux guests. On macOS real smoke jobs emitted numeric start and
completion CPU, memory and disk summaries; cache hit/miss readback remains
unverified.
