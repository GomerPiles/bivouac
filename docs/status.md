# Status

Bivouac runs real CI for a downstream project on a macOS host and a
Windows host (App Sandbox Windows guests and Crosvm Linux GPU guests). This
page records what is validated live, what only tests cover, and the open
gates. No provider is ready for untrusted (for example fork) pull requests.
The latest review fixes are covered by tests only, not yet validated live.

## Checks

`gofmt`, `go vet`, `golangci-lint`, `go test -race ./...`, and cgo-disabled
builds for macOS arm64/amd64, Windows amd64, and Linux amd64 pass locally and
in the hosted Linux/macOS/Windows workflow.

## macOS

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
the REST JIT fallback (idle pool of one), off/on with queued work, retained
cleanup across restart, the Actions archive cache with fallback when its
endpoint stops mid-job, and windowed Metal, focus, and input tests.

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

- Softnet launched by the VM helper (container pairs) and Linux guests on
  this runtime.
- Host reboot persistence of drain, stop, and off.
- Repository-scoped registration, custom runner groups, GHES, pools larger
  than one, multiple providers, and simultaneous failures.
- Docker/Podman engine companions are implemented but not validated: they
  need a Linux baseline with the guest agent, Softnet privileges, public-only network checks
  from guests and privileged containers, and crash/loss/accounting tests.
- Production cutover from Tartelet.
- Native VM-helper process-group launch and the cache bind to `guest_host`
  remain unverified on a real host; the guest agent's runner process lifetime
  was checked separately above.

## Windows: App Sandbox (Windows guests)

Validated live:

- A protected elevated broker and journal. An owned VFP layer on each VM port
  denies host, gateway, LAN, and IPv6 traffic while public DNS and HTTPS
  work. Denial was checked against reachable positive controls, including
  after broker loss and adoption.
- GPU-PV guests on the interactive desktop: hardware D3D11 rendering,
  presentation, pixel readback, focus, and keyboard/mouse input.
- Real jobs, including windowed rendering tests. Fresh-guest reset verified;
  a controller crash mid-job was adopted; off and stop mid-job clean up.
- A host interface change during a guest's life quarantines it and keeps
  its port blocked. Interrupted native deletion recovers.
- Recovery after a host reboot with idle guests and CI still on.
- The optional limited login task registers and runs on demand.

Native process tests reproduce a hidden portable-launch child being killed
when its enclosing Windows job closes. The portable launcher now refuses a new
manager from such a job before mutating mode or control records; its context
guard is exercised in an isolated job using stock Windows PowerShell. This
launcher change is not deployed to the installed controller.

Open:

- Private-peer and source-MAC filtering are inconclusive in the tested
  topology. The interface guard is periodic, not atomic, and stops after
  broker loss.
- Automatic broker admission recovery after interface changes is covered by
  fake-backed tests: quarantine stays closed through stopped/absent VMs and
  partial network cleanup, then a successful guard pass admits fresh guests with
  current host policy without broker restart. Addition/removal, repeated changes,
  canceled passes and retained-record recovery across restart are covered. This
  change is not deployed to the installed controller or validated with live NIC
  changes.
- The administrator-only native fault-injection test is compiled but has
  not run. Recovery of a guest retained across reboot, reboot mid-job, and
  a cleanup soak are untested.
- Login-task behaviour at real logon and reboot, and status-transport
  failures injected during live jobs (tests only).
- Engine prerequisites start manually through an elevated helper;
  packaging is not done. The operator migration to the protected engine
  directory is not done. Read-only checks against the new protection rules
  passed `$PSHOME`, Program Files and the storage root, but found the App
  Sandbox installation under a user-renamable data-drive folder and its data
  folder owned by the ordinary account. Both are documented prerequisites,
  not yet applied.
- The PowerShell helpers parse under PowerShell 7 and 5.1 but have not run.
  Windows-only tests pass on a Windows host without elevation; the native
  credential round trip is opt-in and was not run.

## Windows: direct HCS (in progress)

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
The provider adopts guests by label, pins host keys, reconnects after transport
loss and delivers files by scp. A real named-pipe
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
leftover in 0.85 s. The App Sandbox broker had no guest during the batch and
was not restarted.

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
repeated. No guest has run under the service yet.

Open:

- `bivouac on`/`off` driving the service through a live daemon, and
  `Deactivate` refusing to stop a VM host that holds guests (unit-tested
  only).
- Isolation controls that batch 2 did not cover:
  - A control with the deny layer removed. Without it, a refused host
    listener does not rule out the host firewall; the gateway's DNS proxy is
    the stronger evidence.
  - An owner-controlled private peer.
  - Guest source-address and MAC changes.
  - Host interface changes while a guest runs.
- The provider running live as part of the manager.
- The image factory.
- The warm spare.
- Runner listening and jobs.

## Windows: Crosvm (Linux GPU guests)

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
validated live on all three guest types: cold and warm hits, and direct
fallback after cache loss. Windows and Linux guests reach the cache over
SSH on guest loopback. Not covered: container images, npm/Cargo/rustup,
private releases, and GHES; tools with their own trust stores need setup.

Categorized store, fill and delivery diagnostics passed isolated Windows-host
jobs; object labels and in-flight SSH loss reports are covered by tests only.
SSH revocation tests cover accepted guest sockets still awaiting forwarding.

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
