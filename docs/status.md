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
purego, its own guest agent). Validated on this
runtime with real scale-set jobs from a baseline with the guest agent:

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

Isolated cold-boot validation: 12 successful macOS VM boots (three per condition,
2 CPUs/4 GiB, caching and release proxy enabled), without runner registration.
The original baseline's new one-upload fallback had median helper/cache
preparation of 2.76 s versus 2.09 s for the old two-upload path. On a separately
prepared baseline, verified helper reuse took 0.99 s versus 1.17 s for its
old-path control. Overall startup medians did not improve; boot/readiness varied
from 36.70 to 45.68 s and dominates the total. Host disk caches were retained.
[Individual timings and methodology](macos-startup-benchmark.json) include the
excluded failed verification attempt; successful samples all proved the intended
helper mode and complete guest/record cleanup. Production configuration, mode
and source image checks were unchanged.

The guest LaunchAgent now sets `ProcessType=Interactive`, targeting the
low-priority I/O throttling observed before the agent reached Go main. Six
interleaved cold-boot pairs (2 CPUs/4 GiB, full disk synchronization, identical
agent binaries, equally prepared private image copies) reduced median
boot-to-Aqua/script readiness from 44.16 s to 26.47 s: 17.69 s (40.1%).
Interactive was faster in every pair; ranges were 39.92–48.97 s for default
and 24.85–27.68 s for Interactive. Host disk caches were retained; registration
and helper/cache preparation were outside those timings.
[Individual measurements and methodology](macos-interactive-benchmark.json)
retain every successful sample, including slower observations.

Two additional fresh Interactive guests ran real ephemeral-runner smoke jobs:
Aqua execution, fresh-guest state, child processes, exit propagation and file I/O
passed. In both, the same official listener survived an agent restart, the
start/completion hooks emitted numeric telemetry, and the listener exited zero
after its job. All validation guests, records, image copies and registrations
were removed; production configuration, mode and source image checks were
unchanged. These smoke jobs do not establish complete workload performance.

Tests only: manager JIT/listener stage logging, transport and partial-copy fault
handling, cache failure fallback and optional container-pair reuse. Those paths
were not part of the cold-boot comparison. These changes are not deployed to the
installed controller or source baseline; no end-to-end registered-runner speedup
has been established.

Open:

- Production cutover to a baseline with the guest agent installed.
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
- A fresh guest reaches listening in about 18 s.

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
The cause of a downstream project's earlier Linux release miss and two archive
fill fallbacks is unknown; legacy logs could not distinguish eviction,
invalidation and upstream change.

## Telemetry

Host and guest CPU, memory, disk, and (Windows) commit summaries appear in
controller logs and job hooks as numeric-only reports. Validated live on
Windows and Linux guests. On macOS real smoke jobs emitted numeric start and
completion CPU, memory and disk summaries; cache hit/miss readback remains
unverified.
