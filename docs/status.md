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
on live guests. The LaunchAgent policy and startup changes are not deployed to
the installed controller or source baseline.

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

Upload storage (`store_uploads`) is covered by tests only, including the real
preload against a simulated Azure endpoint and its direct fallback. Unverified
live: that GitHub's download URL names the uploaded blob with the same ETag, the
real storage SDK through the relay, and relay throughput over SSH loopback.
The cause of a downstream project's earlier Linux release miss and two archive
fill fallbacks is unknown; legacy logs could not distinguish eviction,
invalidation and upstream change.

## Telemetry

Host and guest CPU, memory, disk, and (Windows) commit summaries appear in
controller logs and job hooks as numeric-only reports. Validated live on
Windows and Linux guests. On macOS real smoke jobs emitted numeric start and
completion CPU, memory and disk summaries; cache hit/miss readback remains
unverified.
