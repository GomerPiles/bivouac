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
- Timings: clone 1ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ6 ms, boot to guest agent 22ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ31 s, JIT to listening
  5ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ10 s, teardown 1.3ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Â¦ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ1.8 s (power-off).

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
- The Aqua session check, process-group launch, and cache bind to
  `guest_host` are untested on a real host.

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

## Windows: direct HCS spike

A separate `hcs-spike` executable implements offline VM configuration, native
HCS lifecycle, differencing disks, post-start GPU-PV assignment, bounded copies
of selected GPU drivers, guest-agent initialization and ephemeral authenticated
SSH over HvSocket. It is not wired into the CI manager. App Sandbox guest
components remain required. Optional pinned setup assets now generate per-trial
setup media for generalized templates without modifying the baseline. An optional
native guest probe checks setup/console readiness, hardware D3D11, presentation
and GPU/desktop pixel readback through fixed authenticated SSH code. These new
paths pass race tests, vet, lint and an ordinary-token IMAPI media fixture.
The full offline trial with 2 CPUs and 4 GiB RAM validates child-only answer
staging, detach-before-start, native running, GPU assignment, guest-agent
initialization, reported display-driver readiness and ephemeral authenticated
SSH. Fixed command execution and small length-prefixed stdin round trips pass
live. Inspection confirms setup/OOBE complete, the intended account, agent/SSH
services and the setup-complete marker. Large validation payloads still stall
after their header is received (checkpoint 4), before the native probe is staged
or run. The underlying bulk-transfer limitation is not resolved.
Public validation assets use the setup ISO, with only a sub-1-KiB entry/metadata
frame sent over SSH. The guest verifies the script against the host build's
embedded hash and the probe against its configured pin before execution. This
path passes live: setup readiness, the intended active console user's Explorer,
the Default input desktop and interactive native-probe execution are confirmed.
Driver destinations require the documented
`C:\Windows\System32\HostDriverStore\FileRepository` tree. The complete guarded
trial passes: setup and console readiness, authenticated SSH, hardware D3D11 on
the host GPU, successful presentation and both GPU and composited-desktop pixel
checks (stage 7, HRESULT 0). The host accepts the strict JSON report, written and
flushed directly through the guest console. Numeric diagnostics confirm one
GPU-PV device without a problem code after 136 copied driver files. The owned
VM, child disk and journal are removed, with native absence confirmed.
Corrected hidden-folder inspection and matching cleanup finish successfully;
the VM, child and journal are removed and only the trial lock remains. Some
files observed live were absent in the stopped clone after forced termination,
so that inspection is not authoritative for the final live guest state. A
specialized image must preinstall the same pinned probe and validation script.
Production CI and the installed provider remain unchanged. The experiment still
requires the App Sandbox guest service and signed display-driver components.
Fake-backed lifecycle/ownership and guest-protocol tests pass without elevation.
Local formatting, vet, lint, the full race-enabled test suite and cgo-disabled
Windows amd64, Linux amd64 and macOS arm64/amd64 builds pass. Hosted Linux, macOS and Windows checks also pass for this spike.
The ordinary-token DLL-export check passes on the Windows host; configuration
planning also passes without opening any image or contacting the HCS service.
An approved offline native-only trial reached HCS `Running` state, accepted
GPU-PV assignment, explicitly terminated the owned VM, confirmed native absence
and removed its journal/disposable child. It used an independent immutable
template copy with 1 CPU, 2 GiB RAM and no NIC.
The default properties query and retaining the created handle through verified
termination are live validated. Production CI/configuration was unchanged.
Input, process-loss cleanup/recovery and networking/isolation remain unverified.
Ordinary-token headroom reporting and native admission checks refuse missing or
insufficient physical/commit memory, trial-volume space and CPU capacity. Checks
run before staging and HCS creation. A two-second resource watcher cancels only
the isolated trial if the live reserve is lost; cleanup remains independent.
Boundary, pre-dispatch refusal and watcher cancellation tests pass without a VM.
Guarded live trials complete with sufficient headroom. Live reserve-loss
cancellation stopped only the isolated guest and completed owned cleanup.
Host-monotonic stage timings and a cumulative validated-desktop milestone are
implemented, including preparation, agent/SSH, console/GPU waits and cleanup.
Guest wait budgets use monotonic stopwatches. First-logon animation is disabled
by default during disposable provisioning, with other policies and all safety
gates preserved. Ordinary-token tests, race tests, vet, lint and a cgo-free
build pass. Prepared cold-boot timings are validated below; no paired existing-
provider or clone-to-CI-listener comparison has been run.
Supplied existing-provider evidence places about 87% of readiness in native
startup plus console preflight; the latter observes console availability pending
while setup/OOBE flags are already clear.
The prepared-image pipeline is live validated in the experimental executable.
`build-image` prepares an unenrolled derived image, validates rendering, sanitizes
authentication/runner state, acknowledges guest shutdown and requires native
`GracefulExit`/absence before publishing pinned provenance. Sanitation and
shutdown share one SSH operation. Both sshd and the guest agent stay disabled
until a fixed boot task replaces server keys, starts SSH, then starts the agent.
The manifest pins this sanitation implementation; older images fail that pin.
Runtime trials omit setup media, OS setup, installations and driver copies and
rotate the local credential. `trial --repetitions` runs sequential fresh clones
with one session-scoped verification of pinned source/derived images and rejects
missing/repeated public SSH server-key fingerprints. Publication/ownership,
private image ACLs, VHD ancestry, extraction safety and credential gates have
ordinary-token regression coverage.
The corrected factory build completed in 184.604 s. Prepared cold boots pass
with distinct SSH server keys, credential rotation, authenticated SSH, console,
hardware D3D11, presentation/pixel checks and owned cleanup. Setup media, offline
answer staging and driver copies are zero. Before the connection fix, desktop
readiness was 54.666 s including initial verification, then 41.753 s and 42.474 s;
one native connection attempt took about 30 s on every boot.
The spike now owns cancellable event-based overlapped I/O. Cancellation drains
native completion before unpinning buffers or closing handles. The three-second
agent attempt budget, remaining SSH guest budget and all safety/readiness checks
are preserved. Native cancellation/deadline/close regressions, cancellation-race
stress, race tests, vet, lint and cgo-free builds pass; hosted checks pass on all
three platforms. Same-image live trials cap every native attempt at 3.000 s.
Validated-desktop times are 49.991 s including 11.818 s initial image verification,
then 35.272 s and 37.052 s. Agent connection is still 23.531-25.249 s over 7-8
attempts; instrumented results below attribute most delay before script entry. All three
boots pass unique-key, credential, SSH, console, rendering and owned-cleanup
gates. New bounded guest-uptime checkpoints distinguish task entry, key generation and
SSH/agent service startup. The schema requires complete, ordered values within
ten minutes, with no wall-clock timestamps or guest-controlled text. This keeps
fresh keys, service ordering and every readiness check intact. Local race tests,
vet, lint and script/report regressions pass. The instrumented image passes
sanitation, acknowledged clean shutdown, publication and source cleanup. Three
instrumented cold boots pass: task entry is 21.875-23.875 s guest uptime; key
generation takes 0.485-0.578 s, SSH startup 0.281-0.312 s and agent startup
0.516-0.610 s. All identity/readiness/rendering/cleanup gates pass. Validated
desktop times are 49.247 s including 11.714 s initial verification, then 39.694 s
and 38.661 s. The large interval precedes script execution; OS boot, task dispatch
and PowerShell initialization are not yet separated. Three alternating
control/normal-priority pairs pass all six boots with distinct server keys and
complete owned cleanup. Normal priority does not improve readiness in this sample:
desktop spans excluding image verification are 36.225/39.224/40.077 s for control
and 36.535/42.138/44.436 s for normal priority. Default task priority (7) is
retained; no startup speedup is claimed from the earlier script entry. The
installed provider and production CI are unchanged.
A read-only `trial --boot-events` collector targets the unaccounted pre-script
interval using existing kernel, fixed-task process/action and correlated
PowerShell console events. It preserves image pins and normal startup;
missing channels and clock changes remain explicit unknowns. Local bounded-output,
clock-change, identity-correlation and readiness-milestone tests pass. A live
read-only diagnostic passed normal readiness and cleanup, but Task Scheduler
Operational was disabled and no usable classic PowerShell engine boundary was returned. No event
offsets were available; pre-script attribution remains unresolved. An opt-in
`build-image --boot-event-logs` prepares a separate diagnostic image with guest
task logging enabled; console events now correlate directly to the task's
recorded process ID. Diagnostic capture and the cold boot passed normal gates
and cleanup. Task process creation is 2.734 s after kernel-recorded start, while
script entry is 21.187 s guest uptime; console boundaries are absent. These
clock origins have not yet been aligned. A bounded third read-only query now
samples both origins together; live calibration remains pending. No further
optimization is claimed. Embedded image assets
are byte-pinned with repository LF endings; ordinary-token `image-pins` reports
the three script hashes, and a regression rejects CRLF drift before a live build.
No Windows runner-listening/job timing, manager integration, input or networking/
isolation validation has occurred. Production CI is unchanged.
See [`hcs-spike.md`](hcs-spike.md).

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
The cause of a downstream project's earlier Linux release miss and two archive
fill fallbacks is unknown; legacy logs could not distinguish eviction,
invalidation and upstream change.

## Telemetry

Host and guest CPU, memory, disk, and (Windows) commit summaries appear in
controller logs and job hooks as numeric-only reports. Validated live on
Windows and Linux guests. On macOS a live job's report contains valid CPU and
memory samples; completion summaries and cache hit/miss readback are not yet
observed.
