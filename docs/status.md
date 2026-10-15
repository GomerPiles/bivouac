# Status

Bivouac runs real CI for a downstream project on a macOS host (Tart) and a
Windows host (App Sandbox Windows guests and Crosvm Linux GPU guests). This
page records what is validated live, what only tests cover, and the open
gates. No provider is ready for untrusted (for example fork) pull requests.
The latest review fixes are covered by tests only, not yet validated live.

## Checks

`gofmt`, `go vet`, `golangci-lint`, `go test -race ./...`, and cgo-disabled
builds for macOS arm64/amd64, Windows amd64, and Linux amd64 pass locally and
in the hosted Linux/macOS/Windows workflow.

## macOS: Tart

Validated with real jobs:

- Scale-set demand and the REST JIT fallback (idle pool of one). Each job ran
  in a fresh guest; a sentinel check proved no state carried over.
- Drain, stop, and off/on mid-job and with queued work; controller SIGKILL
  with adoption of the live guest; guest loss mid-job. VM capacity returns
  before remote deregistration, and retained cleanup survives restart.
- The runner executes in the Aqua session of a `--no-graphics` guest.
  Windowed Metal rendering and app lifecycle, focus, and input tests pass.
- Actions archive cache and the release proxy: cold and warm hits, and
  fallback to upstream when the cache endpoint is stopped mid-job.
- Credential-pattern scans of state, logs, and diagnostics found no matches.
- Typical timings: clone 0.05 s, boot to guest agent 22–29 s, JIT to
  listening 3–8 s, guest teardown 1.4–3.4 s.

Open:

- Host reboot persistence of drain, stop, and off.
- Repository-scoped registration, custom runner groups, GHES, pools larger
  than one, multiple providers, and simultaneous failures.
- Resource and cache summaries from a real job (deployed, not yet observed).
- Docker/Podman engine companions are implemented but not validated: they
  need a Linux Tart baseline, Softnet privileges, public-only network checks
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

Open:

- Private-peer and source-MAC filtering are inconclusive in the tested
  topology. The interface guard is periodic, not atomic, and stops after
  broker loss.
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
paths pass race tests, vet, lint and an ordinary-token IMAPI media fixture;
The first guest attempt reached native running/GPU assignment but timed out
without reaching the guest agent; verified cleanup removed its child/journal.
The corrected setup media uses `Autounattend.xml`, as required for removable
media discovery. Guest readiness/SSH/rendering still need a live pass.
Fake-backed lifecycle/ownership and guest-protocol tests pass without elevation.
Local formatting, vet, lint, the full race-enabled test suite and cgo-disabled
Windows amd64, Linux amd64 and macOS arm64/amd64 builds pass. The hosted workflow
has not run for this spike.
The ordinary-token DLL-export check passes on the Windows host; configuration
planning also passes without opening any image or contacting the HCS service.
An approved offline native-only trial reached HCS `Running` state, accepted
GPU-PV assignment, explicitly terminated the owned VM, confirmed native absence
and removed its journal/disposable child. It used an independent immutable
template copy with 1 CPU, 2 GiB RAM and no NIC; only the trial lock file remains.
The default properties query and retaining the created handle through verified
termination are live validated. Production CI/configuration was unchanged.
Windows setup/guest readiness, SSH, hardware rendering, desktop/input,
process-loss cleanup/recovery and networking/isolation remain unverified.
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

## Telemetry

Host and guest CPU, memory, disk, and (Windows) commit summaries appear in
controller logs and job hooks as numeric-only reports. Validated live on
Windows and Linux guests. On macOS a live job's report contains valid CPU and
memory samples; completion summaries and cache hit/miss readback are not yet
observed.
