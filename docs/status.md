# Status

Bivouac runs real CI for a downstream project on a macOS host and a
Windows host (HCS Windows guests and Crosvm Linux GPU guests). This
page records what is validated live, what only tests cover, and the open
gates. No provider is ready for untrusted (for example fork) pull requests.
Rootless macOS networking has disposable-guest evidence below; the complete
production migration gates remain open.

Windows HCS guests have two runtimes: production runs the previous one, and
the agent-served runtime with the ISO image factory is not deployed (see
"Windows: direct HCS").

## Checks

Hosted CI checks each PR revision on macOS, Ubuntu and Windows: `gofmt`,
`go vet ./...`, `golangci-lint`, `go build ./...` and `go test -race ./...`,
plus macOS signed-VM and Seatbelt alias tests and the Crosvm packet-filter
tests on Linux. Windows tests include PowerShell 5.1 script fixtures. Local
Windows checks run the same set, with `golangci-lint` for all three OSes and
HCS/vmhost vet with the `integration` tag, but without `-race` (no cgo on that
host). Local macOS checks include full race tests and Windows amd64/Linux
arm64 cross-builds. None of these run the opt-in live labs, and unit tests and
cross-builds do not establish live provider behavior.

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

## Windows: Sandbox spike

The opt-in `cmd/sandbox-lab` executable is based on the PR 29 stack and is not
registered as a manager provider. Production configuration, VM host services,
runner labels and the HCS worktree are unchanged by this spike. No GitHub
credentials, runner registration or JIT configurations were used.

Live on Windows build 26300 with Sandbox CLI 0.8.107.0:

- Caller-selected Sandbox IDs, desktop connection, fixed-command execution,
  read-only bootstrap and isolated writable reports work.
- The guest is an elevated WDAGUtilityAccount in active RDP session 1 on the
  Default desktop; the active-console API returns no session. The stock HCS
  agent's console refusal is expected; its checks remain unchanged.
- The shared guest-agent framing and Windows process jobs pass command,
  stdin and nonzero-exit probes over a private in-memory link inside Sandbox.
- The hash-pinned official runner 2.338.2 reports its version. Its unconfigured
  listener exits 1 as expected; bundled Node 24 and Windows PowerShell run.
  This does not establish registration, listening for jobs or job completion.
- Networking disabled: zero active non-loopback interfaces, no public DNS or
  HTTPS. The final offline run reached the complete bootstrap/runner/protocol
  proof in 18.1 s after create began; cleanup including fresh ownership proof
  and confirmed absence took 2.5 s. These are single-run observations, not a
  comparison with HCS or a job-ready benchmark.
- Networking enabled: public DNS and HTTPS work. Host-to-guest TCP still timed
  out with a guest-scoped allow rule. A reverse callback to a matching host
  interface also timed out without host firewall changes. The cause is
  unresolved; these failures do not establish private-network isolation.
- The elevated read-only helper identifies a Sandbox native VM whose compute
  and runtime UUID differs from the CLI session UUID. Its owner/type/state and
  a guest identity response over the lab's HvSocket service corroborate the
  exact CLI UUID, prefixed name and initial boot UUID. The tuple is journalled;
  native discovery refuses missing or ambiguous identity matches.
- Using that runtime UUID, the ordinary user reaches the private agent while
  networking remains disabled. The complete `--native-probe` passed framed
  host-to-guest stdin, runner/runtime smoke, nonzero exit propagation, cancellation
  followed by a healthy new request, guest-loopback refusal, and reconnection
  after task End/Run with a new agent generation. Both identity paths passed
  again before cleanup; the CLI session was confirmed absent afterwards. A
  separate elevated query also confirmed the recorded native ID absent.
  No shared service, registry, firewall or VM settings were modified.
- `--secure-probe` passed the same native command, stdin, exit, cancellation,
  restart and cleanup checks over mutual TLS 1.3 with zero active guest NICs.
  Missing/wrong client certificates and plaintext were rejected before protocol
  admission, with advancing guest rejection counts and healthy authenticated
  controls. A wrong server pin was refused. Private keys remained in process
  memory; the elevated helper returned only public native metadata.
- A verified anonymous thread token could open the raw native socket, but
  received a remote TLS rejection without a client certificate. The guest's
  rejection count corroborated that refusal. Reads of the private run record
  and opens of the manager process with memory-read rights were denied, with
  ordinary-user positive controls. This is impersonation evidence, not a test
  of another process's primary user or proof of the kernel's socket DACL.
- The separate `--discovery-probe` completed without UAC. Both guest KVP views
  lacked `VirtualMachineId`; SMBIOS and the guest HvSocket `LocalAddress`
  exposed UUIDs, but both routes returned Winsock 10049 and neither reached
  the recorded guest. No candidate was treated as native ownership evidence.
- One elevated session-only metadata broker served two fresh ordinary-user
  `--secure-probe --broker` launches without per-run UAC. Both passed the full
  native/TLS, stdin, exit, cancellation, restart, refusal and cleanup predicates
  with guest networking disabled. No per-run inspection directory was created;
  both CLI sessions were absent, and the broker endpoint closed after its second
  successful query. No persistent service, task, registry or account change was
  made. Broker dispatch/identity, frame bounds, replay and fake-endpoint refusal
  have test coverage. A real, unelevated pipe fixture passed caller-SID
  identification, anonymous denial, and ordinary queries before/after; its
  creator additionally has server rights. The separate elevated account audit
  was canceled at UAC. Durable installation is a documented proposal only.
- Successful lab launches were stopped by their recorded CLI ID after a fresh
  guest/boot challenge, and absence was confirmed. Cleanup failures retain
  records. No unrelated guest was stopped.
- A read-only fresh-Sandbox baseline (guest Windows build 26100) observed
  Defender's service and real-time protection off, Tamper Protection off,
  Search stopped, and SysMain/Windows Update running. No guest or host policy
  was changed. MSVC, MSBuild, Windows SDK, PowerShell 7, Git, 7-Zip, CMake, Ninja,
  Python, Node on PATH, .NET SDK and LLVM were not found by the fixed probes;
  the separately staged runner's Node was present. This does not inventory the
  running production image. The lab now reserves 12 GiB free physical memory
  beyond its 4-GiB guest by default; this is a sample-based development guard,
  not shared-provider resource accounting.

The existing VM-host service now has an opt-in `sandbox_accounts` discovery
capability and a Sandbox-only configuration with no HCS images. Fixtures cover
cross-capability denial, unchanged HCS ownership, sanitized metadata/errors and
service permissions excluding stop for discovery-only accounts. The protected
installed service, production configuration and other HCS worktree are unchanged;
shared-service deployment still requires live validation. Owner-filtered
enumeration passed two complete secure launches through the temporary broker.

The Sandbox lab now supports opt-in pinned PowerShell 7.6.9, MinGit
2.56.0.windows.4, CMake 4.4.4 and Ninja 1.13.2 through a separate verified
host payload cache and offline guest extraction. Live probes verified versions,
PowerShell execution, Git repository creation and a compiler-free CMake/Ninja
configure/build, plus agent-child PATH and executable versions before/after
agent restart over mutual TLS. Two fresh four-tool secure launches used one
temporary broker elevation, passed cancellation/refusal/ownership/cleanup
checks, and reached bootstrap in 24.103 and 24.115 s. Cached host acquisition,
rehashing and staging took 383 and 387 ms, measured separately. The full-archive
guest tool steps took about 8.4 s. These are trusted smoke observations, not
GitHub job readiness or compiler/SDK benchmarks. The subsequent CMake CLI
extraction optimization omits HTML docs and the GUI; it has unit coverage but
has not been timed live. The catalog is not wired into the HCS image builder.

A setup-only MSVC/SDK layout probe verifies the pinned Microsoft bootstrapper
signature and runs it only inside its own networked Sandbox. Two attempts
failed with CLR exit `0xe0434352`; fixed-category diagnostics found an I/O
exception on the local-guest-path retry. No complete layout, offline install
or C++ compile is validated. Raw setup logs were not copied to the host; the
new bounded method-name diagnostics are not yet validated live. Both guests
were stopped with ownership/absence proof. The resource guard also refused an
attempt before launch. Further live testing requires available host headroom;
the reserve was not reduced and no host installer or policy change was made.

Unit tests cover wrong/stale ownership proofs, malformed/oversized inventory,
RDP-session predicates, XML escaping/device defaults and real TLS handshakes
with missing/wrong client certificates and a wrong server pin. The actual
secured listener's admission gate has positive and negative stream tests;
startup reports must match the recorded guest boot, session, generation and
certificate pin. They do not establish a TCP channel. Native transport and corroborated ownership now have
live evidence. Ordinary HCS discovery still requires elevation; ordinary
HvSocket communication does not. An unregistered guest-to-host HvSocket
callback was refused with Winsock 10061 even though the ordinary host could
bind temporary wildcard/child listeners. No global service registration was
attempted, and the reason for that refusal is unverified.
The Sandbox, discovery, HCS and VM-host tests, repository-wide vet and lint
pass. The full non-live suite has two Crosvm native-job fixture failures:
their job names already exist, so creation refuses adoption. Those objects
were not stopped or cleaned up; their origin is unverified. Race checking was
unavailable with the host's cgo-disabled toolchain.

Open: deployment of shared-service discovery and its LocalSystem/reboot
lifecycle, other-primary-account access
(including Sandbox CLI/server management), effective settings, host-enforced
public-only egress, real disposable runner registration/completion and
cancellation, crash/reboot recovery, resource
budgeting and GPU/desktop workload validation. See [sandbox.md](sandbox.md) for
the repeatable lab and its limits.

## Windows: direct HCS (Windows guests)

Two runtimes exist. Production Windows CI runs the previous one (App
Sandbox/SSH guest transport on a template-built image). The agent-served
runtime in this tree (Windows contract 2) is not deployed; it switches
together with its manager, VM host service and image.

### Agent-served runtime and ISO image factory (not deployed)

The HCS provider, image factory and vmhost lab use bivouac's guest agent over
HvSocket. Windows contract 2 adds a separate on-demand runner task beside the
agent logon task; images of an earlier contract are refused. The cutover
switches manager, VM host service and image together, and so does rollback.

Validated live in the lab with CI Off, on reference-ISO builds:

- Publication in about seven minutes with Secure Boot on, TPM present and
  ready, fully decrypted BitLocker state, the embedded 2023/plain-GPT boot
  path, one Hyper-V display and hardware D3D11. Host firmware entries were
  unchanged. The pinned render-probe output bridge and sanitation ran.
- One contract-2 vmhost lab batch passed every gate: installation facts for
  both tasks (stored runner descriptor without a principal entry, autologon
  agreement), loopback refusal, probe SID/elevation/console/desktop context
  and normal priority, a same-account SAFER normal-user token reading the
  agent task but refused reading or starting the runner task (elevated start
  accepted), and the same probe and grandchild surviving agent task End/Run
  and agent kill/Run. A filtered start of the agent task, which keeps the
  default principal read entry, was accepted; that is why the runner task
  omits the entry. The probe also reported the agent in its immediate job,
  which survival does not explain. Job membership is diagnostic only.

Unit coverage only:

- The Windows adapter's preflight, preparation, start/stop, clock setting,
  bounded delivery/extraction and 64-connection cache relay; receive
  metadata, readiness ordering, command/output bounds, terminal protocol
  refusal, transient recovery, adoption without pins, status/diagnostics
  decoding, TLS cache requests, fallback cleanup and revocation.
- The runner task: self-tests of both task definitions and the runner's
  stored security descriptor at preparation and publication; the
  autologon-account/runner-principal/agent-token SID equality at
  installation and manifest admission; structural task XML at start and the
  trampoline's native context checks; schema defaults, task-query failure
  facts, mode-before-marker ordering, claims, injected context refusals,
  helper hard-link/junction refusal, stop during a locked start, and both
  listener/cancellation interleavings.
- In-process listener re-listening and bounded consecutive session refusals;
  MSI-before-leftover uninstall and OpenSSH server-capability removal
  (keeping the inbox client and ssh-agent); factory registration, sanitation
  and manifest admission; the probe bridge's atomic-ACL creation and
  primary-failure preservation; the 180-second first-boot render budget and
  numeric failure facts; failure cleanup's memory-reserve cancellation and
  separate termination/diagnostic/detach deadlines.
- Startup timing records and the network lab's per-run readiness report
  (fake host and transport).

Unverified live:

- Refusal for a real UAC-filtered token (the lab uses a SAFER token with no
  more access), premature or duplicate activation, cancellation during
  startup (helper console attach) and the accepted double Ctrl+C, console
  visibility and focus, scheduler latency, environment/session selection,
  task End descendant behavior, restart-on-failure with a surviving child,
  and recovery after an actual agent crash.
- Native networking, UTC correction, cancellation/result reporting, cache
  behavior and end-to-end jobs on agent-served guests. Sibling-guest
  negative tests are outside the loopback and host-account scope.
- Performance. Interleaved baseline distributions remain an operator gate.
  In one lab comparison the new image reached a validated desktop in 33-40 s
  against 24.5-27 s for a copy of the production image, with different
  validation scripts on each; the gap is unexplained. Short guest PowerShell
  runs that autoload a module rescan all modules when no module-analysis
  cache is saved, which may contribute; unmeasured in guests.

### Deployed runtime (previous App Sandbox/SSH transport)

Production Windows CI runs on the `hcs` provider: the same scale set, labels
and size (10 CPU, 9 GiB, GPU), with Linux unchanged on crosvm. A production
job listened 46 s after create (clone 7 s, boot 21 s, JIT registration 7 s)
and tore down in 1.8 s.

Validated live on that runtime, with production CI Off:

- Lab batch: five cold boots without a network adapter created, started and
  attached GPU-PV, reached the guest over HvSocket, rendered hardware D3D11
  with presentation and pixel checks, and were removed after confirmed
  absence. An unelevated process reached only the HvSocket service its
  account was granted. Lazily committed memory booted with about 0.1 GiB
  committed at start (steady-state saving unmeasured). A flattened
  single-file image booted the same way.
- Network batch 2 (`TestLabNetworkBatch`): two production-sized networked
  cold boots reached public DNS, HTTPS, TCP and UDP DNS; the gateway's DNS
  proxy, host listeners at the gateway, LAN source and switch IPv6
  link-local, and public IPv6 were unreachable. The deny layer survived
  boot, readiness and the probes, and deletion removed the switch adapter.

  The switch port appears only at start, so the deny layer lands about 1 s
  after the guest begins running (0.92-0.97 s in both runs); design accepts
  that window because nothing untrusted reaches the guest before the layer
  is verified.
- A failed start (missing second disk, HRESULT 0x80070002) is cleaned up:
  journal and storage removed after confirmed absence. HCS refuses excess
  vCPUs at create.
- The VM host service installs elevated with one UAC prompt and no reboot;
  the ordinary account starts and stops it (about 0.3 s each), and the
  provider's `Activate`/`Deactivate` start and stop it idempotently. The
  installed service serves with its default owner (Administrators).
- End-to-end GitHub jobs on an isolated home and label: `bivouac on` filled
  the pool, jobs ran with hooks, checkout, GPU-PV and `api.github.com`, the
  second job saw no trace of the first, guests were deregistered and deleted
  in about 2 s, and `bivouac off --wait` stopped the service with no adapter
  or runner left. The cache validation fixture (`save`, `restore`,
  `restore`) passed with production's Windows cache settings.

Open:

- Everything under "Unverified live" above, then a cutover and rollback
  rehearsal and the production cutover.
- Hibernation and fast startup are not disabled inside built guests.
- `Deactivate` refusing to stop a VM host that holds guests (unit-tested
  only).
- A foreground `vmhost run` with the explicit pipe owner.
- Isolation controls that batch 2 did not cover:
  - A control with the deny layer removed. Without it, a refused host
    listener does not rule out the host firewall; the gateway's DNS proxy is
    the stronger evidence.
  - An owner-controlled private peer.
  - Guest source-address and MAC changes.
  - Host interface changes while a guest runs.
- Cache loss fallback, `outage`, `interrupt` and upload storage on HCS guests.
- Longer and heavier jobs over time, and recovery after a daemon or host
  restart with HCS guests.
- Interrupted-apply cleanup, retry from another session and after host reboot,
  and split-media DISM wildcard apply. Ordinary WIM apply through the ISO
  volume-GUID path and publication are validated with the reference ISO.
- Live validation of publication's nonzero BitLocker refusal, automatic-letter
  refusal, replacement-log cleanup, cleanup stage deadlines, probe ACL/error
  changes and `--retain-failed` retention and cleanup. Unit tests cover these
  paths. Admission does not compare the host GPU driver with the image's.
- The warm spare.

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
HCS loss fallback remains open. Crosvm Linux guests and the deployed HCS
runtime reach the cache over SSH on guest loopback; the agent-served HCS
runtime relays it over the agent (unit coverage only). Not covered: container images, npm/Cargo/rustup,
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
Crosvm Linux guests and on Windows guests of the deployed HCS runtime; not yet on the
agent-served runtime. On macOS real smoke jobs emitted numeric start and
completion CPU, memory and disk summaries; cache hit/miss readback remains
unverified.
