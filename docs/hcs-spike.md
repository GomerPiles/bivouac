# Direct HCS Windows spike

`cmd/hcs-spike` is a separate executable exploring removal of the App Sandbox
host application and daemon. It is not a manager provider and has no GitHub,
CI-mode, runner-registration, production configuration or broker API. Building
it does not replace `bivouac`.

## Validated native trial

An approved offline trial against an independent immutable template copy reached
HCS `Running` state, accepted post-start GPU-PV assignment, explicitly terminated
the owned VM, confirmed native absence and removed its journal/disposable child.
That native-only trial left only its lock file. The protected lab retains the
independent baseline, pinned executables, configurations and bounded result files.
No startup component or production configuration was changed.

The native property query uses the schema's default basic properties. Cleanup
keeps the created handle through ownership verification and explicit termination,
then closes it before confirming native absence; closing it earlier can race
asynchronous automatic teardown. Regression tests cover both corrections.

Guest initialization was skipped. HCS running state and accepted GPU assignment
do not establish Windows setup completion, driver readiness, a usable desktop or
hardware rendering. App Sandbox guest components remain required by the full
trial. Removing the host application/daemon is feasible at the native VM layer;
replacing the complete CI provider still requires image provisioning, guest
readiness, graphics/input, networking/isolation and lifecycle validation.

The full guest trial with 2 CPUs, 4 GiB RAM and no NIC validates child-only
answer staging, protected permissions, detach-before-start, native running/GPU
assignment, guest-agent initialization, reported display-driver readiness and
ephemeral authenticated SSH. Fixed command and small length-prefixed input
checks pass live. Setup/OOBE, the intended autologon account, service readiness
and the setup-complete marker are confirmed. A large SSH validation payload
stalls after its length header; the bulk-transfer limitation remains unresolved.

Public validation files travel on the disposable setup ISO: `HCSRENDER.EXE`
and `HCSVALIDATE.PS1` are copied to the fixed guest AppSandbox directory during
setup. SSH sends only a small fixed entry command and metadata, under 1 KiB.
The entry checks the script hash against this host build's embedded source;
the script checks the native probe's configured hash before running it. This
path passes live, including the intended active console user's Explorer,
Default input desktop and interactive native-probe execution. Driver destinations
require `C:\Windows\System32\HostDriverStore\FileRepository`, matching Windows
GPU-PV and the upstream implementation. The complete guarded trial passes with
this path: setup and console readiness, authenticated SSH, hardware D3D11 on
the host GPU, successful presentation and both GPU and composited-desktop pixel
checks (stage 7, HRESULT 0). Explicit flushed console output delivers the strict
JSON report successfully over SSH. Numeric device diagnostics confirm one GPU-PV
device without a problem code after 136 copied driver files. The VM, disposable
child and journal are removed, with native absence confirmed. Parser failures
expose only byte counts and numeric offsets; a synthetic fixture also exercises
the real framed Windows PowerShell launcher.
No raw device identities, names or driver paths enter reports.

The VM, disposable child and journal are removed; native absence is confirmed.
Read-only inspection completed, but some files observed live were absent after
forced termination. Treat the live bounded report as authoritative for completed
checks, rather than inferring that setup had not run from stopped-disk omissions.

Setup media uses the documented removable-media filename `Autounattend.xml`;
the ordinary-token ISO fixture verifies its Joliet directory entry.

## What is implemented

- HCS schema 2.1 generation for an offline Windows amd64 VM, UEFI Secure Boot,
  guest/runtime state files, virtual keyboard/mouse and a basic video device.
  CPU, memory and duration are bounded. Optional `setup_assets` attach one
  disposable resources ISO for generalized-template initialization. Windows
  IMAPI builds it from pinned public guest assets plus an in-memory answer file.
  An optional pinned native probe and the fixed validation script are public
  files on that same media, rather than binary/code payloads over SSH.
  A random local guest password exists only in memory and the protected disposable
  ISO/guest disk, never config, journal, command arguments or logs. Its parent
  directory is Administrators/SYSTEM-only before the owned VM access grant.
  Before HCS creation, fixed Storage code mounts only the new child, guards
  against an explicit offline answer pointer, and writes the answer into
  `Windows\Panther\Unattend\unattend.xml` and its fixed specialization script.
  An existing empty directory is
  accepted; existing contents, links or unexpected ownership records are refused.
  The child is detached before native dispatch; the immutable parent stays pinned.
  No NIC, nested virtualization, audio,
  clipboard, personal share, cache endpoint or display streaming is configured.
- A differencing VHDX against a hash-pinned, read-only baseline. The baseline
  handle denies writes/deletion for the trial; it is not mounted, generalized,
  resized, granted new permissions, or otherwise modified by the spike.
- GPU-PV assignment after native start. Optional explicitly selected GPU driver
  directories are copied into the disposable child, bounded to 8192 files and
  2 GiB total. Only those copies are exposed as read-only Plan9 shares. The
  source directories' ACLs remain unchanged. Link/non-regular entries fail.
- A small implementation of the App Sandbox 0.1.9 guest initialization protocol,
  using fixed agent and SSH HvSocket service IDs. It handles driver-copy queries,
  enables guest SSH, deploys an ephemeral public key and requires display-driver
  readiness. SSH authenticates directly over the owned runtime's HvSocket; no
  host TCP listener or App Sandbox host key is used. When `render_probe` is set,
  fixed SSH code waits for setup and the intended console user, transfers the
  pinned native probe and runs it in an interactive guest scheduled task. It
  accepts only bounded fixed booleans/numbers, never arbitrary guest diagnostics.
  A small encoded launcher avoids the SSH shell command-length limit; trusted
  fixed entry code and metadata are separate fields of the small length-prefixed
  stdin JSON payload. The larger fixed script and probe arrive on setup media.
- A separate protected journal, child marker and exact HCS owner/runtime proof.
  An existing native name is never replaced. Creation is never replayed after
  response loss. Cleanup runs independently of caller cancellation, confirms
  native absence and only then removes the recorded disposable child. A foreign
  identity, uncertain query, failed deletion or missing ownership proof retains
  the journal. Creation intent and interrupted deletion have bounded recovery.
  A pending create without a visible native instance keeps its disk/journal:
  one absent lookup cannot exclude late completion. The cleanup command resolves
  it only after an exact native observation; an indefinitely absent ambiguous
  create needs operator investigation rather than automatic record deletion.
- Native errors contain an operation and HRESULT only. Guest agent text is
  bounded and discarded. Private SSH keys stay in memory; the config and journal
  contain no credentials. Filesystem protection validation is reused from the
  existing Windows adapter; that utility does not contact App Sandbox.

The spike deliberately uses `ShouldTerminateOnLastHandleClosed=true`: its VM
should terminate when its last HCS handle closes, including process loss. This
is a trial lifetime, not the CI provider's controller-crash adoption contract.
An independent cleanup command handles retained disk/journal state. The offline native
start/GPU/explicit termination/absence/storage cleanup path is validated.
Process-loss cleanup and recovery still need live validation.

## Checks without UAC

With the repository's Go toolchain available:

```powershell
go build -trimpath -o bin/hcs-spike/hcs-spike.exe ./cmd/hcs-spike
bin/hcs-spike/hcs-spike.exe check
bin/hcs-spike/hcs-spike.exe plan --config tools/windows/hcs-spike.example.json
# With an existing independent lab root named by the config:
bin/hcs-spike/hcs-spike.exe headroom --config <lab-config.json>
go test ./internal/hcsspike ./cmd/hcs-spike
```

`check` resolves system DLL exports and reports the process token, without
calling the HCS service, opening a VM, or reading the installed CI state.
`plan` validates the bounded JSON input and prints the proposed HCS document;
it neither opens the referenced paths nor proves that the image exists or boots.
The example contains synthetic paths, a sample ID and a placeholder hash.
`headroom` reads ordinary-token host counters and free space on the existing
trial root's filesystem. Its fixed numeric report includes `ready`; a successful
query can report `ready=false`. No image, VM, journal or production CI state is
opened or changed. For a 4 GiB trial it requires at least 10 GiB available
physical memory, 6 GiB commit headroom, 8 GiB free trial-volume space and two more
logical CPUs than the guest uses. Larger trials require their configured RAM
plus 6 GiB physical and 2 GiB commit headroom. Missing counters refuse admission.
The CLI checks before journal/template work; native preparation and HCS creation
recheck after staging. Cleanup does not depend on these checks. These are
point-in-time checks, not an exclusive reservation against other host users.
During a trial, a two-second watcher cancels only that trial if available physical
memory falls below 6 GiB, commit headroom below 2 GiB, volume space below 8 GiB,
or counters become unavailable. The trial's independent owned cleanup still runs;
no production controller, guest or network is stopped or changed.
Fake-backed tests exercise native-name collisions, create response loss, GPU
failure, changed ownership/runtime, interrupted intent/deletion, cancellation,
and the bounded guest protocol. These do not prove native behaviour.

`trial` and `cleanup` refuse an ordinary token before reading config or creating
files. They never request elevation. No startup task/service is installed.

For the smaller first native test, `trial --config <file> --boot-only` stops
after HCS reports a running runtime and accepts GPU assignment, then cleans up.
It skips the guest agent and SSH entirely. An independent copy of a generalized
Windows template is sufficient for this test, since it makes no claim that
Windows completed OOBE or that a desktop is usable. `native_started` reports
HCS running state only. The full trial requires either the specialized image or the explicit pinned
setup assets described below. Boot-only mode never claims guest readiness or authentication.

## Boot and readiness measurements

The spike emits numeric `timings_ms` in its report. Durations use the host's
monotonic clock, so guest setup changing its wall clock cannot change them.
`to_validated_desktop` measures from immediately before baseline verification
through successful setup, SSH, console and hardware-rendering validation. It
excludes host cleanup and is zero if those checks did not all pass. `total`
includes cleanup. Neither includes CLI/configuration validation and admission
before baseline verification. These are desktop prerequisites, **not** a time
to a registered/listening CI runner: this executable has no networking or runner
registration integration.

| Group | Durations (milliseconds) |
| --- | --- |
| `baseline_verify` | Read-only image hash verification |
| `lifecycle` | Preparation, HCS creation/start, GPU assignment, full guest probe, cleanup |
| `preparation` | Child clone, setup assets, ISO creation, offline answer staging, driver copy, payload permission grants |
| `guest` | Agent connection/initialization, SSH authentication/command checks, full desktop validation |
| `guest` checkpoint details | Console wait, GPU device wait, interactive native probe |

Preparation and guest details subdivide lifecycle spans; do not add the groups
again to calculate total. Checkpoint details measure the interval between host
receipt of fixed numeric markers, including possible SSH buffering/scheduling;
they are not guest CPU times. Zero can mean an unvisited/incomplete stage or a
stage shorter than one millisecond. Guest wait budgets also use a monotonic
stopwatch, with the same console/setup, GPU and interactive-task bounds.

The supplied existing-provider measurements show that cloning is inexpensive
(about 1.3 seconds), whereas native agent/SSH readiness takes 42-46 seconds and
console preflight 40-44 seconds. Together native startup and console preflight
account for about 87% of readiness in the original run. The inner console check
reported setup/OOBE flags already clear and console availability still pending;
its five 500-ms stability observations are only about two seconds of that wait.
The earlier animation-off comparison improved total readiness by about four
seconds, but one comparison is not evidence of a repeatable gain. These are
existing-provider results, not newly measured direct-HCS startup times.

First-logon animation is disabled during the owned child's specialize pass by
default, before first logon. Only `EnableFirstLogonAnimation` is changed; existing
policy values, authentication, setup completion, console stability, rendering,
resource admission and isolation checks remain intact. Prepared runtime images
bake this cosmetic policy during their one-time build. Ordinary-token checks,
race tests, vet, lint and compilation pass. Prepared-image cold-boot measurements
are recorded below; no paired existing-provider comparison has been run.

Use separate fresh instance IDs and immutable parent images for each control
and experiment. Keep CPU, RAM, selected host-matching GPU package and host load
comparable; run sequentially with the reserve guard, never by pausing production
CI. Collect repeated paired trials and report range/median with the individual
results. Retain only bounded numeric/boolean evidence. Every run must still
prove readiness/rendering and complete owned cleanup. Failed or cancelled runs
are failures, not fast samples.

The larger image-preparation candidates need separate validation:

- Preinstall the pinned agent, OpenSSH, display/input helpers, matching GPU
  payloads and public validation/runner files during an isolated image build.
  Measure avoided installation, copy and Plug and Play work. Keep credentials,
  runner registration, jobs and caches out of the reusable image.
- Evaluate Sysprep `/mode:vm` and preserved device installation only for matching
  virtual hardware. A generalized image still specializes on its next boot;
  preinstallation does not mean that setup was already completed for the clone.
- Build a prepared runtime image derived from the generalized source, as
  described below, and compare its fresh-child cold boots against provisioning
  boots. This changes the image used for jobs, rather than bypassing readiness.
- Sequential trials now verify the immutable image chain once per session and
  retain read-only handles denying writes/deletion. A future manager integration
  can use the same lifetime model; every new session still fully verifies hashes.

Microsoft documents [generalization and device preservation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation?view=windows-11),
[the next-boot specialize pass](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep-process-overview?view=windows-11)
and the cosmetic [first-logon animation policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation).

## Generalized source and prepared runtime images

Use two immutable artifacts with different purposes:

| Image | Purpose | Setup on a job's boot |
| --- | --- | --- |
| Generalized source | Reproducible image building and recovery | Specialization/OOBE still required if booted directly |
| Prepared runtime, derived from the source | Parent for disposable job disks | OS setup, package/driver installation and first profile creation already completed |

The builder boots an independent disposable source clone once, installs the
pinned guest components, matching GPU payload and public validation/runner
files, creates the CI user's profile, disables cosmetic animation and validates
a stable console and hardware rendering. It captures only after clean shutdown,
before runner registration or any job, then pins the derived image and its build
provenance. Do not generalize the derived runtime image again. Each job receives
a fresh differencing disk; the prepared parent stays read-only and unchanged.
This is a prepared disk image and ordinary cold boot, not a saved running VM
containing reusable memory, sockets or credentials.

The launcher requires an explicit `guest_computer_name` and pinned
`prepared_image` manifest, without `setup_assets` or per-boot driver copies.
The [prepared-image example](../tools/windows/hcs-spike-prepared.example.json)
uses this path. The declared name is bounded ASCII image metadata, bound with
the image hash in the protected configuration and journal. The guest check
still requires that exact name and intended local user. The generated HCS VM
name/owner and observed runtime ID remain fresh and ownership-checked; a common
Windows name never authorizes stopping/deleting another native instance.
Generalized provisioning continues assigning the generated native name, and
refuses an explicit prepared name. No wildcard guest identity check is added.

A prepared trial attaches no setup ISO, performs no offline answer staging, and
needs no `setup_assets`. With matching drivers already in its HostDriverStore,
it omits `drivers`, avoiding their host copy and guest installation. Its
preinstalled validation script must match this host build's embedded script hash;
the native probe must match its configured hash. Hash mismatch or incomplete
setup/console/rendering still fails admission. Ordinary planning and fake-backed
ownership tests cover this configuration. An independent image has now been
built, cleanly captured and booted successfully in three fresh trials; it has
not been promoted to production.

Per-job work is limited to a fresh owned disk/runtime, ephemeral SSH key handoff,
readiness/isolation proof and new runner registration. Those are runtime
admission steps, rather than Windows first-boot setup. Runner registration and
networking remain outside this spike, so its desktop timing is not a CI listener
time. Prepared trials reach the validated desktop in about 42 seconds after
session image verification, with all console/rendering gates retained.

Image promotion must remove runner registration, job files, authorized SSH keys
and transient setup material; GitHub/JIT credentials and host-held private keys
never enter the reusable image. Local Windows account/autologon state is retained
by specialized images, so its factory credential handling and per-clone rotation
uses the protected LSA secret and per-clone rotation implemented below; both
pass live factory/cold-boot validation. A prepared image is rebuilt when its
base, driver package or pinned helpers change. No external NIC or job is admitted
by this spike; provider integration and network isolation remain separate gates.

Microsoft describes [specialized images](https://learn.microsoft.com/azure/virtual-machines/shared-image-galleries#generalized-and-specialized-images)
as already past first boot, with faster startup and retained account/computer-name
state. That supports the two-image approach; the local HCS implementation still
requires its own image and lifecycle validation.

## Elevated trial prerequisites

Prepare and review the following before requesting an elevated launch. Keep
existing controllers, daemons, runners, labels, baselines and networking intact.
Check CPU, physical memory, commit and disk headroom before adding another VM;
the spike is outside the manager's admission budget. An offline VM still consumes
shared CPU, RAM and GPU resources, so concurrent validation needs explicit
operator agreement on those resources.

1. Use a **separate clean, unenrolled Windows image**. A specialized image must
   have the App Sandbox guest service, signed indirect display driver, local
   autologin and OpenSSH available offline. For rendering, preinstall the pinned
   probe as `Windows\AppSandbox\hcs-render-probe.exe` and this build's exact
   `guest_validate.ps1` as `Windows\AppSandbox\hcs-spike-validate.ps1`. A generalized
   template instead needs
   `setup_assets` as in `hcs-spike-guest.example.json`: the agent, display/input
   helpers, VDD DLL/INF/CAT and devcon, plus an offline OpenSSH MSI when the image
   lacks sshd. Every source must be administrator-protected and SHA-256 pinned.
   Generalized-template provisioning also requires Windows Storage PowerShell
   cmdlets and the system offline-registry library. Only the newly recorded
   child is mounted read-write for answer staging. The explicit offline setup
   answer pointer must be absent/empty and the embedded answer directory must
   be absent/empty; images requiring replacement of existing contents are refused.
   Fixed first-boot code runs only in the disposable guest; it initializes the
   local account/autologin, VDD, SSH and guest agent. Never use a live runner's
   disk, export an enrolled guest, or change the production baseline. The image
   must contain no host credentials, repository state or configured runner.
   Leave guest disk encryption/BitLocker disabled; each clone receives fresh
   virtual TPM and firmware state rather than the preparation VM's saved state.
2. Under an independent administrator-protected storage chain, create an empty
   directory whose basename is `HCS-Spike`. Keep the image and optional driver
   source directories outside it. Owners must be Administrators, SYSTEM or
   TrustedInstaller, without ordinary-user mutation rights or reparse points;
   ancestors must not allow replacement. Pregrant VM read access to this test
   baseline through image preparation: the spike will not edit its ACL.
3. Copy the example config into that protected chain, replace all paths and the
   hash, select only the needed host-matching GPU DriverStore payloads, and
   generate a fresh 16-byte lowercase hexadecimal `instance_id`. The example
   identity must not be reused for independent trials. Driver destinations are
   restricted to the guest `C:\Windows\System32\HostDriverStore\FileRepository` tree.
   Automatic driver discovery, vendor runtime/shim packaging and OpenGL/Vulkan
   mapping-layer preparation are outside this spike. A prepared image may
   already contain the required drivers; then `drivers` can be omitted.
4. Build a distinct spike executable, review/pin it in the protected staging
   directory, and run `check` and `plan` before arranging elevation. Do not run
   the existing engine startup helper or replace the installed manager/broker.
5. In the explicitly approved elevated context, run only
   `hcs-spike.exe trial --config <protected-config.json>`. It creates at most
   one offline guest, probes the fixed agent/SSH endpoints and disposes of it.
   There is no App Sandbox API/discovery/registry connection. The existing
   daemon can remain running: this tests independence without stopping CI.
6. Inspect the numeric/boolean result and any retained journal. If cleanup did
   not finish, use the same executable/config in the approved elevated context:
   `hcs-spike.exe cleanup --config <protected-config.json>`. Do not erase records
   or stop another VM to make cleanup succeed. A modified owner, marker or
   configuration is a refusal, not an invitation to bypass proof.

Success reports `agent_connected`, `gpu_assigned` (when requested),
`display_ready`, `ssh_authenticated`, `ssh_command_ready`, `ssh_stdin_ready` and
`cleaned`. With a rendering probe, the actual authenticated framed validation request
proves command and stdin execution; without it, two fixed smoke requests do so. These mean that HCS accepted
GPU assignment, the guest agent reported the display driver ready, SSH actually
authenticated, and cleanup completed. With `render_probe`, success also requires
`guest_ready`, `desktop_ready`, `hardware_d3d11`, `presented` and `pixel_readback`.
The native probe is compiled from `tools/windows/hcs-render-probe.cpp` with a
Windows C++ compiler and linked against d3d11, dxgi, user32 and gdi32. It checks
two colors in both the render target and the composited desktop, enumerates at
most 32 adapters, explicitly selects hardware and rejects WARP/software adapters.
Only bounded booleans, adapter counts, numeric IDs and HRESULTs are returned.
No keyboard/mouse input or cross-reboot/crash recovery is covered. Agent/SSH
success alone does **not** establish hardware rendering or presentation. Neither trial establishes focus/input, fresh-state reset,
host/private-peer isolation, or production readiness. Those require subsequent
disposable-guest tests. No NIC is attached during this first trial, and no network-isolation
claim is made. All App Sandbox guest drivers/services remain dependencies until
separately replaced or packaged and maintained.

For a diagnostic retry, `trial --retain-failed-storage` keeps failed storage
only after stopping the VM and confirming native absence. `native_absent=true`
and `storage_retained=true` mean it is safe to arrange explicit read-only
inspection of that recorded stopped clone. A create that may still complete
never qualifies. Do not mount a live/ambiguous clone or a production disk.
After detaching the inspected clone, use the matching `cleanup` command; it
revalidates ownership and native absence before removing the child. Routine
trials still clean up automatically, including on failure. Offline diagnostics
must emit only bounded flags/codes, never raw setup logs or answer-file contents.

## Prepared runtime images

The image builder and runtime path are implemented here, separate from the
production CI provider. Build once from an independent generalized source;
never export an enrolled runner or production disk. No network or runner
registration is involved in this experiment.

1. Prepare the independent protected `HCS-Spike` root and pinned source/assets
   described above. Create its sibling `HCS-Images` with protected inheritance:
   Administrators/SYSTEM full access and VM worker group (`S-1-5-83-0`) read/execute
   only. Do not grant ordinary-user read access: the prepared disk contains local
   account state. The generalized source must be a standalone VHDX.
2. Start from [`hcs-spike-build.example.json`](../tools/windows/hcs-spike-build.example.json).
   Pin an official Windows runner ZIP as `RUNNER.ZIP`, public guest components,
   the native probe and the independent source. The runner archive is extracted
   once with path/stream/link/duplicate and expansion bounds; no runner is run or
   registered. Use a fresh `instance_id`, review `check`, `headroom` and `plan`,
   and arrange explicit elevation only when the operator is present.
3. Run `hcs-spike.exe build-image --config <protected-build-config.json>`.
   The guarded guest must finish setup, profile creation and hardware rendering.
   Fixed sanitation refuses registered-runner/work state, removes cached answer
   files and SSH keys, randomizes the local password and configures fresh server
   host keys at boot before enabling sshd and then the guest agent. Sanitation and shutdown run in one SSH
   operation so another SSH process cannot recreate factory keys before capture.
   Autologon uses an LSA secret. Only acknowledged guest OS shutdown, a successful native `GracefulExit`
   and confirmed native absence permit copying the owned child into the exclusive
   image directory and publishing `manifest.json` last. The source child is then
   cleaned up. No baseline is mounted or modified by the builder.
4. Review `<HCS-Images>/<build-id>/trial.json` and the manifest. The former is
   the generated runtime config; the
   [prepared example](../tools/windows/hcs-spike-prepared.example.json) shows its
   shape but uses placeholder hashes. Keep the published disk and its recorded
   generalized parent in place. Runtime configuration pins the manifest, which
   binds image/parent hashes, guest identity, build owner, public helper hashes and
   the exact sanitation implementation.
5. In a separately approved elevated context, run
   `hcs-spike.exe trial --config <generated-trial.json> --repetitions 3`.
   Repetitions (1-5) are sequential fresh cold boots, not saved-memory resumes.
   The session verifies both immutable disks once and keeps deny-write/delete
   handles open. Subsequent reports mark `baseline_reused`; only the first
   includes baseline verification time. Every clone gets fresh native identity,
   SSH client identity and local credential rotation, and still proves stable console,
   hardware rendering and clean removal. Setup media, installations and driver
   copies are absent. Prepared repetitions require distinct valid public server-key
   fingerprints. Any failure or retained storage prevents the next boot.
6. If `--retain-failed-storage` was explicitly selected, inspect only a stopped
   clone whose report confirms native absence. Match the report's `instance_id`
   to its journal/owner marker. After detaching, run
   `cleanup --config <matching-config.json> --instance-id <reported-id>`.
   Build cleanup removes only owned unpublished staging. Published images and
   their manifests are preserved; do not erase ownership evidence manually.

Compare host-monotonic `timings_ms.to_validated_desktop` and its preparation,
agent, SSH and console breakdown across cold boots. The build is a one-time cost;
first-session hashing is separately visible. There is no runner-listening time
in this offline spike, so it cannot yet establish clone-to-job latency.

A live independent corrected build completed in 184.604 s, including factory
setup, rendering, sanitation, acknowledged guest shutdown, native `GracefulExit`,
publication and source cleanup. Three fresh prepared cold boots then passed:

| Fresh boot | Validated desktop | Session image verification | Agent connection |
| --- | --- | --- | --- |
| 1 | 54.666 s | 11.664 s | 30.506 s |
| 2 | 41.753 s | reused | 30.510 s |
| 3 | 42.474 s | reused | 30.520 s |

Every boot presented a distinct SSH server key, all different from the factory
key, rotated its local credential, and passed authenticated SSH, console,
hardware D3D11, presentation and pixel checks. Setup-media, answer-staging and
driver-copy times were zero. Native absence and owned cleanup passed after every
boot. These are offline desktop timings, not Windows runner-listening/job times
or a paired comparison with the existing provider.

The repeatable 30.5-s agent connection plateau used two dial attempts per boot,
with one taking about 30 s. The earlier HvSocket implementation did not cancel
its pending native connect when the attempt context expired. The spike now owns
event-based overlapped Winsock transport for both agent and SSH connections.
Timeout, close and changed deadlines wake the wait. Cancellation requests
`CancelIoEx` and drains completion before releasing pinned buffers and events;
close waits for admitted operations before closing the socket and owned native
references. The agent attempt remains three seconds, and the SSH dial remains
within the guest budget. No background attempt is abandoned, no dependency or
production transport is patched, and no readiness check is removed. Ordinary-
token native socket regressions pass; new cold-boot timings remain pending.

Sanitation and shutdown run in one SSH operation to avoid recreating factory
keys through another SSH process. The boot task keeps both sshd and the guest
agent disabled until fresh keys exist, then starts SSH before the agent. The
manifest binds sanitation code, so images made with older sanitation are refused.
Repeated prepared trials reject missing or repeated public server fingerprints.
The corrected image passed this gate on all three cold boots.

## Desktop validation checkpoints

`guest_validation_step` retains only an allowlisted number from the SSH stderr
sink. After parsing the payload, the same number is written to a fixed file in
the disposable guest for explicit stopped-clone inspection. A checkpoint marks
entry into a stage, not its completion.

| Step | Stage entered |
| --- | --- |
| 1 | Read the four-byte frame length |
| 4 | Read the bounded frame payload |
| 2 | Decode and parse the received UTF-8 payload |
| 3 | Invoke the embedded validation script |
| 17 | Verify the intended guest identity |
| 19 | Compile the fixed console API bindings |
| 20 | Wait for stable setup/console readiness |
| 21 | Create and protect the private probe directory |
| 22 | Write and verify the pinned native probe |
| 26 / 27 | Start / finish the bounded read-only GPU device readiness wait |
| 23 | Register the interactive guest task |
| 24 | Start the task and wait for its bounded report |
| 25 | Read and return fixed report fields |

Never copy raw guest stderr, setup logs or answer files into diagnostics.

## References

The machine definition and guest protocol were checked against the pinned
[App Sandbox 0.1.9 HCS implementation](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/hcs_vm.c),
[agent initialization](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/vm_agent.c)
and [SSH proxy](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/vm_ssh_proxy.c).
No upstream binaries, drivers, images or keys are vendored. Microsoft's
[HCS overview](https://learn.microsoft.com/en-us/virtualization/api/hcs/overview)
defines the ephemeral compute-system lifecycle. The pure-Go
[`go-winio`](https://github.com/microsoft/go-winio/tree/v0.6.2) dependency supplies
HvSocket address types and the VHDX ABI at its already-selected version. The
spike's transport uses documented [ConnectEx](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex)
and [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
with explicit operation/buffer lifetimes. It adds no cgo requirement. Start/terminate pass native NULL for the
reserved options parameter, as required by Microsoft's
[start](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsstartcomputesystem)
and [terminate](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsterminatecomputesystem)
contracts; regression tests reject substituting an empty JSON document.

Basic compute-system identity/state uses the default query, not a `"Basic"`
selector: see Microsoft's [schema-2 property query](https://github.com/microsoft/hcsshim/blob/main/internal/hcs/schema2/property_query.go)
and [property types](https://github.com/microsoft/hcsshim/blob/main/internal/hcs/schema2/property_type.go).

Windows answer-file behavior follows Microsoft's [unattended setup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/automate-windows-setup)
and [offline account-screen setting](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-oobe-hideonlineaccountscreens).

Removable-media answer-file naming follows Microsoft's [implicit search order](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview#implicit-answer-file-search-order).

Embedded child-answer precedence uses the same documented search order. The
[offline registry library](https://learn.microsoft.com/en-us/windows/win32/devnotes/offline-registry-library-portal)
checks the explicit pointer without mounting hives in the host registry or saving
modified hives.

Specialization uses a fixed script path to respect the documented
[`RunSynchronousCommand/Path` limit](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-deployment-runsynchronous-runsynchronouscommand-path).
First-logon commands are separately checked against their
[`CommandLine` limit](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-firstlogoncommands-synchronouscommand-commandline).

Windows OpenSSH initially uses [cmd.exe as its default shell](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration).
The small SSH launcher stays below its [command-line limit](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation)
without changing the guest or host shell configuration.

Prepared-image shutdown uses a fixed authenticated guest-only command, followed
by [`HcsWaitForComputeSystemExit`](https://learn.microsoft.com/virtualization/api/hcs/reference/hcswaitforcomputesystemexit)
on the same held native handle. The bounded result must report zero status and
`GracefulExit`; forced/unexpected/unknown exits, missing acknowledgements, timeout
and native absence alone refuse capture. A live trial passed sanitation and
rendering but returned `ERROR_NOT_SUPPORTED` for the host-initiated HCS shutdown
API. The guest-requested path now passes live clean capture and repeated cold
boots without treating forced termination or native absence alone as success.
