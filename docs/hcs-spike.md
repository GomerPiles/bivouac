# Direct HCS Windows spike

`cmd/hcs-spike` is a separate executable exploring removal of the App Sandbox
host application and daemon. It is not a manager provider and has no GitHub,
CI-mode, runner-registration, production configuration or broker API. Building
it does not replace `bivouac`.

## Validated native trial

An approved offline trial against an independent immutable template copy reached
HCS `Running` state, accepted post-start GPU-PV assignment, explicitly terminated
the owned VM, confirmed native absence and removed its journal/disposable child.
The trial root contains only its lock file. The protected lab retains the
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

## What is implemented

- HCS schema 2.1 generation for an offline Windows amd64 VM, UEFI Secure Boot,
  guest/runtime state files, virtual keyboard/mouse and a basic video device.
  CPU, memory and duration are bounded. Optional `setup_assets` attach one
  disposable resources ISO for generalized-template initialization. Windows
  IMAPI builds it from pinned public guest assets plus an in-memory answer file.
  A random local guest password exists only in memory and the protected disposable
  ISO/guest disk, never config, journal, command arguments or logs. Its parent
  directory is Administrators/SYSTEM-only before the owned VM access grant.
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
go test ./internal/hcsspike ./cmd/hcs-spike
```

`check` resolves system DLL exports and reports the process token, without
calling the HCS service, opening a VM, or reading the installed CI state.
`plan` validates the bounded JSON input and prints the proposed HCS document;
it neither opens the referenced paths nor proves that the image exists or boots.
The example contains synthetic paths, a sample ID and a placeholder hash.
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

## Elevated trial prerequisites

Prepare and review the following before requesting an elevated launch. Keep
existing controllers, daemons, runners, labels, baselines and networking intact.
Check CPU, physical memory, commit and disk headroom before adding another VM;
the spike is outside the manager's admission budget. An offline VM still consumes
shared CPU, RAM and GPU resources, so concurrent validation needs explicit
operator agreement on those resources.

1. Use a **separate clean, unenrolled Windows image**. A specialized image must
   have the App Sandbox guest service, signed indirect display driver, local
   autologin and OpenSSH available offline. A generalized template instead needs
   `setup_assets` as in `hcs-spike-guest.example.json`: the agent, display/input
   helpers, VDD DLL/INF/CAT and devcon, plus an offline OpenSSH MSI when the image
   lacks sshd. Every source must be administrator-protected and SHA-256 pinned.
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
   restricted to the guest `C:\Windows\HostDriverStore\FileRepository` tree.
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
`display_ready`, `ssh_authenticated` and `cleaned`. These mean that HCS accepted
GPU assignment, the guest agent reported the display driver ready, SSH actually
authenticated, and cleanup completed. With `render_probe`, success also requires
`guest_ready`, `desktop_ready`, `hardware_d3d11`, `presented` and `pixel_readback`.
The native probe is compiled from `tools/windows/hcs-render-probe.cpp` with a
Windows C++ compiler and linked against d3d11, dxgi, user32 and gdi32. It checks
two colors in both the render target and the composited desktop, rejects WARP
and other software adapters, and leaves only bounded boolean/numeric results.
No keyboard/mouse input or cross-reboot/crash recovery is covered. Agent/SSH success alone does **not** establish hardware rendering or
presentation. Neither trial establishes focus/input, fresh-state reset,
host/private-peer isolation, or production readiness. Those require subsequent disposable-guest
tests. No NIC is attached during this first trial, and no network-isolation
claim is made. All App Sandbox guest drivers/services remain dependencies until
separately replaced or packaged and maintained.

## References

The machine definition and guest protocol were checked against the pinned
[App Sandbox 0.1.9 HCS implementation](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/hcs_vm.c),
[agent initialization](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/vm_agent.c)
and [SSH proxy](https://github.com/jamesstringer90/appsandbox/blob/v0.1.9/src/backend_win/vm_ssh_proxy.c).
No upstream binaries, drivers, images or keys are vendored. Microsoft's
[HCS overview](https://learn.microsoft.com/en-us/virtualization/api/hcs/overview)
defines the ephemeral compute-system lifecycle. The pure-Go
[`go-winio`](https://github.com/microsoft/go-winio/tree/v0.6.2) dependency handles
HvSocket transport and the VHDX ABI, reusing the version already selected by the
existing dependency graph. The spike adds no cgo requirement. Start/terminate pass native NULL for the
reserved options parameter, as required by Microsoft's
[start](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsstartcomputesystem)
and [terminate](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsterminatecomputesystem)
contracts; regression tests reject substituting an empty JSON document.

Basic compute-system identity/state uses the default query, not a `"Basic"`
selector: see Microsoft's [schema-2 property query](https://github.com/microsoft/hcsshim/blob/main/internal/hcs/schema2/property_query.go)
and [property types](https://github.com/microsoft/hcsshim/blob/main/internal/hcs/schema2/property_type.go).

Windows answer-file behavior follows Microsoft's [unattended setup](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/automate-windows-setup)
and [offline account-screen setting](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-oobe-hideonlineaccountscreens).
