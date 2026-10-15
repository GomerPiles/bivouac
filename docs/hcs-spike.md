# Direct HCS Windows spike

`cmd/hcs-spike` is a separate executable exploring removal of the App Sandbox
host application and daemon. It is not a manager provider and has no GitHub,
CI-mode, runner-registration, production configuration or broker API. Building
it does not replace `bivouac`.

## Current elevated attempt

The first approved native-only attempt stopped before VM creation because a
post-grant protection check rejected the intended VM-account payload ACE.
Disk/state-file preparation and automatic cleanup completed; the trial root
contains only its kernel lock file. The protected lab retains the independent
image, pinned tested executable, configuration and fixed progress/result files
for inspection. Nothing was installed into startup and no production controller
was changed. The corrected source now snapshots exact payload identity/ACLs
after the native VM access grant, with administrator-only checks before granting
and separate strict journal/marker checks. It needs a new reviewed executable
and explicitly approved elevated retry. The staged executable remains the
original tested version; it is not silently replaced from the worktree.

## What is implemented

- HCS schema 2.1 generation for an offline Windows amd64 VM, UEFI Secure Boot,
  guest/runtime state files, virtual keyboard/mouse and a basic video device.
  CPU, memory and duration are bounded. No NIC, nested virtualization, audio,
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
  host TCP listener or App Sandbox host key is used. No guest command is executed.
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
An independent cleanup command handles retained disk/journal state. Native
termination, handle-close behaviour and VM cleanup still require live validation.

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
HCS running state only. The full trial still requires the specialized image
described below. Boot-only mode never claims guest readiness or authentication.

## Elevated trial prerequisites

Prepare and review the following before requesting an elevated launch. Keep
existing controllers, daemons, runners, labels, baselines and networking intact.
Check CPU, physical memory, commit and disk headroom before adding another VM;
the spike is outside the manager's admission budget. An offline VM still consumes
shared CPU, RAM and GPU resources, so concurrent validation needs explicit
operator agreement on those resources.

1. Prepare a **separate specialized, clean, unenrolled Windows image**, shut down
   with the App Sandbox guest service, signed indirect display driver, local
   autologin and OpenSSH available offline. A generalized App Sandbox template
   is not directly interchangeable: this spike does not yet generate its
   per-instance setup/resources ISO or automate OOBE. Never use a live runner's
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
authenticated, and cleanup completed. They do **not** establish hardware D3D
rendering, presentation, focus/input, fresh-state reset, host/private-peer
isolation, or production readiness. Those require subsequent disposable-guest
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
