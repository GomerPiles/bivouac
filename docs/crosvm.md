# Linux GPU guests on Windows

The experimental `crosvm` provider runs Linux/amd64 with WHPX and gfxstream
while preserving the separate App Sandbox Windows provider. It needs no
administrator token once Windows Hypervisor Platform and the GPU driver are
installed. The operator approved normal trusted-job cutover after isolated
validation. Remaining hostile-network tests still require operator review;
this does not establish isolation for arbitrary untrusted workflows.

The normal manager owns GitHub authentication, budgets and durable lifecycle
state. A detached Go supervisor owns one native Windows job object containing
the VM and every device child. Atomic process creation assigns that job before
execution. Closing its last handle kills the group. Controller restart adopts
the supervisor; supervisor loss retires the guest. Recovery verifies the
recorded PID/creation-time/image and the independently journalled named job,
confirms native processes are absent, then deletes the owned QCOW overlay.
A PID now held by a process with another creation time or executable name
proves the recorded one exited (Windows reuses PIDs, notably after reboot).
The supervisor is started with `CREATE_BREAKAWAY_FROM_JOB`, so a kill-on-close
job around the controller cannot kill adoptable VMs; if that job forbids
breakaway, the supervisor starts inside it and the launch log says so.

An ambiguous launch is never retried. A launch intent without supervisor
state is abandoned only after writing `stop`, confirming the dispatched
supervisor (`dispatch.json`) has exited, and holding the instance lock that
every supervisor keeps for its whole life. New instance directories
appear by renaming a staging directory that already holds both markers;
marker-only staging left by a crash is swept on open. Unknown files,
unmarked or mismatched directories and contradictory process identities
(same PID and creation time, different image) are listed as unmanaged and keep
ownership and capacity for inspection. Deletion also removes the instance's
pinned known_hosts file.

Paths are canonicalized when the backend opens: each existing file is named by
its final path, with symlinks, junctions and mount points followed, short
names expanded and stored case kept. Running images are resolved the same way,
because `QueryFullProcessImageName` keeps the spelling an image was opened with,
including short names; recorded images compare case-insensitively. An existing
path that cannot be resolved is refused. `provider.json` may change only while
the root holds no instance directory; each instance envelope pins its own configuration.
Recorded options are compared in canonical form, so records written with
another spelling of the same paths stay owned; `provider.json` is then
rewritten canonically, while envelopes and markers are left as written.

## Prerequisites

- A separately staged, tested Crosvm runtime with the packet filter in
  [`tools/crosvm`](../tools/crosvm/README.md). Stock Slirp is not sufficient:
  its guest traffic becomes host sockets, so VM-port VFP rules do not apply.
- A local operator-managed raw Linux disk and matching SHA-256-pinned
  kernel/initrd. The baseline supplies a dedicated non-root user, SSH key
  authentication, noninteractive guest sudo, generic Git/Docker, an unconfigured
  official runner under `/opt/actions-runner`, and a virtio/gfxstream runtime.
  NetworkManager's active eth0 profile is configured to ignore DHCP DNS and
  persist public resolvers in each clone. Other images need a static unmanaged
  resolver file. Writing through a systemd-resolved symlink alone is temporary.
  Do not bake in repositories, configured runners or registry credentials.
- For container GPU jobs, a generic CDI device `ci.local/gpu=all` described by
  `/etc/cdi/ci-gpu.json`, containing the guest render device and matching guest
  driver libraries. These are guest paths; no host directory/socket is shared.
- The matching static Linux/amd64 Bivouac helper, system OpenSSH on the host,
  and the dedicated guest SSH private key. The GitHub App key stays in the
  host credential store. JIT input travels over SSH stdin into a private,
  single-use guest file, never a host file or command argument.
- Enough free instance-volume space for the complete possible growth of every
  retained raw-sized overlay, QCOW metadata, 256 MiB of native logs and a
  16 GiB host reserve. This is conservative disk admission, not a filesystem
  quota. Other programs can still consume host disk space after admission.
  The supervisor caps `native.log` at 64 MiB and retires the guest once it or
  the directly written `serial.log` reaches 64 MiB (checked once per second).

The tested generic image uses Ubuntu 26.04.1, kernel 7.0.0-30-generic, Docker
29.9.0, Git 2.53.0 and Runner 2.338.0. Mesa 26.0.8 gfxstream exposes native
host Vulkan through the virtio render device. Windowed jobs supply their own
Wayland compositor inside the guest/container. The tested presentation path
copies completed hardware-rendered frames through wl_shm with
`MESA_VK_WSI_DEBUG=sw`; it does not promise direct display scanout or DMA-BUF
presentation. There is no emulated Windows desktop in this provider.

## Prepared images and startup measurements

The baseline already supplies installed packages and an unconfigured runner.
Job clones do not reinstall them. A prepared baseline can additionally contain
the exact selected helper at `/usr/local/libexec/bivouac-guest`, with root-owned
ancestors and no group/other mutation permissions. Readiness verifies ownership,
links and SHA-256 before executing that helper. A missing/stale helper falls back
to upload; a failed SSH connection does not. Both paths still perform current
ownership, GPU/CDI, runner-state and network-policy checks.

DNS already configured correctly in the image is verified and reused. Readiness
checks the persistent NetworkManager profile, active upstreams and resolver;
repairs only incorrect state, then verifies the result. A local resolved stub is
accepted only with independently confirmed public upstreams. No native network
filter, host-prefix guard or per-clone JIT requirement is skipped.

Structured `linux startup stage` records include durations for clone, native
start, SSH availability, helper check/upload, bootstrap, cache setup, JIT delivery
and listener launch. Guest bootstrap adds DNS/helper/total durations plus reuse
and mutation flags. Existing manager clone/boot/registration timings cover the
full path through listening. Durations are monotonic; nested spans overlap and
must not be summed with their parent. Explicit validation returns fixed numeric
systemd activation timestamps for SSH, Docker, network wait and cloud-init.
They do not measure service activation duration or establish a critical path.
Use [systemd-analyze](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)
on an isolated clone for dependency analysis before disabling any service.

The explicit guest factory operation is `guest linux prepare-image`, invoked as
guest root with JSON on stdin containing `name`, `controller_id`, `boot_id` and
`helper_sha256`. These must match a fresh, owned, unregistered bootstrap and the
selected helper. It installs the protected helper, prepares DNS, sanitizes bounded
factory runner logs, clears the factory machine-id/random seed/SSH host keys and
installs a systemd prerequisite to generate host keys before ssh.service. It
refuses credentials, nonempty job work, worker logs, unknown files and links.
It removes only its two proven bootstrap files and records public provenance at
`/etc/bivouac/prepared-image.json`. No package download or runner registration
occurs. Never invoke factory preparation in a production guest or on the host.

The host factory entry point is:

```powershell
bivouac crosvm build-image --options native-options.json --helper D:\RunnerTools\bivouac-linux-amd64 --cpu 2 --memory-mb 2048 --output-root D:\ImageBuild\Linux-Images
```

The output directory must be absent, absolute, named `Linux-Images` and outside
disposable instance storage. Use an independent root/controller/options file;
never point a factory at production ownership state. The command bootstraps a
fresh clone, validates absence of a listener, runs sanitation and schedules a
short guest-only clean-shutdown timer. The host must receive an acknowledgement,
then prove natural exit code zero, an empty recorded process group and absence
of the supervisor/VM. It checks the overlay backing metadata again before
one-worker `qemu-img convert` creates a raw image. Output geometry and flush must
pass before `manifest.json` is published last. It never overwrites an image or
changes the source; source cleanup uses the normal ownership contract. One-time
conversion may read the complete source; no such IO is added to job boot.
A failed conversion keeps only unpublishable owned staging for inspection.

The manifest is public provenance, not a new whole-image digest contract. Raw
contents remain operator-managed, with the same per-clone metadata/backing checks
as existing images. Keep the selected helper binary whose hash the image contains;
rebuilding/changing it requires a new image for reuse or the normal upload path.

Create another independent options/root/controller with `baseline` pointing to
`<Linux-Images>/disk.raw`, then run sequential cold trials:

```powershell
bivouac crosvm validate --options prepared-options.json --helper D:\RunnerTools\bivouac-linux-amd64 --cpu 2 --memory-mb 2048 --require-prepared
```

`--require-prepared` fails if the exact helper is unavailable or any DNS repair
is needed. Its bounded report includes SHA-256 fingerprints of machine-id and
the server's public host key; compare multiple fresh clones for distinct values.
No private key or raw machine identity is returned. Every trial must finish with
owned processes/overlay/SSH pin removed before another starts.

Production use still needs provenance review and repeated cold-boot validation
of the independently captured baseline, followed by the normal explicit deployment
procedure.
Do not generalize/reset a captured image again or deploy a partially prepared
image. Confirm distinct machine IDs and server host keys across clones, absence
of runner/job/credential state, public DNS, GPU/CDI readiness and complete cleanup.
The designated SSH authorization public key is retained; private client keys,
GitHub/JIT credentials and repositories never belong in the baseline. Empty
[machine-id](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html)
provides a new identity without requesting the missing-file first-boot path.

`crosvm validate --exercise-prepared-image` exercises factory preparation and
requires actual helper/DNS reuse within the same running test clone, then deletes
it. **It publishes no image and does not prove a prepared cold boot or key renewal.**
Use a separate options file/root/controller ID, bounded resources and the filtered
runtime. This validation is credential-free and uses no CI runner labels. It
requires ordinary-user WHPX availability, not UAC. It admits only with spare
memory/commit, watches reserves every two seconds and cancels only its test guest
if physical availability falls below 6 GiB or commit headroom below 2 GiB.

One isolated 2-CPU/2-GiB trial observed 3.182 s upload bootstrap versus 0.962 s
prepared reuse in the same VM; DNS was 121 ms with a repair versus 32 ms without
writes. Those numbers do not establish a cold-start speedup. A subsequent explicit
build passed clean shutdown/native absence and captured a new raw image with
published provenance; its source clone was removed. Three sequential fresh
prepared cold boots passed in 12.313 s, 10.738 s and
10.884 s through guest readiness. Each proved exact helper/DNS reuse, distinct
machine and SSH-host-key fingerprints, runner/GPU/CDI readiness and cleanup.
These host-monotonic stage sums exclude runner registration/listening. The
prepared baseline also passed provider reopen/adoption and intentional recorded
supervisor-loss cleanup. An independent manager reached real JIT listening in
16.887 s (404 ms clone, 11.495 s readiness, 4.988 s registration/listening),
then Off deregistered its idle runner and fully cleaned up. Actual job execution
on the prepared baseline remains a promotion gate. The repository CI workflow
has an explicit `workflow_dispatch` input, `prepared_linux`, for two sequential
smoke jobs on the dedicated `bivouac-linux-prepared-validation` label. Leave the
input false for normal hosted checks. Provision that label only in an independent
one-runner validation home; the smoke checks helper reuse, fresh sentinel state,
GPU/CDI, Docker, DNS and public HTTPS without repository credentials or checkout.
The installed production image/provider remains unchanged.

## Isolated configuration

Keep production controllers and labels unchanged. Use a separate
`BIVOUAC_HOME`, one-job budget, `github.demand = "jit"`, organization URL and
the approved App's credential-store item. Example provider settings:

```toml
[providers.linux]
type = "crosvm"
labels = ["self-hosted", "Linux", "X64", "bivouac-linux-experimental"]
idle_pool = 1
max_instances = 1

[providers.linux.crosvm]
experimental = true
root = 'D:\RunnerVMs\LinuxInstances'
binary = 'D:\RunnerTools\Crosvm\crosvm.exe'
binary_sha256 = "<64 hexadecimal digits>"
qemu_img = 'D:\RunnerTools\Qemu\qemu-img.exe'
baseline_name = "ci-linux"
baseline = 'D:\RunnerImages\generic-linux.raw'
kernel = 'D:\RunnerImages\vmlinuz'
kernel_sha256 = "<64 hexadecimal digits>"
initrd = 'D:\RunnerImages\initrd.img'
initrd_sha256 = "<64 hexadecimal digits>"
helper = 'D:\RunnerTools\bivouac-linux-amd64'
user = "ciuser"
cpu = 4
memory_gb = 4
gpu = true
# ssh_key = 'D:\RunnerKeys\guest-key'
```

No arbitrary flags, host shares, public port forwarding, private DNS resolver
or host cache exception is accepted. The optional Actions/release download cache
uses a cache-only guest-loopback SSH listener, with no NIC exception or host
directory share. Configure `[cache]` as described in `docs/windows.md`; host
listen/guest identity must be literal loopback. Linux installs trust only inside
the disposable guest and inherits proxy/preload settings in runner children.
Containers with independent environments/trust are a separate integration.
External managers are not
automatically inventoried: keep them stopped during validation and reserve
their resources explicitly before any concurrent operation.

`doctor --github` checks local tools/helper/disk admission and authenticates
runner access without starting a VM or registering a runner. It checks the
executable/kernel/initrd digests. Baseline checks use its path, regular-file size
and each overlay's exact backing metadata; the image contents are never hashed
by the provider, including at clone creation, supervisor startup or doctor.
There is no baseline digest option or cached verification. Static tool hashes
are checked by doctor only, not repeated at VM creation or supervisor startup.
`on` records mode; run the ordinary controller
with `bivouac run`. `off` drains and exits, including the cache service. The
optional ordinary-user Windows login task is explicitly installed; privileged
prerequisites stay operator-managed and startup is uninstalled by default.

Build updates under a new executable filename while a manager or VM supervisor
is running. Go builds on Windows can rename a live destination executable,
changing its native process image path and invalidating ownership verification.
Switch configured binaries only after Off and confirmed empty ownership journals;
never erase a retained record to bypass an identity mismatch.

The explicit credential-free test accepts a JSON `Options` object matching
the native fields above plus `name` and the isolated `controller_id`:

```text
bivouac crosvm validate --options native-options.json --helper D:\RunnerTools\bivouac-linux-amd64 --cpu 2 --memory-mb 2048 --exercise-recovery
# Optional separate factory/reuse trial; no image is published:
bivouac crosvm validate --options native-options.json --helper D:\RunnerTools\bivouac-linux-amd64 --cpu 2 --memory-mb 2048 --exercise-prepared-image
```

It creates one recorded clone, proves generic guest/GPU readiness, reopens and
adopts its provider, intentionally kills only the recorded supervisor, then
confirms teardown. `crosvm cleanup --options native-options.json --name
bivouac-linux-1234abcd` retries an exact retained native validation instance.
Use normal manager cleanup for registered runners so GitHub deregistration
remains journalled too. Never erase a record or marker to force cleanup.

## Networking and remaining gates

The native filter admits public IPv4 before libslirp creates host sockets.
Reserved/private/link-local ranges and every connected host IPv4 prefix are
denied, including public host prefixes. IPv6, VLAN encapsulation and IPv4
options are denied. Public DNS is configured inside each clone. Only replies
to observed host-originated SSH connections get a bounded gateway exception;
using source port 22 alone cannot authorize private traffic.

The patched runtime refuses to create its Slirp network unless
`BIVOUAC_SLIRP_POLICY` selects the filter with a valid inventory or names the
explicit positive-control opt-out, which the provider strips and never sets.
The runtime exposes no positive signal that the filter is active. Readiness
proves only indirectly that the patched Slirp context initialized: the
loopback SSH forward that `WaitReady` requires is installed by the same code,
after the policy check. A different binary implementing that forward without
the filter would pass; only `doctor` checks the pinned runtime digest.

Each supervisor checks effective IPv4 denial once per second and retires the
guest when it changes. Connected prefixes wholly covered by existing deny ranges
are redundant; private Windows VM adapter creation/removal and IPv6 changes
(IPv6 is always dropped) do not alter the frozen boundary. A private address with
a broad mask extending outside those ranges is included, as are public host
prefixes. Public-boundary changes still retire the VM. This is not atomic
protection against a newly added public host interface. Live peer,
NIC-reconfiguration and interface-transition tests remain required before
calling this safe for untrusted workflows. A six-endpoint
host TCP/UDP positive-control comparison passed; a gateway endpoint that was
unreachable in both modes is not evidence that the new filter blocked it.
Twelve normal/source-IP/source-MAC/fragmented UDP probes against three owned
host fixtures all reached an unfiltered control and were denied when filtered.
See `status.md` for validated behaviour and open gates.
