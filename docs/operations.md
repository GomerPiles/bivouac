# Operations

## Resource and cache summaries

The manager writes `host performance` and `cache summary` records at startup
and about once a minute. On macOS, CPU includes overall and logical-processor
utilization; memory reports total/used/available physical bytes and disk reports
available space on the controller-state filesystem. The first CPU observation
has no interval. Available macOS memory estimates free plus inactive pages;
it is not Activity Monitor memory pressure. macOS has no Windows commit reading.

New macOS clones receive job-start/completion hooks without baseline or workflow
edits. GitHub's Set up runner and Complete runner logs include guest CPU/RAM/disk
summaries; diagnostics retain a validated numeric `guest/performance.json`.
Completion also prints archive/release cache hits, misses, bypasses, failures
and delivered bytes when cache setup exists, and with `store_uploads` the
relayed, stored, skipped and fallen-back saves. Disabled caching emits no cache
line; an unavailable service reports an unavailable summary. Controller cache
counters reset at manager restart, guest counters at capability replacement.
These whole-system, sampled readings do not measure individual steps or disk IO.
Updating the binary requires the ordinary idle/drain deployment procedure;
existing clones keep their original bootstrap until replaced normally.

Windows host providers have separate operator procedures:
the direct HCS VM host section below, [`windows.md`](windows.md) for shared
cache and login setup, and [`crosvm.md`](crosvm.md) for Linux GPU guests.
Keep production controllers and labels unchanged until the operator approves
cutover after the relevant live validation. Remaining isolation gates still apply.

## Windows development boundary

Windows providers remain experimental; do not point them at existing production
VMs. Use a separate checkout and `BIVOUAC_HOME` for disposable validation.
`version` and native foundation tests need no GitHub credentials or VM launch.
The optional Windows login task runs only the ordinary manager; native engine
prerequisites are still operator-managed. Foreground operation needs
no login installation, service, or PATH modification.

For explicit portable operation, copy [`Control.ps1`](../tools/windows/Control.ps1)
into the chosen home alongside a `portable.json` manifest naming the immutable
CLI and its SHA-256 digest:

```json
{"binary":"bin\\bivouac-validated.exe","sha256":"<64 hexadecimal digits>"}
```

Run it with PowerShell 7 and `-Action On`, `Off`, `Drain`, `Stop` or `Status`.
`On` checks prerequisites, writes mode and starts a hidden ordinary-user manager
when absent. It verifies the previous launch PID, creation time and executable
before reusing it. `Off` drains active work and exits; `Stop` cancels immediately.
Start an absent portable manager from its ordinary desktop shortcut. An IDE or
agent terminal can place its children in a Windows process job; hiding the
manager window does not let it survive that job being closed. The launcher
refuses this context before changing mode or control records. If it reports a
process-job refusal, use the desktop shortcut, or explicitly install and use
the limited login task. An existing manager can still receive control commands
from that terminal. Restarting a development app must not be used to stop CI:
use Off and wait for owned-guest cleanup. After an unexpected controller loss,
status snapshots are historical; check native inventory before assuming guests
have stopped, and restore missing runtime prerequisites before manager recovery.

Windows daemon liveness uses its kernel lock; stale or reused PIDs after shutdown
do not identify a running manager. The launcher archives a matching stale PID
hint after proving the lock is free, leaving instance records intact. Shutdown
can interrupt jobs; recovery cleans dead guests/registrations rather than
resuming execution from their old state. Pending server-side deregistration is
retained and retried by the normal lifecycle controller.

For a combined Windows/Linux JIT home, use a host budget of at least two with
one idle runner per provider. Existing workflow label arrays can keep routing
normally by adding their labels to each provider alongside its `bivouac-` label.
Disable the previous lifecycle controllers before promotion. Finish with
confirmed empty controller/native journals before changing labels, demand mode
or controller ownership. Never have two homes concurrently use the same
controller/root. Mac and ARM64 routing need not change.

`secret set/check/delete` uses the current Windows user's Credential Manager.
Values enter through the existing file/stdin interface; generic items use the
`bivouac/` namespace. Values must contain 1–2,560 bytes; larger PEM keys are
rejected. Run an optional login item under this same user. Native credential tests
are opt-in: `BIVOUAC_WINDOWS_CREDENTIAL_TEST=1 go test ./internal/secret` writes,
updates, reads, and removes a randomly named synthetic fixture. It never
enumerates or reads existing items; normal tests use a fake backend.

## Direct HCS VM host

The VM host is the elevated half of the direct HCS provider. You can run it
either way:

- as an optional service, installed once by an administrator; or
- in the foreground from an elevated shell, with one UAC prompt per start.

Nothing reboots, enables Windows features or installs drivers. Hyper-V's
compute and network services must already be running.

Keep everything elevated in one administrator-protected folder:
`%ProgramFiles%\bivouac\vmhost` holds the binary, its configuration, the
journal root and the images, and `%ProgramFiles%\bivouac\image-factory` holds
the factory's configuration and pinned inputs.

1. Place `bivouac.exe` in `%ProgramFiles%\bivouac\vmhost`. The service runs
   that file as SYSTEM, so the ordinary user must not be able to replace it.
2. Write the configuration beside it as `vmhost.json`:

   ```json
   {
     "root": "C:\\Program Files\\bivouac\\vmhost\\root",
     "controller": "host-1",
     "accounts": ["<the manager user's SID, from whoami /user>"],
     "images": {"windows": "C:\\Program Files\\bivouac\\vmhost\\images\\<build ID>\\disk.vhdx"},
     "max_instances": 2,
     "max_cpu": 8,
     "max_memory_mb": 16384
   }
   ```

   Images must also be administrator-protected; the Hyper-V VM group may
   read them. The image factory publishes them this way.
3. Either install the service or run in the foreground. Both commands are
   elevated:

   ```powershell
   & "$env:ProgramFiles\bivouac\vmhost\bivouac.exe" vmhost install --config "$env:ProgramFiles\bivouac\vmhost\vmhost.json"
   & "$env:ProgramFiles\bivouac\vmhost\bivouac.exe" vmhost run --config "$env:ProgramFiles\bivouac\vmhost\vmhost.json"
   ```

   A stopped service's binary can be replaced in place. To move the service,
   stop it, run `vmhost uninstall`, and install again from the new place; the
   service records its binary's path.

   Either command creates the protected journal root if it is absent.
   Installing registers a manual-start service that restarts after a crash,
   and grants the configured accounts query, start and stop rights on that
   service only.
4. From the ordinary account, `bivouac on` starts the installed service;
   `bivouac off` stops it after the daemon's guests finish and the VM host
   reports no guest reservations from any caller. A foreground VM host is
   never stopped by bivouac. Manual `bivouac vmhost start`,
   `bivouac vmhost stop` and `bivouac vmhost status` still work; a manual
   stop destroys the service's guests first, and while CI is On the daemon
   starts the service again within a tick, so stop it outside On.
   Any Off exit, including a login start while Off, stops an idle service even
   if it was started manually. For manual lab use, use foreground `vmhost run`
   or leave the daemon off.
5. To remove it, stop it, then run `bivouac vmhost uninstall` elevated. A
   running service is refused.

The service logs to `vmhost.log` in its root. Any guest left by an earlier VM
host is settled when it next starts.
Drain and stop leave the service active. Off logs why if it cannot prove the
VM host has no guests, including reservations retained by failed cleanups,
or cannot stop the service. The daemon still exits; once satisfied it is safe,
the operator settles the host with `bivouac vmhost stop`.

The manager's provider then names one of the VM host's images. `guest_name`
and `guest_user` are that prepared image's Windows computer name and console
user:

```toml
[providers.windows]
type = "hcs"
labels = ["self-hosted", "Windows", "X64", "bivouac-windows-hcs"]
idle_pool = 1

[providers.windows.hcs]
experimental = true
image = "windows"
guest_name = "<image computer name>"
guest_user = "ciuser"
cpu = 4
memory_gb = 8
gpu = true
runner_dir = 'C:\actions-runner'
```

`bivouac doctor` checks that the VM host is serving this image within its
limits, and warns when the installed service is merely stopped. The provider
asks for an isolated network on every guest.

The host cache supports the optional release proxy and upload storage.
With `[cache] enabled = true`, both `listen = "127.0.0.1:0"`
and `guest_host = "127.0.0.1"` must use literal loopback (these are the Windows
defaults). A separate bivouac agent Duplex command over HvSocket carries the cache;
no guest NIC exception is needed. Setup precedes JIT, and uncertain removal of
partial settings refuses launch. Cache transport loss falls back upstream
without reattachment. Archive and release caching passed live on the previous
SSH-based HCS provider; the new agent relay has test coverage only. Upload
storage has not been validated live, so leave it off on Windows hosts. Use the isolated cache validation fixture
below for archive/release cold and warm hits, outage fallback and uploads.

For separately authorized end-to-end validation, reserve host resources and use a
separate `BIVOUAC_HOME` with REST JIT demand, one isolated `bivouac-` label,
`idle_pool = 1` and `max_instances = 1`, as in "REST JIT fallback" below. Run
`bivouac on --wait` and wait for `runner listening`. Route a throwaway
workflow to that label only, for example from an orphan branch that contains
only that workflow and runs on push, so no other workflow runs. Push twice
and check that the second job runs on a fresh guest. Then run
`bivouac off --wait`: it deregisters and deletes the idle guest and stops the
service. Delete the branch and its workflow runs, and confirm no guest switch
adapter remains before turning production CI On.

HCS startup measurements appear at Info in the daemon log as one
`hcs readiness timings` record per WaitReady call, including failed calls.
`*_ms` fields are host-monotonic step durations; `*_since_create_ms` fields
are completion milestones from this provider's Create call. Create milestones
are omitted after adoption because a monotonic origin cannot survive restart.
Absent fields mean a step was skipped or not reached, not a zero duration.
The stages cover `vmhost_create`, `session`, `network`, `agent_dial`, `agent_proof`,
`config`, `delivery_config`, `delivery_helper`, optional `delivery_runner_archive`,
`preflight`, `console_proof`, `prepare`, `desktop_proof` and `clock_sync`.
Console/desktop proof durations cover reply validation; guest proof work is inside
preflight or prepare. `wait_ready_total_ms` includes the whole readiness call.
`agent_dial_retries` counts failed dial attempts, and signed `clock_skew_ms`
is guest UTC minus host UTC after correction. `failure_step` is a fixed stage
name; all measurement values are numbers, with no guest text or identities.

`hcs launch timings` separately records cache setup (including any fallback),
JIT delivery, listener process start and launch total. A disabled cache has a
near-zero setup duration. `hcs listening timings` records `jit_to_listening_ms`
once, at the first existing status poll observing listening or running, measured
from the start of JIT delivery, after cache setup. This includes poll latency;
process start alone does not prove listening. It is absent if listening is never
observed or the manager restarts. No additional guest commands or polls run.
Durations and milestones overlap: do not add milestones or totals to step
durations. The network lab's per-run `readiness.spans_ms` and optional
`readiness.failure_step` contain the identical readiness report, alongside its
existing `timings_ms` VM host/batch measurements, even on readiness failure.
Compare interleaved cold boots at equal resources and quiet host load using
the separately authorized lab procedure below.

Adoption checks current VM host ownership and running state, then reconnects to
the guest's runtime ID over HvSocket. It requires no host-key file or per-guest
secret. Status uses one agent command per existing poll; JIT and start are never
replayed after an uncertain outcome. A protocol-version refusal is terminal.
This provider requires a matching bivouac-agent image; old images are unsupported.
Rollback is the previous manager binary, VM host service binary and image. The factory and vmhost lab batch below
use the same agent protocol; this branch has not been validated live.

### Coordinated HCS cutover and rollback

A matching image is required: the VM host reports each adjacent protected
manifest's `windows_contract`, and doctor/activation refuse missing or different
contracts with a fixed message. The manager does not read protected image files.
Change the Windows contract when the agent CLI, receiver or adapter modes change;
the shared framing Version has a separate purpose.

Drain with CI Off (`bivouac off --wait`) and confirm no HCS guests or reservations
remain before replacing anything. Stop the empty VM host service. Switch the
bivouac manager binary, VM host service binary and newly built image together,
then check doctor/activation before enabling CI. Do not replace a running binary
or erase ownership journals. Rollback requires the previous trio together.
This procedure does not authorize a cutover or a live validation run.

## Direct HCS image factory

`bivouac image build` prepares an agent image for the `hcs` provider from a
generalized App Sandbox template. `bivouac image inspect` runs the same copy
and offline checks without booting, so a template can be checked first. Both
run elevated in the foreground (one UAC prompt each), drive HCS directly and
attach no network adapter, so production CI may keep running. Neither touches
the VM host service, its journal or CI mode.

Images contain bivouac's guest agent and use HCS synthetic video with GPU-PV.
Specialize removes legacy components and MSI server installations; FirstLogon removes the Windows OpenSSH server capability through servicing. The inbox client and ssh-agent remain intact.
The template is still an App Sandbox template; template creation is out of scope.
Rollback uses the previous manager binary, VM host service binary and image together.

The template is only read. The factory copies it into its own workspace,
hashing as it copies, and never changes the template's file, directory, ACL
or owner record. It mounts, grants and boots only files it created.

1. Write a JSON configuration in an administrator-protected directory. The
   inputs must be protected too:

   ```json
   {
     "source": "<template dir>\\disk.vhdx",
     "source_sha256": "<the owner record's SHA256>",
     "expected_template": "<template name>",
     "guest_user": "ciuser",
     "image_root": "<protected parent>\\Images",
     "render_probe": {"source": "<path>", "sha256": "<hash>"},
     "setup_assets": [],
     "drivers": ["C:\\Windows\\System32\\DriverStore\\FileRepository\\<GPU driver dir>"]
   }
   ```

   - `RUNNER.ZIP` is the only accepted setup asset and is required only for a
     template without a runner. The render probe remains required. Legacy guest
     agents, helpers, VDD/devcon files and OpenSSH installers are unsupported.
   - Offline staging copies this factory executable to
     `C:\Program Files\Bivouac\bivouac.exe`, protected for SYSTEM,
     Administrators and TrustedInstaller, with Users read/execute. The manifest
     records its hash and Windows contract. FirstLogon creates and starts the
     `bivouac-guest-agent` logon task for the configured interactive user with
     Highest, priority 4 (normal), three one-minute restarts and no execution
     time limit. Its action runs the binary directly. Build files use
     `C:\ProgramData\Bivouac\Image`.
     It also registers `bivouac-guest-runner` with no trigger: the installed
     binary runs `guest windows detached` on demand for the same elevated
     interactive user, priority 4, IgnoreNew, no restart policy or time limit,
     and no idle/network/battery conditions. Registration XML gives SYSTEM and
     Administrators full control, registered without the principal's own entry
     (`TASK_DONT_ADD_PRINCIPAL_ACE`). Preparation
     and publication self-tests check both task definitions and the runner
     task's current security descriptor. A matching contract-2 image is required.
   - Specialize stop/deletes the legacy agent and, after MSI uninstall, leftover sshd,
     removes VDD nodes/packages and the entire legacy component directory,
     uninstalls registered OpenSSH MSI products first and deletes remaining MSI program
     directories, server state, authorization files and the host-key boot task.
     Traversal is bounded and refuses links. FirstLogon verifies removal and
     synthetic video, preserving incomplete specialize diagnostics. Steps 81–86
     and 90–94 identify removals; 88 means specialize complete, 89 means its
     status could not be verified. Video checks retain steps 35–38. FirstLogon
     step 39 removes OpenSSH.Server through Windows servicing; it preserves the
     inbox client and ssh-agent. A required reboot refuses publication for
     operator review. Verification requires no sshd service/executable, server
     state or authorization files.
   - `drivers` names one to eight host FileRepository directories. A bounded
     staged snapshot is installed offline under guest HostDriverStore,
     preserving nesting and empty directories. Source and destination hashes
     must match the exact inventory; a temporary sibling is renamed only when
     complete, with guest-parent ownership and inherited ACLs. Existing target
     trees refuse the build. FirstLogon restarts only `vrd.inf` devices at
     error 43. D3D11/present/readback is the gate; GL/Vulkan/NVIDIA runtime
     provisioning and other APIs are not covered. Rebuild after host driver changes.
   - `cpu` (default 4) and `memory_mb` (default 8192) size the build guest.
     `timeout_seconds` (default 900) bounds the guest's run, not the copy.
   - Keep `image_root` outside the template and instance trees. Its
     volume needs about 2.2 times the template's size plus 10 GiB free.
2. Inspect, then build, from an elevated shell:

   ```text
   bivouac image inspect --config "<protected parent>\image-factory.json"
   bivouac image build --config "<protected parent>\image-factory.json"
   ```

   Both print the build's facts or result as JSON. A Group Policy execution
   policy overrides the factory's own and can stop its scripts.
3. The offline inspection gates the build. The template must be generalized
   to OOBE, with no answer-file pointer and an empty `Windows\Panther\Unattend`.
   A configured runner (`.runner`, `.credentials`), anything under its `_work`,
   an installed bivouac agent, either guest task, or a `ProgramData\Bivouac\Guest` directory refuses it. Logs left in the
   runner's `_diag` by template preparation are allowed and are deleted during
   setup. The record lists only public facts: agent presence/hash/task, runner state and residue names, never file contents or
   answer-file values.
4. A build boots the guest with GPU-PV, runs Windows setup with the pinned
   agent, checks hardware rendering with the probe, removes setup files and agent logs,
   rotates the console password into the autologon secret, shuts down
   cleanly and flattens the result. A build takes about 3 minutes plus the
   copy. Admission waits for the guest's memory plus 10 GiB available and
   8 GiB commit headroom, and the build cancels itself if available memory
   falls below 6 GiB or commit headroom below 2 GiB.
5. The result is `<image_root>\<build ID>\disk.vhdx`, a single standalone
   VHDX, with `manifest.json` written last. The manifest records the source,
   asset and image hashes, `guest_name`, `guest_user`, the agent hash/Windows contract, public facts for both tasks and autologon-account agreement, driver versions and
   the lab batch's probe, validation and autologon pins. Point `vmhost.json`'s
   image at the disk and set the provider's `guest_name` and `guest_user` from
   the build's output. The manifest also records topology facts; publication
   requires one
   active primary display on Hyper-V synthetic video, no VDD nodes and the
   existing render checks. Sanitation retains both tasks, requires the runner
   task to be Ready, and removes launch/claim/cancellation and lab residue.
   A published directory is never reused.
6. Build records stay in `<image_root>\.builds`. A failed build terminates its
   own guest, confirms it absent and removes its workspace. If it could not
   confirm that, it keeps the workspace; settle it later, elevated:

   ```text
   bivouac image cleanup --config "<protected parent>\image-factory.json" --build <build ID>
   ```

   Cleanup refuses a build that is still running, and never removes a
   published image.

## Direct HCS lab batch

`TestLabBatch` in `internal/vmhost` boots disposable guests from an existing
prepared image through the direct HCS code. It is opt-in: it needs the
`integration` build tag, an explicitly elevated launch, and lab flags. It runs
these cold boots in order:

1. A baseline guest (2 CPU, 4 GiB).
2. The same with lazily committed memory.
3. A guest whose parent is a flattened copy of the image.
4. Two production-sized guests (4 CPU, 8 GiB).

Each run proves bivouac's agent and runs the image's pinned desktop validation
through it. The baseline's unelevated child must be refused the ungranted agent
service; the lazy-memory run grants the manager account and requires connection.
The lab also requires a guest-loopback HvSocket refusal, fixed facts proving the
actual task principal/Highest/Interactive/action/priority 4 and installed owner/ACL.
It starts a harmless long-lived probe through start's runner-task dispatch,
mode/marker and claim path. It reports job membership, immediate-job agent
presence (unknown on an incomplete bounded list), context predicates, priorities,
and a gate stage. Job queries are baseline-only diagnostics: failure reports
unknown without ending the probe, and membership does not gate the run. Context
and priority facts gate it, along with the same recorded probe and sleeping grandchild surviving both
`schtasks /End` + `/Run` and a proven agent process kill + `/Run`. The probe
performs these fixed task operations itself; each cycle validates the current
agent identity and matches fresh request/completion IDs. Results require a
different agent PID/creation identity after each cycle. Probe cleanup
checks recorded identity on the opened process handle. No runner or credentials
are required. These destructive-in-guest checks run only in the explicit lab;
ordinary unit checks simulate their command/report sequence. Recovery and timing
on real Task Scheduler jobs remain unverified until the live run passes.
Only the agent service is exposed. `agent_reachable` records create-to-agent
proof alongside existing connection/desktop spans and bounded numeric step markers.

Every desktop run records topology in the console user's
interactive session and requires exactly one active primary display plus a
probe window that becomes foreground, fits the primary work area and receives
SendInput. Windows Security launch/placement facts are recorded without gating
the run. Every run requires Hyper-V video as the primary adapter, no VDD nodes,
and Hyper-V video enabled and started. Use this factory's image and its matching
manifest pins, with new `-lab.root`, `-lab.flatten-dir` and `-lab.results` paths
for each invocation. Do not share journals, reuse directories or point a lab
invocation at the installed VM host service, production images or a controller
home. Builds and runs still need the operator's explicit live-validation
approval; compiling the tools starts none.

`-lab.only=failed-start` explicitly selects an additional run, skipped when
`-lab.only` is empty. It boots the prepared image with 2 vCPUs and 2048 MiB of
lazy memory plus a second disk whose file does not exist, which HCS accepts at
create and refuses at start (more vCPUs than the host has are refused at
create instead); it needs no networking or GPU. Its `failed_start` record contains
the host CPU count, ordered property/start/terminate observations (ownership
comparisons and runtime-ID presence only), create error and HCS operation/code,
retention status, and journal-empty/native-absent cleanup checks. An unexpected
successful start is destroyed and fails the run.

The batch attaches no network adapter, so it changes no host networking, and it
never touches another compute system or production
state. Production CI may keep running. Before each boot, the batch waits for
the guest's memory plus 10 GiB of available memory and plus 8 GiB of commit
headroom. During a run, it cancels only that run if available memory drops
below 6 GiB or commit headroom below 2 GiB.

Build the test binary unelevated, then launch it once through UAC. Use new or
empty lab directories under an administrator-protected parent, and a new
results path the ordinary user can read. Take the image pins from the image's
build record.

```powershell
go test -c -tags integration -o bin\lab\vmhost-lab.test.exe .\internal\vmhost
Start-Process -Verb RunAs -FilePath bin\lab\vmhost-lab.test.exe -ArgumentList @(
  '-test.run=^TestLabBatch$', '-test.timeout=90m',
  '"-lab.root=<protected parent>\VMHost"', '"-lab.flatten-dir=<protected parent>\VMHost-Images"',
  '"-lab.results=<user path>\lab-results.jsonl"', '"-lab.image=<prepared image>.vhdx"',
  '-lab.image-sha256=<hash>', '-lab.guest-name=<computer name>', '-lab.guest-user=<user>',
  '-lab.probe-sha256=<hash>', '-lab.validation-sha256=<hash>', '-lab.autologon-sha256=<hash>')
```

Results are JSON lines: one start line, then the image verification time,
then one line per run, then an end line. Each run line holds timings in
milliseconds, render and boot checkpoints, host memory samples, and whether
cleanup confirmed absence. Nothing in them is guest-controlled text. If a run
retains storage, the batch stops. Rerunning a VM host's `Recover` on the same
directory settles anything it retained; never delete the directory by hand
while a guest may exist.

## Direct HCS network lab batch

`TestLabNetworkBatch` in `internal/provider/hcsvm` is batch 2. It runs the
real VM host in the test process, with its pipe, caller check and network
guard, and drives it through the `hcs` provider as the manager would. Each run
is a production-sized cold boot (4 CPU, 8 GiB, GPU) with an isolated network:

1. Create records the VM host's timings and whether the port policy was in
   place before start.
2. WaitReady applies the lease through the winrunner preflight and prepare
   steps.
3. The guest probes its network:
   - It must reach public DNS, HTTPS, TCP and UDP DNS.
   - It must not reach its gateway's DNS proxy, public IPv6, or host
     listeners on the gateway, the LAN source address and the switch
     adapter's IPv6 link-local address.
   - Each listener first proves the host can reach it, and counts any other
     connection.
4. The guest must still be running after two guard intervals.
5. Delete must leave no guest, no reservation and no switch adapter.

**Windows CI must be drained first.** Reserve host resources independently of
production; each guest adds a dedicated switch and host vEthernet adapter.

Without a layer-removed control, a host listener's refusal could also come
from the host firewall. The gateway's DNS proxy is the stronger denial check,
because connection sharing normally opens it on the shared switch. If Windows
offers to allow the test binary through the firewall, choose Cancel.

1. Turn Windows CI Off (`Control.ps1 -Action Off`, or `bivouac off --wait`)
   and wait until no Windows guest remains.
2. Build unelevated. The helper is sent into each guest as its adapter:

   ```powershell
   go build -o bin\lab\bivouac.exe .\cmd\bivouac
   go test -c -tags integration -o bin\lab\hcs-network-lab.test.exe .\internal\provider\hcsvm
   ```

3. Launch it once through UAC. Use a matching bivouac-agent image and pins from this factory. The lab root
   must not exist yet; the VM host creates it protected.
   - If the image has no runner, add `-lab.runner-archive` and
     `-lab.runner-sha256` for an official runner ZIP.
   - `-lab.peer=<ip:port>` adds an owner-controlled private peer that the
     host can reach.

   ```powershell
   Start-Process -Verb RunAs -FilePath bin\lab\hcs-network-lab.test.exe -ArgumentList @(
     '-test.run=^TestLabNetworkBatch$', '-test.timeout=60m', '-lab.windows-ci-drained',
     '"-lab.root=<protected parent>\VMHost-Network"',
     '"-lab.results=<user path>\network-results.jsonl"',
     '"-lab.image=<prepared image>.vhdx"', '-lab.image-sha256=<hash>',
     '-lab.guest-name=<computer name>', '-lab.guest-user=<user>',
     "`"-lab.helper=$PWD\bin\lab\bivouac.exe`"")
   ```

4. Results are JSON lines: start, image verification, one line per run, end.
   The VM host's log is written beside them. Probe outcomes use a fixed
   vocabulary; no addresses or guest text are recorded.
5. Turn CI On from its desktop shortcut; the launcher refuses an agent
   terminal. Watch the first Windows guest become ready.

If a run retains a guest, the batch stops. Relaunch with
`-lab.recover-root=<that root>` and a new `-lab.root`: it settles the old root
first, and refuses to boot anything if a guest or network remains. Never
delete the root by hand while a guest may exist.

## GitHub App (separate App can follow cutover)

Both demand modes work with the existing shared App. A dedicated App is
optional follow-up work for independent revocation; it does not block
cutover. Keep the shared installation, permissions, and key unchanged
when retiring Tartelet. To create a separate App later:

1. Organization settings → Developer settings → GitHub Apps → New GitHub
   App. Name `gomerpiles-bivouac`. Any homepage URL. Uncheck Webhook.
2. Permissions: Organization → **Self-hosted runners: Read and write**.
   Nothing else. "Where can this App be installed": only this account.
3. Create, then generate a private key (downloads a `.pem`).
4. Install the App on the organization with repository access limited to
   the repositories that use bivouac. The installation ID is the number at the end of the
   installation settings URL.
5. Note the App's **Client ID** (the `Iv1.` string on the App page).

On the Mac:

```bash
bivouac secret set github-app-key --file ~/Downloads/<app>.private-key.pem
```

then delete the downloaded `.pem`. The key passes once on the command line
of the system `security` tool; nothing else records it.

## Run, with optional login startup

Startup is uninstalled by default. After configuration and prerequisite checks,
use `bivouac on` and then `bivouac run` in a terminal for foreground operation.
`on` records mode but never creates a login item. The following macOS example
opts into login startup explicitly; omit `install` for foreground use.

```bash
go build -o bin/bivouac ./cmd/bivouac
codesign --force --sign - --entitlements tools/macos/bivouac.entitlements bin/bivouac
cp bin/bivouac /usr/local/bin/bivouac      # or anywhere on PATH
bivouac config example > "$(bivouac config path)"   # edit: url, app ids, baseline
bivouac config validate
bivouac doctor --github                    # creates the experimental scale set
bivouac install                            # optional LaunchAgent; does not change mode
bivouac on
```

`bivouac install` does not create a command alias or change PATH. An optional
`biv` symlink can be created separately by the operator.
The LaunchAgent uses `ProcessType=Interactive` and
`AbandonProcessGroup=true`; reinstall after changing its template. Its
executable path is fixed at installation time: rebuilding another copy
does not update the running daemon.

For an installed checkout, build and sign a replacement as above, copy it to
`bin/bivouac.next`, drain active work, send TERM
only to the PID in the state directory's `daemon.pid`, and wait for that
PID file to disappear. Replace `bin/bivouac` with the staged binary, then
run `bin/bivouac on`. Keep workflow dispatches paused during replacement.
Never use a process-name search to stop or wait for the daemon.

The daemon runs every VM through `bivouac vm run` from its own executable, so
that copy must carry the `com.apple.security.virtualization` entitlement;
the daemon refuses to start without it, and `doctor` checks it.
Host startup checks are independent of baseline and Linux helper availability:
a missing, changed or invalid baseline/helper blocks new-instance admission,
while reconciliation can adopt retained runners and clean up recorded clones.
Restore the configured baseline/helper before new admissions; use `doctor` to
check them. Retained operations use each clone's manifest and current ownership
and isolation proof, without re-uploading helpers during adoption.

An unreadable retained manifest or guest-OS mismatch parks only that record:
no adoption, guest cleanup or registration withdrawal; its reservation remains,
and other instances reconcile. Restore that clone's original manifest from
trusted evidence (never substitute baseline metadata), or restore its original
`guest_os`, then restart. Without that evidence, retain the record for owner
recovery; do not erase it to force cleanup.

**VM store.** Baselines and clones live in bivouac's VM store:
`~/Library/Application Support/bivouac/vms`, or `vms` under `BIVOUAC_HOME`.
`bivouac doctor` names it and checks the baseline's manifest and that the
store path is short enough for guest agent sockets (103 bytes on macOS). Import a
stopped Tart-format VM, which clones it when it is on the same volume and
writes the manifest:

```bash
bivouac vz import --runner-dir /Users/admin/actions-runner --sudo <stopped-image-directory> <baseline>
```

Pass `--sudo` only if the guest user has passwordless sudo (the release
proxy needs it). The import records this binary's guest agent protocol, so
import again after installing a new agent. A Linux engine baseline needs no
`--runner-dir`.

Bivouac does not see VMs in other tools' directories, so `foreign_slots`
must reserve Apple's guest slots for any other manager.

**macOS baseline.** Prepare an operator-managed Tart-format image before
importing it. Bivouac uses its own guest agent: boot the image, then install
the darwin/arm64 `bivouac` binary as
`/usr/local/bin/bivouac` (root:wheel, 0755) and
[`dev.bivouac.guest-agent.plist`](../tools/macos/dev.bivouac.guest-agent.plist)
in `/Library/LaunchAgents` (root:wheel, 0644). The baseline user must log in
automatically; the agent runs only in that Aqua session. Shut the baseline
down cleanly. To replace the agent binary, write a new file and `mv` it over
the old one; overwriting the running binary in place corrupts it. Reinstall
the binary when its protocol version changes. The guest plist also needs updating
when its launch policy changes: it sets `ProcessType=Interactive` to avoid
launchd's default low-priority I/O throttling. Install the updated plist during
offline image preparation and shut down cleanly before importing the image;
rebuilding the host binary does not update existing baseline LaunchAgents.

**Linux ARM64 runners on vz.** Import a stopped, prepared Tart-format Linux
baseline with `--runner-dir /opt/actions-runner`. It must contain the matching
non-root guest agent and a root-owned prepared helper built with the `vz-dhcp`
profile; use the [Go provisioning command](#preparing-a-linux-arm64-runner-baseline).
Configure the provider's vz section with:

```toml
guest_os = "linux"
helper = "/opt/bivouac/linux-arm64"
baseline = "ci-linux-arm64"
cpu = 4
memory_gb = 4
```

Omit macOS slot, display, bootstrap-share and companion-engine settings. Linux
uses DHCP virtual DNS without guest rewrites; helper hash mismatches require a
rebuilt baseline. Both guest OSes keep archive caching without recorded sudo;
the host issues an archive-only grant and release-proxy trust is omitted. Setup
failure revokes the grant and requires confirmed adapter removal before JIT can fall back to ordinary public downloads.

For explicit live validation, use an isolated `BIVOUAC_HOME`, import/copy only a
validation baseline, reserve CPU/memory, and set `BIVOUAC_EXE`,
`BIVOUAC_LINUX_HELPER`, `BIVOUAC_VZ_LINUX_BASELINE` and
`BIVOUAC_VZ_CAPACITY_CONFIRMED=1`. The gated `TestRealLinuxGuest` integration test
uses two recorded disposable clones and checks virtual DNS, public access, owned
host-listener denial and privileged-container isolation. It never registers a
GitHub runner. Tests and cross-builds do not establish these live gates.

**Startup timing.** The daemon writes `startup stage`
records to its normal redacted log, with provider, guest name, `stage`,
`duration_ms` and `success`. The stages are:

| Stage | Measurement |
| --- | --- |
| `clone` | Runtime clone call |
| `native_start` | Host VM-helper process launch, not completed guest boot |
| `agent_wait` | Agent availability, including OS boot and Aqua login |
| `script_install`, `aqua_session_check` | Bootstrap delivery and desktop-session proof |
| `helper_upload` | Current helper upload, including source and private destination preparation |
| `cache_setup` | Optional per-clone cache configuration and trust |
| `jit_generation`, `jit_delivery`, `listener_wait` | Registration request, bootstrap/initial listener launch, and official listener readiness |
| `dns_setup` | Public DNS setup is supplied by rootless DHCP; no guest DNS setup command |

The manager emits `jit_generation` and `listener_wait` for every provider; the
other stages listed above are macOS provider measurements. Stages omitted from
a path produce no record. A zero duration can mean less than one millisecond.
Existing `clone_ms`, `boot_ms` and `register_ms` retain their meanings.
Failed stages record their elapsed time without guest output
or raw error details; optional helper/cache failures can still fall back to the
ordinary runner.

Every fresh macOS clone receives one private helper upload, shared by telemetry,
caching and the optional container relay. Caching no longer uploads a second
executable. The baseline agent needs updating only when its protocol or launch
policy changes; the host never updates it in place.

**Moving from the Tart CLI runtime.** Drain to idle first: guests started by
`tart run` are not adopted. Import the baseline, set `type = "vz"`, and
rename `[providers.*.tart]` to `[providers.*.vz]` without `binary`,
`extra_args`, or `runner_dir` (now in the manifest); config validation
rejects the old names. Typed options in `[providers.*.vz.machine]` replace
`extra_args`. `nested_virtualization = true` needs an M3 or newer Mac with
macOS 15 and a Linux guest, such as the engine VM in
`[providers.*.vz.containers.machine]`; the daemon refuses to start otherwise.

Validation config (while Tartelet keeps production):

```toml
[budget]
max_instances = 1
max_pending_cleanup = 2
[providers.macos]
scaleset = "bivouac-macos-experimental"
[providers.macos.vz]
baseline = "ci-macos27"
foreign_slots = 1     # Tartelet's VM keeps one of Apple's two macOS guest slots
```

## Validating with a real workflow

On a throwaway branch of a repository that will use bivouac (never merge),
one workflow:

```yaml
name: bivouac-validation
on: { workflow_dispatch: {} }
permissions: { contents: read }
jobs:
  macos:
    runs-on: bivouac-macos-experimental
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: test ! -e "$HOME/bivouac-sentinel" && touch "$HOME/bivouac-sentinel"
      - run: <the project's usual test command>
```

Dispatch it twice: the sentinel step proves the second guest is fresh.
`bivouac status` during the run shows the guest, its job, and its age; the
`_diag` logs land under the diagnostics directory after the job.

### Label arrays on a scale set

Set `scaleset_labels` before the scale set is first created; GitHub ignores
later label changes. Never give a scale set every label of another runner's
`runs-on` array: a job runs on any runner holding all its labels. To change
labels: `bivouac off --wait`, delete the scale set from the organization's
runner settings, then `bivouac doctor --github` creates it with the
configured labels and reports any difference.

## REST JIT fallback

Finish active work with `bivouac off --wait` before changing demand mode.
Do not switch while a retained cleanup record exists. In the host config:

```toml
[github]
demand = "jit"
[providers.macos]
labels = ["self-hosted", "macOS", "ARM64", "bivouac-macos-jit-experimental"]
idle_pool = 1
max_instances = 1
```

Keep the existing App settings, budget, baseline, and `foreign_slots = 1`.
`bivouac doctor --github` checks REST authentication and runner access without
creating a scale set or registration. The
[REST runner API](https://docs.github.com/en/rest/actions/self-hosted-runners)
documents endpoint permissions. Start with `bivouac on`; wait for
`runner listening`. Route only the throwaway workflow to the same label
array. The ordinary JIT runner executes exactly one job; a replacement is
created within the budget. Unlike scale-set mode, on intentionally keeps
one idle guest warm. Drain/off first deregister idle runners, then delete
the guests; a busy rejection lets an accepted job finish. Stop cancels.

REST needs the same organization **Self-hosted runners: Read and write**
permission; it does not need Actions read/write permission or implement
job cancellation through REST. Custom groups require runner-group access.
Repository registration is implemented but not validated live; it requires
repository Administration write permission, so prefer the verified
organization setup. Enterprise hosts are also unverified.

To return to scale sets: `bivouac off --wait`, verify no instance records or
owned guests remain, restore `demand = "scaleset"` and the workflow's
single scale-set label, then `bivouac on`. Never revoke the shared App.

## macOS rootless network isolation: validation and later rollout

Managed macOS runner guests use a rootless stack in a sandboxed child. `doctor` and
`engine check-isolation` check host policy availability read-only. There is no
Softnet, sudoers/SUID or privileged-service prerequisite and no host network
configuration change. DHCP supplies the virtual router and bounded DNS service;
macOS baseline networking/DNS must use DHCP. Guest DNS uses the host's primary
`/etc/resolv.conf` nameservers; scoped/per-domain macOS DNS is excluded. All DNS
types pass subject to address/hint filtering. Queries may disclose internal DNS
metadata; choose public `dns_servers` to avoid it. Cache egress uses system
resolution unless overridden. No usable resolver makes `doctor` fail; live lookup
failure warns. Public-policy checks fail when all representative addresses are
denied and warn when only some are denied.

```toml
[providers.macos.vz.network]
dns_servers = []           # optional IPv4 literals; empty = primary host DNS
memory_mb = 1024           # TCP buffer sizing budget in MiB, not a whole-process RSS cap
max_flows = 4096           # public TCP/UDP and cache payload, including pending TCP
tcp_idle_timeout = "24h"
udp_idle_timeout = "60s"
mtu = 16384                # 1500..65535 (non-1500 needs macOS 13+); independent of memory_mb
[cache]
max_connections = 256      # per-VM host endpoint and independent parent payload bound
```

All vz providers must agree on DNS overrides for the shared cache client. Both
container-pair members receive the provider's network settings. Restart the
controller to load settings. The per-direction TCP maximum is budget/(2*max_flows),
clamped to 128 KiB..4 MiB (128 KiB by default); the floor can exceed a small
budget. FIN shortens idle expiry to at most 15 minutes. DNS and CRL reserve independent capacity; raising
limits requires sufficient controller/helper/child FD headroom. Guest sudo
remains optional for
release-proxy trust installation and is used explicitly for privileged attack
probes, not for mandatory networking.

Use a separate worktree, staged signed executable, `BIVOUAC_HOME`, VM store,
state, logs and isolated `bivouac-macos-isolation-validation` label. Copy only
GitHub App references if job validation is needed; never copy a key into config
or fixtures. Copy/import a stopped source into that isolated store using
copy-on-write. Never start, edit, replace or delete the production macOS VM or
baseline; preserve it as a backup and verify its files remain unchanged.
Read-only bootstrap shares are an independent optional choice for ordinary
runners. Container pairs retain their existing share prohibition.

Before each guest batch, inspect native VM/controller inventory and active
controller configurations read-only. Reserve other controllers' maximum CPU
and guest memory even when they are idle. Linux validation consumes CPU/RAM but
no Apple macOS guest slot. Account for Apple's two-guest limit and foreign-slot
reservations; an idle status snapshot does not release a reservation. If
capacity cannot be established, report that before starting guests. An
owner-authorized production Off must drain healthy jobs and confirm empty
records first; never terminate a production job to free resources. Choose explicit
CPU/memory and minimum-free-memory bounds for the isolated
batch after that inventory; these are lab safeguards, not cross-controller
admission coordination.

Stage without replacing the installed binary:

```sh
CGO_ENABLED=0 go build -trimpath -o bin/bivouac.next ./cmd/bivouac
codesign --force --sign - --entitlements tools/macos/bivouac.entitlements bin/bivouac.next
CGO_ENABLED=0 go build -trimpath -o bin/bivouac-network-probe ./tools/macos/network-probe
```

The real-guest fixtures require a separate home, copied/imported baseline,
signed staged executable and a completed read-only capacity audit:

```sh
# Set BIVOUAC_HOME, BIVOUAC_VZ_BASELINE and BIVOUAC_EXE to isolated resources.
BIVOUAC_VZ_CAPACITY_CONFIRMED=1 go test -tags integration -run '^TestRealGuest$' -v ./internal/provider/vz
```

The capacity gate records the operator's audit; it does not coordinate other
controllers. The ordinary test holds the isolated lock, records each clone,
checks rootless arguments and adoption proof, Aqua and fresh filesystem state,
and proves ownership-checked teardown. Its temporary host listeners use fresh assigned ports on loopback and the
host's current IPv4 addresses, with positive host controls; they accept and
close connections without serving data. Only those owned ports are probed. Public DNS/HTTPS must work as the runner user and guest root. Private
peer tests need `BIVOUAC_VZ_TEST_PEER`, an explicitly owner-controlled endpoint
with a positive host control. Never scan a LAN or select production services.

`TestRootlessGuestLab` adds numeric performance and failure checks. Set
`BIVOUAC_ROOTLESS_LAB=1` with the same isolated resources and capacity gate.
`BIVOUAC_LAB_MTU`, `BIVOUAC_LAB_MEMORY_MB`, `BIVOUAC_LAB_MAX_FLOWS`,
`BIVOUAC_LAB_TCP_IDLE_TIMEOUT`, `BIVOUAC_LAB_UDP_IDLE_TIMEOUT` and comma-separated
`BIVOUAC_LAB_DNS_SERVERS` use production validation/defaults. The lab checks
guest MTU adoption and records DHCP option 26. `BIVOUAC_LAB_LOCAL_TCP=1` measures
256 MiB in each direction through the virtual Ethernet/cache endpoint, with
numeric child counters before/after (allow a minute per counter observation).
Leave `BIVOUAC_LAB_PUBLIC_ASSET` unset to skip public downloads; setting an explicit
public GitHub release URL without query credentials enables them.
`BIVOUAC_LAB_DNS_PROBES=1` checks A, empty AAAA, TXT and NXDOMAIN through DHCP DNS;
leave DNS overrides unset to test host resolvers. `BIVOUAC_LAB_LIMIT_PROBES=1`
defaults to 256 flows (override `BIVOUAC_LAB_MAX_FLOWS=1..512`), logs background
gauges, requires eight free slots, and attempts ceiling+4 connect-only TCP
sockets to `1.1.1.1:443`. It then checks reserved DNS and re-attempts a few
connects at once, before idle peers close the held sockets. It passes when the
re-attempts are refused and `flow_limit` rises with `admission_denied` and
`dial_failed` unchanged. Fixture failures log fixed
error classes, exit codes and bounded, redacted stderr.
Both DNS checks use dig or host and log a skip when neither is available.
Set `BIVOUAC_LAB_PACKET_PROBE` to the staged guest-only probe executable,
`BIVOUAC_LAB_PUBLIC_PROBES=1` for the benign public/denial matrix and
`BIVOUAC_ROOTLESS_LAB_ROUNDS=2` for repeated fresh clones. Set
`BIVOUAC_LAB_CACHE_CONCURRENCY` up to `BIVOUAC_LAB_CACHE_MAX_CONNECTIONS` (default 256)
and the general flow ceiling. For local warm hits without public downloads,
build `go test -c -tags integration -o bin/cache-lab.test ./internal/cache` and set
`BIVOUAC_LAB_CACHE_FIXTURE` to its absolute path; it uses a local TLS upstream.
The saturation unit fixture separately holds admitted TLS connections and proves
plain HTTP and HTTPS CONNECT fallback without forwarding a capability.
`BIVOUAC_SANDBOX_PUBLIC_DNS_TEST=1 go test -run TestNetworkSandbox ./internal/rootnet`
adds the explicit public-DNS sandbox probe; ordinary unit tests use no public
network probe. The packet probe refuses BPF
unless running as guest root with the virtual guest lease; it sends fixed
MAC/IP spoof, UDP, mDNS, ICMP and IPv6 link-local frames through the disposable
link. Numeric host counters prove the rejection path instead of relying on a
missing guest IPv6 route. Its `--metal` mode submits and verifies a real GPU
buffer copy in Aqua. It does not prove window rendering, focus or input.

With a public asset selected, the lab measures a public download, cold/warm release caching over the virtual endpoint,
authenticated numeric metrics and direct fallback after service shutdown. It
rechecks live helper/child/kernel-sandbox adoption proof, kills only the network
child of its recorded owned VM, confirms the guest stopped, deletes it and removes its record. Its next clone
must lack the sentinel. `BIVOUAC_ROOTLESS_NAT_BENCHMARK=1` explicitly adds a
separate trusted NAT control; that clone receives no runner credentials and
NAT is never a fallback for a failed isolated launch. Public throughput samples
are variable and cannot establish a rootless speed advantage.

Host-only microbenchmarks are reproducible with:

```sh
GOMAXPROCS=2 go test -run '^$' -bench '^BenchmarkDownload$' -benchtime=3x ./internal/rootnet
GOMAXPROCS=2 go test -run '^$' -bench '^BenchmarkCacheEndpointDownload$' -benchtime=2x ./internal/cache
```

The virtual attachment checks both ends of its private datagram pair have the
requested 1 MiB send and 4 MiB receive buffers before launch. Setup/readback
failure refuses launch; no host-wide socket setting is changed. The stack's
data/control byte and frame admission budgets feed one nonblocking FIFO, preserving
frame order without waiting under protocol locks. Numeric reports distinguish
data/control drops from TCP retransmissions; a successful socket write alone
does not prove the virtual NIC delivered a frame.

Set `BIVOUAC_LAB_DESKTOP_PROBE` to `tools/macos/desktop-probe.swift` to add
visible-window, foreground application/focus, Metal drawable pixel readback,
seven typed characters and one button action checks. The events travel through
AppKit's application event path; this does not test host-to-guest hardware input.
Presentation timestamp availability is reported separately and is not compositor
capture evidence.

macOS cache admission is configurable at the host endpoint, default 256. Payload
streams also count against the general VM flow ceiling, and the parent owns an
independent broker bound. Excess connections refuse before TLS/HTTP, permitting
public fallback through mandatory isolation. The container-engine VSOCK mux is
unchanged. For a controlled local native benchmark, compile the cache test executable with
`go test -c -tags integration -o bin/cache-endpoint.test ./internal/cache` and
set `BIVOUAC_LAB_CACHE_FIXTURE` to its absolute path in the lab. It measures raw
virtual TCP, bidirectional transfers with one large receiver held until its
peers complete, and 32 MiB authenticated release hits with 1/8/16/32 native curl
readers. `BIVOUAC_LAB_BURST_PROBES=1` holds 32 raw cache-capability sockets
while fresh public DNS/HTTPS probes run, then verifies authenticated transfers
and fresh public connections after the burst; the private local upstream bypass exists only in that fixture. Setup
and guest metrics are bounded and credentials travel only through stdin.
Docker pulls and a workload soak remain performance gates. Repeat the Actions archive/upload fixture below, full
runner crash/adoption and window/focus/input checks before production rollout.

Stacks/cache services share a parsed policy snapshot for at most 250 ms.
Existing flows refresh once per revalidation pass; cache I/O adds no separate
per-connection throttle. These checks retain a 250 ms observation window; routing changes are not atomic.
Explicit gateway addresses, including those on /32 host links, are denied.
Non-default routed prefixes are denied, while Internet defaults, ICMP-redirect
dynamic routes and ephemeral cloned routes are excluded. Split-default VPNs can
conservatively block public
access; public networks represented only by a default cannot be classified as
LAN. Host/LAN services exposed through public NAT/port-forward, reverse-proxy
or tunnel endpoints are not identified unless the public destination appears in
denied local routes; those public endpoints remain reachable. Inventory and
protect such public services independently. These limits remain with the
rootless stack.

The network child must activate its restrictive Seatbelt profile before the VM
boots. It receives no credential environment and cannot read files, exec or
look up Mach services such as Keychain. The helper passes only its datagram,
lifetime, numeric-report, cache-broker and separate DNS-capability FDs. The broker hands out only
connected per-VM cache streams; it admits no paths or arbitrary dialing and
requires no additional sandbox permissions. This uses deprecated platform sandbox APIs;
API/profile/live-proof failure closes launch/adoption. Repeat the native child
and guest gates after macOS upgrades. `doctor` checks host policy availability,
not a successful child sandbox activation. No host service or privilege setup
is needed.

Guest egress is now attributed to `bivouac` (its network child and cache
controller), rather than Apple's NAT. Endpoint-security and network-filter
software must allow the required public DNS/HTTPS traffic for that process.
Bivouac does not reconfigure those tools or create a host/LAN exception.

For a later owner-controlled rollout, follow the [upgrade prerequisite](#upgrade-prerequisite)
with the installed binary; the new controller cannot adopt old clones. Validate
a separate DHCP baseline and loopback cache config; only then schedule binary migration. This PR stages
replacements and leaves the production VM backup, installed binary/config,
labels and Tartelet untouched. Restore the old controller after validation
when it is safe to resume its original routing. Do not merge before live gates
and an owner-approved migration plan are complete.

## Optional transparent caching

Caching is disabled by default. Darwin and Linux runners on macOS use guest-loopback HTTP
through a fixed cache-only virtual endpoint, with TLS and per-guest capabilities.
VSOCK remains the port-announcement/lifetime transport; it carries no cache payloads:

```toml
[cache]
enabled = true
release_proxy = true
store_uploads = true
listen = "127.0.0.1:0"     # default for macOS; literal loopback required
guest_host = "127.0.0.1"   # TLS identity, never a guest NIC route
max_gb = 4
max_object_mb = 512
```

Remove a gateway `guest_host` or wildcard `listen` from the validation config;
validation rejects them. Only `192.0.2.1:7443` selects the synthetic cache payload capability; it is not a
host address or a configurable host-network exception. The sandboxed child
receives connected stream FDs for the per-VM handler and cannot select Unix paths. A separate
`192.0.2.1:7444` capability serves only the signed public CRL at `/ca.crl` and
has its own 32-connection budget, so cold TLS revocation does not need a free
payload slot. The emitted guest proxy-bypass list includes this fixed virtual
address; it does not permit access to a real host/LAN address. Both private listeners close with the same owner/control lifetime.
 A cache outage falls back to public downloads through the same
mandatory guest isolation. Private adapter files and trust are installed only
inside disposable clones; capabilities and signed URLs never enter host state,
logs or diagnostics. Revocation, guest deletion or controller/service loss closes
the cache capability, active streams and guest-loopback listener. An adopted runner continues with
public fallback after controller loss; cache capabilities are not persisted or
reattached. Upload retries use the existing direct-upstream fallback.

The macOS adapter accelerates Actions v2 cache archives. With `release_proxy`,
bootstrap installs temporary root trust in each disposable clone and gives its
runner standard proxy settings through a loopback bridge. It caches eligible
GitHub release assets independently of the project or download tool. Private
assets fetched through signed URLs are cached too; each read still requires
upstream approval of its own fresh signed URL.
curl, Git, Node, and tools honoring `SSL_CERT_FILE` receive guest trust; other runtimes with separate trust
stores may need provider setup. The proxy sees traffic on its three intercepted
GitHub hosts, but caches no request carrying `Authorization` or cookies. Other
public HTTPS hosts use opaque tunnels. Host and baseline trust remain unchanged.
Newly uploaded Actions archives enter this read-through cache on
their first restore. With `store_uploads`, the host relays each save to GitHub's
storage and keeps what it sent, so the next restore is local. A save larger
than `max_object_mb`, or than idle objects can make room for, is relayed without
a copy; any relay failure sends the rest of that save directly to GitHub.
Every save is stored, evicting the least recently used objects, so size
`max_gb` for the archives saved between restores as well as those restored.
Upload storage is validated on macOS guests only; leave it off on a Windows
host until its guests are validated live. Misses stream as they fill. A service
outage, or a fill that fails before its first byte, sends the request upstream.
No upload/storage quota reduction is claimed. Logs report object class, hit/miss, size and a per-session object
label without source URLs or credentials. Limits include in-flight reservations of each fill's declared
size; eviction never touches instance state. Corrupt and incomplete objects are discarded.

Defaults are 20 GiB total and 2048 MiB per object; `max_gb` and `max_object_mb`
are configurable, with the object limit fitting inside the total (at most
1024 GiB). The 4096-object metadata limit is fixed. Active readers retain their
disk reservation. All object classes share the budget. Restart to load changes.
When the host service is unavailable, new guest proxy connections use upstream
directly. An already established transfer can fail and needs the caller's retry.
Do not configure workflows to depend on the proxy for network availability.

Opaque bytes live in `~/Library/Caches/bivouac` on macOS. The portable core
uses `%LOCALAPPDATA%\bivouac\cache` on Windows and the XDG cache directory
on Linux. HCS Windows and Crosvm Linux guest adapters are implemented
and validated for archive and release downloads. Upload validation remains as described above.
`BIVOUAC_HOME` isolates a cache under that test home.

To revert, finish work with `bivouac off --wait`, set `cache.enabled = false`,
`cache.release_proxy = false` and `cache.store_uploads = false`, then restart in
the desired mode. To stop storing saves alone, set `store_uploads = false`. To
keep Actions acceleration alone, leave `enabled = true` and set
`release_proxy = false`.
Fresh guests then receive no proxy root or settings. Cache objects are expendable; the cache
directory can be removed while off. Keep the ownership state directory
intact. Production cutover and Tartelet remain independent of cache setup.

### Investigating unexpected misses

A GitHub cache-key hit can still be a local miss: GitHub found the archive and
bivouac downloaded its bytes. Archive `bypasses` with `failures` mean a failed
local fill was redirected to GitHub. Release downloads appear under
`release proxy`.

In controller logs, follow the miss's `object` label (valid for one manager
session) through `cache object discarded` (`reason=capacity` or `invalid`),
`cache object validation failed`, `cache fill unavailable`,
`release cache bypass` and `cache response incomplete`. `cache store opened`
shows what survived a restart; `cache store summary` totals losses each minute.
Fill reasons are `capacity`, `object_limit`, `upstream_status`,
`upstream_identity`, `upstream_body`, `upstream_transport`, `upstream_idle`
(a minute waiting on upstream), `upstream_resume` (the object changed or ranges
are unsupported), `length_mismatch`, `timeout`, `canceled`, and `store_*` for
local filesystem failures. `cache fill resumed` names each resume's reason and
offset. `cache reader left during fill` is a guest that stopped waiting for
another request's fill, which continues.
`cache SSH transport ended during requests` names a guest whose transport
dropped mid-transfer. Keep the cache while investigating; it is evidence.

A relayed save logs `cache upload relayed` with its `guest`, then
`cache upload stored` (with `object`), `cache upload not stored` with a
`reason`, or `cache upload sent directly upstream`. Fallback reasons are
`unsupported_request`, `concurrency`, `expired`, `revoked`, `guest_body` and the
upstream transport reasons above. Repeated `unsupported_request` or
`concurrency` means the official action changed how it uploads.
Not-stored reasons include `block_list` (unparseable) and
`block_list_incomplete` (Azure accepted it before the host had all of it).
`cache upload not relayed` (`upload_limit`, `expired`) means the save went
directly; `cache uploads abandoned` counts relays open at revocation or shutdown.

### Cache validation fixture

`tools/cache-validation` runs the official Actions cache code, pinned to a
commit, in a guest. Credentials and action output stay there; it prints only
fixed outcomes and numbers. It needs self-hosted runners, so this public
repository has no workflow for it. Run one from a private repository on
isolated scale sets, for example:

```yaml
on:
  workflow_dispatch:
    inputs: {mode: {required: true}, nonce: {required: true}}
jobs:
  validate:
    strategy:
      fail-fast: false
      matrix:
        scaleset: [bivouac-cache-validation-macos, bivouac-cache-validation-windows, bivouac-cache-validation-linux]
    runs-on: '${{ matrix.scaleset }}'
    timeout-minutes: 20
    steps:
      - uses: <owner>/bivouac/tools/cache-validation@<commit>
        with: {mode: '${{ inputs.mode }}', nonce: '${{ inputs.nonce }}'}
```

Set each isolated provider's `scaleset` to its matching matrix entry. Scale-set
routing uses that single name, without a `self-hosted` or OS label array. For
REST JIT mode instead, set `[github].demand = "jit"`, give each provider a
positive `idle_pool` and an isolated label array, and use that same array in
`runs-on`, as described in "REST JIT fallback" above.

Use a separate validation `BIVOUAC_HOME` on each host; a Windows validation
home may contain both Windows and Linux providers. Never use the normal home
or production labels, or run two homes with the same controller/root at once.
Keep the provider-specific cache transport settings and enable the following
for `save`, `restore`, `mixed`, `outage` and `interrupt`:

```toml
[cache]
enabled = true
release_proxy = true
store_uploads = true
# Omit max_object_mb and max_gb: defaults are 2 GiB per object and 20 GiB total.
```

- `save` uploads 24 and 192 MiB archives under a fresh nonce, covering a
  single-request and a block upload. With `store_uploads`, the host must relay
  and store both, with no fallbacks. `restore` in a later job with that nonce must then hit locally twice
  with no misses; without `store_uploads`, both restores fill upstream.
- `mixed` overlaps restores with new uploads.
- `limited` requires `store_uploads = true` and a deliberately small limit:
  set `[cache].max_object_mb = 16` only for this mode. Saves and restores still
  pass, and both saves must increment the relayed-without-a-copy counter with
  no stored uploads. Disabled upload storage fails validation. Finish the
  isolated home's work with `bivouac off --wait` before changing the limit,
  then restart it to load the new value. Remove the override and restart before
  returning to normal validation with the default 2 GiB limit.
- `outage` checks release hits, then waits up to two minutes for the isolated
  controller to stop. Saves, restores and releases must still pass directly.
  Stop only the isolated controller, after confirming its process. The fixture
  publishes only a fixed stage enum in `RUNNER_TEMP/bivouac-cache-validation/stage.json`;
  `awaiting-outage` is the injection point. It contains no credentials or job
  identity, and is safe for a bounded ownership-checked host probe.
- `interrupt` requires `store_uploads`. It starts both saves through the relay
  and waits for the isolated controller to stop; stop it once the controller
  logs two `cache upload relayed` lines. At least one save must still be open
  then, and both must finish directly and restore intact.
- `fallback` expects caching disabled.
- Every mode checks release downloads through fresh signed URLs.

## Upgrade prerequisite

- **Drain before deploying:** finish standalone and container-pair vz guests with
  the installed binary and confirm empty records/registrations. Pre-upgrade
  markers without the exact provider field become foreign: never adopted or
  cleaned; running Darwin/unknown clones still consume host slots. Crosvm images
  from an older helper need rebuilding with `require_prepared`; otherwise a
  helper-hash mismatch uses the existing upload fallback.

## Cutover (after validation)

Do not cut over while an assignment or recovery problem remains in
`docs/status.md`. Validate idle dispatch, a dispatch 10 s after completion,
queued work across drain/on and off/on, controller and VM failure, and
reboot mode persistence. Host reboot validation is deferred until an
owner-arranged maintenance window; login is required after restart when
FileVault is enabled. LaunchAgent restart checks alone do not verify a host
reboot. A dedicated App is deferred, so do not revoke the shared App.

The intended production route is bivouac with no Tartelet fallback. The
owner has reserved the merge and actual cutover for later: prepare and
validate the routing PR, but do not merge or retire Tartelet now.
Windows/Linux runners are currently offline; unchanged CI selection still
requires their jobs for a workflow change. Missing checks are not passes;
no exception to the full merge gate has been authorized.

1. `bivouac off --wait`; edit the config: `scaleset = "bivouac-macos"`.
   Keep `max_instances = 1` and `foreign_slots = 1` while Tartelet runs.
   `bivouac doctor --github` creates the production scale set.
   `bivouac on`; confirm a `polling scale set` log and nonzero poll capacity
   before changing workflow routing. For pre-merge PR validation, this
   scale set can run alongside unchanged production routing; after its
   guests and registrations are gone, restore the experimental config and
   drain. Repeat activation of the production scale set before the later
   owner-controlled merge.
2. In each workflow, change the macOS jobs' `runs-on` from
   `[self-hosted, macOS, ARM64, tartelet]` to `bivouac-macos`. Merge
   through the normal CI gate.
3. Confirm a production macOS job passes on a fresh bivouac guest. Then
   quit Tartelet and remove it from login items. Keep its label and the
   shared App unchanged; no jobs are routed back to Tartelet. Set
   `foreign_slots = 0` only once
   its VM has stopped; any higher concurrency must still fit CPU, memory,
   and Apple's two-guest limit.
4. Delete the experimental scale set from the organization's runner
   settings once nothing references it.

## Recovery after cutover

The owner has declined fallback to Tartelet. If bivouac fails, use
`bivouac drain --wait` to finish healthy jobs, or `bivouac stop --wait` when
cancelling its jobs is necessary, then `bivouac off --wait`. Retain records
until runner cleanup completes. Jobs stay queued on `bivouac-macos` while
the controller is repaired, or route to an owner-approved alternative.
Do not restore the `tartelet` workflow labels or revoke the shared App.

## Day to day

| Command | Effect |
| --- | --- |
| `biv on` | accept jobs; scale-set demand or the configured REST idle pool |
| `biv drain` | no new jobs; active jobs finish; guests disposed; idle |
| `biv stop` | cancel now; guests destroyed; idle |
| `biv off` | drain, then the daemon exits and stays off across reboots |
| `biv status` | mode, phase, guests, pending runner cleanup, capacity, recent errors |
| `biv vz list` | guests bivouac owns, orphans, and foreign guests |
| `biv vz cleanup` | delete orphans carrying bivouac's marker (daemon stopped) |
| `biv doctor` | host, config, credential, engine, login item checks |

Logs: `~/Library/Logs/bivouac/bivouac.log`, per-guest `<name>.launch.log`,
and `diagnostics/<time>-<name>/` with `instance.json`, the runner log, and
`_diag`. The daemon log and diagnostics are redacted at the sink. The launch
log is not: the VM helper writes fixed host-side status and numeric network counters there
directly, unredacted, capped at 1 MiB per helper with reserved terminal status space, because
the helper must outlive the
daemon. The guest console is never attached.

## Interrupted jobs and recovery

Stop signals the official runner before VM shutdown, allowing up to 30 s
for job termination to reach GitHub; the run can conclude as failed. The
worker may spend 10 s escalating signals before reporting. A ten-second
grace failed during REST validation; the 30 s repeat fully cleaned up in
18.6 s.
Diagnostics and guest deletion follow. A dead VM cannot report a result:
GitHub may reject deregistration with "job still running" until it cancels
or times out the job. Once VM absence is confirmed and saved, the record
changes to `deregistering`; VM, CPU, and memory capacity return immediately.
Status lists the pending registration separately. Deregistration retries
every 5 s, including after restart; drain/off still wait for full cleanup.
A failed or uncertain guest deletion keeps its VM reservation.
Only a successful deletion, HTTP 404 from the runner DELETE, or the SDK's
typed missing-runner response releases the record; arbitrary `404` text in an error does not.

Keep an explicit workflow `timeout-minutes`. Unattended guest-loss tests
with one- and five-minute limits became terminal after six and ten minutes,
respectively, with execution-timeout annotations. The fixed repeat cleaned
up 337.6 s after guest loss, on the next retry after terminal status.
The REST repeat also ended at six minutes: cleanup finished 342.7 s after
guest loss and 2.2 s after terminal status. REST busy deletion returned
HTTP 422 and retained the record; the queued follow-up passed.
These historical measurements predate capacity release during registration
cleanup. A longer
workflow limit still delays remote deregistration, but no longer holds a
confirmed-deleted VM slot. The host's `job_timeout` does not cancel a job
whose runner is already dead. Whole-workflow cancellation remains disabled.
Do not treat `guest gone` alone as proof:
verify no record, owned clone, or runner registration remains, then verify
queued work resumes.

`budget.max_pending_cleanup` defaults to 2: one pending registration permits
replacement work with `max_instances = 1`; two pause new provisioning until
a retry succeeds. The total record bound is `max_instances +
max_pending_cleanup - 1`, including guests still alive, to bound simultaneous
failures. Set the threshold to 1 to restore conservative admission without
replacing the binary; restart the daemon to load the changed config.
Keep instance records intact: deleting them loses
registration cleanup ownership. Scale-set recovery uses one bounded sweep
per pending record for jobs GitHub routes by label; a sweep with no job
retires under `sweep_idle_timeout`.

If a validation run needs operator cancellation, target its exact run ID:
`gh run cancel <run-id> --repo <owner/repo>`. If normal cancellation hangs,
`gh api repos/<owner>/<repo>/actions/runs/<run-id>/force-cancel --method POST`.
Wait for `guest gone`, no owned VM in `bivouac vz list`, and no instance
record before proceeding. Never cancel an unrelated or production run.

After SIGKILL, launchd restarts the controller and it adopts the live
runner. A replacement scale-set session can return 409 until GitHub expires
the dead session; the controller retries with bounded backoff. The current
job continues independently. Do not repeatedly restart the controller or
delete the scale set to resolve that temporary conflict.
New work queued during the conflict was verified to survive it: polling
reopened after 129 s, the active job passed, and the queued job then passed
in a fresh guest. A live guest still occupies the single VM slot; a confirmed-deleted guest
now releases that slot while its registration cleanup continues.

## Optional containers: preparation and validation

This mode is experimental and has not passed live isolation validation.
Leave it disabled on the installed controller until the gates below pass.
Use a separate `BIVOUAC_HOME`, an isolated `bivouac-` test scale set or JIT
label, and a one-job budget. Never change Tartelet, production labels, or the
personal Docker/Podman/Lima configuration.

Prepare a **local Linux/arm64 Tart-format VM** through the image
administrator's normal process, shut it down, and import it with
`bivouac vz import`; keep the imported baseline immutable. It
needs the linux/arm64 `bivouac` binary at `/usr/local/bin/bivouac` with
[`bivouac-guest-agent.service`](../tools/linux/bivouac-guest-agent.service)
enabled, a rootful Docker daemon at
`/var/run/docker.sock` **or** a rootful Podman API service at
`/run/podman/podman.sock`, and permission for guest exec to access that socket.
Both baselines must use DHCP networking and DNS; each rootless link supplies
its own virtual resolver. Do not include registry credentials, configured
runners, host directory shares, or personal keys. The macOS baseline needs the
selected CLI; the source baseline is never modified by bivouac.
No guest agent, engine, client, or baseline is downloaded automatically.

Build the Linux helper from the same source as the host binary using installed Go:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o ./bivouac-linux-arm64 ./cmd/bivouac
CGO_ENABLED=0 go build -trimpath -o ./bivouac ./cmd/bivouac
codesign --force --sign - --entitlements tools/macos/bivouac.entitlements ./bivouac
```

Keep the Linux binary at a stable host location and reference its absolute path.
Add to the isolated provider configuration:

```toml
[providers.macos.vz.containers]
engine = "docker"            # or "podman"
baseline = "ci-linux-engine"
cpu = 2
memory_gb = 2
helper = "/opt/bivouac/bivouac-linux-arm64"
```

Explicitly size the macOS guest too; admission reserves the sum of both VMs.
Include other managers' CPU/memory needs in host reservations. The engine adds
no macOS licence slot, but does consume host CPU, memory, and disk space.
No engine-specific arbitrary launch flags, socket overrides, or host mounts
exist. Leave `bootstrap_share` empty and `cache.enabled = false`.
Do not change container topology or engine while any instance record remains.

The rootless network stack needs no host privileges. Bivouac does not edit sudoers, set SUID, install a privileged helper, or
change its policy to work around a failed probe. Run `bivouac config validate`
and `bivouac doctor` with the isolated config; `bivouac engine check-isolation`
checks the host-side prerequisite without credentials, daemon access, a VM,
or network changes. Doctor checks local baseline OS/architecture and helper
architecture; it does not prove guest VSOCK or engine readiness.

After prerequisites pass, validate only disposable, recorded pairs:

1. Start one throwaway test job. Confirm both clone names and matching IDs/parent
   links exist in state and provider markers before issuing stop/delete operations.
   Check both live helper commands prove `--rootless-network`, with no
   `--share` or `--input`, and both markers identify `rootless-sandbox-public-ipv4`.
2. From each guest and from a privileged container, verify public DNS/HTTPS works
   while host gateway services, host interface addresses, private LAN, peers,
   metadata/link-local addresses, and IPv6 destinations are unreachable. Use
   explicit benign test endpoints; do not scan the LAN or target production services.
   Exercise policy refusal on existing and new flows; route changes retain the
   non-atomic observation window described above.
3. Verify the selected client uses only the guest Unix socket. Test version/ping,
   image pull, context build, binary `cp`, concurrent requests, and exec/attach
   upgrades. Use public images without credentials. Bind paths are inside Linux;
   port publication does not forward to the macOS runner or physical host.
4. Exercise controller crash/adoption, supervisor loss, each VM stopping, and
   partial deletion failure. Confirm the listener disappears on transport loss,
   both recorded VMs are retired, and capacity remains reserved until both are
   confirmed absent. The runner registration still follows normal cleanup retries.
5. Confirm a second job gets new engine state and no previous sentinel/container.
   Leave the isolated controller drained with both VMs, registration, and record
   gone. Retain the evidence before enabling this mode for untrusted workflows.

Never manually erase a pair record to force cleanup: a pair without its durable
record becomes unmanaged and is intentionally excluded from generic orphan
cleanup. Restore ownership evidence before recovery. Stopping a live supervisor
retires its recorded pair; it is not a transparent connection restart.

## Preparing a Linux ARM64 runner baseline

`vz.baseline` is required. The sole recipe supports a disposable Ubuntu 24.04
Server ARM64 image with one virtio NIC. Use an operator-managed Tart-format image;
remove other preparation agents/accounts and credentials before capture.

1. Build the matching static helper on the host:

   ```sh
   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o linux-arm64 ./cmd/bivouac
   ```

2. Stage this exact helper file and the official ARM64 runner archive in the
   image, owned by root and protected from other users' writes. Configure the
   identical helper file as `vz.helper` on the host; another build may hash
   differently. Obtain the archive's published SHA-256; stage no credentials or
   JIT input. Rebuild the baseline whenever the configured helper changes.
3. As guest root, run the fixed command with bounded JSON stdin:

   ```sh
   /tmp/linux-arm64 guest linux provision <<'JSON'
   {"recipe":"ubuntu-24.04-arm64-vz-runner","runner_archive":"/tmp/runner.tar.gz","runner_sha256":"<published-sha256>"}
   JSON
   ```

   It verifies/extracts the archive, installs itself and its embedded agent unit,
   creates the non-root Docker-enabled user, prepares DHCP DNS/MTU without forced
   resolvers or a network restart, disables SSH/cloud-init provisioning, removes
   standard authorization/history, and runs shared VZ image sanitation. If installed,
   cloud-init must report `done` or `disabled` in bounded JSON before mutation;
   degraded completion (exit 2) is accepted. Unknown layouts refuse preparation;
   failures report only a numeric `failed_stage`.
   Inspect or replace a failed preparation image.
4. After success, remove remaining staging/provisioning artifacts and shut down
   cleanly. Import the stopped image on the host:

   ```sh
   bivouac vz import --runner-dir /opt/actions-runner <stopped-image-directory> ci-linux-arm64
   ```

   Add `--sudo` only for operator-verified passwordless guest sudo; the recipe adds
   no sudo rules. Without it archive caching works and release trust is omitted.
5. Run `doctor` and the isolated, gated Linux fixture above (optionally
   `BIVOUAC_VZ_LINUX_CACHE=1`) before using a new baseline.

Package installation uses the image's Ubuntu repositories; this is not a
reproducible OS-image builder. The default-baseline builder is a follow-up.
