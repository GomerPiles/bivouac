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

Windows host experiments have separate operator procedures:
[`windows.md`](windows.md) for the elevated App Sandbox broker and protected
storage, and [`crosvm.md`](crosvm.md) for the ordinary-user Linux GPU supervisor.
Keep production controllers and labels unchanged until the operator approves
cutover after the relevant live validation. Remaining isolation gates still apply.

## Windows development boundary

Windows providers remain experimental; do not point them at existing production
VMs. Use a separate checkout and `BIVOUAC_HOME` for disposable validation.
`version` and native foundation tests need no GitHub credentials or VM launch.
The optional Windows login task runs only the ordinary manager; native engine
and broker prerequisites are still operator-managed. Foreground operation needs
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
have stopped, and restore missing broker prerequisites before manager recovery.
Without an `engine_startup` entry, an unavailable broker remains an explicit
operator prerequisite. An optional `engine_startup` manifest entry can name
[`Start-VMEnginePrompt.ps1`](../tools/windows/Start-VMEnginePrompt.ps1) within the
same home. The protected engine directory is fixed at
`%ProgramFiles%\bivouac\engines`: the user-writable manifest cannot move it,
and `Control.ps1` refuses an `engine_directory` entry naming another path.
Explicit CI On then requests Administrator consent through Explorer only when
doctor reports an unavailable Windows broker. The prompt launches only the protected helper; approve it only
if the consent dialog's details name that helper's path. CI On waits for typed
startup progress from the engine directory, preserves failed-check details and
starts the manager as the ordinary user. No login startup, service, PATH or
host trust installation occurs. Shortcut installation and production routing
are separate, operator-authorized actions; preserve previous targets for rollback.

**Protected engine directory.** The elevated [`Start-VMEngines.ps1`](../tools/windows/Start-VMEngines.ps1) and
everything it trusts live in one engine directory, never in `BIVOUAC_HOME`:

| File | Contents |
| --- | --- |
| `Start-VMEngines.ps1` | the elevated helper |
| `engines.json` | `Home` (absolute `BIVOUAC_HOME`), `Controller`, `OwnerId`, `OwnerFile`, `Credential`, `Daemon` and `DaemonSHA256`, `Broker` (file name here) and `BrokerSHA256` |
| `broker-options.json` | the broker bounds in [`windows.md`](windows.md) |
| the `Broker` executable | validated `bivouac` CLI, used for `appsandbox inspect` and the broker |

The helper writes only here: `engine-startup.json`, `daemon-launch.json`,
`broker-launch.json` and `logs\`. The directory and its files must be owned by
Administrators, SYSTEM or TrustedInstaller, grant nobody else write, delete or
permission rights, contain no reparse points, and have ancestors that cannot
rename them; a folder created elevated under Program Files inherits suitable
rights. Before trusting any input, the helper checks this, PowerShell, and each
executable and its folder. It hashes each executable through a handle that
denies writers until the process has started. It also checks the App Sandbox
data folder before starting anything, and the discovery file and `vms.cfg`
once the daemon is ready; the broker re-checks its options and both files.

The home's manager state, the storage owner marker and Linux records only
gate refusal. The helper starts only absent native prerequisites. Owned journals
predating the current host boot are allowed after exact
controller/instance/native-record checks; they are left for normal manager
reconciliation. Active or unmatched instances refuse startup without stopping
anything; a marker-only Linux `.creating-<id>` staging directory is left for
the backend to sweep. The read-only mode (no `-Execute`) reports the intended recovery.
Same-account consent is not a boundary against code already running as that
user, which can raise its own prompt or influence the elevated environment;
approve only a prompt you requested.

**App Sandbox prerequisites.** Both App Sandbox locations must meet the same
protection rules, and a typical installation meets neither:

- *Installation folder.* `Daemon` is pinned like the broker: the executable,
  its folder and every ancestor must be protected, and the folder must not
  admit new files, because the daemon loads the DLLs beside it. A folder made
  on a data drive usually inherits the drive root's Authenticated Users Modify
  right, which includes Delete, so any user can rename an ancestor and the
  helper refuses it. Move the complete installation folder (executable, DLLs
  and every subfolder, such as `drivers`, `resources`, `web` and
  `headless-api`) unchanged into a folder created elevated under
  `%ProgramFiles%`, and set `Daemon` to the new executable. The bytes are
  unchanged, so `DaemonSHA256` stays. Do not broadly harden a shared CI folder
  to make the old location pass; other controllers may rely on its rights.
  On the reference host no service, startup entry or App Sandbox data file
  named the installation folder, and its drivers live in the driver store.
  The daemon writes its log beside its executable, which under Program Files
  only the elevated daemon can do. Keep the old folder until the relocated
  daemon has served a fresh guest.
- *Data folder.* The broker reads `%ProgramData%\AppSandbox\host.json` and
  `vms.cfg`. If App Sandbox first ran unelevated, that folder is owned by the
  ordinary account, which also holds Full control through the inherited
  CREATOR OWNER entry, while both files themselves pass. With the daemon
  stopped, correct only that folder from an elevated PowerShell, naming the
  ordinary account; this leaves its subfolders and files, and the create rights
  ProgramData gives Users, unchanged:

  ```powershell
  $data = Join-Path $env:ProgramData 'AppSandbox'
  icacls $data /setowner '*S-1-5-32-544'
  icacls $data /inheritance:d
  icacls $data /remove:g '<ordinary-account>'
  ```

The read-only mode checks both before it reports anything. While either is
unmet it refuses with a message starting `App Sandbox installation` or
`App Sandbox data folder`.

To migrate a home-based layout:

1. Turn CI Off and wait until the manager has exited and `bivouac status` lists
   no instance. The helper refuses instances created since the current boot.
2. Confirm `bivouac appsandbox inspect` shows no running or building VM. Then,
   from an elevated shell, stop the broker and then the App Sandbox daemon,
   identified by the PID and start time in the home's `broker-launch.json` and
   `daemon-launch.json`, never by process name alone.
3. Meet the App Sandbox prerequisites above.
4. Copy every home file the following steps change, for rollback. From an
   elevated shell, create `%ProgramFiles%\bivouac\engines`. Move
   `Start-VMEngines.ps1` (replaced by this version), `engines.json` and
   `broker-options.json` from the home into it. The options are unchanged, so
   the storage root's `broker.json` binding still matches.
5. Copy in the broker's `bivouac` executable. Broker and manager change
   together: use the build named by the manager's `portable.json` and deploy
   that manager build in the same window. A new build needs a new
   `BrokerSHA256`; keep the old pin only for identical bytes.
6. In `engines.json`, add `Home` (the absolute `BIVOUAC_HOME`) and set `Broker`
   to the bare file name of the copied executable. A path such as `bin\…` is
   refused. Update `Daemon` if App Sandbox moved.
7. Replace `Start-VMEnginePrompt.ps1` and `Control.ps1` in the home with this
   version, and remove any `engine_directory` entry from `portable.json`.
   Shortcuts to those scripts keep working.
8. From an ordinary shell, run the read-only mode,
   `pwsh -NoProfile -File "$env:ProgramFiles\bivouac\engines\Start-VMEngines.ps1"`;
   it must report the intended action without refusing.
9. CI On. Approve the consent prompt only if it names the helper in the engine
   directory.
10. Archive the home's old progress, launch records and broker logs; they are
    no longer read.

To roll back, with CI Off, stop the new broker and daemon the same way, restore
the copied home files and the previous manager build, and start App Sandbox
from its previous folder. The data folder correction can stay.

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
or controller ownership. Never have two homes concurrently use the same broker
controller/root. Mac and ARM64 routing need not change.

`bivouac appsandbox inspect` reads `%ProgramData%\AppSandbox\host.json`, checks
the live daemon identity, and prints typed version/capacity/storage and foreign
VM/template inventory. Storage paths are diagnostic metadata, never ownership
authority by themselves. `--discovery <file>` overrides the path for an isolated daemon (and
is required on other host platforms). No configuration, GitHub credentials,
state directory, window opening, adoption, or lifecycle action is involved.
Do not paste the discovery file into logs: it contains a per-run bearer token.

`secret set/check/delete` uses the current Windows user's Credential Manager.
Values enter through the existing file/stdin interface; generic items use the
`bivouac/` namespace. Values must contain 1–2,560 bytes; larger PEM keys are
rejected. Run an optional login item under this same user. Native credential tests
are opt-in: `BIVOUAC_WINDOWS_CREDENTIAL_TEST=1 go test ./internal/secret` writes,
updates, reads, and removes a randomly named synthetic fixture. It never
enumerates or reads existing items; normal tests use a fake backend.

If App Sandbox discovery points to an unreachable daemon, report the failed
connection and stop live validation. Do not automatically launch an elevated
daemon, stop another controller, infer liveness from old status files, or
reuse production instances. No administrator prompt is needed for the tests
or a read-only inspection of an already accessible daemon. The operator must
arrange API availability and
isolated baseline/instance ownership. Validate actual GPU/session behavior and
host/LAN denial separately; NAT or Slirp connectivity alone is insufficient.

For operator-approved template provisioning, use a separate storage parent,
persist intent before the request, and never precreate the native VM child.
App Sandbox 0.1.9 requires a nonempty guest password even for templates; generate
it without recording it in diagnostics/state. Creation is asynchronous and
auto-starts. A successful HTTP response or image progress of 100% does not prove
the guest completed setup/Sysprep or entered template inventory. After an
uncertain request, retain intent/storage and inspect; do not retry blindly.
Keep network/GPU disabled during baseline creation and do not register runners.

For BCDBoot failures, capture verbose child output on an independently owned
test disk before changing arguments or production tools. Exit 183 was observed
here at an offline BCD hive load (`0xc0000035`); drive letters and `/offline`
did not fix it. Compare host BCD/firmware enumeration digests and remove only
the test disk's temporary access paths. Do not unload, rename, delete, or relax
permissions on the active host BCD hive as a provisioning workaround. A copied
BCD file is not proof of a valid store or successful guest boot.

The GUI and headless API share the Windows conversion path. If GUI creation
works while an automated attempt fails, compare the launch context before
changing guest registry metadata. In isolated testing, helpers inherited a
process job from the development application; the same elevated disk operation
launched through Explorer and normal UAC consent had no job membership and
succeeded. A breakaway flag alone did not reproduce that context. Keep this an
operator-approved provisioning step; do not introduce implicit privileged
launching, loosen host permissions, or assume any scheduled-task/service context
is equivalent without validation. Successful BCDBoot still does not prove guest
setup/Sysprep, template inventory, or desktop readiness.

The same Explorer launch context has now completed isolated template creation:
conversion, preparation boot, automatic shutdown, and native registration.
Verify the registered template's native VHDX path against the prior intent and
storage marker; template inventory alone omits that path. Inspect a stopped
template only through a read-only attachment and remove its access path/detach
in cleanup. Record Sysprep errors alongside successful generalization/shutdown;
the validated creation here retained firmware-export errors (`c000000d`). A
disposable clone boot remains necessary before claiming the baseline reusable.
When retiring a daemon started for validation, match its recorded PID/start
time and live API identity, recheck all guests/controllers, and use native
`POST /v1/shutdown` with `force=false`. Never force shutdown to finish validation.

Disposable Windows clones should auto-start with native networking disabled;
attach any isolated network only after recording its ownership and policy.
SSH forwarding uses the native loopback/HvSocket path independently of the NIC.
Deliver bounded probe files over that transport and run desktop tests through
an interactive guest logon task; a service-session graphics probe is insufficient.
Verify fresh-state sentinels before copying probe files, and baseline hashes
after discarding the clone. Network-policy readback must be accompanied by
real denial probes and reachable positive controls. In current testing,
Hyper-V firewall settings reported loopback disabled while native VFP rules
still allowed host addresses before explicit blocks. A host-interface firewall
rule alone also failed to block the host's LAN address. Neither is an approved
isolation recipe. Keep experimental switch/port policies owned and disposable;
never alter a shared Default Switch to make validation pass.
An independently owned stateless VFP layer subsequently passed host TCP/UDP
denial for IPv4/IPv6 with reachable controls, public connectivity, and changed
guest source addresses. It is a validation prototype: runtime integration,
private-peer denial, and crash/reboot policy recovery remain prerequisites.
Preserve the Windows service-owned layer. Verify actual native policy after
each mutation; `vfpctrl` does not produce consistently structured JSON for
mutations, and an empty enumeration can report `ERROR_NO_MORE_ITEMS`.
During owned policy cleanup, resetting the last boolean overrides to
`NotConfigured` can remove the VM setting automatically. Query remaining
persistent policy before issuing another remove, and confirm its absence;
do not infer complete cleanup from a successful default-action removal.

## Direct HCS VM host

The VM host is the elevated half of the direct HCS provider. You can run it
either way:

- as an optional service, installed once by an administrator; or
- in the foreground from an elevated shell, with one UAC prompt per start.

Nothing reboots, enables Windows features or installs drivers. Hyper-V's
compute and network services must already be running.

1. Place `bivouac.exe` in an administrator-protected directory, such as
   `%ProgramFiles%\bivouac`. The service runs that file as SYSTEM, so the
   ordinary user must not be able to replace it.
2. Write the configuration in a protected directory too, for example
   `%ProgramData%\bivouac\vmhost.json`:

   ```json
   {
     "root": "C:\\ProgramData\\bivouac\\vmhost",
     "controller": "host-1",
     "accounts": ["<the manager user's SID, from whoami /user>"],
     "images": {"windows": "D:\\RunnerImages\\prepared.vhdx"},
     "max_instances": 2,
     "max_cpu": 8,
     "max_memory_mb": 16384
   }
   ```

   Images must also be administrator-protected; the Hyper-V VM group may
   read them.
3. Either install the service or run in the foreground. Both commands are
   elevated:

   ```powershell
   & "$env:ProgramFiles\bivouac\bivouac.exe" vmhost install --config C:\ProgramData\bivouac\vmhost.json
   & "$env:ProgramFiles\bivouac\bivouac.exe" vmhost run --config C:\ProgramData\bivouac\vmhost.json
   ```

   Installing creates the protected journal root if it is absent. It
   registers a manual-start service that restarts after a crash, and grants
   the configured accounts query, start and stop rights on that service only.
4. From the ordinary account, use `bivouac vmhost start`, `bivouac vmhost stop`
   and `bivouac vmhost status`. Stopping the service destroys its guests
   first.
5. To remove it, stop it, then run `bivouac vmhost uninstall` elevated. A
   running service is refused.

The service logs to `vmhost.log` in its root. Any guest left by an earlier VM
host is settled when it next starts.

## Direct HCS lab batch

`TestLabBatch` in `internal/vmhost` boots disposable guests from an existing
prepared image through the direct HCS code. It is opt-in: it needs the
`integration` build tag, an explicitly elevated launch, and lab flags. It runs
these cold boots in order:

1. A baseline guest (2 CPU, 4 GiB).
2. The same with lazily committed memory.
3. A guest whose parent is a flattened copy of the image.
4. Two production-sized guests (4 CPU, 8 GiB).

Each run checks the guest agent, SSH and desktop rendering. The baseline run
also checks that an unelevated process reaches only the HvSocket service its
account was granted.

The batch attaches no network adapter, so it changes no host networking, and it
never touches another compute system, the App Sandbox broker or production
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

**VM store.** Baselines and clones live in bivouac's VM store:
`~/Library/Application Support/bivouac/vms`, or `vms` under `BIVOUAC_HOME`.
`bivouac doctor` names it and checks the baseline's manifest and that the
store path is short enough for guest agent sockets (103 bytes on macOS). Import a
stopped Tart-format VM, which clones it when it is on the same volume and
writes the manifest:

```bash
bivouac vz import --runner-dir /Users/admin/actions-runner --sudo ~/.tart/vms/<vm> <baseline>
```

Pass `--sudo` only if the guest user has passwordless sudo (the release
proxy needs it). The import records this binary's guest agent protocol, so
import again after installing a new agent. A Linux engine baseline needs no
`--runner-dir`.

Bivouac does not see VMs in other tools' directories, so `foreign_slots`
must reserve Apple's guest slots for any other manager.

**macOS baseline.** Bivouac reaches the guest through its own agent, not
Tart's (which exits on hosts that are not Tart). Until bivouac can prepare
baselines itself, prepare one with Tart before importing it:
boot it, then install the darwin/arm64 `bivouac` binary as
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
| `dns_setup` | Public DNS setup in optional container-pair guests |

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

## Optional transparent caching

Caching is disabled by default. On the experimental macOS setup:

```toml
[cache]
enabled = true
release_proxy = true  # optional GitHub release interception; default false
store_uploads = true  # optional local copy of each Actions save; default false
guest_host = "192.168.64.1" # host gateway reachable from the owned guest
max_gb = 4
max_object_mb = 512
# listen defaults to "0.0.0.0:0" (the vmnet bridge may not exist before a
# guest runs); TLS and per-guest capabilities are required
```

Confirm the guest gateway on an owned clone; do not assume the same address
on another provider. Restart the daemon to load changes, using the recorded
PID and replacement procedure above. Each fresh guest gets its own private
adapter, TLS trust, and expiring capability. No baseline or workflow change
is needed. GitHub remains the authority for Actions cache scope and keys;
metadata uses the normal upstream service.

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
on Linux, but their guest adapters are not yet implemented or validated.
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
or production labels, or run two homes against one native broker at once.
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
  Stop only the isolated controller, after confirming its process.
- `interrupt` requires `store_uploads`. It starts both saves through the relay
  and waits for the isolated controller to stop; stop it once the controller
  logs two `cache upload relayed` lines. At least one save must still be open
  then, and both must finish directly and restore intact.
- `fallback` expects caching disabled.
- Every mode checks release downloads through fresh signed URLs.

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
log is not: the VM helper (and Softnet) write host-side status there
directly, unredacted and unbounded, because the helper must outlive the
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
Guest exec also needs root or noninteractive guest sudo to configure public DNS.
Do not include registry credentials, configured runners, host directory shares,
or personal keys. Disable baseline DNS automation that would overwrite the
public resolver configuration. The macOS baseline needs the selected CLI and
noninteractive **guest** sudo for `networksetup`; it is never modified by bivouac.
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

Host Softnet privileges are an owner-managed prerequisite, separate from guest
sudo. Bivouac does not edit sudoers, set SUID, install a privileged helper, or
change its policy to work around a failed probe. Run `bivouac config validate`
and `bivouac doctor` with the isolated config; `bivouac engine check-isolation`
checks the host-side prerequisite without credentials, daemon access, a VM,
or network changes. Doctor checks local baseline OS/architecture and helper
architecture; it does not prove guest VSOCK or engine readiness.

After prerequisites pass, validate only disposable, recorded pairs:

1. Start one throwaway test job. Confirm both clone names and matching IDs/parent
   links exist in state and provider markers before issuing stop/delete operations.
   Check both launch commands contain `--softnet` and a `--softnet-block` list
   with `@host`, with no `--share` or `--input`.
2. From each guest and from a privileged container, verify public DNS/HTTPS works
   while host gateway services, host interface addresses, private LAN, peers,
   metadata/link-local addresses, and IPv6 destinations are unreachable. Use
   explicit benign test endpoints; do not scan the LAN or target production services.
   Keep public host interfaces stable; changed-interface handling is not atomic.
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
