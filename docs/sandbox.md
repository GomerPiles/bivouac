# Windows Sandbox lab

This is a credential-free spike, not an enabled CI provider. It uses the
Windows Sandbox installation and CLI already on the host. It never reads a
normal bivouac home, changes CI mode, contacts the bivouac VM host service,
installs a host service/task/driver, edits host firewall rules or registers runners. The
explicit `--native-probe` option requests UAC for read-only discovery only;
its manager and guest-command transport remain unelevated.
Keep any concurrent HCS development in its own worktree.

## Repeat the offline probe

Run from an ordinary Windows desktop shell. An agent execution environment can
restrict the Sandbox app alias or native networking independently of Windows.
The lab requires an interactive desktop session and opens the Sandbox desktop
client. It refuses an occupied Sandbox slot; close unrelated sessions yourself
when convenient rather than stopping them through the lab.

Build both executables and use an official Windows x64 runner ZIP with its
SHA-256 from the corresponding GitHub release. `--root` must be an existing
directory outside production state; `bin` is ignored by Git.

```powershell
New-Item -ItemType Directory -Path bin -Force | Out-Null
go build -o bin/bivouac-sandbox.exe ./cmd/bivouac
go build -o bin/sandbox-lab.exe ./cmd/sandbox-lab
$labArgs = @(
    'run', '--root', (Resolve-Path bin).Path,
    '--bivouac', (Resolve-Path bin/bivouac-sandbox.exe).Path,
    '--runner', (Resolve-Path '<runner.zip>').Path,
    '--runner-sha256', '<official-64-digit-lowercase-sha256>'
)
& ./bin/sandbox-lab.exe @labArgs
```

The lab copies assets into a fresh private directory under `--root`. The
source and copied ZIP must both match the pin. Its fixed bootstrap verifies
the ZIP again inside Sandbox before extraction. No host checkout, user profile,
credential store or existing runner directory is shared.

The default requests 4 GiB, networking/vGPU disabled, and disabled clipboard,
printer, audio and video redirection. It installs only guest-local probe tasks
and binaries. It tests the guest's active RDP context, the shared agent's
framing/command jobs over an in-memory link, the official unconfigured listener,
bundled Node and PowerShell, and network absence. The listener's expected exit
1 is a positive unconfigured-runner check, not an accepted GitHub job.

Each run retains `record.json`, bounded public reports under `output`, and
`result.json`. stdout contains the same result predicates and monotonic timing.
`smoke.protocol` reports the in-guest protocol test. Top-level `agent` reports
the separate host/guest framed transport; it stays false for an offline run.
`input` inside the outer smoke reports host-to-guest transport stdin, whereas
`smoke.protocol.input` is the in-guest framing check. Missing proof is never
reported as success. No JIT input or GitHub registration command exists here.

## Explicit network probes

Append `--network-probe` to test host-to-guest mutual TLS, or `--reverse-probe`
to test a guest-initiated connection to a temporary host listener. The latter
implies networking enabled. These modes run only the same fixed trusted
smokes. They allow normal Sandbox networking and do not establish host/LAN
isolation. Do not add real jobs or credentials to them.

The direct mode adds a program/port-specific inbound rule only inside the
disposable guest. Reverse mode uses a temporary host TCP listener, with the
exact expected guest IP and mutual certificate authentication, and creates
no host firewall exception. Public client certificates and server fingerprints
use the diagnostic share; private keys are generated and retained only in
process memory. A timeout is not counted as a successful authentication refusal
when TCP reachability itself is absent. Both live directions currently time
out in the tested environment; authentication works in local socket tests.

## Private transport and native ownership

Append `--native-probe` to the offline command to run the working host/guest
transport probe. Start the manager from the ordinary desktop shell; it refuses
an elevated manager. Approve the UAC prompt for the fresh copy of the same lab
binary. That short-lived helper enumerates compute systems, queries only
Sandbox-class candidates and runs fixed public identity checks. It installs
nothing and changes no compute system or shared host setting. It receives no
JIT data or secrets.

The CLI session UUID is **not** the HCS compute/runtime UUID. Passing it to
`HcsOpenComputeSystem` returned system-not-found even elevated. Discovery
instead checks each Sandbox-class candidate's native type, state and owner,
then uses the lab's parent-only HvSocket service to obtain the exact guest CLI
UUID, prefixed name and boot UUID. Only a unique full match is accepted. An
extra candidate, a recognizable owner or a nearby launch time is insufficient
to authorize a binding. The native tuple is saved in `record.json.native`.

The ordinary user can then dial that runtime UUID without further elevation,
IP networking, firewall exceptions or global service registration on the tested
host. The probe checks command/stdin delivery, runner/runtime smoke, nonzero
exit, cancellation followed by a healthy request, guest-loopback refusal and
reconnection after restarting only the owned guest's agent task. A new public
agent generation proves the restart; both the original boot identity and
post-restart stdin must still match. This passed live with zero active guest
network interfaces. `native`, `agent`, `native_exit`, `native_cancellation`,
`native_loopback_refused` and `native_restart` report these separate gates.
Cancellation does not establish survival or cleanup of an official running job.

Before cleanup, native-bound runs require the fresh CLI challenge **and** the
native channel's matching guest identity. The CLI inventory confirms the CLI
session absent after stop; it does not itself prove native compute-system
absence. A separate elevated read of the recorded native ID also confirmed
absence in the live probe. No hard-crash adoption, reboot recovery or
ambiguous-launch cleanup is implemented. The default host-account authorization on Sandbox's HvSocket
services is also unverified; this is not yet a channel for sensitive CI data.

Discovery currently needs one UAC approval per native probe. An ordinary host
can bind temporary wildcard/child HvSocket listeners, but the tested guest
callback to an unregistered service was refused with Winsock 10061. That is an
observation, not a diagnosis or proof that service registration would fix it.
No global registration or host-policy change was attempted. A supported
unelevated discovery path or an explicitly installed read-only broker remains
a product-design gate.

## Ownership and cleanup

The durable prefixed-name/UUID intent precedes launch. A matching CLI receipt
is required before the lab can stop anything. Each proof uses a new public
request UUID, a marker installed in the specific guest and its initial boot
UUID. Cleanup repeats that proof against the current CLI ID, then confirms the
ID absent before marking state stopped. Records use atomic flushed replacement
outside mapped folders. A challenge is non-secret, read only after explicit
dispatch, and written directly because Sandbox's share service can deny rename.

On uncertain launch, missing desktop, changed marker or failed cleanup, retain
the directory. Do not kill Sandbox processes by name or run host-wide cleanup.
The lab does not automatically reclaim retained instances, adopt a daemon's
guests or recover a hard-killed launcher. Native-bound runs add the corroborated
native/runtime tuple and a live native-channel identity check described above.
There is still a check/stop race against same-account replacement and no
authoritative effective-configuration reader. Same-account host processes are
within the lab trust boundary. Native tuple evidence does not authorize a
host-wide process kill, native delete or foreign-instance sweep.

Optional read-only diagnostics are `sandbox-lab inspect <native-id>` and
`sandbox-lab inventory <cli-id>`. HCS discovery requires Windows elevation or
Hyper-V administrative rights. Access denied must not be interpreted as absence
or as an ID mapping result. `inspect-report` saves a fresh native probe, and
`correlate-report <active-record.json>` saves the bounded matching candidates
beside that helper executable. `probe-runtime <runtime-id> <active-record.json>`
checks the identity channel without native enumeration or elevation.
`inventory-report` writes a fresh sanitized report beside the executable when
invoked explicitly; it does not mutate any compute system.

## Gates before a provider

1. Resolve runtime discovery without per-run UAC and host-account authorization.
   Native correlation works, but effective settings and safe recovery for
   ambiguous starts, launcher loss and reboot remain open.
2. Extend the working private transport to manager adoption and real runner
   lifetimes; agent restart and command cancellation alone are insufficient.
3. Enforce public-only egress outside the administrator-controlled guest, and
   prove host, LAN, IPv6 and peer denials with positive controls. A guest
   firewall or a failed TCP probe is insufficient.
4. Integrate Sandbox's active RDP session explicitly, preserving HCS console
   guarantees; validate official listener lifetime, cancellation and real jobs.
5. Resolve resource accounting, single-slot contention, artifact/cache
   transport, rebooting installers, and GUI/GPU behavior. Sandbox's documented
   configuration has no CPU-count setting or user-selected base image.

Microsoft references: [CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli),
[configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file),
[architecture](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-architecture),
and [Hyper-V socket registration](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service).
