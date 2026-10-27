# Windows Sandbox lab

This is a credential-free spike, not an enabled CI provider. It uses the
Windows Sandbox installation and CLI already on the host. It never reads a
normal bivouac home, changes CI mode, contacts the VM host service, installs a
host service/task/driver, edits host firewall rules or registers runners.
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
guests or recover a hard-killed launcher. Its receipt plus guest proof is a lab
control, not native provider metadata sufficient for the manager contract.
There is still a check/stop race against same-account replacement, and no
authoritative effective-configuration reader or native runtime binding has
been established. Same-account host processes are within the lab trust boundary.

Optional read-only diagnostics are `sandbox-lab inspect <recorded-cli-id>` and
`sandbox-lab inventory <recorded-cli-id>`. HCS access requires Windows elevation
or Hyper-V administrative rights. The lab does not request elevation itself;
access denied must not be interpreted as absence or as an ID mapping result.
`inventory-report` writes a fresh sanitized report beside the executable when
invoked explicitly; it does not mutate any compute system.

## Gates before a provider

1. Bind the CLI instance to native ownership/runtime metadata and effective
   settings, with safe recovery for ambiguous starts, launcher loss and reboot.
2. Establish a private, bounded, recoverable host/guest control transport.
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
