# Windows host setup

Windows guests use the direct HCS VM host; see [the VM host procedures](operations.md#direct-hcs-vm-host).
Linux GPU guests use [Crosvm](crosvm.md). This page covers shared cache and login setup.

## Transparent caching

Enable the same optional download accelerator as on macOS:

```toml
[cache]
enabled = true
release_proxy = true
max_gb = 20
max_object_mb = 2048
```

Windows-hosted providers default `listen = "127.0.0.1:0"` and
`guest_host = "127.0.0.1"`; other addresses are rejected. Guests reach only the
cache handler through a guest-loopback listener bound to their verified
transport: bivouac-agent Duplex/engine relay for HCS, SSH forwarding for Crosvm.
Keep host/LAN NIC denial unchanged. Crosvm's guest SSH service must permit
loopback remote forwarding; do not expose forwarding on a VM interface.

Both adapters install the shared Actions v2 Node preload and optional public
GitHub release proxy inside disposable guests. Windows changes only the runner
guest's machine root trust using its existing administrator account; Linux
changes only the clone's system trust. This avoids requesting protected
CurrentUser root consent over SSH. Proxy certificates include a signed CRL at
the guest's own cache endpoint so Windows retains default revocation checks.
Nothing is installed into the host or baseline. Cache settings/capabilities
travel on the provider's command stdin and are excluded from diagnostics. Workflow cache keys,
metadata and upstream authorization stay on GitHub. `store_uploads` would route
saves through the host relay; it is not yet validated on Windows hosts, so leave
it off. Cache setup failure removes the
partial adapter before normal runner startup. A lost host service falls back
upstream with the same limits documented for macOS; an in-flight transfer can
still fail and depend on caller retries.

The cache starts/stops with the manager and retains its bounded LRU store between
jobs. Foreground operation and Off require no startup task, proxy VM or firewall
exception. Validate cold/warm Actions restores and release downloads in fresh
clones, manager/cache outage, grant revocation, host/private-network denial, and
absence of capabilities in logs before treating parity as complete. Containers
with separate environments/trust need their own guest integration; this does not
claim OCI image caching.

## Optional startup

Foreground operation needs no login task. If desired, run `bivouac install`
from an ordinary, non-elevated shell, with the intended `BIVOUAC_HOME` set.
It registers a per-user Task Scheduler entry using a limited interactive token.
It does not change CI mode, start a VM, change PATH, create aliases, or install a
VM host service. The HCS provider starts an already installed service.
`on` can then request
that installed task; without installation, start `run` yourself. At login the
task waits 30 seconds before starting; host features and images must already
be available.
If they are unavailable, the manager fails closed and needs an explicit retry
after the operator starts them. The task is not a guarantee of unattended reboot
recovery while privileged prerequisites remain manually managed.

Use `bivouac uninstall` with the same home to remove only its matching login
task. It leaves active work alone; use Off or Stop to manage that work separately.
CI mode defaults to Off and is independent of whether startup is installed.
