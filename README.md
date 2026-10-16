# bivouac

Ephemeral GitHub Actions runners in disposable guests on personal machines.

Bivouac runs each CI job in a fresh guest that is destroyed afterwards: on
macOS through Apple's Virtualization framework from Tart-format baselines; on
Windows through App Sandbox and Crosvm. Guests never see host files or long-lived credentials.
The manager needs one binary, one config file, local state/logs, and secrets in
the OS credential store, alongside the selected VM engine and its prerequisites.
Run it in the foreground with `bivouac run`. Starting it at login is optional,
uninstalled by default, and enabled only by `bivouac install`. Caching and command
aliases are optional too; Bivouac does not add itself to PATH.

CLI: `bivouac` (alias `biv`).

- `on` / `off` / `drain` / `stop` / `status`
- `run` (foreground daemon), `install` / `uninstall`
- `doctor`, `config validate`, `secret set`, `vz list` / `cleanup`

## Build

```bash
go build -o bin/bivouac ./cmd/bivouac
codesign --force --sign - --entitlements tools/macos/bivouac.entitlements bin/bivouac  # macOS
```

Real-host validation of the macOS provider (Apple silicon, local baseline with
the guest agent installed):

```bash
BIVOUAC_VZ_BASELINE=<vm> BIVOUAC_EXE=$PWD/bin/bivouac go test -tags integration -run TestRealGuest -v ./internal/provider/vz/
```

## Docs

- [design](docs/design.md): architecture, provider contract, lifecycle, security model, decisions
- [operations](docs/operations.md): GitHub App, install, validation, cutover, rollback
- [status](docs/status.md): what is validated, what is unverified, open gates
- [AGENTS.md](AGENTS.md): conventions for contributors and agents

## License

MIT
