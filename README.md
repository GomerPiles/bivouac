# bivouac

Ephemeral GitHub Actions runners in disposable guests on personal machines.

Bivouac manages existing virtualization engines (Tart on macOS; App Sandbox
and Crosvm on Windows) so that each CI job runs in a fresh guest that is
destroyed afterwards. Guests never see host files or long-lived credentials.
The manager needs one binary, one config file, local state/logs, and secrets in
the OS credential store, alongside the selected VM engine and its prerequisites.
Run it in the foreground with `bivouac run`. Starting it at login is optional,
uninstalled by default, and enabled only by `bivouac install`. Caching and command
aliases are optional too; Bivouac does not add itself to PATH.

CLI: `bivouac` (alias `biv`).

- `on` / `off` / `drain` / `stop` / `status`
- `run` (foreground daemon), `install` / `uninstall`
- `doctor`, `config validate`, `secret set`, `tart list` / `cleanup`

## Build

```bash
go build -o bin/bivouac ./cmd/bivouac
```

Real-host validation of the Tart provider (Apple silicon, local baseline):

```bash
BIVOUAC_TART_BASELINE=<vm> go test -tags integration -run TestRealGuest -v ./internal/provider/tart/
```

## Docs

- [design](docs/design.md): architecture, provider contract, lifecycle, security model, decisions
- [operations](docs/operations.md): GitHub App, install, validation, cutover, rollback
- [status](docs/status.md): what is validated, what is unverified, open gates
- [AGENTS.md](AGENTS.md): conventions for contributors and agents

## License

MIT
