# bivouac

Ephemeral GitHub Actions runners in disposable guests on personal machines.

Bivouac manages existing virtualization engines (Tart on macOS; App Sandbox and
Crosvm on Windows) so that each CI job runs in a fresh guest that is destroyed
afterwards. Guests never see host files or long-lived credentials. The host
footprint is one binary, one config file, one login/service entry, and secrets
in the OS credential store.

CLI: `bivouac` (alias `biv`).

- `on` / `off` / `drain` / `stop` / `status`
- `run` (foreground daemon), `install` / `uninstall`
- `doctor`, `config validate`, provider inspection and cleanup

Status, architecture, and decisions live in [docs/](docs/). Contributor and
agent conventions are in [AGENTS.md](AGENTS.md).

## Build

```bash
go build ./...
```

## License

MIT
