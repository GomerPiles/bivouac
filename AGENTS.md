# Agent conventions

Read `docs/design.md` and `docs/status.md` before changing anything.

## Code

- Go, current stable toolchain. `gofmt`, `go vet`, and `golangci-lint` run in CI.
- Explicit ownership of state and lifetimes. No mutable globals.
- No shell string interpolation anywhere. Commands are argument arrays;
  provider launch options are arrays or structured API fields.
- Structured logging (`log/slog`); redaction happens at the sink.
  Tokens, JIT configs, private keys, and signed URLs never reach logs,
  state, diagnostics, or fixtures.
- Prefer pure-Go dependencies. cgo only with a stated reason.
- Safety: only stop or delete instances bivouac created and recorded.
  Check the name prefix, the state record, and provider metadata first.

## Process

- No version bumps, compatibility shims, or release process yet.
  Producers, consumers, fixtures, and docs change together.
- `docs/design.md` owns architecture, the provider contract, the lifecycle
  state machine, the security model, and durable decisions. Keep it aligned
  with the code. `docs/status.md` records what works and what is unverified.
- Small, coherent commits on the branch you are given. Never merge to
  `main` without approval.
- The repository is public: no personal paths, hostnames, usernames,
  tokens, or keys in tracked files, commits, or logs.
- Never interrupt a production CI job. Never touch production runner
  labels (including `tartelet`) or Tartelet's configuration.
