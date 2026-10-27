package vz

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/vm"
)

// GuestRuntime selects the runner guest's runtime, independently of host checks.
// Current configuration callers select Darwin. Linux configuration and runner
// operations are added separately; specifying a helper here never opens it at
// construction or reconciliation time.
type GuestRuntime struct {
	OS     string
	Helper string // host path to the matching Linux/arm64 executable
}

func (g GuestRuntime) validate() error {
	if g.OS != "darwin" && g.OS != "linux" {
		return errors.New("unsupported VZ runner guest OS")
	}
	return nil
}

// CheckHelper validates only new-instance helper admission, never startup.
func (g GuestRuntime) CheckHelper() error {
	if err := g.validate(); err != nil {
		return err
	}
	if g.OS == "darwin" {
		return nil
	}
	if !filepath.IsAbs(g.Helper) {
		return errors.New("linux guest helper must be an absolute binary path")
	}
	f, err := elf.Open(g.Helper)
	if err != nil {
		return errors.New("linux guest helper must be a built Linux/arm64 bivouac binary")
	}
	defer func() { _ = f.Close() }()
	if f.Machine != elf.EM_AARCH64 || f.Class != elf.ELFCLASS64 || f.Type != elf.ET_EXEC {
		return errors.New("linux guest helper must be a static Linux/arm64 executable")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("linux guest helper must not require a dynamic loader")
		}
	}
	return nil
}

// CheckRunnerBaseline admits a new runner image. Engine images use CheckBaseline
// directly because they need no official runner directory.
func CheckRunnerBaseline(store, name, guestOS string) (vm.Manifest, error) {
	m, err := CheckBaseline(store, name, guestOS)
	if err == nil && m.Guest.RunnerDir == "" {
		err = fmt.Errorf("baseline %q records no runner directory; import it with --runner-dir", name)
	}
	return m, err
}

// prepareRunnerGuest uses the retained clone's contract. A Linux guest must
// never receive the Darwin bootstrap or an Aqua session check. Its neutral
// runtime preparation is a separate runner-adapter step in the next phase.
func (p *Provider) prepareRunnerGuest(ctx context.Context, name string) error {
	m, err := vm.ReadManifest(p.vmDir(name))
	if err != nil {
		return err
	}
	switch m.OS {
	case "darwin":
		if err := p.startupStage(name, "script_install", func() error { return p.installGuestScript(ctx, name) }); err != nil {
			return err
		}
		return p.startupStage(name, "aqua_session_check", func() error { return p.checkSession(ctx, name) })
	case "linux":
		return nil
	default:
		return errors.New("unsupported VZ runner guest OS")
	}
}

// Until the Linux runner adapter is connected, fail closed instead of invoking
// the macOS script on a Linux clone. VM status/stop/delete remain OS-independent.
func (p *Provider) requireDarwinRunner(name string) error {
	m, err := vm.ReadManifest(p.vmDir(name))
	if err != nil {
		return err
	}
	if m.OS != "darwin" {
		return errors.New("linux VZ runner operations are not enabled")
	}
	return nil
}
