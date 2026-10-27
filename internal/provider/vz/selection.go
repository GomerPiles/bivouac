package vz

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/GomerPiles/bivouac/internal/guestagent"
	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"

	"github.com/GomerPiles/bivouac/internal/vm"
)

// GuestRuntime selects the runner guest's runtime, independently of host checks.
// Configuration selects the guest OS and helper; specifying a helper here
// never opens it at construction or reconciliation time.
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
func CheckRunnerBaseline(store, name, provider string, guest GuestRuntime) (vm.Manifest, error) {
	guestOS := guest.OS
	var m vm.Manifest
	var err error
	if guestOS == "linux" {
		m, err = CheckLinuxBaseline(store, name, guest.Helper, provider)
	} else {
		m, err = CheckBaseline(store, name, guestOS)
	}
	if err == nil && guestOS == "linux" && m.Guest.RunnerDir != "/opt/actions-runner" {
		return m, errors.New("linux runner baseline requires /opt/actions-runner")
	}
	if err == nil && m.Guest.RunnerDir == "" {
		err = fmt.Errorf("baseline %q records no runner directory; import it with --runner-dir", name)
	}
	return m, err
}

// prepareRunnerGuest uses the retained clone's contract. A Linux guest must
// never receive the Darwin bootstrap or an Aqua session check.
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
		return p.prepareLinux(ctx, name)
	default:
		return errors.New("unsupported VZ runner guest OS")
	}
}

// BaselineBuildCommand names the configured provider, so the build uses its
// helper and network settings even with several Linux providers.
func BaselineBuildCommand(name, provider string, replace bool) string {
	quote := func(s string) string {
		if s != "" && !strings.ContainsAny(s, " \t\r\n\"'`$;|&<>(){}[]*?!\\") {
			return s
		}
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	command := "bivouac vz build-baseline"
	if provider != "" {
		command += " --provider " + quote(provider)
	}
	if replace {
		command += " --replace"
	}
	if name != vzrecipe.DefaultName {
		if strings.HasPrefix(name, "-") {
			command += " --"
		}
		command += " " + quote(name)
	}
	return command
}

// CheckLinuxBaseline admits current builds without making historical manifests
// unreadable for retained-clone operations or replacement.
func CheckLinuxBaseline(store, name, helper, provider string) (vm.Manifest, error) {
	m, err := vm.ReadManifest(vm.Store(store).Dir(name))
	if errors.Is(err, os.ErrNotExist) {
		command := BaselineBuildCommand(name, provider, false)
		if name == vzrecipe.DefaultName {
			return m, fmt.Errorf("default Linux baseline is missing; run `%s`", command)
		}
		return m, fmt.Errorf("linux baseline is missing; use `bivouac vz import` or run `%s`", command)
	}
	if err != nil {
		return m, err
	}
	if b := m.Build; b != nil {
		r, recipeErr := vzrecipe.Lookup(b.Recipe)
		stale := recipeErr != nil || !slices.Contains(r.Source.URLs, b.SourceURL) || b.SourceSHA256 != r.Source.SHA256 || !slices.Contains(r.Runner.URLs, b.RunnerURL) || b.RunnerSHA256 != r.Runner.SHA256 || m.Guest.AgentVersion != guestagent.Version || m.Guest.RunnerDir != "/opt/actions-runner" || m.Guest.Sudo
		if stale {
			return m, fmt.Errorf("baseline build is stale; run `%s`", BaselineBuildCommand(name, provider, true))
		}
		hash, err := linuxguest.HelperSHA256(helper)
		if err != nil {
			return m, err
		}
		if hash != b.HelperSHA256 {
			return m, fmt.Errorf("built for another helper; run `%s`", BaselineBuildCommand(name, provider, true))
		}
	}
	return CheckBaseline(store, name, "linux")
}
