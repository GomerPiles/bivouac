// Package paths resolves the platform-conventional locations of bivouac's
// config file, state, log, cache, and VM store directories.
package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Layout is where bivouac keeps its files on this host.
type Layout struct {
	Config         string // the one config file
	State          string // durable state: mode, instances, pid, status
	Logs           string // daemon and launch logs
	Diagnostics    string // per-instance diagnostics, under Logs
	Cache          string // bounded opaque objects, separate from ownership state
	BaselineInputs string // verified factory inputs, separate from VM and cache stores
	VMs            string // macOS VM store: baselines and their clones
}

// Resolve returns the layout. BIVOUAC_HOME puts everything under one
// directory, for tests and side-by-side validation.
func Resolve() (Layout, error) {
	if home := os.Getenv("BIVOUAC_HOME"); home != "" {
		return under(home, home, filepath.Join(home, "logs")), nil
	}
	switch runtime.GOOS {
	case "darwin":
		h, err := os.UserHomeDir()
		if err != nil {
			return Layout{}, err
		}
		app := filepath.Join(h, "Library", "Application Support", "bivouac")
		layout := under(app, app, filepath.Join(h, "Library", "Logs", "bivouac"))
		layout.Cache = filepath.Join(h, "Library", "Caches", "bivouac")
		return layout, nil
	case "windows":
		roaming := os.Getenv("APPDATA")
		local := os.Getenv("LOCALAPPDATA")
		if roaming == "" || local == "" {
			return Layout{}, errors.New("APPDATA and LOCALAPPDATA must be set")
		}
		return under(filepath.Join(roaming, "bivouac"), filepath.Join(local, "bivouac"), filepath.Join(local, "bivouac", "logs")), nil
	default:
		cfg, err := os.UserConfigDir()
		if err != nil {
			return Layout{}, err
		}
		st := os.Getenv("XDG_STATE_HOME")
		if st == "" {
			h, err := os.UserHomeDir()
			if err != nil {
				return Layout{}, err
			}
			st = filepath.Join(h, ".local", "state")
		}
		layout := under(filepath.Join(cfg, "bivouac"), filepath.Join(st, "bivouac"), filepath.Join(st, "bivouac", "logs"))
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return Layout{}, err
		}
		layout.Cache = filepath.Join(cacheDir, "bivouac")
		return layout, nil
	}
}

func under(configDir, stateDir, logDir string) Layout {
	return Layout{
		Config:         filepath.Join(configDir, "config.toml"),
		State:          filepath.Join(stateDir, "state"),
		Logs:           logDir,
		Diagnostics:    filepath.Join(logDir, "diagnostics"),
		Cache:          filepath.Join(stateDir, "cache"),
		VMs:            filepath.Join(stateDir, "vms"),
		BaselineInputs: filepath.Join(stateDir, "baseline-inputs"),
	}
}

// Ensure creates the state, log, and diagnostics directories with owner-only
// permissions.
func (l Layout) Ensure() error {
	for _, d := range []string{filepath.Dir(l.Config), l.State, l.Logs, l.Diagnostics} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}
