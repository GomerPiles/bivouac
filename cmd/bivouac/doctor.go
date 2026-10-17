package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/github"
	"github.com/GomerPiles/bivouac/internal/hostinfo"
	"github.com/GomerPiles/bivouac/internal/install"
	"github.com/GomerPiles/bivouac/internal/provider/vz"
	"github.com/GomerPiles/bivouac/internal/secret"
	"github.com/GomerPiles/bivouac/internal/state"
	"github.com/GomerPiles/bivouac/internal/vm"
)

type check struct {
	level, name, detail string
}

func (e env) doctor(ctx context.Context, args []string) error {
	var withGitHub bool
	if err := parseFlags("doctor", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&withGitHub, "github", false, "also authenticate and ensure the scale sets exist")
	}); err != nil {
		return err
	}
	var checks []check
	add := func(level, name, detail string) { checks = append(checks, check{level, name, detail}) }

	add("PASS", "paths", fmt.Sprintf("config %s; state %s; logs %s", e.layout.Config, e.layout.State, e.layout.Logs))
	mode, err := e.files.ReadMode()
	if err != nil {
		add("FAIL", "mode", err.Error())
	} else {
		add("PASS", "mode", string(mode))
	}

	cfg, err := e.loadConfig("")
	if err != nil {
		add("FAIL", "config", err.Error())
		return report(checks)
	}
	add("PASS", "config", fmt.Sprintf("%d provider(s), demand %s", len(cfg.Providers), cfg.GitHub.Demand))

	host := hostinfo.Get()
	add("PASS", "host", fmt.Sprintf("%d CPUs, %d GB memory", host.CPUs, host.MemoryBytes>>30))

	if _, err := secret.Default().Get(ctx, cfg.GitHub.PrivateKeySecret); err != nil {
		add("FAIL", "credential", fmt.Sprintf("item %q: %v (store it with `bivouac secret set %s --file key.pem`)", cfg.GitHub.PrivateKeySecret, err, cfg.GitHub.PrivateKeySecret))
	} else {
		add("PASS", "credential", fmt.Sprintf("item %q present in the credential store", cfg.GitHub.PrivateKeySecret))
	}

	for _, name := range cfg.ProviderNames() {
		p := cfg.Providers[name]
		if p.Type == "crosvm" {
			st, err := state.Open(e.layout.State, newID)
			if err != nil {
				add("FAIL", "state", err.Error())
				continue
			}
			lp, err := buildLinuxProvider(ctx, name, *p.Crosvm, st)
			if err != nil {
				add("FAIL", "crosvm "+name, err.Error())
				continue
			}
			err = lp.CheckLocal()
			lp.Close()
			if err != nil {
				add("FAIL", "crosvm "+name, err.Error())
				continue
			}
			add("PASS", "crosvm "+name, "pinned executable/kernel/initrd, static guest helper, SSH key, disk reserve and host inventory; no VM started")
			add("WARN", "Linux validation", "experimental: actual lifecycle/GPU/isolation tests required; baseline contents are not hashed")
			if p.Crosvm.CPU > host.CPUs-cfg.Budget.ReserveCPU || (host.MemoryBytes > 0 && p.Crosvm.MemoryGB > int(host.MemoryBytes>>30)-cfg.Budget.ReserveMemoryGB) {
				add("FAIL", "budget "+name, "guest resources exceed host capacity after reservations")
			}
			continue
		}
		if p.Type == "appsandbox" {
			st, err := state.Open(e.layout.State, newID)
			if err != nil {
				add("FAIL", "state", err.Error())
				continue
			}
			wp, err := buildWindowsProvider(ctx, name, *p.AppSandbox, st)
			if err != nil {
				add("FAIL", "appsandbox "+name, err.Error())
				continue
			}
			wp.Close()
			add("PASS", "appsandbox "+name, "authenticated protected broker and local transport/package settings; no VM started")
			add("WARN", "Windows validation", "experimental: live broker/guest lifecycle, isolation, and GitHub job checks remain required")
			if p.AppSandbox.CPU > host.CPUs-cfg.Budget.ReserveCPU || (host.MemoryBytes > 0 && p.AppSandbox.MemoryGB > int(host.MemoryBytes>>30)-cfg.Budget.ReserveMemoryGB) {
				add("FAIL", "budget "+name, "guest resources exceed host capacity after reservations")
			}
			continue
		}
		if p.Type != "vz" {
			add("WARN", "provider "+name, "type "+p.Type+" is not implemented on this host")
			continue
		}
		e.doctorVZ(ctx, name, p, host, cfg, add)
	}

	if cfg.Budget.ReserveCPU >= host.CPUs {
		add("FAIL", "budget", "reserve_cpu leaves no CPUs for guests")
	}

	plist, loaded, err := install.Installed(ctx)
	switch {
	case err != nil:
		add("WARN", "login item", err.Error())
	case loaded:
		add("PASS", "login item", plist+" loaded")
	case plist != "":
		add("WARN", "login item", "not installed (run `bivouac install`)")
	}
	if e.files.Alive() {
		add("PASS", "daemon", "running")
	} else {
		add("WARN", "daemon", "not running")
	}

	st, err := state.Open(e.layout.State, newID)
	if err != nil {
		add("FAIL", "state", err.Error())
	} else {
		add("PASS", "state", fmt.Sprintf("controller %s, %d tracked instance(s)", st.ControllerID(), len(st.List())))
	}

	if withGitHub {
		gh, jit, err := e.githubClients(ctx, cfg)
		switch {
		case err != nil:
			add("FAIL", "github", err.Error())
		case jit != nil:
			if err := jit.Check(ctx, cfg.GitHub.RunnerGroup); err != nil {
				add("FAIL", "REST JIT", err.Error())
			} else {
				add("PASS", "REST JIT", "authenticated runner access; no registration created")
			}
		default:
			for _, name := range cfg.ProviderNames() {
				ss := cfg.Providers[name].ScaleSet
				labels := cfg.Providers[name].ScaleSetLabelNames()
				got, err := gh.Ensure(ctx, ss, cfg.GitHub.RunnerGroup, labels)
				switch missing := github.MissingLabels(labels, got.Labels); {
				case err != nil:
					add("FAIL", "scale set "+ss, err.Error())
				case len(missing) > 0:
					add("FAIL", "scale set "+ss, fmt.Sprintf("id %d: GitHub dropped labels %q; it has %q", got.ID, missing, got.Labels))
				default:
					add("PASS", "scale set "+ss, fmt.Sprintf("id %d in runner group %q, labels %q", got.ID, cfg.GitHub.RunnerGroup, got.Labels))
				}
			}
		}
	} else {
		add("WARN", "github", "skipped (pass --github to authenticate and ensure the scale sets)")
	}
	return report(checks)
}

func (e env) doctorVZ(ctx context.Context, name string, p config.Provider, host hostinfo.Info, cfg *config.Config, add func(level, name, detail string)) {
	t := p.VZ
	if exe, err := os.Executable(); err != nil {
		add("FAIL", "vm "+name, err.Error())
	} else if err := vm.CheckEntitlement(ctx, exe); err != nil {
		add("FAIL", "vm "+name, err.Error())
	} else {
		add("PASS", "vm "+name, "executable signed with "+vm.Entitlement)
	}
	if err := vm.Store(e.layout.VMs).CheckSocketPath(); err != nil {
		add("FAIL", "vm store "+name, err.Error())
	}
	if m, err := vz.CheckBaseline(e.layout.VMs, t.Baseline, "darwin"); err != nil {
		add("FAIL", "baseline "+name, err.Error())
	} else if err := vz.MachineOptions(t.Machine).CheckGuest(m); err != nil {
		add("FAIL", "machine "+name, err.Error())
	} else {
		add("PASS", "baseline "+name, fmt.Sprintf("%q in %s: guest agent protocol %d, runner in %s", t.Baseline, e.layout.VMs, m.Guest.AgentVersion, m.Guest.RunnerDir))
	}
	if err := vz.CheckNested(*t); err != nil {
		add("FAIL", "machine "+name, err.Error())
	}
	cpu, mem := t.CPU, t.MemoryGB
	if c := t.Containers; c != nil {
		cpu += c.CPU
		mem += c.MemoryGB
		tp, err := vz.New(name, *t, "doctor", e.layout.VMs, nil)
		if err == nil {
			err = tp.CheckContainers(ctx)
		}
		if err != nil {
			add("FAIL", "containers "+name, err.Error())
		} else {
			add("PASS", "containers "+name, "local Linux baseline/helper and Softnet privilege probe; live VSOCK/engine behavior still requires disposable validation")
		}
	}
	if cpu > host.CPUs-cfg.Budget.ReserveCPU {
		add("FAIL", "budget "+name, fmt.Sprintf("job cpu %d exceeds host %d minus reserve %d", cpu, host.CPUs, cfg.Budget.ReserveCPU))
	}
	if gb := int(host.MemoryBytes >> 30); gb > 0 && mem > gb-cfg.Budget.ReserveMemoryGB {
		add("FAIL", "budget "+name, fmt.Sprintf("job memory %d GB exceeds host %d GB minus reserve %d", mem, gb, cfg.Budget.ReserveMemoryGB))
	}
	if t.HostVMLimit-t.ForeignSlots < 1 {
		add("FAIL", "slots "+name, "foreign_slots leaves no guest slot")
	} else {
		add("PASS", "slots "+name, fmt.Sprintf("%d of %d host VM slot(s) usable (foreign_slots %d)", t.HostVMLimit-t.ForeignSlots, t.HostVMLimit, t.ForeignSlots))
	}
	if ps, err := exec.CommandContext(ctx, "/bin/ps", "-axo", "command").Output(); err == nil && strings.Contains(string(ps), "Tartelet.app") {
		add("WARN", "tartelet", "Tartelet is running; keep foreign_slots >= its VM count during validation")
	}
}

func report(checks []check) error {
	failed := false
	for _, c := range checks {
		fmt.Printf("%-4s %-22s %s\n", c.level, c.name, c.detail)
		if c.level == "FAIL" {
			failed = true
		}
	}
	if failed {
		return errors.New("doctor found problems")
	}
	return nil
}
