// Package config loads and validates bivouac's single TOML config file. The
// file never holds secrets; it names credential-store items instead.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// NamePrefix starts every VM and runner name bivouac creates. Baselines may
// never carry it, so cleanup cannot match one.
const NamePrefix = "bivouac-"

// Demand selects how bivouac learns that a job wants a runner.
type Demand string

const (
	// DemandScaleSet long-polls a runner scale set; one guest per assigned job.
	DemandScaleSet Demand = "scaleset"
	// DemandJIT keeps a small idle pool of JIT-registered ephemeral runners.
	DemandJIT Demand = "jit"
)

// Config is the whole file.
type Config struct {
	Cache     Cache               `toml:"cache"`
	GitHub    GitHub              `toml:"github"`
	Budget    Budget              `toml:"budget"`
	Providers map[string]Provider `toml:"providers"`
}

// Cache configures the optional guest download accelerator. No credentials.
type Cache struct {
	Enabled      bool   `toml:"enabled"`
	ReleaseProxy bool   `toml:"release_proxy"`
	StoreUploads bool   `toml:"store_uploads"`
	Listen       string `toml:"listen"`
	GuestHost    string `toml:"guest_host"`
	MaxGB        int64  `toml:"max_gb"`
	MaxObjectMB  int64  `toml:"max_object_mb"`
}

// GitHub names the App and where runners register.
type GitHub struct {
	// URL is the organization or repository runners register with, for
	// example https://github.com/example-org.
	URL string `toml:"url"`
	// AppClientID is the GitHub App's client ID (its numeric app ID also works).
	AppClientID string `toml:"app_client_id"`
	// AppInstallationID is the App's installation on the org or repo.
	AppInstallationID int64 `toml:"app_installation_id"`
	// PrivateKeySecret names the credential-store item holding the App's PEM key.
	PrivateKeySecret string `toml:"private_key_secret"`
	// Demand is "scaleset" (default) or "jit".
	Demand Demand `toml:"demand"`
	// RunnerGroup is the runner group scale sets and JIT runners join.
	RunnerGroup string `toml:"runner_group"`
}

// Budget bounds host usage.
type Budget struct {
	// MaxInstances is the host-wide guest limit across providers.
	MaxInstances int `toml:"max_instances"`
	// MaxPendingCleanup pauses provisioning at this many deleted guests awaiting deregistration.
	MaxPendingCleanup int `toml:"max_pending_cleanup"`
	// ReserveCPU and ReserveMemoryGB stay free for the host's own use.
	ReserveCPU      int `toml:"reserve_cpu"`
	ReserveMemoryGB int `toml:"reserve_memory_gb"`
	// JobTimeout is the per-job wall-clock ceiling from guest creation.
	JobTimeout Duration `toml:"job_timeout"`
	// IdleTimeout retires a registered runner that never receives a job.
	IdleTimeout Duration `toml:"idle_timeout"`
	// ReadyTimeout bounds boot until the guest agent answers.
	ReadyTimeout Duration `toml:"ready_timeout"`
	// SweepIdleTimeout retires a sweep runner (started after a session opens
	// or a label-matched job is detected) that finds no queued job.
	SweepIdleTimeout Duration `toml:"sweep_idle_timeout"`
}

// Provider is one guest type on one virtualization engine. Each provider has
// exactly one scale set (or JIT label set).
type Provider struct {
	// Type is the engine: "vz" (macOS Virtualization.framework), experimental "appsandbox", "crosvm" or "hcs".
	Type string `toml:"type"`
	// ScaleSet is the scale set name, which is always one of its labels.
	ScaleSet string `toml:"scaleset"`
	// ScaleSetLabels are extra scale set labels, so workflows can target it
	// with a label array (demand = "scaleset").
	ScaleSetLabels []string `toml:"scaleset_labels"`
	// Labels are the JIT-mode runner labels (demand = "jit").
	Labels []string `toml:"labels"`
	// MaxInstances caps this provider; 0 means the host budget decides.
	MaxInstances int `toml:"max_instances"`
	// IdlePool is the JIT-mode number of registered runners kept waiting.
	IdlePool int `toml:"idle_pool"`
	// VZ holds engine-specific settings when Type is "vz".
	VZ         *VZ         `toml:"vz"`
	AppSandbox *AppSandbox `toml:"appsandbox"`
	Crosvm     *Crosvm     `toml:"crosvm"`
	HCS        *HCS        `toml:"hcs"`
}

// HCS runs Windows guests through bivouac's own VM host. Image names one of
// the VM host's administrator-configured images; GuestName and GuestUser are
// that prepared image's Windows computer name and console user.
type HCS struct {
	Experimental  bool   `toml:"experimental"`
	Image         string `toml:"image"`
	GuestName     string `toml:"guest_name"`
	GuestUser     string `toml:"guest_user"`
	CPU           int    `toml:"cpu"`
	MemoryGB      int    `toml:"memory_gb"`
	LazyMemory    bool   `toml:"lazy_memory"`
	GPU           bool   `toml:"gpu"`
	RunnerDir     string `toml:"runner_dir"`
	RunnerArchive string `toml:"runner_archive"`
	RunnerSHA256  string `toml:"runner_sha256"`
}

type Crosvm struct {
	Experimental bool   `toml:"experimental"`
	Root         string `toml:"root"`
	Binary       string `toml:"binary"`
	BinarySHA256 string `toml:"binary_sha256"`
	QemuImg      string `toml:"qemu_img"`
	BaselineName string `toml:"baseline_name"`
	Baseline     string `toml:"baseline"`
	Kernel       string `toml:"kernel"`
	KernelSHA256 string `toml:"kernel_sha256"`
	Initrd       string `toml:"initrd"`
	InitrdSHA256 string `toml:"initrd_sha256"`
	Helper       string `toml:"helper"`
	SSHKey       string `toml:"ssh_key"`
	User         string `toml:"user"`
	CPU          int    `toml:"cpu"`
	MemoryGB     int    `toml:"memory_gb"`
	GPU          bool   `toml:"gpu"`
}

// AppSandbox selects an explicitly experimental Windows broker and guest
// transport. Native storage/network settings are pinned by the operator's
// protected broker configuration, never supplied by an Actions job.
type AppSandbox struct {
	Experimental  bool   `toml:"experimental"`
	BrokerSecret  string `toml:"broker_secret"`
	Baseline      string `toml:"baseline"`
	CPU           int    `toml:"cpu"`
	MemoryGB      int    `toml:"memory_gb"`
	DiskGB        int    `toml:"disk_gb"`
	GPU           bool   `toml:"gpu"`
	RunnerDir     string `toml:"runner_dir"`
	RunnerArchive string `toml:"runner_archive"`
	RunnerSHA256  string `toml:"runner_sha256"`
	SSHKey        string `toml:"ssh_key"`
}

// VZ configures the macOS provider. Guests are clones of a baseline in
// bivouac's VM store, run by bivouac's own VM helper. What the image
// provides (such as the runner directory) is in the baseline's manifest.
type VZ struct {
	// Containers optionally adds an isolated Linux engine clone to each job.
	Containers *Containers `toml:"containers"`
	// Baseline is the local VM each job is cloned from. Never started.
	Baseline string `toml:"baseline"`
	// CPU and MemoryGB size each clone; 0 keeps the baseline's values.
	CPU      int `toml:"cpu"`
	MemoryGB int `toml:"memory_gb"`
	// Machine holds typed options for how runner guests run.
	Machine Machine `toml:"machine"`
	// HostVMLimit is Apple's concurrent macOS guest ceiling per host.
	HostVMLimit int `toml:"host_vm_limit"`
	// ForeignSlots are guests another manager (Tartelet) may be running at
	// the same time; bivouac also counts running VMs it does not own.
	ForeignSlots int `toml:"foreign_slots"`
	// BootstrapShare is an optional host directory shared read-only into the
	// guest (as /Volumes/My Shared Files/bivouac). Empty means no share.
	BootstrapShare string `toml:"bootstrap_share"`
}

// Machine is how a guest runs. Zero values keep the baseline manifest's or
// the framework's defaults. There is deliberately no raw option
// passthrough: each option is typed and validated, here and against the
// baseline's OS and the host when a guest is created.
type Machine struct {
	// Display overrides the baseline's display size (and pixel density);
	// macOS guests only.
	Display Display `toml:"display"`
	// DiskSync is "full" (the default: guest flushes reach the host disk),
	// "fsync", or "none" (flushes are ignored, which is faster and safe only
	// because guests are deleted after one job).
	DiskSync string `toml:"disk_sync"`
	// NestedVirtualization lets the guest run VMs of its own (such as
	// /dev/kvm for containers). Apple's framework offers it to Linux guests
	// on an M3 or newer chip with macOS 15 or later.
	NestedVirtualization bool `toml:"nested_virtualization"`
}

// Display is a guest display size in pixels, with an optional density.
type Display struct {
	Width  int `toml:"width"`
	Height int `toml:"height"`
	PPI    int `toml:"ppi"`
}

func (m Machine) validate() error {
	d := m.Display
	if (d.Width == 0) != (d.Height == 0) || d.Width < 0 || d.Height < 0 || d.Width > 16384 || d.Height > 16384 || d.PPI < 0 || d.PPI > 1000 {
		return errors.New("machine.display needs width and height in 1..16384 and an optional ppi in 1..1000")
	}
	switch m.DiskSync {
	case "", "full", "fsync", "none":
		return nil
	}
	return errors.New("machine.disk_sync must be full, fsync, or none")
}

// Containers is deliberately limited to Linux guests from a local
// Tart-format baseline. No host daemon, arbitrary socket, launch options, or
// host mounts are configurable.
type Containers struct {
	Engine   string `toml:"engine"` // docker or podman
	Baseline string `toml:"baseline"`
	CPU      int    `toml:"cpu"`
	MemoryGB int    `toml:"memory_gb"`
	// Helper is a Linux/arm64 bivouac binary built alongside the host binary.
	Helper string `toml:"helper"`
	// Machine holds typed options for the engine VM; it has no display.
	Machine Machine `toml:"machine"`
}

// Duration is a TOML string such as "30m".
type Duration struct{ time.Duration }

// UnmarshalText parses the duration.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText formats the duration.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Load reads and validates the file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates TOML text.
func Parse(data []byte) (*Config, error) {
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	isWindowsHostCache := false
	for _, p := range c.Providers {
		if p.Type == "appsandbox" || p.Type == "crosvm" || p.Type == "hcs" {
			isWindowsHostCache = true
		}
	}
	if c.Cache.Listen == "" {
		// The vmnet bridge may not exist until a guest runs, so the default
		// binds every interface; TLS and per-guest capabilities gate access.
		c.Cache.Listen = "0.0.0.0:0"
		if isWindowsHostCache {
			c.Cache.Listen = "127.0.0.1:0"
		}
	}
	if isWindowsHostCache && c.Cache.GuestHost == "" {
		c.Cache.GuestHost = "127.0.0.1"
	}
	if c.Cache.MaxGB == 0 {
		c.Cache.MaxGB = 20
	}
	if c.Cache.MaxObjectMB == 0 {
		c.Cache.MaxObjectMB = 2048
	}
	if c.GitHub.Demand == "" {
		c.GitHub.Demand = DemandScaleSet
	}
	if c.GitHub.RunnerGroup == "" {
		c.GitHub.RunnerGroup = "default"
	}
	if c.Budget.MaxInstances == 0 {
		c.Budget.MaxInstances = 1
	}
	if c.Budget.MaxPendingCleanup == 0 {
		c.Budget.MaxPendingCleanup = 2
	}
	if c.Budget.JobTimeout.Duration == 0 {
		c.Budget.JobTimeout.Duration = 2 * time.Hour
	}
	if c.Budget.IdleTimeout.Duration == 0 {
		c.Budget.IdleTimeout.Duration = 10 * time.Minute
	}
	if c.Budget.ReadyTimeout.Duration == 0 {
		c.Budget.ReadyTimeout.Duration = 3 * time.Minute
	}
	if c.Budget.SweepIdleTimeout.Duration == 0 {
		c.Budget.SweepIdleTimeout.Duration = 90 * time.Second
	}
	for name, p := range c.Providers {
		if p.Type == "vz" && p.VZ != nil {
			if p.VZ.HostVMLimit == 0 {
				p.VZ.HostVMLimit = 2
			}
		}
		c.Providers[name] = p
	}
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// Validate checks cross-field rules.
func (c *Config) Validate() error {
	var errs []error
	if c.Cache.ReleaseProxy && !c.Cache.Enabled {
		errs = append(errs, errors.New("cache.release_proxy requires cache.enabled"))
	}
	if c.Cache.StoreUploads && !c.Cache.Enabled {
		errs = append(errs, errors.New("cache.store_uploads requires cache.enabled"))
	}
	if c.Cache.Enabled {
		if ip := net.ParseIP(c.Cache.GuestHost); ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			errs = append(errs, errors.New("cache.guest_host must be the host IP reachable from guests"))
		}
		if _, _, err := net.SplitHostPort(c.Cache.Listen); err != nil {
			errs = append(errs, errors.New("cache.listen must be host:port"))
		}
		if c.Cache.MaxGB < 1 || c.Cache.MaxGB > 1024 || c.Cache.MaxObjectMB < 1 || c.Cache.MaxObjectMB > c.Cache.MaxGB*1024 {
			errs = append(errs, errors.New("cache limits must be positive, max_gb <= 1024, and max_object_mb must fit max_gb"))
		}
	}
	u, err := url.Parse(c.GitHub.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || strings.Trim(u.Path, "/") == "" {
		errs = append(errs, errors.New("github.url must be https://host/org or https://host/org/repo"))
	}
	if c.GitHub.AppClientID == "" {
		errs = append(errs, errors.New("github.app_client_id is required"))
	}
	if c.GitHub.AppInstallationID == 0 {
		errs = append(errs, errors.New("github.app_installation_id is required"))
	}
	if c.GitHub.PrivateKeySecret == "" {
		errs = append(errs, errors.New("github.private_key_secret is required"))
	}
	if c.GitHub.Demand != DemandScaleSet && c.GitHub.Demand != DemandJIT {
		errs = append(errs, fmt.Errorf("github.demand must be %q or %q", DemandScaleSet, DemandJIT))
	}
	if c.Budget.MaxInstances < 1 {
		errs = append(errs, errors.New("budget.max_instances must be at least 1"))
	}
	if c.Budget.MaxPendingCleanup < 1 {
		errs = append(errs, errors.New("budget.max_pending_cleanup must be at least 1"))
	}
	if c.Budget.ReserveCPU < 0 || c.Budget.ReserveMemoryGB < 0 {
		errs = append(errs, errors.New("budget reservations cannot be negative"))
	}
	if c.Budget.JobTimeout.Duration < 0 || c.Budget.IdleTimeout.Duration < 0 || c.Budget.ReadyTimeout.Duration < 0 || c.Budget.SweepIdleTimeout.Duration < 0 {
		errs = append(errs, errors.New("budget durations cannot be negative"))
	}
	if len(c.Providers) == 0 {
		errs = append(errs, errors.New("at least one [providers.<name>] is required"))
	}
	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := c.Providers[name]
		if !nameRE.MatchString(name) {
			errs = append(errs, fmt.Errorf("provider %q: name must match %s", name, nameRE))
		}
		switch c.GitHub.Demand {
		case DemandScaleSet:
			if p.ScaleSet == "" {
				errs = append(errs, fmt.Errorf("provider %q: scaleset is required", name))
			} else if !strings.HasPrefix(p.ScaleSet, NamePrefix) {
				errs = append(errs, fmt.Errorf("provider %q: scaleset must start with %q", name, NamePrefix))
			}
			seen := map[string]bool{strings.ToLower(p.ScaleSet): true}
			for _, label := range p.ScaleSetLabels {
				if strings.TrimSpace(label) != label || label == "" || len(label) > 255 || seen[strings.ToLower(label)] {
					errs = append(errs, fmt.Errorf("provider %q: scaleset_labels must be nonempty, trimmed, unique, and differ from the scaleset name", name))
				}
				seen[strings.ToLower(label)] = true
			}
			if len(p.ScaleSetLabels) > 99 {
				errs = append(errs, fmt.Errorf("provider %q: scaleset_labels allow at most 99 entries", name))
			}
		case DemandJIT:
			if len(p.Labels) == 0 {
				errs = append(errs, fmt.Errorf("provider %q: labels are required for jit demand", name))
			}
			isolated := false
			seen := map[string]bool{}
			for _, label := range p.Labels {
				if strings.HasPrefix(label, NamePrefix) {
					isolated = true
				}
				if strings.TrimSpace(label) == "" || seen[strings.ToLower(label)] {
					errs = append(errs, fmt.Errorf("provider %q: labels must be nonempty and unique", name))
				}
				seen[strings.ToLower(label)] = true
			}
			if !isolated || len(p.Labels) > 100 {
				errs = append(errs, fmt.Errorf("provider %q: jit labels need a bivouac- label and at most 100 entries", name))
			}
			if p.IdlePool < 1 || p.IdlePool > c.Budget.MaxInstances || (p.MaxInstances > 0 && p.IdlePool > p.MaxInstances) {
				errs = append(errs, fmt.Errorf("provider %q: idle_pool must be positive and fit instance budgets", name))
			}
		}
		if p.MaxInstances < 0 {
			errs = append(errs, fmt.Errorf("provider %q: max_instances cannot be negative", name))
		}
		switch p.Type {
		case "crosvm":
			if p.Crosvm == nil || p.VZ != nil || p.AppSandbox != nil || p.HCS != nil {
				errs = append(errs, fmt.Errorf("provider %q: only crosvm settings are required", name))
				continue
			}
			v := p.Crosvm
			if !v.Experimental {
				errs = append(errs, fmt.Errorf("provider %q: crosvm requires experimental = true during live validation", name))
			}
			for _, path := range []string{v.Root, v.Binary, v.QemuImg, v.Baseline, v.Kernel, v.Initrd, v.Helper} {
				if !windowsPath(path) || strings.Contains(path, ",") {
					errs = append(errs, fmt.Errorf("provider %q: crosvm paths must be absolute local Windows paths without option separators", name))
				}
			}
			for _, hash := range []string{v.BinarySHA256, v.KernelSHA256, v.InitrdSHA256} {
				if len(hash) != 64 || strings.Trim(hash, "0123456789abcdefABCDEF") != "" {
					errs = append(errs, fmt.Errorf("provider %q: crosvm executable, kernel and initrd must be SHA-256 pinned", name))
				}
			}
			if !nameRE.MatchString(v.User) || !nameRE.MatchString(v.BaselineName) || strings.HasPrefix(v.BaselineName, NamePrefix) || v.CPU < 1 || v.CPU > 1024 || v.MemoryGB < 1 || v.MemoryGB > 1024 {
				errs = append(errs, fmt.Errorf("provider %q: bounded resources, generic baseline name, and guest user are required", name))
			}
			if c.Cache.Enabled && !c.Cache.loopback() {
				errs = append(errs, fmt.Errorf("provider %q: isolated cache requires literal loopback listen and guest_host", name))
			}
		case "hcs":
			if p.HCS == nil || p.VZ != nil || p.Crosvm != nil || p.AppSandbox != nil {
				errs = append(errs, fmt.Errorf("provider %q: only [providers.%s.hcs] is required", name, name))
				continue
			}
			h := p.HCS
			if !h.Experimental {
				errs = append(errs, fmt.Errorf("provider %q: hcs requires experimental = true until live validation is complete", name))
			}
			if !nameRE.MatchString(h.Image) || !nameRE.MatchString(h.GuestName) || len(h.GuestName) > 15 || !nameRE.MatchString(h.GuestUser) {
				errs = append(errs, fmt.Errorf("provider %q: hcs needs a VM host image name and the image's guest name (at most 15 characters) and user", name))
			}
			if h.CPU < 1 || h.CPU > 64 || h.MemoryGB < 1 || h.MemoryGB > 256 {
				errs = append(errs, fmt.Errorf("provider %q: hcs requires explicit CPU (1-64) and memory_gb (1-256)", name))
			}
			if !windowsPath(h.RunnerDir) || (h.RunnerArchive != "" && !windowsPath(h.RunnerArchive)) {
				errs = append(errs, fmt.Errorf("provider %q: hcs paths must be absolute local Windows paths", name))
			}
			if (h.RunnerArchive == "") != (h.RunnerSHA256 == "") || (h.RunnerSHA256 != "" && (len(h.RunnerSHA256) != 64 || strings.Trim(h.RunnerSHA256, "0123456789abcdefABCDEF") != "")) {
				errs = append(errs, fmt.Errorf("provider %q: runner_archive requires its SHA-256", name))
			}
			if c.Cache.Enabled {
				errs = append(errs, fmt.Errorf("provider %q: the download cache is not yet supported for hcs guests", name))
			}
		case "appsandbox":
			if p.AppSandbox == nil || p.VZ != nil || p.Crosvm != nil || p.HCS != nil {
				errs = append(errs, fmt.Errorf("provider %q: only [providers.%s.appsandbox] is required", name, name))
				continue
			}
			a := p.AppSandbox
			if !a.Experimental {
				errs = append(errs, fmt.Errorf("provider %q: appsandbox requires experimental = true until live validation is complete", name))
			}
			if a.BrokerSecret == "" || a.Baseline == "" || len(a.Baseline) > 15 || !nameRE.MatchString(a.Baseline) {
				errs = append(errs, fmt.Errorf("provider %q: broker_secret and a native baseline name are required", name))
			}
			if a.CPU < 1 || a.CPU > 1024 || a.MemoryGB < 1 || a.MemoryGB > 1024 || a.DiskGB < 16 || a.DiskGB > 2048 {
				errs = append(errs, fmt.Errorf("provider %q: appsandbox requires bounded explicit CPU, memory, and disk", name))
			}
			if !windowsPath(a.RunnerDir) || (a.SSHKey != "" && !windowsPath(a.SSHKey)) || (a.RunnerArchive != "" && !windowsPath(a.RunnerArchive)) {
				errs = append(errs, fmt.Errorf("provider %q: appsandbox paths must be absolute local Windows paths", name))
			}
			if (a.RunnerArchive == "") != (a.RunnerSHA256 == "") || (a.RunnerSHA256 != "" && (len(a.RunnerSHA256) != 64 || strings.Trim(a.RunnerSHA256, "0123456789abcdefABCDEF") != "")) {
				errs = append(errs, fmt.Errorf("provider %q: runner_archive requires its SHA-256", name))
			}
			if c.Cache.Enabled && !c.Cache.loopback() {
				errs = append(errs, fmt.Errorf("provider %q: isolated cache requires literal loopback listen and guest_host", name))
			}
		case "vz":
			if p.Crosvm != nil {
				errs = append(errs, fmt.Errorf("provider %q: crosvm settings do not belong to vz", name))
			}
			if p.AppSandbox != nil {
				errs = append(errs, fmt.Errorf("provider %q: appsandbox settings do not belong to vz", name))
			}
			if p.HCS != nil {
				errs = append(errs, fmt.Errorf("provider %q: hcs settings do not belong to vz", name))
			}
			if p.VZ == nil {
				errs = append(errs, fmt.Errorf("provider %q: [providers.%s.vz] is required", name, name))
				continue
			}
			if p.VZ.Baseline == "" {
				errs = append(errs, fmt.Errorf("provider %q: vz.baseline is required", name))
			}
			if strings.HasPrefix(p.VZ.Baseline, NamePrefix) {
				errs = append(errs, fmt.Errorf("provider %q: vz.baseline may not start with %q", name, NamePrefix))
			}
			if p.VZ.HostVMLimit < 1 || p.VZ.ForeignSlots < 0 || p.VZ.ForeignSlots >= p.VZ.HostVMLimit {
				errs = append(errs, fmt.Errorf("provider %q: need 0 <= foreign_slots < host_vm_limit", name))
			}
			if p.VZ.CPU < 0 || p.VZ.CPU > 1024 || p.VZ.MemoryGB < 0 || p.VZ.MemoryGB > 1024 {
				errs = append(errs, fmt.Errorf("provider %q: vz cpu and memory_gb must be 0 (keep the baseline's) or 1..1024", name))
			}
			if err := p.VZ.Machine.validate(); err != nil {
				errs = append(errs, fmt.Errorf("provider %q: vz %w", name, err))
			}
			if e := p.VZ.Containers; e != nil {
				if err := e.Machine.validate(); err != nil {
					errs = append(errs, fmt.Errorf("provider %q: containers %w", name, err))
				}
				if e.Machine.Display != (Display{}) {
					errs = append(errs, fmt.Errorf("provider %q: the container engine VM has no display", name))
				}
				if e.Engine != "docker" && e.Engine != "podman" {
					errs = append(errs, fmt.Errorf("provider %q: containers.engine must be docker or podman", name))
				}
				if !nameRE.MatchString(e.Baseline) || strings.HasPrefix(e.Baseline, NamePrefix) || e.Baseline == p.VZ.Baseline {
					errs = append(errs, fmt.Errorf("provider %q: containers.baseline must be a distinct local Linux baseline name without the bivouac- prefix", name))
				}
				if e.CPU < 1 || e.MemoryGB < 1 || p.VZ.CPU < 1 || p.VZ.MemoryGB < 1 || e.CPU > 1024 || e.MemoryGB > 1024 || p.VZ.CPU > 1024 || p.VZ.MemoryGB > 1024 {
					errs = append(errs, fmt.Errorf("provider %q: container pairs require explicit CPU and memory in 1..1024 for both guests", name))
				}
				if !strings.HasPrefix(e.Helper, "/") || strings.ContainsAny(e.Helper, "\x00\r\n") {
					errs = append(errs, fmt.Errorf("provider %q: containers.helper must be an absolute Linux/arm64 binary path", name))
				}
				if c.Cache.Enabled || p.VZ.BootstrapShare != "" {
					errs = append(errs, fmt.Errorf("provider %q: isolated containers prohibit the host cache and bootstrap shares", name))
				}
			}
		case "":
			errs = append(errs, fmt.Errorf("provider %q: type is required", name))
		default:
			errs = append(errs, fmt.Errorf("provider %q: unsupported type %q", name, p.Type))
		}
	}
	errs = append(errs, c.validateAcrossProviders(names)...)
	return errors.Join(errs...)
}

// validateAcrossProviders checks rules that span provider entries.
func (c *Config) validateAcrossProviders(names []string) []error {
	var errs []error
	// Guest names are bivouac-<provider>-<id>; a provider named "a" would
	// otherwise match every "a-b" guest in its prefix filters.
	for _, a := range names {
		for _, b := range names {
			if strings.HasPrefix(b, a+"-") {
				errs = append(errs, fmt.Errorf("providers %q and %q: one name is a prefix of the other followed by '-'", a, b))
			}
		}
	}
	if c.GitHub.Demand == DemandScaleSet {
		seen := map[string]string{}
		for _, name := range names {
			key := strings.ToLower(c.Providers[name].ScaleSet)
			if key == "" {
				continue
			}
			if other, dup := seen[key]; dup {
				errs = append(errs, fmt.Errorf("providers %q and %q: scaleset names must be unique (case-insensitive)", other, name))
			}
			seen[key] = name
		}
	}
	// Apple's macOS guest limit belongs to the host, so every vz provider
	// must describe it identically.
	first := ""
	for _, name := range names {
		t := c.Providers[name].VZ
		if c.Providers[name].Type != "vz" || t == nil {
			continue
		}
		if first == "" {
			first = name
			continue
		}
		if f := c.Providers[first].VZ; f.HostVMLimit != t.HostVMLimit || f.ForeignSlots != t.ForeignSlots {
			errs = append(errs, fmt.Errorf("providers %q and %q: vz host_vm_limit and foreign_slots describe the host and must match", first, name))
		}
	}
	return errs
}

func windowsPath(path string) bool {
	return len(path) > 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') && !strings.ContainsAny(path, "\x00\r\n") && !strings.Contains(path, "..")
}

// ScaleSetLabelNames returns the scale set name followed by its extra labels.
func (p Provider) ScaleSetLabelNames() []string {
	return append([]string{p.ScaleSet}, p.ScaleSetLabels...)
}

// ProviderNames returns provider names in a stable order.
func (c *Config) ProviderNames() []string {
	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Example is a starting config for `bivouac config example`.
const Example = `# bivouac config. No secrets here: private_key_secret names a credential-store item.

[github]
url = "https://github.com/example-org"
app_client_id = "Iv1.0123456789abcdef"
app_installation_id = 12345678
private_key_secret = "github-app-key"
demand = "scaleset"          # or "jit"
runner_group = "default"

[budget]
max_instances = 1            # host-wide
max_pending_cleanup = 2      # pause new guests at this deregistration backlog
reserve_cpu = 2
reserve_memory_gb = 8
job_timeout = "2h"
idle_timeout = "10m"
ready_timeout = "3m"
sweep_idle_timeout = "90s"   # a sweep runner that finds no queued job retires after this

[providers.macos]
type = "vz"
scaleset = "bivouac-macos-experimental"
# scaleset_labels = ["bivouac-experimental"]  # extra scale set labels for runs-on arrays
labels = ["self-hosted", "macOS", "ARM64", "bivouac-experimental"]  # jit demand only
max_instances = 1
idle_pool = 1               # jit demand only; kept warm while on

[providers.macos.vz]
baseline = "ci-macos"
cpu = 6
memory_gb = 8
host_vm_limit = 2
foreign_slots = 1            # leave one macOS guest slot for Tartelet during validation

# Optional typed machine options; omitted values keep the baseline's.
# [providers.macos.vz.machine]
# display = { width = 1920, height = 1080, ppi = 144 }
# disk_sync = "none"         # skip host flushes; guests are deleted after one job
# nested_virtualization = true  # Linux guests on M3 or newer; also [providers.macos.vz.containers.machine]
`

func (c Cache) loopback() bool {
	host, _, err := net.SplitHostPort(c.Listen)
	return err == nil && host == "127.0.0.1" && c.GuestHost == "127.0.0.1"
}
