//go:build linux

package crosvm

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"github.com/GomerPiles/bivouac/internal/redact"
)

const guestRoot = "/tmp/bivouac-runner"

type guestProcess struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
	Image string `json:"image"`
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("guest file exceeds bound or is unreadable")
	}
	return data, nil
}
func guestWrite(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(guestRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(name+".new", data, 0o600); err != nil {
		return err
	}
	return root.Rename(name+".new", name)
}
func bootIdentity() (string, error) {
	data, err := readBounded("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if len(value) != 36 {
		return "", errors.New("guest boot identity unavailable")
	}
	return value, nil
}
func guestConfig() (GuestConfig, error) {
	var cfg GuestConfig
	data, err := readBounded(filepath.Join(guestRoot, "config.json"), 65536)
	if err != nil {
		return cfg, err
	}
	if json.Unmarshal(data, &cfg) != nil || !identifier(cfg.Name, 63) || !strings.HasPrefix(cfg.Name, "bivouac-") || !identifier(cfg.ControllerID, 64) || cfg.RunnerDir != "/opt/actions-runner" {
		return cfg, errors.New("invalid fixed Linux guest configuration")
	}
	boot, err := bootIdentity()
	if err != nil || boot != cfg.BootID {
		return cfg, errors.New("linux guest rebooted or its identity differs")
	}
	return cfg, nil
}
func process(pid int) (guestProcess, bool, error) {
	data, err := readBounded("/proc/"+strconv.Itoa(pid)+"/stat", 65536)
	if errors.Is(err, os.ErrNotExist) {
		return guestProcess{}, false, nil
	}
	if err != nil {
		return guestProcess{}, false, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return guestProcess{}, false, errors.New("invalid guest process metadata")
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return guestProcess{}, false, errors.New("incomplete guest process metadata")
	}
	if fields[0] == "Z" {
		return guestProcess{}, false, nil
	}
	image, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return guestProcess{}, false, err
	}
	return guestProcess{PID: pid, Start: fields[19], Image: image}, true, nil
}
func listener(cfg GuestConfig) (guestProcess, bool, error) {
	var recorded guestProcess
	data, err := readBounded(filepath.Join(guestRoot, "listener.json"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return recorded, false, nil
	}
	if err != nil {
		return recorded, false, err
	}
	if json.Unmarshal(data, &recorded) != nil || recorded.PID < 1 || recorded.Start == "" || recorded.Image != filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener") {
		return recorded, false, errors.New("invalid guest listener identity")
	}
	actual, live, err := process(recorded.PID)
	if err != nil || !live {
		return recorded, live, err
	}
	if recorded != actual {
		return recorded, false, errors.New("guest listener PID was reused")
	}
	return recorded, true, nil
}

// RunLinuxGuest is a private guest adapter, never a host daemon or credential
// client. It installs no project tools. The immutable baseline supplies an
// unconfigured official runner, Git, Docker and generic virtio/CDI runtime.
func RunLinuxGuest(ctx context.Context, mode string, input io.Reader, out io.Writer) error {
	self, err := os.Executable()
	if err != nil || (filepath.Base(self) != "bivouac-guest" && self != runtimeHelper) {
		return errors.New("linux adapter must run from its disposable guest installation")
	}
	if mode == "prepare-image" {
		return prepareLinuxImage(ctx, self, input, out)
	}
	if os.Getuid() == 0 {
		return errors.New("linux runner must use its dedicated non-root user")
	}
	if mode == "prepare" {
		return prepareLinuxGuest(ctx, self, input, out)
	}
	cfg, err := guestConfig()
	if err != nil {
		return err
	}
	switch mode {
	case "image-identity":
		return json.NewEncoder(out).Encode(cfg)
	case "boot-report":
		return linuxBootReport(ctx, out)
	case "cache-setup":
		data, err := io.ReadAll(io.LimitReader(input, 32<<10+1))
		if err != nil {
			return errors.New("read private cache bootstrap")
		}
		defer clear(data)
		return cache.PrepareGuest(ctx, guestRoot, data)
	case "cache-remove":
		return cache.RemoveGuest(guestRoot)
	case "seed-jit":
		data, err := io.ReadAll(io.LimitReader(input, 128<<10+1))
		if err != nil || len(data) == 0 || len(data) > 128<<10 {
			return errors.New("invalid bounded guest JIT input")
		}
		defer clear(data)
		f, err := os.OpenFile(filepath.Join(guestRoot, "jit"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("guest JIT input already exists or is unavailable")
		}
		_, err = f.Write(data)
		return errors.Join(err, f.Close())
	case "launch":
		if _, err := os.Stat(filepath.Join(guestRoot, "launch-once")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("listener launch is single-use")
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(filepath.Join(guestRoot, "supervisor.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = output.Close() }()
		cmd := exec.Command(self, "guest", "linux", "listener")
		cmd.Stdout = output
		cmd.Stderr = output
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return errors.New("detached Linux listener could not start")
		}
		return cmd.Process.Release()
	case "listener":
		return linuxListener(ctx, cfg)
	case "status":
		status, err := linuxStatus(cfg)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(status)
	case "cancel":
		identity, live, err := listener(cfg)
		if err != nil {
			return err
		}
		if !live {
			return nil
		}
		return syscall.Kill(identity.PID, syscall.SIGTERM)
	case "hook":
		runID, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
		if err != nil || runID < 1 {
			return errors.New("invalid guest job identity")
		}
		repo, name := os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_JOB")
		if len(repo+name) > 512 || strings.ContainsAny(repo+name, "\r\n\x00") {
			return errors.New("invalid bounded guest job identity")
		}
		if err := guestWrite("job.json", provider.RunnerJob{RunID: runID, Repository: repo, Name: name}); err != nil {
			return err
		}
		perf.PrintStart(out, cfg.RunnerDir)
		return nil
	case "hook-completed":
		perf.PrintEnd(ctx, out, guestRoot)
		cache.PrintGuestSummary(ctx, out, guestRoot)
		return nil
	case "diagnostics":
		return linuxDiagnostics(cfg, out)
	default:
		return errors.New("unknown fixed Linux guest operation")
	}
}

func persistentPublicDNS(ctx context.Context) (dnsPreparation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := os.Stat("/usr/bin/nmcli")
	nm := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return dnsPreparation{}, err
	}
	if !nm {
		info, e := os.Lstat("/etc/resolv.conf")
		if e != nil || !info.Mode().IsRegular() {
			return dnsPreparation{}, errors.New("generic image needs NetworkManager or a static unmanaged resolver file")
		}
	}
	return configurePublicDNS(ctx, nm, func() ([]byte, error) { return readBounded("/etc/resolv.conf", 65536) }, appsandbox.NativeCommands{})
}
func installRuntimeHelper(self string) error {
	if self == preparedHelper {
		return os.Symlink(preparedHelper, runtimeHelper)
	}
	source, err := os.Open(self)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	// #nosec G302 -- This private guest-only executable must be owner-executable.
	destination, err := os.OpenFile(runtimeHelper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, source)
	return errors.Join(err, destination.Close())
}

func linuxDiagnostics(cfg GuestConfig, out io.Writer) error {
	path := filepath.Join(guestRoot, "diagnostics.zip")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(f)
	var total int64
	add := func(path, name string) error {
		input, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		info, err := input.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 16<<20 {
			return errors.New("guest diagnostic file exceeds bound")
		}
		total += info.Size()
		if total > 128<<20 {
			return errors.New("guest diagnostics exceed bound")
		}
		writer, err := archive.Create(name)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, io.LimitReader(input, 16<<20+1))
		return err
	}
	err = add(filepath.Join(guestRoot, "runner.log"), "runner.log")
	if err == nil {
		if report, readErr := perf.ReadReport(guestRoot); readErr == nil {
			var writer io.Writer
			writer, err = archive.Create(perf.FileName)
			if err == nil {
				err = json.NewEncoder(writer).Encode(report)
			}
		}
	}
	if err == nil {
		entries, listErr := os.ReadDir(filepath.Join(cfg.RunnerDir, "_diag"))
		if listErr != nil && !errors.Is(listErr, os.ErrNotExist) {
			err = listErr
		}
		if len(entries) > 1022 {
			err = errors.New("too many guest diagnostics")
		}
		for _, entry := range entries {
			if err != nil {
				break
			}
			if entry.IsDir() {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				err = errors.New("guest diagnostic symlink rejected")
				break
			}
			err = add(filepath.Join(cfg.RunnerDir, "_diag", entry.Name()), "_diag/"+entry.Name())
		}
	}
	if err = errors.Join(err, archive.Close(), f.Close()); err != nil {
		return err
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	stat, err := input.Stat()
	if err != nil || stat.Size() > 32<<20 {
		return errors.New("compressed guest diagnostics exceed bound")
	}
	encoder := base64.NewEncoder(base64.StdEncoding, out)
	_, err = io.Copy(encoder, io.LimitReader(input, 32<<20+1))
	return errors.Join(err, encoder.Close())
}

type boundedLog struct {
	sink  *redact.Writer
	total int64
}

func (w *boundedLog) Write(data []byte) (int, error) {
	n := len(data)
	remaining := int64(8<<20) - w.total
	if remaining <= 0 {
		return n, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	w.total += int64(len(data))
	_, err := w.sink.Write(data)
	return n, err
}
func linuxListener(ctx context.Context, cfg GuestConfig) error {
	guard, err := os.OpenFile(filepath.Join(guestRoot, "launch-once"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("listener launch is single-use")
	}
	if err := guard.Close(); err != nil {
		return err
	}
	jit, err := readBounded(filepath.Join(guestRoot, "jit"), 128<<10)
	if err != nil {
		return err
	}
	defer clear(jit)
	if err := os.Remove(filepath.Join(guestRoot, "jit")); err != nil {
		return err
	}
	const hook = "#!/bin/sh\nexec /tmp/bivouac-runner/helper guest linux hook\n"
	const completedHook = "#!/bin/sh\n/tmp/bivouac-runner/helper guest linux hook-completed\nexit 0\n"
	// #nosec G306 -- The official runner executes this fixed private guest hook.
	if err := os.WriteFile(filepath.Join(guestRoot, "job-started.sh"), []byte(hook), 0o700); err != nil {
		return err
	}
	completedPath := filepath.Join(guestRoot, "job-completed.sh")
	// #nosec G306 -- Fixed owner-only executable hook in the disposable guest.
	if err := os.WriteFile(completedPath, []byte(completedHook), 0o700); err != nil {
		completedPath = ""
	}
	output, err := os.OpenFile(filepath.Join(guestRoot, "runner.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	sink := redact.NewWriter(output)
	defer func() { _ = sink.Close() }()
	log := &boundedLog{sink: sink}
	cmd := exec.Command(filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener"), "run")
	cmd.Dir = cfg.RunnerDir
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(key, "ACTIONS_RUNNER_INPUT_") && !strings.HasPrefix(key, "ACTIONS_RUNNER_HOOK_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "ACTIONS_RUNNER_INPUT_JITCONFIG="+string(jit), "ACTIONS_RUNNER_HOOK_JOB_STARTED="+filepath.Join(guestRoot, "job-started.sh"))
	if completedPath != "" {
		cmd.Env = append(cmd.Env, "ACTIONS_RUNNER_HOOK_JOB_COMPLETED="+completedPath)
	}
	cacheEnv, closeCache, err := cache.GuestEnvironment(guestRoot)
	if err != nil {
		return err
	}
	defer closeCache()
	cmd.Env = cache.MergeEnvironment(cmd.Env, cacheEnv)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return errors.New("official Linux listener failed to start")
	}
	cmd.Env = nil
	identity, live, err := process(cmd.Process.Pid)
	if err != nil || !live {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("linux listener identity could not be recorded")
	}
	if err := guestWrite("listener.json", identity); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	stopPerformance := perf.StartRecorder(ctx, guestRoot, cfg.RunnerDir)
	defer stopPerformance()
	waitErr := cmd.Wait()
	code := 0
	if waitErr != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return guestWrite("runner.exit", struct {
		Code int `json:"code"`
	}{code})
}
func linuxStatus(cfg GuestConfig) (provider.RunnerStatus, error) {
	data, err := readBounded(filepath.Join(guestRoot, "runner.exit"), 4096)
	if err == nil {
		var exit struct{ Code int }
		if json.Unmarshal(data, &exit) != nil {
			return provider.RunnerStatus{}, errors.New("invalid Linux listener exit record")
		}
		return provider.RunnerStatus{State: provider.RunnerExited, ExitCode: exit.Code}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return provider.RunnerStatus{}, err
	}
	_, live, err := listener(cfg)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	if !live {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	status := provider.RunnerStatus{State: provider.RunnerStarting}
	data, err = readBounded(filepath.Join(guestRoot, "runner.log"), 8<<20)
	if err != nil {
		return status, err
	}
	if strings.Contains(string(data), "Listening for Jobs") {
		status.State = provider.RunnerListening
	}
	data, err = readBounded(filepath.Join(guestRoot, "job.json"), 4096)
	if err == nil {
		var job provider.RunnerJob
		if json.Unmarshal(data, &job) != nil || job.RunID < 1 {
			return status, errors.New("invalid Linux guest job record")
		}
		status.State = provider.RunnerRunning
		status.Job = &job
	} else if !errors.Is(err, os.ErrNotExist) {
		return status, err
	}
	return status, nil
}

func prepareLinuxGuest(ctx context.Context, self string, input io.Reader, out io.Writer) (result error) {
	stage := uint32(1)
	defer func() {
		if result != nil {
			var fault *dnsError
			var dnsStage uint32
			if errors.As(result, &fault) {
				dnsStage = fault.stage
			}
			result = json.NewEncoder(out).Encode(GuestPreparation{FailedStage: stage, DNSFailure: dnsStage})
		}
	}()

	started := time.Now()
	var observation GuestPreparation
	var cfg GuestConfig
	decoder := json.NewDecoder(io.LimitReader(input, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || !identifier(cfg.Name, 63) || !strings.HasPrefix(cfg.Name, "bivouac-") ||
		!identifier(cfg.ControllerID, 64) || cfg.RunnerDir != "/opt/actions-runner" || cfg.BootID != "" {
		return errors.New("invalid bounded guest bootstrap")
	}
	stage = 2
	if _, err := os.Stat(guestRoot); err == nil {
		return errors.New("guest bootstrap state already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(guestRoot, 0o700); err != nil {
		return err
	}
	stage = 3
	boot, err := bootIdentity()
	if err != nil {
		return err
	}
	cfg.BootID = boot
	stage = 4
	for _, name := range []string{".runner", ".credentials"} {
		if _, err := os.Stat(filepath.Join(cfg.RunnerDir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("baseline has configured runner state or cannot be inspected")
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener")); err != nil {
		return errors.New("generic official runner is missing")
	}
	stage = 5
	if cfg.GPU {
		data, err := readBounded("/sys/class/drm/renderD128/device/vendor", 128)
		if err != nil || strings.TrimSpace(string(data)) != "0x1af4" {
			return errors.New("generic virtio GPU is unavailable")
		}
		if _, err := os.Stat("/etc/cdi/ci-gpu.json"); err != nil {
			return errors.New("generic GPU CDI runtime is missing")
		}
	}
	stage = 6
	dnsStarted := time.Now()
	dns, err := persistentPublicDNS(ctx)
	observation.DNSMS = time.Since(dnsStarted).Milliseconds()
	if err != nil {
		return err
	}
	observation.DNSReused = dns.Reused
	observation.DNSProfileChanged = dns.ProfileChanged
	observation.DNSResolverChanged = dns.ResolverChanged
	stage = 7
	helperStarted := time.Now()
	if err = installRuntimeHelper(self); err != nil {
		return err
	}
	observation.HelperInstallMS = time.Since(helperStarted).Milliseconds()
	stage = 8
	if err := guestWrite("config.json", cfg); err != nil {
		return err
	}
	observation.Config = cfg
	observation.TotalMS = time.Since(started).Milliseconds()
	return json.NewEncoder(out).Encode(observation)

}
