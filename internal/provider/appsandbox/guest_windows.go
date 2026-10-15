//go:build windows

package appsandbox

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
	"sync"
	"syscall"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/cache"
	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const guestBase = `C:\ProgramData\Bivouac\Guest`

// Actions job hooks accept .ps1 on Windows, not .cmd. Failure to capture the
// accepted job must fail setup rather than leave the manager treating it as idle.
const windowsJobHookName = "job-started.ps1"
const windowsJobHook = `$ErrorActionPreference='Stop'
& 'C:\ProgramData\Bivouac\Guest\bivouac.exe' guest windows hook
if($LASTEXITCODE -ne 0){throw 'Guest job identity capture failed'}
`
const windowsJobCompletedHook = `& 'C:\ProgramData\Bivouac\Guest\bivouac.exe' guest windows hook-completed
exit 0
`

type listenerIdentity struct {
	PID      uint32 `json:"pid"`
	Creation uint64 `json:"creation"`
	Image    string `json:"image"`
}

func readGuestFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("guest file exceeds bound or is unreadable")
	}
	return data, nil
}
func writeGuestJSON(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(guestBase)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tmp := name + ".new"
	if err := root.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}
func loadGuestConfig() (guestConfig, error) {
	var cfg guestConfig
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(self), filepath.Join(guestBase, "bivouac.exe")) {
		return cfg, errors.New("guest adapter must run from the fixed disposable-guest installation")
	}
	data, err := readGuestFile(filepath.Join(guestBase, "config.json"), 65536)
	if err != nil {
		return cfg, err
	}
	if json.Unmarshal(data, &cfg) != nil || !identifier(cfg.NativeName, 15) || !identifier(cfg.ControllerID, 64) || !identifier(cfg.User, 32) || !validRunnerPath(cfg.RunnerDir) ||
		!strings.EqualFold(os.Getenv("COMPUTERNAME"), cfg.NativeName) || !strings.EqualFold(os.Getenv("USERNAME"), cfg.User) {
		return cfg, errors.New("disposable guest identity differs")
	}
	if _, err := instanceKey(cfg.RunnerName); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// RunWindowsGuest is the fixed helper copied into a disposable VM. It never
// loads the host config or touches its credential store. Interactive methods
// are launched by guest Task Scheduler in the logged-in user's session.
func RunWindowsGuest(ctx context.Context, mode string, out io.Writer) error {
	cfg, err := loadGuestConfig()
	if err != nil {
		return err
	}
	switch mode {
	case "cache-setup":
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<10+1))
		if err != nil {
			return errors.New("read private cache bootstrap")
		}
		defer clear(data)
		return cache.PrepareGuest(ctx, guestBase, data)
	case "cache-remove":
		return cache.RemoveGuest(guestBase)
	case "seed-jit":
		jit, err := io.ReadAll(io.LimitReader(os.Stdin, 128<<10+1))
		if err != nil || len(jit) == 0 || len(jit) > 128<<10 {
			return errors.New("invalid bounded guest JIT input")
		}
		defer clear(jit)
		file, err := os.OpenFile(filepath.Join(guestBase, "jit"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("guest JIT input already exists or is unavailable")
		}
		_, err = file.Write(jit)
		return errors.Join(err, file.Close())
	case "probe":
		session, desktop, err := interactiveDesktop()
		if err != nil {
			return err
		}
		return writeGuestJSON("desktop.json", struct {
			Ready   bool   `json:"ready"`
			Session uint32 `json:"session"`
			Desktop string `json:"desktop"`
		}{true, session, desktop})
	case "listener":
		return guestListener(ctx, cfg)
	case "status":
		status, err := guestRunnerStatus(cfg)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(status)
	case "cancel":
		return guestCancel(cfg)
	case "hook":
		runID, err := strconv.ParseInt(os.Getenv("GITHUB_RUN_ID"), 10, 64)
		if err != nil || runID < 1 {
			return errors.New("invalid job identity")
		}
		repo, name := os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_JOB")
		if len(repo) > 256 || len(name) > 256 || strings.ContainsAny(repo+name, "\r\n\x00") {
			return errors.New("invalid bounded job identity")
		}
		if err := writeGuestJSON("job.json", provider.RunnerJob{RunID: runID, Repository: repo, Name: name}); err != nil {
			return err
		}
		perf.PrintStart(out, cfg.RunnerDir)
		return nil
	case "hook-completed":
		perf.PrintEnd(ctx, out, guestBase)
		cache.PrintGuestSummary(ctx, out, guestBase)
		return nil
	case "diagnostics":
		return guestDiagnostics(cfg, out)
	default:
		return errors.New("unknown fixed Windows guest operation")
	}
}
func interactiveDesktop() (uint32, string, error) {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil || session == 0 {
		return 0, "", errors.New("runner requires an interactive session")
	}
	dll := windows.NewLazySystemDLL("user32.dll")
	desktop, _, _ := dll.NewProc("OpenInputDesktop").Call(0, 0, 0x0001)
	if desktop == 0 {
		return 0, "", errors.New("input desktop unavailable")
	}
	defer func() { _, _, _ = dll.NewProc("CloseDesktop").Call(desktop) }()
	var name [256]uint16
	var needed uint32
	// #nosec G103 -- Fixed-size user32 output buffer and documented UOI_NAME ABI.
	result, _, _ := dll.NewProc("GetUserObjectInformationW").Call(desktop, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&needed)))
	if result == 0 || needed > uint32(len(name)*2) || windows.UTF16ToString(name[:]) != "Default" {
		return 0, "", errors.New("default interactive input desktop unavailable")
	}
	return session, "Default", nil
}
func processIdentity(pid uint32) (listenerIdentity, bool, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return listenerIdentity{}, false, nil
	}
	if err != nil {
		return listenerIdentity{}, false, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return listenerIdentity{}, false, err
	}
	const stillActive = 259
	if code != stillActive {
		return listenerIdentity{}, false, nil
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return listenerIdentity{}, false, err
	}
	var image [32768]uint16
	length := uint32(len(image))
	if err := windows.QueryFullProcessImageName(handle, 0, &image[0], &length); err != nil {
		return listenerIdentity{}, false, err
	}
	return listenerIdentity{PID: pid, Creation: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), Image: windows.UTF16ToString(image[:length])}, true, nil
}
func recordedListener(cfg guestConfig) (listenerIdentity, bool, error) {
	var identity listenerIdentity
	data, err := readGuestFile(filepath.Join(guestBase, "listener.json"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return identity, false, nil
	}
	if err != nil {
		return identity, false, err
	}
	if json.Unmarshal(data, &identity) != nil || identity.PID == 0 || identity.Creation == 0 || !strings.EqualFold(identity.Image, filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener.exe")) {
		return identity, false, errors.New("recorded listener identity differs")
	}
	current, live, err := processIdentity(identity.PID)
	if err != nil || !live {
		return identity, live, err
	}
	if current.Creation != identity.Creation || !strings.EqualFold(current.Image, identity.Image) {
		return identity, false, errors.New("listener PID was reused")
	}
	return identity, true, nil
}
func rebuiltPath() (string, error) {
	read := func(hive registry.Key, key string) (string, error) {
		k, err := registry.OpenKey(hive, key, registry.QUERY_VALUE)
		if err != nil {
			return "", err
		}
		defer func() { _ = k.Close() }()
		value, _, err := k.GetStringValue("Path")
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return value, err
	}
	machine, err := read(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	if err != nil {
		return "", err
	}
	user, err := read(registry.CURRENT_USER, `Environment`)
	if err != nil {
		return "", err
	}
	text, err := windows.UTF16PtrFromString(machine + ";" + user)
	if err != nil {
		return "", err
	}
	var result [32768]uint16
	n, err := windows.ExpandEnvironmentStrings(text, &result[0], uint32(len(result)))
	if err != nil || n > uint32(len(result)) {
		return "", errors.New("guest PATH expansion failed")
	}
	return windows.UTF16ToString(result[:]), nil
}

type guestLog struct {
	mu    sync.Mutex
	sink  *redact.Writer
	bytes int64
}

func (w *guestLog) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(data)
	remaining := int64(8<<20) - w.bytes
	if remaining <= 0 {
		return n, nil
	}
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	w.bytes += int64(len(data))
	_, err := w.sink.Write(data)
	return n, err
}
func guestListener(ctx context.Context, cfg guestConfig) error {
	if _, _, err := interactiveDesktop(); err != nil {
		return err
	}
	guard, err := os.OpenFile(filepath.Join(guestBase, "launch-once"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("listener launch is single-use")
	}
	if err := guard.Close(); err != nil {
		return err
	}
	jit, err := readGuestFile(filepath.Join(guestBase, "jit"), 128<<10)
	if err != nil {
		return err
	}
	defer clear(jit)
	if len(jit) == 0 {
		return errors.New("empty guest JIT configuration")
	}
	if err := os.Remove(filepath.Join(guestBase, "jit")); err != nil {
		return err
	}
	path, err := rebuiltPath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(guestBase, windowsJobHookName), []byte(windowsJobHook), 0o600); err != nil {
		return err
	}
	completedHook := filepath.Join(guestBase, "job-completed.ps1")
	if err := os.WriteFile(completedHook, []byte(windowsJobCompletedHook), 0o600); err != nil {
		completedHook = ""
	}
	output, err := os.OpenFile(filepath.Join(guestBase, "runner.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	sink := redact.NewWriter(output)
	defer func() { _ = sink.Close() }()
	log := &guestLog{sink: sink}
	binary := filepath.Join(cfg.RunnerDir, "bin", "Runner.Listener.exe")
	cmd := exec.Command(binary, "run")
	cmd.Dir = cfg.RunnerDir
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.EqualFold(key, "PATH") && !strings.HasPrefix(strings.ToUpper(key), "ACTIONS_RUNNER_INPUT_") && !strings.HasPrefix(strings.ToUpper(key), "ACTIONS_RUNNER_HOOK_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+path, "ACTIONS_RUNNER_INPUT_JITCONFIG="+string(jit), "ACTIONS_RUNNER_HOOK_JOB_STARTED="+filepath.Join(guestBase, windowsJobHookName))
	if completedHook != "" {
		cmd.Env = append(cmd.Env, "ACTIONS_RUNNER_HOOK_JOB_COMPLETED="+completedHook)
	}
	cacheEnv, closeCache, err := cache.GuestEnvironment(guestBase)
	if err != nil {
		return err
	}
	defer closeCache()
	cmd.Env = cache.MergeEnvironment(cmd.Env, cacheEnv)
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_CONSOLE}
	if err := cmd.Start(); err != nil {
		return errors.New("official guest runner could not start")
	}
	cmd.Env = nil
	if cmd.Process.Pid < 1 || uint64(cmd.Process.Pid) > 0xffffffff {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("invalid native listener PID")
	}
	identity, live, err := processIdentity(uint32(cmd.Process.Pid))
	if err != nil || !live {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("listener identity could not be recorded")
	}
	if err := writeGuestJSON("listener.json", identity); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	stopPerformance := perf.StartRecorder(ctx, guestBase, cfg.RunnerDir)
	defer stopPerformance()
	waitErr := cmd.Wait()
	code := 0
	if waitErr != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return writeGuestJSON("runner.exit", struct {
		Code int `json:"code"`
	}{code})
}
func guestRunnerStatus(cfg guestConfig) (provider.RunnerStatus, error) {
	data, err := readGuestFile(filepath.Join(guestBase, "runner.exit"), 4096)
	if err == nil {
		var exit struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(data, &exit) != nil {
			return provider.RunnerStatus{}, errors.New("invalid runner exit record")
		}
		return provider.RunnerStatus{State: provider.RunnerExited, ExitCode: exit.Code}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return provider.RunnerStatus{}, err
	}
	_, live, err := recordedListener(cfg)
	if err != nil {
		return provider.RunnerStatus{}, err
	}
	if !live {
		return provider.RunnerStatus{State: provider.RunnerAbsent}, nil
	}
	status := provider.RunnerStatus{State: provider.RunnerStarting}
	data, err = readGuestFile(filepath.Join(guestBase, "runner.log"), 8<<20)
	if err != nil {
		return status, err
	}
	if strings.Contains(string(data), "Listening for Jobs") {
		status.State = provider.RunnerListening
	}
	data, err = readGuestFile(filepath.Join(guestBase, "job.json"), 4096)
	if err == nil {
		var job provider.RunnerJob
		if json.Unmarshal(data, &job) != nil || job.RunID < 1 {
			return status, errors.New("invalid guest job identity")
		}
		status.State = provider.RunnerRunning
		status.Job = &job
	} else if !errors.Is(err, os.ErrNotExist) {
		return status, err
	}
	return status, nil
}
func guestCancel(cfg guestConfig) error {
	if _, _, err := interactiveDesktop(); err != nil {
		return err
	}
	identity, live, err := recordedListener(cfg)
	if err != nil {
		return err
	}
	if live {
		dll := windows.NewLazySystemDLL("kernel32.dll")
		_, _, _ = dll.NewProc("FreeConsole").Call()
		result, _, _ := dll.NewProc("AttachConsole").Call(uintptr(identity.PID))
		if result == 0 {
			return errors.New("cannot attach to owned listener console")
		}
		defer func() { _, _, _ = dll.NewProc("FreeConsole").Call() }()
		_, _, _ = dll.NewProc("SetConsoleCtrlHandler").Call(0, 1)
		// Recheck the creation time after attaching; never signal a reused PID.
		_, live, err = recordedListener(cfg)
		if err != nil {
			return err
		}
		if live {
			if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(guestBase, "cancelled"), []byte("requested"), 0o600)
}
func guestDiagnostics(cfg guestConfig, out io.Writer) error {
	// The archive is untrusted at the host boundary and is validated/redacted
	// again there. Only the listener log and official _diag are selected here.
	destination := filepath.Join(os.Getenv("USERPROFILE"), "bivouac-diagnostics.zip")
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(f)
	add := func(path, name string) error {
		input, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		stat, err := input.Stat()
		if err != nil || !stat.Mode().IsRegular() || stat.Size() > 16<<20 {
			return errors.New("guest diagnostic file exceeds bound")
		}
		output, err := archive.Create(name)
		if err != nil {
			return err
		}
		_, err = io.Copy(output, io.LimitReader(input, 16<<20+1))
		return err
	}
	err = add(filepath.Join(guestBase, "runner.log"), "runner.log")
	if err == nil {
		if report, readErr := perf.ReadReport(guestBase); readErr == nil {
			var writer io.Writer
			writer, err = archive.Create(perf.FileName)
			if err == nil {
				err = json.NewEncoder(writer).Encode(report)
			}
		}
	}
	if err == nil {
		var entries []os.DirEntry
		entries, err = os.ReadDir(filepath.Join(cfg.RunnerDir, "_diag"))
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		if len(entries) > 1022 {
			err = errors.New("too many guest diagnostic files")
		}
		var total int64
		for _, entry := range entries {
			if err != nil {
				break
			}
			if entry.IsDir() {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				err = infoErr
				break
			}
			total += info.Size()
			if !info.Mode().IsRegular() || total > 120<<20 {
				err = errors.New("guest diagnostics exceed bound")
				break
			}
			err = add(filepath.Join(cfg.RunnerDir, "_diag", entry.Name()), "_diag/"+entry.Name())
		}
	}
	if err = errors.Join(err, archive.Close(), f.Close()); err != nil {
		return err
	}
	input, err := os.Open(destination)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	stat, err := input.Stat()
	if err != nil || stat.Size() > 32<<20 {
		return errors.New("compressed diagnostics exceed bound")
	}
	encoder := base64.NewEncoder(base64.StdEncoding, out)
	_, err = io.Copy(encoder, io.LimitReader(input, 32<<20+1))
	return errors.Join(err, encoder.Close())
}
