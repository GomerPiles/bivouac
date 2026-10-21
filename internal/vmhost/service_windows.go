//go:build windows

package vmhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/winhost"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the optional Windows service. Nothing installs it implicitly.
const ServiceName = "bivouac-vmhost"

// serviceDescriptor lets the configured accounts query, start and stop this
// one service, so mode changes never need elevation, and nothing else.
func serviceDescriptor(accounts []string) string {
	var b strings.Builder
	b.WriteString("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)")
	for _, sid := range accounts {
		b.WriteString("(A;;CCLCSWRPWPLOCRRC;;;" + sid + ")")
	}
	return b.String()
}

// Run serves the VM host until ctx ends, then destroys its guests. It backs
// both the foreground command and the service.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("the VM host must run elevated")
	}
	if err := protectedRoot(cfg.Root); err != nil {
		return err
	}
	host, err := Open(cfg.Root, cfg.Controller)
	if err != nil {
		return err
	}
	defer func() { _ = host.Close() }()
	// Absence polls and network deletion retry until their context ends, so a
	// guest or network that never settles must not hold startup forever.
	recoverCtx, cancelRecover := context.WithTimeout(ctx, 2*time.Minute)
	err = host.Recover(recoverCtx)
	cancelRecover()
	if err != nil {
		log.Warn("guests retained from an earlier VM host", "error", err)
	}
	// ListenPipe creates the first instance exclusively, so an existing
	// server of this name, privileged or not, makes startup fail. The explicit
	// Administrators owner is what clients trust, whatever the local policy
	// for an administrator's default owner.
	l, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: "O:BA" + pipeDescriptor(cfg.Accounts)})
	if err != nil {
		return fmt.Errorf("cannot serve the VM host pipe: %w", err)
	}
	server := NewServer(host, cfg)
	guardCtx, stopGuard := context.WithCancel(ctx)
	guarded := make(chan struct{})
	go func() { defer close(guarded); server.Guard(guardCtx, GuardInterval) }()
	log.Info("VM host serving", "controller", cfg.Controller, "max_instances", cfg.MaxInstances)
	err = server.Serve(ctx, l)
	stopGuard()
	<-guarded
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if destroyErr := server.DestroyAll(cleanup); destroyErr != nil {
		log.Error("guests retained at VM host exit", "error", destroyErr)
		err = errors.Join(err, destroyErr)
	}
	log.Info("VM host stopped")
	return err
}

type service struct {
	cfg Config
	log *slog.Logger
}

func (s service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s.cfg, s.log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				s.log.Error("VM host failed", "error", err)
				return false, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 150000}
				cancel()
				if err := <-done; err != nil {
					s.log.Error("VM host stopped with errors", "error", err)
					return false, 1
				}
				return false, 0
			}
		}
	}
}

// RunService runs under the service control manager.
func RunService(cfg Config, log *slog.Logger) error {
	return svc.Run(ServiceName, service{cfg: cfg, log: log})
}

// Install registers the manual-start service, from an elevated shell. The
// executable and configuration must be administrator-protected: the service
// runs them as SYSTEM.
func Install(exe, configPath string, cfg Config) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("installing the VM host service needs an elevated shell")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	for _, path := range []string{exe, configPath} {
		if err := winhost.CheckProtected(path); err != nil {
			return fmt.Errorf("%s must be administrator-protected: %w", path, err)
		}
	}
	if err := protectedRoot(cfg.Root); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	if existing, err := m.OpenService(ServiceName); err == nil {
		_ = existing.Close()
		return errors.New("the VM host service is already installed")
	}
	s, err := m.CreateService(ServiceName, exe, mgr.Config{
		DisplayName:  "bivouac VM host",
		Description:  "Runs disposable bivouac CI guests through the Host Compute Service. Started and stopped by bivouac on and off.",
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
	}, "vmhost", "service", "--config", configPath)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}}, 3600)
	if err == nil {
		err = setServiceDescriptor(s.Handle, serviceDescriptor(cfg.Accounts))
	}
	if err != nil {
		return errors.Join(err, s.Delete())
	}
	return nil
}

func setServiceDescriptor(handle windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// protectedRoot creates the journal directory administrator-only, or
// accepts an existing one only if it is protected.
func protectedRoot(dir string) error {
	if err := winhost.CheckProtectedParents(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err == nil {
		sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		if err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	return winhost.CheckProtected(dir)
}

// Uninstall removes a stopped service. A running one is refused: stopping it
// ends its guests, which is the caller's decision through bivouac off or stop.
func Uninstall() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("removing the VM host service needs an elevated shell")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return errors.New("the VM host service is not installed")
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		return errors.New("stop the VM host service first; stopping it ends its guests")
	}
	return s.Delete()
}

// ServiceState reports whether the service is installed and its state,
// without elevation.
func ServiceState() (installed bool, state svc.State, err error) {
	err = withService(windows.SERVICE_QUERY_STATUS, func(s windows.Handle) error {
		var st windows.SERVICE_STATUS
		if err := windows.QueryServiceStatus(s, &st); err != nil {
			return err
		}
		state = svc.State(st.CurrentState)
		return nil
	})
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, 0, nil
	}
	return err == nil, state, err
}

// StartService starts an installed service using the rights its installer
// granted, and waits until it is running.
func StartService(ctx context.Context) error {
	err := withService(windows.SERVICE_START|windows.SERVICE_QUERY_STATUS, func(s windows.Handle) error {
		if err := windows.StartService(s, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return waitService(ctx, s, svc.Running)
	})
	return err
}

// StopService stops the service, which destroys its guests first.
func StopService(ctx context.Context) error {
	return withService(windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, func(s windows.Handle) error {
		var st windows.SERVICE_STATUS
		if err := windows.ControlService(s, windows.SERVICE_CONTROL_STOP, &st); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		return waitService(ctx, s, svc.Stopped)
	})
}

func withService(access uint32, f func(windows.Handle) error) error {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseServiceHandle(m) }()
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return err
	}
	s, err := windows.OpenService(m, name, access)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseServiceHandle(s) }()
	return f(s)
}

func waitService(ctx context.Context, s windows.Handle, want svc.State) error {
	for {
		var st windows.SERVICE_STATUS
		if err := windows.QueryServiceStatus(s, &st); err != nil {
			return err
		}
		if svc.State(st.CurrentState) == want {
			return nil
		}
		if want == svc.Running && svc.State(st.CurrentState) == svc.Stopped {
			return errors.New("the VM host service stopped while starting; see its log")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
