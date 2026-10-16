//go:build unix

package vz

import (
	"errors"
	"os/exec"
	"syscall"
)

// detach puts a long-lived child in its own process group, so a terminal's
// Ctrl+C (SIGINT to the foreground group) stops the daemon but not the guest.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// terminate signals a VM helper: SIGTERM has it power the VM off, SIGKILL
// ends a helper that hangs. A process that already exited is not an error.
func terminate(pid int, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
