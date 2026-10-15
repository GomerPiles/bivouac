//go:build unix

package tart

import (
	"os/exec"
	"syscall"
)

// detach puts a long-lived child in its own process group, so a terminal's
// Ctrl+C (SIGINT to the foreground group) stops the daemon but not the guest.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
