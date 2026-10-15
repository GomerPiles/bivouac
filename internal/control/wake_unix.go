//go:build !windows

package control

import (
	"errors"
	"os"
	"syscall"
)

// WakeSignal is what the CLI sends so the daemon re-reads the mode file now.
var WakeSignal = syscall.SIGUSR1

// Wake nudges the daemon. A missing or dead daemon is not an error: the mode
// file is durable and the next start reads it. The PID file is only trusted
// while the daemon lock is held: after a crash or reboot it can name an
// unrelated process, for which SIGUSR1 would be fatal.
func (f Files) Wake() (bool, error) {
	held, err := f.probeLock()
	if err != nil || !held {
		return false, err
	}
	pid, err := f.ReadPID()
	if err != nil {
		return true, err
	}
	if pid <= 0 {
		// The holder has not written its PID yet; it reads the mode when its
		// control loop starts.
		return true, nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	if err := proc.Signal(WakeSignal); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Alive reports whether a daemon holds the state-directory lock. Unreadable
// lock state is reported as alive: it is a status hint, never authority to
// signal or stop anything.
func (f Files) Alive() bool {
	held, err := f.probeLock()
	return held || errors.Is(err, os.ErrPermission)
}
