//go:build windows

package control

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// WakeSignal is unused on Windows; the daemon polls the mode file.
var WakeSignal = os.Interrupt

// The Windows daemon observes durable mode changes through polling. Return its
// liveness so the CLI does not falsely claim that an existing daemon is stopped.
func (f Files) Wake() (bool, error) { return f.Alive(), nil }

// Alive observes the kernel lock, which is released on crash/reboot. A stale
// PID can have been reused by an unrelated process and is not daemon liveness.
func (f Files) Alive() bool {
	held, err := f.probeLock()
	// Inaccessible lock state remains conservative, never stop authority.
	return held || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
