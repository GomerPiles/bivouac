//go:build windows

package main

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// loginRun is the scheduled task's entry point. Carry the installation's home
// explicitly: Task Scheduler does not inherit the installing shell's environment.
func loginRun(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("the login manager must run without elevation")
	}
	if err := os.Setenv("BIVOUAC_HOME", args[0]); err != nil {
		return err
	}
	return dispatch(ctx, "run", nil)
}
