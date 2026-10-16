//go:build !unix

package tart

import (
	"errors"
	"os/exec"
)

func detach(*exec.Cmd) {}

func terminate(int, bool) error { return errors.New("VM helpers run only on macOS") }
