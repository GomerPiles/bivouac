//go:build !unix

package vz

import (
	"errors"
	"os/exec"
)

func detach(*exec.Cmd) {}

func terminate(int, bool) error { return errors.New("VM helpers run only on macOS") }
