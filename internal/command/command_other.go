//go:build !windows

package command

import "os/exec"

func hideWindow(*exec.Cmd) {}
