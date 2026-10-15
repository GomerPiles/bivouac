//go:build !unix

package tart

import "os/exec"

func detach(*exec.Cmd) {}
