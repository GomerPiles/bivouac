//go:build !windows

package crosvm

import (
	"context"
	"errors"
)

func RunSupervisor(context.Context, string) error {
	return errors.New("crosvm supervisor requires Windows")
}
