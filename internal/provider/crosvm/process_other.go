//go:build !windows

package crosvm

import (
	"context"
	"errors"
	"os"
)

func recoverJob(context.Context, Record) error { return errors.New("native recovery requires Windows") }

func diskCapacity(string) (uint64, error) {
	return 0, errors.New("native disk admission requires Windows")
}
func terminateRecorded(ProcessIdentity) error {
	return errors.New("native crash test requires Windows")
}

func startSupervisor(string, ...string) (*os.Process, bool, error) {
	return nil, false, errors.New("native Crosvm supervisor requires Windows")
}

type ProcessIdentity struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
	Image   string `json:"image"`
}

func Identity(uint32) (ProcessIdentity, bool, error) {
	return ProcessIdentity{}, false, errors.New("native Crosvm lifecycle requires a Windows host")
}
func sameProcess(ProcessIdentity) (bool, error) {
	return false, errors.New("native Crosvm lifecycle requires a Windows host")
}
