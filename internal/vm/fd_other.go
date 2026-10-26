//go:build !darwin

package vm

func EnsureNetworkFDs(int) error { return ErrUnsupported }
