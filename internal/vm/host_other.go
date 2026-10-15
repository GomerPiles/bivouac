//go:build !darwin

package vm

import (
	"context"
	"io"
)

// Clone is unavailable off macOS.
func (Home) Clone(string, string) error { return ErrUnsupported }

// Resize is unavailable off macOS.
func (Home) Resize(string, int, int) error { return ErrUnsupported }

// List is unavailable off macOS.
func (Home) List() ([]Entry, error) { return nil, ErrUnsupported }

// Delete is unavailable off macOS.
func (Home) Delete(string) error { return ErrUnsupported }

// Holder is unavailable off macOS.
func Holder(string) (int, error) { return 0, ErrUnsupported }

// RunHelper is unavailable off macOS.
func RunHelper(context.Context, RunOptions, io.Writer) error { return ErrUnsupported }

// CheckEntitlement is unavailable off macOS.
func CheckEntitlement(context.Context, string) error { return ErrUnsupported }
