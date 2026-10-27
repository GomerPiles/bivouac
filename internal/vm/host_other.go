//go:build !darwin

package vm

import (
	"context"
	"errors"
	"io"

	"github.com/GomerPiles/bivouac/internal/config"
)

// Clone is unavailable off macOS.
func (Store) Clone(string, string, CloneOptions) error { return ErrUnsupported }

// Import is unavailable off macOS.
func (Store) Import(string, string, Guest) error { return ErrUnsupported }

// List is unavailable off macOS.
func (Store) List() ([]Entry, error) { return nil, ErrUnsupported }

// Delete is unavailable off macOS.
func (Store) Delete(string) error { return ErrUnsupported }

// Holder is unavailable off macOS.
func Holder(string) (int, error) { return 0, ErrUnsupported }

// RunHelper is unavailable off macOS.
func RunHelper(context.Context, RunOptions, io.Writer) error { return ErrUnsupported }

// CheckEntitlement is unavailable off macOS.
func CheckEntitlement(context.Context, string) error { return ErrUnsupported }

// NestedVirtualizationSupported is false off macOS.
func NestedVirtualizationSupported() (bool, error) { return false, ErrUnsupported }

// ErrForeignHolder reports a VM lock held by something other than its helper.
var ErrForeignHolder = errors.New("VM is held by a process that is not its bivouac helper")

// HelperPID is unavailable off macOS.
func HelperPID(string) (int, error) { return 0, ErrUnsupported }

func ProveIsolation(string, string) error { return ErrUnsupported }

func RunNetwork(context.Context, string, config.VZNetwork) error { return ErrUnsupported }

func NetworkChildPID(string) (int, error) { return 0, ErrUnsupported }

func CreateEFIStore(string) error { return ErrUnsupported }

func (Store) CloneFactory(string, string) error { return ErrUnsupported }
