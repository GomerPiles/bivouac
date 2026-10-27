//go:build !darwin

package vzbuild

import (
	"context"
	"github.com/GomerPiles/bivouac/internal/vm"
)

func Build(context.Context, Options) error { return vm.ErrUnsupported }
