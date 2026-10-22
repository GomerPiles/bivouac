//go:build !windows

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/state"
)

func buildHCSProvider(string, config.HCS, *state.Store, *slog.Logger) (provider.Provider, error) {
	return nil, errors.New("hcs guests run only on Windows hosts")
}

func checkVMHost(context.Context, config.HCS) error {
	return errors.New("hcs guests run only on Windows hosts")
}

func (e env) printHCSOff() {}
