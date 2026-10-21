//go:build !windows

package imagefactory

import (
	"context"
	"errors"
	"io"
	"log/slog"
)

func RequireElevated() error            { return errors.New("image factory requires Windows") }
func LoadConfig(string) (Config, error) { return Config{}, RequireElevated() }
func Build(context.Context, Config, *slog.Logger) (Manifest, error) {
	return Manifest{}, RequireElevated()
}
func Cleanup(context.Context, Config, string) error                  { return RequireElevated() }
func Inspect(context.Context, Config, *slog.Logger, io.Writer) error { return RequireElevated() }
