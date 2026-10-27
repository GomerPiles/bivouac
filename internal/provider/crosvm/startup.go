package crosvm

import (
	"context"
	"log/slog"
	"time"
)

type guestCommands interface {
	Output(context.Context, string, []string) ([]byte, error)
	OutputLimit(context.Context, string, []string, int) ([]byte, error)
	Input(context.Context, string, []string, []byte) ([]byte, error)
}

func logStartup(name, stage string, started time.Time, err error, attrs ...any) {
	fields := []any{"instance", name, "stage", stage, "duration_ms", time.Since(started).Milliseconds(), "success", err == nil}
	slog.Info("linux startup stage", append(fields, attrs...)...)
}
