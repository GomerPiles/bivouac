package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/imagefactory"
	"github.com/GomerPiles/bivouac/internal/redact"
)

func imageCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "build" && args[0] != "cleanup") {
		return errUsage
	}
	fs := flag.NewFlagSet("image "+args[0], flag.ContinueOnError)
	config := fs.String("config", "", "administrator-protected image factory JSON")
	id := fs.String("build", "", "retained build ID (cleanup only)")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *config == "" || (args[0] == "build" && *id != "") || (args[0] == "cleanup" && *id == "") {
		return errUsage
	}
	if err := imagefactory.RequireElevated(); err != nil {
		return err
	}
	abs, err := filepath.Abs(*config)
	if err != nil {
		return err
	}
	c, err := imagefactory.LoadConfig(abs)
	if err != nil {
		return err
	}
	if args[0] == "cleanup" {
		return imagefactory.Cleanup(ctx, c, *id)
	}
	m, err := imagefactory.Build(ctx, c, slog.New(slog.NewTextHandler(redact.NewWriter(os.Stderr), nil)))
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"build_id": m.BuildID, "image_path": m.Output, "guest_name": m.GuestName, "guest_user": m.GuestUser})
}
