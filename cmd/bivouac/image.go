package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/imagefactory"
	"github.com/GomerPiles/bivouac/internal/redact"
)

func imageCmd(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "build" && args[0] != "inspect" && args[0] != "cleanup") {
		return errUsage
	}
	fs := flag.NewFlagSet("image "+args[0], flag.ContinueOnError)
	config := fs.String("config", "", "administrator-protected image factory JSON")
	id := fs.String("build", "", "retained build ID (cleanup only)")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *config == "" || (args[0] != "cleanup" && *id != "") || (args[0] == "cleanup" && *id == "") {
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
		return writeImageCleanupResult(out, *id, imagefactory.Cleanup(ctx, c, *id))
	}
	log := slog.New(slog.NewTextHandler(redact.NewWriter(os.Stderr), nil))
	if args[0] == "inspect" {
		return imagefactory.Inspect(ctx, c, log, out)
	}
	m, err := imagefactory.Build(ctx, c, log)
	return writeImageResult(out, os.Stderr, m, err)
}

func writeImageCleanupResult(out io.Writer, id string, err error) error {
	var retained *imagefactory.RetainedLetterError
	if errors.As(err, &retained) {
		return errors.Join(err, json.NewEncoder(out).Encode(map[string]string{"build_id": id, "retained_letter": retained.Letter}))
	}
	return err
}

func writeImageResult(out, warnings io.Writer, m imagefactory.Manifest, buildErr error) error {
	var published *imagefactory.PublishedError
	if buildErr != nil && !errors.As(buildErr, &published) {
		return buildErr
	}
	printErr := json.NewEncoder(out).Encode(map[string]string{"build_id": m.BuildID, "image_path": m.Output, "guest_name": m.GuestName, "guest_user": m.GuestUser})
	if published != nil {
		_, warnErr := fmt.Fprintf(warnings, "warning: image is published; cleanup or recording incomplete for build %s\n", m.BuildID)
		return errors.Join(buildErr, printErr, warnErr)
	}
	return printErr
}
