package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/vzbuild"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func (e env) vzBuildBaseline(ctx context.Context, args []string) error {
	o := vzbuild.Options{Layout: e.layout}
	var providerName string
	fs := flag.NewFlagSet("vz build-baseline", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.Recipe, "recipe", "", "")
	fs.StringVar(&providerName, "provider", "", "")
	fs.StringVar(&o.Helper, "helper", "", "")
	fs.StringVar(&o.Image, "image", "", "")
	fs.StringVar(&o.RunnerArchive, "runner-archive", "", "")
	fs.IntVar(&o.DiskGB, "disk-gb", 0, "")
	fs.IntVar(&o.CPU, "cpu", 0, "")
	fs.IntVar(&o.MemoryGB, "memory-gb", 0, "")
	fs.BoolVar(&o.Replace, "replace", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 1 {
		return errUsage
	}
	if fs.NArg() == 1 {
		o.Name = fs.Arg(0)
	}
	if providerName != "" && o.Helper != "" {
		return errors.New("choose --provider or --helper")
	}
	if o.Helper != "" {
		// Explicit helper dispatch needs no host config or GitHub credentials.
		var err error
		o.Helper, err = filepath.Abs(o.Helper)
		if err != nil {
			return err
		}
	} else {
		cfg, err := e.loadConfig("")
		if err != nil {
			return err
		}
		if providerName == "" {
			for _, name := range cfg.ProviderNames() {
				p := cfg.Providers[name]
				if p.Type == "vz" && p.VZ != nil && p.VZ.RunnerOS() == "linux" {
					if providerName != "" {
						return errors.New("multiple Linux VZ providers; select --provider or --helper")
					}
					providerName = name
				}
			}
		}
		p, ok := cfg.Providers[providerName]
		if !ok || p.Type != "vz" || p.VZ == nil || p.VZ.RunnerOS() != "linux" {
			return errors.New("select a Linux VZ --provider or supply --helper")
		}
		o.Helper = p.VZ.Helper
		o.Network = p.VZ.Network
		if o.Name == "" {
			o.Name = p.VZ.Baseline
		}
	}
	if err := vzbuild.Build(ctx, o); err != nil {
		return err
	}
	if o.Name == "" {
		recipe := o.Recipe
		if recipe == "" {
			recipe = vzrecipe.DefaultName
		}
		r, err := vzrecipe.Lookup(recipe)
		if err != nil {
			return err
		}
		o.Name = r.DefaultBaseline
	}
	fmt.Printf("built baseline %q in %s\n", o.Name, e.layout.VMs)
	return nil
}
