package vzbuild

import (
	"errors"

	"github.com/GomerPiles/bivouac/internal/config"
	"github.com/GomerPiles/bivouac/internal/paths"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

// Options contain no arbitrary VM launch arguments or guest commands.
type Options struct {
	Layout                paths.Layout
	Recipe, Name, Helper  string
	Image, RunnerArchive  string
	DiskGB, CPU, MemoryGB int
	Replace               bool
	Network               config.VZNetwork
}

func (o *Options) prepare() (vzrecipe.Recipe, int64, error) {
	if o.Recipe == "" {
		o.Recipe = vzrecipe.DefaultName
	}
	r, err := vzrecipe.Lookup(o.Recipe)
	if err != nil {
		return r, 0, err
	}
	if o.Name == "" {
		o.Name = r.DefaultBaseline
	}
	if err := validTarget(o.Name); err != nil {
		return r, 0, err
	}
	if o.DiskGB == 0 {
		o.DiskGB = r.DiskGB
	}
	if o.CPU == 0 {
		o.CPU = r.CPU
	}
	if o.MemoryGB == 0 {
		o.MemoryGB = r.MemoryGB
	}
	if o.CPU < 1 || o.CPU > 1024 || o.MemoryGB < 1 || o.MemoryGB > 1024 {
		return r, 0, errors.New("build CPU and memory must be 1..1024")
	}
	if err := o.Network.Validate(); err != nil {
		return r, 0, err
	}
	o.Network = o.Network.WithDefaults()
	disk, err := vzrecipe.DiskBytes(o.DiskGB)
	return r, disk, err
}
