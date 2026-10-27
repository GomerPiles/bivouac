package vzbuild

import (
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
	"testing"
)

func TestOptionsDefaultsAndBounds(t *testing.T) {
	var o Options
	r, disk, err := o.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != r.DefaultBaseline || o.Recipe != r.Name || disk != 64*vzrecipe.GiB || o.CPU != 4 || o.MemoryGB != 4 {
		t.Fatal("recipe defaults differ")
	}
	for _, kind := range []string{"recipe", "name", "disk-low", "disk-high", "cpu", "memory"} {
		c := Options{}
		switch kind {
		case "recipe":
			c.Recipe = "unknown"
		case "name":
			c.Name = "bivouac-target"
		case "disk-low":
			c.DiskGB = 15
		case "disk-high":
			c.DiskGB = 513
		case "cpu":
			c.CPU = -1
		case "memory":
			c.MemoryGB = 1025
		}
		if _, _, err := c.prepare(); err == nil {
			t.Fatal("invalid options accepted", kind)
		}
	}
}
