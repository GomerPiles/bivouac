package config

import (
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func TestLinuxVZDefaultResolutionAgreesWithHostAndGuestRecipe(t *testing.T) {
	c := linuxVZConfig(t)
	c.Providers["macos"].VZ.Baseline = ""
	c.applyDefaults()
	r, err := vzrecipe.Lookup(linuxguest.ProvisionRecipeName)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Providers["macos"].VZ.Baseline; got != r.DefaultBaseline || got != r.Name {
		t.Fatalf("default = %q", got)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Providers["macos"].VZ.Baseline = "custom-linux"
	c.applyDefaults()
	if c.Providers["macos"].VZ.Baseline != "custom-linux" {
		t.Fatal("explicit baseline changed")
	}
	darwin, err := Parse([]byte(strings.Replace(Example, `baseline = "ci-macos"`, "", 1)))
	if err == nil || darwin != nil {
		t.Fatal("Darwin accepted a missing baseline", err)
	}
}
