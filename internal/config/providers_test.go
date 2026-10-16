package config

import (
	"fmt"
	"testing"
)

func TestCrossProviderRules(t *testing.T) {
	second := func(name, scaleset string, foreign int) string {
		return Example + fmt.Sprintf("\n[providers.%s]\ntype = \"vz\"\nscaleset = %q\n\n[providers.%s.vz]\nbaseline = \"ci-macos\"\nforeign_slots = %d\n", name, scaleset, name, foreign)
	}
	if _, err := Parse([]byte(second("studio", "bivouac-studio", 1))); err != nil {
		t.Fatalf("valid second vz provider: %v", err)
	}
	cases := map[string]string{
		"duplicate scaleset":   second("studio", "bivouac-MACOS-experimental", 1),
		"prefix provider name": second("macos-gpu", "bivouac-macos-gpu", 1),
		"host limit mismatch":  second("studio", "bivouac-studio", 0),
	}
	for name, text := range cases {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
