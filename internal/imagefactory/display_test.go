package imagefactory

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/winguest"
)

func TestDisplayConfig(t *testing.T) {
	for _, mode := range []winguest.DisplayMode{"", winguest.DisplayVDD, winguest.DisplaySynthetic} {
		t.Run(string(mode), func(t *testing.T) {
			c := testConfig()
			c.Display = mode
			if mode == winguest.DisplaySynthetic {
				c.SetupAssets = c.SetupAssets[:3]
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(c)
			decoded, err := DecodeConfig(strings.NewReader(string(b)))
			expected := mode
			if expected == "" {
				expected = winguest.DisplayVDD
			}
			if err != nil || decoded.Display != expected {
				t.Fatal("decoded display", err)
			}
			for index := range c.SetupAssets {
				bad := c
				bad.SetupAssets = append([]Asset(nil), c.SetupAssets[:index]...)
				bad.SetupAssets = append(bad.SetupAssets, c.SetupAssets[index+1:]...)
				if bad.Validate() == nil {
					t.Fatal("missing required asset accepted")
				}
			}
			if mode == winguest.DisplaySynthetic {
				for _, asset := range testConfig().SetupAssets[3:] {
					bad := c
					bad.SetupAssets = append(append([]Asset(nil), c.SetupAssets...), asset)
					if bad.Validate() == nil {
						t.Fatal("display tool accepted")
					}
				}
			}
		})
	}
	c := testConfig()
	c.Display = "guest-private-output"
	if err := c.Validate(); err == nil || strings.Contains(err.Error(), string(c.Display)) {
		t.Fatal("unknown display")
	}
	b, _ := json.Marshal(c)
	if _, err := DecodeConfig(strings.NewReader(string(b))); err == nil {
		t.Fatal("unknown display decoded")
	}
}
