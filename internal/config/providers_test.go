package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestWindowsHostProvidersParseTogether(t *testing.T) {
	text := strings.Replace(hcsExample, "max_instances = 1", "max_instances = 2", 1)
	text = strings.Replace(text, "[providers.windows]", "[providers.windows]\nscaleset = 'bivouac-windows'", 1) + `
[providers.linux]
type = "crosvm"
scaleset = "bivouac-linux"
labels = ["self-hosted", "Linux", "X64", "bivouac-linux"]
idle_pool = 1
[providers.linux.crosvm]
experimental = true
root = 'D:\Instances\Linux'
binary = 'D:\Tools\crosvm.exe'
binary_sha256 = "` + strings.Repeat("a", 64) + `"
qemu_img = 'D:\Tools\qemu-img.exe'
baseline_name = "ci-linux"
baseline = 'D:\Images\linux.raw'
kernel = 'D:\Images\vmlinuz'
kernel_sha256 = "` + strings.Repeat("b", 64) + `"
initrd = 'D:\Images\initrd.img'
initrd_sha256 = "` + strings.Repeat("c", 64) + `"
helper = 'D:\Tools\bivouac-linux-amd64'
user = "ciuser"
cpu = 4
memory_gb = 4
[cache]
enabled = true
release_proxy = true
`
	for _, demand := range []string{"jit", "scaleset"} {
		t.Run(demand, func(t *testing.T) {
			c, err := Parse([]byte(strings.Replace(text, `demand = "jit"`, `demand = "`+demand+`"`, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Providers) != 2 || c.Providers["windows"].HCS == nil || c.Providers["linux"].Crosvm == nil {
				t.Fatal("Windows host providers not decoded")
			}
			if c.Cache.Listen != "127.0.0.1:0" || c.Cache.GuestHost != "127.0.0.1" {
				t.Fatal("Windows host cache defaults changed")
			}
		})
	}
}

func TestRemovedProviderRejected(t *testing.T) {
	text := strings.Replace(hcsExample, `type = "hcs"`, `type = "appsandbox"`, 1)
	if _, err := Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), `unsupported type "appsandbox"`) {
		t.Fatalf("removed provider error = %v", err)
	}
	text = strings.Replace(hcsExample, "[providers.windows.hcs]", "[providers.windows.appsandbox]", 1)
	if _, err := Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), "unknown keys: providers.windows.appsandbox") {
		t.Fatalf("removed settings error = %v", err)
	}
}

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
