// Package vzrecipe owns immutable public inputs for the Linux VZ image factory.
// Registry returns fresh values; config preparation uses only DefaultName.
package vzrecipe

import (
	"errors"
	"time"
)

const DefaultName = "ubuntu-24.04-arm64-vz-runner"
const GiB int64 = 1 << 30

type Input struct {
	URLs   []string
	SHA256 string
	Size   int64
}
type Recipe struct {
	Name                          string
	DefaultBaseline               string
	Source                        Input
	Runner                        Input
	DiskGB, CPU, MemoryGB         int
	ProvisionTimeout, GateTimeout time.Duration
}

func Registry() []Recipe {
	const image = "ubuntu-24.04-server-cloudimg-arm64.img"
	return []Recipe{{
		Name: DefaultName, DefaultBaseline: DefaultName,
		Source: Input{URLs: []string{
			"https://cloud-images.ubuntu.com/releases/noble/release-20261017/" + image,
			"https://cloud-images-archive.ubuntu.com/releases/noble/release-20261017/" + image,
		}, SHA256: "50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e", Size: 616522752},
		Runner: Input{URLs: []string{"https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-linux-arm64-2.338.2.tar.gz"}, SHA256: "670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945", Size: 140231317},
		DiskGB: 64, CPU: 4, MemoryGB: 4, ProvisionTimeout: 45 * time.Minute, GateTimeout: 10 * time.Minute,
	}}
}
func Lookup(name string) (Recipe, error) {
	for _, r := range Registry() {
		if r.Name == name {
			return r, nil
		}
	}
	return Recipe{}, errors.New("unknown Linux VZ baseline recipe")
}
func DiskBytes(gb int) (int64, error) {
	if gb < 16 || gb > 512 {
		return 0, errors.New("baseline disk must be 16..512 GiB")
	}
	return int64(gb) * GiB, nil
}
