package crosvm

import (
	"encoding/hex"
	"errors"
	"strings"
)

// The fixed kernel launch disables predictable naming: the isolated virtio
// uplink is eth0. Do not configure Docker bridges or loopback profiles.
func uplinkProfile(data []byte) (string, error) {
	if len(data) > 65536 {
		return "", errors.New("guest network profile inventory exceeds bound")
	}
	profile := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		id, device, ok := strings.Cut(line, ":")
		if !ok {
			return "", errors.New("invalid guest network profile inventory")
		}
		if device != "eth0" {
			continue
		}
		if profile != "" || len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			return "", errors.New("ambiguous or invalid guest uplink profile")
		}
		decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(decoded) != 16 {
			return "", errors.New("invalid guest uplink UUID")
		}
		profile = id
	}
	if profile == "" {
		return "", errors.New("active generic eth0 profile is missing")
	}
	return profile, nil
}
