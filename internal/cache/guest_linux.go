//go:build linux

package cache

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

func guestTrust(ctx context.Context, caFile string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/bin/install", "-m", "0644", caFile, "/usr/local/share/ca-certificates/bivouac-guest-cache.crt").Run() != nil ||
		exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/sbin/update-ca-certificates").Run() != nil {
		return nil, errors.New("install disposable guest proxy trust")
	}
	return os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
}
