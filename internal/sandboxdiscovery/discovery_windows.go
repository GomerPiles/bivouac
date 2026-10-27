//go:build windows

package sandboxdiscovery

import (
	"context"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
)

// Discover only enumerates Sandbox-owned metadata. No VM is opened, created,
// adopted, modified or stopped; the native Sandbox owner label is not bivouac's.
func Discover(ctx context.Context) ([]Candidate, error) {
	step, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	api, err := hcs.Load()
	if err != nil {
		return nil, err
	}
	properties, err := api.EnumerateOwner(step, "WindowsSandbox")
	if err != nil {
		return nil, err
	}
	return candidates(properties)
}
