//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
)

func inventoryISOFile(path, edition string, index uint32) (MediaInventory, error) {
	f, e := openReadOnlyPinned(path)
	if e != nil {
		return MediaInventory{}, e
	}
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32<<30 {
		return MediaInventory{}, errors.New("ISO must be a regular file of at most 32 GiB")
	}
	return readISOInventory(f, info.Size(), edition, index)
}

// Inspect hashes and inventories one immutable handle. It creates no native
// object, workspace, disk, or mount and never calls HCS.
func Inspect(ctx context.Context, c Config, _ *slog.Logger, out io.Writer) error {
	if out == nil {
		return errors.New("image inspect requires an output writer")
	}
	if e := c.Validate(); e != nil {
		return e
	}
	f, e := openReadOnlyPinned(c.ISO)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32<<30 {
		return errors.New("ISO must be a regular file of at most 32 GiB")
	}
	// Hash and inventory use this same deny-write/delete handle.
	digest, e := hashReader(ctx, f, 32<<30)
	if e != nil {
		return e
	}
	if !strings.EqualFold(digest, c.ISOSHA256) {
		return errors.New("ISO SHA-256 differs")
	}
	result, e := readISOInventory(f, info.Size(), c.EditionID, c.ImageIndex)
	if e != nil {
		return e
	}
	result.ISOSHA256 = digest
	return json.NewEncoder(out).Encode(result)
}
