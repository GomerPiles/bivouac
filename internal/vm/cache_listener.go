package vm

import (
	"errors"
	"github.com/GomerPiles/bivouac/internal/cachelink"
	"net"
	"os"
)

// ListenCache is called only while the controller owns its state lock and has
// proved this VM's record, marker and live isolated helper. A remaining socket
// then belongs to a crashed attachment. Refuse non-sockets and symlinks.
func (s Store) ListenCache(name string, kind cachelink.Kind) (net.Listener, error) {
	if validName(name) != nil {
		return nil, errors.New("invalid cache owner")
	}
	var path string
	var err error
	switch kind {
	case cachelink.Payload:
		path, err = s.CacheSocketPath(name)
	case cachelink.Revocation:
		path, err = s.RevocationSocketPath(name)
	default:
		return nil, errors.New("invalid cache capability kind")
	}
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("cache socket ownership unavailable")
		}
		if os.Remove(path) != nil {
			return nil, errors.New("remove stale cache capability")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cache socket unavailable")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("listen for private cache capability")
	}
	if os.Chmod(path, 0600) != nil {
		_ = listener.Close()
		return nil, errors.New("protect cache capability")
	}
	return listener, nil
}
