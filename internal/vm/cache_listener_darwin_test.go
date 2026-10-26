package vm

import (
	"github.com/GomerPiles/bivouac/internal/cachelink"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheSocketIsPrivateDistinctAndRejectsNonSockets(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "biv-cache-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	store := Store(dir)
	if os.Mkdir(filepath.Join(dir, runDir), 0700) != nil {
		t.Fatal("private runtime directory unavailable")
	}
	const name = "bivouac-macos-cache-fixture"
	path, err := store.CacheSocketPath(name)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := store.SocketPath(name)
	if err != nil || path == agent || len(path) != len(agent) {
		t.Fatal("cache capability aliases agent or changes path budget")
	}
	listener, err := store.ListenCache(name, cachelink.Payload)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatal("cache listener not protected")
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = listener.Close() // emulate a crashed controller's leftover socket.
	listener, err = store.ListenCache(name, cachelink.Payload)
	if err != nil {
		t.Fatal("stale socket could not be replaced")
	}
	_ = listener.Close()
	if os.WriteFile(path, []byte("unowned"), 0600) != nil {
		t.Fatal("fixture file unavailable")
	}
	if listener, err = store.ListenCache(name, cachelink.Payload); err == nil {
		_ = listener.Close()
		t.Fatal("non-socket replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "unowned" {
		t.Fatal("unowned file altered")
	}
}
