package cache

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fill(text string) func(context.Context, io.Writer) error {
	return func(_ context.Context, w io.Writer) error { _, e := io.WriteString(w, text); return e }
}
func readObject(t *testing.T, s *Store, key string, size int64, fetch func(context.Context, io.Writer) error) bool {
	t.Helper()
	f, hit, e := s.Get(context.Background(), key, size, fetch)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = f.Close() }()
	if _, e = io.ReadAll(f); e != nil {
		t.Fatal(e)
	}
	return hit
}

func TestStoreRestartCorruptionAndEviction(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, 10, 6, slog.New(slog.DiscardHandler))
	if e != nil {
		t.Fatal(e)
	}
	if readObject(t, s, "first", 5, fill("aaaaa")) {
		t.Fatal("unexpected initial hit")
	}
	s, e = Open(dir, 10, 6, slog.New(slog.DiscardHandler))
	if e != nil {
		t.Fatal(e)
	}
	if !readObject(t, s, "first", 5, fill("bad")) {
		t.Fatal("restart lost committed object")
	}
	if e = os.WriteFile(s.path(identity("first")), []byte("other"), 0o600); e != nil {
		t.Fatal(e)
	}
	if readObject(t, s, "first", 5, fill("aaaaa")) {
		t.Fatal("corrupt object served")
	}
	readObject(t, s, "second", 6, fill("bbbbbb"))
	n, used, reserved := s.Stats()
	if n != 1 || used != 6 || reserved != 0 {
		t.Fatalf("unbounded store: %d %d %d", n, used, reserved)
	}
	if readObject(t, s, "first", 5, fill("aaaaa")) {
		t.Fatal("old object should have been evicted")
	}
}

func TestStoreConcurrentFillAndCancellation(t *testing.T) {
	s, e := Open(t.TempDir(), 100, 50, slog.New(slog.DiscardHandler))
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	fetch := func(_ context.Context, w io.Writer) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		_, err := io.WriteString(w, "payload")
		return err
	}
	var wg sync.WaitGroup
	failures := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			f, _, err := s.Get(context.Background(), "shared", 7, fetch)
			if err == nil {
				data, _ := io.ReadAll(f)
				_ = f.Close()
				if string(data) != "payload" {
					err = errors.New("wrong payload")
				}
			}
			failures <- err
		})
	}
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Get(ctx, "shared", 7, fetch); !errors.Is(err, context.Canceled) {
		t.Fatal("waiter ignored cancellation")
	}
	close(release)
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal(e)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate fills: %d", calls.Load())
	}
}

func TestStoreLimitsPinsAndInterruptedFill(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, 20, 10, slog.New(slog.DiscardHandler))
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		size int64
		data string
	}{{11, strings.Repeat("x", 11)}, {-1, "x"}, {10, strings.Repeat("x", 11)}, {7, "short"}} {
		if _, _, err := s.Get(context.Background(), "https://upstream?sig=must-not-persist", tc.size, fill(tc.data)); err == nil {
			t.Fatalf("invalid object committed: declared %d, wrote %d", tc.size, len(tc.data))
		}
	}
	if n, used, reserved := s.Stats(); n != 0 || used != 0 || reserved != 0 {
		t.Fatal("failed fill retained reservation")
	}
	f, _, err := s.Get(context.Background(), "public", 7, fill("payload"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if e = os.WriteFile(filepath.Join(dir, "fill-interrupted"), []byte("partial"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(dir, 20, 10, slog.New(slog.DiscardHandler)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "fill-interrupted")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("partial fill survived startup")
	}
	files, _ := os.ReadDir(dir)
	for _, file := range files {
		data, _ := os.ReadFile(filepath.Join(dir, file.Name()))
		if strings.Contains(string(data), "sig=") {
			t.Fatal("source URL persisted")
		}
	}
}

func TestStoreRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, strings.Repeat("a", 64))); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Open(dir, 20, 10, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("accepted symlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "private" {
		t.Fatal("foreign file changed")
	}
}

func TestActiveReaderRetainsDiskBudget(t *testing.T) {
	s, err := Open(t.TempDir(), 10, 6, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := s.Get(context.Background(), "first", 5, fill("aaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Get(context.Background(), "second", 6, fill("bbbbbb")); err == nil {
		t.Fatal("evicted an active reader's disk reservation")
	}
	if _, err = os.Stat(s.path(identity("first"))); err != nil {
		t.Fatal("active object unlinked")
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if readObject(t, s, "second", 6, fill("bbbbbb")) {
		t.Fatal("unexpected cache hit")
	}
}

func TestStoreReservesExactSizeAndEvictsOnlyWhatIsNeeded(t *testing.T) {
	s, err := Open(t.TempDir(), 20, 10, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, key := range []string{"a", "b", "c", "d"} {
		readObject(t, s, key, 5, fill(strings.Repeat(key, 5)))
		at := now.Add(time.Duration(i-4) * time.Hour)
		if err = os.Chtimes(s.path(identity(key)), at, at); err != nil {
			t.Fatal(err)
		}
	}
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		f, _, err := s.Get(context.Background(), "e", 3, func(_ context.Context, w io.Writer) error {
			close(started)
			<-release
			_, err := io.WriteString(w, "eee")
			return err
		})
		if err == nil {
			// An open object blocks TempDir cleanup on Windows.
			err = f.Close()
		}
		done <- err
	}()
	<-started
	if n, used, reserved := s.Stats(); n != 3 || used != 15 || reserved != 3 {
		t.Fatalf("small fill reserved or evicted too much: %d %d %d", n, used, reserved)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(s.path(identity("a"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("least recently used object survived")
	}
	for _, key := range []string{"b", "c", "d"} {
		if !readObject(t, s, key, 5, fill("wrong")) {
			t.Fatalf("object %s evicted unnecessarily", key)
		}
	}
}

func TestStoreEvictsNothingWhenRoomIsImpossible(t *testing.T) {
	s, err := Open(t.TempDir(), 10, 6, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := s.Get(context.Background(), "pinned", 5, fill("aaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	readObject(t, s, "idle", 1, fill("b"))
	if _, _, err = s.Get(context.Background(), "large", 6, fill("cccccc")); err == nil {
		t.Fatal("fill exceeded capacity held by an active reader")
	}
	if !readObject(t, s, "idle", 1, fill("x")) {
		t.Fatal("infeasible fill evicted an idle object")
	}
}
