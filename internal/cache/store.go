// Package cache provides bounded, opaque object storage and guest adapters.
// It never extracts archives or persists URLs, credentials, or cache keys.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type entry struct {
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
type flight struct {
	done chan struct{}
	err  error
}

// maxEntries bounds object metadata, including in-flight fills.
const maxEntries = 4096

// Store bounds committed bytes plus reserved in-flight fills. Objects are
// immutable; a checksum is checked on every open, including after restart,
// except by readers of the fill that just hashed those bytes.
type Store struct {
	mu                                  sync.Mutex
	dir                                 string
	maxBytes, maxObject, used, reserved int64
	entries                             map[string]entry
	readers                             map[string]int
	flights                             map[string]*flight
}

func Open(dir string, maxBytes, maxObject int64) (*Store, error) {
	if maxObject <= 0 || maxBytes < maxObject {
		return nil, errors.New("invalid cache limits")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("cache directory must be a real directory")
	}
	s := &Store{dir: dir, maxBytes: maxBytes, maxObject: maxObject, entries: map[string]entry{}, readers: map[string]int{}, flights: map[string]*flight{}}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		name := file.Name()
		if file.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink in cache directory")
		}
		if len(name) == 69 && name[64:] == ".json" {
			id := name[:64]
			if !digestString(id) {
				continue
			}
			data, e := os.ReadFile(filepath.Join(dir, name))
			var record entry
			if e == nil {
				e = json.Unmarshal(data, &record)
			}
			fi, fe := os.Stat(s.path(id))
			if e == nil && fe == nil && fi.Mode().IsRegular() && record.Size == fi.Size() && record.Size >= 0 && record.Size <= maxObject && digestString(record.Digest) {
				s.entries[id] = record
				s.used += record.Size
			} else {
				_ = os.Remove(s.path(id))
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}
	// Interrupted fills and objects without a committed descriptor are expendable.
	for _, file := range files {
		name := file.Name()
		if len(name) == 64 && digestString(name) {
			if _, ok := s.entries[name]; !ok {
				_ = os.Remove(s.path(name))
			}
		}
		if len(name) > 5 && name[:5] == "fill-" {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	s.mu.Lock()
	err = s.makeRoom(0, 0)
	s.mu.Unlock()
	return s, err
}

func digestString(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func (s *Store) path(id string) string { return filepath.Join(s.dir, id) }
func identity(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) remove(id string) error {
	if s.readers[id] > 0 {
		return errors.New("cache object is in use")
	}
	if err := os.Remove(s.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(s.path(id) + ".json")
	s.used -= s.entries[id].Size
	delete(s.entries, id)
	return nil
}

// makeRoom evicts idle objects by last use until n more bytes and slots more
// metadata entries fit. It evicts nothing when even that cannot make room.
func (s *Store) makeRoom(n int64, slots int) error {
	fits := func() bool {
		return s.used+s.reserved+n <= s.maxBytes && len(s.entries)+len(s.flights)+slots <= maxEntries
	}
	if fits() {
		return nil
	}
	type age struct {
		id string
		at time.Time
	}
	var ages []age
	var idle int64
	for id, e := range s.entries {
		if s.readers[id] > 0 {
			continue
		}
		var at time.Time // A missing file is evicted first.
		if info, err := os.Stat(s.path(id)); err == nil {
			at = info.ModTime()
		}
		ages = append(ages, age{id, at})
		idle += e.Size
	}
	if s.used-idle+s.reserved+n > s.maxBytes || len(s.entries)-len(ages)+len(s.flights)+slots > maxEntries {
		return errors.New("cache capacity unavailable")
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].at.Before(ages[j].at) })
	for _, a := range ages {
		if fits() {
			break
		}
		_ = s.remove(a.id)
	}
	if !fits() {
		return errors.New("cache capacity unavailable")
	}
	return nil
}

// verify opens a pinned object outside the store lock. The caller holds a
// reader count, so eviction cannot remove the file or reuse its budget.
// trusted skips the checksum for bytes this process just hashed during a fill.
func (s *Store) verify(id string, record entry, size int64, trusted bool) (*Object, error) {
	f, err := os.Open(s.path(id))
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.Size || record.Size != size {
		_ = f.Close()
		return nil, errors.New("cache object corrupt")
	}
	if !trusted {
		hash := sha256.New()
		n, err := io.Copy(hash, f)
		if err != nil || n != record.Size || hex.EncodeToString(hash.Sum(nil)) != record.Digest {
			_ = f.Close()
			return nil, errors.New("cache object corrupt")
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	now := time.Now()
	_ = os.Chtimes(s.path(id), now, now)
	return &Object{File: f, store: s, id: id}, nil
}

// unpin drops a reader count taken for an object that failed verification.
// The last holder discards the object; it reports whether the entry is gone.
func (s *Store) unpin(id string, record entry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readers[id]--
	if s.readers[id] > 0 {
		return false
	}
	delete(s.readers, id)
	if current, ok := s.entries[id]; ok && current == record {
		return s.remove(id) == nil
	}
	return true
}

// Object pins its disk reservation until the reader closes it. Eviction cannot
// hide live Unix inodes from accounting or depend on Windows unlink behavior.
type Object struct {
	*os.File
	store    *Store
	id       string
	once     sync.Once
	closeErr error
}

func (o *Object) Close() error {
	o.once.Do(func() {
		o.closeErr = o.File.Close()
		o.store.mu.Lock()
		o.store.readers[o.id]--
		if o.store.readers[o.id] == 0 {
			delete(o.store.readers, o.id)
		}
		o.store.mu.Unlock()
	})
	return o.closeErr
}

// Get returns an open immutable object of exactly size bytes. fetch runs once
// per concurrent key. A fill reserves only size; unknown (negative) or
// oversized objects are refused. Checksums are verified outside the store lock.
func (s *Store) Get(ctx context.Context, key string, size int64, fetch func(context.Context, io.Writer) error) (*Object, bool, error) {
	if size < 0 || size > s.maxObject {
		return nil, false, errors.New("cache object size unsupported")
	}
	id := identity(key)
	// Coalesced waiters read bytes that the fill they waited for just hashed.
	trusted := false
	for {
		s.mu.Lock()
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, false, err
		}
		if record, ok := s.entries[id]; ok {
			s.readers[id]++
			s.mu.Unlock()
			if f, err := s.verify(id, record, size, trusted); err == nil {
				return f, true, nil
			}
			if !s.unpin(id, record) {
				return nil, false, errors.New("corrupt cache object is still in use")
			}
			trusted = false
			continue
		}
		if pending, ok := s.flights[id]; ok {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-pending.done:
			}
			if pending.err != nil {
				return nil, false, pending.err
			}
			trusted = true
			continue
		}
		if err := s.makeRoom(size, 1); err != nil {
			s.mu.Unlock()
			return nil, false, err
		}
		pending := &flight{done: make(chan struct{})}
		s.flights[id] = pending
		s.reserved += size
		s.mu.Unlock()
		record, err := s.fill(ctx, id, size, fetch)
		s.mu.Lock()
		s.reserved -= size
		if err == nil {
			s.entries[id] = record
			s.used += record.Size
			s.readers[id]++ // Pinned before eviction can see the new entry.
		}
		pending.err = err
		delete(s.flights, id)
		close(pending.done)
		s.mu.Unlock()
		if err != nil {
			return nil, false, err
		}
		f, err := s.verify(id, record, size, true)
		if err != nil {
			s.unpin(id, record)
			return nil, false, err
		}
		return f, false, nil
	}
}

type limitedWriter struct {
	w    io.Writer
	left int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, errors.New("cache object exceeds its declared size")
	}
	n, e := w.w.Write(p)
	w.left -= int64(n)
	return n, e
}

func (s *Store) fill(ctx context.Context, id string, size int64, fetch func(context.Context, io.Writer) error) (entry, error) {
	f, err := os.CreateTemp(s.dir, "fill-")
	if err != nil {
		return entry{}, err
	}
	temp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(temp) }()
	hash := sha256.New()
	writer := &limitedWriter{w: io.MultiWriter(f, hash), left: size}
	if err = fetch(ctx, writer); err != nil {
		return entry{}, err
	}
	if writer.left != 0 {
		return entry{}, errors.New("cache object is shorter than its declared size")
	}
	record := entry{Size: size, Digest: hex.EncodeToString(hash.Sum(nil))}
	if err = f.Sync(); err != nil {
		return entry{}, err
	}
	if err = f.Close(); err != nil {
		return entry{}, err
	}
	if err = os.Rename(temp, s.path(id)); err != nil {
		return entry{}, err
	}
	data, err := json.Marshal(record)
	if err == nil {
		err = os.WriteFile(s.path(id)+".json", data, 0o600)
	}
	if err != nil {
		_ = os.Remove(s.path(id))
		return entry{}, err
	}
	return record, nil
}
