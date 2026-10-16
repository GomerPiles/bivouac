// Package cache provides bounded, opaque object storage and guest adapters.
// It never extracts archives or persists URLs, credentials, or cache keys.
package cache

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	log                                 *slog.Logger
	labelKey                            []byte
	diagnostics                         StoreDiagnostics
	dir                                 string
	maxBytes, maxObject, used, reserved int64
	entries                             map[string]entry
	readers                             map[string]int
	flights                             map[string]*flight
}

func Open(dir string, maxBytes, maxObject int64, logger *slog.Logger) (*Store, error) {
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
	labelKey := make([]byte, 32)
	_, _ = rand.Read(labelKey)
	s := &Store{log: logger, labelKey: labelKey, dir: dir, maxBytes: maxBytes, maxObject: maxObject, entries: map[string]entry{}, readers: map[string]int{}, flights: map[string]*flight{}}
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
				if os.Remove(s.path(id)) == nil {
					s.diagnostics.StartupDiscardedFiles++
				}
				if os.Remove(filepath.Join(dir, name)) == nil {
					s.diagnostics.StartupDiscardedFiles++
				}
			}
		}
	}
	// Interrupted fills and objects without a committed descriptor are expendable.
	for _, file := range files {
		name := file.Name()
		if len(name) == 64 && digestString(name) {
			if _, ok := s.entries[name]; !ok {
				if os.Remove(s.path(name)) == nil {
					s.diagnostics.StartupDiscardedFiles++
				}
			}
		}
		if len(name) > 5 && name[:5] == "fill-" {
			if os.Remove(filepath.Join(dir, name)) == nil {
				s.diagnostics.StartupDiscardedFiles++
			}
		}
	}
	s.mu.Lock()
	err = s.makeRoom(0, 0)
	s.mu.Unlock()
	logger.Info("cache store opened", "objects", len(s.entries), "stored_bytes", s.used, "max_bytes", maxBytes, "max_object_bytes", maxObject, "startup_discarded_files", s.diagnostics.StartupDiscardedFiles)
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

// label names an object in logs. The per-session key lets one session's events
// be correlated without letting a reader confirm a guessed URL or asset.
func (s *Store) label(key string) string { return s.labelID(identity(key)) }

func (s *Store) labelID(id string) string {
	mac := hmac.New(sha256.New, s.labelKey)
	_, _ = mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil)[:6])
}

func identity(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) remove(id, reason string) error {
	if s.readers[id] > 0 {
		return errors.New("cache object is in use")
	}
	if err := os.Remove(s.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(s.path(id) + ".json")
	size := s.entries[id].Size
	s.used -= size
	if reason == "capacity" {
		s.diagnostics.Evictions++
		s.diagnostics.EvictedBytes += uint64(size) // #nosec G115 -- Only admitted entries with nonnegative sizes reach removal.
	} else {
		s.diagnostics.Invalidations++
	}
	s.log.Info("cache object discarded", "object", s.labelID(id), "reason", reason, "bytes", size)
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
		return failure("capacity")
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].at.Before(ages[j].at) })
	for _, a := range ages {
		if fits() {
			break
		}
		_ = s.remove(a.id, "capacity")
	}
	if !fits() {
		return failure("capacity")
	}
	return nil
}

// verify opens a pinned object outside the store lock. The caller holds a
// reader count, so eviction cannot remove the file or reuse its budget.
// trusted skips the checksum for bytes this process just hashed during a fill.
func (s *Store) verify(id string, record entry, size int64, trusted bool) (*Object, error) {
	f, err := os.Open(s.path(id))
	if err != nil {
		return nil, failure("store_open")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.Size || record.Size != size {
		_ = f.Close()
		return nil, failure("store_integrity")
	}
	if !trusted {
		hash := sha256.New()
		n, err := io.Copy(hash, f)
		if err != nil || n != record.Size || hex.EncodeToString(hash.Sum(nil)) != record.Digest {
			_ = f.Close()
			return nil, failure("store_integrity")
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, failure("store_read")
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
		return s.remove(id, "invalid") == nil
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
		return nil, false, failure("object_limit")
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
			} else {
				reason, _ := failureDetails(err)
				s.log.Warn("cache object validation failed", "object", s.labelID(id), "reason", reason, "bytes", record.Size)
			}
			if !s.unpin(id, record) {
				return nil, false, failure("invalid_object_in_use")
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
		return 0, failure("length_mismatch")
	}
	n, e := w.w.Write(p)
	w.left -= int64(n)
	if e != nil {
		return n, failure("store_write")
	}
	return n, nil
}

func (s *Store) fill(ctx context.Context, id string, size int64, fetch func(context.Context, io.Writer) error) (entry, error) {
	f, err := os.CreateTemp(s.dir, "fill-")
	if err != nil {
		return entry{}, failure("store_create")
	}
	temp := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(temp) }()
	hash := sha256.New()
	writer := &limitedWriter{w: io.MultiWriter(f, hash), left: size}
	if err = fetch(ctx, writer); err != nil {
		return entry{}, err
	}
	if writer.left != 0 {
		return entry{}, failure("length_mismatch")
	}
	record := entry{Size: size, Digest: hex.EncodeToString(hash.Sum(nil))}
	if err = f.Sync(); err != nil {
		return entry{}, failure("store_sync")
	}
	if err = f.Close(); err != nil {
		return entry{}, failure("store_close")
	}
	if err = os.Rename(temp, s.path(id)); err != nil {
		return entry{}, failure("store_commit")
	}
	data, err := json.Marshal(record)
	if err == nil {
		err = os.WriteFile(s.path(id)+".json", data, 0o600)
	}
	if err != nil {
		_ = os.Remove(s.path(id))
		return entry{}, failure("store_commit")
	}
	return record, nil
}

// stage reserves capacity for bytes written outside a fill, such as a relayed
// upload whose identity is known only once upstream commits it. Staged files
// use the fill prefix, so startup discards any that an interruption leaves.
type stage struct {
	store *Store
	bytes int64
}

func (s *Store) newStage() *stage { return &stage{store: s} }

func (s *Store) stageFile() (*os.File, error) { return os.CreateTemp(s.dir, "fill-") }

// grow reserves n more bytes, evicting idle objects by last use as needed.
func (st *stage) grow(n int64) error {
	s := st.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || st.bytes+n > s.maxObject {
		return failure("object_limit")
	}
	if err := s.makeRoom(n, 0); err != nil {
		return err
	}
	s.reserved += n
	st.bytes += n
	return nil
}

func (st *stage) shrink(n int64) {
	st.store.mu.Lock()
	defer st.store.mu.Unlock()
	st.store.reserved -= n
	st.bytes -= n
}

// commit stores exactly the staged byte count that write produces under key and
// hands the reservation to the new entry. write may delete staged files as it
// copies them, so disk use exceeds the reservation by at most one staged file.
// present reports that key is already stored or filling; nothing is written.
func (st *stage) commit(ctx context.Context, key string, write func(context.Context, io.Writer) error) (present bool, err error) {
	s := st.store
	id := identity(key)
	s.mu.Lock()
	size := st.bytes
	release := func() { s.reserved -= size; st.bytes = 0 }
	if _, ok := s.entries[id]; ok || s.flights[id] != nil {
		release()
		s.mu.Unlock()
		return true, nil
	}
	if err = s.makeRoom(0, 1); err != nil {
		release()
		s.mu.Unlock()
		return false, err
	}
	pending := &flight{done: make(chan struct{})}
	s.flights[id] = pending
	s.mu.Unlock()
	record, err := s.fill(ctx, id, size, write)
	s.mu.Lock()
	release()
	if err == nil {
		s.entries[id] = record
		s.used += record.Size
	}
	pending.err = err
	delete(s.flights, id)
	close(pending.done)
	s.mu.Unlock()
	return false, err
}

// StoreDiagnostics counts local losses without retaining object identifiers.
type StoreDiagnostics struct {
	Evictions             uint64 `json:"evictions"`
	EvictedBytes          uint64 `json:"evicted_bytes"`
	Invalidations         uint64 `json:"invalidations"`
	StartupDiscardedFiles uint64 `json:"startup_discarded_files"`
}

func (s *Store) Diagnostics() StoreDiagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.diagnostics
}
