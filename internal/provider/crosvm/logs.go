package crosvm

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// The guest can make Crosvm write serial.log directly and influence its
// native.log output. The supervisor retires the guest once either log reaches
// logLimit. Admission reserves logReserve per instance: both logs at the limit
// plus as much again for output written within one supervisor poll interval.
const (
	logLimit   = 64 << 20
	logReserve = 4 * logLimit
)

// cappedWriter forwards at most limit bytes and silently drains the rest, so a
// full log never blocks the native pipes. Exceeded tells the supervisor to
// retire the guest. It is safe for concurrent writers.
type cappedWriter struct {
	mu       sync.Mutex
	w        io.Writer
	limit    int64
	written  int64
	exceeded bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.written
	if int64(len(p)) > room {
		c.exceeded = true
		if room <= 0 {
			return len(p), nil
		}
		n, err := c.w.Write(p[:room])
		c.written += int64(n)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	n, err := c.w.Write(p)
	c.written += int64(n)
	return n, err
}

func (c *cappedWriter) Exceeded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exceeded
}

// logLimitReached reports whether the guest exhausted its log allowance. Both
// logs share the native writer's limit; an unreadable serial log counts as full.
func logLimitReached(directory string, native *cappedWriter) bool {
	if native.Exceeded() {
		return true
	}
	info, err := os.Stat(filepath.Join(directory, "serial.log"))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	return err != nil || info.Size() >= native.limit
}
