package vm

import (
	"io"
	"sync"
	"time"

	"github.com/GomerPiles/bivouac/internal/rootnet"
)

// cappedLog bounds each disposable helper's launch log, including status and
// numeric child reports. Suppression never turns logging into a VM failure.
type cappedLog struct {
	mu       sync.Mutex
	out      io.Writer
	left     int
	reserved int
}

func (w *cappedLog) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	count := len(b)
	if len(b) > w.left {
		b = b[:w.left]
	}
	if len(b) > 0 {
		n, err := w.out.Write(b)
		w.left -= n
		if err != nil {
			return n, err
		}
	}
	return count, nil
}

// terminal consumes reserved space only at helper exit. Ordinary counter output
// cannot exhaust this budget, and the total remains within the original cap.
func (w *cappedLog) terminal(b []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// The ordinary cap may have cut the preceding JSON line in the middle.
	b = append([]byte{'\n'}, b...)
	available := w.left + w.reserved
	if len(b) > available {
		b = b[:available]
	}
	_, _ = w.out.Write(b)
	w.left, w.reserved = 0, 0
}

// Retain the last emitted snapshot so changes during a rate-limited interval
// are still emitted when a later report arrives.
type counterLogState struct {
	last rootnet.Snapshot
	at   time.Time
}

func (s *counterLogState) due(now time.Time, current rootnet.Snapshot) bool {
	if current == s.last || !s.at.IsZero() && now.Sub(s.at) < time.Minute {
		return false
	}
	s.last, s.at = current, now
	return true
}
