//go:build windows

package guestagent

import (
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

const agentLogLimit int64 = 1 << 20 // Current file plus one rotation, 2 MiB total.

// agentLog is used only by the agent's fixed-category slog calls, never by
// command streams or raw native errors. It owns no unbounded buffer.
type agentLog struct {
	mu     sync.Mutex
	dir    *guestDir
	file   *os.File
	size   int64
	closed bool
}

func newAgentLog(dir *guestDir) (*agentLog, error) {
	f, err := dir.open("agent.log", windows.GENERIC_WRITE, windows.OPEN_ALWAYS, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
	if err != nil {
		return nil, err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	l := &agentLog{dir: dir, file: f, size: size}
	if size > agentLogLimit {
		// Never rotate an oversized preexisting file into an oversized archive.
		if err := f.Truncate(0); err != nil {
			_ = l.Close()
			return nil, err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = l.Close()
			return nil, err
		}
		l.size = 0
	}
	return l, nil
}

func (l *agentLog) rotate() error {
	if err := l.file.Close(); err != nil {
		return err
	}
	if _, err := l.dir.absentOrRegular("agent.log.1"); err != nil {
		return err
	}
	root, err := os.OpenRoot(l.dir.path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Rename("agent.log", "agent.log.1"); err != nil {
		return err
	}
	l.file, err = l.dir.open("agent.log", windows.GENERIC_WRITE, windows.CREATE_NEW, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
	l.size = 0
	return err
}

func (l *agentLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, os.ErrClosed
	}
	if int64(len(p)) > agentLogLimit {
		return 0, errors.New("agent log record too large")
	}
	if l.size+int64(len(p)) > agentLogLimit {
		if err := l.rotate(); err != nil {
			l.closed = true
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *agentLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
