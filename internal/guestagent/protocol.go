// Package guestagent runs commands inside a guest for the host. The guest
// side, `bivouac guest-agent`, listens on a vsock port; on macOS it is a
// LaunchAgent in the auto-login user's GUI (Aqua) session, so commands it
// starts can reach the window server. The host side connects through the VM
// helper's Unix socket.
//
// One connection carries one command. Every message is a frame: a type
// byte, a big-endian uint32 length, and that many bytes. The host sends a
// request and then stdin frames (an empty one is EOF); the guest sends
// stdout and stderr frames and finally an exit or failure frame. Closing the
// connection before the exit frame kills the command.
package guestagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Port is the guest agent's vsock port.
const Port uint32 = 7473

// Version is the request format; the agent refuses any other and names its
// own in the failure frame, so a host fails fast on an outdated baseline.
const Version = 1

const (
	frameRequest = 'R' // JSON request, host to guest, first frame only
	frameStdin   = 'I' // host to guest; empty means EOF
	frameStdout  = 'O'
	frameStderr  = 'E'
	frameExit    = 'X' // big-endian int32 exit code, last frame
	frameFailed  = 'F' // the command could not start, last frame
)

// maxFrame bounds a frame's payload; data frames are smaller.
const (
	maxFrame = 64 << 10
	chunk    = 32 << 10
	maxArgs  = 256
)

type request struct {
	Version int      `json:"v"`
	Argv    []string `json:"argv"`
	Stdin   bool     `json:"stdin"`
}

func (r request) validate() error {
	if r.Version != Version {
		return &VersionError{Agent: Version, Host: r.Version}
	}
	if len(r.Argv) == 0 || len(r.Argv) > maxArgs || r.Argv[0] == "" {
		return errors.New("invalid command")
	}
	return nil
}

var errFrame = errors.New("invalid guest agent frame")

// versionPrefix starts the failure payload of a refused request version.
// It is the only failure payload the host parses; any other is opaque guest
// text and never reaches host errors or logs.
const versionPrefix = "version "

// VersionError is an agent that speaks another request version than the
// host: the baseline's guest agent must be replaced, and retrying cannot help.
type VersionError struct{ Agent, Host int }

func (e *VersionError) Error() string {
	return fmt.Sprintf("guest agent speaks protocol version %d, this bivouac needs %d: install the matching bivouac guest agent in the baseline", e.Agent, e.Host)
}

// parseFailure maps a failure payload to an error, trusting only a
// well-formed version refusal.
func parseFailure(p []byte) error {
	if v, ok := strings.CutPrefix(string(p), versionPrefix); ok && len(v) <= 5 {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n != Version {
			return &VersionError{Agent: n, Host: Version}
		}
	}
	return ErrFailed
}

func writeFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > maxFrame {
		return errFrame
	}
	header := [5]byte{kind}
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload))) //nolint:gosec // Bounded by maxFrame.
	if _, err := w.Write(append(header[:], payload...)); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader, buf []byte) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n > maxFrame {
		return 0, nil, errFrame
	}
	if cap(buf) < int(n) {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return header[0], buf, nil
}
