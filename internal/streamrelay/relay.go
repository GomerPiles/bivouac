// Package streamrelay joins owned streams while preserving TCP half-closes.
package streamrelay

import (
	"io"
	"net"
)

// Copy waits for both directions. EOF closes only the destination's write half;
// an error closes both streams to unblock the other direction. The caller owns
// cancellation and final closure. Non-half-close streams require full closure
// on EOF because they cannot otherwise signal it to their peer.
func Copy(a, b net.Conn) {
	done := make(chan struct{})
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if w, ok := dst.(interface{ CloseWrite() error }); ok {
				err = w.CloseWrite()
			} else {
				err = dst.Close()
			}
		}
		if err != nil {
			_ = a.Close()
			_ = b.Close()
		}
	}
	go func() { defer close(done); copyOne(a, b) }()
	copyOne(b, a)
	<-done
}
