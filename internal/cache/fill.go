package cache

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// Fills belong to the service, not to the request that started them: a guest
// that disconnects or times out leaves its fill running, and a retry joins it.
// A fill is bounded by progress rather than total time, and after an upstream
// failure mid-transfer it resumes from the bytes it already has.

const fillResumes = 3

// resumable marks an upstream failure after which a fill may continue from its
// offset. Failures of the writer or of identity checks are final.
type resumable struct{ error }

func (e resumable) Unwrap() error { return e.error }

// download copies size bytes with identity etag from base's URL into out.
// check validates the first response before any byte is copied, so a fill that
// fails there leaves out untouched and its guest can still be sent upstream.
func (s *Service) download(base *http.Request, label string, etag string, size int64, check func(*http.Response) error, out io.Writer) error {
	// No total timeout: progress bounds each attempt instead.
	client := &http.Client{Transport: s.client.Transport, CheckRedirect: s.client.CheckRedirect}
	verified := &verifiedWriter{out: out, left: size}
	var done int64
	for resumes := 0; ; resumes++ {
		ctx, cancel := context.WithCancel(s.work)
		req := base.Clone(ctx)
		req.Header.Set("If-Match", etag)
		if done > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(done, 10)+"-")
		}
		n, err := s.attempt(client, req, cancel, etag, size, done, check, verified)
		cancel()
		done += n
		if err != nil && s.work.Err() != nil {
			return s.work.Err()
		}
		var again resumable
		if err == nil {
			return verified.finish()
		}
		if done == 0 || done >= size || resumes == fillResumes || !errors.As(err, &again) {
			return err
		}
		reason, _ := failureDetails(err)
		s.log.Info("cache fill resumed", "object", label, "reason", reason, "offset_bytes", done, "bytes", size)
	}
}

func (s *Service) attempt(client *http.Client, req *http.Request, cancel context.CancelFunc, etag string, size, offset int64, check func(*http.Response) error, out *verifiedWriter) (int64, error) {
	response, err := client.Do(req) // #nosec G704 -- callers pass a URL that passed upstream admission; the public transport refuses host networks.
	if err != nil {
		return 0, resumable{upstreamFailure(err)}
	}
	defer func() { _ = response.Body.Close() }()
	if offset == 0 {
		if err := check(response); err != nil {
			return 0, err
		}
	} else if response.StatusCode != http.StatusPartialContent || response.Header.Get("ETag") != etag ||
		response.Header.Get("Content-Range") != "bytes "+strconv.FormatInt(offset, 10)+"-"+strconv.FormatInt(size-1, 10)+"/"+strconv.FormatInt(size, 10) {
		return 0, &fault{reason: "upstream_resume", status: response.StatusCode}
	}
	body := &idleReader{r: response.Body, limit: s.fillIdle, cancel: cancel}
	n, err := io.Copy(out, body)
	if out.err != nil {
		return n, out.err // Writer failures, including an overlong body, are final.
	}
	switch {
	case err == nil && offset+n == size:
		return n, nil // Complete, even if the idle timer fired since.
	case body.idle.Load():
		return n, resumable{failure("upstream_idle")}
	case err != nil:
		return n, resumable{failure("upstream_body")}
	default: // A short body without an error.
		return n, resumable{failure("length_mismatch")}
	}
}

// verifiedWriter withholds the final byte until the attempt has read EOF with
// exactly the declared length. Overlong bodies are final writer failures;
// failed framing after the declared bytes cannot resume past the object end.
type verifiedWriter struct {
	out     io.Writer
	left    int64
	tail    [1]byte
	pending bool
	err     error // Writer failure, even when the upstream read also failed.
}

func (w *verifiedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		w.err = failure("length_mismatch")
		return 0, w.err
	}
	data := p
	if len(p) > 0 && int64(len(p)) == w.left {
		w.tail[0] = p[len(p)-1]
		w.pending = true
		data = p[:len(p)-1]
	}
	if len(data) > 0 {
		n, err := w.out.Write(data)
		if err != nil || n != len(data) {
			if err == nil {
				err = io.ErrShortWrite
			}
			w.err = err
			return n, err
		}
	}
	w.left -= int64(len(p))
	return len(p), nil
}

func (w *verifiedWriter) finish() error {
	if w.left != 0 {
		return failure("length_mismatch")
	}
	if !w.pending {
		return nil // An empty object has no tail.
	}
	n, err := w.out.Write(w.tail[:])
	if err == nil && n != 1 {
		err = io.ErrShortWrite
	}
	return err
}

// idleReader arms its bound only while waiting in an upstream Read. Stopping
// and joining a fired callback before returning keeps destination writes out
// of the idle budget, including the guest's separate write deadline.
type idleReader struct {
	r      io.Reader
	limit  time.Duration
	cancel context.CancelFunc
	idle   atomic.Bool
}

func (b *idleReader) Read(p []byte) (int, error) {
	fired := make(chan struct{})
	timer := time.AfterFunc(b.limit, func() {
		b.idle.Store(true)
		b.cancel()
		close(fired)
	})
	n, err := b.r.Read(p)
	if !timer.Stop() {
		<-fired
	}
	return n, err
}

// streamTee writes a fill to the store and, from its first byte, to the guest
// that started it, so a miss arrives like a direct download. Losing that guest
// never stops the fill, and a store failure still lets the guest finish.
type streamTee struct {
	store     io.Writer
	open      func() io.Writer // Sends the response headers.
	deadline  func()           // Bounds each write to the guest.
	flush     func() error     // Publishes each write; failures end guest delivery.
	client    io.Writer
	delivered int64 // Bytes the guest accepted.
	clientErr error
	storeErr  error
}

func (t *streamTee) Write(p []byte) (int, error) {
	if t.storeErr == nil {
		if _, err := t.store.Write(p); err != nil {
			t.storeErr = err
		}
	}
	if t.clientErr == nil {
		t.deadline()
		if t.client == nil {
			t.client = t.open()
		}
		n, err := t.client.Write(p)
		t.delivered += int64(n)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = t.flush()
		}
		if err != nil {
			t.clientErr = err
		}
	}
	if t.storeErr != nil && t.clientErr != nil {
		return 0, t.storeErr
	}
	return len(p), nil
}

// started reports whether the guest's response has begun; it can no longer
// be redirected upstream.
func (t *streamTee) started() bool { return t != nil && t.client != nil }

// plainGet reports whether a request takes the whole object as is, so a fill
// can stream to it.
func plainGet(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	for _, header := range []string{"Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range"} {
		if r.Header.Get(header) != "" {
			return false
		}
	}
	return true
}
