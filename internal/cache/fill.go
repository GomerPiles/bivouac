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
	var done int64
	for resumes := 0; ; resumes++ {
		ctx, cancel := context.WithCancel(s.work)
		req := base.Clone(ctx)
		req.Header.Set("If-Match", etag)
		if done > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(done, 10)+"-")
		}
		n, err := s.attempt(client, req, cancel, etag, size, done, check, out)
		cancel()
		done += n
		if err != nil && s.work.Err() != nil {
			return s.work.Err()
		}
		var again resumable
		if err == nil || done == 0 || resumes == fillResumes || !errors.As(err, &again) {
			return err
		}
		reason, _ := failureDetails(err)
		s.log.Info("cache fill resumed", "object", label, "reason", reason, "offset_bytes", done, "bytes", size)
	}
}

func (s *Service) attempt(client *http.Client, req *http.Request, cancel context.CancelFunc, etag string, size, offset int64, check func(*http.Response) error, out io.Writer) (int64, error) {
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
	body := &idleReader{r: response.Body, limit: s.fillIdle}
	body.timer = time.AfterFunc(s.fillIdle, func() { body.idle.Store(true); cancel() })
	defer body.timer.Stop()
	n, err := io.Copy(out, body)
	switch {
	case err == nil && offset+n == size:
		return n, nil // Complete, even if the idle timer fired since.
	case err != nil && body.err == nil:
		return n, err // The writer failed.
	case body.idle.Load():
		return n, resumable{failure("upstream_idle")}
	case err != nil:
		return n, resumable{failure("upstream_body")}
	default: // A short body without an error.
		return n, resumable{failure("length_mismatch")}
	}
}

// idleReader ends an attempt that receives nothing for limit.
type idleReader struct {
	r     io.Reader
	limit time.Duration
	timer *time.Timer
	idle  atomic.Bool
	err   error // The first read error other than EOF.
}

func (b *idleReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.timer.Reset(b.limit)
	}
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
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
		if t.client == nil {
			t.client = t.open()
		}
		t.deadline()
		n, err := t.client.Write(p)
		t.delivered += int64(n)
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
