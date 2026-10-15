// Package redact removes credentials from text before it reaches a log,
// state file, or diagnostics directory. Every sink wraps its writer with
// [Writer]; nothing upstream is trusted to have scrubbed first.
package redact

import (
	"bytes"
	"io"
	"regexp"
	"sync"
)

const mask = "<redacted>"

// patterns are applied in order to every line.
var patterns = []*regexp.Regexp{
	// GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_.
	regexp.MustCompile(`\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{16,}\b`),
	// JSON Web Tokens (installation tokens, Actions service tokens, JIT configs
	// embed them).
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	// PEM headers and the base64 body lines that follow them.
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	// Authorization headers.
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+`),
	// Signed URL and token query parameters (Azure SAS, S3 presign, Actions
	// results service, OAuth).
	regexp.MustCompile(`(?i)([?&](?:sig|signature|token|access_token|sas|X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|skoid|sktid|skt|ske|sks|skv)=)[^&\s"'<>]+`),
	// Long unbroken base64 runs (standard or URL-safe alphabet): JIT
	// configs, key material, session tokens. Checksums match too, which is
	// harmless. Paths do not: they mix '/' with '-' or contain '.'.
	regexp.MustCompile(`[A-Za-z0-9+/=]{64,}`),
	regexp.MustCompile(`[A-Za-z0-9_-]{64,}`),
}

// String returns s with every recognised credential replaced.
func String(s string) string {
	return string(Bytes([]byte(s)))
}

// Bytes returns a redacted copy of b.
func Bytes(b []byte) []byte {
	out := b
	for i, p := range patterns {
		switch i {
		case 3, 4: // keep the prefix group
			out = p.ReplaceAll(out, []byte("${1}"+mask))
		default:
			out = p.ReplaceAll(out, []byte(mask))
		}
	}
	return out
}

// MaxLine bounds the bytes a [Writer] holds while waiting for a newline.
//
// A longer line is flushed early at a boundary no recognised credential
// spans: whitespace, a quote, an angle bracket, or before '&'. An
// authorization scheme stays with its value. A run of MaxLine bytes with no
// such boundary is replaced by one mask up to the next boundary, so a
// credential cannot leak by straddling a flush. Multi-line PEM blocks are
// only recognised by [Bytes]; through a Writer their base64 body lines are
// masked as long runs.
const MaxLine = 64 << 10

// authTail matches an authorization header whose value has not arrived yet.
var authTail = regexp.MustCompile(`(?i)authorization:[ \t]*(?:(?:bearer|basic|token)[ \t]*)?$`)

// Writer redacts complete lines before forwarding them. A partial trailing
// line is held until its newline arrives, it reaches MaxLine, or Close is
// called.
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	buf     []byte
	max     int
	masking bool // dropping an overlong run that has already been masked
}

// NewWriter wraps w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w, max: MaxLine}
}

// boundary reports bytes that terminate every redacted credential value.
func boundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f', '"', '\'', '<', '>', '&':
		return true
	}
	return false
}

// Write redacts every complete line and forwards it. Memory stays within a
// small multiple of MaxLine regardless of input.
func (r *Writer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), r.max)]
		if err := r.write(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (r *Writer) write(p []byte) error {
	if r.masking {
		i := 0
		for i < len(p) && !boundary(p[i]) {
			i++
		}
		if i == len(p) {
			return nil
		}
		r.masking = false
		p = p[i:]
	}
	r.buf = append(r.buf, p...)
	start := 0
	for {
		i := bytes.IndexByte(r.buf[start:], '\n')
		if i < 0 {
			break
		}
		_, err := r.w.Write(Bytes(r.buf[start : start+i+1]))
		start += i + 1
		if err != nil {
			r.drop(start)
			return err
		}
	}
	r.drop(start)
	for len(r.buf) >= r.max {
		last := len(r.buf) - 1
		for last >= 0 && !boundary(r.buf[last]) {
			last--
		}
		if len(r.buf)-(last+1) >= r.max {
			// One unbroken run: emit what precedes it, then mask the run.
			out := append(Bytes(r.buf[:last+1]), mask...)
			_, err := r.w.Write(out)
			r.buf = r.buf[:0]
			r.masking = true
			return err
		}
		cut := last
		if loc := authTail.FindIndex(r.buf[max(0, cut-64):cut]); loc != nil {
			cut = max(0, cut-64) + loc[0]
		}
		if cut <= 0 {
			return nil // the run after a boundary is still shorter than max
		}
		_, err := r.w.Write(Bytes(r.buf[:cut]))
		r.drop(cut)
		if err != nil {
			return err
		}
	}
	return nil
}

// drop discards the first n buffered bytes without retaining a large array.
func (r *Writer) drop(n int) {
	rest := copy(r.buf, r.buf[n:])
	r.buf = r.buf[:rest]
	if cap(r.buf) > 4*r.max {
		r.buf = append([]byte(nil), r.buf...)
	}
}

// Close flushes a trailing partial line.
func (r *Writer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.masking = false
	if len(r.buf) == 0 {
		return nil
	}
	line := Bytes(r.buf)
	r.buf = r.buf[:0]
	_, err := r.w.Write(line)
	return err
}
