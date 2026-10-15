package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	long := strings.Repeat("Ab3", 30)
	cases := []struct{ in, want string }{
		{"token ghs_" + strings.Repeat("a", 30) + " end", "token <redacted> end"},
		{"pat github_pat_" + strings.Repeat("A1", 20), "pat <redacted>"},
		{"jwt eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3ZhbHVl", "jwt <redacted>"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "<redacted>"},
		{"Authorization: Bearer abc.def", "Authorization: Bearer <redacted>"},
		{"https://x.blob.core.windows.net/a?sv=2020&sig=abc%2Fdef&se=2026", "https://x.blob.core.windows.net/a?sv=2020&sig=<redacted>&se=2026"},
		{"jit " + long, "jit <redacted>"},
		{"plain text stays", "plain text stays"},
		{"path /private/tmp/agent-502/-Users-example-projects-example-bivouac/ff0dde49-bdeb-4d5a-a9ab-7e1ed5684a95/scratchpad/config.toml stays", "path /private/tmp/agent-502/-Users-example-projects-example-bivouac/ff0dde49-bdeb-4d5a-a9ab-7e1ed5684a95/scratchpad/config.toml stays"},
		{"urlsafe " + strings.Repeat("a-", 40), "urlsafe <redacted>"},
		{"short b64 QUJD stays", "short b64 QUJD stays"},
	}
	for _, c := range cases {
		if got := String(c.in); got != c.want {
			t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWriterLines(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out)
	secret := "ghs_" + strings.Repeat("b", 30)
	if _, err := w.Write([]byte("a " + secret[:10])); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("partial line written early: %q", out.String())
	}
	if _, err := w.Write([]byte(secret[10:] + "\nnext ")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "a <redacted>\nnext " {
		t.Fatalf("got %q", got)
	}
}

// writeBytewise feeds s one byte at a time so every possible flush point is hit.
func writeBytewise(t *testing.T, w *Writer, s string) {
	t.Helper()
	for i := range len(s) {
		if _, err := w.Write([]byte{s[i]}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWriterBoundsLongLines(t *testing.T) {
	const limit = 256
	secrets := []string{
		"ghs_" + strings.Repeat("c", 40),
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX3ZhbHVl",
		strings.Repeat("Zm9v", 20),
	}
	for _, secret := range secrets {
		// Place the credential at every offset relative to the flush limit.
		for pad := 0; pad < limit; pad += 7 {
			var out bytes.Buffer
			w := NewWriter(&out)
			w.max = limit
			in := strings.Repeat("word ", limit/5) + strings.Repeat("y", pad) + " " + secret + " tail " + strings.Repeat("z ", limit)
			writeBytewise(t, w, in)
			if len(w.buf) > 3*limit {
				t.Fatalf("buffered %d bytes", len(w.buf))
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), secret[:20]) || !strings.Contains(out.String(), mask) {
				t.Fatalf("secret straddling a flush leaked (pad %d): %q", pad, out.String())
			}
		}
	}
	// An authorization scheme stays with a value that arrives after a flush.
	for pad := 0; pad < limit; pad += 5 {
		var out bytes.Buffer
		w := NewWriter(&out)
		w.max = limit
		writeBytewise(t, w, strings.Repeat("a ", limit/2)+strings.Repeat("b", pad)+" Authorization: Bearer opaque-value tail"+strings.Repeat(" c", limit))
		_ = w.Close()
		if strings.Contains(out.String(), "opaque-value") {
			t.Fatalf("authorization value leaked (pad %d)", pad)
		}
	}
}

func TestWriterMasksUnbrokenRun(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out)
	w.max = 128
	run := strings.Repeat("x.", 4096) // no boundary; not itself a recognised token
	if _, err := w.Write([]byte("before " + run + " after\n")); err != nil {
		t.Fatal(err)
	}
	if len(w.buf) != 0 {
		t.Fatalf("buffered %d bytes", len(w.buf))
	}
	if got := out.String(); got != "before "+mask+" after\n" {
		t.Fatalf("got %q", got)
	}
	// Large writes without any newline stay bounded.
	big := bytes.Repeat([]byte("ab "), 1<<14)
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	if len(w.buf) > 3*w.max {
		t.Fatalf("buffered %d bytes", len(w.buf))
	}
}
