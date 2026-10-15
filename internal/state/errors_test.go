package state

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMessageRedactsAndBounds(t *testing.T) {
	token := "ghs_" + strings.Repeat("x", 40)
	long := "GET https://api.example/r?sig=secret: " + token + " " + strings.Repeat("é", 2000)
	got := Message(long)
	if strings.Contains(got, token) || strings.Contains(got, "sig=secret") {
		t.Fatalf("credential kept: %.100s", got)
	}
	if len(got) > MaxMessage || !utf8.ValidString(got) || !strings.HasSuffix(got, "[truncated]") {
		t.Fatalf("bad bound: %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if Message("short") != "short" {
		t.Fatal("short message changed")
	}
}

func TestRecordErrorSkipsRepeats(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, func() string { return "c" })
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordError("a", "guest not owned"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordError("b", "other"); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if err := s.RecordError("a", "guest not owned"); err != nil {
			t.Fatal(err)
		}
	}
	if errs := s.Errors(); len(errs) != 2 {
		t.Fatalf("repeats recorded: %+v", errs)
	}
	if err := s.RecordError("a", "different"); err != nil {
		t.Fatal(err)
	}
	if errs := s.Errors(); len(errs) != 3 {
		t.Fatalf("new message dropped: %+v", errs)
	}
}
