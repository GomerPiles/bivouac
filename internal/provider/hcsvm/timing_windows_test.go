//go:build windows

package hcsvm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureTimings(p *Provider) *bytes.Buffer {
	var buf bytes.Buffer
	p.logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return &buf
}

// Simulate the transport's internal boundaries without dialing a real guest.
func fakeOpenTimings(ctx context.Context) error {
	t := contextTiming(ctx)
	t.begin(stepAgentDial)
	t.report.SpansMS["agent_dial_retries"] = 2
	return nil
}

func numericRecord(t *testing.T, line []byte, message string) map[string]int64 {
	t.Helper()
	var record map[string]json.RawMessage
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatal(err)
	}
	if string(record["msg"]) != `"`+message+`"` || string(record["level"]) != `"INFO"` {
		t.Fatal("missing Info timing record")
	}
	// Check the raw keys too: decoding a JSON object would hide duplicates.
	dec := json.NewDecoder(bytes.NewReader(line))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		name := key.(string)
		if seen[name] {
			t.Fatal("duplicate timing key", name)
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	values := map[string]int64{}
	for name, raw := range record {
		switch name {
		case "time", "level", "msg", "failure_step":
			continue
		}
		var value int64
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal("non-numeric timing value", name)
		}
		values[name] = value
	}
	return values
}

func TestReadinessTimingsSuccess(t *testing.T) {
	p, _, f := fixture(t, true)
	defer p.Close()
	buf := captureTimings(p)
	f.openHook = fakeOpenTimings
	archive := []byte("synthetic runner archive")
	p.opts.RunnerArchive = filepath.Join(t.TempDir(), "runner.zip")
	digest := sha256.Sum256(archive)
	p.opts.RunnerSHA256 = hex.EncodeToString(digest[:])
	if err := os.WriteFile(p.opts.RunnerArchive, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	report, err := p.waitReady(t.Context(), spec().Name)
	if err != nil || report.FailureStep != "" {
		t.Fatal("readiness failed", err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 1 {
		t.Fatal("expected one readiness record", len(lines))
	}
	values := numericRecord(t, lines[0], "hcs readiness timings")
	encoded, err := json.Marshal(report.SpansMS)
	if err != nil {
		t.Fatal(err)
	}
	logged, err := json.Marshal(values)
	if err != nil || !bytes.Equal(encoded, logged) {
		t.Fatal("lab payload differs from log")
	}
	steps := []string{"vmhost_create", "session", "agent_dial", "network", "agent_proof", "config", "delivery_config", "delivery_helper", "delivery_runner_archive", "preflight", "console_proof", "prepare", "desktop_proof", "gpu_proof", "clock_sync", "wait_ready_total"}
	var previous int64
	for _, step := range steps {
		duration, ok := values[step+"_ms"]
		if !ok || duration < 0 {
			t.Fatal("missing or negative duration", step)
		}
		milestone, ok := values[step+"_since_create_ms"]
		if !ok || milestone < previous || duration > milestone {
			t.Fatal("invalid milestone ordering", step)
		}
		previous = milestone
	}
	if len(values) != len(steps)*2+2 || values["agent_dial_retries"] != 2 || values["clock_skew_ms"] != 1000 {
		t.Fatal("unexpected span schema, retries or skew")
	}
	if values["wait_ready_total_ms"] > time.Since(before).Milliseconds() {
		t.Fatal("total exceeded observed operation")
	}
	// Reusing a session does not fabricate another dial or handshake span.
	buf.Reset()
	if err := p.WaitReady(t.Context(), spec().Name); err != nil {
		t.Fatal(err)
	}
	values = numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs readiness timings")
	if _, ok := values["agent_dial_ms"]; ok {
		t.Fatal("cached session fabricated a dial")
	}
}

func TestReadinessTimingsFailures(t *testing.T) {
	const untrusted = "synthetic-sensitive-guest-text"
	sentinel := errors.New(untrusted)
	for _, tc := range []struct {
		name, failure, absent string
		setup                 func(*Provider, *fakeTransport)
		wantError             error
	}{
		{"dial", "agent_dial", "agent_proof_ms", func(_ *Provider, f *fakeTransport) {
			f.openHook = func(ctx context.Context) error {
				tm := contextTiming(ctx)
				tm.begin(stepAgentDial)
				tm.report.SpansMS["agent_dial_retries"] = 3
				return sentinel
			}
		}, sentinel},
		{"preflight", "preflight", "console_proof_ms", func(_ *Provider, f *fakeTransport) { f.fail = sentinel }, sentinel},
		{"console", "console_proof", "prepare_ms", func(_ *Provider, f *fakeTransport) { f.replies["guest windows preflight"] = untrusted }, nil},
		{"helper", "delivery_helper", "prepare_ms", func(p *Provider, _ *fakeTransport) { p.opts.Helper = filepath.Join(t.TempDir(), "missing.exe") }, nil},
		{"prepare", "prepare", "desktop_proof_ms", func(_ *Provider, f *fakeTransport) {
			f.runHook = func(command string, _ []byte) error {
				if command == guestIncomingHelper+" guest windows prepare" {
					return sentinel
				}
				return nil
			}
		}, sentinel},
		{"desktop", "desktop_proof", "clock_sync_ms", func(_ *Provider, f *fakeTransport) { f.replies["guest windows prepare"] = untrusted }, nil},
		{"clock", "clock_sync", "clock_skew_ms", func(_ *Provider, f *fakeTransport) { f.replies["guest windows clock"] = untrusted }, nil},
		{"skew", "clock_sync", "unused_ms", func(_ *Provider, f *fakeTransport) {
			f.replies["guest windows clock"] = hostNow.Add(time.Hour).Format(time.RFC3339Nano)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, f := fixture(t, true)
			defer p.Close()
			buf := captureTimings(p)
			f.openHook = fakeOpenTimings
			tc.setup(p, f)
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			report, err := p.waitReady(t.Context(), spec().Name)
			if err == nil || (tc.wantError != nil && !errors.Is(err, tc.wantError)) || report.FailureStep != tc.failure {
				t.Fatal("failure mapping changed", report.FailureStep)
			}
			values := numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs readiness timings")
			for _, name := range []string{"vmhost_create_ms", tc.failure + "_ms", "wait_ready_total_ms"} {
				if _, ok := values[name]; !ok {
					t.Fatal("missing reached span", name)
				}
			}
			if _, ok := values[tc.absent]; ok || bytes.Contains(buf.Bytes(), []byte(untrusted)) {
				t.Fatal("unreached span or guest text logged")
			}
			if !bytes.Contains(buf.Bytes(), []byte(`"failure_step":"`+tc.failure+`"`)) {
				t.Fatal("missing fixed failure step")
			}
		})
	}
}

func TestLaunchAndListeningTimings(t *testing.T) {
	p, _, f := fixture(t, true)
	defer p.Close()
	buf := captureTimings(p)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	if err := p.StartRunner(t.Context(), spec().Name, []byte("synthetic-jit-secret")); err != nil {
		t.Fatal(err)
	}
	values := numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs launch timings")
	for _, key := range []string{"cache_setup_ms", "jit_delivery_ms", "runner_start_ms", "launch_total_ms"} {
		if _, ok := values[key]; !ok {
			t.Fatal("missing launch span", key)
		}
	}
	if _, ok := values["jit_to_listening_ms"]; ok {
		t.Fatal("process creation was treated as listening")
	}
	buf.Reset()
	f.replies["guest windows status"] = `{"State":"starting"}`
	if _, err := p.RunnerStatus(t.Context(), spec().Name); err != nil || buf.Len() != 0 {
		t.Fatal("starting was treated as listening")
	}
	f.replies["guest windows status"] = `{"State":"listening"}`
	for range 2 {
		if _, err := p.RunnerStatus(t.Context(), spec().Name); err != nil {
			t.Fatal(err)
		}
	}
	values = numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs listening timings")
	if len(values) != 2 || values["jit_to_listening_ms"] < 0 || values["listening_since_create_ms"] < values["jit_to_listening_ms"] || strings.Contains(buf.String(), "synthetic-jit-secret") {
		t.Fatal("invalid listening report")
	}
	if err := p.Delete(t.Context(), spec().Name); err != nil || len(p.timings) != 0 {
		t.Fatal("timings outlived guest", err)
	}
}

func TestReadinessTimingsWithoutCreateOrigin(t *testing.T) {
	p, _, _ := fixture(t, true)
	defer p.Close()
	buf := captureTimings(p)
	if err := p.Create(t.Context(), spec()); err != nil {
		t.Fatal(err)
	}
	// A reconstructed provider has ownership proof but no monotonic origin.
	p.mu.Lock()
	delete(p.timings, spec().Name)
	p.mu.Unlock()
	if err := p.WaitReady(t.Context(), spec().Name); err != nil {
		t.Fatal(err)
	}
	values := numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs readiness timings")
	for key := range values {
		if strings.Contains(key, "since_create") || key == "vmhost_create_ms" {
			t.Fatal("fabricated create origin", key)
		}
	}
}

func TestLaunchTimingsFailurePreservesError(t *testing.T) {
	for _, command := range []string{guestHelper + " guest windows seed-jit", guestHelper + " guest windows start"} {
		t.Run(command, func(t *testing.T) {
			p, _, f := fixture(t, true)
			defer p.Close()
			buf := captureTimings(p)
			sentinel := errors.New("synthetic-sensitive-text")
			f.runHook = func(got string, _ []byte) error {
				if got == command {
					return sentinel
				}
				return nil
			}
			if err := p.Create(t.Context(), spec()); err != nil {
				t.Fatal(err)
			}
			if err := p.StartRunner(t.Context(), spec().Name, []byte("synthetic-jit-secret")); !errors.Is(err, sentinel) {
				t.Fatal("launch error changed")
			}
			values := numericRecord(t, bytes.TrimSpace(buf.Bytes()), "hcs launch timings")
			step := "jit_delivery"
			if command == guestHelper+" guest windows start" {
				step = "runner_start"
			}
			if _, ok := values[step+"_ms"]; !ok || !bytes.Contains(buf.Bytes(), []byte(`"failure_step":"`+step+`"`)) || bytes.Contains(buf.Bytes(), []byte("synthetic-")) {
				t.Fatal("invalid launch failure report")
			}
			if !p.timings[spec().Name].jitStarted.IsZero() {
				t.Fatal("failed launch retained listening observation")
			}
		})
	}
}
