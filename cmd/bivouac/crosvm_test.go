package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/perf"
	"github.com/GomerPiles/bivouac/internal/provider/crosvm"
)

type validationGuestFixture struct {
	sanitized         bool
	boots, identities int
	failure           error
}

func (g *validationGuestFixture) ExercisePreparedImage(context.Context, crosvm.Record) error {
	g.sanitized = true
	return g.failure
}
func (g *validationGuestFixture) BootReport(context.Context, crosvm.Record) (map[string]uint64, error) {
	g.boots++
	return map[string]uint64{"ssh_active_us": 100}, nil
}
func (g *validationGuestFixture) CloneIdentity(context.Context, crosvm.Record) (map[string]string, error) {
	g.identities++
	if g.sanitized {
		return nil, errors.New("factory identity files are absent")
	}
	return map[string]string{"machine_id_sha256": strings.Repeat("a", 64)}, nil
}

func TestCrosvmSanitationTrialDoesNotProbeClearedIdentity(t *testing.T) {
	g := &validationGuestFixture{}
	var out bytes.Buffer
	if err := validateCrosvmGuest(context.Background(), g, crosvm.Record{}, true, &out); err != nil {
		t.Fatal(err)
	}
	if !g.sanitized || g.boots != 0 || g.identities != 0 || !strings.Contains(out.String(), "no image published") {
		t.Fatal("sanitation trial did not finish independently of cold-boot probes")
	}
	g.failure = errors.New("synthetic sanitation refusal")
	out.Reset()
	if err := validateCrosvmGuest(context.Background(), g, crosvm.Record{}, true, &out); !errors.Is(err, g.failure) || out.Len() != 0 {
		t.Fatal("failed sanitation reported success")
	}
}

func TestCrosvmColdValidationReportsIdentity(t *testing.T) {
	g := &validationGuestFixture{}
	var out bytes.Buffer
	if err := validateCrosvmGuest(context.Background(), g, crosvm.Record{}, false, &out); err != nil {
		t.Fatal(err)
	}
	var report map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &report) != nil || report["clone_identity"] == nil || report["boot_timestamps_us"] == nil || g.sanitized || g.boots != 1 || g.identities != 1 {
		t.Fatal("cold validation lost boot/identity observations")
	}
}

func TestCrosvmModeFlagsRefusedBeforeOpeningBackend(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "helper")
	for _, args := range [][]string{
		{"cleanup", "--name", "bivouac-linux-1234abcd", "--require-prepared"},
		{"cleanup", "--name", "bivouac-linux-1234abcd", "--exercise-prepared-image"},
		{"validate", "--helper", helper, "--output-root", filepath.Join(t.TempDir(), "Linux-Images")},
		{"build-image", "--helper", helper, "--output-root", filepath.Join(t.TempDir(), "Linux-Images"), "--exercise-recovery"},
		{"validate", "--helper", helper, "--reserve-memory-mb", "0"},
	} {
		args = append(args, "--options", "absent-options.json")
		if err := crosvmCmd(context.Background(), args, io.Discard); !errors.Is(err, errUsage) {
			t.Fatalf("invalid mode flags were accepted: %v: %v", args, err)
		}
	}
}

func TestCrosvmTrialReservesIncludeGuestBeforeLaunch(t *testing.T) {
	r := crosvmTrialReserves{memoryMB: 2048, commitMB: 1024}
	s := perf.Sample{AvailableBytes: 4096 << 20, Commit: &perf.CommitSpace{LimitBytes: 8192 << 20, UsedBytes: 5120 << 20}}
	if !r.valid() || !r.allows(s, 2048) {
		t.Fatal("exact prelaunch reserves rejected")
	}
	s.AvailableBytes--
	if r.allows(s, 2048) || !r.allows(s, 0) {
		t.Fatal("guest allocation not reserved separately from live reserve")
	}
	s.AvailableBytes++
	s.Commit.UsedBytes++
	if r.allows(s, 2048) {
		t.Fatal("insufficient commit headroom accepted")
	}
	s.Commit = nil
	if r.allows(s, 0) {
		t.Fatal("missing commit observation accepted")
	}
}
