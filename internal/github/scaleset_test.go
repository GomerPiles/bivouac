package github

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/actions/scaleset"
)

func TestRunnerRemovalError(t *testing.T) {
	busy := fmt.Errorf(`request DELETE https://example.test/agents/58 failed(status="400 Bad Request", github_request_id="ABCD:404:1234"): %w`, scaleset.JobStillRunningError)
	for _, tc := range []struct {
		name    string
		err     error
		missing bool
	}{
		{name: "success"},
		{name: "wrapped missing runner", err: fmt.Errorf("remove: %w", scaleset.RunnerNotFoundError), missing: true},
		{name: "busy with 404 in request ID", err: busy},
		{name: "404 in response body", err: errors.New("server error: reference 404")},
		{name: "unclassified HTTP error", err: errors.New(`request failed(status="404 Not Found"): unknown error`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runnerRemovalError(tc.err)
			if tc.missing || tc.err == nil {
				if got != nil {
					t.Fatalf("expected completed cleanup, got %v", got)
				}
			} else if !errors.Is(got, tc.err) {
				t.Fatalf("cleanup failure discarded: got %v, want %v", got, tc.err)
			}
		})
	}
}

func TestMissingLabels(t *testing.T) {
	want := []string{"bivouac-x", "Self-Hosted", "bivouac-lt-a"}
	if got := MissingLabels(want, []string{"BIVOUAC-X", "self-hosted"}); !slices.Equal(got, []string{"bivouac-lt-a"}) {
		t.Fatalf("missing %q", got)
	}
	if !sameLabels(want, []string{"bivouac-lt-a", "bivouac-x", "self-hosted"}) || sameLabels(want, append(want, "extra")) {
		t.Fatal("label set comparison is wrong")
	}
}
