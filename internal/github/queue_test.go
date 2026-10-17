package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func queueTestClient(srv *httptest.Server) *JITClient {
	return &JITClient{http: srv.Client(), base: srv.URL, scope: "/orgs/example-org", owner: "example-org", token: "synthetic-installation", expires: time.Now().Add(time.Hour)}
}

func TestQueuedJobsReadsBothRunStatesAndPaginatesJobs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-installation" {
			t.Error("queue request was not authenticated")
		}
		if r.URL.Path == "/repos/example-org/repo/actions/runs" {
			id := 1
			if r.URL.Query().Get("status") == "in_progress" {
				id = 2
			}
			_, _ = fmt.Fprintf(w, `{"workflow_runs":[{"id":%d}]}`, id)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/1/jobs") {
			if r.URL.Query().Get("filter") != "latest" || r.URL.Query().Get("per_page") != "100" {
				t.Error("missing latest-attempt or page-size filter")
			}
			if r.URL.Query().Get("page") == "1" {
				jobs := make([]QueuedJob, 100)
				for i := range jobs {
					jobs[i] = QueuedJob{ID: int64(i + 1), Status: "completed"}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
			} else {
				_, _ = fmt.Fprint(w, `{"jobs":[{"id":101,"status":"queued","labels":["Windows","bivouac-test"]},{"id":102,"status":"queued","runner_id":7,"labels":["Windows"]}]}`)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/2/jobs") {
			_, _ = fmt.Fprint(w, `{"jobs":[{"id":103,"status":"queued","labels":["Linux"]},{"id":101,"status":"queued","labels":["Windows"]}]}`)
			return
		}
		t.Error("unexpected queue route")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	jobs, err := queueTestClient(srv).QueuedJobs(t.Context(), []string{"example-org/repo"})
	if err != nil || len(jobs) != 2 || jobs[0].ID != 101 || jobs[1].ID != 103 {
		t.Fatalf("queue scan: %v, %v", jobs, err)
	}
}

func TestQueueReadFailuresCannotExposeResponseOrPartialDemand(t *testing.T) {
	for _, mode := range []string{"forbidden", "invalid", "pagination"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "forbidden":
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, "private-response-body")
				case "invalid":
					_, _ = fmt.Fprint(w, `{}`)
				case "pagination":
					if strings.HasSuffix(r.URL.Path, "/jobs") {
						_, _ = fmt.Fprint(w, `{"jobs":[{"id":1,"status":"queued","labels":["Windows"]}]}`)
						return
					}
					runs := make([]map[string]int, 100)
					for i := range runs {
						runs[i] = map[string]int{"id": 1}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
				}
			}))
			defer srv.Close()
			jobs, err := queueTestClient(srv).QueuedJobs(t.Context(), []string{"example-org/repo"})
			if err == nil || len(jobs) != 0 || strings.Contains(err.Error(), "private-response-body") || strings.Contains(err.Error(), "example-org/repo") {
				t.Fatalf("unsafe failed scan: %v, %v", jobs, err)
			}
		})
	}
}

func TestQueueReadCancellationAndRepositoryScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	client := queueTestClient(srv)
	if _, err := client.QueuedJobs(t.Context(), []string{"another-org/repo"}); err == nil {
		t.Fatal("accepted a queue outside the registration organization")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.QueuedJobs(ctx, []string{"example-org/repo"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue cancellation: %v", err)
	}
}

func TestSeparateQueueCredentialDoesNotReplaceRegistrationOrFallBack(t *testing.T) {
	var revoked atomic.Bool
	var queueCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/actions/runners") {
			if r.Header.Get("Authorization") != "Bearer synthetic-installation" {
				t.Error("queue credential replaced the runner registration credential")
			}
			_, _ = fmt.Fprint(w, `{"runners":[]}`)
			return
		}
		queueCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-queue-read" {
			t.Error("queue read fell back to a different credential")
		}
		if revoked.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"workflow_runs":[]}`)
	}))
	defer srv.Close()
	client := queueTestClient(srv)
	if err := client.SetQueueReadToken([]byte("synthetic-queue-read")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.QueuedJobs(t.Context(), []string{"example-org/repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RunnerByName(t.Context(), "bivouac-fixture"); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	before := queueCalls.Load()
	if _, err := client.QueuedJobs(t.Context(), []string{"example-org/repo"}); err == nil || strings.Contains(err.Error(), "synthetic-queue-read") {
		t.Fatalf("revoked queue credential: %v", err)
	}
	if queueCalls.Load() != before+1 {
		t.Fatal("revoked queue credential was retried with another identity")
	}
}

func TestQueueRunPaginationDoesNotMissLaterRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/1/jobs"):
			_, _ = fmt.Fprint(w, `{"jobs":[]}`)
		case strings.HasSuffix(r.URL.Path, "/2/jobs"):
			_, _ = fmt.Fprint(w, `{"jobs":[{"id":9,"status":"queued","labels":["Windows"]}]}`)
		case r.URL.Query().Get("status") == "in_progress":
			_, _ = fmt.Fprint(w, `{"workflow_runs":[]}`)
		case r.URL.Query().Get("page") == "1":
			runs := make([]map[string]int, 100)
			for i := range runs {
				runs[i] = map[string]int{"id": 1}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
		default:
			_, _ = fmt.Fprint(w, `{"workflow_runs":[{"id":2}]}`)
		}
	}))
	defer srv.Close()
	jobs, err := queueTestClient(srv).QueuedJobs(t.Context(), []string{"example-org/repo"})
	if err != nil || len(jobs) != 1 || jobs[0].ID != 9 {
		t.Fatalf("later-page queue demand: %v, %v", jobs, err)
	}
}
