package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// QueuedJob contains only routing metadata. Names, URLs and workflow contents
// are neither needed for admission nor retained in diagnostics.
type QueuedJob struct {
	ID     int64    `json:"id"`
	Status string   `json:"status"`
	Labels []string `json:"labels"`
	Group  string   `json:"runner_group_name"`
	Runner int64    `json:"runner_id"`
}

// JobQueue reads ready jobs; GitHub remains authoritative for runner assignment.
type JobQueue interface {
	QueuedJobs(context.Context, []string) ([]QueuedJob, error)
}

// SetQueueReadToken supplies an optional Actions-read token before the client
// is shared. Registration still uses the App; a failed queue token never falls
// back to another credential or to warm guests.
func (c *JITClient) SetQueueReadToken(token []byte) error {
	if len(token) == 0 || len(token) > 4096 {
		return errors.New("invalid queue-read credential")
	}
	for _, b := range token {
		if b <= 32 || b >= 127 {
			return errors.New("invalid queue-read credential")
		}
	}
	c.queueToken = string(token)
	return nil
}

// QueuedJobs reads both queued runs and runs already executing other jobs.
// Every collection is paginated and bounded. An incomplete scan fails closed
// rather than launching guests from a partial or stale result.
func (c *JITClient) QueuedJobs(ctx context.Context, repositories []string) ([]QueuedJob, error) {
	if len(repositories) == 0 || len(repositories) > 20 {
		return nil, errors.New("queue scan requires 1–20 repositories")
	}
	var jobs []QueuedJob
	seenRuns, seenJobs := map[int64]bool{}, map[int64]bool{}
	for _, repository := range repositories {
		owner, repo, ok := strings.Cut(repository, "/")
		if !ok || owner == "" || repo == "" || repo == "." || repo == ".." || strings.ContainsAny(repo, "/?#%\\\r\n\t ") || !strings.EqualFold(owner, c.owner) ||
			strings.HasPrefix(c.scope, "/repos/") && !strings.EqualFold(c.scope, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)) {
			return nil, errors.New("queue repository is outside the registration scope")
		}
		base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/actions/runs"
		for _, status := range []string{"queued", "in_progress"} {
			for page := 1; ; page++ {
				if page > 10 {
					return nil, errors.New("queue run pagination exceeds the bounded scan")
				}
				var result struct {
					Runs []struct {
						ID int64 `json:"id"`
					} `json:"workflow_runs"`
				}
				path := fmt.Sprintf("%s?status=%s&per_page=100&page=%d", base, status, page)
				if err := c.queueCall(ctx, path, &result); err != nil {
					return nil, err
				}
				if result.Runs == nil || len(result.Runs) > 100 {
					return nil, errors.New("invalid bounded queue run response")
				}
				for _, run := range result.Runs {
					if run.ID <= 0 || seenRuns[run.ID] {
						continue
					}
					seenRuns[run.ID] = true
					for jobPage := 1; ; jobPage++ {
						if jobPage > 10 {
							return nil, errors.New("queue job pagination exceeds the bounded scan")
						}
						var result struct {
							Jobs []QueuedJob `json:"jobs"`
						}
						path := fmt.Sprintf("%s/%d/jobs?filter=latest&per_page=100&page=%d", base, run.ID, jobPage)
						if err := c.queueCall(ctx, path, &result); err != nil {
							return nil, err
						}
						if result.Jobs == nil || len(result.Jobs) > 100 {
							return nil, errors.New("invalid bounded queue job response")
						}
						for _, job := range result.Jobs {
							if job.Status != "queued" || job.Runner != 0 || job.ID <= 0 || seenJobs[job.ID] || len(job.Labels) == 0 {
								continue
							}
							if len(job.Labels) > 100 || len(jobs) >= 1000 {
								return nil, errors.New("queue routing metadata exceeds the bounded scan")
							}
							if len(job.Group) > 255 {
								return nil, errors.New("queue runner group exceeds the bounded scan")
							}
							for _, label := range job.Labels {
								if len(label) == 0 || len(label) > 255 || strings.TrimSpace(label) == "" {
									return nil, errors.New("invalid bounded queue label")
								}
							}
							seenJobs[job.ID] = true
							jobs = append(jobs, job)
						}
						if len(result.Jobs) < 100 {
							break
						}
					}
				}
				if len(result.Runs) < 100 {
					break
				}
			}
		}
	}
	return jobs, nil
}

func (c *JITClient) queueCall(ctx context.Context, path string, out any) error {
	var err error
	if c.queueToken != "" {
		err = c.request(ctx, http.MethodGet, path, c.queueToken, nil, out)
	} else {
		err = c.call(ctx, http.MethodGet, path, nil, out)
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var api *restError
		if errors.As(err, &api) {
			return fmt.Errorf("GitHub queue read failed: HTTP %d; check repository Actions read access", api.status)
		}
		return errors.New("GitHub queue read failed; no demand admitted")
	}
	return nil
}
