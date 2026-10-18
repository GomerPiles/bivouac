// Package github wraps the runner scale set API (through actions/scaleset)
// and the REST JIT-config fallback behind small interfaces the manager and
// tests use.
package github

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/actions/scaleset"
)

// Message is one scale set poll result. A nil *Message means the long poll
// timed out with nothing new.
type Message = scaleset.RunnerScaleSetMessage

// Statistics is the scale set's current counts.
type Statistics = scaleset.RunnerScaleSetStatistic

// JITConfig is a freshly registered runner and its one-time config. The
// encoded config is a secret until the runner consumes it.
type JITConfig struct {
	RunnerID   int64
	RunnerName string
	Encoded    []byte
}

// Session is an open message session on one scale set.
type Session interface {
	// Poll long-polls for the next message. maxCapacity is the total runner
	// ceiling, including runners already active.
	Poll(ctx context.Context, lastMessageID, maxCapacity int) (*Message, error)
	Ack(ctx context.Context, messageID int) error
	Acquire(ctx context.Context, requestIDs []int64) ([]int64, error)
	Statistics() *Statistics
	Close(ctx context.Context) error
}

// ScaleSet is an ensured scale set and the labels GitHub reports for it.
type ScaleSet struct {
	ID     int
	Labels []string
}

// ScaleSets is what the manager needs from GitHub in scale-set mode.
type ScaleSets interface {
	// Ensure returns the scale set and the labels GitHub reports, creating
	// it with labels when absent. GitHub fixes labels at creation and
	// silently ignores label updates; compare the result with LabelDiff.
	Ensure(ctx context.Context, name, runnerGroup string, labels []string) (ScaleSet, error)
	Open(ctx context.Context, scaleSetID int, owner string) (Session, error)
	GenerateJIT(ctx context.Context, scaleSetID int, runnerName, workFolder string) (JITConfig, error)
	// RemoveRunner deregisters a runner that never ran or died. Missing
	// runners are not an error.
	RemoveRunner(ctx context.Context, runnerID int64) error
	// RunnerByName returns the ID of a registered runner, or 0.
	RunnerByName(ctx context.Context, name string) (int64, error)
}

// AppAuth is a GitHub App credential.
type AppAuth struct {
	ClientID       string
	InstallationID int64
	PrivateKeyPEM  []byte
}

// Client talks to github.com through actions/scaleset.
type Client struct {
	c *scaleset.Client
}

// NewClient authenticates as the App against the org or repo URL.
func NewClient(configURL string, auth AppAuth, version string) (*Client, error) {
	c, err := scaleset.NewClientWithGitHubApp(scaleset.ClientWithGitHubAppConfig{
		GitHubConfigURL: configURL,
		GitHubAppAuth: scaleset.GitHubAppAuth{
			ClientID:       auth.ClientID,
			InstallationID: auth.InstallationID,
			PrivateKey:     string(auth.PrivateKeyPEM),
		},
		SystemInfo: scaleset.SystemInfo{System: "bivouac", Version: version},
	})
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Ensure implements ScaleSets.
func (c *Client) Ensure(ctx context.Context, name, runnerGroup string, labels []string) (ScaleSet, error) {
	groupID := 1
	if runnerGroup != "" && runnerGroup != scaleset.DefaultRunnerGroup {
		g, err := c.c.GetRunnerGroupByName(ctx, runnerGroup)
		if err != nil {
			return ScaleSet{}, fmt.Errorf("runner group %q: %w", runnerGroup, err)
		}
		groupID = g.ID
	}
	existing, err := c.c.GetRunnerScaleSet(ctx, groupID, name)
	if err != nil {
		return ScaleSet{}, fmt.Errorf("look up scale set %q: %w", name, err)
	}
	if existing != nil {
		return ScaleSet{ID: existing.ID, Labels: labelNames(existing.Labels)}, nil
	}
	if _, err := c.c.CreateRunnerScaleSet(ctx, &scaleset.RunnerScaleSet{
		Name:          name,
		RunnerGroupID: groupID,
		Labels:        systemLabels(labels),
		RunnerSetting: scaleset.RunnerSetting{DisableUpdate: true},
	}); err != nil {
		return ScaleSet{}, fmt.Errorf("create scale set %q: %w", name, err)
	}
	// Read back rather than trusting the create response: unsupported
	// labels can be dropped without an error.
	got, err := c.c.GetRunnerScaleSet(ctx, groupID, name)
	if err != nil {
		return ScaleSet{}, fmt.Errorf("look up scale set %q: %w", name, err)
	}
	if got == nil {
		return ScaleSet{}, fmt.Errorf("scale set %q missing after create", name)
	}
	return ScaleSet{ID: got.ID, Labels: labelNames(got.Labels)}, nil
}

func systemLabels(names []string) []scaleset.Label {
	labels := make([]scaleset.Label, len(names))
	for i, name := range names {
		labels[i] = scaleset.Label{Type: "System", Name: name}
	}
	return labels
}

func labelNames(labels []scaleset.Label) []string {
	names := make([]string, len(labels))
	for i, l := range labels {
		names[i] = l.Name
	}
	return names
}

// LabelDiff returns the wanted labels absent from got and the labels in
// got that are not wanted. GitHub labels are case-insensitive.
func LabelDiff(want, got []string) (missing, extra []string) {
	return absent(want, got), absent(got, want)
}

func absent(from, in []string) []string {
	have := make(map[string]bool, len(in))
	for _, l := range in {
		have[strings.ToLower(l)] = true
	}
	var out []string
	for _, l := range from {
		if !have[strings.ToLower(l)] {
			out = append(out, l)
		}
	}
	return out
}

// Open implements ScaleSets.
func (c *Client) Open(ctx context.Context, scaleSetID int, owner string) (Session, error) {
	s, err := c.c.MessageSessionClient(ctx, scaleSetID, owner)
	if err != nil {
		return nil, err
	}
	return &session{s: s}, nil
}

// GenerateJIT implements ScaleSets.
func (c *Client) GenerateJIT(ctx context.Context, scaleSetID int, runnerName, workFolder string) (JITConfig, error) {
	cfg, err := c.c.GenerateJitRunnerConfig(ctx, &scaleset.RunnerScaleSetJitRunnerSetting{Name: runnerName, WorkFolder: workFolder}, scaleSetID)
	if err != nil {
		return JITConfig{}, err
	}
	if cfg == nil || cfg.Runner == nil || cfg.EncodedJITConfig == "" {
		return JITConfig{}, errors.New("empty JIT config response")
	}
	return JITConfig{RunnerID: int64(cfg.Runner.ID), RunnerName: cfg.Runner.Name, Encoded: []byte(cfg.EncodedJITConfig)}, nil
}

// RemoveRunner implements ScaleSets.
func (c *Client) RemoveRunner(ctx context.Context, runnerID int64) error {
	return runnerRemovalError(c.c.RemoveRunner(ctx, runnerID))
}

func runnerRemovalError(err error) error {
	// Request IDs and response bodies can contain "404" even when a busy
	// runner's deletion failed. Only the SDK's typed missing-runner error
	// proves cleanup is already complete.
	if errors.Is(err, scaleset.RunnerNotFoundError) {
		return nil
	}
	return err
}

// RunnerByName implements ScaleSets.
func (c *Client) RunnerByName(ctx context.Context, name string) (int64, error) {
	r, err := c.c.GetRunnerByName(ctx, name)
	if err != nil {
		return 0, err
	}
	if r == nil {
		return 0, nil
	}
	return int64(r.ID), nil
}

type session struct {
	s *scaleset.MessageSessionClient
}

func (s *session) Poll(ctx context.Context, lastMessageID, maxCapacity int) (*Message, error) {
	return s.s.GetMessage(ctx, lastMessageID, maxCapacity)
}

func (s *session) Ack(ctx context.Context, messageID int) error {
	return s.s.DeleteMessage(ctx, messageID)
}

func (s *session) Acquire(ctx context.Context, requestIDs []int64) ([]int64, error) {
	return s.s.AcquireJobs(ctx, requestIDs)
}

func (s *session) Statistics() *Statistics {
	return s.s.Session().Statistics
}

func (s *session) Close(ctx context.Context) error {
	return s.s.Close(ctx)
}
