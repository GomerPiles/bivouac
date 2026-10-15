package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// RunnerRegistry is shared by both registration protocols.
type RunnerRegistry interface {
	RemoveRunner(context.Context, int64) error
	RunnerByName(context.Context, string) (int64, error)
}

// JITRunners registers ordinary ephemeral runners through GitHub REST.
type JITRunners interface {
	RunnerRegistry
	Check(context.Context, string) error
	GenerateRunnerJIT(context.Context, string, string, []string, string) (JITConfig, error)
}

// JITClient owns its App key and cached installation token. Neither leaves
// memory. Errors intentionally exclude response bodies and credentials.
type JITClient struct {
	http                        *http.Client
	base, scope, owner, version string
	auth                        AppAuth
	key                         *rsa.PrivateKey
	mu                          sync.Mutex
	token                       string
	expires                     time.Time
}

func NewJITClient(configURL string, auth AppAuth, version string) (*JITClient, error) {
	u, err := url.Parse(configURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid GitHub organization or repository URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return nil, errors.New("GitHub URL must name an organization or repository")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(auth.PrivateKeyPEM)
	if err != nil {
		return nil, errors.New("invalid GitHub App RSA private key")
	}
	base := "https://" + u.Host + "/api/v3"
	if u.Host == "github.com" {
		base = "https://api.github.com"
	}
	scope := "/orgs/" + url.PathEscape(parts[0])
	if len(parts) == 2 {
		scope = "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	}
	// The parsed key is sufficient; do not retain a second PEM copy.
	auth.PrivateKeyPEM = nil
	return &JITClient{http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: base, scope: scope, owner: parts[0], version: version, auth: auth, key: key}, nil
}

type restError struct {
	method, path string
	status       int
}

func (e *restError) Error() string {
	return fmt.Sprintf("GitHub REST %s %s: HTTP %d", e.method, strings.Split(e.path, "?")[0], e.status)
}

func (c *JITClient) request(ctx context.Context, method, path, token string, body, out any) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("encode GitHub REST request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("construct GitHub REST request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "bivouac/"+c.version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("GitHub REST transport failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &restError{method, path, resp.StatusCode}
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
			return errors.New("invalid GitHub REST response")
		}
	}
	return nil
}

func (c *JITClient) installationToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > time.Minute {
		return c.token, nil
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: c.auth.ClientID, IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)), ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute))}
	appToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(c.key)
	if err != nil {
		return "", errors.New("sign GitHub App JWT")
	}
	var result struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	if err := c.request(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", c.auth.InstallationID), appToken, nil, &result); err != nil {
		return "", err
	}
	if result.Token == "" || time.Until(result.Expires) <= time.Minute {
		return "", errors.New("invalid GitHub installation token response")
	}
	c.token, c.expires = result.Token, result.Expires
	return c.token, nil
}

func (c *JITClient) call(ctx context.Context, method, path string, body, out any) error {
	token, err := c.installationToken(ctx)
	if err != nil {
		return err
	}
	err = c.request(ctx, method, path, token, body, out)
	var apiErr *restError
	if errors.As(err, &apiErr) && apiErr.status == http.StatusUnauthorized {
		c.mu.Lock()
		if c.token == token {
			c.token = ""
		}
		c.mu.Unlock()
		token, err = c.installationToken(ctx)
		if err != nil {
			return err
		}
		return c.request(ctx, method, path, token, body, out)
	}
	return err
}

func (c *JITClient) groupID(ctx context.Context, name string) (int64, error) {
	if name == "" || strings.EqualFold(name, "default") {
		return 1, nil
	}
	for page := 1; ; page++ {
		var result struct {
			Groups []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"runner_groups"`
		}
		path := fmt.Sprintf("/orgs/%s/actions/runner-groups?per_page=100&page=%d", url.PathEscape(c.owner), page)
		if err := c.call(ctx, http.MethodGet, path, nil, &result); err != nil {
			return 0, err
		}
		for _, g := range result.Groups {
			if g.Name == name {
				return g.ID, nil
			}
		}
		if len(result.Groups) < 100 {
			return 0, fmt.Errorf("runner group %q not found", name)
		}
	}
}

// Check validates access without registering a runner or creating a scale set.
func (c *JITClient) Check(ctx context.Context, group string) error {
	if _, err := c.groupID(ctx, group); err != nil {
		return err
	}
	_, err := c.RunnerByName(ctx, "bivouac-doctor-access-check")
	return err
}

func (c *JITClient) GenerateRunnerJIT(ctx context.Context, name, group string, labels []string, workFolder string) (JITConfig, error) {
	id, err := c.groupID(ctx, group)
	if err != nil {
		return JITConfig{}, err
	}
	body := struct {
		Name   string   `json:"name"`
		Group  int64    `json:"runner_group_id"`
		Labels []string `json:"labels"`
		Work   string   `json:"work_folder"`
	}{name, id, labels, workFolder}
	var result struct {
		Runner struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"runner"`
		Encoded string `json:"encoded_jit_config"`
	}
	if err := c.call(ctx, http.MethodPost, c.scope+"/actions/runners/generate-jitconfig", body, &result); err != nil {
		return JITConfig{}, err
	}
	if result.Runner.ID <= 0 || result.Runner.Name != name || result.Encoded == "" {
		return JITConfig{}, errors.New("invalid REST JIT config response")
	}
	return JITConfig{RunnerID: result.Runner.ID, RunnerName: result.Runner.Name, Encoded: []byte(result.Encoded)}, nil
}

func (c *JITClient) RunnerByName(ctx context.Context, name string) (int64, error) {
	var found int64
	for page := 1; ; page++ {
		var result struct {
			Runners []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"runners"`
		}
		path := fmt.Sprintf("%s/actions/runners?name=%s&per_page=100&page=%d", c.scope, url.QueryEscape(name), page)
		if err := c.call(ctx, http.MethodGet, path, nil, &result); err != nil {
			return 0, err
		}
		for _, r := range result.Runners {
			if r.Name == name {
				if found != 0 {
					return 0, errors.New("duplicate runner name")
				}
				found = r.ID
			}
		}
		if len(result.Runners) < 100 {
			return found, nil
		}
	}
}

func (c *JITClient) RemoveRunner(ctx context.Context, id int64) error {
	path := fmt.Sprintf("%s/actions/runners/%d", c.scope, id)
	err := c.call(ctx, http.MethodDelete, path, nil, nil)
	var apiErr *restError
	if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound && apiErr.method == http.MethodDelete && apiErr.path == path {
		return nil
	}
	return err
}
