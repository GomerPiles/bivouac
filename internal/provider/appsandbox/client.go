// Package appsandbox implements the Windows App Sandbox provider and its
// bounded v1 API transport. Inspection remains independent of VM ownership.
package appsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxDiscoveryBytes = 16 * 1024
	maxResponseBytes  = 1024 * 1024
)

// ErrNotFound is returned for a missing VM (HTTP 404).
var ErrNotFound = errors.New("appsandbox resource not found")

// HTTPError reports only the status, never the daemon's response body or a
// redirect URL, either of which could contain credentials.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string { return fmt.Sprintf("App Sandbox HTTP status %d", e.StatusCode) }
func (e *HTTPError) Unwrap() error {
	if e.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

// Client holds a daemon credential in memory. It follows no redirects and
// uses no ambient HTTP proxy. Close releases idle connections.
type Client struct {
	base      string
	token     string
	http      *http.Client
	transport *http.Transport
}

func (Client) String() string     { return "AppSandbox client (credential redacted)" }
func (c Client) GoString() string { return c.String() }
func (Client) MarshalJSON() ([]byte, error) {
	return []byte(`"AppSandbox client (credential redacted)"`), nil
}

// Open reads the per-run discovery file and checks the live daemon identity.
// It never starts a daemon or guest, even when discovery is missing or stale.
func Open(ctx context.Context, path string) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open App Sandbox discovery file")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxDiscoveryBytes+1))
	if err != nil || len(data) > maxDiscoveryBytes {
		return nil, errors.New("cannot read bounded App Sandbox discovery file")
	}
	var d struct {
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, errors.New("invalid App Sandbox discovery document")
	}
	c, err := newClient(d.Endpoint, d.Token)
	if err != nil {
		return nil, err
	}
	if _, err := c.Version(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func newClient(endpoint, token string) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("appsandbox endpoint must be literal HTTP IPv4 loopback with a port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		return nil, errors.New("invalid App Sandbox loopback port")
	}
	// Bearer credentials are nonempty ASCII without spaces/control characters.
	if len(token) == 0 || len(token) > 4096 {
		return nil, errors.New("invalid App Sandbox discovery credential")
	}
	for _, b := range []byte(token) {
		if b <= 32 || b >= 127 {
			return nil, errors.New("invalid App Sandbox discovery credential")
		}
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout:  30 * time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxConnsPerHost:        1, // the daemon serializes core operations
		MaxResponseHeaderBytes: 32 * 1024,
		DisableCompression:     true,
	}
	return &Client{
		base: strings.TrimRight(endpoint, "/") + "/v1", token: token, transport: transport,
		http: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Close releases this client's idle HTTP connections.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

func (c *Client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.request(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader, out any) error {
	// #nosec G704 -- newClient pins literal IPv4 loopback; path is a fixed internal API route.
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return errors.New("cannot construct App Sandbox request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// #nosec G704 -- The private transport forbids proxies and redirects.
	resp, err := c.http.Do(req)
	if err != nil {
		if method != http.MethodGet {
			return errors.Join(ErrOutcomeUnknown, ctx.Err())
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("appsandbox daemon did not respond; discovery may be stale")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errors.New("cannot read App Sandbox response")
	}
	if len(data) > maxResponseBytes {
		return errors.New("appsandbox response exceeds size limit")
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid App Sandbox JSON response")
	}
	return nil
}

func vmPath(name string) (string, error) {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return "", errors.New("invalid App Sandbox VM name")
	}
	for _, b := range []byte(name) {
		valid := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-'
		if !valid {
			return "", errors.New("invalid App Sandbox VM name")
		}
	}
	return "/vms/" + name, nil
}

// Version is the live daemon identity. API version is preserved as JSON
// because the SDK contract does not specify its scalar type.
type Version struct {
	Product      string          `json:"product"`
	Version      string          `json:"version"`
	APIVersion   json.RawMessage `json:"apiVersion"`
	HostOS       string          `json:"hostOs"`
	Capabilities struct {
		Snapshots bool `json:"snapshots"`
		Templates bool `json:"templates"`
	} `json:"capabilities"`
}

// Version validates the product before exposing other inspection methods.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	if err := c.get(ctx, "/version", &v); err != nil {
		return v, err
	}
	if v.Product != "AppSandbox" || v.Version == "" || v.HostOS == "" || len(v.APIVersion) == 0 || string(v.APIVersion) == "null" {
		return Version{}, errors.New("discovery does not identify an App Sandbox daemon")
	}
	return v, nil
}

// Host reports native capacity and declared/running VM resource usage.
type Host struct {
	DefaultDiskDirectory string  `json:"defaultDiskDirectory"`
	HostCores            int     `json:"hostCores"`
	HostRAMMB            int     `json:"hostRamMb"`
	FreeGB               float64 `json:"freeGb"`
	VMCores              int     `json:"vmCores"`
	VMRAMMB              int     `json:"vmRamMb"`
	VMHDDGB              int     `json:"vmHddGb"`
}

// VM is a live status snapshot, not proof of bivouac ownership or desktop
// readiness. Native GPU/network modes are retained without interpreting NAT
// as a host-isolation boundary. DiskDirectory is the storage parent; the native
// VM child is <parent>/<name>, not the reported parent itself.
type VM struct {
	Name            string `json:"name"`
	DiskDirectory   string `json:"diskDirectory"`
	OSType          string `json:"osType"`
	State           string `json:"state"`
	Running         bool   `json:"running"`
	AgentOnline     bool   `json:"agentOnline"`
	InstallComplete bool   `json:"installComplete"`
	Building        bool   `json:"building"`
	Progress        int    `json:"progress"`
	SSHState        int    `json:"sshState"`
	SSHPort         int    `json:"sshPort"`
	RAMMB           int    `json:"ramMb"`
	HDDGB           int    `json:"hddGb"`
	CPUCores        int    `json:"cpuCores"`
	GPUMode         int    `json:"gpuMode"`
	NetworkMode     int    `json:"networkMode"`
	DisplayOpen     bool   `json:"displayOpen"`
}

// Display is the agent's passive display-driver readiness report.
type Display struct {
	Open  bool `json:"open"`
	Ready bool `json:"ready"`
}

// Template identifies a native Windows template. The inventory does not
// report its storage path or establish ownership.
type Template struct {
	Name   string `json:"name"`
	OSType string `json:"osType"`
}

// Branch and Snapshot retain native indices, including negative base indices.
type Branch struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
}

type Snapshot struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	BranchCount int      `json:"branchCount"`
	Branches    []Branch `json:"branches"`
}

// SnapshotTree is passive inventory, never an instruction to reset a VM.
type SnapshotTree struct {
	Current struct {
		SnapshotIndex int `json:"snapIndex"`
		BranchIndex   int `json:"branchIndex"`
	} `json:"current"`
	Snapshots    []Snapshot `json:"snapshots"`
	BaseBranches []Branch   `json:"baseBranches"`
}

// SSH reports the loopback forwarding endpoint. It contains no private key
// and does not prove ownership, authentication success, or desktop readiness.
type SSH struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	State       int    `json:"sshState"`
	Enabled     bool   `json:"enabled"`
	KeyDeployed bool   `json:"keyDeployed"`
}

// ForwardReady reports only the native key-enabled loopback forwarding state.
// State 4 is App Sandbox 0.1.9's SSH_READY_KEY report. A future provider must
// separately bind this endpoint to owned native storage and authenticate it.
func (s SSH) ForwardReady() bool {
	return s.Host == "127.0.0.1" && s.Port >= 1 && s.Port <= 65535 && s.User != "" && s.Enabled && s.KeyDeployed && s.State == 4
}

// Templates reads the template inventory without claiming any entry.
func (c *Client) Templates(ctx context.Context) ([]Template, error) {
	var body struct {
		Templates []Template `json:"templates"`
	}
	err := c.get(ctx, "/templates", &body)
	return body.Templates, err
}

// Snapshots reads a VM's snapshot tree without disk or lifecycle mutation.
func (c *Client) Snapshots(ctx context.Context, name string) (SnapshotTree, error) {
	var tree SnapshotTree
	path, err := vmPath(name)
	if err != nil {
		return tree, err
	}
	err = c.get(ctx, path+"/snapshots", &tree)
	return tree, err
}

// SSHInfo reads the native forwarding state without connecting to the guest.
func (c *Client) SSHInfo(ctx context.Context, name string) (SSH, error) {
	var ssh SSH
	path, err := vmPath(name)
	if err != nil {
		return ssh, err
	}
	err = c.get(ctx, path+"/sshInfo", &ssh)
	return ssh, err
}

// Host reads host capacity without modifying guests.
func (c *Client) Host(ctx context.Context) (Host, error) {
	var h Host
	err := c.get(ctx, "/host", &h)
	return h, err
}

// List reads the daemon's VM inventory; every VM is treated as foreign.
func (c *Client) List(ctx context.Context) ([]VM, error) {
	var body struct {
		VMs []VM `json:"vms"`
	}
	err := c.get(ctx, "/vms", &body)
	return body.VMs, err
}

// Status reads one VM's live status without starting or adopting it.
func (c *Client) Status(ctx context.Context, name string) (VM, error) {
	var v VM
	path, err := vmPath(name)
	if err != nil {
		return v, err
	}
	err = c.get(ctx, path, &v)
	return v, err
}

// DisplayStatus is passive; it never opens a window or consumes frames.
func (c *Client) DisplayStatus(ctx context.Context, name string) (Display, error) {
	var d Display
	path, err := vmPath(name)
	if err != nil {
		return d, err
	}
	err = c.get(ctx, path+"/display", &d)
	return d, err
}
