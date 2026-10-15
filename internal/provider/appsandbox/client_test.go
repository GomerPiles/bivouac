package appsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureCredential = "synthetic-fixture"
const fixtureVersion = `{"product":"AppSandbox","version":"0.1.9","apiVersion":"v1","hostOs":"Windows","capabilities":{"snapshots":true,"templates":true}}`

func discoveryFixture(t *testing.T, endpoint string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{"endpoint": endpoint, "token": fixtureCredential})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectionRoutes(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+fixtureCredential {
			t.Error("unexpected method or credential")
		}
		var body string
		switch r.URL.Path {
		case "/v1/version":
			body = fixtureVersion
		case "/v1/host":
			body = `{"hostCores":16,"hostRamMb":65536,"freeGb":234.5,"vmCores":4,"vmRamMb":8192,"vmHddGb":80,"defaultDiskDirectory":"D:\\VMs"}`
		case "/v1/vms":
			body = `{"vms":[{"name":"foreign-vm","osType":"Windows","state":"online","running":true,"ramMb":8192,"cpuCores":4,"gpuMode":1,"networkMode":1,"displayOpen":true}],"ignored":"synthetic-fixture"}`
		case "/v1/vms/foreign-vm":
			body = `{"name":"foreign-vm","state":"online","agentOnline":true,"installComplete":true,"running":true,"diskDirectory":"D:\\VMs"}`
		case "/v1/vms/foreign-vm/display":
			body = `{"open":false,"ready":true}`
		case "/v1/templates":
			body = `{"templates":[{"name":"foreign-tpl","osType":"Windows"}],"token":"synthetic-fixture"}`
		case "/v1/vms/foreign-vm/snapshots":
			body = `{"current":{"snapIndex":-2,"branchIndex":1},"snapshots":[{"index":0,"name":"clean","branchCount":1,"branches":[{"index":0,"name":"job"}]}],"baseBranches":[{"index":1,"name":"base-job"}]}`
		case "/v1/vms/foreign-vm/sshInfo":
			body = `{"host":"127.0.0.1","port":2200,"user":"runner","sshState":4,"enabled":true,"keyDeployed":true,"privateKey":"synthetic-fixture"}`
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer s.Close()
	ctx := context.Background()
	c, err := Open(ctx, discoveryFixture(t, s.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := c.Version(ctx)
	if err != nil || !v.Capabilities.Snapshots || v.Version != "0.1.9" {
		t.Fatalf("version: %+v %v", v, err)
	}
	h, err := c.Host(ctx)
	if err != nil || h.HostRAMMB != 65536 || h.FreeGB != 234.5 || h.DefaultDiskDirectory != `D:\VMs` {
		t.Fatalf("host: %+v %v", h, err)
	}
	vms, err := c.List(ctx)
	if err != nil || len(vms) != 1 || vms[0].NetworkMode != 1 || vms[0].GPUMode != 1 {
		t.Fatalf("inventory: %+v %v", vms, err)
	}
	vm, err := c.Status(ctx, "foreign-vm")
	if err != nil || !vm.AgentOnline || vm.Name != "foreign-vm" || vm.DiskDirectory != `D:\VMs` {
		t.Fatalf("status: %+v %v", vm, err)
	}
	d, err := c.DisplayStatus(ctx, "foreign-vm")
	if err != nil || !d.Ready || d.Open {
		t.Fatalf("display: %+v %v", d, err)
	}
	templates, err := c.Templates(ctx)
	if err != nil || len(templates) != 1 || templates[0].Name != "foreign-tpl" || templates[0].OSType != "Windows" {
		t.Fatalf("templates: %+v %v", templates, err)
	}
	tree, err := c.Snapshots(ctx, "foreign-vm")
	if err != nil || tree.Current.SnapshotIndex != -2 || tree.Current.BranchIndex != 1 || len(tree.Snapshots) != 1 || tree.Snapshots[0].Branches[0].Name != "job" || tree.BaseBranches[0].Index != 1 {
		t.Fatalf("snapshots: %+v %v", tree, err)
	}
	ssh, err := c.SSHInfo(ctx, "foreign-vm")
	if err != nil || !ssh.ForwardReady() {
		t.Fatalf("SSH: %+v %v", ssh, err)
	}
	metadata, err := json.Marshal([]any{templates, tree, ssh})
	if err != nil || strings.Contains(string(metadata), fixtureCredential) {
		t.Fatal("metadata serialization exposed ignored credential fields")
	}
	if _, err := c.Status(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../vm", "vm?token", "vm/path", "vm%2fpath", "-vm", strings.Repeat("a", 64)} {
		if _, err := c.Status(ctx, name); err == nil {
			t.Fatal("accepted unsafe VM name")
		}
		if _, err := c.Snapshots(ctx, name); err == nil {
			t.Fatal("snapshot route accepted unsafe VM name")
		}
		if _, err := c.SSHInfo(ctx, name); err == nil {
			t.Fatal("SSH route accepted unsafe VM name")
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%+v", *c), fmt.Sprintf("%#v", *c), string(encoded)} {
		if strings.Contains(value, fixtureCredential) {
			t.Fatal("client formatting leaked credential")
		}
	}
}

func TestSSHForwardReadiness(t *testing.T) {
	ready := SSH{Host: "127.0.0.1", Port: 2200, User: "runner", State: 4, Enabled: true, KeyDeployed: true}
	if !ready.ForwardReady() {
		t.Fatal("rejected ready native forwarding")
	}
	for _, change := range []func(*SSH){
		func(s *SSH) { s.Host = "localhost" },
		func(s *SSH) { s.Host = "192.168.1.1" },
		func(s *SSH) { s.Host = "::1" },
		func(s *SSH) { s.Port = 0 },
		func(s *SSH) { s.Port = 65536 },
		func(s *SSH) { s.User = "" },
		func(s *SSH) { s.Enabled = false },
		func(s *SSH) { s.KeyDeployed = false },
		func(s *SSH) { s.State = 2 },
	} {
		s := ready
		change(&s)
		if s.ForwardReady() {
			t.Fatal("accepted incomplete or non-loopback native forwarding")
		}
	}
}

func TestRejectDiscovery(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("accepted missing discovery file")
	}
	for _, endpoint := range []string{
		"https://127.0.0.1:1234", "http://localhost:1234", "http://[::1]:1234", "http://192.168.1.1:1234", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:01234", "http://user@127.0.0.1:1234", "http://127.0.0.1:1234/path", "http://127.0.0.1:1234?", "http://127.0.0.1:1234#fragment", "http://127.0.0.1:1234?token=synthetic-fixture",
	} {
		if _, err := newClient(endpoint, fixtureCredential); err == nil || strings.Contains(err.Error(), fixtureCredential) {
			t.Fatalf("unsafe endpoint accepted or echoed: %v", err)
		}
	}
	for _, token := range []string{"", "a\nb", "a b", "a\x00b", strings.Repeat("a", 4097)} {
		if _, err := newClient("http://127.0.0.1:1234", token); err == nil {
			t.Fatal("accepted invalid credential")
		}
	}
	for _, body := range []string{"{invalid", `{"endpoint":123,"token":"synthetic-fixture"}`, strings.Repeat("x", maxDiscoveryBytes+1)} {
		path := filepath.Join(t.TempDir(), "host.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), path); err == nil || strings.Contains(err.Error(), fixtureCredential) {
			t.Fatalf("bad discovery: %v", err)
		}
	}
}

func TestNoRedirectOrProxy(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		_, _ = w.Write([]byte(fixtureVersion))
	}))
	defer target.Close()
	t.Setenv("HTTP_PROXY", target.URL)
	t.Setenv("http_proxy", target.URL)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/?credential="+fixtureCredential, http.StatusFound)
	}))
	defer s.Close()
	c, err := newClient(s.URL, fixtureCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.transport.Proxy != nil {
		t.Fatal("ambient proxy configured")
	}
	_, err = c.Version(context.Background())
	var status *HTTPError
	if !errors.As(err, &status) || status.StatusCode != http.StatusFound || strings.Contains(err.Error(), fixtureCredential) {
		t.Fatalf("redirect: %v", err)
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect/proxy received request")
	}
}

func TestInvalidResponsesAndIdentity(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"product":"AnotherServer"}`, `{"product":"AppSandbox","version":"0.1.9","hostOs":"Windows"}`, `{"product":"AppSandbox","version":"0.1.9","apiVersion":null,"hostOs":"Windows"}`, `{"product":123,"token":"synthetic-fixture"}`, `{bad synthetic-fixture`, strings.Repeat("x", maxResponseBytes+1)} {
		t.Run(fmt.Sprintf("body-%d", len(body)), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			if _, err := Open(context.Background(), discoveryFixture(t, s.URL)); err == nil || strings.Contains(err.Error(), fixtureCredential) {
				t.Fatalf("invalid identity/response: %v", err)
			}
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(fixtureCredential))
	}))
	defer s.Close()
	if _, err := Open(context.Background(), discoveryFixture(t, s.URL)); err == nil || strings.Contains(err.Error(), fixtureCredential) {
		t.Fatalf("status leaked body: %v", err)
	}
}

func TestRequestCancellationAndStaleDiscovery(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	c, err := newClient(s.URL, fixtureCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Version(ctx); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	s.Close()
	if _, err := c.Version(context.Background()); err == nil {
		t.Fatal("accepted stale discovery")
	}
}
