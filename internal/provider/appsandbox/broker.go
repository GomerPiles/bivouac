package appsandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/secret"
)

const brokerProduct = "bivouac-appsandbox-broker"
const brokerPolicy = "vfp-public-ipv4-v1"

// brokerOperationTimeout bounds one privileged lifecycle sequence. The longest
// is a graceful stop: a 30 s shutdown dispatch, up to 30 s of polling, a 30 s
// hard stop and bounded status lookups. Native calls carry their own shorter
// deadlines; this only keeps a wedged sequence from holding the engine forever.
const brokerOperationTimeout = 150 * time.Second

// brokerClientTimeout exceeds brokerOperationTimeout so the normal-user client
// never abandons (and reports ErrOutcomeUnknown for) a sequence the broker is
// still allowed to finish.
const brokerClientTimeout = 3 * time.Minute

// operationTimeout is the provider's advertised per-call bound. It exceeds
// brokerClientTimeout, so the client, not the manager, ends a broker call.
const operationTimeout = brokerClientTimeout + 30*time.Second

type BrokerInfo struct {
	Product      string `json:"product"`
	Protocol     int    `json:"protocol"`
	Policy       string `json:"policy"`
	Root         string `json:"root"`
	ControllerID string `json:"controller_id"`
	Baseline     string `json:"baseline"`
	MaxCPU       int    `json:"max_cpu"`
	MaxMemoryMB  int    `json:"max_memory_mb"`
	MaxDiskGB    int    `json:"max_disk_gb"`
	MaxInstances int    `json:"max_instances"`
}
type brokerCredential struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}
type brokerRequest struct {
	Operation string       `json:"operation"`
	Name      string       `json:"name,omitempty"`
	Clone     *CloneRecord `json:"clone,omitempty"`
	TimeoutMS int64        `json:"timeout_ms,omitempty"`
}
type brokerList struct {
	Owned   []provider.Owned   `json:"owned"`
	Foreign []provider.Foreign `json:"foreign"`
}

// BrokerHandler exposes a fixed VM lifecycle, not an administrator command
// executor. The authenticated normal-user caller cannot supply disks, network
// settings, templates, executables, credentials, or guest command lines.
func BrokerHandler(engine *Engine, token string) http.Handler {
	return brokerHandler(engine, token, nil)
}

func brokerHandler(engine *Engine, token string, report func(string, string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || token == "" || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var result any
		var err error
		operation, name := "info", ""
		if r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == "/v1/info" && r.Method == http.MethodGet:
			result = BrokerInfo{Product: brokerProduct, Protocol: 1, Policy: brokerPolicy, Root: engine.Root(), ControllerID: engine.opts.ControllerID, Baseline: engine.opts.Baseline, MaxCPU: engine.opts.MaxCPU, MaxMemoryMB: engine.opts.MaxMemoryMB, MaxDiskGB: engine.opts.MaxDiskGB, MaxInstances: engine.opts.MaxInstances}
		case r.URL.Path == "/v1/operation" && r.Method == http.MethodPost:
			var request brokerRequest
			reader := http.MaxBytesReader(w, r.Body, 64*1024)
			decoder := json.NewDecoder(reader)
			decoder.DisallowUnknownFields()
			if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.TimeoutMS < 0 || request.TimeoutMS > 30000 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.Operation != "create" && request.Clone != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.Operation != "stop" && request.TimeoutMS != 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.Operation != "list" && request.Operation != "create" {
				if _, err = instanceKey(request.Name); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}
			operation, name = request.Operation, request.Name
			// A client disconnect or timeout must not interrupt a half-finished
			// native sequence (for example between a graceful shutdown and the
			// hard stop). Operations run detached from the request, but bounded.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), brokerOperationTimeout)
			defer cancel()
			switch request.Operation {
			case "create":
				if request.Clone == nil || request.Name != "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				err = engine.Create(ctx, *request.Clone)
			case "lookup":
				result, err = engine.Lookup(ctx, request.Name)
			case "start":
				err = engine.Start(ctx, request.Name)
			case "prepare":
				result, err = engine.Prepare(ctx, request.Name)
			case "verify":
				err = engine.Verify(ctx, request.Name)
			case "stop":
				err = engine.Stop(ctx, request.Name, time.Duration(request.TimeoutMS)*time.Millisecond)
			case "delete":
				err = engine.Delete(ctx, request.Name)
			case "list":
				var list brokerList
				list.Owned, list.Foreign, err = engine.List(ctx)
				result = list
			default:
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			if report != nil {
				report(operation, name, err)
			}
			// Typed codes preserve cleanup semantics without exposing diagnostics,
			// paths, request bodies or credentials over the privileged boundary.
			code := http.StatusServiceUnavailable
			switch {
			case errors.Is(err, provider.ErrNotOwned):
				code = http.StatusForbidden
			case errors.Is(err, provider.ErrNotFound):
				code = http.StatusNotFound
			case errors.Is(err, ErrOutcomeUnknown):
				code = http.StatusConflict
			}
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if result == nil {
			result = struct {
				OK bool `json:"ok"`
			}{true}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
}

// ServeBroker publishes its per-run capability in the current user's native
// credential store. No plaintext discovery token file or host firewall opening
// is needed. Caller holds the protected root's exclusive lock for its lifetime.
func ServeBroker(ctx context.Context, engine *Engine, store secret.Store, item string, ready io.Writer) error {
	sink := redact.NewWriter(ready)
	defer func() { _ = sink.Close() }()
	log := slog.New(slog.NewTextHandler(sink, nil))
	// Check retained guests before exposing the broker. Failed policy blocks
	// admission, but keep the cleanup API available for protected records.
	if err := engine.Guard(ctx); err != nil {
		if _, writeErr := io.WriteString(ready, "Retained guest policy failed; cleanup only\n"); writeErr != nil {
			return writeErr
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(random[:])
	credential, err := json.Marshal(brokerCredential{Endpoint: "http://" + listener.Addr().String(), Token: token})
	if err != nil {
		return err
	}
	if err = store.Set(ctx, item, credential); err != nil {
		return err
	}
	defer func() {
		if current, getErr := store.Get(context.Background(), item); getErr == nil && bytes.Equal(current, credential) {
			_ = store.Delete(context.Background(), item)
		}
	}()
	handler := brokerHandler(engine, token, func(operation, name string, err error) {
		log.Warn("native lifecycle operation failed", "operation", operation, "instance", name, "error", err)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	guardCtx, stopGuard := context.WithCancel(ctx)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-guardCtx.Done():
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(guardCtx, 30*time.Second)
				if err := engine.Guard(checkCtx); err != nil {
					log.Warn("native policy guard failed", "error", err)
				}
				cancel()
			}
		}
	}()
	defer func() { stopGuard(); <-guardDone }()
	if _, err = io.WriteString(ready, "App Sandbox lifecycle broker ready on local loopback\n"); err != nil {
		_ = server.Close()
		return err
	}
	select {
	case <-ctx.Done():
		// Let an in-flight lifecycle sequence finish before the caller closes
		// the protected journal and native API.
		stop, cancel := context.WithTimeout(context.Background(), brokerOperationTimeout+10*time.Second)
		defer cancel()
		err = server.Shutdown(stop)
		if err != nil {
			_ = server.Close()
		}
		return err
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// BrokerClient is the normal-user Backend transport. Its capability never
// appears in formatting, JSON, command lines, errors or persistent VM records.
type BrokerClient struct {
	endpoint, token string
	http            *http.Client
	transport       *http.Transport
	info            BrokerInfo
}

func (*BrokerClient) String() string     { return "App Sandbox broker (credential redacted)" }
func (c *BrokerClient) GoString() string { return c.String() }
func (*BrokerClient) MarshalJSON() ([]byte, error) {
	return []byte(`"App Sandbox broker (credential redacted)"`), nil
}
func OpenBroker(ctx context.Context, store secret.Store, item, controllerID string) (*BrokerClient, error) {
	data, err := store.Get(ctx, item)
	if err != nil {
		return nil, errors.New("appsandbox broker credential unavailable; arrange elevated broker startup")
	}
	var credential brokerCredential
	if len(data) > 4096 || json.Unmarshal(data, &credential) != nil {
		return nil, errors.New("invalid broker credential")
	}
	// Reuse the native API client's strict endpoint/token validation only;
	// it does not contact the App Sandbox daemon or launch anything.
	if _, err = newClient(credential.Endpoint, credential.Token); err != nil {
		return nil, err
	}
	// The broker needs its own transport: the native client's 30 s header
	// timeout is shorter than a privileged stop, prepare or delete sequence.
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout:  brokerClientTimeout,
		IdleConnTimeout:        30 * time.Second,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: 32 * 1024,
		DisableCompression:     true,
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	c := &BrokerClient{endpoint: strings.TrimRight(credential.Endpoint, "/"), token: credential.Token, http: client, transport: transport}
	if err = c.request(ctx, nil, &c.info); err != nil {
		c.Close()
		return nil, err
	}
	if c.info.Product != brokerProduct || c.info.Protocol != 1 || c.info.Policy != brokerPolicy || c.info.ControllerID != controllerID || c.info.Root == "" || !identifier(c.info.Baseline, 15) {
		c.Close()
		return nil, errors.New("privileged broker identity or policy differs")
	}
	return c, nil
}
func (c *BrokerClient) Info() BrokerInfo { return c.info }
func (c *BrokerClient) Close()           { c.transport.CloseIdleConnections() }
func (c *BrokerClient) request(ctx context.Context, body *brokerRequest, out any) error {
	ctx, cancel := context.WithTimeout(ctx, brokerClientTimeout)
	defer cancel()
	method, path := http.MethodGet, "/v1/info"
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return errors.New("encode privileged operation")
		}
		input = bytes.NewReader(data)
		method = http.MethodPost
		path = "/v1/operation"
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, input)
	if err != nil {
		return errors.New("construct privileged operation")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		if body != nil {
			return errors.Join(ErrOutcomeUnknown, ctx.Err())
		}
		return errors.New("privileged broker unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return provider.ErrNotOwned
	case http.StatusNotFound:
		return provider.ErrNotFound
	case http.StatusConflict:
		return ErrOutcomeUnknown
	default:
		return errors.New("privileged lifecycle operation unavailable or rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return errors.New("invalid bounded broker response")
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errors.New("invalid broker response")
	}
	return nil
}
func (c *BrokerClient) Create(ctx context.Context, r CloneRecord) error {
	return c.request(ctx, &brokerRequest{Operation: "create", Clone: &r}, nil)
}
func (c *BrokerClient) Lookup(ctx context.Context, name string) (Lease, error) {
	var l Lease
	err := c.request(ctx, &brokerRequest{Operation: "lookup", Name: name}, &l)
	return l, err
}
func (c *BrokerClient) Start(ctx context.Context, name string) error {
	return c.request(ctx, &brokerRequest{Operation: "start", Name: name}, nil)
}
func (c *BrokerClient) Prepare(ctx context.Context, name string) (Lease, error) {
	var l Lease
	err := c.request(ctx, &brokerRequest{Operation: "prepare", Name: name}, &l)
	return l, err
}
func (c *BrokerClient) Verify(ctx context.Context, name string) error {
	return c.request(ctx, &brokerRequest{Operation: "verify", Name: name}, nil)
}
func (c *BrokerClient) Stop(ctx context.Context, name string, timeout time.Duration) error {
	return c.request(ctx, &brokerRequest{Operation: "stop", Name: name, TimeoutMS: min(max(timeout.Milliseconds(), 0), 30000)}, nil)
}
func (c *BrokerClient) Delete(ctx context.Context, name string) error {
	return c.request(ctx, &brokerRequest{Operation: "delete", Name: name}, nil)
}
func (c *BrokerClient) List(ctx context.Context) ([]provider.Owned, []provider.Foreign, error) {
	var list brokerList
	err := c.request(ctx, &brokerRequest{Operation: "list"}, &list)
	return list.Owned, list.Foreign, err
}
