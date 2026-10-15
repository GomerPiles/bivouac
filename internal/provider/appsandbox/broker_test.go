package appsandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/provider"
	"github.com/GomerPiles/bivouac/internal/redact"
	"github.com/GomerPiles/bivouac/internal/secret"
)

func TestBrokerFailureDiagnosticsStayOutOfResponseAndRedactAtSink(t *testing.T) {
	e, api, _, record := engineFixture(t)
	const sensitive = "ghs_abcdefghijklmnopqrstuvwxyz123456"
	api.createErr = fmt.Errorf("synthetic native failure %s", sensitive)
	var output bytes.Buffer
	sink := redact.NewWriter(&output)
	log := slog.New(slog.NewTextHandler(sink, nil))
	handler := brokerHandler(e, fixtureCredential, func(operation, name string, err error) {
		log.Warn("native lifecycle operation failed", "operation", operation, "instance", name, "error", err)
	})
	body, err := json.Marshal(brokerRequest{Operation: "create", Clone: &record})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/operation", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+fixtureCredential)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if response.Code != 503 || response.Body.Len() != 0 {
		t.Fatal("native diagnostics crossed broker boundary")
	}
	if strings.Contains(output.String(), sensitive) || strings.Contains(output.String(), fixtureCredential) || !strings.Contains(output.String(), "synthetic native failure") || !strings.Contains(output.String(), "<redacted>") {
		t.Fatal("failure diagnostics missing or unredacted")
	}
}

func TestBrokerRejectsUnauthenticatedAndArbitraryOperations(t *testing.T) {
	e, a, _, _ := engineFixture(t)
	handler := BrokerHandler(e, fixtureCredential)
	for _, tc := range []struct {
		method, path, auth, body string
		code                     int
	}{
		{"GET", "/v1/info", "", "", 401},
		{"GET", "/v1/info", fixtureCredential, "", 401},
		{"GET", "/v1/info", "Bearer wrong", "", 401},
		{"GET", "/v1/info?token=anything", "Bearer " + fixtureCredential, "", 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, `{"operation":"exec","name":"bivouac-test-1234abcd"}`, 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, `{"operation":"list","command":"whoami"}`, 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, `{"operation":"list"}{}`, 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, `{"operation":"delete","name":"../../foreign"}`, 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, `{"operation":"list","timeout_ms":1}`, 400},
		{"POST", "/v1/operation", "Bearer " + fixtureCredential, strings.Repeat(" ", 65537), 400},
		{"DELETE", "/v1/info", "Bearer " + fixtureCredential, "", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.path, w.Code, tc.code)
		}
		if strings.Contains(w.Body.String(), fixtureCredential) {
			t.Fatal("credential in response")
		}
	}
	if len(a.calls) != 0 {
		t.Fatal("invalid request mutated native state")
	}
}

func TestBrokerRoundTripAndOwnershipError(t *testing.T) {
	e, a, _, r := engineFixture(t)
	server := httptest.NewServer(BrokerHandler(e, fixtureCredential))
	defer server.Close()
	data, err := json.Marshal(brokerCredential{Endpoint: server.URL, Token: fixtureCredential})
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenBroker(context.Background(), secret.Memory{"broker": data}, "broker", r.Meta.ControllerID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, formatted := range []string{fmt.Sprint(c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(formatted, fixtureCredential) {
			t.Fatal("client formatting leaked capability")
		}
	}
	foreign := r
	foreign.StorageParent = e.Root()
	if err := c.Create(context.Background(), foreign); !errors.Is(err, provider.ErrNotOwned) {
		t.Fatal(err)
	}
	if len(a.calls) != 0 {
		t.Fatal("foreign create reached native API")
	}
	if err := c.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got, err := c.Lookup(context.Background(), r.RunnerName)
	if err != nil || got.Record != r {
		t.Fatalf("lookup: %v", err)
	}
	if err := c.Delete(context.Background(), r.RunnerName); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lookup(context.Background(), r.RunnerName); !errors.Is(err, provider.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestBrokerIdentityCannotBeReplaced(t *testing.T) {
	e, _, _, r := engineFixture(t)
	server := httptest.NewServer(BrokerHandler(e, fixtureCredential))
	defer server.Close()
	data, err := json.Marshal(brokerCredential{Endpoint: server.URL, Token: fixtureCredential})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBroker(context.Background(), secret.Memory{"broker": data}, "broker", r.Meta.ControllerID+"other"); err == nil {
		t.Fatal("another controller's broker accepted")
	}
}

// contextAPI fails a native call whose context has ended, as the real client
// does, and rejects calls without the broker's operation bound.
type contextAPI struct{ NativeAPI }

func (contextAPI) check(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > brokerOperationTimeout {
		return errors.New("unbounded privileged operation")
	}
	return ctx.Err()
}
func (a contextAPI) CreateClone(ctx context.Context, r CloneRecord, user, password string) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.NativeAPI.CreateClone(ctx, r, user, password)
}
func (a contextAPI) VMCommand(ctx context.Context, name, action string) error {
	if err := a.check(ctx); err != nil {
		return err
	}
	return a.NativeAPI.VMCommand(ctx, name, action)
}
func (a contextAPI) Status(ctx context.Context, name string) (VM, error) {
	if err := a.check(ctx); err != nil {
		return VM{}, err
	}
	return a.NativeAPI.Status(ctx, name)
}

func TestBrokerOperationsSurviveClientDisconnect(t *testing.T) {
	e, a, _, r := engineFixture(t)
	e.api = contextAPI{a}
	handler := BrokerHandler(e, fixtureCredential)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for _, request := range []brokerRequest{
		{Operation: "create", Clone: &r},
		{Operation: "stop", Name: r.RunnerName, TimeoutMS: 1000},
		{Operation: "delete", Name: r.RunnerName},
	} {
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/v1/operation", bytes.NewReader(body)).WithContext(gone)
		req.Header.Set("Authorization", "Bearer "+fixtureCredential)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s interrupted by client disconnect: %d", request.Operation, w.Code)
		}
	}
	if !slices.Equal(a.calls, []string{"create", "shutdown", "delete"}) {
		t.Fatalf("lifecycle sequence: %v", a.calls)
	}
	if _, err := e.records.Get(r.RunnerName); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("detached delete did not finish")
	}
}

func TestBrokerClientOutlastsLongestOperation(t *testing.T) {
	e, _, _, r := engineFixture(t)
	server := httptest.NewServer(BrokerHandler(e, fixtureCredential))
	defer server.Close()
	data, err := json.Marshal(brokerCredential{Endpoint: server.URL, Token: fixtureCredential})
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenBroker(context.Background(), secret.Memory{"broker": data}, "broker", r.Meta.ControllerID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.transport.ResponseHeaderTimeout <= brokerOperationTimeout || brokerClientTimeout <= brokerOperationTimeout || c.transport.Proxy != nil {
		t.Fatal("broker client can abandon a sequence the broker is still finishing")
	}
	// The manager bounds each call by the advertised operation timeout.
	if (&Provider{}).Capabilities().OperationTimeout <= brokerClientTimeout {
		t.Fatal("manager can abandon a broker call the client is still waiting for")
	}
}
