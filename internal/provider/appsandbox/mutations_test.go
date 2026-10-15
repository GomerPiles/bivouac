package appsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNativeCreatePinsNoNetworkAndRedactsFailure(t *testing.T) {
	_, _, _, record := engineFixture(t)
	password := "synthetic-password-long-enough"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/vms" || r.Header.Get("Authorization") != "Bearer "+fixtureCredential {
			t.Error("wrong create route")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid create body")
		}
		if body["name"] != record.NativeName || body["diskDirectory"] != record.StorageParent || body["templateName"] != record.Template || body["networkMode"] != float64(0) || body["gpuMode"] != float64(1) || body["isTemplate"] != false || body["adminPass"] != password {
			t.Error("create intent differs")
		}
		w.WriteHeader(500)
		_, _ = w.Write([]byte(password + " " + fixtureCredential))
	}))
	defer server.Close()
	c, err := newClient(server.URL, fixtureCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.CreateClone(context.Background(), record, "ciuser", password)
	if err == nil || strings.Contains(err.Error(), password) || strings.Contains(err.Error(), fixtureCredential) {
		t.Fatal("native failure exposed credentials")
	}
	if calls.Load() != 1 {
		t.Fatal("create retried")
	}
	for _, operation := range []string{"display", "daemonShutdown", "snapshot", "../delete"} {
		if err := c.VMCommand(context.Background(), record.NativeName, operation); err == nil {
			t.Fatal("arbitrary native operation accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid operation reached native API")
	}
}
func TestLostCreateResponseNeverRetries(t *testing.T) {
	_, _, _, record := engineFixture(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server cannot hijack")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}))
	defer server.Close()
	c, err := newClient(server.URL, fixtureCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.CreateClone(context.Background(), record, "ciuser", "synthetic-password-long-enough"); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("ambiguous POST was retried")
	}
}
