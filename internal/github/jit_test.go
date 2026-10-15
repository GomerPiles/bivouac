package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestRESTJITRegistrationAndCleanup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	for _, target := range []struct{ url, scope string }{{"https://github.com/example-org", "/orgs/example-org"}, {"https://github.com/example-org/repo", "/repos/example-org/repo"}} {
		t.Run(target.scope, func(t *testing.T) {
			var tokens atomic.Int32
			var deleteStatus atomic.Int32
			deleteStatus.Store(http.StatusNoContent)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/app/installations/17/access_tokens" {
					tokens.Add(1)
					token, err := jwt.Parse(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
					if err != nil || !token.Valid {
						t.Error("invalid App JWT")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"token": "test-installation", "expires_at": time.Now().Add(time.Hour)})
					return
				}
				if r.Header.Get("Authorization") != "Bearer test-installation" || r.Header.Get("X-GitHub-Api-Version") == "" {
					t.Error("missing authenticated REST headers")
				}
				switch {
				case r.URL.Path == target.scope+"/actions/runners/generate-jitconfig":
					var body struct {
						Name   string   `json:"name"`
						Group  int      `json:"runner_group_id"`
						Labels []string `json:"labels"`
						Work   string   `json:"work_folder"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Name != "bivouac-test" || body.Group != 1 || body.Work != "_work" || len(body.Labels) != 1 {
						t.Errorf("incorrect JIT settings: %+v", body)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = fmt.Fprint(w, `{"runner":{"id":42,"name":"bivouac-test"},"encoded_jit_config":"test-config"}`)
				case r.Method == http.MethodGet && r.URL.Path == target.scope+"/actions/runners":
					if r.URL.Query().Get("name") != "bivouac-test" {
						t.Error("missing name filter")
					}
					_, _ = fmt.Fprint(w, `{"runners":[{"id":99,"name":"other"},{"id":42,"name":"bivouac-test"}]}`)
				case r.Method == http.MethodDelete && r.URL.Path == target.scope+"/actions/runners/42":
					w.WriteHeader(int(deleteStatus.Load()))
					if deleteStatus.Load() != http.StatusNoContent {
						_, _ = fmt.Fprint(w, `secret-body with 404 request ID`)
					}
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					w.WriteHeader(500)
				}
			}))
			defer srv.Close()
			c, err := NewJITClient(target.url, AppAuth{ClientID: "123", InstallationID: 17, PrivateKeyPEM: encoded}, "test")
			if err != nil {
				t.Fatal(err)
			}
			c.base, c.http = srv.URL, srv.Client()
			cfg, err := c.GenerateRunnerJIT(t.Context(), "bivouac-test", "default", []string{"bivouac-experimental"}, "_work")
			if err != nil || cfg.RunnerID != 42 || string(cfg.Encoded) != "test-config" {
				t.Fatalf("JIT: %+v %v", cfg, err)
			}
			id, err := c.RunnerByName(t.Context(), "bivouac-test")
			if err != nil || id != 42 {
				t.Fatalf("lookup: %d %v", id, err)
			}
			if err := c.RemoveRunner(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			deleteStatus.Store(http.StatusBadRequest)
			if err := c.RemoveRunner(t.Context(), id); err == nil || strings.Contains(err.Error(), "secret-body") || strings.Contains(err.Error(), "404") {
				t.Fatalf("busy error lost or leaked: %v", err)
			}
			deleteStatus.Store(http.StatusNotFound)
			if err := c.RemoveRunner(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			if tokens.Load() != 1 {
				t.Fatalf("installation token not reused: %d", tokens.Load())
			}
		})
	}
}

func TestRESTRefreshesRejectedInstallationToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	var tokens atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/17/access_tokens" {
			n := tokens.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("installation-%d", n), "expires_at": time.Now().Add(time.Hour)})
			return
		}
		if r.Header.Get("Authorization") == "Bearer installation-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer installation-2" {
			t.Error("incorrect refreshed token")
		}
		_, _ = fmt.Fprint(w, `{"runners":[]}`)
	}))
	defer srv.Close()
	c, err := NewJITClient("https://github.com/example-org", AppAuth{ClientID: "123", InstallationID: 17, PrivateKeyPEM: encoded}, "test")
	if err != nil {
		t.Fatal(err)
	}
	c.base, c.http = srv.URL, srv.Client()
	id, err := c.RunnerByName(t.Context(), "bivouac-test")
	if err != nil || id != 0 || tokens.Load() != 2 {
		t.Fatalf("refresh failed: %d %v requests=%d", id, err, tokens.Load())
	}
}

func TestRESTAuthentication404DoesNotReleaseRunner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/17/access_tokens" {
			t.Error("unexpected request before authentication")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, err := NewJITClient("https://github.com/example-org", AppAuth{ClientID: "123", InstallationID: 17, PrivateKeyPEM: encoded}, "test")
	if err != nil {
		t.Fatal(err)
	}
	c.base, c.http = srv.URL, srv.Client()
	if err := c.RemoveRunner(t.Context(), 42); err == nil {
		t.Fatal("authentication failure mistaken for missing runner")
	}
}
