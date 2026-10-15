package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppSandboxInspectWithoutHostSetup(t *testing.T) {
	// This must not load config, GitHub credentials, or create state dirs.
	home := filepath.Join(t.TempDir(), "unused-home")
	t.Setenv("BIVOUAC_HOME", home)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("unexpected request")
		}
		switch r.URL.Path {
		case "/v1/version":
			_, _ = w.Write([]byte(`{"product":"AppSandbox","version":"0.1.9","apiVersion":1,"hostOs":"Windows"}`))
		case "/v1/host":
			_, _ = w.Write([]byte(`{"hostCores":8,"hostRamMb":32768}`))
		case "/v1/vms":
			_, _ = w.Write([]byte(`{"vms":[{"name":"foreign-vm","state":"stopped","token":"synthetic"}]}`))
		case "/v1/templates":
			_, _ = w.Write([]byte(`{"templates":[{"name":"foreign-tpl","osType":"Windows","token":"synthetic"}]}`))
		default:
			t.Error("unexpected route")
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	data, err := json.Marshal(map[string]string{"endpoint": s.URL, "token": "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := appsandboxCmd(context.Background(), []string{"inspect", "--discovery", path}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "synthetic") || !strings.Contains(out.String(), `"foreign_vms"`) || !strings.Contains(out.String(), `"foreign_templates"`) || !strings.Contains(out.String(), `"foreign-tpl"`) || !json.Valid(out.Bytes()) {
		t.Fatal("unexpected inspection output")
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection touched host setup: %v", err)
	}
	for _, args := range [][]string{nil, {"start"}, {"inspect", "extra"}} {
		if err := appsandboxCmd(context.Background(), args, &out); !errors.Is(err, errUsage) {
			t.Fatalf("invalid command must fail before contacting the default daemon: %v", err)
		}
	}
}
