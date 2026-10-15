package cache

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuestCachePrivateSetupEnvironmentAndRemoval(t *testing.T) {
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	_, b, _ := testService(t, backend)
	dir := filepath.Join(t.TempDir(), "guest directory")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	// No release proxy: this test never touches the host trust store.
	if err = PrepareGuest(context.Background(), dir, data); err != nil {
		t.Fatal(err)
	}
	env, cleanup, err := GuestEnvironment(dir)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	merged := MergeEnvironment([]string{"Node_Options=stale", "HTTPS_PROXY=original", "KEEP=value"}, env)
	options := 0
	for _, value := range merged {
		if strings.Contains(value, b.Token) || strings.Contains(value, "CERTIFICATE") {
			t.Fatal("capability or trust contents escaped into environment")
		}
		if strings.HasPrefix(value, "NODE_OPTIONS=") {
			options++
			if !strings.Contains(value, `--require="`+filepath.ToSlash(filepath.Join(dir, "cache-preload.cjs"))+`"`) {
				t.Fatal("preload path not quoted")
			}
		}
	}
	if options != 1 {
		t.Fatal("case-insensitive environment replacement failed")
	}
	if err = RemoveGuest(dir); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("private cache configuration retained")
	}
	env, cleanup, err = GuestEnvironment(dir)
	if err != nil || len(env) != 0 {
		t.Fatal("missing adapter did not restore normal downloads")
	}
	cleanup()
}

func TestGuestEnvironmentLoadsNodePreloadWithSpacesAndWindowsPaths(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is required to verify the actual preload environment")
	}
	backend := httptest.NewTLSServer(http.NotFoundHandler())
	defer backend.Close()
	_, b, _ := testService(t, backend)
	dir := filepath.Join(t.TempDir(), "guest directory")
	if err = os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err = PrepareGuest(context.Background(), dir, data); err != nil {
		t.Fatal(err)
	}
	values, cleanup, err := GuestEnvironment(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Cold Node startup can consume the former ten-second bound on hosted
	// Windows. This remains an isolated loopback probe with a bounded lifetime.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	program := `const https=require('node:https');const req=https.request(process.argv[1]+'/probe',res=>{res.resume();res.on('end',()=>{if(res.statusCode!==404)process.exitCode=2;});});req.on('error',()=>process.exitCode=3);req.end();`
	cmd := exec.CommandContext(ctx, node, "-e", program, b.URL)
	cmd.Env = MergeEnvironment(os.Environ(), values)
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatal("Node cache preload probe exceeded its test deadline")
		}
		t.Fatal("Node did not load the cache preload or trust its endpoint from the actual runner environment")
	}
}
