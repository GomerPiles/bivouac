package vz

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GomerPiles/bivouac/internal/cache"
)

// Exercise real Node HTTPS streams: deferred metadata must preserve end/close
// ordering, authorize a lease, and retain the upstream URL on service failure.
func TestCachePreloadStreamAndFailOpen(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node needed for guest adapter integration")
	}
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "upstream"}[unavailable], func(t *testing.T) {
			const token = "test-capability"
			const upstream = "https://example.blob.core.windows.net/archive?sig=fixture"
			var cacheURL string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/lease" {
					if r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("capability missing")
					}
					if unavailable {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"url": cacheURL + "/object/lease"})
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"ok":true,"matched_key":"original-key","signed_download_url":"`+upstream+`"}`)
			}))
			defer server.Close()
			cacheURL = server.URL
			dir := t.TempDir()
			preload := filepath.Join(dir, "preload.cjs")
			configPath := filepath.Join(dir, "config.json")
			script := filepath.Join(dir, "check.cjs")
			_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
			data, _ := json.Marshal(map[string]string{"url": server.URL, "token": token, "ca": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))})
			expected := cacheURL + "/object/lease"
			if unavailable {
				expected = upstream
			}
			program := `const https=require('node:https');let closed=false;let ended=false;
const req=https.request({hostname:'unit.actions.githubusercontent.com',port:process.argv[2],path:'/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',method:'POST',lookup:(host,opts,cb)=>cb(null,opts.all?[{address:'127.0.0.1',family:4}]:'127.0.0.1',4),rejectUnauthorized:false},res=>{
let data='';res.on('data',c=>data+=c);res.on('end',()=>{ended=true;let body=JSON.parse(data);if(body.matched_key!=='original-key'||body.signed_download_url!==process.argv[3])process.exitCode=2;});res.on('close',()=>{closed=true;if(!ended)process.exitCode=3;});});req.on('error',e=>{console.error(e.message);process.exitCode=4;});req.end('{}');process.on('beforeExit',()=>{if(!closed||!ended){console.error({closed,ended});process.exitCode=5;};});`
			for name, contents := range map[string][]byte{preload: cache.Preload(), configPath: data, script: []byte(program)} {
				if err := os.WriteFile(name, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, script, port, expected)
			cmd.Env = append(os.Environ(), "NODE_OPTIONS=--require="+preload, "BIVOUAC_CACHE_CONFIG="+configPath)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Node adapter: %v, %s", err, output)
			}
		})
	}
}
