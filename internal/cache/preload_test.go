package cache

import (
	"bytes"
	"context"
	"encoding/json"
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
)

// uploadProgram drives a real Node process the way the official cache action
// does: CreateCacheEntry, then the storage SDK's block requests with its retry
// rule (network errors, 500 and 503). It prints the URL the action received.
const uploadProgram = `const https=require('node:https');
const [port,mode]=process.argv.slice(1);
const rpc=(path,body)=>new Promise((resolve,reject)=>{const req=https.request({hostname:'unit.actions.githubusercontent.com',port,path,method:'POST',agent:false,rejectUnauthorized:false,lookup:(h,o,cb)=>cb(null,o.all?[{address:'127.0.0.1',family:4}]:'127.0.0.1',4),headers:{authorization:'Bearer runtime-token','content-type':'application/json'}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>resolve(d));});req.on('error',reject);req.end(body);});
const send=(url,headers,body)=>new Promise(resolve=>{const req=https.request(url,{method:'PUT',rejectUnauthorized:false,headers:{...headers,'content-length':Buffer.byteLength(body)}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',()=>resolve(0));req.end(body);});
async function put(url,headers,body){for(let i=0;i<4;i++){const status=await send(url,headers,body);if(status!==0&&status!==500&&status!==503)return status;}return 0;}
(async()=>{
const created=JSON.parse(await rpc('/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry','{"key":"k","version":"v"}'));
console.log(created.signed_upload_url);
if(mode==='revoke'||mode==='close')await rpc('/'+mode,'{}');
const target=created.signed_upload_url;
for(const [id,data] of [['AAAA','first-'],['AAAB','second']]){if(await put(target+(target.includes('?')?'&':'?')+'comp=block&blockid='+id,{'x-ms-version':'2020-04-08'},data)!==201)process.exit(2);}
if(await put(target+(target.includes('?')?'&':'?')+'comp=blocklist',{'content-type':'application/xml'},'<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>AAAA</Latest><Latest>AAAB</Latest></BlockList>')!==201)process.exit(3);
})().catch(e=>{console.error(e.message);process.exit(4);});`

func TestPreloadRelaysUploadsAndFallsBackToAzure(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node needed for the guest adapter")
	}
	for _, mode := range []string{"relay", "disabled", "revoke", "close"} {
		t.Run(mode, func(t *testing.T) {
			s, _, client, blob, upstream := uploadFixture(t)
			if mode == "disabled" {
				s.storing.Store(false)
			}
			data, err := s.Issue("guest") // Reissue: the bootstrap now carries store_uploads.
			if err != nil {
				t.Fatal(err)
			}
			var b Bootstrap
			if err = json.Unmarshal(data, &b); err != nil || b.StoreUploads != (mode != "disabled") {
				t.Fatal("bootstrap does not carry upload storage", err)
			}
			source := upstream + "/cache/node?sig=upload"
			rpc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/revoke":
					s.Revoke("guest")
				case "/close":
					s.Close()
				case "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry":
					if r.Header.Get("Authorization") != "Bearer runtime-token" {
						t.Error("runtime authorization lost")
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "signed_upload_url": source})
				default:
					t.Error("unexpected RPC", r.URL.Path)
				}
			}))
			defer rpc.Close()
			dir := t.TempDir()
			preload, settings := filepath.Join(dir, "preload.cjs"), filepath.Join(dir, "cache.json")
			for name, body := range map[string][]byte{preload: Preload(), settings: data} {
				if err := os.WriteFile(name, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, port, _ := net.SplitHostPort(strings.TrimPrefix(rpc.URL, "https://"))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, "-e", uploadProgram, port, mode)
			cmd.Env = MergeEnvironment(os.Environ(), []string{"NODE_OPTIONS=--require=" + preload, "BIVOUAC_CACHE_CONFIG=" + settings})
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("upload through preload failed: %v %s", err, stderr.String())
			}
			received := strings.TrimSpace(string(output))
			if relayed := strings.HasPrefix(received, b.URL+"/upload/"); relayed == (mode == "disabled") || strings.Contains(received, "sig=") == (mode != "disabled") {
				t.Fatal("action received the wrong upload URL", relayed)
			}
			if string(blob.blob("/cache/node")) != "first-second" {
				t.Fatal("Azure did not commit the archive")
			}
			if mode != "relay" {
				// Only the lease was counted: revocation and shutdown end it uncounted.
				want := UploadCounters{Relayed: 1}
				if mode == "disabled" {
					want = UploadCounters{}
				}
				if s.Snapshot().Uploads != want {
					t.Fatal("fallback stored an upload", s.Snapshot().Uploads)
				}
				return
			}
			// Storing at all proves the preload sent the guest token to the relay;
			// the fake Azure refuses any request carrying a credential.
			waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Stored: 1, StoredBytes: 12}})
			r, err := client.Get(makeLease(t, b, client, upstream+"/cache/node?sig=read"))
			if err != nil {
				t.Fatal(err)
			}
			restored, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if _, gets := blob.requests(); !bytes.Equal(restored, []byte("first-second")) || gets != 0 {
				t.Fatal("restore after a relayed save was not a local hit", gets)
			}
		})
	}
}
