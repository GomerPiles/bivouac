package cache

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Mimic a storage SDK retrying the exact rewritten lookup URL, retaining byte
// ranges after a partial response. Only fixed outcomes leave the Node process.
const downloadRetryProgram = `const https=require('node:https');
const [port,method]=process.argv.slice(1);
const rpc=()=>new Promise((resolve,reject)=>{const r=https.request({hostname:'unit.actions.githubusercontent.com',port,path:'/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',method:'POST',agent:false,rejectUnauthorized:false,lookup:(h,o,cb)=>cb(null,o.all?[{address:'127.0.0.1',family:4}]:'127.0.0.1',4),headers:{authorization:'Bearer runtime-only'}},s=>{let d='';s.on('data',c=>d+=c);s.on('end',()=>resolve(JSON.parse(d).signed_download_url));});r.on('error',reject);r.end('{}');});
const get=(url,offset)=>new Promise(resolve=>{
let chunks=[],status=0,done=false;
const finish=complete=>{if(done)return;done=true;resolve({status,complete,data:Buffer.concat(chunks)});};
const r=https.request(url,{method:method,rejectUnauthorized:false,agent:false,headers:{Range:'bytes='+offset+'-',Authorization:'cache-only-private','Proxy-Authorization':'proxy-only-private'}},s=>{status=s.statusCode;s.on('data',c=>chunks.push(c));s.on('end',()=>finish(true));s.on('aborted',()=>finish(false));s.on('error',()=>finish(false));});r.on('error',()=>finish(false));r.end();});
(async()=>{const url=await rpc();let data=Buffer.alloc(0);for(let n=0;n<4;n++){const r=await get(url,4+data.length);if(r.status===206){data=Buffer.concat([data,r.data]);if(r.complete)break;}}
if(data.length!==65532||data.some((b,i)=>b!==(i+4)%251))process.exit(2);
console.log('download recovery verified');})().catch(()=>process.exit(3));`

func TestPreloadDownloadRetriesRecoverPublicSource(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node needed for the guest adapter")
	}
	for _, mode := range []string{"cached", "refused", "partial", "expired"} {
		for _, method := range []string{"GET", "get"} {
			t.Run(mode+"_"+method, func(t *testing.T) {
				payload := make([]byte, 65536)
				for i := range payload {
					payload[i] = byte(i % 251)
				}
				var upstreamGets, localGets atomic.Int32
				serve := func(w http.ResponseWriter, r *http.Request, partial bool) {
					offset, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), "-"))
					if err != nil || offset < 0 || offset >= len(payload) {
						t.Error("download range changed")
						w.WriteHeader(416)
						return
					}
					body := payload[offset:]
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.Header().Set("Content-Range", "bytes "+strconv.Itoa(offset)+"-65535/65536")
					w.WriteHeader(206)
					if partial {
						_, _ = w.Write(body[:8192])
						w.(http.Flusher).Flush()
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}
						return
					}
					_, _ = w.Write(body)
				}
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamGets.Add(1)
					if r.URL.Path != "/archive" || r.URL.RawQuery != "sig=fixture" || r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
						t.Error("fallback changed source or leaked a private header")
						w.WriteHeader(403)
						return
					}
					serve(w, r, false)
				}))
				defer upstream.Close()
				var localURL string
				endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/lease":
						if r.Header.Get("Authorization") != "Bearer guest-only" {
							t.Error("claim lost guest authentication")
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"url": localURL + "/object/fixture"})
					case "/object/fixture":
						localGets.Add(1)
						switch mode {
						case "refused":
							conn, _, err := w.(http.Hijacker).Hijack()
							if err == nil {
								_ = conn.Close()
							}
						case "expired":
							w.WriteHeader(403)
						default:
							serve(w, r, mode == "partial")
						}
					default:
						t.Error("unexpected local operation")
						w.WriteHeader(404)
					}
				}))
				defer endpoint.Close()
				localURL = endpoint.URL
				rpc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer runtime-only" {
						t.Error("metadata authorization changed")
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"signed_download_url": upstream.URL + "/archive?sig=fixture"})
				}))
				defer rpc.Close()
				dir := t.TempDir()
				preload := filepath.Join(dir, "preload.cjs")
				settings := filepath.Join(dir, "cache.json")
				cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw})
				data, _ := json.Marshal(Bootstrap{URL: endpoint.URL, Token: "guest-only", CA: string(cert)})
				if os.WriteFile(preload, Preload(), 0600) != nil || os.WriteFile(settings, data, 0600) != nil {
					t.Fatal("private fixture unavailable")
				}
				_, port, _ := net.SplitHostPort(rpc.Listener.Addr().String())
				// Hosted Windows may start Node cold while the race suite is busy.
				// Bound the whole subprocess, including module/TLS initialization.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, node, "-e", downloadRetryProgram, port, method)
				cmd.Env = MergeEnvironment(os.Environ(), []string{"NODE_OPTIONS=--require=" + preload, "BIVOUAC_CACHE_CONFIG=" + settings})
				cmd.Stderr = io.Discard
				output, err := cmd.Output()
				if err != nil || !bytes.Equal(bytes.TrimSpace(output), []byte("download recovery verified")) {
					t.Fatalf("download retry did not recover intact bytes: deadline=%t local_requests=%d upstream_requests=%d", ctx.Err() != nil, localGets.Load(), upstreamGets.Load())
				}
				if localGets.Load() != 1 {
					t.Fatal("failed local lease was retried instead of its source")
				}
				expected := int32(1)
				if mode == "cached" {
					expected = 0
				}
				if upstreamGets.Load() != expected {
					t.Fatal("download source retry count changed")
				}
			})
		}
	}
}
