package cache

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBlob emulates the block-blob operations the Azure SDK uses to upload,
// plus HEAD and GET for restores. Writes need sig=upload, reads sig=read.
type fakeBlob struct {
	mu         sync.Mutex
	staged     map[string][]byte
	blobs      map[string][]byte
	etags      map[string]string
	queries    []string
	gets       int
	rejectList bool
}

func newFakeBlob() *fakeBlob {
	return &fakeBlob{staged: map[string][]byte{}, blobs: map[string][]byte{}, etags: map[string]string{}}
}

func (f *fakeBlob) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	query := r.URL.Query()
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "credential forwarded", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodHead || r.Method == http.MethodGet {
		data, ok := f.blobs[r.URL.Path]
		if query.Get("sig") != "read" || !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", f.etags[r.URL.Path])
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		if r.Method == http.MethodGet {
			f.gets++
			_, _ = w.Write(data)
		}
		return
	}
	f.queries = append(f.queries, r.URL.RawQuery)
	body, err := io.ReadAll(r.Body)
	if r.Method != http.MethodPut || query.Get("sig") != "upload" || err != nil || int64(len(body)) != r.ContentLength {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	commit := func(data []byte) {
		f.blobs[r.URL.Path] = data
		f.etags[r.URL.Path] = fmt.Sprintf(`"0x%d"`, len(f.etags)+1)
		w.Header().Set("ETag", f.etags[r.URL.Path])
		w.Header().Set("x-ms-request-id", "fixture")
		w.WriteHeader(http.StatusCreated)
	}
	switch query.Get("comp") {
	case "":
		if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		commit(body)
	case "block":
		f.staged[r.URL.Path+"\x00"+query.Get("blockid")] = body
		w.WriteHeader(http.StatusCreated)
	case "blocklist":
		var list struct {
			Latest []string `xml:"Latest"`
		}
		if f.rejectList || xml.Unmarshal(body, &list) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var data []byte
		for _, id := range list.Latest {
			data = append(data, f.staged[r.URL.Path+"\x00"+id]...)
		}
		commit(data)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *fakeBlob) blob(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blobs[path]
}

func (f *fakeBlob) requests() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), f.gets
}

func (f *fakeBlob) refuseCommits() {
	f.mu.Lock()
	f.rejectList = true
	f.mu.Unlock()
}

func uploadFixture(t *testing.T) (*Service, Bootstrap, *http.Client, *fakeBlob, string) {
	t.Helper()
	blob := newFakeBlob()
	backend := httptest.NewTLSServer(blob)
	t.Cleanup(backend.Close)
	s, b, client := testService(t, backend)
	s.EnableUploadStore()
	return s, b, client, blob, backend.URL
}

func createUploadLease(t *testing.T, b Bootstrap, c *http.Client, source string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"url": source})
	req, _ := http.NewRequest(http.MethodPost, b.URL+"/upload", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	var body struct {
		URL string `json:"url"`
	}
	if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&body) != nil {
		t.Fatalf("upload lease status %d", r.StatusCode)
	}
	return body.URL
}

func put(t *testing.T, c *http.Client, target string, header map[string]string, body []byte) (int, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, target, bytes.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	return r.StatusCode, r.Header
}

// relayPut sends a relay request as the preload does, with the guest's token.
func relayPut(t *testing.T, c *http.Client, b Bootstrap, target string, header map[string]string, body []byte) (int, http.Header) {
	t.Helper()
	h := map[string]string{"Authorization": "Bearer " + b.Token}
	for k, v := range header {
		h[k] = v
	}
	return put(t, c, target, h, body)
}

func blockList(ids ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><BlockList>`)
	for _, id := range ids {
		b.WriteString("<Latest>" + id + "</Latest>")
	}
	b.WriteString("</BlockList>")
	return []byte(b.String())
}

// restore leases a fresh read URL for path and returns the bytes served.
func restore(t *testing.T, b Bootstrap, c *http.Client, upstream, path string) []byte {
	t.Helper()
	r, err := c.Get(makeLease(t, b, c, upstream+path+"?sig=read"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	data, _ := io.ReadAll(r.Body)
	return data
}

func stagedFiles(t *testing.T, s *Service) int {
	t.Helper()
	entries, err := os.ReadDir(s.store.dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "fill-") {
			n++
		}
	}
	return n
}

// The relay forwards every byte and the signed query to Azure, stores what Azure
// committed, and the first restore of that archive is a local hit.
func TestUploadRelayStoresCommittedBlocksForTheFirstRestore(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/blocks?sig=upload&se=2999-01-01T00:00:00Z")
	if !strings.HasPrefix(relay, b.URL+"/upload/") || strings.Contains(relay, "sig") {
		t.Fatal("relay URL exposes or omits its capability", relay)
	}
	first, second := bytes.Repeat([]byte("a"), 3000), bytes.Repeat([]byte("b"), 1234)
	for id, data := range map[string][]byte{"AAAA": first, "AAAB": second} {
		if status, _ := relayPut(t, client, b, relay+"?comp=block&blockid="+id, map[string]string{"x-ms-version": "2020-04-08"}, data); status != http.StatusCreated {
			t.Fatal("block not relayed", status)
		}
	}
	status, header := relayPut(t, client, b, relay+"?comp=blocklist", map[string]string{"Content-Type": "application/xml"}, blockList("AAAA", "AAAB"))
	if status != http.StatusCreated || header.Get("ETag") == "" || header.Get("x-ms-request-id") != "fixture" {
		t.Fatal("commit response not relayed", status, header)
	}
	want := append(append([]byte{}, first...), second...)
	if !bytes.Equal(blob.blob("/cache/blocks"), want) {
		t.Fatal("Azure did not receive the exact archive")
	}
	queries, _ := blob.requests()
	for _, q := range queries {
		if !strings.HasPrefix(q, "sig=upload&se=") {
			t.Fatal("guest parameters displaced the signed query", q)
		}
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Stored: 1, StoredBytes: uint64(len(want))}})
	if got := restore(t, b, client, upstream, "/cache/blocks"); !bytes.Equal(got, want) {
		t.Fatal("restore did not return the uploaded archive")
	}
	if _, gets := blob.requests(); gets != 0 {
		t.Fatal("first restore after upload was not a local hit", gets)
	}
	if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("staging outlived its commit", reserved)
	}
	// The lease ends at commit, so a retried commit goes to Azure directly.
	if status, header := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList("AAAA", "AAAB")); status != http.StatusServiceUnavailable || header.Get("X-Bivouac-Relay") != "unavailable" {
		t.Fatal("finished upload still relayed", status)
	}
}

func TestUploadRelayStoresSingleShotUploads(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/single?sig=upload")
	if status, _ := relayPut(t, client, b, relay, map[string]string{"x-ms-blob-type": "BlockBlob"}, []byte("payload")); status != http.StatusCreated {
		t.Fatal("put blob not relayed", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Stored: 1, StoredBytes: 7}})
	if got := restore(t, b, client, upstream, "/cache/single"); string(got) != "payload" {
		t.Fatal("single-shot upload not restored")
	}
	if _, gets := blob.requests(); gets != 0 {
		t.Fatal("single-shot upload not served locally", gets)
	}
}

// Only bytes the relay itself sent may be stored. A block that reached Azure
// another way, or a commit Azure refused, leaves no object and no staging.
func TestUploadRelayNeverStoresBytesItDidNotCommit(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/partial?sig=upload")
	relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("relayed"))
	put(t, s.client, upstream+"/cache/partial?sig=upload&comp=block&blockid=AAAB", nil, []byte("direct"))
	if status, _ := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList("AAAA", "AAAB")); status != http.StatusCreated {
		t.Fatal("commit not relayed", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Skipped: 1}})

	blob.refuseCommits()
	relay = createUploadLease(t, b, client, upstream+"/cache/rejected?sig=upload")
	relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("bytes"))
	if status, _ := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusForbidden {
		t.Fatal("Azure refusal not relayed", status)
	}
	if objects, _, reserved := s.store.Stats(); objects != 0 || reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("uncommitted bytes stored or left staged", objects, reserved)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 2, Skipped: 2}})
}

// Anything outside the SDK's three upload operations is refused before reaching
// Azure with the marker the preload falls back on. The preload takes the marker
// as final, so the lease and its staged bytes end at once and count once.
func TestUploadRelayRefusesWhatItCannotCarry(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	cases := map[string]struct {
		method, query string
		header        map[string]string
	}{
		"read":             {http.MethodGet, "", nil},
		"signed parameter": {http.MethodPut, "?comp=block&blockid=AAAB&sig=other", nil},
		"other operation":  {http.MethodPut, "?comp=properties", nil},
		"copy source":      {http.MethodPut, "", map[string]string{"x-ms-blob-type": "BlockBlob", "x-ms-copy-source": "https://example.invalid/"}},
		"page blob":        {http.MethodPut, "", map[string]string{"x-ms-blob-type": "PageBlob"}},
	}
	for name, request := range cases {
		relay := createUploadLease(t, b, client, upstream+"/cache/refused?sig=upload")
		if status, _ := relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("staged")); status != http.StatusCreated {
			t.Fatal(name, "block not relayed", status)
		}
		for range 2 { // A request racing the first refusal finds no lease.
			req, _ := http.NewRequest(request.method, relay+request.query, strings.NewReader("x"))
			req.Header.Set("Authorization", "Bearer "+b.Token)
			for k, v := range request.header {
				req.Header.Set(k, v)
			}
			r, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Body.Close()
			if r.StatusCode != http.StatusServiceUnavailable || r.Header.Get("X-Bivouac-Relay") != "unavailable" {
				t.Fatal(name, "not refused for direct fallback", r.StatusCode)
			}
		}
		if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
			t.Fatal(name, "fallback left staged bytes", reserved)
		}
	}
	if queries, _ := blob.requests(); len(queries) != len(cases) {
		t.Fatal("refused request reached Azure", queries)
	}
	n := uint64(len(cases))
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: n, Fallbacks: n}})
	s.storing.Store(false)
	payload, _ := json.Marshal(map[string]string{"url": upstream + "/cache/off?sig=upload"})
	req, _ := http.NewRequest(http.MethodPost, b.URL+"/upload", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	if r, err := client.Do(req); err != nil || r.StatusCode != http.StatusNotFound {
		t.Fatal("disabled upload storage issued a relay")
	}
}

// The relay ID can appear in the official action's debug output. Without the
// guest's own token a request is refused and cannot disturb the upload.
func TestUploadRelayRequiresTheGuestToken(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	data, err := s.Issue("other", GrantCapabilities{ReleaseProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	var other Bootstrap
	if err = json.Unmarshal(data, &other); err != nil {
		t.Fatal(err)
	}
	relay := createUploadLease(t, b, client, upstream+"/cache/owned?sig=upload")
	for name, header := range map[string]map[string]string{
		"no token":      {"x-ms-blob-type": "BlockBlob"},
		"other guest":   {"x-ms-blob-type": "BlockBlob", "Authorization": "Bearer " + other.Token},
		"unknown relay": {"x-ms-blob-type": "BlockBlob", "Authorization": "Bearer " + b.Token},
	} {
		target := relay
		if name == "unknown relay" {
			target = b.URL + "/upload/unknown"
		}
		if status, h := put(t, client, target, header, []byte("forged")); status != http.StatusServiceUnavailable || h.Get("X-Bivouac-Relay") != "unavailable" {
			t.Fatal(name, "accepted", status)
		}
	}
	if queries, _ := blob.requests(); len(queries) != 0 {
		t.Fatal("unauthenticated request reached Azure", queries)
	}
	if status, _ := relayPut(t, client, b, relay, map[string]string{"x-ms-blob-type": "BlockBlob"}, []byte("payload")); status != http.StatusCreated {
		t.Fatal("refused strangers ended the guest's relay", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Stored: 1, StoredBytes: 7}})
}

func TestUploadRelayFallsBackWhenAzureIsUnreachable(t *testing.T) {
	s, b, client, _, _ := uploadFixture(t)
	s.validate = func(*url.URL) bool { return true }
	relay := createUploadLease(t, b, client, "https://127.0.0.1:1/cache/unreachable?sig=upload")
	if status, header := relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("x")); status != http.StatusServiceUnavailable || header.Get("X-Bivouac-Relay") != "unavailable" {
		t.Fatal("unreachable upstream did not request direct fallback", status)
	}
	if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("fallback left staged bytes", reserved)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Fallbacks: 1}})
}

// A guest that stops sending its block mid-request is named as the broken side,
// not Azure, and its relay ends like any other fallback.
func TestUploadRelayNamesAGuestThatStopsSending(t *testing.T) {
	s, b, client, _, upstream := uploadFixture(t)
	var logs bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&logs, nil))
	relay := createUploadLease(t, b, client, upstream+"/cache/cut?sig=upload")
	target, _ := url.Parse(relay)
	conn, err := tls.Dial("tcp", target.Host, client.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "PUT %s?comp=block&blockid=AAAA HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Length: 1000\r\n\r\npartial", target.Path, target.Host, b.Token)
	time.Sleep(100 * time.Millisecond)
	_ = conn.Close()
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Fallbacks: 1}})
	if !strings.Contains(logs.String(), "reason=guest_body") {
		t.Fatal("guest failure not named", logs.String())
	}
	if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("cut request left staged bytes", reserved)
	}
}

// Capacity is a limit on the local copy only: an oversize upload is still
// relayed, then skipped. Revocation discards a guest's staged blocks.
func TestUploadRelayCapacityAndRevocation(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/large?sig=upload")
	large := bytes.Repeat([]byte("x"), int(s.store.maxObject)+1)
	if status, _ := relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, large); status != http.StatusCreated {
		t.Fatal("oversize block not relayed", status)
	}
	if status, _ := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusCreated || len(blob.blob("/cache/large")) != len(large) {
		t.Fatal("oversize upload not committed upstream", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 1, Skipped: 1}})

	relay = createUploadLease(t, b, client, upstream+"/cache/revoked?sig=upload")
	relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("staged"))
	if _, _, reserved := s.store.Stats(); reserved != 6 || stagedFiles(t, s) != 1 {
		t.Fatal("block not staged", reserved)
	}
	s.Revoke("guest")
	if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("revocation left staged bytes", reserved)
	}
	if status, _ := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusServiceUnavailable {
		t.Fatal("revoked upload still relayed", status)
	}
	// Revocation ends the guest's saves uncounted.
	waitSummary(t, s, Summary{Uploads: UploadCounters{Relayed: 2, Skipped: 1}})
}

// Use Go's actual HTTP transport: a successful response may race the
// transport's still-running request-body writer.
func TestBlockListEarlyHTTPResponseSkipsIncompleteCopy(t *testing.T) {
	accepted := make(chan struct{})
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Query().Get("comp") == "blocklist" {
			if _, err := io.ReadFull(r.Body, make([]byte, 100)); err != nil {
				return
			}
			w.Header().Set("ETag", `"id"`)
			w.WriteHeader(http.StatusCreated)
			w.(http.Flusher).Flush()
			close(accepted)
		} else {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	s.EnableUploadStore()
	relay := createUploadLease(t, b, client, backend.URL+"/object?sig=fixture")
	if status, _ := relayPut(t, client, b, relay+"?comp=block&blockid=AAAA", nil, []byte("staged")); status != http.StatusCreated {
		t.Fatal("block not accepted")
	}
	in, out := io.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()
	// A valid XML prefix must not qualify as a complete copy: Azure can respond
	// before the declared trailing whitespace has even reached the relay.
	prefix := append(blockList("AAAA"), bytes.Repeat([]byte(" "), 256)...)
	req, _ := http.NewRequest(http.MethodPut, relay+"?comp=blocklist", in)
	req.ContentLength = maxBlockListBytes
	req.Header.Set("Authorization", "Bearer "+b.Token)
	done := make(chan *http.Response, 1)
	go func() { r, _ := client.Do(req); done <- r }()
	if _, err := out.Write(prefix); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive prefix")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		summary := s.Snapshot().Uploads
		if summary.Stored+summary.Skipped > 0 {
			if summary.Stored != 0 || summary.Skipped != 1 {
				t.Fatalf("incomplete block list was stored: %+v", summary)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted upload was not accounted")
		}
		time.Sleep(time.Millisecond)
	}
	go func() {
		_, _ = out.Write(bytes.Repeat([]byte(" "), maxBlockListBytes-len(prefix)))
		_ = out.Close()
	}()
	select {
	case response := <-done:
		if response == nil {
			t.Fatal("accepted response lost")
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatal("accepted response changed", response.StatusCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay response blocked")
	}
	objects, _, reserved := s.store.Stats()
	if objects != 0 || reserved != 0 {
		t.Fatalf("incomplete list retained staging: objects=%d reserved=%d", objects, reserved)
	}
}

func TestBlockListEarlyHTTPResponseConcurrentBody(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.ReadFull(r.Body, make([]byte, 100))
		w.Header().Set("ETag", `"id"`)
		w.WriteHeader(http.StatusCreated)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	s, b, client := testService(t, backend)
	s.EnableUploadStore()
	relay := createUploadLease(t, b, client, backend.URL+"/object?sig=fixture")
	ids := make([]string, 100000)
	for i := range ids {
		ids[i] = "AAAA"
	}
	if status, _ := relayPut(t, client, b, relay+"?comp=blocklist", nil, blockList(ids...)); status != http.StatusCreated {
		t.Fatal("early success not relayed", status)
	}
}
