package cache

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
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
		if status, _ := put(t, client, relay+"?comp=block&blockid="+id, map[string]string{"x-ms-version": "2020-04-08"}, data); status != http.StatusCreated {
			t.Fatal("block not relayed", status)
		}
	}
	status, header := put(t, client, relay+"?comp=blocklist", map[string]string{"Content-Type": "application/xml"}, blockList("AAAA", "AAAB"))
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
	waitSummary(t, s, Summary{Uploads: UploadCounters{Stored: 1, StoredBytes: uint64(len(want))}})
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
	if status, header := put(t, client, relay+"?comp=blocklist", nil, blockList("AAAA", "AAAB")); status != http.StatusServiceUnavailable || header.Get("X-Bivouac-Relay") != "unavailable" {
		t.Fatal("finished upload still relayed", status)
	}
}

func TestUploadRelayStoresSingleShotUploads(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/single?sig=upload")
	if status, _ := put(t, client, relay, map[string]string{"x-ms-blob-type": "BlockBlob"}, []byte("payload")); status != http.StatusCreated {
		t.Fatal("put blob not relayed", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Stored: 1, StoredBytes: 7}})
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
	put(t, client, relay+"?comp=block&blockid=AAAA", nil, []byte("relayed"))
	put(t, s.client, upstream+"/cache/partial?sig=upload&comp=block&blockid=AAAB", nil, []byte("direct"))
	if status, _ := put(t, client, relay+"?comp=blocklist", nil, blockList("AAAA", "AAAB")); status != http.StatusCreated {
		t.Fatal("commit not relayed", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Skipped: 1}})

	blob.refuseCommits()
	relay = createUploadLease(t, b, client, upstream+"/cache/rejected?sig=upload")
	put(t, client, relay+"?comp=block&blockid=AAAA", nil, []byte("bytes"))
	if status, _ := put(t, client, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusForbidden {
		t.Fatal("Azure refusal not relayed", status)
	}
	if objects, _, reserved := s.store.Stats(); objects != 0 || reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("uncommitted bytes stored or left staged", objects, reserved)
	}
}

// Anything outside the SDK's three upload operations, or for an unknown lease,
// is refused before reaching Azure with the marker the preload falls back on.
func TestUploadRelayRefusesWhatItCannotCarry(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/refused?sig=upload")
	for name, request := range map[string]struct {
		method, target string
		header         map[string]string
	}{
		"unknown lease":    {http.MethodPut, b.URL + "/upload/unknown", map[string]string{"x-ms-blob-type": "BlockBlob"}},
		"read":             {http.MethodGet, relay, nil},
		"signed parameter": {http.MethodPut, relay + "?comp=block&blockid=AAAA&sig=other", nil},
		"other operation":  {http.MethodPut, relay + "?comp=properties", nil},
		"copy source":      {http.MethodPut, relay, map[string]string{"x-ms-blob-type": "BlockBlob", "x-ms-copy-source": "https://example.invalid/"}},
		"page blob":        {http.MethodPut, relay, map[string]string{"x-ms-blob-type": "PageBlob"}},
	} {
		req, _ := http.NewRequest(request.method, request.target, strings.NewReader("x"))
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
	if queries, _ := blob.requests(); len(queries) != 0 {
		t.Fatal("refused request reached Azure", queries)
	}
	s.storing.Store(false)
	payload, _ := json.Marshal(map[string]string{"url": upstream + "/cache/off?sig=upload"})
	req, _ := http.NewRequest(http.MethodPost, b.URL+"/upload", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+b.Token)
	if r, err := client.Do(req); err != nil || r.StatusCode != http.StatusNotFound {
		t.Fatal("disabled upload storage issued a relay")
	}
}

func TestUploadRelayFallsBackWhenAzureIsUnreachable(t *testing.T) {
	s, b, client, _, _ := uploadFixture(t)
	s.validate = func(*url.URL) bool { return true }
	relay := createUploadLease(t, b, client, "https://127.0.0.1:1/cache/unreachable?sig=upload")
	if status, header := put(t, client, relay+"?comp=block&blockid=AAAA", nil, []byte("x")); status != http.StatusServiceUnavailable || header.Get("X-Bivouac-Relay") != "unavailable" {
		t.Fatal("unreachable upstream did not request direct fallback", status)
	}
}

// Capacity is a limit on the local copy only: an oversize upload is still
// relayed, then skipped. Revocation discards a guest's staged blocks.
func TestUploadRelayCapacityAndRevocation(t *testing.T) {
	s, b, client, blob, upstream := uploadFixture(t)
	relay := createUploadLease(t, b, client, upstream+"/cache/large?sig=upload")
	large := bytes.Repeat([]byte("x"), int(s.store.maxObject)+1)
	if status, _ := put(t, client, relay+"?comp=block&blockid=AAAA", nil, large); status != http.StatusCreated {
		t.Fatal("oversize block not relayed", status)
	}
	if status, _ := put(t, client, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusCreated || len(blob.blob("/cache/large")) != len(large) {
		t.Fatal("oversize upload not committed upstream", status)
	}
	waitSummary(t, s, Summary{Uploads: UploadCounters{Skipped: 1}})

	relay = createUploadLease(t, b, client, upstream+"/cache/revoked?sig=upload")
	put(t, client, relay+"?comp=block&blockid=AAAA", nil, []byte("staged"))
	if _, _, reserved := s.store.Stats(); reserved != 6 || stagedFiles(t, s) != 1 {
		t.Fatal("block not staged", reserved)
	}
	s.Revoke("guest")
	if _, _, reserved := s.store.Stats(); reserved != 0 || stagedFiles(t, s) != 0 {
		t.Fatal("revocation left staged bytes", reserved)
	}
	if status, _ := put(t, client, relay+"?comp=blocklist", nil, blockList("AAAA")); status != http.StatusServiceUnavailable {
		t.Fatal("revoked upload still relayed", status)
	}
}
