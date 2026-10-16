package cache

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The preload points the Azure SDK's signed upload URL at /upload/<id>. The host
// forwards each request to Azure itself and keeps the bytes it sent, so a commit
// Azure accepts stores exactly the archive Azure holds, under the identity a
// later restore's HEAD reports. A guest can store only objects it can write
// upstream. Requests the relay cannot carry get relayUnavailable, and the
// preload sends that upload's retries directly to Azure.

const (
	uploadsPerGuest   = 8
	requestsPerUpload = 16
	maxUploadBlocks   = 50000 // Azure's limit for one blob.
	maxBlockListBytes = 8 << 20
	maxRelayReply     = 1 << 20
)

type stagedBlock struct {
	path string
	size int64
}

// uploadLease relays one signed upload URL. mu guards the fields below it; all
// changes to stage happen under mu until take hands the stage to a commit.
type uploadLease struct {
	token    string
	upstream *url.URL
	expires  time.Time

	mu     sync.Mutex
	closed bool // Taken or abandoned: later requests relay without staging.
	reason string
	active int
	stage  *stage
	blocks map[string]stagedBlock
}

// UploadCounters count saves whose bytes the relay kept. Skipped saves reached
// GitHub through the relay without a complete local copy.
type UploadCounters struct {
	Stored      uint64 `json:"stored"`
	StoredBytes uint64 `json:"stored_bytes"`
	Skipped     uint64 `json:"skipped"`
}

// EnableUploadStore is configured before attaching this service to providers.
func (s *Service) EnableUploadStore() {
	s.storing.Store(true)
	s.log.Info("cache upload storage enabled")
}

func (s *Service) createUpload(w http.ResponseWriter, r *http.Request) {
	if !s.storing.Load() {
		http.NotFound(w, r)
		return
	}
	u, ok := s.readUpstreamRequest(w, r)
	if !ok {
		return
	}
	expires := signedExpiry(u.parsed, u.grant.expires)
	if time.Now().After(expires) {
		http.Error(w, "expired upstream", http.StatusForbidden)
		return
	}
	id := randomToken()
	var expired []*uploadLease
	s.mu.Lock()
	count := 0
	for existing, l := range s.uploads {
		if time.Now().After(l.expires) {
			delete(s.uploads, existing)
			expired = append(expired, l)
		} else if l.token == u.token {
			count++
		}
	}
	_, valid := s.grants[u.token]
	admitted := !s.closed && valid && count < uploadsPerGuest
	if admitted {
		s.uploads[id] = &uploadLease{token: u.token, upstream: u.parsed, expires: expires, stage: s.store.newStage(), blocks: map[string]stagedBlock{}}
	}
	s.mu.Unlock()
	for _, l := range expired {
		l.abandon("expired")
	}
	if !admitted {
		http.Error(w, "upload limit", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		URL string `json:"url"`
	}{u.grant.url + "/upload/" + id})
}

// relayUnavailable tells the preload to send this upload's retries to Azure.
// The storage SDK retries 503 responses.
func relayUnavailable(w http.ResponseWriter) {
	w.Header().Set("X-Bivouac-Relay", "unavailable")
	http.Error(w, "upload relay unavailable", http.StatusServiceUnavailable)
}

type uploadKind int

const (
	putBlob uploadKind = iota
	putBlock
	putBlockList
)

type uploadRequest struct {
	kind    uploadKind
	blockID string
	query   url.Values
}

// parseUploadRequest admits only the three Azure operations a block-blob
// upload uses. Guest parameters can never replace the signed query.
func parseUploadRequest(r *http.Request) (uploadRequest, bool) {
	query := r.URL.Query()
	if r.Method != http.MethodPut || r.ContentLength < 0 {
		return uploadRequest{}, false
	}
	for key, values := range query {
		if (key != "comp" && key != "blockid" && key != "timeout") || len(values) != 1 {
			return uploadRequest{}, false
		}
	}
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-ms-copy-") {
			return uploadRequest{}, false
		}
	}
	op := uploadRequest{query: query, blockID: query.Get("blockid")}
	switch query.Get("comp") {
	case "":
		op.kind = putBlob
		if op.blockID != "" || r.Header.Get("x-ms-blob-type") != "BlockBlob" {
			return uploadRequest{}, false
		}
	case "block":
		op.kind = putBlock
		if op.blockID == "" || len(op.blockID) > 256 {
			return uploadRequest{}, false
		}
	case "blocklist":
		op.kind = putBlockList
		if op.blockID != "" || r.ContentLength > maxBlockListBytes {
			return uploadRequest{}, false
		}
	default:
		return uploadRequest{}, false
	}
	return op, true
}

func (s *Service) relayUpload(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	u := s.uploads[id]
	valid := false
	if u != nil {
		_, valid = s.grants[u.token]
	}
	s.mu.Unlock()
	op, ok := parseUploadRequest(r)
	if u == nil || !valid || !ok || time.Now().After(u.expires) || !u.enter() {
		relayUnavailable(w)
		return
	}
	defer u.leave()
	// The listener's read and write timeouts suit small requests. A block on a
	// slow uplink is bounded by the signed URL and grant instead.
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(u.expires)
	_ = controller.SetWriteDeadline(u.expires)
	ctx, cancel := context.WithDeadline(r.Context(), u.expires)
	defer cancel()

	var body io.Reader = r.Body
	var list []string
	listed := false
	var staged *stageWriter
	if op.kind == putBlockList {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			relayUnavailable(w)
			return
		}
		body = bytes.NewReader(data)
		list, listed = parseBlockList(data)
	} else if staged = u.reserve(r.ContentLength); staged != nil {
		body = io.TeeReader(r.Body, staged)
	}
	if r.ContentLength == 0 {
		body = http.NoBody
	}
	target := *u.upstream
	if len(op.query) > 0 {
		target.RawQuery += "&" + op.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), body)
	if err != nil {
		u.discard(staged)
		relayUnavailable(w)
		return
	}
	req.ContentLength = r.ContentLength
	for key, values := range r.Header {
		if relayedHeader(key) {
			req.Header[key] = values
		}
	}
	client := &http.Client{Transport: s.client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req) // #nosec G704 -- The signed URL passed allowedURL; the public transport refuses host networks.
	if err != nil {
		u.discard(staged)
		reason, _ := failureDetails(upstreamFailure(err))
		s.log.Info("cache upload relay unavailable", "reason", reason)
		relayUnavailable(w)
		return
	}
	defer func() { _ = response.Body.Close() }()
	// Record the result before replying: the SDK commits the block list as soon
	// as the last block is acknowledged.
	if response.StatusCode != http.StatusCreated {
		u.discard(staged)
		if op.kind != putBlock && response.StatusCode < http.StatusInternalServerError {
			// The SDK does not retry a refused commit; free its staged blocks now.
			s.dropUpload(id)
			u.abandon("upstream_status")
		}
	} else {
		switch op.kind {
		case putBlock:
			u.addBlock(op.blockID, staged)
		case putBlob:
			u.addBlock("", staged)
			s.storeUpload(id, u, []string{""}, true, response.Header.Get("ETag"))
		case putBlockList:
			s.storeUpload(id, u, list, listed, response.Header.Get("ETag"))
		}
	}
	for key, values := range response.Header {
		if relayedHeader(key) || key == "Etag" || key == "Last-Modified" || key == "Date" || key == "Retry-After" {
			w.Header()[key] = values
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, maxRelayReply))
}

// relayedHeader passes Azure's own protocol headers, never credentials, cookies
// or hop-by-hop fields.
func relayedHeader(key string) bool {
	key = http.CanonicalHeaderKey(key)
	return key == "Content-Type" || key == "Content-Md5" || key == "User-Agent" || strings.HasPrefix(key, "X-Ms-")
}

// parseBlockList returns the committed order of a Put Block List body. Only
// blocks this upload staged qualify, so Committed entries are refused.
func parseBlockList(data []byte) ([]string, bool) {
	var list struct {
		XMLName xml.Name
		Blocks  []struct {
			XMLName xml.Name
			ID      string `xml:",chardata"`
		} `xml:",any"`
	}
	if xml.Unmarshal(data, &list) != nil || list.XMLName.Local != "BlockList" || len(list.Blocks) > maxUploadBlocks {
		return nil, false
	}
	ids := make([]string, 0, len(list.Blocks))
	for _, b := range list.Blocks {
		if b.XMLName.Local != "Latest" && b.XMLName.Local != "Uncommitted" {
			return nil, false
		}
		ids = append(ids, strings.TrimSpace(b.ID))
	}
	return ids, true
}

// storeUpload takes the staged blocks for a commit Azure accepted and stores
// them in the background. The service owns that work, so it may finish after
// the guest exits; Close cancels and joins it.
func (s *Service) storeUpload(id string, u *uploadLease, order []string, listed bool, etag string) {
	s.dropUpload(id) // A retried commit goes directly to Azure.
	if !listed {
		u.abandon("block_list")
	} else if etag == "" {
		u.abandon("upload_identity")
	}
	blocks, st, size, err := u.take(order)
	if err != nil {
		reason, _ := failureDetails(err)
		s.log.Info("cache upload not stored", "reason", reason)
		s.addUpload(u.token, func(c *UploadCounters) { c.Skipped++ })
		return
	}
	key := archiveKey(u.upstream, etag, size)
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.commits.Add(1)
	}
	s.mu.Unlock()
	if closed {
		removeBlocks(blocks)
		st.shrink(st.bytes)
		return
	}
	go func() {
		defer s.commits.Done()
		present, err := st.commit(s.work, key, func(ctx context.Context, out io.Writer) error {
			for _, b := range blocks {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := appendFile(out, b.path); err != nil {
					return err
				}
				_ = os.Remove(b.path)
			}
			return nil
		})
		removeBlocks(blocks)
		if err != nil {
			reason, _ := failureDetails(err)
			s.log.Warn("cache upload not stored", "object", s.store.label(key), "reason", reason, "bytes", size)
			s.addUpload(u.token, func(c *UploadCounters) { c.Skipped++ })
			return
		}
		s.log.Info("cache upload stored", "object", s.store.label(key), "present", present, "bytes", size)
		s.addUpload(u.token, func(c *UploadCounters) {
			c.Stored++
			c.StoredBytes += uint64(size) // #nosec G115 -- Staged sizes are nonnegative Content-Length values.
		})
	}()
}

func (s *Service) dropUpload(id string) {
	s.mu.Lock()
	delete(s.uploads, id)
	s.mu.Unlock()
}

func appendFile(out io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return failure("store_read")
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(out, f)
	return err
}

func removeBlocks(blocks []stagedBlock) {
	for _, b := range blocks {
		_ = os.Remove(b.path)
	}
}

func (s *Service) addUpload(token string, update func(*UploadCounters)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	update(&s.summary.Uploads)
	if g, ok := s.grants[token]; ok {
		update(&g.summary.Uploads)
		s.grants[token] = g
	}
}

func (u *uploadLease) enter() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.active >= requestsPerUpload {
		return false
	}
	u.active++
	return true
}

func (u *uploadLease) leave() {
	u.mu.Lock()
	u.active--
	u.mu.Unlock()
}

// stageWriter copies relayed bytes to a staged file. Its errors never reach the
// relay; they only leave the upload without a local copy. The transport may
// still hold the request body when the response arrives, so mu orders its
// writes before seal.
type stageWriter struct {
	mu     sync.Mutex
	f      *os.File
	size   int64
	n      int64
	failed bool
}

func (w *stageWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.failed {
		n, err := w.f.Write(p)
		w.n += int64(n)
		w.failed = err != nil || w.n > w.size
	}
	return len(p), nil
}

// seal closes the staged file and reports whether it holds exactly size bytes.
// Later writes are ignored.
func (w *stageWriter) seal() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	complete := w.f.Close() == nil && !w.failed && w.n == w.size
	w.failed = true
	return complete
}

// reserve stages n bytes, or returns nil to relay without a copy. Failing to
// reserve dooms the copy, so it abandons the upload's other blocks at once.
func (u *uploadLease) reserve(n int64) *stageWriter {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	if len(u.blocks) >= maxUploadBlocks {
		u.abandonLocked("object_limit")
		return nil
	}
	if err := u.stage.grow(n); err != nil {
		reason, _ := failureDetails(err)
		u.abandonLocked(reason)
		return nil
	}
	f, err := u.stage.store.stageFile()
	if err != nil {
		u.stage.shrink(n)
		u.abandonLocked("store_create")
		return nil
	}
	return &stageWriter{f: f, size: n}
}

func (u *uploadLease) discard(w *stageWriter) {
	if w == nil {
		return
	}
	w.seal()
	_ = os.Remove(w.f.Name())
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.closed {
		u.stage.shrink(w.size)
	}
}

// addBlock keeps a block Azure acknowledged. A repeated ID replaces the older
// bytes, as it does upstream.
func (u *uploadLease) addBlock(id string, w *stageWriter) {
	if w == nil {
		return
	}
	if !w.seal() {
		u.discard(w)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = os.Remove(w.f.Name())
		return
	}
	if old, ok := u.blocks[id]; ok {
		_ = os.Remove(old.path)
		u.stage.shrink(old.size)
	}
	u.blocks[id] = stagedBlock{path: w.f.Name(), size: w.size}
}

// take closes the lease and hands its staged blocks, in commit order, to the
// caller with a stage holding exactly their bytes. Unless every listed block
// was staged once, it abandons the upload instead.
func (u *uploadLease) take(order []string) ([]stagedBlock, *stage, int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, nil, 0, failure(cmp.Or(u.reason, "duplicate_commit"))
	}
	blocks := make([]stagedBlock, 0, len(order))
	listed := make(map[string]bool, len(order))
	var size int64
	for _, id := range order {
		b, ok := u.blocks[id]
		if !ok || listed[id] {
			u.abandonLocked("incomplete_upload")
			return nil, nil, 0, failure(u.reason)
		}
		listed[id] = true
		blocks = append(blocks, b)
		size += b.size
	}
	for id, b := range u.blocks {
		if !listed[id] {
			_ = os.Remove(b.path)
		}
	}
	u.closed, u.blocks = true, nil
	// Unlisted blocks and requests still in flight leave the reservation now.
	u.stage.shrink(u.stage.bytes - size)
	return blocks, u.stage, size, nil
}

func (u *uploadLease) abandon(reason string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.abandonLocked(reason)
}

func (u *uploadLease) abandonLocked(reason string) {
	if u.closed {
		return
	}
	u.closed, u.reason = true, reason
	for _, b := range u.blocks {
		_ = os.Remove(b.path)
	}
	u.blocks = nil
	u.stage.shrink(u.stage.bytes)
}
