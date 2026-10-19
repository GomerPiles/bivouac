package cache

import (
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The preload points the Azure SDK's signed upload URL at /upload/<id>. The host
// forwards each request to Azure itself and keeps the bytes it sent. When Azure
// accepts a commit, those bytes are stored under the identity (blob path, ETag,
// size) a later restore's HEAD reports. A guest holding the signed URL can also
// write blocks to Azure directly, so the copy matches Azure only for a guest
// that does not; either way it can affect only an object it can write upstream.
// Relay requests need the relay ID and the guest's bearer token. Requests the
// relay cannot carry get relayUnavailable, and the preload sends that upload's
// retries directly to Azure.

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
	guest    string
	upstream *url.URL
	expires  time.Time

	mu     sync.Mutex
	closed bool // Taken or abandoned: later requests relay without staging.
	reason string
	active int
	stage  *stage
	blocks map[string]stagedBlock
}

// UploadCounters count saves routed through the relay. Each ends stored, skipped
// (the relay carried it, or Azure refused it, without a complete local copy) or
// fallen back (the relay sent the guest straight to Azure); a save abandoned by
// revocation, expiry or shutdown ends uncounted.
type UploadCounters struct {
	Relayed     uint64 `json:"relayed"`
	Stored      uint64 `json:"stored"`
	StoredBytes uint64 `json:"stored_bytes"`
	Skipped     uint64 `json:"skipped"`
	Fallbacks   uint64 `json:"fallbacks"`
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
		s.log.Info("cache upload not relayed", "reason", "expired")
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
	open := !s.closed && valid
	admitted := open && count < uploadsPerGuest
	if admitted {
		s.uploads[id] = &uploadLease{token: u.token, guest: u.grant.name, upstream: u.parsed, expires: expires, stage: s.store.newStage(), blocks: map[string]stagedBlock{}}
	}
	s.mu.Unlock()
	for _, l := range expired {
		l.abandon("expired")
	}
	if !admitted {
		if open {
			s.log.Info("cache upload not relayed", "reason", "upload_limit")
		}
		http.Error(w, "upload limit", http.StatusTooManyRequests)
		return
	}
	s.addUpload(u.token, func(c *UploadCounters) { c.Relayed++ })
	s.log.Info("cache upload relayed", "guest", u.grant.name)
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
	// The relay ID alone is not enough: the official action logs it in debug
	// output, and a macOS host listens beyond the guest. Without the guest's own
	// token the lease is left untouched, so a stranger cannot end the relay.
	if u == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+u.token)) != 1 {
		relayUnavailable(w)
		return
	}
	op, ok := parseUploadRequest(r)
	switch {
	case !valid:
		s.fallBack(w, id, u, "revoked")
		return
	case !ok:
		s.fallBack(w, id, u, "unsupported_request")
		return
	case time.Now().After(u.expires):
		s.fallBack(w, id, u, "expired")
		return
	case !u.enter():
		s.fallBack(w, id, u, "concurrency")
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

	guest := &guestBody{r: r.Body}
	var body io.Reader = guest
	var list []string
	listed := false
	var staged *stageWriter
	if op.kind == putBlockList {
		data, err := io.ReadAll(guest)
		if err != nil {
			s.fallBack(w, id, u, "guest_body")
			return
		}
		body = bytes.NewReader(data)
		list, listed = parseBlockList(data)
	} else if staged = u.reserve(r.ContentLength); staged != nil {
		body = io.TeeReader(guest, staged)
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
		s.fallBack(w, id, u, "unsupported_request")
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
		if guest.failed.Load() {
			reason = "guest_body"
		}
		s.fallBack(w, id, u, reason)
		return
	}
	defer func() { _ = response.Body.Close() }()
	// Record the result before replying: the SDK commits the block list as soon
	// as the last block is acknowledged.
	if response.StatusCode != http.StatusCreated {
		u.discard(staged)
		if op.kind != putBlock && response.StatusCode < http.StatusInternalServerError && s.dropUpload(id) {
			// The SDK does not retry a refused commit; free its staged blocks now.
			u.abandon("upstream_status")
			s.log.Info("cache upload not stored", "reason", "upstream_status")
			s.addUpload(u.token, func(c *UploadCounters) { c.Skipped++ })
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

// guestBody records whether reading the guest's request failed, so a relay
// failure names the side that broke. The transport may still read it after
// the request returns.
type guestBody struct {
	r      io.Reader
	failed atomic.Bool
}

func (g *guestBody) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if err != nil && err != io.EOF {
		g.failed.Store(true)
	}
	return n, err
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
	// A retried commit goes directly to Azure. Every other path that ends a
	// lease abandons it, and counts it if it should be counted.
	if !s.dropUpload(id) {
		return
	}
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

// dropUpload ends a relay lease and reports whether this call ended it.
func (s *Service) dropUpload(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.uploads[id]
	delete(s.uploads, id)
	return ok
}

// fallBack sends the guest's upload straight to Azure: the preload takes the
// marker as final for that upload, so the lease and its staged bytes end now.
// Only the call that ends the lease counts it.
func (s *Service) fallBack(w http.ResponseWriter, id string, u *uploadLease, reason string) {
	if s.dropUpload(id) {
		u.abandon(reason)
		s.log.Warn("cache upload sent directly upstream", "guest", u.guest, "reason", reason)
		s.addUpload(u.token, func(c *UploadCounters) { c.Fallbacks++ })
	}
	relayUnavailable(w)
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
