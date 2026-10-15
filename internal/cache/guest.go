package cache

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed actions-preload.cjs
var preload string

func Preload() []byte { return []byte(preload) }

const guestConfigFile = "cache-config.json"

// PrepareGuest is called only by a provider's fixed, identity-checked guest
// helper. Capabilities arrive over SSH stdin, never via host staging files.
func PrepareGuest(ctx context.Context, dir string, data []byte) error {
	var b Bootstrap
	if len(data) > 32<<10 || json.Unmarshal(data, &b) != nil {
		return errors.New("invalid bounded guest cache bootstrap")
	}
	u, err := url.Parse(b.URL)
	if err != nil || u.Hostname() != "127.0.0.1" {
		return errors.New("guest cache transport must use loopback")
	}
	proxy, err := NewGuestProxy(b)
	if err != nil {
		return err
	}
	proxy.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for name, value := range map[string][]byte{guestConfigFile: data, "cache-preload.cjs": Preload(), "cache-ca.pem": []byte(b.CA)} {
		if err = root.WriteFile(name, value, 0o600); err != nil {
			return err
		}
	}
	if b.ReleaseProxy {
		roots, err := guestTrust(ctx, filepath.Join(dir, "cache-ca.pem"))
		if err != nil {
			return err
		}
		if err = root.WriteFile("cache-roots.pem", roots, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func RemoveGuest(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{guestConfigFile, "cache-preload.cjs", "cache-ca.pem", "cache-roots.pem"} {
		if err = root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// GuestEnvironment runs the proxy in the existing guest listener process. No
// extra daemon survives the job. Missing cache setup leaves normal downloads.
func GuestEnvironment(dir string) ([]string, func(), error) {
	data, err := os.ReadFile(filepath.Join(dir, guestConfigFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, func() {}, nil
	}
	if err != nil || len(data) > 32<<10 {
		return nil, nil, errors.New("read bounded guest cache settings")
	}
	var b Bootstrap
	if json.Unmarshal(data, &b) != nil {
		return nil, nil, errors.New("invalid guest cache settings")
	}
	values := []string{"BIVOUAC_CACHE_CONFIG=" + filepath.Join(dir, guestConfigFile), "NODE_OPTIONS=" + strings.TrimSpace(os.Getenv("NODE_OPTIONS")+` --require="`+filepath.ToSlash(filepath.Join(dir, "cache-preload.cjs"))+`"`)}
	if !b.ReleaseProxy {
		return values, func() {}, nil
	}
	proxy, err := NewGuestProxy(b)
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		proxy.Close()
		return nil, nil, errors.New("guest release proxy listener unavailable")
	}
	endpoint := "http://" + listener.Addr().String()
	server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(listener) }()
	values = append(values, "http_proxy="+endpoint, "https_proxy="+endpoint, "HTTP_PROXY="+endpoint, "HTTPS_PROXY="+endpoint, "no_proxy=127.0.0.1,localhost", "NO_PROXY=127.0.0.1,localhost",
		"SSL_CERT_FILE="+filepath.Join(dir, "cache-roots.pem"), "CURL_CA_BUNDLE="+filepath.Join(dir, "cache-roots.pem"), "GIT_SSL_CAINFO="+filepath.Join(dir, "cache-roots.pem"), "NODE_EXTRA_CA_CERTS="+filepath.Join(dir, "cache-ca.pem"))
	return values, func() { _ = server.Close(); proxy.Close() }, nil
}

// MergeEnvironment replaces each supplied key; Windows keys are case-insensitive.
func MergeEnvironment(existing, added []string) []string {
	var result []string
	for _, value := range existing {
		key, _, _ := strings.Cut(value, "=")
		duplicate := false
		for _, replacement := range added {
			k, _, _ := strings.Cut(replacement, "=")
			if strings.EqualFold(k, key) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, value)
		}
	}
	return append(result, added...)
}
