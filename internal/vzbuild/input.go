// Package vzbuild builds explicitly requested Linux baselines. Daemon admission
// never calls this package to download or boot an image.
package vzbuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

const downloadIdleTimeout = 2 * time.Minute

func inputClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = downloadIdleTimeout
	transport.TLSHandshakeTimeout = 30 * time.Second
	return &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 || !httpsURL(req.URL.String()) {
			return errors.New("baseline download redirect refused")
		}
		return nil
	}}
}

type progressReader struct {
	io.Reader
	progress func()
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.Reader.Read(b)
	if n > 0 {
		p.progress()
	}
	return n, err
}

// Each attempt has an idle deadline, reset by received bytes. Slow but active
// downloads have no total deadline; parent cancellation always remains effective.
func downloadAttempt(ctx context.Context, client *http.Client, u string, pin vzrecipe.Input, out *os.File, idle time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.AfterFunc(idle, cancel)
	defer timer.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.New("invalid pinned download")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("baseline download failed or made no progress")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.ContentLength >= 0 && resp.ContentLength != pin.Size {
		return errors.New("baseline download size or status differs")
	}
	if err := out.Truncate(0); err != nil {
		return err
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return verify(progressReader{Reader: resp.Body, progress: func() { timer.Reset(idle) }}, out, pin)
}
func verify(r io.Reader, w io.Writer, pin vzrecipe.Input) error {
	if pin.Size <= 0 || pin.Size > 2<<30 || len(pin.SHA256) != 64 {
		return errors.New("invalid baseline input pin")
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(r, pin.Size+1))
	if err != nil || n != pin.Size || hex.EncodeToString(hash.Sum(nil)) != pin.SHA256 {
		return errors.New("baseline input size or SHA-256 differs from recipe")
	}
	return nil
}
func verifiedFile(path string, pin vzrecipe.Input) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	i, err := f.Stat()
	return err == nil && i.Mode().IsRegular() && i.Size() == pin.Size && verify(f, io.Discard, pin) == nil
}

// obtain always re-verifies cached files; local overrides go through identical
// pins and atomic storage. URLs and HTTP response bodies never enter errors.
func obtain(ctx context.Context, dir, local string, pin vzrecipe.Input, client *http.Client) (string, error) {
	decoded, err := hex.DecodeString(pin.SHA256)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid input SHA-256 pin")
	}
	for _, u := range pin.URLs {
		if !httpsURL(u) {
			return "", errors.New("baseline inputs require HTTPS without credentials")
		}
	}
	if len(pin.URLs) == 0 {
		return "", errors.New("baseline input has no pinned source")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, pin.SHA256)
	if local == "" && verifiedFile(dst, pin) {
		return dst, nil
	}
	f, err := os.CreateTemp(dir, ".input-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if local != "" {
		in, err := os.Open(local)
		if err != nil {
			return "", errors.New("cannot open local baseline input")
		}
		i, statErr := in.Stat()
		if statErr != nil || !i.Mode().IsRegular() {
			_ = in.Close()
			return "", errors.New("local baseline input must be regular")
		}
		err = verify(in, f, pin)
		_ = in.Close()
		if err != nil {
			return "", err
		}
	} else {
		success := false
		for _, u := range pin.URLs {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			err = downloadAttempt(ctx, client, u, pin, f, downloadIdleTimeout)
			if err == nil {
				success = true
				break
			}
		}
		if !success {
			return "", errors.New("cannot obtain verified baseline input")
		}
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(f.Name(), dst); err != nil {
		return "", err
	}
	if err = syncDir(dir); err != nil {
		return "", err
	}
	return dst, nil
}
