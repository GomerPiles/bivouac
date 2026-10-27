package wintools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func verify(file *os.File, recipe Recipe) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != recipe.Bytes || recipe.Bytes < 1 || recipe.Bytes > 128<<20 {
		return errors.New("tool payload size refused")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, recipe.Bytes+1))
	if err != nil || n != recipe.Bytes || hex.EncodeToString(hash.Sum(nil)) != recipe.SHA256 {
		return errors.New("tool payload digest differs")
	}
	return nil
}

func Verify(path string, recipe Recipe) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("tool payload unavailable")
	}
	defer func() { _ = file.Close() }()
	return verify(file, recipe)
}

func releaseURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil && u.Port() == "" &&
		(u.Hostname() == "github.com" || u.Hostname() == "release-assets.githubusercontent.com" || u.Hostname() == "objects.githubusercontent.com")
}

// Acquire uses a content-addressed cache in an existing private directory.
// Every hit is rehashed. A corrupt existing entry refuses instead of being
// overwritten. Redirects are restricted to official release delivery hosts;
// URLs, response bodies and underlying HTTP errors never reach diagnostics.
func Acquire(ctx context.Context, directory string, recipe Recipe) (path string, hit bool, err error) {
	resolved, err := Resolve([]string{recipe.Name})
	if err != nil || len(resolved) != 1 || recipe != resolved[0] {
		return "", false, errors.New("reviewed catalog recipe required")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", false, errors.New("tool cache unavailable")
	}
	defer func() { _ = root.Close() }()
	name := recipe.SHA256 + ".zip"
	if file, openErr := root.Open(name); openErr == nil {
		defer func() { _ = file.Close() }()
		if err := verify(file, recipe); err != nil {
			return "", false, err
		}
		return root.Name() + string(os.PathSeparator) + name, true, nil
	} else if !errors.Is(openErr, os.ErrNotExist) {
		return "", false, errors.New("tool cache entry refused")
	}
	// Exclusive staging also refuses concurrent writers. This small lab cache
	// has no eviction or repair; interrupted staging is retained for diagnosis.
	file, err := root.OpenFile(name+".partial", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", false, errors.New("fresh tool cache staging required")
	}
	defer func() { _ = file.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, recipe.URL, nil)
	if err != nil || !releaseURL(request.URL) {
		return "", false, errors.New("tool download origin refused")
	}
	request.Header.Set("User-Agent", "bivouac-tool-cache")
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 4 || !releaseURL(req.URL) {
			return errors.New("tool redirect refused")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return "", false, errors.New("tool download unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || (response.ContentLength != -1 && response.ContentLength != recipe.Bytes) {
		return "", false, errors.New("tool download response refused")
	}
	// Cap transfer to 4 MiB/s while the development host is shared with CI.
	hash := sha256.New()
	reader := io.LimitReader(response.Body, recipe.Bytes+1)
	buffer := make([]byte, 256<<10)
	started, total := time.Now(), int64(0)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if _, err := io.MultiWriter(file, hash).Write(buffer[:n]); err != nil {
				return "", false, errors.New("tool cache write failed")
			}
			total += int64(n)
			wait := time.Until(started.Add(time.Duration(total) * time.Second / (4 << 20)))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return "", false, errors.New("tool download canceled")
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", false, errors.New("tool download incomplete")
		}
	}
	if total != recipe.Bytes || hex.EncodeToString(hash.Sum(nil)) != recipe.SHA256 {
		return "", false, errors.New("downloaded tool pin differs")
	}
	if errors.Join(file.Sync(), file.Close()) != nil || root.Rename(name+".partial", name) != nil {
		return "", false, errors.New("tool cache publication failed")
	}
	return root.Name() + string(os.PathSeparator) + name, false, nil
}
