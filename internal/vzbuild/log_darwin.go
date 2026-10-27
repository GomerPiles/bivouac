package vzbuild

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/GomerPiles/bivouac/internal/redact"
)

// Archive only bounded host-side helper status; the guest console is detached.
// Sink redaction still applies if future helper diagnostics gain sensitive data.
func archiveLaunchLog(dir, logs, id string, gate bool) (string, error) {
	source := filepath.Join(dir, "launch.log")
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if logs == "" {
		return "", nil
	}
	if !info.Mode().IsRegular() || !validID(id) {
		return "", errors.New("unrecognized factory launch log retained")
	}
	if _, err := fileIdentity(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(logs, 0700); err != nil {
		return "", err
	}
	phase := "provision"
	if gate {
		phase = "gate"
	}
	dst := filepath.Join(logs, "factory-"+id+"-"+phase+".log")
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return dst, nil
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = out.Close() }()
	sink := redact.NewWriter(out)
	_, copyErr := io.Copy(sink, io.LimitReader(in, 1<<20))
	if err = errors.Join(copyErr, sink.Close()); err != nil {
		return "", err
	}
	if err = out.Sync(); err != nil {
		return "", err
	}
	if err = syncDir(logs); err != nil {
		return "", err
	}
	return dst, nil
}
