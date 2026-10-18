package vz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

const preparedHelper = "/usr/local/bin/bivouac"
const maxHelperBytes = 128 << 20

// This fixed script fingerprints a public image helper without executing it.
// The candidate is an argument, never interpolated into shell source. Every
// ancestor must be root-owned, non-writable by group/other and not a symlink.
const helperProbe = `set -eu
candidate=$1
p=$candidate
while :; do
 if [ -L "$p" ]; then printf 'untrusted\n'; exit 0; fi
 if [ ! -e "$p" ]; then printf 'absent\n'; exit 0; fi
 owner=$(/usr/bin/stat -f %u "$p")
 mode=$(/usr/bin/stat -f %Lp "$p")
 if [ "$owner" != 0 ] || [ "$((0$mode & 0022))" != 0 ]; then printf 'untrusted\n'; exit 0; fi
 [ "$p" != / ] || break
 p=$(/usr/bin/dirname "$p")
done
if [ ! -f "$candidate" ] || [ ! -x "$candidate" ]; then printf 'untrusted\n'; exit 0; fi
size=$(/usr/bin/stat -f %z "$candidate")
if [ "$size" -gt 134217728 ]; then printf 'untrusted\n'; exit 0; fi
sum=$(/usr/bin/shasum -a 256 "$candidate")
printf '%s\n' "${sum%% *}"
`

func helperMatches(report []byte, want string) (bool, error) {
	value := strings.TrimSpace(string(report))
	if value == "absent" || value == "untrusted" {
		return false, nil
	}
	if digest, err := hex.DecodeString(value); err != nil || len(digest) != sha256.Size {
		return false, errors.New("invalid prepared guest helper fingerprint")
	}
	return value == want, nil
}

// installGuestHelper selects exactly one macOS executable for telemetry,
// caching and the optional container relay. The same opened host file is hashed
// and uploaded, so a pathname replacement cannot change the selected bytes.
func (p *Provider) installGuestHelper(ctx context.Context, name string) (result error) {
	started, reused := time.Now(), false
	defer func() { p.logStartup(name, "helper_prepare", started, result, "helper_reused", reused) }()
	exe, err := os.Executable()
	if err != nil {
		return errors.New("locate guest helper source")
	}
	f, err := os.Open(exe)
	if err != nil {
		return errors.New("open guest helper source")
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxHelperBytes+1))
	if err != nil || n > maxHelperBytes {
		return errors.New("guest helper source fingerprint unavailable")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind guest helper source")
	}
	matched := false
	err = p.startupStage(name, "helper_check", func() error {
		report, err := p.guest(ctx, name, []string{"/bin/sh", "-s", "--", preparedHelper}, strings.NewReader(helperProbe), 128)
		if err != nil {
			return errors.New("check prepared guest helper")
		}
		matched, err = helperMatches(report, hex.EncodeToString(hash.Sum(nil)))
		return err
	})
	if err != nil {
		return err
	}
	// Remove only the disposable runtime leaf before creating it. In particular,
	// a stale symlink must never direct an upload/chmod into the running agent.
	if _, err = p.output(ctx, name, []string{"rm", "-f", guestHelper}, nil); err != nil {
		return errors.New("prepare private guest helper path")
	}
	if matched {
		_, err = p.output(ctx, name, []string{"/bin/ln", "-s", preparedHelper, guestHelper}, nil)
		reused = err == nil
		return err
	}
	return p.startupStage(name, "helper_upload", func() error {
		if _, err := p.output(ctx, name, []string{"/usr/bin/install", "-m", "0600", "/dev/null", guestHelper}, nil); err != nil {
			return errors.New("prepare guest helper")
		}
		if _, err := p.output(ctx, name, []string{"dd", "of=" + guestHelper, "status=none"}, f); err != nil {
			return errors.New("install guest helper")
		}
		_, err := p.output(ctx, name, []string{"chmod", "0700", guestHelper}, nil)
		return err
	})
}
