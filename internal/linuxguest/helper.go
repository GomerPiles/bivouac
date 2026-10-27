package linuxguest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// Probe fixed root-owned paths without executing an unverified image helper.
// No data is interpolated into shell source; this fixed script travels on stdin.
const PreparedHelperProbe = `set -eu
for p in / /usr /usr/local /usr/local/libexec /usr/local/libexec/bivouac-guest; do
 if [ ! -e "$p" ]; then printf 'absent\n';exit 0;fi
 if [ -L "$p" ]; then printf 'untrusted\n';exit 0;fi
 owner=$(/usr/bin/stat -c %u -- "$p")
 mode=$(/usr/bin/stat -c %a -- "$p")
 if [ "$owner" != 0 ] || [ "$((0$mode & 0022))" != 0 ]; then printf 'untrusted\n';exit 0;fi
done
if [ ! -f /usr/local/libexec/bivouac-guest ] || [ ! -x /usr/local/libexec/bivouac-guest ]; then printf 'untrusted\n';exit 0;fi
exec /usr/bin/sha256sum -- /usr/local/libexec/bivouac-guest
`

func HelperMatches(b []byte, want string) bool {
	return digest(want) && PreparedHelperFingerprint(b) == want
}

func PreparedHelperFingerprint(b []byte) string {
	if len(b) > 256 {
		return ""
	}
	hash, path, ok := strings.Cut(strings.TrimSpace(string(b)), "  ")
	if !ok || !digest(hash) || path != PreparedHelper {
		return ""
	}
	return hash
}

// HelperSHA256 pins a bounded public helper file before guest execution.
func HelperSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("cannot fingerprint Linux helper")
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, 128<<20+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || n > 128<<20 {
		return "", errors.New("linux helper fingerprint exceeds bound or is unreadable")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
