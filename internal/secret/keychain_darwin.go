package secret

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Keychain stores items as generic passwords in the login keychain through
// the system `security` tool. Using the tool instead of the Security
// framework keeps the binary cgo-free; items it creates are readable by the
// same tool without an access prompt, including from a LaunchAgent.
type Keychain struct {
	// Binary is the security tool; default /usr/bin/security.
	Binary string
}

func (k Keychain) bin() string {
	if k.Binary != "" {
		return k.Binary
	}
	return "/usr/bin/security"
}

// Get implements Store.
//
// `find-generic-password -w` prints the value verbatim when every byte is
// isprint() and as unmarked lowercase hex otherwise, so a secret that is
// itself even-length hex cannot be told apart from an encoded one. Get uses
// `-g` instead, which writes one stderr line "password: " followed by either
// a quoted literal ("...", used only when every byte is ' '..'~' and none is
// a backslash) or "0x" and uppercase hex, optionally followed by two spaces
// and an escaped quoted rendering. The 0x marker decides decoding.
func (k Keychain) Get(ctx context.Context, name string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, k.bin(), "find-generic-password", "-s", Service, "-a", name, "-g")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	defer func() { clear(stderr.Bytes()) }()
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "could not be found") {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keychain read %q: %w", name, err)
	}
	v, err := parsePassword(stderr.Bytes())
	if err != nil {
		return nil, fmt.Errorf("keychain read %q: %w", name, err)
	}
	return v, nil
}

const passwordPrefix = "password: "

// parsePassword extracts the value from `security ... -g` stderr. Errors
// never include the output, which holds the secret.
func parsePassword(out []byte) ([]byte, error) {
	for _, line := range bytes.Split(out, []byte("\n")) {
		rest, ok := bytes.CutPrefix(line, []byte(passwordPrefix))
		if !ok {
			continue
		}
		switch {
		case len(rest) == 0:
			return []byte{}, nil
		case bytes.HasPrefix(rest, []byte("0x")):
			digits, _, _ := bytes.Cut(rest[2:], []byte(" "))
			v := make([]byte, hex.DecodedLen(len(digits)))
			if len(digits) == 0 {
				return nil, errors.New("unrecognised hex password output")
			}
			if _, err := hex.Decode(v, digits); err != nil {
				return nil, errors.New("unrecognised hex password output")
			}
			return v, nil
		case len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"':
			v := rest[1 : len(rest)-1]
			for _, c := range v {
				if c < ' ' || c > '~' || c == '\\' {
					return nil, errors.New("unrecognised literal password output")
				}
			}
			return append([]byte(nil), v...), nil
		default:
			return nil, errors.New("unrecognised password output")
		}
	}
	return nil, errors.New("no password in keychain output")
}

// Set implements Store. The value passes on the command line of a short-lived
// same-user process; the system tool offers no stdin path for the value.
func (k Keychain) Set(ctx context.Context, name string, value []byte) error {
	if len(value) == 0 {
		return errors.New("empty secret")
	}
	cmd := exec.CommandContext(ctx, k.bin(), "add-generic-password", "-U", "-s", Service, "-a", name, "-l", "bivouac: "+name, "-w", string(value))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain write %q: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Delete implements Store.
func (k Keychain) Delete(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, k.bin(), "delete-generic-password", "-s", Service, "-a", name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "could not be found") {
			return ErrNotFound
		}
		return fmt.Errorf("keychain delete %q: %w", name, err)
	}
	return nil
}

// Default returns the platform store.
func Default() Store { return Keychain{} }
