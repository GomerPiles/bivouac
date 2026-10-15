package secret

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
)

// fakeSecurityEnv makes the test binary act as `security find-generic-password
// -g`, printing the value in that command's stderr format.
const fakeSecurityEnv = "BIVOUAC_TEST_FAKE_SECURITY"

func TestMain(m *testing.M) {
	if v, ok := os.LookupEnv(fakeSecurityEnv); ok {
		_, _ = os.Stdout.WriteString("keychain: \"/tmp/login.keychain-db\"\nclass: \"genp\"\n")
		_, _ = os.Stderr.WriteString(securityRendering([]byte(v)) + "\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// securityRendering mirrors print_buffer in Apple's security tool
// (SecurityTool/macOS/keychain_utilities.c), which `-g` uses.
func securityRendering(v []byte) string {
	var b bytes.Buffer
	b.WriteString(passwordPrefix)
	hexForm, ascii := false, false
	for _, c := range v {
		if c >= ' ' && c <= '~' && c != '\\' {
			ascii = true
		} else {
			hexForm = true
		}
	}
	if hexForm {
		b.WriteString("0x")
		for _, c := range v {
			fmt.Fprintf(&b, "%02X", c)
		}
		if ascii {
			b.WriteString("  ")
		}
	}
	if ascii {
		b.WriteByte('"')
		for _, c := range v {
			if c >= ' ' && c <= '~' && c != '\\' {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\%03o", c)
			}
		}
		b.WriteByte('"')
	}
	return b.String()
}

var keychainValues = [][]byte{
	[]byte("deadbeefcafe0123"), // even-length hex: must not be decoded
	[]byte("0a0b"),
	[]byte("plain-token_with spaces and \"quotes\""),
	[]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n"),
	[]byte(`back\slash`),
	{0x00, 0xff, 0x10},
	[]byte("caf\xc3\xa9"),
}

func TestParsePasswordIsUnambiguous(t *testing.T) {
	for _, v := range keychainValues {
		got, err := parsePassword([]byte(securityRendering(v) + "\n"))
		if err != nil || !bytes.Equal(got, v) {
			t.Fatalf("%q: got %q, %v", v, got, err)
		}
	}
	for _, bad := range []string{"", "nothing here\n", "password: 0x\n", "password: 0xZZ\n", "password: 0xABC\n", "password: unquoted\n"} {
		if _, err := parsePassword([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestKeychainGetThroughTool(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range keychainValues {
		if bytes.IndexByte(v, 0) >= 0 {
			continue // environment values cannot carry NUL
		}
		t.Setenv(fakeSecurityEnv, string(v))
		got, err := (Keychain{Binary: exe}).Get(context.Background(), "item")
		if err != nil || !bytes.Equal(got, v) {
			t.Fatalf("%q: got %q, %v", v, got, err)
		}
	}
}
