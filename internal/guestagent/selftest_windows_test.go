//go:build windows

package guestagent

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestTaskFactsAreFixedAndRequireActualSettings(t *testing.T) {
	raw := `<?xml version="1.0" encoding="UTF-16"?><Task><Principals><Principal><UserId>user-sid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><Priority>4</Priority></Settings><Actions><Exec><Command>C:\Program Files\Bivouac\bivouac.exe</Command><Arguments>guest-agent --user imageuser</Arguments></Exec></Actions></Task>`
	resolve := func(value string) string { return value }
	for _, mode := range []string{"valid", "utf16", "user", "priority", "interactive", "action", "highest", "DTD"} {
		t.Run(mode, func(t *testing.T) {
			text := raw
			switch mode {
			case "user":
				text = strings.ReplaceAll(text, "user-sid", "other-sid")
			case "priority":
				text = strings.ReplaceAll(text, ">4<", ">7<")
			case "interactive":
				text = strings.ReplaceAll(text, "InteractiveToken", "Password")
			case "highest":
				text = strings.ReplaceAll(text, "HighestAvailable", "LeastPrivilege")
			case "action":
				text = strings.ReplaceAll(text, "--user imageuser", "--user other")
			case "DTD":
				text = `<!DOCTYPE Task>` + text
			}
			b := []byte(text)
			if mode == "utf16" {
				b = []byte{0xff, 0xfe}
				for _, word := range utf16.Encode([]rune(text)) {
					b = binary.LittleEndian.AppendUint16(b, word)
				}
			}
			facts, err := taskFacts(b, "imageuser", "user-sid", resolve)
			valid := err == nil && facts.TaskUser && facts.TaskHighest && facts.TaskInteractive && facts.TaskAction && facts.TaskPriority == 4
			if valid != (mode == "valid" || mode == "utf16") {
				t.Fatal("invalid task facts decision")
			}
		})
	}
}

func TestTaskFactsUserID(t *testing.T) {
	const agentSID = "S-1-5-21-1-2-3-1001"
	const otherSID = "S-1-5-21-1-2-3-1002"
	for _, tc := range []struct {
		name        string
		userID      string
		wantMatch   bool
		wantResolve bool
	}{
		{"SID match", agentSID, true, false},
		{"SID mismatch", otherSID, false, false},
		{"account match", "imageuser", true, true},
		{"account mismatch", "otheruser", false, true},
		{"unresolvable account", "unknownuser", false, true},
		{"malformed SID", "S-1-5-invalid", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `<Task><Principals><Principal><UserId>` + tc.userID + `</UserId></Principal></Principals><Actions><Exec/></Actions></Task>`
			resolved := false
			resolve := func(name string) string {
				resolved = true
				switch name {
				case "imageuser":
					return agentSID
				case "otheruser":
					return otherSID
				}
				return ""
			}
			facts, err := taskFacts([]byte(raw), "imageuser", agentSID, resolve)
			if err != nil {
				t.Fatal(err)
			}
			if facts.TaskUser != tc.wantMatch || resolved != tc.wantResolve {
				t.Fatalf("task user match = %t, account lookup = %t; want %t, %t", facts.TaskUser, resolved, tc.wantMatch, tc.wantResolve)
			}
		})
	}
}

func TestInstalledAgentSecurityFacts(t *testing.T) {
	good := "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + installerSID + ")(A;;0x1200a9;;;BU)"
	for _, mode := range []string{"valid", "user write", "owner", "inheritance", "extra principal"} {
		t.Run(mode, func(t *testing.T) {
			text := good
			switch mode {
			case "user write":
				text = strings.ReplaceAll(text, "0x1200a9", "FA")
			case "owner":
				text = strings.ReplaceAll(text, "O:BA", "O:BU")
			case "inheritance":
				text = strings.ReplaceAll(text, "D:P", "D:")
			case "extra principal":
				text += "(A;;FA;;;WD)"
			}
			sd, err := windows.SecurityDescriptorFromString(text)
			if err != nil {
				t.Fatal(err)
			}
			owner, protected, expected := installationSecurity(sd)
			if (owner && protected && expected) != (mode == "valid") {
				t.Fatal("untrusted agent ACL admitted")
			}
		})
	}
}
