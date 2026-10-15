package vm

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const tartConfig = `{"version":1,"os":"darwin","arch":"arm64","cpuCount":4,"cpuCountMin":2,
"memorySize":8589934592,"memorySizeMin":4294967296,"macAddress":"86:a8:41:17:aa:30",
"hardwareModel":"aGFyZHdhcmU=","ecid":"ZWNpZA==","diskFormat":"asif",
"display":{"width":1024,"height":768},"futureField":{"kept":true}}`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadConfigDecodesTartFormat(t *testing.T) {
	c, err := ReadConfig(writeConfig(t, tartConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.CPUCount != 4 || c.MemorySize != 8<<30 || string(c.HardwareModel) != "hardware" || string(c.ECID) != "ecid" || c.Display.Width != 1024 {
		t.Fatalf("decoded %+v", c)
	}
}

func TestReadConfigRejectsUnsupported(t *testing.T) {
	for _, edit := range []struct{ from, to string }{
		{`"version":1`, `"version":2`},
		{`"arch":"arm64"`, `"arch":"amd64"`},
		{`"os":"darwin"`, `"os":"windows"`},
		{`"cpuCount":4`, `"cpuCount":0`},
		{`"macAddress":"86:a8:41:17:aa:30"`, `"macAddress":"nope"`},
		{`"ecid":"ZWNpZA=="`, `"ecid":""`},
	} {
		if _, err := ReadConfig(writeConfig(t, strings.Replace(tartConfig, edit.from, edit.to, 1))); err == nil {
			t.Errorf("accepted %s", edit.to)
		}
	}
	linux := strings.NewReplacer(`"os":"darwin"`, `"os":"linux"`, `"ecid":"ZWNpZA=="`, `"ecid":""`).Replace(tartConfig)
	if _, err := ReadConfig(writeConfig(t, linux)); err != nil {
		t.Errorf("Linux guests need no Mac identity: %v", err)
	}
}

func TestUpdateConfigKeepsUnknownFields(t *testing.T) {
	dir := writeConfig(t, tartConfig)
	if err := updateConfig(dir, map[string]any{"cpuCount": 6, "macAddress": "02:00:00:00:00:01"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["cpuCount"] != 6.0 || raw["macAddress"] != "02:00:00:00:00:01" || raw["futureField"] == nil || raw["hardwareModel"] != "aGFyZHdhcmU=" {
		t.Fatalf("rewrote %s", data)
	}
}

func TestRandomMACIsLocalUnicast(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		s, err := randomMAC()
		if err != nil {
			t.Fatal(err)
		}
		mac, err := net.ParseMAC(s)
		if err != nil || mac[0]&0x01 != 0 || mac[0]&0x02 == 0 {
			t.Fatalf("%s is not a locally administered unicast address", s)
		}
		seen[s] = true
	}
	if len(seen) < 60 {
		t.Fatal("MAC addresses repeat")
	}
}

func TestNamesStayInsideHome(t *testing.T) {
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", `a\b`, "a\x00b", "a\nb"} {
		if validName(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := validName("bivouac-macos-1234abcd"); err != nil {
		t.Fatal(err)
	}
	home := Home(strings.Repeat("h", 120))
	if _, err := home.SocketPath("x"); err == nil {
		t.Fatal("accepted an agent socket path longer than sun_path")
	}
}

func TestHelperArgumentsRoundTrip(t *testing.T) {
	for _, o := range []RunOptions{
		{Dir: "/vms/a", AgentPort: 7},
		{Dir: "/vms/a", Share: "/share", Input: true, AgentPort: 9, Softnet: &SoftnetOptions{Binary: "/bin/softnet", Sudo: true, Block: "@host,10.0.0.0/8"}},
	} {
		got, err := ParseArgs(o.Args())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, o) {
			t.Fatalf("round trip %+v -> %+v", o, got)
		}
	}
	for _, bad := range [][]string{
		{"--dir", "relative", "--agent-port", "1"},
		{"--dir", "/a"},
		{"--dir", "/a", "--agent-port", "1", "extra"},
		{"--dir", "/a", "--agent-port", "1", "--softnet-block", "@host"},
		{"--dir", "/a", "--agent-port", "4294967296"},
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
