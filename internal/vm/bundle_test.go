package vm

import (
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tartFixture is a Tart-format config.json.
const tartFixture = `{"version":1,"os":"darwin","arch":"arm64","cpuCount":4,"cpuCountMin":2,
"memorySize":8589934592,"memorySizeMin":4294967296,"macAddress":"86:a8:41:17:aa:30",
"hardwareModel":"aGFyZHdhcmU=","ecid":"ZWNpZA==","diskFormat":"asif",
"display":{"width":1024,"height":768},"futureField":{"kept":true}}`

func testManifest() Manifest {
	return Manifest{
		Version: ManifestVersion, OS: "darwin", Arch: "arm64", CPU: 4, CPUMin: 2, MemoryMiB: 8192, MemoryMinMiB: 4096,
		MAC: "86:a8:41:17:aa:30", Display: Display{Width: 1024, Height: 768},
		MacOS: &MacOSPlatform{HardwareModel: []byte("hardware"), MachineID: []byte("ecid")},
		Guest: Guest{AgentVersion: 1, RunnerDir: "/Users/admin/actions-runner", Sudo: true},
	}
}

func TestTartConfigImportsAsManifest(t *testing.T) {
	c, err := parseTartConfig([]byte(tartFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := testManifest()
	got, err := c.manifest(want.Guest)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest = %+v, %v", got, err)
	}
	linux := strings.NewReplacer(`"os":"darwin"`, `"os":"linux"`, `"ecid":"ZWNpZA=="`, `"ecid":""`).Replace(tartFixture)
	if c, err = parseTartConfig([]byte(linux)); err != nil {
		t.Fatal(err)
	}
	if m, err := c.manifest(Guest{AgentVersion: 1}); err != nil || m.MacOS != nil {
		t.Fatalf("Linux guests need no Mac identity: %+v, %v", m, err)
	}
	for _, edit := range []struct{ from, to string }{
		{`"version":1`, `"version":2`},
		{`"arch":"arm64"`, `"arch":"amd64"`},
		{`"cpuCount":4`, `"cpuCount":0`},
		{`"memorySize":8589934592`, `"memorySize":8589934593`},
		{`"ecid":"ZWNpZA=="`, `"ecid":""`},
	} {
		c, err := parseTartConfig([]byte(strings.Replace(tartFixture, edit.from, edit.to, 1)))
		if err == nil {
			_, err = c.manifest(want.Guest)
		}
		if err == nil {
			t.Errorf("imported %s", edit.to)
		}
	}
}

func TestManifestRoundTripsAndRejectsUnsupported(t *testing.T) {
	dir := t.TempDir()
	if err := writeManifest(dir, testManifest()); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadManifest(dir); err != nil || !reflect.DeepEqual(m, testManifest()) {
		t.Fatalf("read back %+v, %v", m, err)
	}
	for name, edit := range map[string]func(*Manifest){
		"version":         func(m *Manifest) { m.Version = 2 },
		"arch":            func(m *Manifest) { m.Arch = "amd64" },
		"os":              func(m *Manifest) { m.OS = "windows" },
		"cpu":             func(m *Manifest) { m.CPU = 0 },
		"cpu below min":   func(m *Manifest) { m.CPU = 1 },
		"memory":          func(m *Manifest) { m.MemoryMiB = 1024 },
		"mac":             func(m *Manifest) { m.MAC = "nope" },
		"multicast mac":   func(m *Manifest) { m.MAC = "01:00:5e:00:00:01" },
		"no mac identity": func(m *Manifest) { m.MacOS = nil },
		"linux identity":  func(m *Manifest) { m.OS = "linux" },
		"agent":           func(m *Manifest) { m.Guest.AgentVersion = 0 },
		"runner dir":      func(m *Manifest) { m.Guest.RunnerDir = "actions-runner" },
		"half display":    func(m *Manifest) { m.Display.Height = 0 },
	} {
		m := testManifest()
		edit(&m)
		if err := m.validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, m)
		}
	}
	data, err := json.Marshal(testManifest())
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(data), `{"version"`, `{"future":true,"version"`, 1)
	if _, err := parseManifest([]byte(unknown)); err == nil {
		t.Error("accepted an unknown field")
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

func TestNamesStayInsideTheStore(t *testing.T) {
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", `a\b`, "a\x00b", "a\nb"} {
		if validName(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := validName("bivouac-macos-1234abcd"); err != nil {
		t.Fatal(err)
	}
	if _, err := Store(strings.Repeat("h", 90)).SocketPath("x"); err == nil {
		t.Fatal("accepted an agent socket path longer than sun_path")
	}
	if Store(strings.Repeat("h", 90)).CheckSocketPath() == nil || Store("/Users/someone/Library/Application Support/bivouac/vms").CheckSocketPath() != nil {
		t.Fatal("store socket check disagrees with SocketPath")
	}
	// The socket path length does not depend on the VM name.
	store := Store("/Users/someone/Library/Application Support/bivouac/vms")
	short, err := store.SocketPath("x")
	if err != nil {
		t.Fatal(err)
	}
	long, err := store.SocketPath("bivouac-" + strings.Repeat("p", 60) + "-1234abcd-engine")
	if err != nil || len(long) != len(short) || long == short || filepath.Dir(long) != filepath.Join(string(store), runDir) {
		t.Fatalf("socket paths %q, %q: %v", short, long, err)
	}
}

func TestHelperArgumentsRoundTrip(t *testing.T) {
	abs := func(name string) string { return filepath.Join(t.TempDir(), name) }
	dir, sock := abs("a"), abs("a.sock")
	for _, o := range []RunOptions{
		{Dir: dir, AgentPort: 7, AgentSocket: sock},
		{Dir: dir, Share: abs("share"), Input: true, AgentPort: 9, AgentSocket: sock, RootlessNetwork: true},
		{Dir: dir, AgentPort: 7, AgentSocket: sock, Machine: MachineOptions{Display: Display{Width: 1920, Height: 1080}, DiskSync: "none"}},
		{Dir: dir, AgentPort: 7, AgentSocket: sock, Machine: MachineOptions{Display: Display{Width: 2560, Height: 1600, PPI: 144}, DiskSync: "fsync"}},
		{Dir: dir, AgentPort: 7, AgentSocket: sock, Machine: MachineOptions{Nested: true}},
	} {
		if o.RootlessNetwork {
			o.Network = o.Network.WithDefaults()
		}
		got, err := ParseArgs(o.Args())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, o) {
			t.Fatalf("round trip %+v -> %+v", o, got)
		}
	}
	for _, bad := range [][]string{
		{"--dir", "relative", "--agent-port", "1", "--agent-socket", sock},
		{"--dir", dir, "--agent-socket", sock},
		{"--dir", dir, "--agent-port", "1"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", "relative.sock"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "extra"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--softnet-block", "@host"},
		{"--dir", dir, "--agent-port", "4294967296", "--agent-socket", sock},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--disk-sync", "unsafe"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--display", "1920"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--display", "1920x1080@0"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--display", "0x0"},
		{"--dir", dir, "--agent-port", "1", "--agent-socket", sock, "--display", "99999x1080"},
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMachineOptionsFitTheGuest(t *testing.T) {
	mac := testManifest()
	linux := testManifest()
	linux.OS, linux.MacOS = "linux", nil
	nested := MachineOptions{Nested: true}
	display := MachineOptions{Display: Display{Width: 1920, Height: 1080}}
	if err := nested.CheckGuest(linux); err != nil {
		t.Fatal(err)
	}
	if err := display.CheckGuest(mac); err != nil {
		t.Fatal(err)
	}
	if err := nested.CheckGuest(mac); err == nil || !strings.Contains(err.Error(), "only to Linux guests") {
		t.Fatalf("nested macOS guest: %v", err)
	}
	if err := display.CheckGuest(linux); err == nil {
		t.Fatal("display accepted for a Linux guest")
	}
}
