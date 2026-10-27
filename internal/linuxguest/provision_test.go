package linuxguest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func provisionHelperFixture() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 183)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[52:], 64)
	return b
}
func runnerArchiveFixture(t *testing.T, extra ...*tar.Header) ([]byte, string) {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tr := tar.NewWriter(gz)
	for _, name := range []string{"bin/Runner.Listener", "bin/installdependencies.sh", "run.sh", "config.sh"} {
		if err := tr.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0755, Size: 7}); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Write([]byte("fixture")); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range extra {
		if err := tr.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data.Bytes())
	return data.Bytes(), hex.EncodeToString(hash[:])
}
func TestProvisionRegistryAndBoundedRequest(t *testing.T) {
	registry := provisionRecipes()
	if len(registry) != 1 || registry[0].profile != VZ {
		t.Fatal("unexpected recipe registry")
	}
	r := registry[0]
	request := ProvisionRequest{Recipe: r.name, RunnerArchive: "/tmp/runner with spaces;$(literal).tar.gz", RunnerSHA256: strings.Repeat("a", 64)}
	data, _ := json.Marshal(request)
	if got, err := decodeProvisionRequest(bytes.NewReader(data)); err != nil || got != request {
		t.Fatal("bounded request", err)
	}
	for _, bad := range []string{string(data) + " {}", strings.Replace(string(data), `{`, `{"unknown":true,`, 1), strings.Repeat(" ", 4097), strings.Replace(string(data), r.name, "unknown", 1), strings.Replace(string(data), request.RunnerArchive, "../runner", 1), strings.Replace(string(data), request.RunnerSHA256, strings.Repeat("A", 64), 1)} {
		if _, err := decodeProvisionRequest(strings.NewReader(bad)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	for _, env := range []struct {
		os, arch        string
		uid             int
		distro, version string
	}{
		{"linux", "arm64", 0, "ubuntu", "24.04"}, {"darwin", "arm64", 0, "ubuntu", "24.04"}, {"linux", "amd64", 0, "ubuntu", "24.04"}, {"linux", "arm64", 1000, "ubuntu", "24.04"}, {"linux", "arm64", 0, "debian", "24.04"}, {"linux", "arm64", 0, "ubuntu", "26.04"},
	} {
		selected, err := selectProvisionRecipe(r.name, env.os, env.arch, env.uid, env.distro, env.version)
		if err == nil && (selected.name != r.name || selected.profile != VZ || selected.distro != "ubuntu" || selected.version != "24.04") {
			t.Fatal("selected recipe lost its execution constraints")
		}
		if (err == nil) != (env.os == "linux" && env.arch == "arm64" && env.uid == 0 && env.distro == "ubuntu" && env.version == "24.04") {
			t.Fatal("unknown environment admitted")
		}
	}
	registry[0].packages[0] = "modified"
	if provisionRecipes()[0].packages[0] == "modified" {
		t.Fatal("mutable registry leaked")
	}
	for _, forbidden := range []string{"nameservers:", "1.1.1.1", "8.8.8.8"} {
		if strings.Contains(provisionNetwork, forbidden) {
			t.Fatal("forced DNS in VZ recipe")
		}
	}
	if !strings.Contains(provisionNetwork, "use-dns: true") || !strings.Contains(provisionAgentDropin, "User=bivouac") {
		t.Fatal("DHCP/non-root agent contract")
	}
}
func TestProvisionDistroAccountsAndStaticHelper(t *testing.T) {
	distro, version, err := provisionDistro([]byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	if err != nil || distro != "ubuntu" || version != "24.04" {
		t.Fatal("Ubuntu identity", err)
	}
	for _, bad := range []string{"ID=ubuntu\nID=debian", `ID="$(command)"`, "ID='ubuntu'", strings.Repeat(" ", 16385)} {
		if _, _, err := provisionDistro([]byte(bad)); err == nil {
			t.Fatal("ambiguous release accepted")
		}
	}
	accounts := "root:x:0:0::/root:/bin/bash\nbivouac:x:1001:1001::/home/bivouac:/bin/bash\n"
	parsed, err := provisionAccounts([]byte(accounts))
	if err != nil || len(parsed) != 2 || parsed["root"].uid != 0 || parsed["bivouac"].uid != 1001 || parsed["bivouac"].gid != 1001 || parsed["bivouac"].home != "/home/bivouac" {
		t.Fatal("dedicated account identity", err)
	}
	for _, bad := range []string{accounts + accounts, strings.Replace(accounts, "/home/bivouac", "/root", 1), accounts + "other:x:1002:1002::/home/other:/bin/bash\n", strings.Replace(accounts, "1001:1001", "0:0", 1)} {
		if _, err := provisionAccounts([]byte(bad)); err == nil {
			t.Fatal("unknown account layout accepted")
		}
	}
	helper := provisionHelperFixture()
	if err := validateProvisionHelper(helper); err != nil {
		t.Fatal(err)
	}
	dynamic := append(append([]byte{}, helper...), make([]byte, 56)...)
	binary.LittleEndian.PutUint64(dynamic[32:], 64)
	binary.LittleEndian.PutUint16(dynamic[54:], 56)
	binary.LittleEndian.PutUint16(dynamic[56:], 1)
	binary.LittleEndian.PutUint32(dynamic[64:], 3)
	wrongArch := append([]byte{}, helper...)
	binary.LittleEndian.PutUint16(wrongArch[18:], 62)
	for _, bad := range [][]byte{[]byte("not ELF"), wrongArch, dynamic} {
		if validateProvisionHelper(bad) == nil {
			t.Fatal("non-static ARM64 helper accepted")
		}
	}
}
func TestProvisionArchivePlanningAndRefusals(t *testing.T) {
	good, hash := runnerArchiveFixture(t, &tar.Header{Name: "bin/listener-link", Typeflag: tar.TypeSymlink, Linkname: "Runner.Listener"}, &tar.Header{Name: "listener-hardlink", Typeflag: tar.TypeLink, Linkname: "bin/Runner.Listener"})
	if entries, err := planProvisionArchive(bytes.NewReader(good), hash); err != nil || len(entries) != 6 {
		t.Fatal("safe pinned archive", err)
	}
	if _, err := planProvisionArchive(bytes.NewReader(good), strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	for _, header := range []*tar.Header{
		{Name: "../outside", Typeflag: tar.TypeReg}, {Name: "/outside", Typeflag: tar.TypeReg}, {Name: `C:\outside`, Typeflag: tar.TypeReg},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "hard", Typeflag: tar.TypeLink, Linkname: "missing"}, {Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "elsewhere"},
		{Name: "fifo", Typeflag: tar.TypeFifo}, {Name: ".credentials", Typeflag: tar.TypeReg}, {Name: "_work/job", Typeflag: tar.TypeDir},
		{Name: "run.sh", Typeflag: tar.TypeReg},
	} {
		t.Run(header.Name, func(t *testing.T) {
			data, hash := runnerArchiveFixture(t, header)
			if _, err := planProvisionArchive(bytes.NewReader(data), hash); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	if _, err := provisionArchiveEntry(&tar.Header{Name: "huge", Typeflag: tar.TypeReg, Size: provisionExtractLimit + 1}); err == nil {
		t.Fatal("oversize entry accepted")
	}
	// Tar/gzip corruption is checked even after the final tar end marker.
	corrupt := append([]byte{}, good...)
	corrupt[len(corrupt)-5] ^= 1
	hashBytes := sha256.Sum256(corrupt)
	if _, err := planProvisionArchive(bytes.NewReader(corrupt), hex.EncodeToString(hashBytes[:])); err == nil {
		t.Fatal("corrupt gzip trailer accepted")
	}
}
