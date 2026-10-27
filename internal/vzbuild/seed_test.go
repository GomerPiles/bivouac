package vzbuild

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

func TestSeedContentAndGuestRequest(t *testing.T) {
	r := vzrecipe.Registry()[0]
	files, err := seedFiles(r, ISOFile{Size: 6, Reader: strings.NewReader("helper")}, ISOFile{Size: 6, Reader: strings.NewReader("runner")})
	if err != nil {
		t.Fatal(err)
	}
	var iso bytes.Buffer
	if err := WriteISO(&iso, files); err != nil {
		t.Fatal(err)
	}
	read := readISO(t, iso.Bytes(), true)
	// Keep the security/order boundary explicit in the regression, independent of
	// the production seed constant. No packages, persistent files or shell input.
	expected := `#cloud-config
users: []
ssh_pwauth: false
disable_root: true
runcmd:
  - [mkdir, -p, /run/bivouac-seed]
  - [mount, -t, iso9660, -o, ro, /dev/disk/by-id/virtio-bivouac-seed, /run/bivouac-seed]
  - [systemd-run, --no-block, --unit=bivouac-provision, --property=Type=oneshot, --property=After=cloud-final.service, --property=SuccessAction=poweroff, --property=FailureAction=poweroff, --property=StandardInput=file:/run/bivouac-seed/provision.json, --property=StandardOutput=file:/dev/disk/by-id/virtio-bivouac-receipt, --property=StandardError=null, /run/bivouac-seed/helper, guest, linux, provision]
`
	if string(read["user-data"]) != expected || string(read["helper"]) != "helper" || string(read["runner.tar.gz"]) != "runner" || len(read) != 5 {
		t.Fatal("seed differs")
	}
	request, err := linuxguest.DecodeProvisionRequest(bytes.NewReader(read["provision.json"]))
	if err != nil || request.Recipe != linuxguest.ProvisionRecipeName || request.RunnerSHA256 != r.Runner.SHA256 || request.RunnerArchive != "/run/bivouac-seed/runner.tar.gz" {
		t.Fatal("guest request differs", err)
	}
}
func TestReceiptWholeDiskAndContract(t *testing.T) {
	hash := strings.Repeat("a", 64)
	success := linuxguest.PreparedLinuxImage{Profile: linuxguest.VZ, DNSDHCP: true, HelperSHA256: hash, RunnerUnconfigured: true, MachineIDCleared: true}
	b, err := json.Marshal(success)
	if err != nil {
		t.Fatal(err)
	}
	framed := func(line []byte) []byte {
		out := make([]byte, receiptSize)
		copy(out, line)
		out[len(line)] = '\n'
		return out
	}
	if err := readReceipt(bytes.NewReader(framed(b)), hash); err != nil {
		t.Fatal(err)
	}
	failure := framed([]byte(`{"failed_stage":7}`))
	if err := readReceipt(bytes.NewReader(failure), hash); err == nil || err.Error() != "baseline provisioning failed at stage 7" {
		t.Fatal("failure stage lost", err)
	}
	for _, kind := range []string{"tail", "second-line", "missing-newline", "short", "long", "hash", "unknown", "bad-stage"} {
		t.Run(kind, func(t *testing.T) {
			out := framed(b)
			want := hash
			switch kind {
			case "tail":
				out[receiptSize-1] = 1
			case "second-line":
				copy(out[len(b)+1:], "{}\n")
			case "missing-newline":
				out = make([]byte, receiptSize)
			case "short":
				out = out[:len(out)-1]
			case "long":
				out = append(out, 0)
			case "hash":
				want = strings.Repeat("b", 64)
			case "unknown":
				out = framed([]byte(`{"unexpected":true}`))
			case "bad-stage":
				out = framed([]byte(`{"failed_stage":99}`))
			}
			if err := readReceipt(bytes.NewReader(out), want); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}
}
func TestFactoryRecordValidation(t *testing.T) {
	r := factoryRecord{Owner: factoryOwner, ID: strings.Repeat("a", 32), Recipe: vzrecipe.DefaultName, Target: vzrecipe.DefaultName, Phase: "staging", BuildDir: ".build-" + strings.Repeat("a", 32), GateDir: ".gate-" + strings.Repeat("a", 32)}
	dir := t.TempDir()
	if err := writeRecord(dir, r); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(dir + "/" + r.ID + ".json"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".hidden", "../escape", "bivouac-runner", "white space", "a;command"} {
		if validTarget(name) == nil {
			t.Fatal("bad target accepted", name)
		}
	}
	r.Phase = "swap"
	if writeRecord(dir, r) == nil {
		t.Fatal("swap without identities accepted")
	}
}
