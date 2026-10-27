package vzbuild

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/GomerPiles/bivouac/internal/linuxguest"
	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

// Cloud-init renders these fixed lists into shell-quoted commands. There is no
// interpolated shell source. The mount stays in /run; the unit is transient.
const seedUserData = `#cloud-config
users: []
ssh_pwauth: false
disable_root: true
runcmd:
  - [mkdir, -p, /run/bivouac-seed]
  - [mount, -t, iso9660, -o, ro, /dev/disk/by-id/virtio-bivouac-seed, /run/bivouac-seed]
  - [systemd-run, --no-block, --unit=bivouac-provision, --property=Type=oneshot, --property=After=cloud-final.service, --property=SuccessAction=poweroff, --property=FailureAction=poweroff, --property=StandardInput=file:/run/bivouac-seed/provision.json, --property=StandardOutput=file:/dev/disk/by-id/virtio-bivouac-receipt, --property=StandardError=null, /run/bivouac-seed/helper, guest, linux, provision]
`

func seedFiles(r vzrecipe.Recipe, helper, runner ISOFile) ([]ISOFile, error) {
	req := linuxguest.ProvisionRequest{Recipe: r.Name, RunnerArchive: "/run/bivouac-seed/runner.tar.gz", RunnerSHA256: r.Runner.SHA256}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err = linuxguest.DecodeProvisionRequest(bytes.NewReader(b)); err != nil {
		return nil, err
	}
	file := func(name string, data []byte) ISOFile {
		return ISOFile{Name: name, Size: int64(len(data)), Reader: bytes.NewReader(data)}
	}
	helper.Name = "helper"
	runner.Name = "runner.tar.gz"
	return []ISOFile{file("meta-data", []byte("instance-id: bivouac-baseline\n")), file("user-data", []byte(seedUserData)), helper, runner, file("provision.json", b)}, nil
}

const receiptSize = 1 << 20

func readReceipt(r io.Reader, helperDigest string) error {
	b, err := io.ReadAll(io.LimitReader(r, receiptSize+1))
	if err != nil || len(b) != receiptSize {
		return errors.New("invalid provisioning receipt disk size")
	}
	end := bytes.IndexByte(b, '\n')
	if end < 1 || end > 64<<10 || !allZero(b[end+1:]) {
		return errors.New("invalid provisioning receipt framing")
	}
	line := b[:end]
	if _, err := linuxguest.DecodePreparedImage(line, linuxguest.VZ, helperDigest); err == nil {
		return nil
	}
	var failure struct {
		Stage uint32 `json:"failed_stage"`
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&failure) == nil && d.Decode(new(any)) == io.EOF && failure.Stage > 0 && failure.Stage <= 17 {
		return fmt.Errorf("baseline provisioning failed at stage %d", failure.Stage)
	}
	return errors.New("invalid provisioning success receipt")
}
