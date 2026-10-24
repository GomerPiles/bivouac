//go:build windows

package imagefactory

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

func createBase(path string, gb uint32) error {
	h, err := vhd.CreateVirtualDisk(path, vhd.VirtualDiskAccessNone, vhd.CreateVirtualDiskFlagNone, &vhd.CreateVirtualDiskParameters{Version: 2, Version2: vhd.CreateVersion2{MaximumSize: uint64(gb) << 30, SectorSizeInBytes: 512, PhysicalSectorSizeInByte: 512}})
	if err != nil {
		return errors.New("owned base VHDX creation failed")
	}
	return windows.CloseHandle(windows.Handle(h))
}

func prepareBase(ctx context.Context, c Config, r *record) error {
	return prepareBaseWith(ctx, c, r, r.save, createBase, runHost)
}

func (r *record) intent(name string, save func() error) error {
	if r.StorageIntents == nil {
		r.StorageIntents = map[string]bool{}
	}
	r.StorageIntents[name] = true
	return save()
}

func validGUID(s string) bool {
	if len(s) != 38 || s[0] != '{' || s[37] != '}' {
		return false
	}
	for i := 1; i < 37; i++ {
		if i == 9 || i == 14 || i == 19 || i == 24 {
			if s[i] != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", rune(s[i])) {
			return false
		}
	}
	return s != "{00000000-0000-0000-0000-000000000000}"
}

func prepareBaseWith(ctx context.Context, c Config, r *record, save func() error, create func(string, uint32) error, run func(context.Context, string, any, bool) ([]byte, error)) error {
	data := r.scriptData()
	data["index"] = strconv.FormatUint(uint64(r.Manifest.Media.Image.Index), 10)
	data["kind"] = r.Manifest.Media.Kind
	data["locale"] = r.Manifest.Media.Image.DefaultLanguage
	invoke := func(mode string) ([]byte, error) {
		data["mode"] = mode
		b, e := run(ctx, bootHelpers+baseDisk, data, true)
		r.hostError("base_"+mode, e)
		return b, e
	}
	if err := r.intent("iso_mount", save); err != nil {
		return err
	}
	b, err := invoke("media")
	if err != nil {
		return err
	}
	var media struct {
		Volume        string `json:"volume"`
		Letter        string `json:"letter"`
		WindowsLetter string `json:"windows_letter"`
	}
	if json.Unmarshal(b, &media) != nil || !strings.HasPrefix(media.Volume, `\\?\Volume{`) || !strings.HasSuffix(media.Volume, `}\`) || !validTemporaryLetter(media.Letter) || !validTemporaryLetter(media.WindowsLetter) || media.Letter == media.WindowsLetter {
		return errors.New("invalid owned media mount result")
	}
	data["volume"] = media.Volume
	r.TemporaryLetter = media.Letter
	r.WindowsTemporaryLetter = media.WindowsLetter
	if err = r.intent("base_attach", save); err != nil {
		return err
	}
	if err = create(filepath.Join(r.Workspace, "source.vhdx"), c.DiskGB); err != nil {
		return err
	}
	// The complete layout/access-path plan is durable before the first attach.
	// Even a process loss between New-Partition and the returned GUIDs can be
	// recovered by detaching only the recorded owned backing file.
	for _, name := range []string{"esp_access", "windows_access"} {
		if err = r.intent(name, save); err != nil {
			return err
		}
	}
	data["letter"] = r.TemporaryLetter
	data["windows_letter"] = r.WindowsTemporaryLetter
	b, err = invoke("layout")
	if err != nil {
		return errors.Join(err, layoutShape(b))
	}
	var layout DiskLayout
	if json.Unmarshal(b, &layout) != nil || !validGUID(layout.DiskGUID) || !validGUID(layout.ESPGUID) || !validGUID(layout.MSRGUID) || !validGUID(layout.WindowsGUID) {
		return errors.New("invalid owned GPT layout result")
	}
	r.Manifest.Media.Layout = layout
	if err = save(); err != nil {
		return err
	}
	data["disk_guid"] = layout.DiskGUID
	data["windows_guid"] = layout.WindowsGUID
	data["esp_guid"] = layout.ESPGUID
	b, err = invoke("apply")
	if err != nil {
		return err
	}
	var applied struct {
		DISMVersion string `json:"dism_version"`
	}
	if json.Unmarshal(b, &applied) != nil || !numericVersion(applied.DISMVersion) {
		return errors.New("invalid DISM version result")
	}
	r.Manifest.Media.DISMVersion = applied.DISMVersion
	// Use the applied image's 2011 boot files and explicit private BCD store.
	loader, err := windows.GenerateGUID()
	if err != nil {
		return errors.New("boot loader identity generation failed")
	}
	r.Manifest.Media.LoaderGUID = strings.ToLower(loader.String())
	r.Manifest.Media.BootMethod = "scratch_bcdedit_uefi_2011"
	data["loader_guid"] = r.Manifest.Media.LoaderGUID
	r.Manifest.Media.WinRE = "apply_time_no_recovery_partition_not_registered_by_factory"
	if err = save(); err != nil {
		return err
	}
	if err = r.intent("temporary_letter", save); err != nil {
		return err
	}
	if err = r.intent("windows_temporary_letter", save); err != nil {
		return err
	}
	b, err = invoke("boot")
	if err != nil {
		return errors.Join(err, bootShape(b))
	}
	var boot struct {
		Version  string      `json:"bcdedit_version"`
		Issuers  BootIssuers `json:"boot_issuers"`
		Verified bool        `json:"bcd_verified"`
	}
	if json.Unmarshal(b, &boot) != nil || !numericVersion(boot.Version) || !boot.Verified || boot.Issuers.Fallback != "windows_production_pca_2011" || boot.Issuers.Microsoft != "windows_production_pca_2011" || boot.Issuers.Source != "windows_production_pca_2011" {
		return errors.New("invalid offline boot signature result")
	}
	r.Manifest.Media.BCDEditVersion = boot.Version
	r.Manifest.Media.BCDVerified = boot.Verified
	r.Manifest.Media.BootIssuers = boot.Issuers
	if err = save(); err != nil {
		return err
	}
	if _, err = invoke("detach"); err != nil {
		return err
	}
	return nil
}

func validTemporaryLetter(s string) bool {
	return len(s) == 1 && s[0] >= 'D' && s[0] <= 'Z'
}

func numericVersion(s string) bool {
	if len(s) < 7 || len(s) > 48 {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, e := strconv.ParseUint(p, 10, 32); e != nil {
			return false
		}
	}
	return true
}
