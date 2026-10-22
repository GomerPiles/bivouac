//go:build windows

package imagefactory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

func prepareMedia(ctx context.Context, c Config, r *record) error {
	return prepareMediaWith(ctx, c, r, newProtectedDirectory, copyPinned, runHost)
}

func prepareMediaWith(ctx context.Context, c Config, r *record, mkdir func(string) error, copyFile func(context.Context, string, string, string, int64) (int64, string, error), run func(context.Context, string, any, bool) ([]byte, error)) error {
	assets := filepath.Join(r.Workspace, "setup-assets")
	private := filepath.Join(r.Workspace, "setup-private")
	for _, dir := range []string{assets, private} {
		if err := mkdir(dir); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	_, digest, err := hashFile(ctx, self)
	if err != nil {
		return err
	}
	agent := filepath.Join(r.Workspace, "agent.exe")
	if _, _, err = copyFile(ctx, self, agent, digest, 128<<20); err != nil {
		return err
	}
	r.Manifest.AgentSHA256, r.Manifest.WindowsContract = digest, guestagent.WindowsContract
	var total int64
	for _, a := range c.SetupAssets {
		limit := int64(64 << 20)
		if strings.EqualFold(a.Name, "RUNNER.ZIP") {
			limit = 128 << 20
		}
		n, _, err := copyFile(ctx, a.Source, filepath.Join(assets, strings.ToUpper(a.Name)), a.SHA256, min(limit, (256<<20)-total))
		if err != nil {
			return err
		}
		total += n
		r.Manifest.Assets[strings.ToUpper(a.Name)] = strings.ToLower(a.SHA256)
	}
	if _, _, err := copyFile(ctx, c.RenderProbe.Source, filepath.Join(assets, "HCSRENDER.EXE"), c.RenderProbe.SHA256, min(64<<20, (256<<20)-total)); err != nil {
		return err
	}
	for name, content := range mediaScripts() {
		if err := os.WriteFile(filepath.Join(assets, name), []byte(content), 0600); err != nil {
			return err
		}
	}
	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	password := "Bv!" + hex.EncodeToString(secret[:])
	clear(secret[:])
	data := r.scriptData()
	data["assets"] = assets
	data["destination"] = filepath.Join(private, "setup.iso")
	data["unattend"] = unattended(r.Name, c.GuestUser, password)
	data["specialize"] = guestVideo + guestSpecialize + disableFirstLogonAnimation
	data["agent"] = agent
	data["agent_sha256"] = digest
	driverPlan, err := encodeDriverPlan(r.Manifest.Drivers)
	if err != nil {
		return err
	}
	data["driver_plan"] = string(driverPlan)
	defer func() { delete(data, "unattend") }()
	if _, err := run(ctx, makeISO, data, false); err != nil {
		r.hostError("setup_iso", err)
		return fmt.Errorf("protected setup ISO creation failed: %w", err)
	}
	if _, err := run(ctx, offlinePayload+stageSetup, data, false); err != nil {
		r.hostError("stage_setup", err)
		return fmt.Errorf("offline owned-child answer staging failed: %w", err)
	}
	return nil
}

const disableFirstLogonAnimation = `
$policy='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if(!(Test-Path -LiteralPath $policy)){New-Item -Path $policy | Out-Null}
New-ItemProperty -Path $policy -Name EnableFirstLogonAnimation -Value 0 -PropertyType DWord -Force | Out-Null
`
