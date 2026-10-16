//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"golang.org/x/sys/windows"
)

//go:embed make_iso.ps1
var makeISO string

//go:embed guest_setup.ps1
var guestSetup string

//go:embed stage_setup.ps1
var stageSetup string

//go:embed guest_specialize.ps1
var guestSpecialize string

func validatePinned(c Config, f PinnedFile) error {
	h, err := hex.DecodeString(f.SHA256)
	if !localPath(f.Source) || within(c.Root, f.Source) || err != nil || len(h) != 32 {
		return errors.New("resource must be an external local file with a SHA-256 pin")
	}
	return nil
}
func validateAssets(c Config) error {
	if c.RenderProbe != nil {
		if err := validatePinned(c, *c.RenderProbe); err != nil {
			return err
		}
	}
	if len(c.SetupAssets) == 0 {
		return nil
	}
	required := map[string]bool{"APPSANDBOX-AGENT.EXE": false, "APPSANDBOX-INPUT.EXE": false, "APPSANDBOX-DISPLAYS.EXE": false, "APPSANDBOXVDD.DLL": false, "APPSANDBOXVDD.INF": false, "APPSANDBOXVDD.CAT": false, "DEVCON.EXE": false}
	seen := map[string]bool{}
	for _, a := range c.SetupAssets {
		name := strings.ToUpper(a.Name)
		_, requiredName := required[name]
		if (!requiredName && name != "OPENSSH.MSI") || seen[name] {
			return errors.New("unsupported or duplicate setup asset")
		}
		seen[name] = true
		required[name] = true
		if err := validatePinned(c, a.PinnedFile); err != nil {
			return err
		}
	}
	for _, present := range required {
		if !present {
			return errors.New("setup assets must include the fixed guest agent, display/input helpers and VDD package")
		}
	}
	return nil
}
func readPinned(f PinnedFile) ([]byte, error) {
	if err := appsandbox.CheckProtectedFile(f.Source); err != nil {
		return nil, errors.New("spike resource is not administrator-protected")
	}
	in, err := os.Open(f.Source)
	if err != nil {
		return nil, errors.New("cannot open spike resource")
	}
	defer func() { _ = in.Close() }()
	b, err := io.ReadAll(io.LimitReader(in, 64<<20+1))
	if err != nil || len(b) > 64<<20 {
		return nil, errors.New("spike resource exceeds 64 MiB")
	}
	h := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(h[:]), f.SHA256) {
		return nil, errors.New("spike resource SHA-256 differs")
	}
	return b, nil
}
func encodedPowerShell(s string) string {
	words := utf16.Encode([]rune(s))
	b := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func unattended(c Config, password string) string {
	// Code is fixed; instance fields appear only in XML data elements.
	boot := encodedPowerShell(`$ErrorActionPreference='Stop';$d=Get-Volume | Where-Object FileSystemLabel -eq 'HCSSETUP' | Select-Object -First 1;if(!$d.DriveLetter){exit 1};& (Join-Path ($d.DriveLetter+':\') 'SETUP.PS1')`)
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
<settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>%s</ComputerName></component><component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Windows\Panther\Unattend\specialize.ps1</Path></RunSynchronousCommand></RunSynchronous></component></settings>
<settings pass="oobeSystem">
<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
<OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
<UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>%s</Name><Group>Administrators</Group><Password><Value>%s</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
<AutoLogon><Enabled>true</Enabled><Username>%s</Username><Password><Value>%s</Value><PlainText>true</PlainText></Password><LogonCount>1</LogonCount></AutoLogon>
<FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><Description>Initialize disposable HCS guest</Description><CommandLine>powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s</CommandLine><RequiresUserInput>false</RequiresUserInput></SynchronousCommand></FirstLogonCommands>
</component></settings></unattend>`, xmlText(c.name()), xmlText(c.GuestUser), xmlText(password), xmlText(c.GuestUser), xmlText(password), boot)
}
func makeSetupISO(ctx context.Context, c Config) error {
	private := filepath.Join(c.directory(), "setup-private")
	if err := os.Mkdir(private, 0700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return errors.New("cannot construct private setup permissions")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetNamedSecurityInfo(private, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return errors.New("cannot protect private setup directory")
	}
	folder := filepath.Join(c.directory(), "setup-assets")
	if err := os.Mkdir(folder, 0700); err != nil {
		return err
	}
	var total int
	for _, asset := range c.SetupAssets {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := readPinned(asset.PinnedFile)
		if err != nil {
			return err
		}
		total += len(b)
		if total > 128<<20 {
			return errors.New("setup assets exceed 128 MiB")
		}
		if err = os.WriteFile(filepath.Join(folder, asset.Name), b, 0600); err != nil {
			return err
		}
	}
	if c.RenderProbe != nil {
		probe, err := readPinned(*c.RenderProbe)
		if err != nil {
			return err
		}
		if len(probe) > 128<<20-total {
			return errors.New("setup assets exceed 128 MiB")
		}
		if err := os.WriteFile(filepath.Join(folder, "HCSRENDER.EXE"), probe, 0600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(folder, "HCSVALIDATE.PS1"), []byte(guestValidate), 0600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(folder, "SETUP.PS1"), []byte(guestSetup), 0600); err != nil {
		return err
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	password := "Bv!" + hex.EncodeToString(random[:])
	clear(random[:])
	data, err := json.Marshal(map[string]string{"assets": folder, "destination": filepath.Join(private, "setup.iso"), "unattend": unattended(c, password), "specialize": guestSpecialize, "disk": c.disk(), "root": c.Root, "instance_id": c.InstanceID})
	if err != nil {
		return errors.New("cannot encode private setup input")
	}
	defer clear(data)
	if err = runPrivateSetup(ctx, makeISO, data); err != nil {
		return errors.New("disposable setup ISO creation failed")
	}
	if err = appsandbox.CheckProtectedFile(c.disk()); err != nil {
		return errors.New("new child disk lost protection before offline setup")
	}
	if err = runPrivateSetup(ctx, stageSetup, data); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if code := exitErr.ExitCode(); code > 10000 && code <= 75535 {
				return fmt.Errorf("offline child answer-directory protection failed (Win32 %d)", code-10000)
			}
			switch exitErr.ExitCode() {
			case 10, 20, 30, 40, 50, 60, 61, 62, 63, 70:
				return fmt.Errorf("offline child answer-file staging failed at step %d", exitErr.ExitCode())
			}
		}
		return errors.New("offline child answer-file staging failed")
	}
	// No host staging file ever contains the local guest password. Only the
	// protected child ISO/guest disk does; both are removed with this trial.
	return nil
}

// Scripts are fixed code; private input is bounded JSON on stdin, never arguments
// or output. The baseline handle remains pinned read-only in the caller.
func runPrivateSetup(ctx context.Context, script string, data []byte) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
