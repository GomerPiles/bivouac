//go:build windows

package hcsspike

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio/vhd"
	"golang.org/x/sys/windows"
)

func imageBuildFixture(c Config) Config {
	c.ImageRoot = filepath.Join(filepath.Dir(c.Root), "HCS-Images")
	c.SetupAssets = setupFixture(c)
	c.SetupAssets = append(c.SetupAssets, SetupAsset{Name: "RUNNER.ZIP", PinnedFile: PinnedFile{Source: `C:\Fixture\runner.zip`, SHA256: c.BaselineSHA256}})
	c.RenderProbe = &PinnedFile{Source: `C:\Fixture\render.exe`, SHA256: c.BaselineSHA256}
	return c
}
func TestImageCaptureRequiresSanitationAndCleanShutdown(t *testing.T) {
	for _, fault := range []string{"none", "sanitation", "shutdown", "acknowledgement"} {
		t.Run(fault, func(t *testing.T) {
			c, j := testJournal(t)
			c = imageBuildFixture(c)
			f := &fakeBackend{imageReady: fault != "sanitation", shutdownAcknowledgementMissing: fault == "acknowledgement"}
			if fault == "shutdown" {
				f.shutdownErr = errors.New("shutdown rejected")
			}
			r, err := trial(context.Background(), c, j, f, false, true)
			if (err != nil) != (fault != "none") || !r.NativeAbsent || !r.StorageRetained || r.ImageBuilt {
				t.Fatalf("capture state: %+v %v", r, err)
			}
			if fault == "none" && (!r.CleanShutdown || f.shutdowns != 1 || f.stops != 0) {
				t.Fatal("clean capture used forced termination")
			}
			if fault != "none" && (r.CleanShutdown || f.stops != 1) {
				t.Fatal("failed sanitation/shutdown was accepted as a clean image")
			}
			if err := cleanup(context.Background(), c, j, f); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestTrialSessionUsesFreshIDsAndStopsOnRetainedWork(t *testing.T) {
	seed := exampleConfig()
	seen := map[string]bool{}
	reports := 0
	err := runTrialSession(context.Background(), seed, 3, func(_ context.Context, c Config, i int) (Report, error) {
		if c.Validate() != nil || seen[c.InstanceID] || (i == 0 && c.InstanceID != seed.InstanceID) {
			t.Fatal("session reused or changed seed identity")
		}
		seen[c.InstanceID] = true
		return Report{Cleaned: true, NativeAbsent: true}, nil
	}, func(r Report) error {
		if r.BaselineReused != (reports > 0) || !seen[r.InstanceID] {
			t.Fatal("session verification/identity observation differs")
		}
		reports++
		return nil
	})
	if err != nil || reports != 3 {
		t.Fatal("sequential session failed", err)
	}
	calls := 0
	err = runTrialSession(context.Background(), seed, 3, func(context.Context, Config, int) (Report, error) { calls++; return Report{StorageRetained: true}, nil }, func(Report) error { return nil })
	if err == nil || calls != 1 {
		t.Fatal("retained state admitted another clone")
	}
	for _, count := range []int{0, 6} {
		if runTrialSession(context.Background(), seed, count, func(context.Context, Config, int) (Report, error) {
			t.Fatal("invalid count dispatched")
			return Report{}, nil
		}, func(Report) error { return nil }) == nil {
			t.Fatal("invalid count accepted")
		}
	}
}
func TestImagePinPreventsWritesAndDeletionUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.vhdx")
	if err := os.WriteFile(path, []byte("immutable"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openReadOnlyPinned(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(path, []byte("changed"), 0600) == nil || os.Remove(path) == nil {
		_ = f.Close()
		t.Fatal("session pin allowed mutation")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("after close"), 0600); err != nil {
		t.Fatal("session leaked its pin")
	}
}
func TestImageCopyBoundsCancellationAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	dst := filepath.Join(dir, "output")
	data := bytes.Repeat([]byte("public image bytes"), 10000)
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := copyImageFile(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("image digest differs")
	}
	if _, err = copyImageFile(context.Background(), src, dst); err == nil {
		t.Fatal("image destination overwritten")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = copyImageFile(ctx, src, filepath.Join(dir, "cancelled")); err == nil {
		t.Fatal("cancelled image copy completed")
	}
}
func TestPreparedManifestBindsBuildAssetsAndParent(t *testing.T) {
	source := imageBuildFixture(exampleConfig())
	c := source
	c.ImageRoot = ""
	c.SetupAssets = nil
	c.Drivers = nil
	c.GuestComputerName = source.name()
	c.Baseline = filepath.Join(source.ImageRoot, source.InstanceID, "disk.vhdx")
	c.PreparedImage = &PinnedFile{Source: filepath.Join(source.ImageRoot, source.InstanceID, "manifest.json"), SHA256: strings.Repeat("b", 64)}
	m := ImageManifest{AutologonSHA256: autologonHash(), BuildID: source.InstanceID, BuildOwner: source.owner(), Image: PinnedFile{Source: c.Baseline, SHA256: c.BaselineSHA256}, Parent: PinnedFile{Source: source.Baseline, SHA256: source.BaselineSHA256}, GuestComputerName: c.GuestComputerName, GuestUser: c.GuestUser, ProbeSHA256: c.RenderProbe.SHA256, ValidationSHA256: validationHash(), RunnerSHA256: strings.Repeat("c", 64), CleanShutdown: true, Sanitized: true}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := m.validate(c); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ImageManifest){func(v *ImageManifest) { v.CleanShutdown = false }, func(v *ImageManifest) { v.Sanitized = false }, func(v *ImageManifest) { v.Parent.Source = v.Image.Source }, func(v *ImageManifest) { v.ValidationSHA256 = strings.Repeat("0", 64) }, func(v *ImageManifest) { v.RunnerSHA256 = "" }, func(v *ImageManifest) { v.GuestComputerName = "another" }, func(v *ImageManifest) { v.BuildID = "unknown" }} {
		bad := m
		mutate(&bad)
		if bad.validate(c) == nil {
			t.Fatal("mismatched manifest accepted")
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeImageManifest(append(b, []byte(" {}")...)); err == nil {
		t.Fatal("multiple manifest documents accepted")
	}
}

// This creates only tiny synthetic, unmounted disks; no VM or lab image is used.
func TestImmutableDiskChainMetadata(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "parent.vhdx")
	child := filepath.Join(dir, "child.vhdx")
	if err := vhd.CreateVhdx(parent, 1, 2); err != nil {
		t.Fatal(err)
	}
	f, err := openReadOnlyPinned(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := vhd.CreateDiffVhd(child, parent, 2); err != nil {
		t.Fatal(err)
	}

	if err = verifyDiskChain(parent, ""); err != nil {
		t.Fatal(err)
	}
	if err = verifyDiskChain(child, parent); err != nil {
		t.Fatal(err)
	}
	if verifyDiskChain(child, "") == nil || verifyDiskChain(child, filepath.Join(dir, "other.vhdx")) == nil {
		t.Fatal("unrecorded ancestry accepted")
	}
}
func TestPreparedCredentialRotationRequired(t *testing.T) {
	r := renderResult{GuestReady: true, DesktopReady: true, HardwareD3D11: true, Presented: true, PixelReadback: true, Stage: 7, AdapterCount: 1, HardwareAdapterCount: 1, VendorID: 0x1002, DeviceID: 1}
	b, _ := json.Marshal(r)
	if _, err := validateRenderReport(b, true); err == nil {
		t.Fatal("prepared clone admitted without credential rotation")
	}
	r.CredentialRotated = true
	b, _ = json.Marshal(r)
	if _, err := validateRenderReport(b, true); err != nil {
		t.Fatal(err)
	}
}
func TestSanitizerDeliveryIsSmallAndPinned(t *testing.T) {
	c := imageBuildFixture(exampleConfig())
	b, err := imageSanitizeInput(c)
	if err != nil || len(b) > 1024 {
		t.Fatal("sanitation request exceeds small transport bound", err)
	}
	var payload struct {
		Script string
		Data   map[string]string
	}
	if json.Unmarshal(b[4:], &payload) != nil || payload.Script != imageSanitizeEntry || len(payload.Data) != 6 || payload.Data["autologon_sha256"] != autologonHash() {
		t.Fatal("sanitizer pin/data differs")
	}
}
func runImageFixture(t *testing.T, script string, input []byte) error {
	t.Helper()
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedPowerShell(script))
	cmd.Stdin = bytes.NewReader(input)
	return cmd.Run()
}
func TestGuestAutologonHelperCompilesWithoutStoringAnything(t *testing.T) {
	// Add-Type only: Store is deliberately never invoked on the host.
	if err := runImageFixture(t, autologonSecret+"\nif(!('SpikeAutoLogonSecret' -as [type])){exit 1}", nil); err != nil {
		t.Fatal("guest LSA binding compilation failed", err)
	}
}
func TestRunnerExtractionRejectsTraversalLinksAndDuplicates(t *testing.T) {
	for _, kind := range []string{"valid", "traversal", "absolute", "stream", "symlink", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "runner.zip")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			z := zip.NewWriter(f)
			names := []string{"bin/Runner.Listener.exe"}
			switch kind {
			case "traversal":
				names = append(names, "../escaped")
			case "absolute":
				names = append(names, "C:/escaped")
			case "stream":
				names = append(names, "bin/file:stream")
			case "symlink":
				names = append(names, "bin/link")
			case "duplicate":
				names = append(names, names[0])
			}
			for _, name := range names {
				h := &zip.FileHeader{Name: name, Method: zip.Store}
				if kind == "symlink" && name == "bin/link" {
					h.SetMode(os.ModeSymlink | 0777)
				}
				w, e := z.CreateHeader(h)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = w.Write([]byte("synthetic")); e != nil {
					t.Fatal(e)
				}
			}
			if err = errors.Join(z.Close(), f.Close()); err != nil {
				t.Fatal(err)
			}
			scriptPath := filepath.Join(dir, "extract.ps1")
			if err = os.WriteFile(scriptPath, []byte(runnerExtract), 0600); err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(map[string]string{"script": scriptPath, "archive": path, "destination": filepath.Join(dir, "runner")})
			e := runImageFixture(t, `$d=[Console]::In.ReadToEnd()|ConvertFrom-Json;& $d.script $d.archive $d.destination;exit $LASTEXITCODE`, b)
			if kind == "valid" {
				if _, statErr := os.Stat(filepath.Join(dir, "runner", "bin", "Runner.Listener.exe")); statErr != nil {
					t.Fatal("valid archive did not extract", statErr)
				}
			}
			if (e == nil) != (kind == "valid") {
				t.Fatal("archive acceptance differs", e)
			}
			if _, e = os.Stat(filepath.Join(dir, "escaped")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("archive escaped its root")
			}
		})
	}
}

func TestPreparedImageRejectsOrdinaryUserReadAccess(t *testing.T) {
	for _, entry := range []struct {
		sddl    string
		allowed bool
	}{
		{"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;S-1-5-83-0)", true},
		{"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", false},
		{"D:P(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(entry.sddl)
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if (privateImageACL(acl) == nil) != entry.allowed {
			t.Fatal("image privacy policy differs")
		}
	}
	if privateImageACL(nil) == nil {
		t.Fatal("null image DACL accepted")
	}
}

func TestImageStagingCleanupHonorsOwnershipAndPublication(t *testing.T) {
	for _, kind := range []string{"owned", "foreign", "published", "unexpected"} {
		t.Run(kind, func(t *testing.T) {
			c := imageBuildFixture(exampleConfig())
			c.ImageRoot = filepath.Join(t.TempDir(), "HCS-Images")
			if err := os.MkdirAll(imageDirectory(c), 0700); err != nil {
				t.Fatal(err)
			}
			j, err := openJournal(c.ImageRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = j.root.Close() }()
			owner := c
			if kind == "foreign" {
				owner.InstanceID = "112233445566778899aabbccddeeff00"
			}
			if err = j.write(markerName(c), owner, true); err != nil {
				t.Fatal(err)
			}
			if err = j.write(filepath.Join(c.InstanceID, "disk.vhdx"), true, true); err != nil {
				t.Fatal(err)
			}
			if kind == "published" {
				if err = j.write(filepath.Join(c.InstanceID, "manifest.json"), true, true); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unexpected" {
				if err = j.write(filepath.Join(c.InstanceID, "foreign.txt"), true, true); err != nil {
					t.Fatal(err)
				}
			}
			e := cleanupImageFiles(c, j)
			if (e != nil) != (kind == "foreign" || kind == "unexpected") {
				t.Fatal("cleanup result differs", e)
			}
			_, statErr := j.root.Stat(markerName(c))
			if kind == "owned" {
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("owned staging remains")
				}
			} else if statErr != nil {
				t.Fatal("retained ownership evidence removed")
			}
		})
	}
}
func TestImageConfigurationExamples(t *testing.T) {
	for _, name := range []string{"hcs-spike-build.example.json", "hcs-spike-prepared.example.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "tools", "windows", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeConfig(bytes.NewReader(b)); err != nil {
			t.Fatal(name, err)
		}
	}
	c := exampleConfig()
	c.GuestComputerName = "prepared"
	if c.Validate() == nil {
		t.Fatal("prepared guest name accepted without provenance")
	}
}

func TestGuestShutdownRequestStaysFixedAndBounded(t *testing.T) {
	c := imageBuildFixture(exampleConfig())
	input, err := imageShutdownInput(c)
	if err != nil || len(input) > 1024 {
		t.Fatal("guest-only shutdown frame exceeds transport bound", len(input), err)
	}
	if !strings.Contains(imageShutdownScript, `C:\Windows\System32\shutdown.exe`) || strings.Contains(imageShutdownScript, "/m") {
		t.Fatal("shutdown is not local to the authenticated guest")
	}
}
