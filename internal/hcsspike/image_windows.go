//go:build windows

package hcsspike

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unsafe"

	"github.com/GomerPiles/bivouac/internal/provider/appsandbox"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

//go:embed image_sanitize.ps1
var imageSanitize string

//go:embed autologon_secret.ps1
var autologonSecret string

// ImageManifest is public provenance, never credential or guest diagnostic data.
// The runtime disk is an immutable differencing image with one pinned flat parent.
type ImageManifest struct {
	AutologonSHA256   string     `json:"autologon_sha256"`
	BuildID           string     `json:"build_id"`
	BuildOwner        string     `json:"build_owner"`
	Image             PinnedFile `json:"image"`
	Parent            PinnedFile `json:"parent"`
	GuestComputerName string     `json:"guest_computer_name"`
	GuestUser         string     `json:"guest_user"`
	ProbeSHA256       string     `json:"probe_sha256"`
	ValidationSHA256  string     `json:"validation_sha256"`
	RunnerSHA256      string     `json:"runner_sha256"`
	CleanShutdown     bool       `json:"clean_shutdown"`
	Sanitized         bool       `json:"sanitized"`
}

func decodeImageManifest(b []byte) (ImageManifest, error) {
	var m ImageManifest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, errors.New("invalid prepared image manifest")
	}
	return m, nil
}

func (m ImageManifest) validate(c Config) error {
	id, e := hex.DecodeString(m.BuildID)
	imageRoot := filepath.Dir(filepath.Dir(m.Image.Source))
	if e != nil || len(id) != 16 || strings.ToLower(m.BuildID) != m.BuildID || !m.CleanShutdown || !m.Sanitized || m.BuildOwner != (Config{Root: c.Root, InstanceID: m.BuildID}).owner() {
		return errors.New("prepared image lacks valid build ownership/shutdown proof")
	}
	if validatePinned(c, m.Image) != nil || validatePinned(c, m.Parent) != nil || !strings.EqualFold(filepath.Base(imageRoot), "HCS-Images") || !strings.EqualFold(m.Image.Source, filepath.Join(imageRoot, m.BuildID, "disk.vhdx")) || within(imageRoot, m.Parent.Source) || within(c.Root, m.Parent.Source) {
		return errors.New("prepared image provenance paths differ")
	}
	if c.PreparedImage == nil || !strings.EqualFold(c.PreparedImage.Source, filepath.Join(imageRoot, m.BuildID, "manifest.json")) || !strings.EqualFold(c.Baseline, m.Image.Source) || !strings.EqualFold(c.BaselineSHA256, m.Image.SHA256) || c.GuestComputerName != m.GuestComputerName || c.GuestUser != m.GuestUser || c.RenderProbe == nil || !strings.EqualFold(c.RenderProbe.SHA256, m.ProbeSHA256) || m.ValidationSHA256 != validationHash() || m.AutologonSHA256 != autologonHash() {
		return errors.New("prepared image does not match runtime configuration/build")
	}
	buildName := (Config{InstanceID: m.BuildID}).name()
	if m.GuestComputerName != buildName {
		return errors.New("prepared guest name differs from captured build")
	}
	for _, value := range []string{m.RunnerSHA256, m.ProbeSHA256, m.ValidationSHA256} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			return errors.New("prepared image integrity pin missing")
		}
	}
	return nil
}

func autologonHash() string {
	h := sha256.Sum256([]byte(autologonSecret))
	return hex.EncodeToString(h[:])
}

func validationHash() string {
	h := sha256.Sum256([]byte(guestValidate))
	return hex.EncodeToString(h[:])
}

type imageSession struct{ files []*os.File }

func (s *imageSession) Close() {
	for i := len(s.files) - 1; i >= 0; i-- {
		_ = s.files[i].Close()
	}
	s.files = nil
}

// All image files remain read-only and deny write/delete until the session ends.
// No persistent cache, timestamps, or mutable "verified" flag substitutes for pins.
func openImageSession(c Config) (session *imageSession, err error) {
	s := &imageSession{}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	parent := ""
	if c.PreparedImage != nil {
		for _, path := range []string{c.PreparedImage.Source, c.Baseline, filepath.Dir(c.Baseline), filepath.Dir(filepath.Dir(c.Baseline))} {
			if e := checkImagePrivacy(path); e != nil {
				return nil, e
			}
		}
		b, e := readPinnedLimit(*c.PreparedImage, 65536)
		if e != nil {
			return nil, e
		}
		m, e := decodeImageManifest(b)
		if e != nil {
			return nil, e
		}
		if e = m.validate(c); e != nil {
			return nil, e
		}
		pc := c
		pc.Baseline = m.Parent.Source
		pc.BaselineSHA256 = m.Parent.SHA256
		f, e := pinBaseline(pc)
		if e != nil {
			return nil, e
		}
		s.files = append(s.files, f)
		if e = verifyDiskChain(pc.Baseline, ""); e != nil {
			return nil, e
		}
		parent = pc.Baseline
	}
	f, e := pinBaseline(c)
	if e != nil {
		return nil, e
	}
	s.files = append(s.files, f)
	if e = verifyDiskChain(c.Baseline, parent); e != nil {
		return nil, e
	}
	return s, nil
}

func newInstanceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("cannot generate fresh trial identity")
	}
	return hex.EncodeToString(b[:]), nil
}

func runTrialSession(ctx context.Context, c Config, count int, run func(context.Context, Config, int) (Report, error), emit func(Report) error) error {
	if count < 1 || count > 5 {
		return errors.New("repetitions must be 1-5")
	}
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			id, err := newInstanceID()
			if err != nil {
				return err
			}
			c.InstanceID = id
		}
		r, err := run(ctx, c, i)
		r.InstanceID = c.InstanceID
		r.BaselineReused = i > 0
		if outErr := emit(r); outErr != nil {
			return errors.Join(err, outErr)
		}
		if err != nil {
			return err
		}
		if !r.Cleaned || !r.NativeAbsent || r.StorageRetained {
			return errors.New("trial session retained work; no next guest was launched")
		}
	}
	return nil
}

func imageDirectory(c Config) string { return filepath.Join(c.ImageRoot, c.InstanceID) }

func beginImageOutput(c Config) (*journal, error) {
	if err := checkImagePrivacy(c.ImageRoot); err != nil {
		return nil, errors.New("create a protected sibling HCS-Images root before building")
	}
	j, err := openJournal(c.ImageRoot)
	if err != nil {
		return nil, err
	}
	if err = j.root.Mkdir(c.InstanceID, 0700); err != nil {
		_ = j.root.Close()
		return nil, errors.New("image output exists or cannot be created")
	}
	if err = j.write(markerName(c), c, true); err != nil {
		_ = j.root.Close()
		return nil, errors.New("image output ownership record unavailable")
	}
	return j, nil
}
func proveImageOutput(c Config, j *journal) error {
	var owner Config
	if j.read(markerName(c), &owner) != nil || !reflect.DeepEqual(owner, c) {
		return errors.New("image output ownership differs")
	}
	return nil
}

// Partial builds can be removed only through their exact owner marker. Published
// manifests are never removed by trial cleanup. Windows pins prevent deletion
// while a published image is in use, independently of this journal policy.
func cleanupImageStaging(c Config) error {
	if c.ImageRoot == "" {
		return nil
	}
	if err := checkImagePrivacy(c.ImageRoot); err != nil {
		return errors.New("image staging root lost administrator protection")
	}
	j, err := openJournal(c.ImageRoot)
	if err != nil {
		return err
	}
	defer func() { _ = j.root.Close() }()
	return cleanupImageFiles(c, j)
}

func cleanupImageFiles(c Config, j *journal) error {
	var err error
	if _, err = j.root.Stat(c.InstanceID); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err = proveImageOutput(c, j); err != nil {
		return err
	}
	if _, err = j.root.Stat(filepath.Join(c.InstanceID, "manifest.json")); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	directory, err := j.root.Open(c.InstanceID)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(16)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "owner.json", "disk.vhdx", "manifest.json.new", "trial.json", "trial.json.new":
		default:
			return errors.New("unexpected image staging entry retained with ownership marker")
		}
	}
	for _, name := range []string{"disk.vhdx", "manifest.json.new", "trial.json", "trial.json.new"} {
		if err = j.root.Remove(filepath.Join(c.InstanceID, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err = j.root.Remove(markerName(c)); err != nil {
		return err
	}
	return j.root.Remove(c.InstanceID)
}

// Copy through bounded buffers; cancellation/reserve loss stops the copy. Both
// source and output use the same directory depth beneath sibling protected roots,
// preserving relative parent locators. verifyDiskChain confirms the resolved parent.
func copyImageFile(ctx context.Context, source, dest string) (string, error) {
	f, err := openReadOnlyPinned(source)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() < 1 || info.Size() > 64<<30 {
		return "", errors.New("prepared disk size outside copy bounds")
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("prepared disk destination unavailable")
	}
	h := sha256.New()
	n, copyErr := io.CopyBuffer(io.MultiWriter(out, h), &contextReader{ctx: ctx, r: io.LimitReader(f, info.Size()+1)}, make([]byte, 65536))
	if copyErr == nil && n != info.Size() {
		copyErr = errors.New("prepared disk changed while copying")
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if err = errors.Join(copyErr, out.Close()); err != nil {
		return "", errors.New("prepared disk copy failed; owned staging retained")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func publishImage(ctx context.Context, c Config, sourceJournal, imageJournal *journal, api backend, r *Report) error {
	if !r.NativeAbsent || !r.StorageRetained || !r.CleanShutdown || !r.ImageSanitized || !r.GuestReady || !r.PixelReadback {
		return errors.New("image publication requires clean, sanitized, stopped validation")
	}
	if err := absent(ctx, api, c.name()); err != nil {
		return err
	}
	if err := sourceJournal.prove(c); err != nil {
		return err
	}
	if err := proveImageOutput(c, imageJournal); err != nil {
		return err
	}
	dest := filepath.Join(imageDirectory(c), "disk.vhdx")
	hash, err := copyImageFile(ctx, c.disk(), dest)
	if err != nil {
		return err
	}
	if err = checkImagePrivacy(dest); err != nil {
		return err
	}
	if err = verifyDiskChain(dest, c.Baseline); err != nil {
		return err
	}
	runnerHash := ""
	for _, a := range c.SetupAssets {
		if strings.EqualFold(a.Name, "RUNNER.ZIP") {
			runnerHash = a.SHA256
		}
	}
	m := ImageManifest{AutologonSHA256: autologonHash(), BuildID: c.InstanceID, BuildOwner: c.owner(), Image: PinnedFile{Source: dest, SHA256: hash}, Parent: PinnedFile{Source: c.Baseline, SHA256: c.BaselineSHA256}, GuestComputerName: c.name(), GuestUser: c.GuestUser, ProbeSHA256: c.RenderProbe.SHA256, ValidationSHA256: validationHash(), RunnerSHA256: runnerHash, CleanShutdown: true, Sanitized: true}
	b, err := json.Marshal(m)
	if err != nil {
		return errors.New("cannot encode prepared image provenance")
	}
	sum := sha256.Sum256(b)
	runtimeConfig := c
	runtimeConfig.ImageRoot = ""
	runtimeConfig.Baseline = dest
	runtimeConfig.BaselineSHA256 = hash
	runtimeConfig.GuestComputerName = c.name()
	runtimeConfig.SetupAssets = nil
	runtimeConfig.Drivers = nil
	runtimeConfig.InstanceID, err = newInstanceID()
	if err != nil {
		return err
	}
	runtimeConfig.PreparedImage = &PinnedFile{Source: filepath.Join(imageDirectory(c), "manifest.json"), SHA256: hex.EncodeToString(sum[:])}
	if err = runtimeConfig.Validate(); err != nil {
		return err
	}
	if err = m.validate(runtimeConfig); err != nil {
		return err
	}
	// The ready-to-review runtime configuration is written first. Until the final
	// manifest is durable, no runtime can pass its integrity check.
	if err = imageJournal.write(filepath.Join(c.InstanceID, "trial.json"), runtimeConfig, true); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = imageJournal.write(filepath.Join(c.InstanceID, "manifest.json.new"), m, true); err != nil {
		return err
	}
	if err = imageJournal.root.Rename(filepath.Join(c.InstanceID, "manifest.json.new"), filepath.Join(c.InstanceID, "manifest.json")); err != nil {
		return err
	}
	r.ImageBuilt = true
	r.ImageSHA256 = hash
	r.ManifestSHA256 = runtimeConfig.PreparedImage.SHA256
	return nil
}

const imageSanitizeEntry = `param($data);$f=Join-Path $env:SystemRoot 'AppSandbox\hcs-spike-sanitize.ps1';if((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $data.sanitizer_sha256){exit 14};& $f $data`

func sanitizeImageGuest(ctx context.Context, client *ssh.Client, c Config) error {
	input, err := imageSanitizeInput(c)
	if err != nil {
		return errors.New("cannot encode fixed image sanitation input")
	}
	defer clear(input)
	out, _, err := runGuestSSH(ctx, client, desktopValidationCommand(), input)
	if err != nil || string(out) != "sanitized" {
		return errors.New("fixed image sanitation failed; image was not published")
	}
	return nil
}

func imageSanitizeInput(c Config) ([]byte, error) {
	hash := sha256.Sum256([]byte(imageSanitize))
	return guestScriptInput(imageSanitizeEntry, map[string]string{"sanitizer_sha256": hex.EncodeToString(hash[:]), "name": c.name(), "user": c.GuestUser, "probe_sha256": c.RenderProbe.SHA256, "validation_sha256": validationHash(), "autologon_sha256": autologonHash()})
}

func imageError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("prepared image build: %w", err)
}

// A captured local account is machine-specific state. Unlike public assets,
// image contents may be read only by administrators/SYSTEM and VM worker identities.
func checkImagePrivacy(path string) error {
	if err := appsandbox.CheckProtectedFile(path); err != nil {
		return errors.New("prepared image storage is not administrator-protected")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("prepared image access policy unavailable")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return errors.New("prepared image access policy unavailable")
	}
	return privateImageACL(acl)
}
func privateImageACL(acl *windows.ACL) error {
	if acl == nil {
		return errors.New("prepared image requires a private access policy")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return errors.New("prepared image access entry unavailable")
		}
		if ace.Header.AceFlags&0x08 != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("prepared image access entry unsupported")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- GetAce returns a bounded Windows ACE with a trailing SID.
		if !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.IsWellKnown(windows.WinLocalSystemSid) && sid.String() != "S-1-5-83-0" {
			return errors.New("prepared image grants non-administrator access")
		}
	}
	return nil
}

// This fixed command is sent only over the authenticated owned-guest transport.
// It never executes through a host process launcher. Windows flushes the guest
// filesystems before power-off; a forced native stop cannot pass exit validation.
const imageShutdownScript = `param($data)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ine $data.name -or $env:USERNAME -ine $data.user){exit 1}
$marker=Get-Content -LiteralPath 'C:\Windows\AppSandbox\hcs-spike-prepared.json' -Raw|ConvertFrom-Json
if($marker.name -cne $data.name -or $marker.user -cne $data.user){exit 1}
& 'C:\Windows\System32\shutdown.exe' @('/s','/t','5','/d','p:0:0') *> $null
if($LASTEXITCODE){exit 1}
[Console]::Out.Write('shutdown-scheduled');[Console]::Out.Flush()
`

func imageShutdownInput(c Config) ([]byte, error) {
	return guestScriptInput(imageShutdownScript, map[string]string{"name": c.name(), "user": c.GuestUser})
}
func requestImageShutdown(ctx context.Context, client *ssh.Client, c Config) error {
	input, err := imageShutdownInput(c)
	if err != nil {
		return errors.New("cannot encode fixed guest shutdown request")
	}
	defer clear(input)
	out, _, err := runGuestSSH(ctx, client, desktopValidationCommand(), input)
	if err != nil || string(out) != "shutdown-scheduled" {
		return errors.New("guest clean shutdown acknowledgement unavailable")
	}
	return nil
}
