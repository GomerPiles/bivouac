//go:build windows

package imagefactory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/GomerPiles/bivouac/internal/hcs"
	"github.com/GomerPiles/bivouac/internal/winhost"
	"golang.org/x/sys/windows"
)

type record struct {
	BuildID          string            `json:"build_id"`
	Workspace        string            `json:"workspace"`
	Name             string            `json:"name"`
	Owner            string            `json:"owner"`
	RuntimeID        string            `json:"runtime_id,omitempty"`
	Phase            string            `json:"phase"`
	Inspection       *Inspection       `json:"inspection,omitempty"`
	Retained         bool              `json:"retained"`
	Published        bool              `json:"published"`
	Manifest         Manifest          `json:"manifest"`
	HostSteps        map[string]int    `json:"host_steps,omitempty"`
	GuestSetupStep   uint32            `json:"guest_setup_step,omitempty"`
	GuestSetupFailed bool              `json:"guest_setup_failed,omitempty"`
	GuestSetupVideo  *SetupVideoStatus `json:"guest_setup_video,omitempty"`
	NativeAttempted  bool              `json:"native_attempted"`
	GuestCompleted   bool              `json:"guest_completed"`
	SpaceChecks      []SpaceCheck      `json:"space_checks,omitempty"`
}

func (r *record) setupFailure(facts *Inspection) error {
	r.GuestSetupStep = facts.GuestSetupStep
	r.GuestSetupFailed = facts.GuestSetupFailed
	r.GuestSetupVideo = facts.GuestSetupVideo
	if !r.GuestSetupFailed {
		return nil
	}
	if r.GuestSetupVideo != nil {
		// Marshaling the typed facts emits fixed field names and numbers only.
		b, err := json.Marshal(r.GuestSetupVideo)
		if err == nil {
			return fmt.Errorf("guest setup failed at step %d (video %s)", r.GuestSetupStep, b)
		}
	}
	return fmt.Errorf("guest setup failed at step %d", r.GuestSetupStep)
}

func (r *record) disk() string { return filepath.Join(r.Workspace, "disk.vhdx") }
func (r *record) scriptData() map[string]string {
	return map[string]string{"root": filepath.Dir(r.Workspace), "instance_id": r.BuildID, "disk": r.disk()}
}
func (r *record) save() error {
	return replaceJSON(filepath.Join(filepath.Dir(r.Workspace), r.BuildID+".json"), r)
}

// protect is only called on paths created by this invocation. Never on input.
func protect(root, path string, vmRead bool) error {
	return mutateOwnedPath(root, path, func(path string) error { return protectCreated(path, vmRead) })
}
func protectCreated(path string, vmRead bool) error {
	sddl := "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if vmRead {
		sddl += "(A;OICI;FRFX;;;S-1-5-83-0)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
}
func newProtectedDirectory(path string) (err error) {
	if err := winhost.CheckProtectedParents(path); err != nil {
		return errors.New("workspace parent must be administrator-protected")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	// This call created the still-empty directory. A protection failure must
	// not strand an unrecorded workspace; Remove never traverses descendants.
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(path))
		}
	}()
	if err := protect(path, path, false); err != nil {
		return err
	}
	return winhost.CheckProtected(path)
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.New("cannot encode image metadata")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return protect(filepath.Dir(path), path, false)
}
func replaceJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.New("cannot encode build record")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".record-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = protect(filepath.Dir(path), tmp, false); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func publishManifest(path string, m Manifest) error {
	tmp := path + ".tmp"
	if err := writeJSON(tmp, m); err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// No REPLACE_EXISTING: even a publication marker is never overwritten.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
func copyPinned(ctx context.Context, source, dest, expected string, limit int64) (int64, string, error) {
	if err := winhost.CheckProtected(source); err != nil {
		return 0, "", errors.New("image input must be administrator-protected")
	}
	in, err := openReadOnlyPinned(source)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return 0, "", errors.New("image input is not a bounded regular file")
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := copyContext(ctx, io.MultiWriter(out, h), in, limit)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	sum := hex.EncodeToString(h.Sum(nil))
	if n != info.Size() || !strings.EqualFold(sum, expected) {
		err = errors.Join(err, errors.New("copied input size or SHA-256 differs"))
	}
	return n, sum, err
}
func copyContext(ctx context.Context, w io.Writer, r io.Reader, limit int64) (int64, error) {
	buf := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := r.Read(buf)
		if int64(n) > limit-total {
			return total, errors.New("copy exceeds byte bound")
		}
		if n > 0 {
			m, e := w.Write(buf[:n])
			total += int64(m)
			if e != nil {
				return total, e
			}
			if m != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, errors.New("input read failed")
		}
	}
}

func ownerTemplate(c Config) (string, error) {
	path := filepath.Join(filepath.Dir(c.Source), ".bivouac-template-owner.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return missingOwner(c.ExpectedTemplate)
	}
	if err := winhost.CheckProtected(path); err != nil {
		return "", errors.New("template owner record must be protected")
	}
	f, err := openReadOnlyPinned(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return "", errors.New("template owner record exceeds bound")
	}
	var owner struct {
		Template string
		SHA256   string
		Phase    string
	}
	if json.Unmarshal(b, &owner) != nil || len(owner.Template) == 0 || len(owner.Template) > 128 || strings.ContainsAny(owner.Template, "\\/:\x00\r\n") || !strings.EqualFold(owner.SHA256, c.SourceSHA256) || owner.Phase != "export-complete" || (c.ExpectedTemplate != "" && owner.Template != c.ExpectedTemplate) {
		return "", errors.New("template owner record does not match configured source")
	}
	return owner.Template, nil
}

func missingOwner(expected string) (string, error) {
	if expected != "" {
		return "", errors.New("expected template requires a source owner record")
	}
	return "", nil
}

type HostScriptError struct{ Step int }

func (e *HostScriptError) Error() string {
	return fmt.Sprintf("image host script failed at step %d", e.Step)
}
func (r *record) hostError(phase string, err error) {
	var scriptErr *HostScriptError
	if errors.As(err, &scriptErr) {
		if r.HostSteps == nil {
			r.HostSteps = map[string]int{}
		}
		r.HostSteps[phase] = scriptErr.Step
	}
}

const resultSentinel = "BIVOUAC_IMAGE_RESULT"

func framedResult(b []byte) ([]byte, error) {
	lines := bytes.Split(b, []byte{'\n'})
	var result []byte
	for i, line := range lines {
		if strings.TrimSuffix(string(line), "\r") == resultSentinel {
			if result != nil || i+1 >= len(lines) || len(lines[i+1]) == 0 {
				return nil, errors.New("invalid image script result frame")
			}
			result = bytes.TrimSuffix(lines[i+1], []byte{'\r'})
		}
	}
	if result == nil || len(result) > 49152 {
		return nil, errors.New("image script result frame unavailable or exceeds bound")
	}
	return result, nil
}

func runHost(ctx context.Context, script string, data any, output bool) ([]byte, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, errors.New("cannot encode setup input")
	}
	defer clear(b)
	paths, ok := data.(map[string]string)
	if !ok || !validID(paths["instance_id"]) || !localPath(paths["root"]) {
		return nil, errors.New("invalid owned host script workspace")
	}
	workspace := filepath.Join(paths["root"], paths["instance_id"])
	if err = winhost.CheckProtected(workspace); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(workspace, ".host-*.ps1")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	_, err = f.WriteString(script)
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if err = protect(workspace, path, false); err != nil {
		return nil, err
	}
	return executeHost(ctx, path, b, output)
}

func executeHost(ctx context.Context, path string, b []byte, output bool) ([]byte, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Stdin = bytes.NewReader(b)
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	var result boundedOutput
	if output {
		cmd.Stdout = &result
	}
	runErr := cmd.Run()
	var errResult error
	if runErr != nil {
		step := 65535
		var exit *exec.ExitError
		if errors.As(runErr, &exit) && exit.ExitCode() > 0 {
			step = exit.ExitCode()
		}
		errResult = &HostScriptError{Step: step}
	}
	if !output {
		return nil, errResult
	}
	payload, frameErr := framedResult(result.data)
	return payload, errors.Join(errResult, frameErr)
}

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 65536 {
		return 0, errors.New("script result exceeds bound")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func grantOwned(api *hcs.API, r *record, path string) error {
	return grantPath(r.Workspace, path, func(p string) error {
		return api.GrantVMAccess(r.Name, p)
	})
}
func grantPath(workspace, path string, grant func(string) error) error {
	return mutateOwnedPath(workspace, path, grant)
}
func mutateOwnedPath(workspace, path string, mutate func(string) error) error {
	if !localPath(path) || !within(workspace, path) {
		return errors.New("VM access grant requires a build-owned path")
	}
	return mutate(path)
}

func copyDrivers(ctx context.Context, c Config, r *record) ([]Driver, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	repository := filepath.Join(system, "DriverStore", "FileRepository")
	var result []Driver
	var total int64
	files := 0
	infCount := 0
	version := regexp.MustCompile(`(?im)^\s*DriverVer\s*=\s*([^;\r\n]{1,128})`)
	for i, source := range c.Drivers {
		if !strings.EqualFold(filepath.Dir(source), repository) {
			return nil, errors.New("GPU driver source must be directly under system FileRepository")
		}
		if err := winhost.CheckProtected(source); err != nil {
			return nil, errors.New("GPU driver directory must be protected")
		}
		info, err := os.Stat(source)
		if err != nil || !info.IsDir() {
			return nil, errors.New("GPU driver directory unavailable")
		}
		root, err := os.OpenRoot(source)
		if err != nil {
			return nil, err
		}
		driver := Driver{Name: filepath.Base(source), INFVersions: map[string]string{}}
		err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("cannot read GPU driver tree")
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("GPU driver tree contains a link")
			}
			if len(path) > 240 {
				return errors.New("driver relative path exceeds bound")
			}
			target := filepath.Join(r.Workspace, "drivers", fmt.Sprint(i), filepath.FromSlash(path))
			if entry.IsDir() {
				return os.MkdirAll(target, 0700)
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("GPU driver tree has a non-regular file")
			}
			files++
			if files > 8192 || info.Size() < 0 || info.Size() > (2<<30)-total {
				return errors.New("driver payload exceeds 8192 files or 2 GiB")
			}
			total += info.Size()
			in, err := root.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = in.Close() }()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			n, err := copyContext(ctx, out, in, info.Size())
			err = errors.Join(err, out.Close())
			if err != nil {
				return err
			}
			if n != info.Size() {
				return errors.New("GPU driver changed during copy")
			}
			if strings.EqualFold(filepath.Ext(path), ".inf") {
				infCount++
				if infCount > 32 {
					return errors.New("driver INF count exceeds 32")
				}
				if info.Size() > 1<<20 {
					return errors.New("driver INF exceeds bound")
				}
				b, err := os.ReadFile(target)
				if err != nil {
					return err
				}
				text := string(b)
				if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
					words := make([]uint16, 0, len(b)/2)
					for j := 2; j+1 < len(b); j += 2 {
						words = append(words, uint16(b[j])|uint16(b[j+1])<<8)
					}
					text = windows.UTF16ToString(words)
				}
				match := version.FindStringSubmatch(text)
				if len(match) != 2 {
					return errors.New("driver INF lacks DriverVer")
				}
				driver.INFVersions[filepath.FromSlash(path)] = strings.TrimSpace(match[1])
			}
			return nil
		})
		err = errors.Join(err, root.Close())
		if err != nil {
			return nil, err
		}
		if len(driver.INFVersions) == 0 {
			return nil, errors.New("GPU driver tree lacks INF provenance")
		}
		result = append(result, driver)
	}
	return result, nil
}

func waitAbsent(ctx context.Context, api *hcs.API, name string) error {
	for {
		s, err := api.Open(ctx, name)
		if errors.Is(err, hcs.ErrNotFound) {
			return nil
		}
		if err != nil {
			return errors.New("native absence cannot be observed")
		}
		s.Close()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
