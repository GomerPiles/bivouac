package crosvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type imageShutdownReceipt struct {
	Record               Record `json:"record"`
	HelperSHA256         string `json:"helper_sha256"`
	Sanitized            bool   `json:"sanitized"`
	ShutdownAcknowledged bool   `json:"shutdown_acknowledged"`
}

// RecordImageShutdown records only a successful factory response plus a clean
// shutdown command acknowledgement. It is not called by ordinary lifecycle work.
func (b *NativeBackend) RecordImageShutdown(name, helperHash string) error {
	if !digest(helperHash) {
		return errors.New("invalid image helper pin")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e, _, err := b.owned(name)
	if err != nil {
		return err
	}
	return writeJSON(e.Record.Directory, "image-shutdown.json", imageShutdownReceipt{Record: e.Record, HelperSHA256: helperHash, Sanitized: true, ShutdownAcknowledged: true})
}

// WaitCleanImageExit never stops/restarts a VM. It accepts only the recorded
// naturally exited, empty process group after acknowledged guest shutdown.
func (b *NativeBackend) WaitCleanImageExit(ctx context.Context, name string) (Record, error) {
	for {
		b.mu.Lock()
		envelope, _, err := b.owned(name)
		if err != nil {
			b.mu.Unlock()
			return Record{}, err
		}
		r := envelope.Record
		var state NativeState
		err = readJSON(filepath.Join(r.Directory, "native.json"), &state)
		if err == nil {
			if _, e := os.Stat(filepath.Join(r.Directory, "stop")); !errors.Is(e, os.ErrNotExist) {
				err = errors.New("forced image stop or ambiguous stop state; capture refused")
			}
		}
		done := false
		if err == nil && state.Phase == "exited" && state.Empty {
			if !state.JobOwned || state.ExitCode != 0 || state.VM.PID == 0 || state.Supervisor.PID == 0 || !sameImage(state.VM.Image, r.Binary) {
				err = errors.New("clean image exit proof incomplete")
			} else {
				done = true
				for _, identity := range []ProcessIdentity{state.Supervisor, state.VM} {
					live, e := b.alive(identity)
					if e != nil {
						err = e
						break
					}
					if live {
						done = false
					}
				}
			}
		}
		if err == nil && done {
			err = b.disk(ctx, r)
		}
		b.mu.Unlock()
		if err != nil {
			return Record{}, err
		}
		if done {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return Record{}, errors.New("clean image shutdown/absence unconfirmed; capture refused")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// CaptureRawImage copies only a stopped, fully owned overlay into a fresh owned
// output directory. It never overwrites a destination or changes the raw source.
// A ready manifest is the publication point; partial output remains unpublishable.
func (b *NativeBackend) CaptureRawImage(ctx context.Context, name, outputRoot, helperHash string) (string, error) {
	if !filepath.IsAbs(outputRoot) || filepath.Clean(outputRoot) != outputRoot || filepath.Base(outputRoot) != "Linux-Images" || !digest(helperHash) {
		return "", errors.New("image output requires a fresh absolute Linux-Images directory and helper pin")
	}
	r, err := b.WaitCleanImageExit(ctx, name)
	if err != nil {
		return "", err
	}
	var receipt imageShutdownReceipt
	if err = readJSON(filepath.Join(r.Directory, "image-shutdown.json"), &receipt); err != nil || !validImageReceipt(receipt, r, helperHash) {
		return "", errors.New("image sanitation/shutdown receipt differs")
	}
	b.mu.Lock()
	root := b.opts.Root
	b.mu.Unlock()
	outputRoot, err = imageOutputPath(outputRoot, root)
	if err != nil {
		return "", err
	}

	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = os.Mkdir(outputRoot, 0700); err != nil {
		return "", errors.New("image output directory exists or cannot be exclusively created")
	}
	owner := struct{ Name, ControllerID, InstanceID, HelperSHA256 string }{r.Name, r.Meta.ControllerID, r.Meta.InstanceID, helperHash}
	if err = writeJSON(outputRoot, "owner.json", owner); err != nil {
		return "", err
	}
	output := filepath.Join(outputRoot, "disk.raw")
	b.mu.Lock()
	opts := b.opts
	b.mu.Unlock()
	// One-time image creation may read the entire source; no hashing/conversion
	// is added to normal job creation. One converter worker bounds CPU pressure.
	if _, err = b.commands.Output(ctx, opts.QemuImg, []string{"convert", "-f", "qcow2", "-O", "raw", "-S", "4k", "-m", "1", r.Disk, output}); err != nil {
		return "", errors.New("owned image conversion failed; unpublished staging retained")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	sourceInfo, err := os.Stat(opts.Baseline)
	if err != nil {
		return "", err
	}
	imageInfo, err := os.Stat(output)
	if err != nil || !imageInfo.Mode().IsRegular() || imageInfo.Size() != sourceInfo.Size() {
		return "", errors.New("captured raw image geometry differs")
	}
	f, err := os.OpenFile(output, os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	err = errors.Join(f.Sync(), f.Close())
	if err != nil {
		return "", err
	}
	manifest := struct {
		Owner         any    `json:"owner"`
		Source        string `json:"source"`
		Bytes         int64  `json:"bytes"`
		CleanShutdown bool   `json:"clean_shutdown"`
		NativeAbsent  bool   `json:"native_absent"`
		Sanitized     bool   `json:"sanitized"`
	}{owner, opts.Baseline, imageInfo.Size(), true, true, true}
	if err = writeJSON(outputRoot, "manifest.json", manifest); err != nil {
		return "", err
	}
	return output, nil
}

// The destination does not exist yet. Resolve its existing parent through the
// native filesystem API so junctions and short names cannot hide instance storage.
func imageOutputPath(outputRoot, instanceRoot string) (string, error) {
	parent, err := resolvePath(filepath.Dir(outputRoot))
	if err != nil {
		return "", errors.New("image output parent cannot be resolved")
	}
	root, err := resolvePath(instanceRoot)
	if err != nil {
		return "", errors.New("instance storage cannot be resolved")
	}
	output := filepath.Join(parent, filepath.Base(outputRoot))
	if strings.EqualFold(output, root) || strings.HasPrefix(strings.ToLower(output), strings.ToLower(root)+string(filepath.Separator)) {
		return "", errors.New("published images must be outside disposable instance storage")
	}
	return output, nil
}

func validImageReceipt(receipt imageShutdownReceipt, r Record, helperHash string) bool {
	return reflect.DeepEqual(receipt.Record, r) && digest(helperHash) && receipt.HelperSHA256 == helperHash && receipt.Sanitized && receipt.ShutdownAcknowledged
}
