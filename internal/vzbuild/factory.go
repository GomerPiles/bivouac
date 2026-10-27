package vzbuild

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

const factoryDir = ".factory"
const factoryOwner = "bivouac-factory-owned"

type identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (i identity) empty() bool { return i == identity{} }

type factoryRecord struct {
	Owner    string   `json:"owner"`
	ID       string   `json:"build_id"`
	Recipe   string   `json:"recipe"`
	Target   string   `json:"target"`
	BuildDir string   `json:"build_dir"`
	GateDir  string   `json:"gate_dir"`
	Phase    string   `json:"phase"`
	Build    identity `json:"build_identity"`
	Gate     identity `json:"gate_identity"`
	Old      identity `json:"old_identity"`
	New      identity `json:"new_identity"`
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func validTarget(name string) error {
	if name == "" || len(name) > 100 || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "bivouac-") {
		return errors.New("invalid baseline target name")
	}
	for _, c := range name {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.", c) {
			return errors.New("invalid baseline target name")
		}
	}
	return nil
}
func (r factoryRecord) validate() error {
	if r.Owner != factoryOwner || !validID(r.ID) || validTarget(r.Target) != nil || r.BuildDir != ".build-"+r.ID || r.GateDir != ".gate-"+r.ID {
		return errors.New("unrecognized factory record")
	}
	if _, err := vzrecipe.Lookup(r.Recipe); err != nil {
		return errors.New("unrecognized factory recipe")
	}
	switch r.Phase {
	case "staging", "provisioning", "prepared", "gate", "publish", "swap", "published":
	default:
		return errors.New("unrecognized factory phase")
	}
	if (r.Phase == "publish" || r.Phase == "swap" || r.Phase == "published") && (r.New.empty() || r.New != r.Build) {
		return errors.New("invalid factory publication identity")
	}
	if r.Phase == "swap" && r.Old.empty() {
		return errors.New("invalid factory replacement intent")
	}
	return nil
}
func readRecord(path string) (factoryRecord, error) {
	var r factoryRecord
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(data) > 8192 {
		return r, errors.New("factory record exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, errors.New("invalid factory record")
	}
	return r, r.validate()
}
func writeRecord(dir string, r factoryRecord) error {
	if err := r.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, r.ID+".json")); err != nil {
		return err
	}
	return syncDir(dir)
}

// FactoryStatus reports leftover recorded and unrecognized factory state without
// opening guests or modifying files. An empty idle lock file is expected.
func FactoryStatus(store string) error {
	entries, err := os.ReadDir(store)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".build-") || strings.HasPrefix(e.Name(), ".gate-") {
			return errors.New("leftover factory VM state; recorded state is recovered before the next baseline build")
		}
	}
	entries, err = os.ReadDir(filepath.Join(store, factoryDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "builder.lock" {
			return errors.New("leftover factory records; recorded state is recovered before the next baseline build")
		}
	}
	return nil
}
