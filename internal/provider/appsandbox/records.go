package appsandbox

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const ownerMarker = ".bivouac-owner.json"

// EngineRecord is the broker's protected journal. Clone intent is immutable;
// phases and network IDs are written before each potentially partial mutation.
// No credentials, passwords, JIT configuration or guest log belongs here.
type EngineRecord struct {
	Clone     CloneRecord  `json:"clone"`
	Phase     string       `json:"phase"`
	Attempted bool         `json:"attempted"`
	Network   *NetworkPlan `json:"network,omitempty"`
}

// Records holds an already protected root open, so relative operations cannot
// escape through a guest-selected path. The native broker must validate its
// Windows ACLs and reject reparse points before calling OpenRecords.
type Records struct {
	root *os.Root
	path string
}

func OpenRecords(path string) (*Records, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("broker root must be absolute")
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err = r.MkdirAll("records", 0o700); err != nil {
		_ = r.Close()
		return nil, err
	}
	return &Records{root: r, path: filepath.Clean(path)}, nil
}
func (s *Records) Close() error { return s.root.Close() }

func instanceKey(name string) (string, error) {
	if !strings.HasPrefix(name, "bivouac-") || !identifier(name, 63) {
		return "", errors.New("invalid managed runner name")
	}
	i := strings.LastIndexByte(name, '-')
	id := name[i+1:]
	if _, err := NativeName(id); err != nil {
		return "", err
	}
	return id, nil
}
func (s *Records) read(path string, out any) error {
	f, err := s.root.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return err
	}
	if len(b) > 65536 {
		return errors.New("broker record exceeds bound")
	}
	if err = json.Unmarshal(b, out); err != nil {
		return errors.New("invalid broker record")
	}
	return nil
}
func (s *Records) write(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Operations are serialized by the broker. A fixed sibling temporary name
	// is safe inside its protected root; publication never deletes the old file.
	tmp := path + ".new"
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.root.Rename(tmp, path)
	}
	if err != nil {
		_ = s.root.Remove(tmp)
	}
	return err
}
func (s *Records) Get(name string) (EngineRecord, error) {
	id, err := instanceKey(name)
	if err != nil {
		return EngineRecord{}, err
	}
	var r EngineRecord
	if err = s.read(filepath.Join("records", id+".json"), &r); err != nil {
		return r, err
	}
	if r.Clone.RunnerName != name || r.Clone.Meta.InstanceID != id {
		return r, errors.New("broker record identity differs")
	}
	return r, nil
}
func (s *Records) Put(r EngineRecord) error {
	id, err := instanceKey(r.Clone.RunnerName)
	if err != nil {
		return err
	}
	if r.Clone.Meta.InstanceID != id {
		return errors.New("broker instance key differs")
	}
	return s.write(filepath.Join("records", id+".json"), r)
}
func (s *Records) All() ([]EngineRecord, error) {
	f, err := s.root.Open("records")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(1025)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 1024 {
		return nil, errors.New("broker record count exceeds bound")
	}
	var result []EngineRecord
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if _, err = NativeName(id); err != nil {
			return nil, err
		}
		var r EngineRecord
		if err = s.read(filepath.Join("records", entry.Name()), &r); err != nil {
			return nil, err
		}
		if r.Clone.Meta.InstanceID != id {
			return nil, errors.New("broker record key differs")
		}
		result = append(result, r)
	}
	return result, nil
}
func (s *Records) parent(r CloneRecord) string { return r.Meta.InstanceID }
func (s *Records) PrepareParent(r CloneRecord) error {
	if err := s.root.Mkdir(s.parent(r), 0o700); err != nil {
		return err
	}
	return s.write(filepath.Join(s.parent(r), ownerMarker), r)
}
func (s *Records) Parent(r CloneRecord) (CloneRecord, error) {
	var marker CloneRecord
	err := s.read(filepath.Join(s.parent(r), ownerMarker), &marker)
	return marker, err
}
func (s *Records) Child(r CloneRecord) (CloneRecord, error) {
	var marker CloneRecord
	err := s.read(filepath.Join(s.parent(r), r.NativeName, ownerMarker), &marker)
	return marker, err
}
func (s *Records) MarkChild(r CloneRecord) error {
	return s.write(filepath.Join(s.parent(r), r.NativeName, ownerMarker), r)
}
func (s *Records) ChildExists(r CloneRecord) (bool, error) {
	_, err := s.root.Stat(filepath.Join(s.parent(r), r.NativeName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// ParentExists reports whether anything occupies the per-instance parent.
func (s *Records) ParentExists(r CloneRecord) (bool, error) {
	_, err := s.root.Lstat(s.parent(r))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// cleanupPhase names journal phases in which the broker may have created the
// parent without its marker (intent) or already removed the marker or parent
// (deletion). Only these may finish cleanup without a parent marker.
func cleanupPhase(phase string) bool {
	return phase == "intent" || phase == "native_deleted" || phase == "network_deleted"
}

// removeMarkerTemp discards an interrupted marker write left by write(). It is
// the broker's own file in its own parent; anything else is left in place.
func (s *Records) removeMarkerTemp(parent string) error {
	path := filepath.Join(parent, ownerMarker+".new")
	info, err := s.root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("unexpected entry at parent marker temporary path")
	}
	return s.root.Remove(path)
}

func (s *Records) Remove(e EngineRecord) error {
	r := e.Clone
	// Native deletion must already have removed the child. Never recursively
	// remove a disk tree or discard unknown files after an ambiguous operation.
	if exists, err := s.ChildExists(r); err != nil {
		return err
	} else if exists {
		return errors.New("native VM child remains")
	}
	parent := s.parent(r)
	marker, err := s.Parent(r)
	if errors.Is(err, os.ErrNotExist) {
		info, statErr := s.root.Lstat(parent)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if statErr == nil {
			// The protected root admits only broker-created entries, Create
			// proved this parent absent before recording intent, and the record
			// still reserves it. In a cleanup phase an unmarked directory is
			// therefore the broker's own interrupted creation or deletion. It is
			// removed only while empty; a reparse point or file is refused.
			if !info.IsDir() || !cleanupPhase(e.Phase) {
				return errors.New("unmarked parent remains")
			}
			if err = s.removeMarkerTemp(parent); err != nil {
				return err
			}
			if err = s.root.Remove(parent); err != nil {
				return errors.Join(errors.New("unmarked parent is not empty"), err)
			}
		}
	} else {
		if err != nil {
			return err
		}
		if marker != r {
			return errors.New("parent marker differs")
		}
		if err = s.removeMarkerTemp(parent); err != nil {
			return err
		}
		if err = s.root.Remove(filepath.Join(parent, ownerMarker)); err != nil {
			return err
		}
		if err = s.root.Remove(parent); err != nil {
			// Keep ownership evidence if an unexpected sibling prevents removal.
			return errors.Join(err, s.write(filepath.Join(parent, ownerMarker), r))
		}
	}
	return s.root.Remove(filepath.Join("records", r.Meta.InstanceID+".json"))
}
