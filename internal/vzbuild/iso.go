package vzbuild

import (
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

const sector = 2048

// ISOFile is a single extent. Reader must contain exactly Size bytes. The
// writer supports a flat root only, no Rock Ridge, links or directory trees.
type ISOFile struct {
	Name   string
	Size   int64
	Reader io.Reader
}

func both16(b []byte, n uint16) {
	binary.LittleEndian.PutUint16(b, n)
	binary.BigEndian.PutUint16(b[2:], n)
}
func both32(b []byte, n uint32) {
	binary.LittleEndian.PutUint32(b, n)
	binary.BigEndian.PutUint32(b[4:], n)
}
func joliet(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.BigEndian.PutUint16(b[i*2:], c)
	}
	return b
}
func directoryRecord(id []byte, lba, length uint32, dir bool) []byte {
	n := 33 + len(id)
	if n%2 != 0 {
		n++
	}
	b := make([]byte, n)
	b[0] = byte(n) //nolint:gosec // Flat filenames are bounded to 28 ASCII bytes (Joliet records under 100 bytes).
	both32(b[2:], lba)
	both32(b[10:], length)
	copy(b[18:25], []byte{126, 1, 1, 0, 0, 0, 0})
	if dir {
		b[25] = 2
	}
	both16(b[28:], 1)
	b[32] = byte(len(id)) //nolint:gosec // Identifier length is at most 64 bytes.
	copy(b[33:], id)
	return b
}
func primaryIdentifier(name string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name)) + ".;1"
}
func rootDirectory(files []ISOFile, extents []uint32, root uint32, j bool) ([]byte, error) {
	b := make([]byte, 0, sector)
	b = append(b, directoryRecord([]byte{0}, root, sector, true)...)
	b = append(b, directoryRecord([]byte{1}, root, sector, true)...)
	type record struct {
		id              []byte
		extent          uint32
		size            uint32
		name, extension string
	}
	entries := make([]record, 0, len(files))
	for i, f := range files {
		id := []byte(primaryIdentifier(f.Name))
		if j {
			id = joliet(f.Name + ";1")
		}
		name, extension := strings.TrimSuffix(primaryIdentifier(f.Name), ".;1"), ""
		if j {
			name = f.Name
			if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
				extension = name[dot+1:]
				name = name[:dot]
			}
		}
		entries = append(entries, record{id: id, extent: extents[i], size: uint32(f.Size), name: name, extension: extension}) //nolint:gosec // Size is validated <= 4 GiB-1.
	}
	sort.Slice(entries, func(i, k int) bool {
		if entries[i].name != entries[k].name {
			return entries[i].name < entries[k].name
		}
		return entries[i].extension < entries[k].extension
	})
	for _, e := range entries {
		b = append(b, directoryRecord(e.id, e.extent, e.size, false)...)
	}

	if len(b) > sector {
		return nil, errors.New("ISO root directory exceeds one sector")
	}
	return append(b, make([]byte, sector-len(b))...), nil
}
func descriptor(kind byte, total, root, pathLE, pathBE uint32, j bool) []byte {
	b := make([]byte, sector)
	b[0] = kind
	copy(b[1:6], "CD001")
	b[6] = 1
	for i := 8; i < 72; i++ {
		b[i] = ' '
	}
	copy(b[40:72], "cidata")
	if j {
		for i := 8; i < 72; i += 2 {
			b[i] = 0
			b[i+1] = ' '
		}
		copy(b[40:72], joliet("cidata"))
		copy(b[88:91], "%/E")
	}
	both32(b[80:], total)
	both16(b[120:], 1)
	both16(b[124:], 1)
	both16(b[128:], sector)
	both32(b[132:], 10)
	binary.LittleEndian.PutUint32(b[140:], pathLE)
	binary.BigEndian.PutUint32(b[148:], pathBE)
	copy(b[156:], directoryRecord([]byte{0}, root, sector, true))
	// Identifier fields are padded with spaces, UCS-2 spaces in Joliet.
	for _, span := range [][2]int{{190, 318}, {318, 446}, {446, 574}, {574, 702}, {702, 739}, {739, 776}, {776, 813}} {
		for at := span[0]; at < span[1]; at++ {
			b[at] = ' '
		}
		if j {
			for at := span[0]; at+1 < span[1]; at += 2 {
				b[at] = 0
				b[at+1] = ' '
			}
		}
	}
	for _, off := range []int{813, 830} {
		copy(b[off:off+16], "2026010100000000")
	}
	for _, off := range []int{847, 864} {
		copy(b[off:off+16], "0000000000000000")
	}

	b[881] = 1
	return b
}
func pathTable(root uint32, big bool) []byte {
	b := make([]byte, sector)
	b[0] = 1
	if big {
		binary.BigEndian.PutUint32(b[2:], root)
		binary.BigEndian.PutUint16(b[6:], 1)
	} else {
		binary.LittleEndian.PutUint32(b[2:], root)
		binary.LittleEndian.PutUint16(b[6:], 1)
	}
	return b
}

// WriteISO emits deterministic ISO9660 + Joliet media without a module dependency.
// Each file is at most 4 GiB-1; image metadata is bounded to 25 sectors.
func WriteISO(w io.Writer, files []ISOFile) error {
	if len(files) == 0 || len(files) > 12 {
		return errors.New("invalid ISO file count")
	}
	extents := make([]uint32, len(files))
	next := uint64(25)
	seen := map[string]bool{}
	for i, f := range files {
		if f.Name == "" || len(f.Name) > 28 || f.Size < 0 || f.Size > 1<<32-1 || f.Reader == nil || seen[primaryIdentifier(f.Name)] {
			return errors.New("invalid ISO file")
		}
		for _, c := range f.Name {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-._", c) {
				return errors.New("invalid ISO filename")
			}
		}
		seen[primaryIdentifier(f.Name)] = true
		extents[i] = uint32(next)
		next += uint64((f.Size + sector - 1) / sector) //nolint:gosec // Size was checked nonnegative and <= 4 GiB-1.
		if next > 1<<32-1 {
			return errors.New("ISO exceeds extent bounds")
		}
	}
	primary, err := rootDirectory(files, extents, 23, false)
	if err != nil {
		return err
	}
	supplementary, err := rootDirectory(files, extents, 24, true)
	if err != nil {
		return err
	}
	terminator := make([]byte, sector)
	terminator[0] = 255
	copy(terminator[1:], "CD001")
	terminator[6] = 1
	blocks := [][]byte{make([]byte, 16*sector), descriptor(1, uint32(next), 23, 19, 20, false), descriptor(2, uint32(next), 24, 21, 22, true), terminator, pathTable(23, false), pathTable(23, true), pathTable(24, false), pathTable(24, true), primary, supplementary}
	for _, b := range blocks {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	for _, f := range files {
		if _, err := io.CopyN(w, f.Reader, f.Size); err != nil {
			return errors.New("ISO file size differs")
		}
		var extra [1]byte
		if n, err := f.Reader.Read(extra[:]); n != 0 || err != io.EOF {
			return errors.New("ISO file size differs")
		}
		pad := (sector - f.Size%sector) % sector
		if _, err := w.Write(make([]byte, int(pad))); err != nil {
			return err
		}
	}
	return nil
}
