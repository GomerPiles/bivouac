package imagefactory

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// A deliberately small read-only UDF reader for Windows installation ISOs.
// Only physical partition maps, recorded extents, and ordinary files/directories
// are accepted. No extraction, filesystem writes, links, or native mounts occur.
// Structures follow ECMA-167, part 4 (UDF 1.02/1.50).
type udfVolume struct {
	r             io.ReaderAt
	size          int64
	start, blocks uint32
}
type udfAddress struct {
	block     uint32
	partition uint16
}

func readISOInventory(r io.ReaderAt, size int64, edition string, index uint32) (MediaInventory, error) {
	v := udfVolume{r: r, size: size}
	root, err := v.open()
	if err != nil {
		return MediaInventory{}, err
	}
	dirs, err := v.directory(root)
	if err != nil {
		return MediaInventory{}, err
	}
	sources, ok := dirs["sources"]
	if !ok {
		return MediaInventory{}, errors.New("ISO has no sources directory")
	}
	entries, err := v.directory(sources)
	if err != nil {
		return MediaInventory{}, err
	}
	files := map[string]*io.SectionReader{}
	for name, a := range entries {
		if name != "install.wim" && name != "install.esd" && (!strings.HasPrefix(name, "install") || !strings.HasSuffix(name, ".swm")) {
			continue
		}
		file, kind, e := v.file(a)
		if e != nil {
			return MediaInventory{}, e
		}
		if kind != 5 {
			return MediaInventory{}, errors.New("install image is not an ordinary file")
		}
		files[name] = file
	}
	return inventoryInstall(files, edition, index)
}

func (v udfVolume) read(offset int64, length int) ([]byte, error) {
	if offset < 0 || length < 0 || length > 4<<20 || offset > v.size || int64(length) > v.size-offset {
		return nil, errors.New("ISO extent exceeds bounds")
	}
	b := make([]byte, length)
	if _, e := v.r.ReadAt(b, offset); e != nil {
		return nil, errors.New("truncated ISO extent")
	}
	return b, nil
}
func udfTag(b []byte, id uint16) bool {
	if len(b) < 16 || binary.LittleEndian.Uint16(b) != id {
		return false
	}
	var sum byte
	for i := range 16 {
		if i != 4 {
			sum += b[i]
		}
	}
	if sum != b[4] {
		return false
	}
	n := int(binary.LittleEndian.Uint16(b[10:]))
	if n > len(b)-16 {
		return false
	}
	var crc uint16
	for _, x := range b[16 : 16+n] {
		crc ^= uint16(x) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc == binary.LittleEndian.Uint16(b[8:])
}
func udfLong(b []byte) udfAddress {
	return udfAddress{binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint16(b[8:])}
}
func (v *udfVolume) open() (udfAddress, error) {
	le := binary.LittleEndian
	b, e := v.read(256*2048, 2048)
	if e != nil {
		return udfAddress{}, e
	}
	if !udfTag(b, 2) {
		return udfAddress{}, errors.New("unsupported ISO: UDF anchor required")
	}
	length, location := le.Uint32(b[16:]), le.Uint32(b[20:])
	if length == 0 || length > 128*2048 || length%2048 != 0 {
		return udfAddress{}, errors.New("invalid UDF descriptor sequence")
	}
	var fsd udfAddress
	var partitionID, mapID uint16
	partitionFound, logicalFound := false, false
	for off := uint32(0); off < length; off += 2048 {
		b, e = v.read(int64(location)*2048+int64(off), 2048)
		if e != nil {
			return udfAddress{}, e
		}
		switch le.Uint16(b) {
		case 5:
			if partitionFound || !udfTag(b, 5) {
				return udfAddress{}, errors.New("unsupported UDF partition")
			}
			partitionID = le.Uint16(b[22:])
			v.start, v.blocks = le.Uint32(b[188:]), le.Uint32(b[192:])
			partitionFound = true
		case 6:
			if logicalFound || !udfTag(b, 6) || le.Uint32(b[212:]) != 2048 || le.Uint32(b[264:]) != 6 || le.Uint32(b[268:]) != 1 || b[440] != 1 || b[441] != 6 {
				return udfAddress{}, errors.New("unsupported UDF logical volume")
			}
			mapID = le.Uint16(b[444:])
			fsd = udfLong(b[248:])
			logicalFound = true
		}
	}
	if !partitionFound || !logicalFound || partitionID != mapID || v.blocks == 0 || (int64(v.start)+int64(v.blocks))*2048 > v.size {
		return udfAddress{}, errors.New("invalid UDF volume bounds")
	}
	b, e = v.block(fsd)
	if e != nil {
		return udfAddress{}, e
	}
	if !udfTag(b, 256) {
		return udfAddress{}, errors.New("invalid UDF file set")
	}
	return udfLong(b[400:]), nil
}
func (v udfVolume) block(a udfAddress) ([]byte, error) {
	if a.partition != 0 || a.block >= v.blocks {
		return nil, errors.New("invalid UDF block address")
	}
	return v.read((int64(v.start)+int64(a.block))*2048, 2048)
}

type udfExtent struct{ offset, size int64 }
type udfFile struct {
	v       udfVolume
	extents []udfExtent
	size    int64
}

func (f udfFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative ISO file offset")
	}
	n := 0
	for _, ex := range f.extents {
		if off >= ex.size {
			off -= ex.size
			continue
		}
		length := min(int64(len(p)), ex.size-off)
		m, e := f.v.r.ReadAt(p[:int(length)], ex.offset+off)
		n += m
		p = p[m:]
		if e != nil {
			return n, e
		}
		off = 0
		if len(p) == 0 {
			return n, nil
		}
	}
	return n, io.EOF
}
func (v udfVolume) file(a udfAddress) (*io.SectionReader, byte, error) {
	b, e := v.block(a)
	if e != nil {
		return nil, 0, e
	}
	le := binary.LittleEndian
	id := le.Uint16(b)
	base := 176
	if id == 266 {
		base = 216
	}
	if (id != 261 && id != 266) || !udfTag(b, id) {
		return nil, 0, errors.New("invalid UDF file entry")
	}
	kind := b[27]
	if kind != 4 && kind != 5 {
		return nil, 0, errors.New("UDF links and special files refused")
	}
	size := le.Uint64(b[56:])
	if size > 256<<30 {
		return nil, 0, errors.New("ISO file exceeds size bound")
	}
	ea, ads := le.Uint32(b[base-8:]), le.Uint32(b[base-4:])
	if uint64(base)+uint64(ea)+uint64(ads) > uint64(len(b)) {
		return nil, 0, errors.New("UDF allocation bounds")
	}
	ad := b[base+int(ea) : base+int(ea)+int(ads)]
	mode := le.Uint16(b[34:]) & 7
	f := udfFile{v: v, size: int64(size)} // #nosec G115 -- <=256 GiB above.
	if mode == 3 {
		if uint64(len(ad)) < size {
			return nil, 0, errors.New("truncated inline UDF file")
		}
		f.extents = []udfExtent{{(int64(v.start)+int64(a.block))*2048 + int64(base) + int64(ea), int64(size)}}
	} else {
		stride := 8
		if mode == 1 {
			stride = 16
		} else if mode != 0 {
			return nil, 0, errors.New("unsupported UDF allocation type")
		}
		if len(ad)%stride != 0 {
			return nil, 0, errors.New("invalid UDF allocation descriptors")
		}
		var total int64
		for len(ad) > 0 {
			length := le.Uint32(ad)
			block := le.Uint32(ad[4:])
			if length>>30 != 0 || block >= v.blocks || (mode == 1 && le.Uint16(ad[8:]) != 0) || uint64(block)*2048+uint64(length) > uint64(v.blocks)*2048 {
				return nil, 0, errors.New("unsupported or invalid UDF extent")
			}
			n := min(int64(length), f.size-total)
			if n > 0 {
				f.extents = append(f.extents, udfExtent{(int64(v.start) + int64(block)) * 2048, n})
				total += n
			}
			ad = ad[stride:]
		}
		if total != f.size {
			return nil, 0, errors.New("incomplete UDF file")
		}
	}
	return io.NewSectionReader(f, 0, f.size), kind, nil
}
func (v udfVolume) directory(a udfAddress) (map[string]udfAddress, error) {
	f, kind, e := v.file(a)
	if e != nil {
		return nil, e
	}
	if kind != 4 || f.Size() > 4<<20 {
		return nil, errors.New("invalid or oversized UDF directory")
	}
	b, e := io.ReadAll(f)
	if e != nil {
		return nil, errors.New("unreadable UDF directory")
	}
	entries := map[string]udfAddress{}
	le := binary.LittleEndian
	for len(b) > 0 {
		if len(b) < 38 {
			return nil, errors.New("truncated UDF directory entry")
		}
		n := int(b[19])
		impl := int(le.Uint16(b[36:]))
		length := (38 + impl + n + 3) &^ 3
		if length > len(b) || !udfTag(b[:length], 257) {
			return nil, errors.New("invalid UDF directory entry")
		}
		if b[18]&12 == 0 && n > 0 {
			nameBytes := b[38+impl : 38+impl+n]
			var name strings.Builder
			if nameBytes[0] != 8 && nameBytes[0] != 16 {
				return nil, errors.New("unsupported UDF filename encoding")
			}
			for i := 1; i < len(nameBytes); i++ {
				ch := uint16(nameBytes[i])
				if nameBytes[0] == 16 {
					if i+1 >= len(nameBytes) {
						return nil, errors.New("invalid UDF filename")
					}
					ch = le.Uint16([]byte{nameBytes[i+1], nameBytes[i]})
					i++
				}
				if ch < 32 || ch > 126 || ch == '/' || ch == '\\' {
					return nil, errors.New("unsupported UDF filename")
				}
				name.WriteByte(byte(ch))
			}
			s := strings.ToLower(name.String())
			if _, exists := entries[s]; exists {
				return nil, errors.New("duplicate UDF filename")
			}
			entries[s] = udfLong(b[20:])
		}
		b = b[length:]
	}
	return entries, nil
}
