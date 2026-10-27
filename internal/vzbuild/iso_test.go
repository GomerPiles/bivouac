package vzbuild

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
)

// Test reader walks on-disk records using offsets from the volume
// descriptor, checking paired endian fields and sector boundaries.
func readISO(t *testing.T, image []byte, j bool) map[string][]byte {
	t.Helper()
	at := 16 * 2048
	if j {
		at += 2048
	}
	d := image[at : at+2048]
	if string(d[1:6]) != "CD001" || d[6] != 1 || d[0] != map[bool]byte{false: 1, true: 2}[j] {
		t.Fatal("invalid volume descriptor")
	}
	if j && string(d[88:91]) != "%/E" {
		t.Fatal("missing Joliet escape sequence")
	}
	dual := func(b []byte) uint32 {
		a := binary.LittleEndian.Uint32(b)
		if a != binary.BigEndian.Uint32(b[4:]) {
			t.Fatal("endian pair differs")
		}
		return a
	}
	for _, offset := range []int{847, 864} {
		if string(d[offset:offset+16]) != "0000000000000000" || d[offset+16] != 0 {
			t.Fatal("expiration/effective date is specified")
		}
	}
	for _, span := range [][2]int{{190, 318}, {318, 446}, {446, 574}, {574, 702}, {702, 739}, {739, 776}, {776, 813}} {
		for at := span[0]; at < span[1]; at++ {
			want := byte(' ')
			if j && (at-span[0])%2 == 0 && at+1 < span[1] {
				want = 0
			}
			if d[at] != want {
				t.Fatal("identifier padding differs", at)
			}
		}
	}
	if int(dual(d[80:]))*2048 != len(image) {
		t.Fatal("wrong volume length")
	}
	if binary.LittleEndian.Uint16(d[128:]) != 2048 {
		t.Fatal("wrong logical block size")
	}
	root := d[156:190]
	start := int(dual(root[2:])) * 2048
	size := int(dual(root[10:]))
	dir := image[start : start+size]
	result := map[string][]byte{}
	var previous []byte
	for at := 0; at < len(dir) && dir[at] != 0; {
		n := int(dir[at])
		if n < 34 || at+n > len(dir) || at/2048 != (at+n-1)/2048 {
			t.Fatal("invalid directory record")
		}
		r := dir[at : at+n]
		id := r[33 : 33+int(r[32])]
		at += n
		if r[25]&2 != 0 {
			continue
		}
		if previous != nil && bytes.Compare(previous, id) >= 0 {
			t.Fatal("directory records are not ordered")
		}
		previous = append(previous[:0], id...)
		var name string
		if j {
			var u []uint16
			for i := 0; i < len(id); i += 2 {
				u = append(u, binary.BigEndian.Uint16(id[i:]))
			}
			name = string(utf16.Decode(u))
		} else {
			name = string(id)
		}
		if !strings.HasSuffix(name, ";1") {
			t.Fatal("file version missing")
		}
		name = strings.TrimSuffix(name, ";1")
		if !j {
			name = strings.TrimSuffix(name, ".")
		}
		pos, length := int(dual(r[2:]))*2048, int(dual(r[10:]))
		if pos+length > len(image) {
			t.Fatal("file extent outside image")
		}
		result[name] = image[pos : pos+length]
	}
	return result
}
func isoFixture(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	files := []ISOFile{{Name: "meta-data", Size: 4, Reader: strings.NewReader("meta")}, {Name: "user-data", Size: 4, Reader: strings.NewReader("user")}, {Name: "helper", Size: 3000, Reader: bytes.NewReader(bytes.Repeat([]byte{0xab}, 3000))}}
	if err := WriteISO(&out, files); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestISOVolumeDirectoriesAndContents(t *testing.T) {
	image := isoFixture(t)
	if image[18*2048] != 255 || string(image[18*2048+1:18*2048+6]) != "CD001" {
		t.Fatal("missing terminator")
	}
	if strings.TrimSpace(string(image[16*2048+40:16*2048+72])) != "cidata" {
		t.Fatal("wrong volume ID")
	}
	for _, j := range []bool{false, true} {
		files := readISO(t, image, j)
		meta, user, helper := "META_DATA", "USER_DATA", "HELPER"
		if j {
			meta, user, helper = "meta-data", "user-data", "helper"
		}
		if string(files[meta]) != "meta" || string(files[user]) != "user" || !bytes.Equal(files[helper], bytes.Repeat([]byte{0xab}, 3000)) {
			t.Fatal("ISO contents differ")
		}
	}
	if !bytes.Equal(image, isoFixture(t)) {
		t.Fatal("ISO is not deterministic")
	}
	for _, test := range []ISOFile{{Name: "../file", Reader: strings.NewReader("")}, {Name: "large", Size: 1 << 32, Reader: strings.NewReader("")}, {Name: "short", Size: 2, Reader: strings.NewReader("x")}, {Name: "long", Size: 1, Reader: strings.NewReader("xx")}} {
		if WriteISO(io.Discard, []ISOFile{test}) == nil {
			t.Fatal("invalid ISO file accepted")
		}
	}
}

func TestISODirectoryFilenameAndExtensionOrder(t *testing.T) {
	names := []string{"alpha-x", "alpha.txt", "alpha", "alpha.tar.gz"}
	var files []ISOFile
	for _, name := range names {
		files = append(files, ISOFile{Name: name, Reader: strings.NewReader("")})
	}
	var image bytes.Buffer
	if err := WriteISO(&image, files); err != nil {
		t.Fatal(err)
	}
	for _, j := range []bool{false, true} {
		at := 16 * sector
		if j {
			at += sector
		}
		d := image.Bytes()[at : at+sector]
		root := int(binary.LittleEndian.Uint32(d[158:])) * sector
		var got []string
		for offset := 0; offset < sector && image.Bytes()[root+offset] != 0; {
			r := image.Bytes()[root+offset:]
			length := int(r[0])
			offset += length
			if r[25]&2 != 0 {
				continue
			}
			id := r[33 : 33+int(r[32])]
			name := string(id)
			if j {
				var u []uint16
				for i := 0; i < len(id); i += 2 {
					u = append(u, binary.BigEndian.Uint16(id[i:]))
				}
				name = string(utf16.Decode(u))
			}
			got = append(got, name)
		}
		want := []string{"ALPHA.;1", "ALPHA_TAR_GZ.;1", "ALPHA_TXT.;1", "ALPHA_X.;1"}
		if j {
			want = []string{"alpha;1", "alpha.txt;1", "alpha-x;1", "alpha.tar.gz;1"}
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatal("directory filename/extension order differs", got)
		}
	}
}
