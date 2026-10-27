package vzbuild

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func rawEFIFixture() []byte {
	b := make([]byte, 128*512)
	b[510] = 0x55
	b[511] = 0xaa
	b[450] = 0xee
	le := binary.LittleEndian
	le.PutUint32(b[454:], 1)
	le.PutUint32(b[458:], 127)
	h := b[512:1024]
	copy(h, "EFI PART")
	le.PutUint32(h[8:], 0x10000)
	le.PutUint32(h[12:], 92)
	le.PutUint64(h[24:], 1)
	le.PutUint64(h[32:], 127)
	le.PutUint64(h[40:], 34)
	le.PutUint64(h[48:], 126)
	le.PutUint64(h[72:], 2)
	le.PutUint32(h[80:], 1)
	le.PutUint32(h[84:], 128)
	p := b[1024:1152]
	copy(p, []byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b})
	le.PutUint64(p[32:], 34)
	le.PutUint64(p[40:], 40)
	le.PutUint32(h[88:], crc32.ChecksumIEEE(p))
	le.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
	return b
}
func TestEFIValidationFailsClosed(t *testing.T) {
	for _, offset := range []int{510, 450, 512, 512 + 12, 512 + 16, 512 + 72, 1024} {
		b := rawEFIFixture()
		b[offset] ^= 0xff
		if validateEFI(bytes.NewReader(b), int64(len(b))) == nil {
			t.Fatal("bad GPT accepted", offset)
		}
	}
}
