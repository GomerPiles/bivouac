package imagefactory

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func tagUDFFixture(b []byte, id uint16) {
	b[4] = 0
	le := binary.LittleEndian
	le.PutUint16(b, id)
	le.PutUint16(b[2:], 2)
	le.PutUint16(b[10:], uint16(len(b)-16)) // #nosec G115 -- fixture descriptors <=2048 bytes.
	var crc uint16
	for _, x := range b[16:] {
		crc ^= uint16(x) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	le.PutUint16(b[8:], crc)
	for i := range 16 {
		if i != 4 {
			b[4] += b[i]
		}
	}
}
func syntheticUDF() []byte {
	b := make([]byte, 600*2048)
	le := binary.LittleEndian
	block := func(n int) []byte { return b[n*2048 : (n+1)*2048] }
	anchor := block(256)
	le.PutUint32(anchor[16:], 2*2048)
	le.PutUint32(anchor[20:], 257)
	tagUDFFixture(anchor, 2)
	pd := block(257)
	le.PutUint32(pd[188:], 400)
	le.PutUint32(pd[192:], 100)
	tagUDFFixture(pd, 5)
	lvd := block(258)
	le.PutUint32(lvd[212:], 2048)
	le.PutUint32(lvd[248:], 2048)
	le.PutUint32(lvd[264:], 6)
	le.PutUint32(lvd[268:], 1)
	lvd[440] = 1
	lvd[441] = 6
	tagUDFFixture(lvd, 6)
	fsd := block(400)
	le.PutUint32(fsd[400:], 2048)
	le.PutUint32(fsd[404:], 1)
	tagUDFFixture(fsd, 256)
	fid := func(name string, where uint32) []byte {
		n := 1 + len(name)
		entry := make([]byte, (38+n+3)&^3)
		entry[19] = byte(n)
		le.PutUint32(entry[20:], 2048)
		le.PutUint32(entry[24:], where)
		entry[38] = 8
		copy(entry[39:], name)
		tagUDFFixture(entry, 257)
		return entry
	} // #nosec G115 -- short fixture names.
	file := func(n int, kind byte, data []byte) {
		fe := block(n)
		fe[27] = kind
		le.PutUint16(fe[34:], 3)
		le.PutUint64(fe[56:], uint64(len(data)))
		le.PutUint32(fe[172:], uint32(len(data)))
		copy(fe[176:], data)
		tagUDFFixture(fe, 261)
	} // #nosec G115 -- fixture data <=2048 bytes.
	file(401, 4, fid("sources", 2))
	file(402, 4, fid("install.wim", 3))
	file(403, 5, syntheticWIM(`<WIM>`+imageXML("Professional", 1)+`</WIM>`))
	return b
}
func TestUDFInventoryAndBounds(t *testing.T) {
	good := syntheticUDF()
	got, e := readISOInventory(bytes.NewReader(good), int64(len(good)), "Professional", 0)
	if e != nil || got.Selected.Index != 1 {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:100] }, "checksum": func(b []byte) []byte { b[256*2048+4]++; return b }, "partition extent": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[257*2048+188:], ^uint32(0))
			tagUDFFixture(b[257*2048:258*2048], 5)
			return b
		}, "file size": func(b []byte) []byte {
			binary.LittleEndian.PutUint64(b[403*2048+56:], ^uint64(0))
			tagUDFFixture(b[403*2048:404*2048], 261)
			return b
		}, "corrupt entry": func(b []byte) []byte { b[401*2048+176+19] = 255; return b },
	} {
		t.Run(name, func(t *testing.T) {
			b := mutate(bytes.Clone(good))
			if _, e := readISOInventory(bytes.NewReader(b), int64(len(b)), "Professional", 0); e == nil {
				t.Fatal("corrupt media accepted")
			}
		})
	}
}
