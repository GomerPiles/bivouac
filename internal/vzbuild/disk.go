package vzbuild

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// validateEFI checks the protective MBR, primary GPT CRC/geometry and partition
// table CRC and requires an EFI System Partition within the original raw image.
// Fallback loader bootability is established by the fresh-NVRAM cold gate.
func validateEFI(disk io.ReaderAt, size int64) error {
	bad := errors.New("raw disk requires a valid protective MBR, GPT and EFI System Partition")
	if size < 3*512 || size%512 != 0 {
		return bad
	}
	mbr := make([]byte, 512)
	if _, err := disk.ReadAt(mbr, 0); err != nil {
		return bad
	}
	if !bytes.Equal(mbr[510:], []byte{0x55, 0xaa}) {
		return bad
	}
	protective := false
	for i := 0; i < 4; i++ {
		p := mbr[446+i*16 : 462+i*16]
		if p[4] == 0xee && binary.LittleEndian.Uint32(p[8:12]) == 1 && uint64(binary.LittleEndian.Uint32(p[12:16])) == uint64(size/512-1) {
			protective = true
		}
	}
	if !protective {
		return bad
	}
	hdr := make([]byte, 512)
	if _, err := disk.ReadAt(hdr, 512); err != nil {
		return bad
	}
	le := binary.LittleEndian
	headerSize := le.Uint32(hdr[12:16])
	if string(hdr[:8]) != "EFI PART" || le.Uint32(hdr[8:12]) != 0x10000 || headerSize < 92 || headerSize > 512 || le.Uint64(hdr[24:32]) != 1 || le.Uint64(hdr[32:40]) != uint64(size/512-1) {
		return bad
	}
	wantCRC := le.Uint32(hdr[16:20])
	clear(hdr[16:20])
	if crc32.ChecksumIEEE(hdr[:headerSize]) != wantCRC {
		return bad
	}
	tableLBA := le.Uint64(hdr[72:80])
	count := le.Uint32(hdr[80:84])
	stride := le.Uint32(hdr[84:88])
	if count == 0 || count > 4096 || stride < 128 || stride > 4096 || stride%128 != 0 {
		return bad
	}
	tableBytes := uint64(count) * uint64(stride)
	if tableBytes > 16<<20 || tableLBA < 2 || tableLBA > uint64(size/512) || tableBytes > uint64(size)-tableLBA*512 {
		return bad
	}
	table := make([]byte, int(tableBytes))
	//nolint:gosec // tableLBA*512 is bounded above by the positive int64 raw size.
	if _, err := disk.ReadAt(table, int64(tableLBA*512)); err != nil || crc32.ChecksumIEEE(table) != le.Uint32(hdr[88:92]) {
		return bad
	}
	first, last := le.Uint64(hdr[40:48]), le.Uint64(hdr[48:56])
	if first < 2 || last < first || last >= uint64(size/512-1) || tableLBA*512+tableBytes > first*512 {
		return bad
	}
	esp := []byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}
	found := false
	for i := uint32(0); i < count; i++ {
		p := table[int(i*stride):int((i+1)*stride)]
		if allZero(p[:16]) {
			continue
		}
		start, end := le.Uint64(p[32:40]), le.Uint64(p[40:48])
		if start < first || end < start || end > last {
			return bad
		}
		if bytes.Equal(p[:16], esp) {
			found = true
		}
	}
	if !found {
		return bad
	}
	return nil
}
