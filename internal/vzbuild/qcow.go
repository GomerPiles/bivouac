package vzbuild

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

// Read-only subset of https://www.qemu.org/docs/master/interop/qcow2.html.
// Refcounts are never used to decide whether a guest cluster is present.
const (
	qcowCopied     uint64 = 1 << 63
	qcowCompressed uint64 = 1 << 62
	qcowOffset     uint64 = (1<<56 - 1) &^ 511
	maxL1Bytes     uint64 = 32 << 20
	maxL2Bytes     uint64 = 256 << 20
)

type qcowImage struct {
	file                       io.ReaderAt
	fileSize, virtual, cluster uint64
	bits, version              uint32
	l1                         []byte
}

func qcowError() error { return errors.New("unsupported or malformed qcow2 disk image") }
func (q *qcowImage) rangeOK(offset, size, alignment uint64) bool {
	return offset > 0 && offset%alignment == 0 && offset <= q.fileSize && size <= q.fileSize-offset
}
func (q *qcowImage) read(dst []byte, off uint64) error {
	if off > q.fileSize || uint64(len(dst)) > q.fileSize-off {
		return qcowError()
	}
	//nolint:gosec // fileSize originates in a nonnegative int64 file size.
	if _, err := q.file.ReadAt(dst, int64(off)); err != nil {
		return qcowError()
	}
	return nil
}
func openQCOW(file io.ReaderAt, fileSize, target uint64) (*qcowImage, error) {
	q := &qcowImage{file: file, fileSize: fileSize}
	h := make([]byte, 104)
	if err := q.read(h[:72], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	q.version = be.Uint32(h[4:])
	q.bits = be.Uint32(h[20:])
	q.virtual = be.Uint64(h[24:])
	if string(h[:4]) != "QFI\xfb" || q.version != 2 && q.version != 3 || q.bits < 9 || q.bits > 21 || be.Uint64(h[8:]) != 0 || be.Uint32(h[16:]) != 0 || be.Uint32(h[32:]) != 0 || be.Uint32(h[60:]) != 0 || be.Uint64(h[64:]) != 0 || q.virtual == 0 || q.virtual%512 != 0 || q.virtual > target {
		return nil, qcowError()
	}
	q.cluster = 1 << q.bits
	if q.cluster > q.fileSize {
		return nil, qcowError()
	}
	headerLength := uint64(72)
	if q.version == 3 {
		if err := q.read(h, 0); err != nil {
			return nil, err
		}
		headerLength = uint64(be.Uint32(h[100:]))
		if be.Uint64(h[72:]) != 0 || be.Uint64(h[88:])&2 != 0 || be.Uint32(h[96:]) > 6 || headerLength < 104 || headerLength%8 != 0 || headerLength > 1<<20 || headerLength+8 > q.cluster {
			return nil, qcowError()
		}
	}
	// One bounded first cluster contains all header fields and extensions.
	first := make([]byte, q.cluster)
	if err := q.read(first, 0); err != nil {
		return nil, err
	}
	if headerLength > 104 && first[104] != 0 {
		return nil, qcowError()
	} // only raw deflate
	if headerLength >= 112 && !allZero(first[105:112]) {
		return nil, qcowError()
	}
	seen := map[uint32]bool{}
	terminated := false
	for at, n := headerLength, 0; at+8 <= q.cluster && n < 128; n++ {
		kind, length := be.Uint32(first[at:]), uint64(be.Uint32(first[at+4:]))
		at += 8
		if kind == 0 {
			if length != 0 {
				return nil, qcowError()
			}
			terminated = true
			break
		}
		padded := (length + 7) &^ 7
		if seen[kind] || padded > q.cluster-at {
			return nil, qcowError()
		}
		seen[kind] = true
		switch kind {
		case 0xe2792aca, 0x23852875, 0x0537be77, 0x44415441:
			return nil, qcowError()
		}
		at += padded
	}
	if !terminated {
		return nil, qcowError()
	}
	// Validate the declared refcount table geometry only. Its contents are not
	// consulted, even when compatible lazy-refcount flags are present.
	refOffset, refClusters := be.Uint64(h[48:]), uint64(be.Uint32(h[56:]))
	if refClusters == 0 {
		if refOffset != 0 {
			return nil, qcowError()
		}
	} else if refClusters > (8<<20)/q.cluster || !q.rangeOK(refOffset, refClusters*q.cluster, q.cluster) {
		return nil, qcowError()
	}
	l1Count := uint64(be.Uint32(h[36:]))
	needed := (q.virtual + q.cluster*(q.cluster/8) - 1) / (q.cluster * (q.cluster / 8))
	l1Offset := be.Uint64(h[40:])
	if l1Count < needed || l1Count > maxL1Bytes/8 || !q.rangeOK(l1Offset, l1Count*8, q.cluster) {
		return nil, qcowError()
	}
	q.l1 = make([]byte, l1Count*8)
	if err := q.read(q.l1, l1Offset); err != nil {
		return nil, err
	}
	for i := uint64(0); i < l1Count; i++ {
		entry := be.Uint64(q.l1[i*8:])
		off := entry & qcowOffset
		if entry&^(qcowCopied|qcowOffset) != 0 || off == 0 && entry != 0 || off != 0 && !q.rangeOK(off, q.cluster, q.cluster) || i >= needed && entry != 0 {
			return nil, qcowError()
		}
	}
	return q, nil
}
func (q *qcowImage) clusterData(entry uint64, buf []byte, read bool) error {
	if entry&qcowCompressed != 0 {
		if entry&qcowCopied != 0 {
			return qcowError()
		}
		shift := 70 - q.bits
		offset := entry & ((uint64(1) << shift) - 1)
		sectors := ((entry >> shift) & ((uint64(1) << (q.bits - 8)) - 1)) + 1
		length := sectors*512 - offset%512
		if offset>>56 != 0 || !q.rangeOK(offset, length, 1) || length > 2*q.cluster {
			return qcowError()
		}
		if !read {
			return nil
		}
		compressed := make([]byte, length)
		if err := q.read(compressed, offset); err != nil {
			return err
		}
		decoder := flate.NewReader(bytes.NewReader(compressed))
		defer func() { _ = decoder.Close() }()
		out, err := io.ReadAll(io.LimitReader(decoder, int64(q.cluster)+1)) //nolint:gosec // cluster <= 2 MiB.
		if err != nil || uint64(len(out)) != q.cluster {
			return qcowError()
		}
		copy(buf, out)
		return nil
	}
	if entry&^(qcowCopied|qcowOffset|1) != 0 || q.version == 2 && entry&1 != 0 {
		return qcowError()
	}
	offset := entry & qcowOffset
	if offset == 0 && entry&qcowCopied != 0 || offset != 0 && !q.rangeOK(offset, q.cluster, q.cluster) {
		return qcowError()
	}
	if !read {
		return nil
	}
	if entry&1 != 0 || offset == 0 {
		clear(buf)
		return nil
	}
	return q.read(buf, offset)
}
func (q *qcowImage) writeRaw(ctx context.Context, out *os.File) error {
	var metadata uint64
	for i := 0; i < len(q.l1); i += 8 {
		if binary.BigEndian.Uint64(q.l1[i:])&qcowOffset != 0 {
			metadata += q.cluster
			if metadata > maxL2Bytes {
				return qcowError()
			}
		}
	}
	be := binary.BigEndian
	table, buf := make([]byte, q.cluster), make([]byte, q.cluster)
	var position uint64
	for i := 0; i < len(q.l1); i += 8 {
		if err := ctx.Err(); err != nil {
			return err
		}
		offset := be.Uint64(q.l1[i:]) & qcowOffset
		span := min(q.cluster*(q.cluster/8), q.virtual-position)
		if position == q.virtual {
			break
		}
		if offset == 0 {
			//nolint:gosec // span <= virtual <= 512 GiB.
			if _, err := out.Seek(int64(span), io.SeekCurrent); err != nil {
				return err
			}
			position += span
			continue
		}
		if err := q.read(table, offset); err != nil {
			return err
		}
		for j := 0; j < len(table); j += 8 {
			if err := ctx.Err(); err != nil {
				return err
			}
			active := position < q.virtual
			if err := q.clusterData(be.Uint64(table[j:]), buf, active); err != nil {
				return err
			}
			if !active {
				continue
			}
			n := min(q.cluster, q.virtual-position)
			if allZero(buf[:n]) {
				//nolint:gosec // n <= cluster <= 2 MiB.
				if _, err := out.Seek(int64(n), io.SeekCurrent); err != nil {
					return err
				}
			} else if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			position += n
		}
	}
	return nil
}
func convert(ctx context.Context, input, dst string, target int64) (int64, error) {
	if target < 16*vzrecipe.GiB || target > 512*vzrecipe.GiB {
		return 0, errors.New("invalid target disk size")
	}
	in, err := os.Open(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()
	stat, err := in.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return 0, qcowError()
	}
	fileSize := stat.Size()
	if fileSize < 0 {
		return 0, qcowError()
	}
	q, err := openQCOW(in, uint64(fileSize), uint64(target))
	if err != nil {
		return 0, err
	} //nolint:gosec // regular file size and validated target are nonnegative.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return 0, err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	if err = q.writeRaw(ctx, out); err != nil {
		return 0, err
	}
	virtual := int64(q.virtual) //nolint:gosec // virtual <= target <= 512 GiB.
	if err = out.Truncate(virtual); err != nil {
		return 0, err
	}
	if err = validateEFI(out, virtual); err != nil {
		return 0, err
	}
	if err = out.Truncate(target); err != nil {
		return 0, err
	}
	if err = out.Sync(); err != nil {
		return 0, err
	}
	ok = true
	return virtual, nil
}
