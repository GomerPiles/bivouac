package vzbuild

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/GomerPiles/bivouac/internal/vzrecipe"
)

const testCluster = 4096

// Four metadata clusters, followed by standard clusters; refcounts deliberately
// contain junk. Only L1/L2 mappings determine the virtual disk contents.
func qcowFixture(t *testing.T, raw []byte, version uint32) []byte {
	t.Helper()
	l1Count := (len(raw) + testCluster*(testCluster/8) - 1) / (testCluster * (testCluster / 8))
	b := make([]byte, (3+l1Count)*testCluster)
	be := binary.BigEndian
	copy(b, "QFI\xfb")
	be.PutUint32(b[4:], version)
	be.PutUint32(b[20:], 12)
	be.PutUint64(b[24:], uint64(len(raw)))
	be.PutUint32(b[36:], uint32(l1Count)) //nolint:gosec // Fixture uses at most two L1 entries.
	be.PutUint64(b[40:], testCluster)
	be.PutUint64(b[48:], uint64((2+l1Count)*testCluster)) //nolint:gosec // Small fixture metadata allocation.
	be.PutUint32(b[56:], 1)
	if version == 3 {
		be.PutUint32(b[96:], 4)
		be.PutUint32(b[100:], 104)
	}
	for i := 0; i < l1Count; i++ {
		be.PutUint64(b[testCluster+i*8:], uint64((2+i)*testCluster)|qcowCopied)
	} //nolint:gosec // Small fixture metadata offsets.
	for at := (2 + l1Count) * testCluster; at < (3+l1Count)*testCluster; at++ {
		b[at] = 0xff
	}
	for at := 0; at < len(raw); at += testCluster {
		cluster := make([]byte, testCluster)
		copy(cluster, raw[at:min(at+testCluster, len(raw))])
		if allZero(cluster) {
			continue
		}
		off := len(b)
		b = append(b, cluster...)
		table := 2 + at/(testCluster*(testCluster/8))
		index := at / testCluster % (testCluster / 8)
		be.PutUint64(b[table*testCluster+index*8:], uint64(off)|qcowCopied) //nolint:gosec // off is an existing fixture allocation.
	}
	return b
}
func compressedFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	b := qcowFixture(t, make([]byte, len(raw)), 3)
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw[:testCluster]); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	off := uint64(len(b) + 37)                                        // compressed offsets need not be sector aligned
	end := int(off) + compressed.Len()                                //nolint:gosec // off is the small fixture buffer length + 37.
	sectors := (uint64(end)+511)/512 - off/512                        //nolint:gosec // end is a positive fixture buffer length.
	b = append(b, make([]byte, int((off/512+sectors)*512)-len(b))...) //nolint:gosec // Fixture compression occupies at most a few sectors.
	copy(b[off:], compressed.Bytes())
	binary.BigEndian.PutUint64(b[2*testCluster:], qcowCompressed|((sectors-1)<<58)|off)
	return b
}
func qcowPath(t *testing.T, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.img")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestQCOWConversionEFIAndSparseExtension(t *testing.T) {
	for _, kind := range []string{"v2", "v3", "compressed", "zero-preallocated", "zero-unallocated", "unallocated-l1"} {
		t.Run(kind, func(t *testing.T) {
			raw := rawEFIFixture()
			v := uint32(3)
			if kind == "v2" {
				v = 2
			}
			image := qcowFixture(t, raw, v)
			switch kind {
			case "compressed":
				image = compressedFixture(t, raw)
			case "zero-unallocated":
				binary.BigEndian.PutUint64(image[2*testCluster+8:], 1)
			case "zero-preallocated":
				image = append(image, bytes.Repeat([]byte{0xff}, testCluster)...)
				binary.BigEndian.PutUint64(image[2*testCluster+8:], uint64(len(image)-testCluster)|qcowCopied|1) //nolint:gosec // Image contains several full clusters.
			case "unallocated-l1":
				// Cover two L1 spans; the second is entirely unallocated. Read virtual data
				// directly, because this larger geometry intentionally has no matching GPT.
				binary.BigEndian.PutUint64(image[24:], testCluster*(testCluster/8)+512)
				binary.BigEndian.PutUint32(image[36:], 2)
				q, err := openQCOW(bytes.NewReader(image), uint64(len(image)), 16*uint64(vzrecipe.GiB))
				if err != nil {
					t.Fatal(err)
				}
				out, err := os.CreateTemp(t.TempDir(), "raw")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = out.Close() }()
				if err = q.writeRaw(context.Background(), out); err != nil {
					t.Fatal(err)
				}
				pos, err := out.Seek(0, io.SeekCurrent)
				//nolint:gosec // Fixture virtual geometry is a little over 2 MiB.
				if err != nil || pos != int64(q.virtual) {
					t.Fatal("unallocated L1 span changed geometry", err)
				}
				return
			}
			path := qcowPath(t, image)
			dst := filepath.Join(t.TempDir(), "disk.img")
			size, err := convert(context.Background(), path, dst, 16*vzrecipe.GiB)
			if err != nil || size != int64(len(raw)) {
				t.Fatal("conversion", err)
			}
			f, err := os.Open(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			got := make([]byte, len(raw))
			if _, err = f.ReadAt(got, 0); err != nil || !bytes.Equal(got, raw) {
				t.Fatal("decoded disk differs", err)
			}
			stat, err := f.Stat()
			if err != nil || stat.Size() != 16*vzrecipe.GiB {
				t.Fatal("target disk not extended", err)
			}
			tail := make([]byte, 512)
			if _, err = f.ReadAt(tail, stat.Size()-512); err != nil || !allZero(tail) {
				t.Fatal("extension is not zero", err)
			}
		})
	}
}
func TestQCOWMalformedFieldsFailClosed(t *testing.T) {
	type mutation func([]byte)
	be := binary.BigEndian
	tests := map[string]mutation{
		"magic": func(b []byte) { b[0] = 0 }, "version": func(b []byte) { be.PutUint32(b[4:], 4) },
		"backing-offset": func(b []byte) { be.PutUint64(b[8:], 512) }, "backing-size": func(b []byte) { be.PutUint32(b[16:], 1) },
		"cluster-small": func(b []byte) { be.PutUint32(b[20:], 8) }, "cluster-large": func(b []byte) { be.PutUint32(b[20:], 22) },
		"empty-virtual": func(b []byte) { be.PutUint64(b[24:], 0) }, "virtual-alignment": func(b []byte) { be.PutUint64(b[24:], 513) }, "virtual-bound": func(b []byte) { be.PutUint64(b[24:], 17*uint64(vzrecipe.GiB)) },
		"encryption": func(b []byte) { be.PutUint32(b[32:], 1) }, "snapshots": func(b []byte) { be.PutUint32(b[60:], 1) }, "snapshot-offset": func(b []byte) { be.PutUint64(b[64:], testCluster) },
		"l1-empty": func(b []byte) { be.PutUint32(b[36:], 0) }, "l1-bound": func(b []byte) { be.PutUint32(b[36:], 1<<24) }, "l1-offset": func(b []byte) { be.PutUint64(b[40:], testCluster+1) }, "l1-outside": func(b []byte) { be.PutUint64(b[40:], 1<<60) },
		"refcount-offset": func(b []byte) { be.PutUint64(b[48:], 1) }, "refcount-bound": func(b []byte) { be.PutUint32(b[56:], 1<<30) }, "refcount-outside": func(b []byte) { be.PutUint64(b[48:], 1<<60) }, "refcount-order": func(b []byte) { be.PutUint32(b[96:], 7) },
		"header-small": func(b []byte) { be.PutUint32(b[100:], 96) }, "header-unaligned": func(b []byte) { be.PutUint32(b[100:], 105) }, "header-outside": func(b []byte) { be.PutUint32(b[100:], testCluster) },
		"non-deflate": func(b []byte) { be.PutUint32(b[100:], 112); b[104] = 1 }, "padding": func(b []byte) { be.PutUint32(b[100:], 112); b[105] = 1 },
		"extension-end-size": func(b []byte) { be.PutUint32(b[108:], 8) }, "extension-overflow": func(b []byte) { be.PutUint32(b[104:], 123); be.PutUint32(b[108:], 0xffffffff) },
		"l1-reserved": func(b []byte) { be.PutUint64(b[testCluster:], 2*testCluster|2) }, "l2-unaligned": func(b []byte) { be.PutUint64(b[testCluster:], 2*testCluster+512) }, "l2-outside": func(b []byte) { be.PutUint64(b[testCluster:], 1<<40) }, "l1-empty-copied": func(b []byte) { be.PutUint64(b[testCluster:], qcowCopied) },
		"data-reserved": func(b []byte) { be.PutUint64(b[2*testCluster:], 4*testCluster|2) }, "data-unaligned": func(b []byte) { be.PutUint64(b[2*testCluster:], 4*testCluster+512) }, "data-outside": func(b []byte) { be.PutUint64(b[2*testCluster:], 1<<40) }, "data-empty-copied": func(b []byte) { be.PutUint64(b[2*testCluster:], qcowCopied) },
		"zero-offset-outside": func(b []byte) { be.PutUint64(b[2*testCluster+8:], 1<<40|1) }, "v2-zero": func(b []byte) { be.PutUint32(b[4:], 2); clear(b[72:112]); be.PutUint64(b[2*testCluster+8:], 1) },
	}
	for bit := uint(0); bit < 64; bit++ {
		tests[fmt.Sprintf("incompatible-%d", bit)] = func(b []byte) { be.PutUint64(b[72:], uint64(1)<<bit) }
	}
	for _, kind := range []uint32{0xe2792aca, 0x23852875, 0x0537be77, 0x44415441} {
		tests[fmt.Sprintf("forbidden-extension-%x", kind)] = func(b []byte) { be.PutUint32(b[104:], kind) }
	}
	tests["raw-external"] = func(b []byte) { be.PutUint64(b[88:], 2) }
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			b := qcowFixture(t, rawEFIFixture(), 3)
			mutate(b)
			dst := filepath.Join(t.TempDir(), "disk.img")
			if _, err := convert(context.Background(), qcowPath(t, b), dst, 16*vzrecipe.GiB); err == nil {
				t.Fatal("malformed image accepted")
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatal("failed conversion retained output")
			}
		})
	}
}
func TestQCOWCompressionBoundsAndTruncation(t *testing.T) {
	be := binary.BigEndian
	for _, kind := range []string{"truncated-header", "truncated-data", "bad-deflate", "copied-compressed", "compressed-outside", "output-short", "output-long", "extension-count", "l2-budget", "bad-efi"} {
		t.Run(kind, func(t *testing.T) {
			b := compressedFixture(t, rawEFIFixture())
			switch kind {
			case "truncated-header":
				b = b[:71]
			case "truncated-data":
				b = b[:len(b)-1]
			case "bad-deflate":
				for i := 4 * testCluster; i < len(b); i++ {
					b[i] = 0xff
				}
			case "copied-compressed":
				be.PutUint64(b[2*testCluster:], be.Uint64(b[2*testCluster:])|qcowCopied)
			case "compressed-outside":
				be.PutUint64(b[2*testCluster:], qcowCompressed|1<<50)
			case "output-short", "output-long":
				raw := make([]byte, testCluster+1)
				if kind == "output-short" {
					raw = raw[:testCluster-1]
				}
				var compressed bytes.Buffer
				w, _ := flate.NewWriter(&compressed, flate.BestCompression)
				_, _ = w.Write(raw)
				_ = w.Close()
				off := 4 * testCluster
				b = append(b[:off], make([]byte, 1024)...)
				copy(b[off:], compressed.Bytes())
				be.PutUint64(b[2*testCluster:], qcowCompressed|uint64(off)|1<<58)
			case "extension-count":
				for at := 104; at+8 < testCluster; at += 8 {
					be.PutUint32(b[at:], uint32(at))
				}
			case "l2-budget":
				// A compact repeated L2 mapping cannot cause unlimited metadata work.
				q := &qcowImage{file: bytes.NewReader(b), fileSize: uint64(len(b)), virtual: 512 * uint64(vzrecipe.GiB), cluster: testCluster, bits: 12, version: 3, l1: make([]byte, (maxL2Bytes/testCluster+1)*8)}
				for i := 0; i < len(q.l1); i += 8 {
					be.PutUint64(q.l1[i:], 2*testCluster)
				}
				out, err := os.CreateTemp(t.TempDir(), "raw")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = out.Close() }()
				// Avoid decompressing repeated data: use an all-unallocated L2 table.
				clear(b[2*testCluster : 3*testCluster])
				if err := q.writeRaw(context.Background(), out); err == nil {
					t.Fatal("L2 work bound missing")
				}
				return
			case "bad-efi":
				b = qcowFixture(t, make([]byte, 65536), 3)
			}
			dst := filepath.Join(t.TempDir(), "disk.img")
			if _, err := convert(context.Background(), qcowPath(t, b), dst, 16*vzrecipe.GiB); err == nil {
				t.Fatal("invalid compressed image accepted")
			}
		})
	}
}

func TestQCOWMultipleL2TablesAndPartialLastCluster(t *testing.T) {
	raw := make([]byte, testCluster*(testCluster/8)+512)
	copy(raw, rawEFIFixture())
	copy(raw[len(raw)-512:], bytes.Repeat([]byte{0xa5}, 512))
	image := qcowFixture(t, raw, 3)
	q, err := openQCOW(bytes.NewReader(image), uint64(len(image)), 16*uint64(vzrecipe.GiB))
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "raw")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	if err = q.writeRaw(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	if err = out.Truncate(int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(raw))
	if _, err = out.ReadAt(got, 0); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("multi-table virtual disk differs", err)
	}
}
func TestQCOWBoundsAndCancellationDoNotLeaveCandidate(t *testing.T) {
	path := qcowPath(t, qcowFixture(t, rawEFIFixture(), 3))
	for _, target := range []int64{15 * vzrecipe.GiB, 513 * vzrecipe.GiB} {
		if _, err := convert(context.Background(), path, filepath.Join(t.TempDir(), "raw"), target); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := filepath.Join(t.TempDir(), "raw")
	if _, err := convert(ctx, path, dst, 16*vzrecipe.GiB); !errors.Is(err, context.Canceled) {
		t.Fatal("conversion ignored cancellation", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("cancelled candidate retained")
	}
}
func TestQCOWOptionalHeaderAndSafeExtensions(t *testing.T) {
	b := qcowFixture(t, rawEFIFixture(), 3)
	be := binary.BigEndian
	be.PutUint32(b[100:], 112)
	be.PutUint64(b[80:], 1) // compatible lazy refcounts are irrelevant to a read-only converter
	be.PutUint32(b[112:], 0x6803f857)
	be.PutUint32(b[116:], 48)
	be.PutUint32(b[168:], 0x12345678)
	be.PutUint32(b[172:], 1)
	b[176] = 1
	if _, err := openQCOW(bytes.NewReader(b), uint64(len(b)), 16*uint64(vzrecipe.GiB)); err != nil {
		t.Fatal("bounded safe extensions refused", err)
	}
	be.PutUint32(b[184:], 0x12345678)
	if _, err := openQCOW(bytes.NewReader(b), uint64(len(b)), 16*uint64(vzrecipe.GiB)); err == nil {
		t.Fatal("duplicate header extension accepted")
	}
}
