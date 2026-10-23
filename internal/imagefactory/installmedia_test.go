package imagefactory

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestReferenceISO(t *testing.T) {
	path := os.Getenv("BIVOUAC_TEST_ISO")
	if path == "" {
		t.Skip("set BIVOUAC_TEST_ISO for read-only real media inventory")
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	got, e := readISOInventory(f, info.Size(), "Professional", 0)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(got)
	t.Log(string(b))
}

func syntheticWIM(text string) []byte {
	words := utf16.Encode([]rune(text))
	b := make([]byte, 208+2*len(words))
	copy(b, "MSWIM\x00\x00\x00")
	le := binary.LittleEndian
	le.PutUint32(b[8:], 208)
	le.PutUint32(b[12:], 0x10d00)
	le.PutUint16(b[40:], 1)
	le.PutUint16(b[42:], 1)
	le.PutUint32(b[44:], 1)
	le.PutUint64(b[72:], uint64(2*len(words)))
	le.PutUint64(b[80:], 208)
	le.PutUint64(b[88:], uint64(2*len(words)))
	for i, w := range words {
		le.PutUint16(b[208+2*i:], w)
	}
	return b
}
func imageXML(edition string, index int) string {
	return `<IMAGE INDEX="` + strconv.Itoa(index) + `"><DISPLAYNAME>Windows Pro</DISPLAYNAME><TOTALBYTES>12000000000</TOTALBYTES><WINDOWS><ARCH>9</ARCH><EDITIONID>` + edition + `</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-US</LANGUAGE><DEFAULT>en-US</DEFAULT></LANGUAGES><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26300</BUILD><SPBUILD>9457</SPBUILD></VERSION></WINDOWS></IMAGE>`
}
func TestWIMMetadata(t *testing.T) {
	good := syntheticWIM(`<WIM>` + imageXML("Professional", 1) + `</WIM>`)
	declared := syntheticWIM(`<?xml version="1.0" encoding="UTF-16"?><WIM>` + imageXML("Professional", 1) + `</WIM>`)
	if _, _, e := readWIMImages(bytes.NewReader(declared), int64(len(declared))); e != nil {
		t.Fatal("UTF-16 declaration rejected", e)
	}
	for _, kind := range []string{"wim", "esd", "swm"} {
		got, e := inventoryInstall(map[string]*io.SectionReader{"install." + kind: sectionBytes(good)}, "Professional", 0)
		if e != nil || got.Selected.EditionID != "Professional" || got.Selected.Version != "10.0.26300.9457" {
			t.Fatal(kind, e)
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:100] }, "magic": func(b []byte) []byte { b[0] = 0; return b }, "header": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[8:], 4096); return b }, "oversized": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[72:], 8<<20); return b }, "encrypted flag": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:], 0x20000000); return b }, "xml bounds": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[80:], ^uint64(0)); return b }, "entity": func([]byte) []byte {
			return syntheticWIM(`<!DOCTYPE WIM [<!ENTITY x "expanded">]><WIM>` + imageXML("Professional", 1) + `</WIM>`)
		}, "broken xml": func([]byte) []byte { return syntheticWIM(`<WIM><IMAGE></WIM>`) }, "encrypted xml": func([]byte) []byte {
			return syntheticWIM(`<WIM><ESD><ENCRYPTED>1</ENCRYPTED></ESD>` + imageXML("Professional", 1) + `</WIM>`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := mutate(bytes.Clone(good))
			if _, _, e := readWIMImages(bytes.NewReader(b), int64(len(b))); e == nil {
				t.Fatal("invalid media accepted")
			}
		})
	}
	split := bytes.Clone(good)
	binary.LittleEndian.PutUint16(split[42:], 2)
	files := map[string]*io.SectionReader{"install.swm": sectionBytes(split)}
	if _, e := inventoryInstall(files, "Professional", 0); e == nil {
		t.Fatal("missing split part accepted")
	}
	second := bytes.Clone(split)
	binary.LittleEndian.PutUint16(second[40:], 2)
	files["install2.swm"] = sectionBytes(second)
	if _, e := inventoryInstall(files, "Professional", 0); e != nil {
		t.Fatal(e)
	}
	files["install.wim"] = sectionBytes(good)
	if _, e := inventoryInstall(files, "Professional", 0); e == nil {
		t.Fatal("mixed media accepted")
	}
}
func TestImageSelection(t *testing.T) {
	images := []MediaImage{{Index: 1, EditionID: "ProfessionalN", Arch: 9, InstallationType: "Client"}, {Index: 2, EditionID: "Professional", Arch: 9, InstallationType: "Client"}}
	got, e := selectImage(images, "Professional", 0)
	if e != nil || got.Index != 2 {
		t.Fatal(e)
	}
	got, e = selectImage(images, "Professional", 1)
	if e != nil || got.EditionID != "ProfessionalN" {
		t.Fatal(e)
	}
	if _, e = selectImage(images, "missing", 0); e == nil {
		t.Fatal("zero matches")
	}
	images = append(images, images[1])
	if _, e = selectImage(images, "Professional", 0); e == nil {
		t.Fatal("ambiguous matches")
	}
	images[0].Arch = 12
	if _, e = selectImage(images, "Professional", 1); e == nil {
		t.Fatal("arm64 override")
	}
	images[0].Arch = 9
	images[0].InstallationType = "Server"
	if _, e = selectImage(images, "Professional", 1); e == nil {
		t.Fatal("server override")
	}
	if len(sanitizeMediaName(strings.Repeat("x", 200)+"\x1b")) > 128 {
		t.Fatal("display length")
	}
}

func TestWIMSelectionFromMetadata(t *testing.T) {
	for _, second := range []string{"ProfessionalN", "Professional"} {
		b := syntheticWIM(`<WIM>` + imageXML("Professional", 1) + imageXML(second, 2) + `</WIM>`)
		binary.LittleEndian.PutUint32(b[44:], 2)
		got, e := inventoryInstall(map[string]*io.SectionReader{"install.wim": sectionBytes(b)}, "Professional", 0)
		if second == "ProfessionalN" {
			if e != nil || got.Selected.Index != 1 {
				t.Fatal("N edition accidentally ambiguous", e)
			}
		} else if e == nil {
			t.Fatal("ambiguous edition accepted")
		}
	}
}

func TestWIMIndexMustMatchPosition(t *testing.T) {
	for _, indexes := range [][]int{{2}, {2, 1}, {1, 3}, {1, 1}} {
		var images strings.Builder
		for _, index := range indexes {
			images.WriteString(imageXML("Professional", index))
		}
		b := syntheticWIM("<WIM>" + images.String() + "</WIM>")
		binary.LittleEndian.PutUint32(b[44:], uint32(len(indexes))) // #nosec G115 -- <=2 fixture images.
		if _, _, e := readWIMImages(bytes.NewReader(b), int64(len(b))); e == nil {
			t.Fatal("non-positional INDEX accepted", indexes)
		}
	}
}

func sectionBytes(b []byte) *io.SectionReader {
	return io.NewSectionReader(bytes.NewReader(b), 0, int64(len(b)))
}

func TestLayoutShapeNumbersOnly(t *testing.T) {
	b := []byte(`{"layout_failure":true,"partition_count":2,"partitions":[{"type":2,"offset_mib":1,"size_mib":16,"guid_match":false},{"type":1,"offset_mib":17,"size_mib":200,"guid_match":true}]}`)
	err := layoutShape(b)
	if err == nil || err.Error() != "partition table refused: count=2 p1=type2@1MiB+16MiB,guid0 p2=type1@17MiB+200MiB,guid1" {
		t.Fatalf("unexpected shape: %v", err)
	}
	for _, b := range [][]byte{nil, []byte(`{}`), []byte(`{"disk_guid":"x"}`), []byte(`not json`)} {
		if layoutShape(b) != nil {
			t.Fatal("shape reported without a layout failure frame")
		}
	}
}

func TestBootShapeNumbersOnly(t *testing.T) {
	if e := bootShape([]byte(`{"boot_failure":true,"bcdboot_exit":-1073741819}`)); e == nil || e.Error() != "bcdboot refused: exit=-1073741819" {
		t.Fatalf("unexpected exit shape: %v", e)
	}
	if e := bootShape([]byte(`{"boot_failure":true,"fallback_issuer":3,"microsoft_issuer":3,"source_issuer":3}`)); e == nil || e.Error() != "boot loaders refused: fallback_issuer=3 microsoft_issuer=3 source_issuer=3" {
		t.Fatalf("unexpected issuer shape: %v", e)
	}
	for _, b := range [][]byte{nil, []byte(`{}`), []byte(`{"bcdboot_version":"1.2.3.4"}`)} {
		if bootShape(b) != nil {
			t.Fatal("shape reported without a boot failure frame")
		}
	}
}
