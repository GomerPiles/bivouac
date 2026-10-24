package imagefactory

import (
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MediaImage contains bounded, public installation metadata. DisplayName is
// informational and is never used to select an image.
type MediaImage struct {
	Index            uint32   `json:"index"`
	EditionID        string   `json:"edition_id"`
	Arch             uint32   `json:"arch"`
	Languages        []string `json:"languages"`
	DefaultLanguage  string   `json:"default_language"`
	Version          string   `json:"version"`
	InstallationType string   `json:"installation_type"`
	TotalBytes       uint64   `json:"total_bytes"`
	DisplayName      string   `json:"display_name"`
}

type MediaInventory struct {
	ISOSHA256 string       `json:"iso_sha256"`
	Kind      string       `json:"install_kind"`
	Images    []MediaImage `json:"images"`
	Selected  MediaImage   `json:"selected"`
}

type MediaRecord struct {
	ISOSHA256      string      `json:"iso_sha256"`
	Kind           string      `json:"install_kind"`
	Image          MediaImage  `json:"image"`
	DISMVersion    string      `json:"host_dism_version"`
	BootMethod     string      `json:"boot_method"`
	BCDEditVersion string      `json:"host_bcdedit_version"`
	LoaderGUID     string      `json:"loader_guid"`
	BCDVerified    bool        `json:"bcd_verified"`
	BootIssuers    BootIssuers `json:"boot_issuers"`
	WinRE          string      `json:"winre"`
	Layout         DiskLayout  `json:"layout"`
}

type BootIssuers struct {
	Fallback  string `json:"fallback"`
	Microsoft string `json:"microsoft"`
	Source    string `json:"source"`
}

type DiskLayout struct {
	DiskGUID    string `json:"disk_guid"`
	ESPGUID     string `json:"esp_guid"`
	MSRGUID     string `json:"msr_guid"`
	WindowsGUID string `json:"windows_guid"`
	// GPT initialization may create its own MSR; the factory removes it so
	// the owned disk keeps the ESP, MSR, Windows order.
	AutomaticMSRRemoved bool `json:"automatic_msr_removed"`
}

// bootShape describes a refused boot step with numbers only: bcdedit's exit
// code, or issuer codes for the ESP loaders and the applied image's own boot
// manager (0 invalid, 1 PCA 2011, 2 UEFI CA 2023, 3 PCA 2026, 4 other).
func bootShape(b []byte) error {
	var shape struct {
		Failure   bool   `json:"boot_failure"`
		Exit      *int64 `json:"bcdedit_exit"`
		Command   uint32 `json:"bcdedit_command"`
		Verify    uint32 `json:"bcd_verify"`
		Write     uint32 `json:"bcd_write"`
		Fallback  uint32 `json:"fallback_issuer"`
		Microsoft uint32 `json:"microsoft_issuer"`
		Source    uint32 `json:"source_issuer"`
	}
	if !json.Valid(b) {
		return nil
	}
	_ = json.Unmarshal(b, &shape)
	if !shape.Failure {
		return nil
	}
	if shape.Exit != nil {
		return fmt.Errorf("bcdedit refused: command=%d exit=%d", shape.Command, *shape.Exit)
	}
	if shape.Verify != 0 {
		return fmt.Errorf("offline BCD refused: code=%d", shape.Verify)
	}
	if shape.Write != 0 {
		return fmt.Errorf("offline BCD device write refused: code=%d", shape.Write)
	}
	return fmt.Errorf("boot loaders refused: fallback_issuer=%d microsoft_issuer=%d source_issuer=%d", shape.Fallback, shape.Microsoft, shape.Source)
}

// layoutShape describes a refused partition table with numbers only, from the
// frame the layout script emits before failing. It returns nil without one.
func layoutShape(b []byte) error {
	var shape struct {
		Failure    bool   `json:"layout_failure"`
		Count      uint32 `json:"partition_count"`
		Partitions []struct {
			Type      uint32 `json:"type"`
			OffsetMiB uint64 `json:"offset_mib"`
			SizeMiB   uint64 `json:"size_mib"`
			GUIDMatch bool   `json:"guid_match"`
		} `json:"partitions"`
	}
	// An absent or malformed frame adds nothing: the script step already failed.
	if !json.Valid(b) {
		return nil
	}
	_ = json.Unmarshal(b, &shape)
	if !shape.Failure || len(shape.Partitions) > 16 {
		return nil
	}
	s := fmt.Sprintf("partition table refused: count=%d", shape.Count)
	for i, p := range shape.Partitions {
		match := 0
		if p.GUIDMatch {
			match = 1
		}
		s += fmt.Sprintf(" p%d=type%d@%dMiB+%dMiB,guid%d", i+1, p.Type, p.OffsetMiB, p.SizeMiB, match)
	}
	return errors.New(s)
}

type wimHeader struct {
	GUID               [16]byte
	Part, Parts        uint16
	Count              uint32
	XMLSize, XMLOffset uint64
}

func readWIMHeader(r io.ReaderAt, size int64) (wimHeader, error) {
	var h wimHeader
	b := make([]byte, 208)
	if size < 208 {
		return h, errors.New("truncated WIM header")
	}
	if _, err := r.ReadAt(b, 0); err != nil {
		return h, errors.New("unreadable WIM header")
	}
	le := binary.LittleEndian
	version, flags := le.Uint32(b[12:]), le.Uint32(b[16:])
	// Reject unknown/reserved flags, including encrypted ESD variants, rather
	// than pretending that readable XML establishes that DISM can apply them.
	if string(b[:8]) != "MSWIM\x00\x00\x00" || le.Uint32(b[8:]) != 208 || (version != 0x10d00 && version != 0xe00) || flags & ^uint32(0x002e008e) != 0 {
		return h, errors.New("unsupported, encrypted or invalid WIM header")
	}
	copy(h.GUID[:], b[24:40])
	h.Part, h.Parts, h.Count = le.Uint16(b[40:]), le.Uint16(b[42:]), le.Uint32(b[44:])
	if h.Part == 0 || h.Parts == 0 || h.Part > h.Parts || h.Parts > 128 || h.Count > 128 {
		return h, errors.New("invalid WIM part or image count")
	}
	h.XMLSize = le.Uint64(b[72:80]) & 0x00ffffffffffffff
	h.XMLOffset = le.Uint64(b[80:88])
	if h.Part == 1 && (h.Count == 0 || b[79]&^byte(2) != 0 || h.XMLSize < 2 || h.XMLSize > 4<<20 || h.XMLSize%2 != 0 || le.Uint64(b[88:96]) != h.XMLSize || h.XMLOffset < 208 || h.XMLOffset > uint64(size) || h.XMLSize > uint64(size)-h.XMLOffset) {
		return h, errors.New("invalid or oversized WIM XML resource")
	}
	return h, nil
}

func readWIMImages(r io.ReaderAt, size int64) ([]MediaImage, wimHeader, error) {
	h, err := readWIMHeader(r, size)
	if err != nil {
		return nil, h, err
	}
	if h.Part != 1 {
		return nil, h, errors.New("install metadata requires the first WIM part")
	}
	b := make([]byte, int(h.XMLSize)) // #nosec G115 -- first-part XML size checked <=4 MiB above.
	if _, err = r.ReadAt(b, int64(h.XMLOffset)); err != nil {
		return nil, h, errors.New("truncated WIM XML")
	} // #nosec G115 -- offset bounded by positive int64 file size.
	words := make([]uint16, len(b)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	if len(words) > 0 && words[0] == 0xfeff {
		words = words[1:]
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w >= 0xd800 && w <= 0xdbff {
			if i+1 >= len(words) || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return nil, h, errors.New("invalid UTF-16 XML")
			}
			i++
		} else if w >= 0xdc00 && w <= 0xdfff {
			return nil, h, errors.New("invalid UTF-16 XML")
		}
	}
	text := string(utf16.Decode(words))
	// Go's strict XML decoder has no external entity resolution. Reject DTDs
	// explicitly as well as excessive nesting before decoding the schema.
	d := wimXMLDecoder(text)
	depth := 0
	for {
		t, e := d.Token()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, h, errors.New("invalid WIM XML")
		}
		switch t.(type) {
		case xml.Directive:
			return nil, h, errors.New("WIM XML directives refused")
		case xml.StartElement:
			depth++
			if depth > 32 {
				return nil, h, errors.New("WIM XML depth exceeds bound")
			}
		case xml.EndElement:
			depth--
		}
	}
	var doc struct {
		XMLName   xml.Name `xml:"WIM"`
		Encrypted []string `xml:"ESD>ENCRYPTED"`
		Images    []struct {
			Index   uint32 `xml:"INDEX,attr"`
			Name    string `xml:"DISPLAYNAME"`
			Total   uint64 `xml:"TOTALBYTES"`
			Windows struct {
				Arch      uint32   `xml:"ARCH"`
				Edition   string   `xml:"EDITIONID"`
				Type      string   `xml:"INSTALLATIONTYPE"`
				Languages []string `xml:"LANGUAGES>LANGUAGE"`
				Default   string   `xml:"LANGUAGES>DEFAULT"`
				Version   struct {
					Major   uint32 `xml:"MAJOR"`
					Minor   uint32 `xml:"MINOR"`
					Build   uint32 `xml:"BUILD"`
					SPBuild uint32 `xml:"SPBUILD"`
				} `xml:"VERSION"`
			} `xml:"WINDOWS"`
		} `xml:"IMAGE"`
	}
	decoder := wimXMLDecoder(text)
	if decoder.Decode(&doc) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || len(doc.Encrypted) > 0 || len(doc.Images) != int(h.Count) {
		return nil, h, errors.New("invalid or encrypted WIM image metadata")
	}
	seen := map[uint32]bool{}
	images := make([]MediaImage, 0, len(doc.Images))
	for position, im := range doc.Images {
		w := im.Windows
		if im.Index != uint32(position+1) || im.Index > 128 || seen[im.Index] || !mediaIdentifier(w.Edition, 64) || !mediaIdentifier(w.Type, 32) || im.Total == 0 || im.Total > 256<<30 || len(w.Languages) < 1 || len(w.Languages) > 32 { // #nosec G115 -- image count <=128.
			return nil, h, errors.New("invalid WIM image identity")
		}
		seen[im.Index] = true
		found := false
		for _, l := range w.Languages {
			if !mediaIdentifier(l, 64) {
				return nil, h, errors.New("invalid WIM language")
			}
			found = found || l == w.Default
		}
		if !found {
			return nil, h, errors.New("invalid WIM default language")
		}
		v := w.Version
		images = append(images, MediaImage{im.Index, w.Edition, w.Arch, w.Languages, w.Default, fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Build, v.SPBuild), w.Type, im.Total, sanitizeMediaName(im.Name)})
	}
	return images, h, nil
}

func wimXMLDecoder(text string) *xml.Decoder {
	d := xml.NewDecoder(strings.NewReader(text))
	// Bytes were strictly decoded from UTF-16LE above. Honor that declaration
	// without asking encoding/xml to reinterpret the resulting UTF-8 string.
	d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf-16") || strings.EqualFold(label, "utf-16le") {
			return r, nil
		}
		return nil, errors.New("unsupported WIM XML encoding declaration")
	}
	return d
}

func mediaIdentifier(s string, limit int) bool {
	if len(s) < 1 || len(s) > limit {
		return false
	}
	for _, r := range s {
		if r != '-' && r != '_' && r != ' ' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func sanitizeMediaName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 128 {
			break
		}
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func selectImage(images []MediaImage, edition string, index uint32) (MediaImage, error) {
	var selected MediaImage
	count := 0
	for _, im := range images {
		if (index != 0 && im.Index == index) || (index == 0 && im.EditionID == edition && im.Arch == 9) {
			if im.Arch != 9 || im.InstallationType != "Client" {
				return selected, errors.New("selected image must be x64 Client")
			}
			selected = im
			count++
		}
	}
	if count != 1 {
		return MediaImage{}, errors.New("media selection requires exactly one matching image")
	}
	return selected, nil
}

// inventoryInstall operates on either the read-only ISO filesystem or a small
// synthetic fixture. Names are direct children of sources, never host paths.
func inventoryInstall(files map[string]*io.SectionReader, edition string, index uint32) (MediaInventory, error) {
	var result MediaInventory
	var first *io.SectionReader
	kinds := 0
	for _, kind := range []string{"wim", "esd", "swm"} {
		if f := files["install."+kind]; f != nil {
			kinds++
			result.Kind = kind
			first = f
		}
	}
	if kinds != 1 {
		return result, errors.New("media must contain exactly one install file kind")
	}
	images, h, err := readWIMImages(first, first.Size())
	if err != nil {
		return result, err
	}
	if result.Kind != "swm" && (h.Part != 1 || h.Parts != 1) {
		return result, errors.New("unexpected split install image")
	}
	if result.Kind == "swm" {
		for n := uint16(1); n <= h.Parts; n++ {
			name := "install.swm"
			if n > 1 {
				name = "install" + strconv.Itoa(int(n)) + ".swm"
			}
			part := files[name]
			if part == nil {
				return result, errors.New("missing split WIM segment")
			}
			ph, e := readWIMHeader(part, part.Size())
			if e != nil {
				return result, e
			}
			if ph.GUID != h.GUID || ph.Part != n || ph.Parts != h.Parts {
				return result, errors.New("mismatched split WIM segment")
			}
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "install") && strings.HasSuffix(name, ".swm") {
			if result.Kind != "swm" {
				return result, errors.New("mixed install media")
			}
			suffix := strings.TrimSuffix(strings.TrimPrefix(name, "install"), ".swm")
			if suffix != "" {
				n, e := strconv.Atoi(suffix)
				if e != nil || n < 2 || n > int(h.Parts) || suffix != strconv.Itoa(n) {
					return result, errors.New("unexpected split WIM segment")
				}
			}
		}
	}
	result.Images = images
	result.Selected, err = selectImage(images, edition, index)
	return result, err
}
