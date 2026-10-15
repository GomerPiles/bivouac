package install

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"testing"
)

func TestPlistEscapesValues(t *testing.T) {
	binary := `/Applications/A & B <x>/"bivouac"`
	plist, err := renderPlist(binary, "/tmp/logs & <more>")
	if err != nil {
		t.Fatal(err)
	}
	d := xml.NewDecoder(bytes.NewReader(plist))
	var strs []string
	inString := false
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v\n%s", err, plist)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			inString = v.Name.Local == "string"
		case xml.EndElement:
			inString = false
		case xml.CharData:
			if inString {
				strs = append(strs, string(v))
			}
		}
	}
	for _, want := range []string{Label, binary, "/tmp/logs & <more>/launchd.log"} {
		if !slices.Contains(strs, want) {
			t.Fatalf("decoded strings %q lack %q", strs, want)
		}
	}
	if _, err := renderPlist("/bin/biv\nouac", "/tmp"); err == nil {
		t.Fatal("control character accepted in plist value")
	}
}
