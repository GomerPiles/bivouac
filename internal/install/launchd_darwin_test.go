package install

import (
	"bytes"
	"context"
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

func TestOtherHomeNeverTouchesTheLoginItem(t *testing.T) {
	t.Setenv("BIVOUAC_HOME", t.TempDir())
	ctx := context.Background()
	if _, err := Install(ctx, Paths{Binary: "/usr/local/bin/bivouac", LogDir: t.TempDir()}); !errors.Is(err, errOtherHome) {
		t.Fatalf("Install = %v", err)
	}
	if err := Uninstall(ctx); !errors.Is(err, errOtherHome) {
		t.Fatalf("Uninstall = %v", err)
	}
	if err := Kickstart(ctx); !errors.Is(err, errOtherHome) {
		t.Fatalf("Kickstart = %v", err)
	}
	if plist, loaded, err := Installed(ctx); plist != "" || loaded || err != nil {
		t.Fatalf("Installed = %q, %v, %v", plist, loaded, err)
	}
}
