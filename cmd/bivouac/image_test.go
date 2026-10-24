package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/GomerPiles/bivouac/internal/imagefactory"
	"io"
	"strings"
	"testing"
)

func TestImageCommandUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"plan"}, {"build"}, {"inspect"}, {"inspect", "--config", "file.json", "--build", "id"}, {"cleanup", "--config", "file.json"}, {"build", "--config", "file.json", "--build", "id"}, {"build", "--config", "file.json", "extra"}} {
		if err := imageCmd(context.Background(), args, io.Discard); !errors.Is(err, errUsage) {
			t.Fatalf("image usage rejected incorrectly: %v", args)
		}
	}
}

func TestPublishedImageCleanupWarning(t *testing.T) {
	var out, warnings bytes.Buffer
	m := imagefactory.Manifest{BuildID: "example-build", Output: `D:\Images\disk.vhdx`, GuestName: "bivouac-aaaaaaa", GuestUser: "imageuser"}
	cause := errors.New("workspace retained")
	err := writeImageResult(&out, &warnings, m, &imagefactory.PublishedError{BuildID: m.BuildID, Err: cause})
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "image is published") || !strings.Contains(out.String(), "image_path") || !strings.Contains(warnings.String(), "warning: image is published") {
		t.Fatal("published result lost on cleanup error")
	}
	out.Reset()
	warnings.Reset()
	if writeImageResult(&out, &warnings, m, cause) == nil || out.Len() != 0 {
		t.Fatal("failed unpublished build printed image values")
	}
}

func TestImageCleanupRetainedLetterOutput(t *testing.T) {
	var out bytes.Buffer
	cause := &imagefactory.RetainedLettersError{Letters: []string{"Z", "Y"}}
	if e := writeImageCleanupResult(&out, "test-build", cause); !errors.Is(e, cause) || !strings.Contains(out.String(), `"retained_letters":["Z","Y"]`) {
		t.Fatal("cleanup operator output lost retained letter")
	}
	out.Reset()
	if e := writeImageCleanupResult(&out, "test-build", nil); e != nil || out.Len() != 0 {
		t.Fatal("successful cleanup changed output")
	}
}
