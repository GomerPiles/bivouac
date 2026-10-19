package command

import (
	"strings"
	"testing"
)

func TestBoundedNativeCommandOutput(t *testing.T) {
	var b boundedOutput
	data := []byte(strings.Repeat("x", DefaultLimit+10))
	n, err := b.Write(data)
	if n != len(data) || err != nil || !b.overflow || len(b.data) != DefaultLimit {
		t.Fatal("output bound failed")
	}
}
