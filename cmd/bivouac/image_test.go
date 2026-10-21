package main

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestImageCommandUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"plan"}, {"build"}, {"cleanup", "--config", "file.json"}, {"build", "--config", "file.json", "--build", "id"}, {"build", "--config", "file.json", "extra"}} {
		if err := imageCmd(context.Background(), args, io.Discard); !errors.Is(err, errUsage) {
			t.Fatalf("image usage rejected incorrectly: %v", args)
		}
	}
}
