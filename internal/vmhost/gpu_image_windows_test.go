//go:build windows

package vmhost

import (
	"context"
	"errors"
	"os"
	"testing"
)

type fakeImageCache struct {
	source  string
	calls   int
	failure error
}

func (c *fakeImageCache) Ensure(_ context.Context, source string) (string, bool, error) {
	c.calls++
	c.source = source
	return `C:\Images\derived\disk.vhdx`, false, c.failure
}
func (*fakeImageCache) Close() error { return nil }

func TestGPUCacheParentIsRecordedBeforeNativeCreation(t *testing.T) {
	h, n := fixture(t)
	cache := &fakeImageCache{}
	h.images = cache
	spec := validSpec()
	spec.GPU = true
	g, err := h.Create(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var recorded record
	if err := h.read(recordName(spec.Name), &recorded); err != nil {
		t.Fatal(err)
	}
	if cache.calls != 1 || cache.source != spec.Image || recorded.Spec.Image != `C:\Images\derived\disk.vhdx` || !n.sawIntent {
		t.Fatal("derived parent was not journalled")
	}
	if err := h.Destroy(t.Context(), g); err != nil {
		t.Fatal(err)
	}
}

func TestGPUCacheFailureCreatesNoGuest(t *testing.T) {
	h, n := fixture(t)
	cache := &fakeImageCache{failure: errors.New("injected preparation failure")}
	h.images = cache
	spec := validSpec()
	spec.GPU = true
	if _, err := h.Create(t.Context(), spec); err == nil || len(n.created) != 0 {
		t.Fatal("failed preparation dispatched a guest")
	}
	var recorded record
	err := h.read(recordName(spec.Name), &recorded)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed preparation left a guest journal", err)
	}
}
