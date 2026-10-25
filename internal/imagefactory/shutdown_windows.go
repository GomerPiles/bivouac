//go:build windows

package imagefactory

import (
	"context"
	"io"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

const failureShutdownBudget = 60 * time.Second

func requestFailureShutdown(ctx context.Context, dial guestagent.Dialer) error {
	return guestagent.Run(ctx, dial, []string{`C:\Windows\System32\shutdown.exe`, "/s", "/t", "5", "/d", "p:0:0"}, nil, io.Discard)
}

// Cleanup owns the creating handle. Request and observation share one bound,
// independent of the failed build context; neither can suppress termination.
func terminateAfterGuestFailure(ctx context.Context, budget time.Duration, request, wait func(context.Context) error, terminate func() error) error {
	grace, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	requestCtx, cancelRequest := context.WithTimeout(grace, 10*time.Second)
	err := request(requestCtx)
	cancelRequest()
	if err == nil {
		_ = wait(grace)
	}
	return terminate()
}
