//go:build windows

package imagefactory

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/GomerPiles/bivouac/internal/guestagent"
)

const failureShutdownBudget = 60 * time.Second

type memoryReserveLostError struct{}

func (*memoryReserveLostError) Error() string {
	return "host memory reserve lost; canceling image build"
}

func allowFailureShutdown(preparationStarted bool, failure, cause error) bool {
	var reserve *memoryReserveLostError
	return preparationStarted && failure != nil && !errors.As(cause, &reserve) && !errors.As(failure, &reserve)
}

// Subtract from the enclosing deadline rather than starting a new full budget
// after an earlier stage has already consumed its share.
func cleanupStageContext(ctx context.Context, reserve time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(ctx, deadline.Add(-reserve))
	}
	return context.WithCancel(ctx)
}

func requestFailureShutdown(ctx context.Context, dial guestagent.Dialer) error {
	return guestagent.Run(ctx, dial, []string{`C:\Windows\System32\shutdown.exe`, "/s", "/t", "5", "/d", "p:0:0"}, nil, io.Discard)
}

// Cleanup owns the creating handle. Request and observation share one bound,
// independent of the failed build context; neither can suppress termination.
func terminateAfterGuestFailure(ctx context.Context, budget time.Duration, request, wait func(context.Context) error, terminate func() error) error {
	if ctx.Err() != nil {
		return terminate()
	}
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
