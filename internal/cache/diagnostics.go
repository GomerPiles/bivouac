package cache

import (
	"context"
	"errors"
	"net"
)

// fault retains only a fixed category and optional HTTP status. In particular,
// transport errors can contain signed URLs and filesystem errors contain paths.
type fault struct {
	reason string
	status int
}

func (e *fault) Error() string { return e.reason }

func failure(reason string) error { return &fault{reason: reason} }

func failureDetails(err error) (string, int) {
	var f *fault
	if errors.As(err, &f) {
		return f.reason, f.status
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", 0
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "timeout", 0
	}
	return "unavailable", 0
}

func upstreamFailure(err error) error {
	reason, _ := failureDetails(err)
	if reason == "unavailable" {
		reason = "upstream_transport"
	}
	return failure(reason)
}

func bodyFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var f *fault
	if errors.As(err, &f) {
		return f
	}
	return failure("upstream_body")
}

// Delivery errors can contain connection addresses or filesystem paths. Keep
// only a fixed category, including when an error is observed by a writer.
func deliveryFailure(err error) string {
	reason, _ := failureDetails(err)
	if reason == "unavailable" {
		return "response_body"
	}
	return reason
}
