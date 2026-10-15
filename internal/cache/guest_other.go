//go:build !windows && !linux

package cache

import (
	"context"
	"errors"
)

func guestTrust(context.Context, string) ([]byte, error) {
	return nil, errors.New("this provider supplies its own guest trust adapter")
}
