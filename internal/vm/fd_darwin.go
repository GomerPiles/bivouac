package vm

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// EnsureNetworkFDs reserves headroom for this process's maximum owned sockets.
// Called before sandbox activation and before any VM/credential operation.
func EnsureNetworkFDs(required int) error {
	if required < 0 || required > 1<<24 {
		return errors.New("invalid network descriptor budget")
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return errors.New("network descriptor inventory unavailable")
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
		return errors.New("network descriptor limit unavailable")
	}
	needed := uint64(required + len(entries))
	if needed > limit.Cur {
		if needed > limit.Max {
			return errors.New("network descriptor hard limit insufficient")
		}
		limit.Cur = needed
		if unix.Setrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
			return errors.New("cannot raise network descriptor limit")
		}
	}
	return nil
}
