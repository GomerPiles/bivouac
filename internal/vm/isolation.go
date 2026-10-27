package vm

import (
	"errors"
	"net"

	"github.com/GomerPiles/bivouac/internal/rootnet"
)

func proveIsolationArgs(args []string, dir, policy string) error {
	if len(args) < 6 {
		return errors.New("isolated VM launch unavailable")
	}
	opts, err := ParseArgs(args[3:])
	if err != nil || opts.Dir != dir || !opts.RootlessNetwork || opts.Machine.SeedDisk != "" || opts.Machine.ReceiptDisk != "" || policy != rootnet.PolicyID {
		return errors.New("live VM isolation differs; drain and replace the guest")
	}
	return nil
}

func networkChildArgs(args []string) bool {
	if len(args) < 4 || args[1] != "vm" || args[2] != "network" {
		return false
	}
	mac, err := net.ParseMAC(args[3])
	if err != nil || len(mac) != 6 {
		return false
	}
	_, err = ParseNetworkArgs(args[4:])
	return err == nil
}
