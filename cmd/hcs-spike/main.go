// hcs-spike is an isolated direct-HCS experiment, never a CI controller.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/GomerPiles/bivouac/internal/hcsspike"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := hcsspike.RunCLI(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
