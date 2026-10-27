package rootnet

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Serve owns a datagram attachment, not a host-network listener. A failed link
// is terminal: the VM helper must end its VM, never replace it with NAT.
func (n *Network) Serve(link net.Conn) error {
	errorsOut := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() {
		b := make([]byte, n.options.settings.MTU+15)
		for {
			count, err := readDatagram(link, b)
			if err != nil {
				errorsOut <- err
				return
			}
			n.Input(b[:count])
		}
	})
	wg.Go(func() {
		for {
			b := n.Output(n.ctx)
			if b == nil {
				errorsOut <- net.ErrClosed
				return
			}
			if err := link.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				errorsOut <- err
				return
			}
			if _, err := link.Write(b); err != nil {
				errorsOut <- err
				return
			}
		}
	})
	select {
	case <-n.ctx.Done():
	case err := <-errorsOut:
		_ = err
	}
	n.cancel()
	_ = link.Close()
	wg.Wait()
	return errors.New("isolated network attachment ended")
}
