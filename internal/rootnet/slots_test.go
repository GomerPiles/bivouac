package rootnet

// acquire and release take general slots without moving the active-flow
// gauges; production paths account slots and gauges together.
func (n *Network) acquire() bool { return n.acquireSlot(n.slots) }
func (n *Network) release()      { <-n.slots; n.wg.Done() }
